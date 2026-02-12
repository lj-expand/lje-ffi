#include "disasm.hpp"
#include "../globals.hpp"

#include <capstone/capstone.h>
#include <cstdint>
#include <vector>

namespace api::disasm {

static csh s_handle = 0;

static bool ensure_init() {
  if (s_handle)
    return true;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &s_handle) != CS_ERR_OK) {
    return false;
  }
  cs_option(s_handle, CS_OPT_DETAIL, CS_OPT_ON);
  return true;
}

static void push_operand(lua_State *L, const cs_x86_op *op) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 5);

  switch (op->type) {
  case X86_OP_REG:
    lua->pushstring(L, "reg");
    lua->setfield(L, -2, "type");
    lua->pushstring(L, cs_reg_name(s_handle, op->reg));
    lua->setfield(L, -2, "reg");
    break;

  case X86_OP_IMM:
    lua->pushstring(L, "imm");
    lua->setfield(L, -2, "type");
    lua->pushnumber(L, static_cast<double>(op->imm));
    lua->setfield(L, -2, "imm");
    break;

  case X86_OP_MEM:
    lua->pushstring(L, "mem");
    lua->setfield(L, -2, "type");
    if (op->mem.base != X86_REG_INVALID) {
      lua->pushstring(L, cs_reg_name(s_handle, op->mem.base));
      lua->setfield(L, -2, "base");
    }
    if (op->mem.index != X86_REG_INVALID) {
      lua->pushstring(L, cs_reg_name(s_handle, op->mem.index));
      lua->setfield(L, -2, "index");
    }
    lua->pushnumber(L, static_cast<double>(op->mem.scale));
    lua->setfield(L, -2, "scale");
    lua->pushnumber(L, static_cast<double>(op->mem.disp));
    lua->setfield(L, -2, "disp");
    break;

  default:
    lua->pushstring(L, "unknown");
    lua->setfield(L, -2, "type");
    break;
  }

  lua->pushnumber(L, static_cast<double>(op->size));
  lua->setfield(L, -2, "size");
}

static void push_instruction(lua_State *L, const cs_insn *insn) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 6);

  lua->pushnumber(L, static_cast<double>(insn->address));
  lua->setfield(L, -2, "address");

  lua->pushstring(L, insn->mnemonic);
  lua->setfield(L, -2, "mnemonic");

  lua->pushstring(L, insn->op_str);
  lua->setfield(L, -2, "op_str");

  lua->pushnumber(L, static_cast<double>(insn->size));
  lua->setfield(L, -2, "size");

  // Bytes as table
  lua->createtable(L, insn->size, 0);
  for (uint16_t i = 0; i < insn->size; i++) {
    lua->pushnumber(L, static_cast<double>(insn->bytes[i]));
    lua->rawseti(L, -2, i + 1);
  }
  lua->setfield(L, -2, "bytes");

  // Operands
  if (insn->detail) {
    cs_x86 *x86 = &insn->detail->x86;
    lua->createtable(L, x86->op_count, 0);
    for (uint8_t i = 0; i < x86->op_count; i++) {
      push_operand(L, &x86->operands[i]);
      lua->rawseti(L, -2, i + 1);
    }
    lua->setfield(L, -2, "operands");
  }
}

// disasm.at(address: number, count?: number) -> table of instructions
static int at(lua_State *L) {
  auto lua = g_api->lua;

  if (!ensure_init()) {
    lua->createtable(L, 0, 0);
    return 1;
  }

  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto count = static_cast<size_t>(lua->gettop(L) >= 2 ? lua->tonumber(L, 2) : 1);

  cs_insn *insns;
  size_t disasm_count = cs_disasm(s_handle, reinterpret_cast<const uint8_t *>(addr), 128 * count,
                                  addr, count, &insns);

  lua->createtable(L, static_cast<int>(disasm_count), 0);

  for (size_t i = 0; i < disasm_count; i++) {
    push_instruction(L, &insns[i]);
    lua->rawseti(L, -2, static_cast<int>(i + 1));
  }

  if (disasm_count > 0) {
    cs_free(insns, disasm_count);
  }

  return 1;
}

static uintptr_t pull_global_from_ins(cs_insn *insn) {
  if (insn->detail) {
    cs_x86 *x86 = &insn->detail->x86;
    if (x86->op_count == 2 && x86->operands[0].type == X86_OP_REG &&
        x86->operands[1].type == X86_OP_MEM && x86->operands[1].mem.base == X86_REG_RIP) {
      const auto offset = x86->operands[1].mem.disp;
      return static_cast<uintptr_t>(insn->address + insn->size + offset);
    }
  }

  return 0;
}

// disasm.pull_global(address: number) -> global_address: number
static int pull_global(lua_State* L) {
  auto lua = g_api->lua;

  if (!ensure_init()) {
    lua->pushnil(L);
    return 1;
  }

  // Disassemble the instruction, should be in the format mov <reg>, qword ptr [rip+offset]
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  cs_insn *insns;
  size_t disasm_count = cs_disasm(s_handle, reinterpret_cast<const uint8_t *>(addr), 15, addr, 1, &insns);
  if (disasm_count == 0) {
    lua->pushnil(L);
    return 1;
  }

  const auto global_addr = pull_global_from_ins(&insns[0]);
  cs_free(insns, disasm_count);

  if (global_addr == 0) {
    lua->pushnil(L);
    return 1;
  }

  lua->pushnumber(L, static_cast<double>(global_addr));
  return 1;
}

// disasm.pull_all_globals(address: number, max_size: number?) -> table of {number}
static int pull_all_globals(lua_State* L) {
  auto lua = g_api->lua;

  if (!ensure_init()) {
    lua->createtable(L, 0, 0);
    return 1;
  }

  const auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  const auto max_size = static_cast<size_t>(lua->gettop(L) >= 2 ? lua->tonumber(L, 2) : 128);
  // We'll basically go through each instruction to find all of the globals, and terminate when we hit max_size or padding (CC)
  // We do not terminate on ret since that is an awful function ending heuristic and there are many cases where globals are pulled after the ret (e.g. in a function epilogue or when pulling into a register for a return)

  cs_insn *insns;
  size_t disasm_count = cs_disasm(s_handle, reinterpret_cast<const uint8_t *>(addr), 15 * max_size, addr, max_size, &insns);
  if (disasm_count == 0) {
    lua->createtable(L, 0, 0);
    return 1;
  }

  std::vector<uintptr_t> globals;
  for (size_t i = 0; i < disasm_count; i++) {
    if (insns[i].id == X86_INS_INT3) { // padding, stop disassembling
      break;
    }

    const auto global_addr = pull_global_from_ins(&insns[i]);
    if (global_addr != 0) {
      globals.push_back(global_addr);
    }
  }

  cs_free(insns, disasm_count);

  lua->createtable(L, static_cast<int>(globals.size()), 0);
  for (size_t i = 0; i < globals.size(); i++) {
    lua->pushnumber(L, static_cast<double>(globals[i]));
    lua->rawseti(L, -2, static_cast<int>(i + 1));
  }
  return 1;
}

// disasm.pull_calls(address: number, max_size: number?) -> table of {number}
// This is a bit more complex since we need to handle both relative and absolute calls,
// but this allows us to easily pull thunk addresses for virtual functions which need their inner function hooked to be useful.
static int pull_calls(lua_State* L) {
  auto lua = g_api->lua;

  if (!ensure_init()) {
    lua->createtable(L, 0, 0);
    return 1;
  }

  const auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  const auto max_size = static_cast<size_t>(lua->gettop(L) >= 2 ? lua->tonumber(L, 2) : 128);

  cs_insn *insns;
  size_t disasm_count = cs_disasm(s_handle, reinterpret_cast<const uint8_t *>(addr), 15 * max_size, addr, max_size, &insns);
  if (disasm_count == 0) {
    lua->createtable(L, 0, 0);
    return 1;
  }

  std::vector<uintptr_t> calls;
  for (size_t i = 0; i < disasm_count; i++) {
    if (insns[i].id == X86_INS_INT3) { // padding, stop disassembling
      break;
    }

    if (insns[i].id == X86_INS_CALL) {
      if (insns[i].detail) {
        cs_x86 *x86 = &insns[i].detail->x86;
        if (x86->op_count == 1) {
          const cs_x86_op *op = &x86->operands[0];
          uintptr_t call_addr = 0;
          if (op->type == X86_OP_IMM) {
            call_addr = static_cast<uintptr_t>(op->imm);
          } else if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP) {
            call_addr = static_cast<uintptr_t>(insns[i].address + insns[i].size + op->mem.disp);
          }

          if (call_addr != 0) {
            calls.push_back(call_addr);
          }
        }
      }
    }
  }

  cs_free(insns, disasm_count);

  lua->createtable(L, static_cast<int>(calls.size()), 0);
  for (size_t i = 0; i < calls.size(); i++) {
    lua->pushnumber(L, static_cast<double>(calls[i]));
    lua->rawseti(L, -2, static_cast<int>(i + 1));
  }
  return 1;
}

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 1);

  lua->pushcclosure(L, reinterpret_cast<void *>(at), 0);
  lua->setfield(L, -2, "at");

  lua->pushcclosure(L, reinterpret_cast<void *>(pull_global), 0);
  lua->setfield(L, -2, "pull_global");

  lua->pushcclosure(L, reinterpret_cast<void *>(pull_all_globals), 0);
  lua->setfield(L, -2, "pull_all_globals");

  lua->pushcclosure(L, reinterpret_cast<void *>(pull_calls), 0);
  lua->setfield(L, -2, "pull_calls");

  lua->setfield(L, -2, "disasm");
}

} // namespace api::disasm
