#include "vtable.hpp"
#include "../globals.hpp"
#include "mem.hpp"

#include <cstdint>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include "../util/memscan.hpp"
#include "../util/module.hpp"
#include "../util/sigscan.hpp"

#include <Windows.h>
#include <cstdio>

namespace api::vtable {
namespace {
constexpr auto NULL_POINTER_PATTERN = "00 00 00 00 00 00 00 00";
}
using api::mem::t_jmp_buf;
using api::mem::t_protected;

// vtable.base(obj: number) -> number | nil
// Gets the vtable pointer from an object (first pointer in object)
static int base(lua_State *L) {
  auto lua = g_api->lua;
  auto obj = static_cast<uintptr_t>(lua->tonumber(L, 1));

  t_protected = true;
  if (setjmp(t_jmp_buf) == 0) {
    auto vtbl = *reinterpret_cast<uintptr_t *>(obj);
    t_protected = false;
    lua->pushnumber(L, static_cast<double>(vtbl));
    return 1;
  } else {
    t_protected = false;
    return 0;
  }
}

// vtable.get(obj: number, index: number) -> number | nil
// Gets the function pointer at vtable[index]
static int get(lua_State *L) {
  auto lua = g_api->lua;
  auto obj = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto index = static_cast<size_t>(lua->tonumber(L, 2));

  t_protected = true;
  if (setjmp(t_jmp_buf) == 0) {
    auto vtbl = *reinterpret_cast<uintptr_t *>(obj);
    auto func = reinterpret_cast<uintptr_t *>(vtbl)[index];
    t_protected = false;
    lua->pushnumber(L, static_cast<double>(func));
    return 1;
  } else {
    t_protected = false;
    return 0;
  }
}

// vtable.get_from(vtbl: number, index: number) -> number | nil
// Gets the function pointer at vtable[index] from a vtable pointer directly
static int get_from(lua_State *L) {
  auto lua = g_api->lua;
  auto vtbl = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto index = static_cast<size_t>(lua->tonumber(L, 2));

  t_protected = true;
  if (setjmp(t_jmp_buf) == 0) {
    auto func = reinterpret_cast<uintptr_t *>(vtbl)[index];
    t_protected = false;
    lua->pushnumber(L, static_cast<double>(func));
    return 1;
  } else {
    t_protected = false;
    return 0;
  }
}

// vtable.set(obj: number, index: number, func: number) -> boolean
// Sets the function pointer at vtable[index] (requires writable vtable)
static int set(lua_State *L) {
  auto lua = g_api->lua;
  auto obj = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto index = static_cast<size_t>(lua->tonumber(L, 2));
  auto func = static_cast<uintptr_t>(lua->tonumber(L, 3));

  t_protected = true;
  if (setjmp(t_jmp_buf) == 0) {
    auto vtbl = *reinterpret_cast<uintptr_t *>(obj);
    reinterpret_cast<uintptr_t *>(vtbl)[index] = func;
    t_protected = false;
    lua->pushboolean(L, 1);
    return 1;
  } else {
    t_protected = false;
    lua->pushboolean(L, 0);
    return 1;
  }
}

// vtable.set_from(vtbl: number, index: number, func: number) -> boolean
// Sets the function pointer at vtable[index] from a vtable pointer directly
static int set_from(lua_State *L) {
  auto lua = g_api->lua;
  auto vtbl = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto index = static_cast<size_t>(lua->tonumber(L, 2));
  auto func = static_cast<uintptr_t>(lua->tonumber(L, 3));

  t_protected = true;
  if (setjmp(t_jmp_buf) == 0) {
    reinterpret_cast<uintptr_t *>(vtbl)[index] = func;
    t_protected = false;
    lua->pushboolean(L, 1);
    return 1;
  } else {
    t_protected = false;
    lua->pushboolean(L, 0);
    return 1;
  }
}

// vtable.size(vtbl: number) -> number
// Estimates vtable size by counting valid function pointers
static int size(lua_State *L) {
  auto lua = g_api->lua;
  auto vtbl = static_cast<uintptr_t>(lua->tonumber(L, 1));

  size_t count = 0;
  t_protected = true;

  while (true) {
    if (setjmp(t_jmp_buf) == 0) {
      auto ptr = reinterpret_cast<uintptr_t *>(vtbl)[count];
      t_protected = false;

      // Check if it looks like a valid code pointer
      // Basic heuristic: non-null and in a reasonable range
      if (ptr == 0 || ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) {
        break;
      }

      // Check if the target memory is executable
      MEMORY_BASIC_INFORMATION mbi;
      if (VirtualQuery(reinterpret_cast<void *>(ptr), &mbi, sizeof(mbi))) {
        if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                             PAGE_EXECUTE_WRITECOPY))) {
          break;
        }
      } else {
        break;
      }

      count++;
      t_protected = true;
    } else {
      t_protected = false;
      break;
    }
  }

  lua->pushnumber(L, static_cast<double>(count));
  return 1;
}

/* Converts something like ABAB to 41 42 41 42, padding with zeros for the hex pattern. */
static void stringToPattern(const char *str, char *pattern, size_t patternSize) {
  size_t j = 0;
  for (size_t i = 0; str[i] != '\0' && j < patternSize - 1; i++) {
    if (str[i] == ' ') {
      continue; // Skip spaces in the input string
    }

    if (j + 2 >= patternSize) {
      break; // Not enough space for another byte and a space
    }

    uint8_t byte = static_cast<uint8_t>(str[i]);
    std::snprintf(pattern + j, 4, "%02X ", byte);
    j += 3; // Move past the two hex digits and the space
  }

  pattern[j > 0 ? j - 1 : 0] = '\0'; // Remove trailing space and null-terminate
}

static void addressToPattern(uintptr_t address, char *pattern, size_t patternSize) {
  std::snprintf(pattern, patternSize, "%02X %02X %02X %02X %02X %02X %02X %02X",
                (address >> 0) & 0xFF, (address >> 8) & 0xFF, (address >> 16) & 0xFF,
                (address >> 24) & 0xFF, (address >> 32) & 0xFF, (address >> 40) & 0xFF,
                (address >> 48) & 0xFF, (address >> 56) & 0xFF);
}

static void ibo32ToPattern(uint32_t value, char *pattern, size_t patternSize) {
  std::snprintf(pattern, patternSize, "%02X %02X %02X %02X", value & 0xFF,
                (value >> 8) & 0xFF, (value >> 16) & 0xFF, (value >> 24) & 0xFF);
}

/* This is a RTTI-based algorithm to search for and identify module vtables through three relations,
 * type descriptor ---\
 *                   |
 *                   complete object locator ---\
 *                                              vftable meta ptr --> vtable
 * Returns the vtable address, or 0 on failure.
 */
static uintptr_t find_vtable_rtti(HMODULE handle, const char *name) {
  const auto info = util::get_module_info(handle);
  if (!info.valid())
    return 0;

  const auto data_section = util::find_module_section(handle, ".data");
  const auto rdata_section = util::find_module_section(handle, ".rdata");
  if (data_section.size == 0 || rdata_section.size == 0)
    return 0;

  const auto to_ibo32 = [&](uintptr_t addr) -> uint32_t {
    return static_cast<uint32_t>(addr - info.base);
  };

  char type_descriptor_pattern[512];
  char rtti_object_name[256];
  std::snprintf(rtti_object_name, sizeof(rtti_object_name), ".?AV%s@@", name);

  char rttiObjectPattern[512];
  stringToPattern(rtti_object_name, rttiObjectPattern, sizeof(rttiObjectPattern));

  std::snprintf(type_descriptor_pattern, sizeof(type_descriptor_pattern), "%s %s 00",
                NULL_POINTER_PATTERN, rttiObjectPattern);

  const auto type_descriptor_addr =
      util::sigscan(data_section.base, data_section.size, type_descriptor_pattern);
  if (!type_descriptor_addr)
    return 0;

  uint32_t type_descriptor_ibo32 = to_ibo32(type_descriptor_addr - sizeof(uintptr_t));
  char type_descriptor_ibo32_pattern[128];
  ibo32ToPattern(type_descriptor_ibo32, type_descriptor_ibo32_pattern,
                 sizeof(type_descriptor_ibo32_pattern));

  char object_locator_pattern[512];
  std::snprintf(object_locator_pattern, sizeof(object_locator_pattern),
                "01 00 00 00 00 00 00 00 00 00 00 00 %s",
                type_descriptor_ibo32_pattern);

  const auto object_locator_addr =
      util::sigscan(rdata_section.base, rdata_section.size, object_locator_pattern);
  if (!object_locator_addr)
    return 0;

  char meta_ptr_pattern[128];
  addressToPattern(object_locator_addr, meta_ptr_pattern, sizeof(meta_ptr_pattern));

  const auto meta_ptr_addr =
      util::sigscan(rdata_section.base, rdata_section.size, meta_ptr_pattern);
  if (!meta_ptr_addr)
    return 0;

  return meta_ptr_addr + sizeof(uintptr_t);
}

// vtable.find(handle: lightuserdata, name: string) -> number | nil
static int find(lua_State *L) {
  auto lua = g_api->lua;
  const auto handle = util::lua_to_module(L, 1, lua->tolightuserdata);
  const auto name = lua->tolstring(L, 2, nullptr);
  if (!handle || !name)
    return 0;

  auto vtable = find_vtable_rtti(handle, name);
  if (!vtable)
    return 0;

  lua->pushnumber(L, static_cast<double>(vtable));
  return 1;
}

// vtable.find_instances(handle: lightuserdata, name: string, multiple?: boolean)
//   -> table {number, ...}
// vtable.find_instances(handle, name, multiple?, min_size?) -> table {number, ...}
// Finds class instances by scanning for the vtable pointer.
// First tries the module's own sections, then falls back to a process-wide memory scan.
static int find_instances(lua_State *L) {
  auto lua = g_api->lua;
  const auto handle = util::lua_to_module(L, 1, lua->tolightuserdata);
  const auto name = lua->tolstring(L, 2, nullptr);
  bool multiple = lua->gettop(L) >= 3 && lua->toboolean(L, 3);
  size_t min_size = lua->gettop(L) >= 4 ? static_cast<size_t>(lua->tonumber(L, 4)) : 0x100000;
  if (!handle || !name)
    return 0;

  auto vtable = find_vtable_rtti(handle, name);
  if (!vtable)
    return 0;

  // Build pattern bytes for the vtable address (little-endian)
  std::vector<uint8_t> bytes(8);
  std::vector<uint8_t> mask(8, 1);
  for (int i = 0; i < 8; i++)
    bytes[i] = static_cast<uint8_t>((vtable >> (i * 8)) & 0xFF);

  // Exclude the bytes vector's own heap buffer from results
  uintptr_t self_buf = reinterpret_cast<uintptr_t>(bytes.data());
  uintptr_t self_buf_end = self_buf + bytes.size();

  // Phase 1: scan the module itself
  const auto info = util::get_module_info(handle);
  // We can cut down the search space a lot by just using .data
  // There's basically no way a static class would end up in .rdata since it contains only read-only data.
  const auto data_section = util::find_module_section(handle, ".data");
  std::vector<uintptr_t> results;

  if (info.valid()) {
    uintptr_t cursor = data_section.base;
    uintptr_t end = data_section.base + data_section.size;
    while (cursor < end) {
      uintptr_t found = util::scan_memory(cursor, end - cursor, bytes, mask);
      if (found == 0)
        break;
      results.push_back(found);
      if (!multiple && !results.empty())
        break;
      cursor = found + 1;
    }
  }

  if (!results.empty()) {
    lua->createtable(L, static_cast<int>(results.size()), 0);
    for (size_t i = 0; i < results.size(); i++) {
      lua->pushnumber(L, static_cast<double>(results[i]));
      lua->rawseti(L, -2, static_cast<int>(i + 1));
    }
    return 1;
  }

  // Phase 2: fall back to process-wide memory scan (rw-, non-image, >= 1MB regions)
  results = util::scan_process_memory(bytes, mask, min_size, self_buf, self_buf_end);

  lua->createtable(L, static_cast<int>(results.size()), 0);
  for (size_t i = 0; i < results.size(); i++) {
    lua->pushnumber(L, static_cast<double>(results[i]));
    lua->rawseti(L, -2, static_cast<int>(i + 1));
  }
  return 1;
}

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 6);

  lua->pushcclosure(L, reinterpret_cast<void *>(base), 0);
  lua->setfield(L, -2, "base");

  lua->pushcclosure(L, reinterpret_cast<void *>(get), 0);
  lua->setfield(L, -2, "get");

  lua->pushcclosure(L, reinterpret_cast<void *>(get_from), 0);
  lua->setfield(L, -2, "get_from");

  lua->pushcclosure(L, reinterpret_cast<void *>(set), 0);
  lua->setfield(L, -2, "set");

  lua->pushcclosure(L, reinterpret_cast<void *>(set_from), 0);
  lua->setfield(L, -2, "set_from");

  lua->pushcclosure(L, reinterpret_cast<void *>(size), 0);
  lua->setfield(L, -2, "size");

  lua->pushcclosure(L, reinterpret_cast<void *>(find), 0);
  lua->setfield(L, -2, "find");

  lua->pushcclosure(L, reinterpret_cast<void *>(find_instances), 0);
  lua->setfield(L, -2, "find_instances");

  lua->setfield(L, -2, "vtable");
}

} // namespace api::vtable
