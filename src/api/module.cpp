#include "module.hpp"
#include "../globals.hpp"
#include "../util/module.hpp"

#include "../util/call-auth.hpp"
#include "../util/sigmask.hpp"
#include "../util/sigscan.hpp"

#include <cstdio>
#include <vector>

namespace api::module {

// module.find(name: string) -> lightuserdata | nil
static int find(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  const char *name = lua->tolstring(L, 1, nullptr);
  auto info = util::get_module_info(name);

  if (info.valid()) {
    lua->pushlightuserdata(L, info.handle);
  } else {
    return 0;
  }
  return 1;
}

// module.name(handle: lightuserdata) -> string
static int name(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));

  char buffer[MAX_PATH];
  if (GetModuleBaseNameA(GetCurrentProcess(), handle, buffer, MAX_PATH)) {
    lua->pushstring(L, buffer);
  } else {
    lua->pushstring(L, "");
  }
  return 1;
}

// module.base(handle: lightuserdata) -> number
static int base(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));
  auto info = util::get_module_info(handle);

  if (info.valid()) {
    lua->pushnumber(L, static_cast<double>(info.base));
  } else {
    lua->pushnumber(L, 0);
  }
  return 1;
}

// module.size(handle: lightuserdata) -> number
static int size(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));
  auto info = util::get_module_info(handle);

  lua->pushnumber(L, static_cast<double>(info.size));
  return 1;
}

// module.export(handle: lightuserdata, name: string) -> number
static int get_export(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));
  const char *export_name = lua->tolstring(L, 2, nullptr);

  auto addr = reinterpret_cast<uintptr_t>(GetProcAddress(handle, export_name));
  lua->pushnumber(L, static_cast<double>(addr));
  return 1;
}

// module.bind_export(handle: lightuserdata, name: string, signature: string) -> function | nil
static int bind_export(lua_State* L) {
  // It won't be pretty if we try to reuse functionality at the C++ level, so we'll just literally
  // push the binding to the stack and call it, since this is not necessarily a hot path.
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));
  const char* export_name = lua->tolstring(L, 2, nullptr);
  const char* signature = lua->tolstring(L, 3, nullptr);

  const auto addr = reinterpret_cast<uintptr_t>(GetProcAddress(handle, export_name));
  if (!addr) {
    lua->pushnil(L);
    return 1;
  }

  lua->pushljeenv(L);
  lua->getfield(L, -1, "ffi");
  lua->getfield(L, -1, "call");
  lua->getfield(L, -1, "bind");
  lua->pushnumber(L, static_cast<double>(addr));
  lua->pushstring(L, signature);
  lua->call(L, 2, 1);
  return 1;
}

// module.exports(handle: lightuserdata) -> table {name = address, ...}
static int exports(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));
  auto mod_base = reinterpret_cast<uintptr_t>(handle);

  lua->createtable(L, 0, 0);

  auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(mod_base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return 1;

  auto nt = reinterpret_cast<IMAGE_NT_HEADERS *>(mod_base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return 1;

  auto export_dir_rva =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  if (!export_dir_rva)
    return 1;

  auto export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(mod_base + export_dir_rva);
  auto names = reinterpret_cast<uint32_t *>(mod_base + export_dir->AddressOfNames);
  auto ordinals = reinterpret_cast<uint16_t *>(mod_base + export_dir->AddressOfNameOrdinals);
  auto functions = reinterpret_cast<uint32_t *>(mod_base + export_dir->AddressOfFunctions);

  for (uint32_t i = 0; i < export_dir->NumberOfNames; i++) {
    const char *export_name = reinterpret_cast<const char *>(mod_base + names[i]);
    auto addr = mod_base + functions[ordinals[i]];

    lua->pushnumber(L, static_cast<double>(addr));
    lua->setfield(L, -2, export_name);
  }

  return 1;
}

// module.enumerate() -> table {lightuserdata, ...}
static int enumerate(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);

  HANDLE process = GetCurrentProcess();
  HMODULE modules[1024];
  DWORD needed;

  lua->createtable(L, 0, 0);

  if (EnumProcessModules(process, modules, sizeof(modules), &needed)) {
    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
      lua->pushlightuserdata(L, modules[i]);
      lua->rawseti(L, -2, static_cast<int>(i + 1));
    }
  }

  return 1;
}

// module.scan(handle: lightuserdata, pattern: string, no_mask?: boolean, all?: boolean)
//   -> number | nil              (all = false, default)
//   -> table {number, ...}       (all = true)
static int scan(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));
  const char *pattern = lua->tolstring(L, 2, nullptr);
  bool no_mask = lua->gettop(L) >= 3 && lua->toboolean(L, 3);
  bool all = lua->gettop(L) >= 4 && lua->toboolean(L, 4);

  const auto text_section = util::find_module_section(handle, ".text");
  if (text_section.size == 0) {
    return 0;
  }

  // Parse pattern + auto-mask
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> mask;

  if (no_mask) {
    if (!util::parse_pattern(pattern, bytes, mask))
      return 0;
  } else {
    std::vector<uint8_t> raw_bytes;
    std::vector<uint8_t> raw_mask;
    if (!util::parse_pattern(pattern, raw_bytes, raw_mask))
      return 0;

    bool has_wildcards = false;
    for (bool m : raw_mask) {
      if (!m) {
        has_wildcards = true;
        break;
      }
    }

    if (has_wildcards) {
      bytes = std::move(raw_bytes);
      mask = std::move(raw_mask);
    } else {
      std::string masked = util::auto_mask_pattern(raw_bytes);
      if (!masked.empty() && masked != pattern) {
        printf("[LJE-FFI] Auto-masked signature:\n  in:  %s\n  out: %s\n", pattern,
               masked.c_str());
      }
      if (!util::parse_pattern(masked.c_str(), bytes, mask))
        return 0;
    }
  }

  if (!all) {
    auto result = util::scan_memory(text_section.base, text_section.size, bytes, mask);
    if (result == 0)
      return 0;
    lua->pushnumber(L, static_cast<double>(result));
    return 1;
  }

  // Find all matches
  lua->createtable(L, 0, 0);
  int idx = 1;
  uintptr_t cursor = text_section.base;
  uintptr_t end = text_section.base + text_section.size;
  while (cursor < end) {
    uintptr_t found = util::scan_memory(cursor, end - cursor, bytes, mask);
    if (found == 0)
      break;
    lua->pushnumber(L, static_cast<double>(found));
    lua->rawseti(L, -2, idx++);
    cursor = found + 1;
  }
  return 1;
}

// module.sections(handle: lightuserdata) -> table { {name, base, size, characteristics}, ... }
static int sections(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));

  auto secs = util::get_module_sections(handle);

  lua->createtable(L, static_cast<int>(secs.size()), 0);
  for (size_t i = 0; i < secs.size(); i++) {
    lua->createtable(L, 0, 4);

    lua->pushstring(L, secs[i].name);
    lua->setfield(L, -2, "name");

    lua->pushnumber(L, static_cast<double>(secs[i].base));
    lua->setfield(L, -2, "base");

    lua->pushnumber(L, static_cast<double>(secs[i].size));
    lua->setfield(L, -2, "size");

    lua->pushnumber(L, static_cast<double>(secs[i].characteristics));
    lua->setfield(L, -2, "characteristics");

    lua->rawseti(L, -2, static_cast<int>(i + 1));
  }
  return 1;
}

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 7);

  lua->pushcclosure(L, reinterpret_cast<void *>(find), 0);
  lua->setfield(L, -2, "find");

  lua->pushcclosure(L, reinterpret_cast<void *>(name), 0);
  lua->setfield(L, -2, "name");

  lua->pushcclosure(L, reinterpret_cast<void *>(base), 0);
  lua->setfield(L, -2, "base");

  lua->pushcclosure(L, reinterpret_cast<void *>(size), 0);
  lua->setfield(L, -2, "size");

  lua->pushcclosure(L, reinterpret_cast<void *>(get_export), 0);
  lua->setfield(L, -2, "export");

  lua->pushcclosure(L, reinterpret_cast<void *>(bind_export), 0);
  lua->setfield(L, -2, "bind_export");

  lua->pushcclosure(L, reinterpret_cast<void *>(exports), 0);
  lua->setfield(L, -2, "exports");

  lua->pushcclosure(L, reinterpret_cast<void *>(enumerate), 0);
  lua->setfield(L, -2, "enumerate");

  lua->pushcclosure(L, reinterpret_cast<void *>(scan), 0);
  lua->setfield(L, -2, "scan");

  lua->pushcclosure(L, reinterpret_cast<void *>(sections), 0);
  lua->setfield(L, -2, "sections");

  lua->setfield(L, -2, "module");
}

} // namespace api::module
