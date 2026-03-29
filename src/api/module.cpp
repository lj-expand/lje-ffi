#include "module.hpp"
#include "../globals.hpp"
#include "../util/module.hpp"

#include "../util/call-auth.hpp"
#include "../util/sigmask.hpp"
#include "../util/sigscan.hpp"

#include <DbgHelp.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace api::module {

// MSVC x64 RTTI structures
struct RTTICompleteObjectLocator {
  uint32_t signature;       // 1 on x64
  uint32_t offset;
  uint32_t cdOffset;
  uint32_t pTypeDescriptor; // RVA from image base
  uint32_t pClassHierarchy; // RVA from image base
  uint32_t pSelf;           // RVA to this COL (x64 only)
};

struct RTTITypeDescriptor {
  void    *pVFTable;        // pointer to type_info's vtable
  void    *spare;
  char     name[1];         // mangled name, e.g. ".?AVFoo@@"
};

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

// module.is_system(handle: lightuserdata) -> boolean
static int is_system(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));

  char mod_path[MAX_PATH];
  if (!GetModuleFileNameExA(GetCurrentProcess(), handle, mod_path, MAX_PATH)) {
    lua->pushboolean(L, false);
    return 1;
  }

  char win_dir[MAX_PATH];
  UINT win_dir_len = GetWindowsDirectoryA(win_dir, MAX_PATH);

  bool result = win_dir_len > 0 &&
                _strnicmp(mod_path, win_dir, win_dir_len) == 0;
  lua->pushboolean(L, result);
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

// Demangles an MSVC RTTI type descriptor name (e.g. ".?AVIRecipientFilter@@" -> "IRecipientFilter").
//
// RTTI name format: .?A<kind><components>@@
//   kind:       V=class, U=struct, W=enum, T=union, ...
//   components: @-separated name parts, innermost first  e.g. "Foo@MyNS@" -> "MyNS::Foo"
//
// UnDecorateSymbolName does not understand the RTTI type-descriptor format directly —
// passing "?AVFoo@@" leaves "AV" in the output. We therefore strip ".?A<kind>" ourselves
// and only delegate to DbgHelp for template names (?$...), where we wrap the template name
// in a dummy function signature that DbgHelp can decode into e.g. "NS::Foo<int>".
static std::string demangle_rtti_name(const char *mangled) {
  if (!mangled) return "";

  // Regular decorated name (export, symbol) — pass straight to DbgHelp.
  if (mangled[0] == '?') {
    char buf[2048];
    if (UnDecorateSymbolName(mangled, buf, sizeof(buf), UNDNAME_NAME_ONLY))
      return buf;
    return mangled;
  }

  if (mangled[0] != '.' || mangled[1] != '?' || mangled[2] != 'A')
    return mangled;

  // Skip ".?A<kind>" — 4 chars total (dot, question, A, type indicator)
  const char *name_start = mangled + 4;

  if (name_start[0] == '?' && name_start[1] == '$') {
    // Template type. Construct a dummy __cdecl void() function mangled name so DbgHelp
    // can decode the template parameters. e.g. "?$Foo@H@NS@@" -> "??$Foo@H@NS@@YAXXZ"
    // which UnDecorateSymbolName(UNDNAME_NAME_ONLY) decodes to "NS::Foo<int>".
    std::string wrapper;
    wrapper.reserve(strlen(name_start) + 8);
    wrapper  = '?';      // decorated name start
    wrapper += name_start; // "?$Foo@H@NS@@"
    wrapper += "YAXXZ"; // dummy: __cdecl, returns void, no params

    char buf[2048];
    if (UnDecorateSymbolName(wrapper.c_str(), buf, sizeof(buf), UNDNAME_NAME_ONLY))
      return buf;

    // DbgHelp failed — at least return the template class name without params
    const char *end = strchr(name_start + 2, '@');
    return end ? std::string(name_start + 2, end) + "<...>" : std::string(name_start + 2);
  }

  // Non-template: split on '@' and reverse components for "Outer::Inner" order.
  std::vector<std::string> parts;
  const char *start = name_start;
  for (const char *p = name_start; *p; ++p) {
    if (*p == '@') {
      if (p == start) break; // empty component = @@ terminator
      std::string comp(start, p - start);
      // Anonymous namespace encodes as "?A0x<hex>" — normalise it.
      if (comp.size() >= 2 && comp[0] == '?' && comp[1] == 'A')
        comp = "(anonymous namespace)";
      parts.push_back(std::move(comp));
      start = p + 1;
    }
  }

  if (parts.empty()) return mangled;

  std::string result;
  for (int i = static_cast<int>(parts.size()) - 1; i >= 0; --i) {
    if (!result.empty()) result += "::";
    result += parts[i];
  }
  return result;
}

// module.demangle(name: string) -> string
// Demangles an MSVC RTTI type descriptor name.
static int demangle(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  const char *mangled = lua->tolstring(L, 1, nullptr);
  auto result = demangle_rtti_name(mangled);
  lua->pushstring(L, result.c_str());
  return 1;
}

// module.rtti_classes(handle: lightuserdata) -> table { {name, col, td, vtable?}, ... }
// Enumerates all MSVC RTTI classes in the module's .rdata section.
// Requires RTTI to be enabled (/GR) in the target module.
// For classes with multiple inheritance, multiple entries may share the same name
// (one per COL/vtable, as each base subobject gets its own COL).
static int rtti_classes(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto handle = static_cast<HMODULE>(lua->tolightuserdata(L, 1));

  auto info = util::get_module_info(handle);
  if (!info.valid()) {
    lua->createtable(L, 0, 0);
    return 1;
  }

  const uintptr_t base    = info.base;
  const uintptr_t mod_end = base + info.size;

  auto rdata = util::find_module_section(handle, ".rdata");
  if (rdata.size == 0) {
    lua->createtable(L, 0, 0);
    return 1;
  }

  struct ClassEntry {
    uintptr_t   col;
    uintptr_t   td;
    uintptr_t   vtable; // 0 if not found
    const char *name;   // points into mapped module memory
  };

  std::vector<ClassEntry> entries;
  std::unordered_map<uintptr_t, size_t> col_to_idx;

  const uintptr_t rdata_start = rdata.base;
  const uintptr_t rdata_end   = rdata.base + rdata.size;

  // Pass 1: find all valid COLs.
  // A COL is valid if signature == 1 and base + pSelf == col_address.
  for (uintptr_t cursor = rdata_start; cursor + sizeof(RTTICompleteObjectLocator) <= rdata_end; cursor += 4) {
    auto col = reinterpret_cast<const RTTICompleteObjectLocator *>(cursor);

    if (col->signature != 1 || col->pSelf == 0)
      continue;
    if (base + static_cast<uintptr_t>(col->pSelf) != cursor)
      continue;
    if (col->pTypeDescriptor == 0)
      continue;

    uintptr_t td_addr = base + static_cast<uintptr_t>(col->pTypeDescriptor);
    // Validate td is within the module and large enough to hold the fixed fields + at least ".?A\0"
    if (td_addr < base || td_addr + sizeof(RTTITypeDescriptor) + 3 > mod_end)
      continue;

    auto td = reinterpret_cast<const RTTITypeDescriptor *>(td_addr);
    const char *name = td->name;

    // All MSVC RTTI names start with ".?A" (.?AV = class, .?AU = struct, .?AW = enum, etc.)
    if (name[0] != '.' || name[1] != '?' || name[2] != 'A')
      continue;

    size_t idx = entries.size();
    col_to_idx[cursor] = idx;
    entries.push_back({cursor, td_addr, 0, name});
  }

  // Pass 2: scan all non-executable data sections for 8-byte-aligned pointers to any COL.
  // The 8 bytes immediately before a vtable contain a pointer to its COL.
  // So: vtable = backpointer_address + 8.
  // We scan beyond .rdata because some builds (especially games that hot-patch vtables)
  // emit vtables in .data (read-write) rather than .rdata (read-only).
  auto all_sections = util::get_module_sections(handle);
  for (const auto &sec : all_sections) {
    // Skip executable sections — vtable backpointers are never in code.
    if (sec.characteristics & IMAGE_SCN_MEM_EXECUTE)
      continue;
    // Skip empty sections.
    if (sec.size < 8)
      continue;

    uintptr_t sec_start = sec.base;
    uintptr_t sec_end   = sec.base + sec.size;

    // Align start up to 8-byte boundary.
    uintptr_t p2_start = (sec_start + 7) & ~uintptr_t(7);

    for (uintptr_t cursor = p2_start; cursor + 8 <= sec_end; cursor += 8) {
      uintptr_t val = *reinterpret_cast<const uintptr_t *>(cursor);
      auto it = col_to_idx.find(val);
      if (it == col_to_idx.end())
        continue;
      entries[it->second].vtable = cursor + 8;
    }
  }

  // Build Lua table
  lua->createtable(L, static_cast<int>(entries.size()), 0);
  for (size_t i = 0; i < entries.size(); i++) {
    const auto &e = entries[i];
    lua->createtable(L, 0, 4);

    lua->pushstring(L, e.name);
    lua->setfield(L, -2, "name");

    lua->pushnumber(L, static_cast<double>(e.col));
    lua->setfield(L, -2, "col");

    lua->pushnumber(L, static_cast<double>(e.td));
    lua->setfield(L, -2, "td");

    if (e.vtable != 0) {
      lua->pushnumber(L, static_cast<double>(e.vtable));
      lua->setfield(L, -2, "vtable");
    }

    lua->rawseti(L, -2, static_cast<int>(i + 1));
  }
  return 1;
}

// module.get_from_addr(addr: number) -> lightuserdata | nil
// Fetches what module (if any) the given address belongs to.
static int get_from_addr(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));

  HMODULE handle = nullptr;
  if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(addr), &handle)) {
    lua->pushlightuserdata(L, handle);
    return 1;
  }

  return 0;
}

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 8);

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

  lua->pushcclosure(L, reinterpret_cast<void *>(is_system), 0);
  lua->setfield(L, -2, "is_system");

  lua->pushcclosure(L, reinterpret_cast<void *>(rtti_classes), 0);
  lua->setfield(L, -2, "rtti_classes");

  lua->pushcclosure(L, reinterpret_cast<void *>(demangle), 0);
  lua->setfield(L, -2, "demangle");

  lua->pushcclosure(L, reinterpret_cast<void *>(get_from_addr), 0);
  lua->setfield(L, -2, "get_from_addr");

  lua->setfield(L, -2, "module");
}

} // namespace api::module
