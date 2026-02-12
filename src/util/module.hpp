#pragma once

#include <cstdint>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

namespace util {

struct ModuleInfo {
  HMODULE handle;
  uintptr_t base;
  size_t size;

  bool valid() const { return handle != nullptr; }
};

struct SectionInfo {
  char name[IMAGE_SIZEOF_SHORT_NAME + 1]; // null-terminated
  uintptr_t base;
  size_t size;
  DWORD characteristics;
};

// Get module info from handle
inline ModuleInfo get_module_info(HMODULE handle) {
  ModuleInfo info = {handle, 0, 0};

  if (handle) {
    MODULEINFO mi{};
    if (GetModuleInformation(GetCurrentProcess(), handle, &mi, sizeof(mi))) {
      info.base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
      info.size = mi.SizeOfImage;
    }
  }

  return info;
}

// Get module info by name
inline ModuleInfo get_module_info(const char *name) {
  return get_module_info(GetModuleHandleA(name));
}

// Extract HMODULE from Lua lightuserdata at given index
inline HMODULE lua_to_module(void *L, int idx, void *(*tolightuserdata)(void *, int)) {
  return static_cast<HMODULE>(tolightuserdata(L, idx));
}

// Get module info from Lua lightuserdata
inline ModuleInfo get_module_info_lua(void *L, int idx, void *(*tolightuserdata)(void *, int)) {
  return get_module_info(lua_to_module(L, idx, tolightuserdata));
}

// Get all PE sections for a module
inline std::vector<SectionInfo> get_module_sections(HMODULE handle) {
  std::vector<SectionInfo> sections;
  if (!handle)
    return sections;

  auto mod_base = reinterpret_cast<uintptr_t>(handle);
  auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(mod_base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return sections;

  auto nt = reinterpret_cast<IMAGE_NT_HEADERS *>(mod_base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return sections;

  auto section = IMAGE_FIRST_SECTION(nt);
  for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
    SectionInfo info;
    memcpy(info.name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
    info.name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
    info.base = mod_base + section->VirtualAddress;
    info.size = section->Misc.VirtualSize;
    info.characteristics = section->Characteristics;
    sections.push_back(info);
  }

  return sections;
}

// Find a specific section by name
inline SectionInfo find_module_section(HMODULE handle, const char *name) {
  auto sections = get_module_sections(handle);
  for (auto &s : sections) {
    if (strcmp(s.name, name) == 0)
      return s;
  }
  return {"", 0, 0, 0};
}

} // namespace util
