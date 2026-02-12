#include "mem.hpp"
#include "../globals.hpp"
#include "../util/memscan.hpp"
#include "../util/sigmask.hpp"
#include "../util/sigscan.hpp"

#include <csetjmp>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace api::mem {

// Exception handling for try_read_* functions.
// This works by longjmping out of a VEH. We restrain the jmp_buf
// to be only within the context of a single memory operation, it is highly unlikely to cause
// any actual problems, and allows us to prevent crashes when trying to read from invalid memory
// addresses from Lua.
thread_local jmp_buf t_jmp_buf;
thread_local bool t_protected = false;

static bool is_preventable_exception(DWORD code) {
  return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_GUARD_PAGE ||
         code == EXCEPTION_IN_PAGE_ERROR;
}

static LONG WINAPI veh_handler(EXCEPTION_POINTERS *ep) {
  if (t_protected && is_preventable_exception(ep->ExceptionRecord->ExceptionCode)) {
    longjmp(t_jmp_buf, 1);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

static bool s_veh_installed = false;

void install_veh() {
  if (!s_veh_installed) {
    AddVectoredExceptionHandler(1, veh_handler);
    s_veh_installed = true;
  }
}

// mem.alloc(size: number) -> number (address)
static int alloc(lua_State *L) {
  auto lua = g_api->lua;
  auto size = static_cast<size_t>(lua->tonumber(L, 1));
  void *ptr = malloc(size);
  lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(ptr)));
  return 1;
}

// mem.free(address: number)
static int free_(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  free(reinterpret_cast<void *>(addr));
  return 0;
}

// mem.copy(dest: number, src: number, size: number)
static int copy(lua_State *L) {
  auto lua = g_api->lua;
  auto dest = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto src = static_cast<uintptr_t>(lua->tonumber(L, 2));
  auto size = static_cast<size_t>(lua->tonumber(L, 3));
  memcpy(reinterpret_cast<void *>(dest), reinterpret_cast<void *>(src), size);
  return 0;
}

// mem.fill(address: number, value: number, size: number)
static int fill(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto value = static_cast<int>(lua->tonumber(L, 2));
  auto size = static_cast<size_t>(lua->tonumber(L, 3));
  memset(reinterpret_cast<void *>(addr), value, size);
  return 0;
}

// Read functions
static int read_u8(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uint8_t *>(addr)));
  return 1;
}

static int read_i8(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<int8_t *>(addr)));
  return 1;
}

static int read_u16(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uint16_t *>(addr)));
  return 1;
}

static int read_i16(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<int16_t *>(addr)));
  return 1;
}

static int read_u32(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uint32_t *>(addr)));
  return 1;
}

static int read_i32(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<int32_t *>(addr)));
  return 1;
}

static int read_u64(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uint64_t *>(addr)));
  return 1;
}

static int read_i64(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<int64_t *>(addr)));
  return 1;
}

static int read_f32(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<float *>(addr)));
  return 1;
}

static int read_f64(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, *reinterpret_cast<double *>(addr));
  return 1;
}

static int read_ptr(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  lua->pushnumber(L, static_cast<double>(*reinterpret_cast<uintptr_t *>(addr)));
  return 1;
}

// mem.read_string(address: number, max_len?: number) -> string
static int read_string(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto ptr = reinterpret_cast<const char *>(addr);

  if (lua->gettop(L) >= 2) {
    auto max_len = static_cast<size_t>(lua->tonumber(L, 2));
    size_t len = strnlen(ptr, max_len);
    // Push string with explicit length
    char *buf = static_cast<char *>(alloca(len + 1));
    memcpy(buf, ptr, len);
    buf[len] = '\0';
    lua->pushstring(L, buf);
  } else {
    lua->pushstring(L, ptr);
  }
  return 1;
}

// Protected read functions - return value, nil on success; nil, error on failure
#define TRY_READ_FUNC(name, type, cast)                                                            \
  static int try_read_##name(lua_State *L) {                                                       \
    auto lua = g_api->lua;                                                                         \
    auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));                                       \
    t_protected = true;                                                                            \
    if (setjmp(t_jmp_buf) == 0) {                                                                  \
      auto val = *reinterpret_cast<type *>(addr);                                                  \
      t_protected = false;                                                                         \
      lua->pushnumber(L, static_cast<double>(cast val));                                           \
      return 1;                                                                                    \
    } else {                                                                                       \
      t_protected = false;                                                                         \
      return 0;                                                                                    \
    }                                                                                              \
  }

TRY_READ_FUNC(u8, uint8_t, )
TRY_READ_FUNC(i8, int8_t, )
TRY_READ_FUNC(u16, uint16_t, )
TRY_READ_FUNC(i16, int16_t, )
TRY_READ_FUNC(u32, uint32_t, )
TRY_READ_FUNC(i32, int32_t, )
TRY_READ_FUNC(u64, uint64_t, )
TRY_READ_FUNC(i64, int64_t, )
TRY_READ_FUNC(f32, float, )
TRY_READ_FUNC(f64, double, )
TRY_READ_FUNC(ptr, uintptr_t, )

#undef TRY_READ_FUNC

// SEH-wrapped strnlen — longjmp from VEH doesn't work reliably for CRT
// functions like strlen/strnlen because they use SSE2 vectorized reads.
// Basically, it just cannot unwind properly through those.
static size_t safe_strnlen(const char *ptr, size_t max_len) {
  __try {
    return strnlen(ptr, max_len);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return SIZE_MAX;
  }
}

// mem.try_read_string(address: number, max_len?: number) -> string | nil
static int try_read_string(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto ptr = reinterpret_cast<const char *>(addr);

  size_t max_len = lua->gettop(L) >= 2 ? static_cast<size_t>(lua->tonumber(L, 2)) : SIZE_MAX;
  size_t len = safe_strnlen(ptr, max_len);
  if (len == SIZE_MAX)
    return 0;

  char *buf = static_cast<char *>(alloca(len + 1));
  memcpy(buf, ptr, len);
  buf[len] = '\0';
  lua->pushstring(L, buf);
  return 1;
}

// Write functions
static int write_u8(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<uint8_t>(lua->tonumber(L, 2));
  *reinterpret_cast<uint8_t *>(addr) = val;
  return 0;
}

static int write_i8(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<int8_t>(lua->tonumber(L, 2));
  *reinterpret_cast<int8_t *>(addr) = val;
  return 0;
}

static int write_u16(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<uint16_t>(lua->tonumber(L, 2));
  *reinterpret_cast<uint16_t *>(addr) = val;
  return 0;
}

static int write_i16(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<int16_t>(lua->tonumber(L, 2));
  *reinterpret_cast<int16_t *>(addr) = val;
  return 0;
}

static int write_u32(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<uint32_t>(lua->tonumber(L, 2));
  *reinterpret_cast<uint32_t *>(addr) = val;
  return 0;
}

static int write_i32(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<int32_t>(lua->tonumber(L, 2));
  *reinterpret_cast<int32_t *>(addr) = val;
  return 0;
}

static int write_u64(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<uint64_t>(lua->tonumber(L, 2));
  *reinterpret_cast<uint64_t *>(addr) = val;
  return 0;
}

static int write_i64(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<int64_t>(lua->tonumber(L, 2));
  *reinterpret_cast<int64_t *>(addr) = val;
  return 0;
}

static int write_f32(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<float>(lua->tonumber(L, 2));
  *reinterpret_cast<float *>(addr) = val;
  return 0;
}

static int write_f64(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = lua->tonumber(L, 2);
  *reinterpret_cast<double *>(addr) = val;
  return 0;
}

static int write_ptr(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto val = static_cast<uintptr_t>(lua->tonumber(L, 2));
  *reinterpret_cast<uintptr_t *>(addr) = val;
  return 0;
}

// mem.write_string(address: number, str: string)
static int write_string(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  size_t len;
  const char *str = lua->tolstring(L, 2, &len);
  memcpy(reinterpret_cast<void *>(addr), str, len + 1); // include null terminator
  return 0;
}

// Protected write functions - return true on success, false on access violation
#define TRY_WRITE_FUNC(name, type)                                                                 \
  static int try_write_##name(lua_State *L) {                                                      \
    auto lua = g_api->lua;                                                                         \
    auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));                                       \
    auto val = static_cast<type>(lua->tonumber(L, 2));                                             \
    t_protected = true;                                                                            \
    if (setjmp(t_jmp_buf) == 0) {                                                                  \
      *reinterpret_cast<type *>(addr) = val;                                                       \
      t_protected = false;                                                                         \
      lua->pushboolean(L, 1);                                                                      \
      return 1;                                                                                    \
    } else {                                                                                       \
      t_protected = false;                                                                         \
      lua->pushboolean(L, 0);                                                                      \
      return 1;                                                                                    \
    }                                                                                              \
  }

TRY_WRITE_FUNC(u8, uint8_t)
TRY_WRITE_FUNC(i8, int8_t)
TRY_WRITE_FUNC(u16, uint16_t)
TRY_WRITE_FUNC(i16, int16_t)
TRY_WRITE_FUNC(u32, uint32_t)
TRY_WRITE_FUNC(i32, int32_t)
TRY_WRITE_FUNC(u64, uint64_t)
TRY_WRITE_FUNC(i64, int64_t)
TRY_WRITE_FUNC(f32, float)
TRY_WRITE_FUNC(f64, double)
TRY_WRITE_FUNC(ptr, uintptr_t)

#undef TRY_WRITE_FUNC

// mem.try_write_string(address: number, str: string) -> boolean
static int try_write_string(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  size_t len;
  const char *str = lua->tolstring(L, 2, &len);

  t_protected = true;
  if (setjmp(t_jmp_buf) == 0) {
    memcpy(reinterpret_cast<void *>(addr), str, len + 1);
    t_protected = false;
    lua->pushboolean(L, 1);
    return 1;
  } else {
    t_protected = false;
    lua->pushboolean(L, 0);
    return 1;
  }
}

// mem.sizeof(type: string) -> number
static int sizeof_(lua_State *L) {
  auto lua = g_api->lua;
  const char *type = lua->tolstring(L, 1, nullptr);

  size_t size = 0;
  if (strcmp(type, "u8") == 0 || strcmp(type, "i8") == 0)
    size = 1;
  else if (strcmp(type, "u16") == 0 || strcmp(type, "i16") == 0)
    size = 2;
  else if (strcmp(type, "u32") == 0 || strcmp(type, "i32") == 0 || strcmp(type, "f32") == 0)
    size = 4;
  else if (strcmp(type, "u64") == 0 || strcmp(type, "i64") == 0 || strcmp(type, "f64") == 0)
    size = 8;
  else if (strcmp(type, "ptr") == 0)
    size = sizeof(void *);

  lua->pushnumber(L, static_cast<double>(size));
  return 1;
}

// mem.unwrap_userdata(userdata) -> number (address)
static int unwrap_userdata(lua_State *L) {
  auto lua = g_api->lua;
  auto ptr = lua->tolightuserdata(L, 1);
  lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(ptr)));
  return 1;
}

static DWORD parse_protection(const char *rights) {
  bool r = false, w = false, x = false;
  for (const char *c = rights; *c; c++) {
    if (*c == 'r' || *c == 'R')
      r = true;
    if (*c == 'w' || *c == 'W')
      w = true;
    if (*c == 'x' || *c == 'X')
      x = true;
  }

  if (x && w)
    return PAGE_EXECUTE_READWRITE;
  if (x && r)
    return PAGE_EXECUTE_READ;
  if (x)
    return PAGE_EXECUTE;
  if (w)
    return PAGE_READWRITE;
  if (r)
    return PAGE_READONLY;
  return PAGE_NOACCESS;
}

// mem.protect(address: number, size: number, rights: string) -> boolean, old_rights
static int protect(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto size = static_cast<size_t>(lua->tonumber(L, 2));
  const char *rights = lua->tolstring(L, 3, nullptr);

  DWORD new_prot = parse_protection(rights);
  DWORD old_prot = 0;

  BOOL success = VirtualProtect(reinterpret_cast<void *>(addr), size, new_prot, &old_prot);
  lua->pushboolean(L, success ? 1 : 0);
  return 1;
}

// mem.deref(base: number, offsets: table) -> number | nil
// Follows pointer chain: [[base+off1]+off2]+off3...
static int deref(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));

  // Iterate through offsets table
  int len = static_cast<int>(lua->objlen(L, 2));

  for (int i = 1; i <= len; i++) {
    lua->rawgeti(L, 2, i);
    auto offset = static_cast<int64_t>(lua->tonumber(L, -1));
    lua->settop(L, 2); // pop the offset

    addr += offset;

    // Try to dereference (except for last offset)
    if (i < len) {
      t_protected = true;
      if (setjmp(t_jmp_buf) == 0) {
        addr = *reinterpret_cast<uintptr_t *>(addr);
        t_protected = false;
        if (addr == 0) {
          return 0; // null pointer
        }
      } else {
        t_protected = false;
        return 0; // access violation
      }
    }
  }

  lua->pushnumber(L, static_cast<double>(addr));
  return 1;
}

// SEH-wrapped HeapWalk — returns false on crash instead of bringing down the process
static bool safe_heap_walk(HANDLE heap, PROCESS_HEAP_ENTRY *entry) {
  __try {
    return HeapWalk(heap, entry) != FALSE;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

// mem.heaps() -> table { {base=number, size=number}, ... }
static int heaps(lua_State *L) {
  auto lua = g_api->lua;

  HANDLE heap_handles[256];
  DWORD heap_count = GetProcessHeaps(256, heap_handles);

  lua->createtable(L, 0, 0);
  int idx = 1;

  for (DWORD i = 0; i < heap_count; i++) {
    if (!HeapLock(heap_handles[i]))
      continue;

    PROCESS_HEAP_ENTRY entry = {};
    while (safe_heap_walk(heap_handles[i], &entry)) {
      if (entry.wFlags & PROCESS_HEAP_REGION) {
        lua->createtable(L, 0, 2);

        lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(entry.lpData)));
        lua->setfield(L, -2, "base");

        lua->pushnumber(L, static_cast<double>(entry.Region.dwCommittedSize));
        lua->setfield(L, -2, "size");

        lua->rawseti(L, -2, idx++);
      }
    }

    HeapUnlock(heap_handles[i]);
  }

  return 1;
}

// mem.scan(base: number, size: number, pattern: string, no_mask?: boolean) -> number | nil
static int scan(lua_State *L) {
  auto lua = g_api->lua;
  auto base = static_cast<uintptr_t>(lua->tonumber(L, 1));
  auto size = static_cast<size_t>(lua->tonumber(L, 2));
  const char *pattern = lua->tolstring(L, 3, nullptr);
  bool no_mask = lua->gettop(L) >= 4 && lua->toboolean(L, 4);

  if (no_mask) {
    auto result = util::sigscan(base, size, pattern);
    if (result == 0) return 0;
    lua->pushnumber(L, static_cast<double>(result));
    return 1;
  }

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

  std::string masked_pattern;
  if (!has_wildcards) {
    masked_pattern = util::auto_mask_pattern(raw_bytes);
    if (!masked_pattern.empty() && masked_pattern != pattern) {
      printf("[LJE-FFI] Auto-masked signature:\n  in:  %s\n  out: %s\n", pattern,
             masked_pattern.c_str());
    }
  }

  const char *scan_pattern = has_wildcards ? pattern : masked_pattern.c_str();
  auto result = util::sigscan(base, size, scan_pattern);
  if (result == 0) return 0;
  lua->pushnumber(L, static_cast<double>(result));
  return 1;
}

// mem.memory_scan(pattern: string, no_mask?: boolean, min_size?: number) -> table {number, ...}
// Scans all committed readable (rw-) pages in the process. Coalesces adjacent pages with the same
// protection. min_size filters out regions smaller than the given size (default 0x10000).
static int memory_scan(lua_State *L) {
  auto lua = g_api->lua;
  const char *pattern = lua->tolstring(L, 1, nullptr);
  bool no_mask = lua->gettop(L) >= 2 && lua->toboolean(L, 2);
  size_t min_size =
      lua->gettop(L) >= 3 ? static_cast<size_t>(lua->tonumber(L, 3)) : 0x10000;

  // Parse pattern once upfront
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
        printf("[LJE-FFI] Auto-masked signature:\n  in:  %s\n  out: %s\n", pattern, masked.c_str());
      }
      if (!util::parse_pattern(masked.c_str(), bytes, mask))
        return 0;
    }
  }

  // Exclude the bytes vector's own buffer — it's on the heap and contains the pattern
  uintptr_t self_buf = reinterpret_cast<uintptr_t>(bytes.data());
  uintptr_t self_buf_end = self_buf + bytes.size();

  auto results = util::scan_process_memory(bytes, mask, min_size, self_buf, self_buf_end);

  // Collect results into Lua table
  lua->createtable(L, static_cast<int>(results.size()), 0);
  for (size_t i = 0; i < results.size(); i++) {
    lua->pushnumber(L, static_cast<double>(results[i]));
    lua->rawseti(L, -2, static_cast<int>(i + 1));
  }

  return 1;
}

// mem.addr_to_pat(address: number) -> string
static int addr_to_pat(lua_State *L) {
  auto lua = g_api->lua;
  auto addr = static_cast<uintptr_t>(lua->tonumber(L, 1));

  char buf[24];
  snprintf(buf, sizeof(buf), "%02X %02X %02X %02X %02X %02X %02X %02X",
           static_cast<unsigned>(addr & 0xFF), static_cast<unsigned>((addr >> 8) & 0xFF),
           static_cast<unsigned>((addr >> 16) & 0xFF), static_cast<unsigned>((addr >> 24) & 0xFF),
           static_cast<unsigned>((addr >> 32) & 0xFF), static_cast<unsigned>((addr >> 40) & 0xFF),
           static_cast<unsigned>((addr >> 48) & 0xFF), static_cast<unsigned>((addr >> 56) & 0xFF));

  lua->pushstring(L, buf);
  return 1;
}

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  install_veh();

  lua->createtable(L, 0, 40);

  // Allocation
  lua->pushcclosure(L, reinterpret_cast<void *>(alloc), 0);
  lua->setfield(L, -2, "alloc");

  lua->pushcclosure(L, reinterpret_cast<void *>(free_), 0);
  lua->setfield(L, -2, "free");

  lua->pushcclosure(L, reinterpret_cast<void *>(copy), 0);
  lua->setfield(L, -2, "copy");

  lua->pushcclosure(L, reinterpret_cast<void *>(fill), 0);
  lua->setfield(L, -2, "fill");

  // Reads
  lua->pushcclosure(L, reinterpret_cast<void *>(read_u8), 0);
  lua->setfield(L, -2, "read_u8");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_i8), 0);
  lua->setfield(L, -2, "read_i8");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_u16), 0);
  lua->setfield(L, -2, "read_u16");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_i16), 0);
  lua->setfield(L, -2, "read_i16");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_u32), 0);
  lua->setfield(L, -2, "read_u32");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_i32), 0);
  lua->setfield(L, -2, "read_i32");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_u64), 0);
  lua->setfield(L, -2, "read_u64");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_i64), 0);
  lua->setfield(L, -2, "read_i64");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_f32), 0);
  lua->setfield(L, -2, "read_f32");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_f64), 0);
  lua->setfield(L, -2, "read_f64");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_ptr), 0);
  lua->setfield(L, -2, "read_ptr");

  lua->pushcclosure(L, reinterpret_cast<void *>(read_string), 0);
  lua->setfield(L, -2, "read_string");

  // Protected reads (return nil on access violation)
  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_u8), 0);
  lua->setfield(L, -2, "try_read_u8");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_i8), 0);
  lua->setfield(L, -2, "try_read_i8");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_u16), 0);
  lua->setfield(L, -2, "try_read_u16");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_i16), 0);
  lua->setfield(L, -2, "try_read_i16");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_u32), 0);
  lua->setfield(L, -2, "try_read_u32");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_i32), 0);
  lua->setfield(L, -2, "try_read_i32");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_u64), 0);
  lua->setfield(L, -2, "try_read_u64");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_i64), 0);
  lua->setfield(L, -2, "try_read_i64");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_f32), 0);
  lua->setfield(L, -2, "try_read_f32");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_f64), 0);
  lua->setfield(L, -2, "try_read_f64");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_ptr), 0);
  lua->setfield(L, -2, "try_read_ptr");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_read_string), 0);
  lua->setfield(L, -2, "try_read_string");

  // Writes
  lua->pushcclosure(L, reinterpret_cast<void *>(write_u8), 0);
  lua->setfield(L, -2, "write_u8");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_i8), 0);
  lua->setfield(L, -2, "write_i8");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_u16), 0);
  lua->setfield(L, -2, "write_u16");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_i16), 0);
  lua->setfield(L, -2, "write_i16");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_u32), 0);
  lua->setfield(L, -2, "write_u32");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_i32), 0);
  lua->setfield(L, -2, "write_i32");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_u64), 0);
  lua->setfield(L, -2, "write_u64");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_i64), 0);
  lua->setfield(L, -2, "write_i64");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_f32), 0);
  lua->setfield(L, -2, "write_f32");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_f64), 0);
  lua->setfield(L, -2, "write_f64");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_ptr), 0);
  lua->setfield(L, -2, "write_ptr");

  lua->pushcclosure(L, reinterpret_cast<void *>(write_string), 0);
  lua->setfield(L, -2, "write_string");

  // Protected writes (return true/false)
  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_u8), 0);
  lua->setfield(L, -2, "try_write_u8");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_i8), 0);
  lua->setfield(L, -2, "try_write_i8");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_u16), 0);
  lua->setfield(L, -2, "try_write_u16");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_i16), 0);
  lua->setfield(L, -2, "try_write_i16");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_u32), 0);
  lua->setfield(L, -2, "try_write_u32");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_i32), 0);
  lua->setfield(L, -2, "try_write_i32");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_u64), 0);
  lua->setfield(L, -2, "try_write_u64");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_i64), 0);
  lua->setfield(L, -2, "try_write_i64");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_f32), 0);
  lua->setfield(L, -2, "try_write_f32");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_f64), 0);
  lua->setfield(L, -2, "try_write_f64");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_ptr), 0);
  lua->setfield(L, -2, "try_write_ptr");

  lua->pushcclosure(L, reinterpret_cast<void *>(try_write_string), 0);
  lua->setfield(L, -2, "try_write_string");

  lua->pushcclosure(L, reinterpret_cast<void *>(sizeof_), 0);
  lua->setfield(L, -2, "sizeof");

  lua->pushcclosure(L, reinterpret_cast<void *>(unwrap_userdata), 0);
  lua->setfield(L, -2, "unwrap_userdata");

  lua->pushcclosure(L, reinterpret_cast<void *>(protect), 0);
  lua->setfield(L, -2, "protect");

  lua->pushcclosure(L, reinterpret_cast<void *>(deref), 0);
  lua->setfield(L, -2, "deref");

  lua->pushcclosure(L, reinterpret_cast<void *>(heaps), 0);
  lua->setfield(L, -2, "heaps");

  lua->pushcclosure(L, reinterpret_cast<void *>(scan), 0);
  lua->setfield(L, -2, "scan");

  lua->pushcclosure(L, reinterpret_cast<void *>(memory_scan), 0);
  lua->setfield(L, -2, "memory_scan");

  lua->pushcclosure(L, reinterpret_cast<void *>(addr_to_pat), 0);
  lua->setfield(L, -2, "addr_to_pat");

  lua->setfield(L, -2, "mem");
}

} // namespace api::mem
