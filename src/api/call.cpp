#include "call.hpp"
#include "../globals.hpp"

#include <cstdint>
#include <cstring>
#include <ffi.h>
#include <vector>

namespace api::call {

// Type codes:
//   v = void
//   i = int32
//   u = uint32
//   l = int64 (long long)
//   f = float
//   d = double
//   p = pointer
//   s = string (Lua string passed as const char*)
//
// Signature format: first char is return type, rest are arg types
// Examples:
//   "vi"   = void(int)
//   "iip"  = int(int, pointer)
//   "vs"   = void(const char*)
//   "vsi"  = void(const char*, int)  -- for variadic like printf

static ffi_type *char_to_ffi_type(char c) {
  switch (c) {
  case 'v':
    return &ffi_type_void;
  case 'i':
    return &ffi_type_sint32;
  case 'u':
    return &ffi_type_uint32;
  case 'l':
    return &ffi_type_sint64;
  case 'f':
    return &ffi_type_float;
  case 'd':
    return &ffi_type_double;
  case 'p':
    return &ffi_type_pointer;
  case 's':
    return &ffi_type_pointer; // string is just a pointer to ffi
  default:
    return nullptr;
  }
}

static void store_arg(lua_State *L, int lua_idx, char type, uint64_t *storage) {
  auto lua = g_api->lua;

  switch (type) {
  case 'i': {
    auto val = static_cast<int32_t>(lua->tonumber(L, lua_idx));
    memcpy(storage, &val, sizeof(val));
    break;
  }
  case 'u': {
    auto val = static_cast<uint32_t>(lua->tonumber(L, lua_idx));
    memcpy(storage, &val, sizeof(val));
    break;
  }
  case 'l': {
    auto val = static_cast<int64_t>(lua->tonumber(L, lua_idx));
    memcpy(storage, &val, sizeof(val));
    break;
  }
  case 'f': {
    auto val = static_cast<float>(lua->tonumber(L, lua_idx));
    memcpy(storage, &val, sizeof(val));
    break;
  }
  case 'd': {
    auto val = lua->tonumber(L, lua_idx);
    memcpy(storage, &val, sizeof(val));
    break;
  }
  case 'p': {
    auto val = reinterpret_cast<void *>(static_cast<uintptr_t>(lua->tonumber(L, lua_idx)));
    memcpy(storage, &val, sizeof(val));
    break;
  }
  case 's': {
    // Get string pointer directly from Lua - valid for duration of call
    auto val = lua->tolstring(L, lua_idx, nullptr);
    memcpy(storage, &val, sizeof(val));
    break;
  }
  }
}

static int push_return(lua_State *L, char ret_type, uint64_t *ret_storage) {
  auto lua = g_api->lua;

  switch (ret_type) {
  case 'v':
    return 0;
  case 'i': {
    int32_t val;
    memcpy(&val, ret_storage, sizeof(val));
    lua->pushnumber(L, static_cast<double>(val));
    return 1;
  }
  case 'u': {
    uint32_t val;
    memcpy(&val, ret_storage, sizeof(val));
    lua->pushnumber(L, static_cast<double>(val));
    return 1;
  }
  case 'l': {
    int64_t val;
    memcpy(&val, ret_storage, sizeof(val));
    lua->pushnumber(L, static_cast<double>(val));
    return 1;
  }
  case 'f': {
    float val;
    memcpy(&val, ret_storage, sizeof(val));
    lua->pushnumber(L, static_cast<double>(val));
    return 1;
  }
  case 'd': {
    double val;
    memcpy(&val, ret_storage, sizeof(val));
    lua->pushnumber(L, val);
    return 1;
  }
  case 'p': {
    void *val;
    memcpy(&val, ret_storage, sizeof(val));
    lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(val)));
    return 1;
  }
  case 's': {
    const char *val;
    memcpy(&val, ret_storage, sizeof(val));
    if (val) {
      lua->pushstring(L, val);
    } else {
      return 0;
    }
    return 1;
  }
  default:
    return 0;
  }
}

// call.invoke(address: number, signature: string, ...) -> varies
static int invoke(lua_State *L) {
  auto lua = g_api->lua;

  auto address = static_cast<uintptr_t>(lua->tonumber(L, 1));
  const char *sig = lua->tolstring(L, 2, nullptr);

  if (!sig || !sig[0]) {
    lua->pushstring(L, "invalid signature");
    return 1;
  }

  char ret_type = sig[0];
  const char *arg_types = sig + 1;
  size_t arg_count = strlen(arg_types);

  ffi_type *ffi_ret = char_to_ffi_type(ret_type);
  if (!ffi_ret) {
    lua->pushstring(L, "invalid return type");
    return 1;
  }

  std::vector<ffi_type *> ffi_args(arg_count);
  for (size_t i = 0; i < arg_count; i++) {
    ffi_args[i] = char_to_ffi_type(arg_types[i]);
    if (!ffi_args[i]) {
      lua->pushstring(L, "invalid argument type");
      return 1;
    }
  }

  ffi_cif cif;
  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, static_cast<unsigned>(arg_count), ffi_ret,
                   arg_count ? ffi_args.data() : nullptr) != FFI_OK) {
    lua->pushstring(L, "ffi_prep_cif failed");
    return 1;
  }

  std::vector<uint64_t> arg_storage(arg_count);
  std::vector<void *> arg_ptrs(arg_count);

  for (size_t i = 0; i < arg_count; i++) {
    arg_ptrs[i] = &arg_storage[i];
    store_arg(L, static_cast<int>(i + 3), arg_types[i], &arg_storage[i]);
  }

  uint64_t ret_storage = 0;
  ffi_call(&cif, reinterpret_cast<void (*)()>(address), &ret_storage,
           arg_count ? arg_ptrs.data() : nullptr);

  return push_return(L, ret_type, &ret_storage);
}

// call.invoke_var(address: number, signature: string, fixed_count: number, ...) -> varies
static int invoke_var(lua_State *L) {
  auto lua = g_api->lua;

  auto address = static_cast<uintptr_t>(lua->tonumber(L, 1));
  const char *sig = lua->tolstring(L, 2, nullptr);
  auto fixed_count = static_cast<unsigned>(lua->tonumber(L, 3));

  if (!sig || !sig[0]) {
    lua->pushstring(L, "invalid signature");
    return 1;
  }

  char ret_type = sig[0];
  const char *arg_types = sig + 1;
  size_t arg_count = strlen(arg_types);

  if (fixed_count > arg_count) {
    lua->pushstring(L, "fixed_count exceeds argument count");
    return 1;
  }

  ffi_type *ffi_ret = char_to_ffi_type(ret_type);
  if (!ffi_ret) {
    lua->pushstring(L, "invalid return type");
    return 1;
  }

  std::vector<ffi_type *> ffi_args(arg_count);
  for (size_t i = 0; i < arg_count; i++) {
    ffi_args[i] = char_to_ffi_type(arg_types[i]);
    if (!ffi_args[i]) {
      lua->pushstring(L, "invalid argument type");
      return 1;
    }
  }

  ffi_cif cif;
  if (ffi_prep_cif_var(&cif, FFI_DEFAULT_ABI, fixed_count, static_cast<unsigned>(arg_count),
                       ffi_ret, arg_count ? ffi_args.data() : nullptr) != FFI_OK) {
    lua->pushstring(L, "ffi_prep_cif_var failed");
    return 1;
  }

  std::vector<uint64_t> arg_storage(arg_count);
  std::vector<void *> arg_ptrs(arg_count);

  for (size_t i = 0; i < arg_count; i++) {
    arg_ptrs[i] = &arg_storage[i];
    store_arg(L, static_cast<int>(i + 4), arg_types[i], &arg_storage[i]); // args start at 4
  }

  uint64_t ret_storage = 0;
  ffi_call(&cif, reinterpret_cast<void (*)()>(address), &ret_storage,
           arg_count ? arg_ptrs.data() : nullptr);

  return push_return(L, ret_type, &ret_storage);
}

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 2);

  lua->pushcclosure(L, reinterpret_cast<void *>(invoke), 0);
  lua->setfield(L, -2, "invoke");

  lua->pushcclosure(L, reinterpret_cast<void *>(invoke_var), 0);
  lua->setfield(L, -2, "invoke_var");

  lua->setfield(L, -2, "call");
}

} // namespace api::call
