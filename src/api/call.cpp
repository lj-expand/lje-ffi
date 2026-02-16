#include "call.hpp"
#include "../util/call-auth.hpp"
#include "ffi-helpers.hpp"

#include <cstring>
#include <string>
#include <vector>

using namespace api::ffi_helpers;

namespace api::call {

// Variadic CIF cache (call-specific, key includes fixed_count)
static std::unordered_map<std::string, CachedCif> s_cif_var_cache;

static CachedCif *get_or_prep_cif_var(const char *sig, unsigned fixed_count) {
  std::string key(sig);
  key += ':';
  key += std::to_string(fixed_count);

  auto it = s_cif_var_cache.find(key);
  if (it != s_cif_var_cache.end())
    return &it->second;

  char ret_type = sig[0];
  const char *arg_str = sig + 1;
  size_t arg_count = strlen(arg_str);

  ffi_type *ffi_ret = char_to_ffi_type(ret_type);
  if (!ffi_ret)
    return nullptr;

  auto &entry = s_cif_var_cache[key];
  entry.arg_types.resize(arg_count);

  for (size_t i = 0; i < arg_count; i++) {
    entry.arg_types[i] = char_to_ffi_type(arg_str[i]);
    if (!entry.arg_types[i]) {
      s_cif_var_cache.erase(key);
      return nullptr;
    }
  }

  if (ffi_prep_cif_var(&entry.cif, FFI_DEFAULT_ABI, fixed_count,
                       static_cast<unsigned>(arg_count), ffi_ret,
                       arg_count ? entry.arg_types.data() : nullptr) != FFI_OK) {
    s_cif_var_cache.erase(key);
    return nullptr;
  }

  return &entry;
}

// call.invoke(address: number, signature: string, ...) -> varies
static int invoke(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);

  auto address = static_cast<uintptr_t>(lua->tonumber(L, 1));
  const char *sig = lua->tolstring(L, 2, nullptr);

  if (!sig || !sig[0]) {
    lua->pushstring(L, "invalid signature");
    return 1;
  }

  auto *cached = get_or_prep_cif(sig);
  if (!cached) {
    lua->pushstring(L, "invalid signature or ffi_prep_cif failed");
    return 1;
  }

  char ret_type = sig[0];
  const char *arg_types = sig + 1;
  size_t arg_count = strlen(arg_types);

  std::vector<uint64_t> arg_storage(arg_count);
  std::vector<void *> arg_ptrs(arg_count);

  for (size_t i = 0; i < arg_count; i++) {
    arg_ptrs[i] = &arg_storage[i];
    store_arg(L, static_cast<int>(i + 3), arg_types[i], &arg_storage[i]);
  }

  uint64_t ret_storage = 0;
  ffi_call(&cached->cif, reinterpret_cast<void (*)()>(address), &ret_storage,
           arg_count ? arg_ptrs.data() : nullptr);

  return push_return(L, ret_type, &ret_storage);
}

// call.bind(address: number, signature: string) -> function
static int bind(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);

  auto address = static_cast<uintptr_t>(lua->tonumber(L, 1));
  const char *sig = lua->tolstring(L, 2, nullptr);

  if (!sig || !sig[0]) {
    lua->pushstring(L, "invalid signature");
    return 1;
  }

  auto *cached = get_or_prep_cif(sig);
  if (!cached) {
    lua->pushstring(L, "invalid signature or ffi_prep_cif failed");
    return 1;
  }

  push_bound_closure(L, sig, address, cached);
  return 1;
}

// call.invoke_var(address: number, signature: string, fixed_count: number, ...) -> varies
static int invoke_var(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);

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

  auto *cached = get_or_prep_cif_var(sig, fixed_count);
  if (!cached) {
    lua->pushstring(L, "invalid signature or ffi_prep_cif_var failed");
    return 1;
  }

  std::vector<uint64_t> arg_storage(arg_count);
  std::vector<void *> arg_ptrs(arg_count);

  for (size_t i = 0; i < arg_count; i++) {
    arg_ptrs[i] = &arg_storage[i];
    store_arg(L, static_cast<int>(i + 4), arg_types[i], &arg_storage[i]); // args start at 4
  }

  uint64_t ret_storage = 0;
  ffi_call(&cached->cif, reinterpret_cast<void (*)()>(address), &ret_storage,
           arg_count ? arg_ptrs.data() : nullptr);

  return push_return(L, ret_type, &ret_storage);
}

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  lua->createtable(L, 0, 3);

  lua->pushcclosure(L, reinterpret_cast<void *>(invoke), 0);
  lua->setfield(L, -2, "invoke");

  lua->pushcclosure(L, reinterpret_cast<void *>(invoke_var), 0);
  lua->setfield(L, -2, "invoke_var");

  lua->pushcclosure(L, reinterpret_cast<void *>(bind), 0);
  lua->setfield(L, -2, "bind");

  lua->setfield(L, -2, "call");
}

} // namespace api::call
