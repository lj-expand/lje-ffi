#pragma once
#include "lje_sdk.h"
#include "../globals.hpp"

#include <ffi.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

// Upvalue pseudo-indices (LuaJIT convention: GLOBALSINDEX - n)
#define LJE_UPVALUEINDEX(n) (LUA_GLOBALSINDEX - (n))

namespace api::ffi_helpers {

inline ffi_type* char_to_ffi_type(char c) {
    switch (c) {
    case 'v': return &ffi_type_void;
    case 'i': return &ffi_type_sint32;
    case 'u': return &ffi_type_uint32;
    case 'l': return &ffi_type_sint64;
    case 'f': return &ffi_type_float;
    case 'd': return &ffi_type_double;
    case 'b': return &ffi_type_uint8;
    case 'p': return &ffi_type_pointer;
    case 's': return &ffi_type_pointer;
    default:  return nullptr;
    }
}

inline void push_arg(lua_State* L, char type, void* arg) {
    auto lua = g_api->lua;

    switch (type) {
    case 'i':
        lua->pushnumber(L, static_cast<double>(*static_cast<int32_t*>(arg)));
        break;
    case 'u':
        lua->pushnumber(L, static_cast<double>(*static_cast<uint32_t*>(arg)));
        break;
    case 'l':
        lua->pushnumber(L, static_cast<double>(*static_cast<int64_t*>(arg)));
        break;
    case 'f':
        lua->pushnumber(L, static_cast<double>(*static_cast<float*>(arg)));
        break;
    case 'd':
        lua->pushnumber(L, *static_cast<double*>(arg));
        break;
    case 'b':
        lua->pushboolean(L, *static_cast<uint8_t*>(arg));
        break;
    case 'p':
        lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(*static_cast<void**>(arg))));
        break;
    case 's':
        if (*static_cast<const char**>(arg)) {
            lua->pushstring(L, *static_cast<const char**>(arg));
        } else {
            lua->pushnumber(L, 0);
        }
        break;
    }
}

inline void read_return(lua_State* L, char type, void* ret) {
    auto lua = g_api->lua;

    switch (type) {
    case 'v':
        break;
    case 'i':
        *static_cast<int32_t*>(ret) = static_cast<int32_t>(lua->tonumber(L, -1));
        break;
    case 'u':
        *static_cast<uint32_t*>(ret) = static_cast<uint32_t>(lua->tonumber(L, -1));
        break;
    case 'l':
        *static_cast<int64_t*>(ret) = static_cast<int64_t>(lua->tonumber(L, -1));
        break;
    case 'f':
        *static_cast<float*>(ret) = static_cast<float>(lua->tonumber(L, -1));
        break;
    case 'd':
        *static_cast<double*>(ret) = lua->tonumber(L, -1);
        break;
    case 'b':
        *static_cast<uint8_t*>(ret) = static_cast<uint8_t>(lua->toboolean(L, -1));
        break;
    case 'p':
        *static_cast<void**>(ret) = reinterpret_cast<void*>(static_cast<uintptr_t>(lua->tonumber(L, -1)));
        break;
    case 's':
        *static_cast<const char**>(ret) = lua->tolstring(L, -1, nullptr);
        break;
    }
}

// --- CIF cache (shared by call and hook modules) ---

struct CachedCif {
    ffi_cif cif;
    std::vector<ffi_type*> arg_types;
};

inline std::unordered_map<std::string, CachedCif>& cif_cache() {
    static std::unordered_map<std::string, CachedCif> s_cache;
    return s_cache;
}

inline CachedCif* get_or_prep_cif(const char* sig) {
    auto& cache = cif_cache();
    auto it = cache.find(sig);
    if (it != cache.end())
        return &it->second;

    char ret_type = sig[0];
    const char* arg_str = sig + 1;
    size_t arg_count = strlen(arg_str);

    ffi_type* ffi_ret = char_to_ffi_type(ret_type);
    if (!ffi_ret)
        return nullptr;

    auto& entry = cache[sig];
    entry.arg_types.resize(arg_count);

    for (size_t i = 0; i < arg_count; i++) {
        entry.arg_types[i] = char_to_ffi_type(arg_str[i]);
        if (!entry.arg_types[i]) {
            cache.erase(sig);
            return nullptr;
        }
    }

    if (ffi_prep_cif(&entry.cif, FFI_DEFAULT_ABI, static_cast<unsigned>(arg_count), ffi_ret,
                     arg_count ? entry.arg_types.data() : nullptr) != FFI_OK) {
        cache.erase(sig);
        return nullptr;
    }

    return &entry;
}

// --- Lua arg marshalling for ffi_call ---

inline void store_arg(lua_State* L, int lua_idx, char type, uint64_t* storage) {
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
    case 'b': {
        auto val = lua->toboolean(L, lua_idx) ? 1 : 0;
        memcpy(storage, &val, sizeof(val));
        break;
    }
    case 'p': {
        auto val = reinterpret_cast<void*>(static_cast<uintptr_t>(lua->tonumber(L, lua_idx)));
        memcpy(storage, &val, sizeof(val));
        break;
    }
    case 's': {
        auto val = lua->tolstring(L, lua_idx, nullptr);
        memcpy(storage, &val, sizeof(val));
        break;
    }
    }
}

inline int push_return(lua_State* L, char ret_type, uint64_t* ret_storage) {
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
    case 'b': {
        uint8_t val;
        memcpy(&val, ret_storage, sizeof(val));
        lua->pushboolean(L, val ? 1 : 0);
        return 1;
    }
    case 'p': {
        void* val;
        memcpy(&val, ret_storage, sizeof(val));
        lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(val)));
        return 1;
    }
    case 's': {
        const char* val;
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

// --- Bound closure dispatch + creation ---

// Generic dispatch for bound closures. Upvalues:
//   1: signature (string)
//   2: address (number)
//   3: CachedCif* (lightuserdata)
inline int bound_dispatch(lua_State* L) {
    auto lua = g_api->lua;

    const char* sig = lua->tolstring(L, LJE_UPVALUEINDEX(1), nullptr);
    auto address = static_cast<uintptr_t>(lua->tonumber(L, LJE_UPVALUEINDEX(2)));
    auto* cached = static_cast<CachedCif*>(lua->tolightuserdata(L, LJE_UPVALUEINDEX(3)));

    char ret_type = sig[0];
    const char* arg_types = sig + 1;
    size_t arg_count = strlen(arg_types);

    std::vector<uint64_t> arg_storage(arg_count);
    std::vector<void*> arg_ptrs(arg_count);

    for (size_t i = 0; i < arg_count; i++) {
        arg_ptrs[i] = &arg_storage[i];
        store_arg(L, static_cast<int>(i + 1), arg_types[i], &arg_storage[i]);
    }

    uint64_t ret_storage = 0;
    ffi_call(&cached->cif, reinterpret_cast<void(*)()>(address), &ret_storage,
             arg_count ? arg_ptrs.data() : nullptr);

    return push_return(L, ret_type, &ret_storage);
}

// Pushes a bound closure onto the Lua stack.
// The closure captures sig, address, and cif as upvalues.
inline void push_bound_closure(lua_State* L, const char* sig, uintptr_t address, CachedCif* cached) {
    auto lua = g_api->lua;
    lua->pushstring(L, sig);
    lua->pushnumber(L, static_cast<double>(address));
    lua->pushlightuserdata(L, cached);
    lua->pushcclosure(L, reinterpret_cast<void*>(bound_dispatch), 3);
}

} // namespace api::ffi_helpers
