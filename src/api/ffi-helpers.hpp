#pragma once
#include "lje_sdk.h"
#include "../globals.hpp"

#include <ffi.h>
#include <cstdint>

namespace api::ffi_helpers {

inline ffi_type* char_to_ffi_type(char c) {
    switch (c) {
    case 'v': return &ffi_type_void;
    case 'i': return &ffi_type_sint32;
    case 'u': return &ffi_type_uint32;
    case 'l': return &ffi_type_sint64;
    case 'f': return &ffi_type_float;
    case 'd': return &ffi_type_double;
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
    case 'p':
        *static_cast<void**>(ret) = reinterpret_cast<void*>(static_cast<uintptr_t>(lua->tonumber(L, -1)));
        break;
    case 's':
        *static_cast<const char**>(ret) = lua->tolstring(L, -1, nullptr);
        break;
    }
}

} // namespace api::ffi_helpers
