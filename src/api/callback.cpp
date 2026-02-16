#include "callback.hpp"
#include "../util/call-auth.hpp"
#include "ffi-helpers.hpp"

#include <cstring>
#include <vector>

using api::ffi_helpers::char_to_ffi_type;
using api::ffi_helpers::push_arg;
using api::ffi_helpers::read_return;

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace api::callback {

static DWORD s_main_thread_id = 0;
static int s_metatable_ref = LUA_NOREF;
static lua_State* s_lua_state = nullptr;

struct CallbackInfo {
    int callback_ref;
    int on_remove_ref;
    char signature[64];
    bool destroyed;

    ffi_cif cif;
    ffi_closure* closure;
    void* closure_code;
    std::vector<ffi_type*> arg_types;
};

static void closure_handler(ffi_cif* cif, void* ret, void** args, void* userdata) {
    auto* cb = static_cast<CallbackInfo*>(userdata);
    auto lua = g_api->lua;

    if (GetCurrentThreadId() != s_main_thread_id) {
        if (ret) memset(ret, 0, cif->rtype->size);
        return;
    }

    if (!s_lua_state || cb->callback_ref == LUA_NOREF) {
        if (ret) memset(ret, 0, cif->rtype->size);
        return;
    }

    lua_State* L = s_lua_state;

    lua->rawgeti(L, LUA_REGISTRYINDEX, cb->callback_ref);

    const char* arg_types_str = cb->signature + 1;
    size_t arg_count = strlen(arg_types_str);

    for (size_t i = 0; i < arg_count; i++) {
        push_arg(L, arg_types_str[i], args[i]);
    }

    char ret_type = cb->signature[0];
    int nresults = (ret_type == 'v') ? 0 : 1;

    g_in_ffi_hook = true;
    if (lua->pcall(L, static_cast<int>(arg_count), nresults, 0) != LUA_OK) {
        lua->settop(L, -2);
        g_in_ffi_hook = false;
        if (ret) memset(ret, 0, cif->rtype->size);
        return;
    }
    g_in_ffi_hook = false;

    if (ret_type != 'v') {
        read_return(L, ret_type, ret);
        lua->settop(L, -2);
    }
}

static void cleanup_callback(CallbackInfo* cb, lua_State* L) {
    if (!cb || cb->destroyed) return;

    cb->destroyed = true;

    if (cb->on_remove_ref != LUA_NOREF && L) {
        g_api->lua->rawgeti(L, LUA_REGISTRYINDEX, cb->on_remove_ref);
        g_api->lua->pcall(L, 0, 0, 0);
        g_api->lua->unref(L, LUA_REGISTRYINDEX, cb->on_remove_ref);
        cb->on_remove_ref = LUA_NOREF;
    }

    if (cb->callback_ref != LUA_NOREF && L) {
        g_api->lua->unref(L, LUA_REGISTRYINDEX, cb->callback_ref);
        cb->callback_ref = LUA_NOREF;
    }

    if (cb->closure) {
        ffi_closure_free(cb->closure);
        cb->closure = nullptr;
    }
}

static int gc(lua_State* L) {
    auto lua = g_api->lua;
    auto** ud = static_cast<CallbackInfo**>(lua->touserdata(L, 1));
    if (ud && *ud) {
        cleanup_callback(*ud, L);
    }
    return 0;
}

static CallbackInfo* get_callback(lua_State* L, int idx) {
    auto lua = g_api->lua;
    auto** ud = static_cast<CallbackInfo**>(lua->touserdata(L, idx));
    if (!ud || !*ud || (*ud)->destroyed) {
        return nullptr;
    }
    return *ud;
}

// callback.create(sig, handler, on_remove?) -> userdata, number
static int create(lua_State* L) {
    auto lua = g_api->lua;
    FFI_AUTH_CALL(lua, L);

    if (s_main_thread_id == 0) {
        s_main_thread_id = GetCurrentThreadId();
    }

    s_lua_state = L;

    const char* sig = lua->tolstring(L, 1, nullptr);
    // arg 2 is the handler function
    // arg 3 is optional on_remove function

    if (!sig || !sig[0]) {
        return 0;
    }

    // Parse signature
    char ret_type = sig[0];
    const char* arg_types_str = sig + 1;
    size_t arg_count = strlen(arg_types_str);

    ffi_type* ffi_ret = char_to_ffi_type(ret_type);
    if (!ffi_ret) {
        return 0;
    }

    std::vector<ffi_type*> ffi_args(arg_count);
    for (size_t i = 0; i < arg_count; i++) {
        ffi_args[i] = char_to_ffi_type(arg_types_str[i]);
        if (!ffi_args[i]) {
            return 0;
        }
    }

    auto* cb = new CallbackInfo();
    cb->callback_ref = LUA_NOREF;
    cb->on_remove_ref = LUA_NOREF;
    cb->destroyed = false;
    cb->closure = nullptr;
    cb->closure_code = nullptr;
    cb->arg_types = std::move(ffi_args);
    strncpy(cb->signature, sig, sizeof(cb->signature) - 1);
    cb->signature[sizeof(cb->signature) - 1] = '\0';

    if (ffi_prep_cif(&cb->cif, FFI_DEFAULT_ABI, static_cast<unsigned>(arg_count),
                     ffi_ret, arg_count ? cb->arg_types.data() : nullptr) != FFI_OK) {
        delete cb;
        return 0;
    }

    cb->closure = static_cast<ffi_closure*>(ffi_closure_alloc(sizeof(ffi_closure), &cb->closure_code));
    if (!cb->closure) {
        delete cb;
        return 0;
    }

    if (ffi_prep_closure_loc(cb->closure, &cb->cif, closure_handler, cb, cb->closure_code) != FFI_OK) {
        ffi_closure_free(cb->closure);
        delete cb;
        return 0;
    }

    // Ref handler
    lua->pushvalue(L, 2);
    cb->callback_ref = lua->ref(L, LUA_REGISTRYINDEX);

    // Ref on_remove if provided
    if (lua->type(L, 3) == LUA_TFUNCTION) {
        lua->pushvalue(L, 3);
        cb->on_remove_ref = lua->ref(L, LUA_REGISTRYINDEX);
    }

    // Create userdata
    auto** ud = static_cast<CallbackInfo**>(lua->newuserdata(L, sizeof(CallbackInfo*)));
    *ud = cb;

    lua->rawgeti(L, LUA_REGISTRYINDEX, s_metatable_ref);
    lua->setmetatable(L, -2);

    // Push closure address as double
    lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(cb->closure_code)));

    return 2;
}

// callback.remove(cb) -> boolean
static int remove(lua_State* L) {
    auto lua = g_api->lua;
    FFI_AUTH_CALL(lua, L);
    auto* cb = get_callback(L, 1);

    if (!cb) {
        lua->pushboolean(L, 0);
        return 1;
    }

    cleanup_callback(cb, L);

    lua->pushboolean(L, 1);
    return 1;
}

// callback.address(cb) -> number
static int address(lua_State* L) {
    auto lua = g_api->lua;
    FFI_AUTH_CALL(lua, L);
    auto* cb = get_callback(L, 1);

    if (!cb) {
        lua->pushnumber(L, 0);
        return 1;
    }

    lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(cb->closure_code)));
    return 1;
}

void register_all(lua_State* L) {
    auto lua = g_api->lua;

    s_lua_state = L;

    // Create metatable with __gc
    lua->createtable(L, 0, 1);
    lua->pushcclosure(L, reinterpret_cast<void*>(gc), 0);
    lua->setfield(L, -2, "__gc");
    s_metatable_ref = lua->ref(L, LUA_REGISTRYINDEX);

    lua->createtable(L, 0, 3);

    lua->pushcclosure(L, reinterpret_cast<void*>(create), 0);
    lua->setfield(L, -2, "create");

    lua->pushcclosure(L, reinterpret_cast<void*>(remove), 0);
    lua->setfield(L, -2, "remove");

    lua->pushcclosure(L, reinterpret_cast<void*>(address), 0);
    lua->setfield(L, -2, "address");

    lua->setfield(L, -2, "callback");
}

} // namespace api::callback
