#include "hook.hpp"
#include "../globals.hpp"

#include <MinHook.h>
#include <ffi.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace api::hook {

static bool s_mh_initialized = false;
static DWORD s_main_thread_id = 0;
static int s_metatable_ref = LUA_NOREF;

struct HookInfo {
    uintptr_t target;
    uintptr_t trampoline;
    int callback_ref;
    char signature[64];
    bool enabled;
    bool destroyed;

    // libffi closure data
    ffi_cif cif;
    ffi_closure* closure;
    void* closure_code;
    std::vector<ffi_type*> arg_types;
};

// Track hooks to prevent double-hooking same target
static std::unordered_map<uintptr_t, HookInfo*> s_hooks;

static ffi_type* char_to_ffi_type(char c) {
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

static void push_arg(lua_State* L, char type, void* arg) {
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

static void read_return(lua_State* L, char type, void* ret) {
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

// Global Lua state for closure callbacks (set during hook creation)
static lua_State* s_lua_state = nullptr;

// This is called by libffi when the hooked function is invoked
static void closure_handler(ffi_cif* cif, void* ret, void** args, void* userdata) {
    auto* hook = static_cast<HookInfo*>(userdata);
    auto lua = g_api->lua;

    // Warn if not on main thread - call original and return
    if (GetCurrentThreadId() != s_main_thread_id) {
        ffi_call(&hook->cif, reinterpret_cast<void(*)()>(hook->trampoline), ret, args);
        return;
    }

    if (!s_lua_state || hook->callback_ref == LUA_NOREF) {
        ffi_call(&hook->cif, reinterpret_cast<void(*)()>(hook->trampoline), ret, args);
        return;
    }

    lua_State* L = s_lua_state;

    // Get callback from registry
    lua->rawgeti(L, LUA_REGISTRYINDEX, hook->callback_ref);

    // Push original (trampoline) as first argument
    lua->pushnumber(L, static_cast<double>(hook->trampoline));

    // Push remaining args based on signature
    const char* arg_types_str = hook->signature + 1; // skip return type
    size_t arg_count = strlen(arg_types_str);

    for (size_t i = 0; i < arg_count; i++) {
        push_arg(L, arg_types_str[i], args[i]);
    }

    // Call with (1 + arg_count) args, 1 result (or 0 for void)
    char ret_type = hook->signature[0];
    int nresults = (ret_type == 'v') ? 0 : 1;

    if (lua->pcall(L, static_cast<int>(1 + arg_count), nresults, 0) != LUA_OK) {
        // Error - call original and continue
        lua->settop(L, 0);
        ffi_call(&hook->cif, reinterpret_cast<void(*)()>(hook->trampoline), ret, args);
        return;
    }

    // Read return value
    if (ret_type != 'v') {
        read_return(L, ret_type, ret);
        lua->settop(L, 0);
    }
}

static void cleanup_hook(HookInfo* hook, lua_State* L) {
    if (!hook || hook->destroyed) return;

    hook->destroyed = true;

    // Remove from tracking map
    s_hooks.erase(hook->target);

    if (hook->enabled) {
        MH_DisableHook(reinterpret_cast<void*>(hook->target));
        MH_RemoveHook(reinterpret_cast<void*>(hook->target));
        hook->enabled = false;
    }

    if (hook->callback_ref != LUA_NOREF && L) {
        g_api->lua->unref(L, LUA_REGISTRYINDEX, hook->callback_ref);
        hook->callback_ref = LUA_NOREF;
    }

    if (hook->closure) {
        ffi_closure_free(hook->closure);
        hook->closure = nullptr;
    }
}

// __gc metamethod for hook userdata
static int gc(lua_State* L) {
    auto lua = g_api->lua;
    auto** ud = static_cast<HookInfo**>(lua->touserdata(L, 1));
    if (ud && *ud) {
        cleanup_hook(*ud, L);
    }
    return 0;
}

// hook.create(target: number, signature: string, callback: function) -> userdata
static int create(lua_State* L) {
    auto lua = g_api->lua;

    if (!s_mh_initialized) {
        if (MH_Initialize() != MH_OK) {
            return 0;
        }
        s_mh_initialized = true;
        s_main_thread_id = GetCurrentThreadId();
    }

    s_lua_state = L; // Store for closure callbacks

    auto target = static_cast<uintptr_t>(lua->tonumber(L, 1));
    const char* sig = lua->tolstring(L, 2, nullptr);
    // arg 3 is the callback function

    if (!sig || !sig[0]) {
        return 0;
    }

    // Check if already hooked
    if (s_hooks.count(target)) {
        return 0;
    }

    // Parse signature
    char ret_type = sig[0];
    const char* arg_types_str = sig + 1;
    size_t arg_count = strlen(arg_types_str);

    // Build ffi types
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

    // Allocate hook info
    auto* hook = new HookInfo();
    hook->target = target;
    hook->trampoline = 0;
    hook->callback_ref = LUA_NOREF;
    hook->enabled = false;
    hook->destroyed = false;
    hook->closure = nullptr;
    hook->closure_code = nullptr;
    hook->arg_types = std::move(ffi_args);
    strncpy(hook->signature, sig, sizeof(hook->signature) - 1);
    hook->signature[sizeof(hook->signature) - 1] = '\0';

    // Prep CIF
    if (ffi_prep_cif(&hook->cif, FFI_DEFAULT_ABI, static_cast<unsigned>(arg_count),
                     ffi_ret, arg_count ? hook->arg_types.data() : nullptr) != FFI_OK) {
        delete hook;
        return 0;
    }

    // Create closure
    hook->closure = static_cast<ffi_closure*>(ffi_closure_alloc(sizeof(ffi_closure), &hook->closure_code));
    if (!hook->closure) {
        delete hook;
        return 0;
    }

    if (ffi_prep_closure_loc(hook->closure, &hook->cif, closure_handler, hook, hook->closure_code) != FFI_OK) {
        ffi_closure_free(hook->closure);
        delete hook;
        return 0;
    }

    // Create MinHook
    void* trampoline = nullptr;
    MH_STATUS status = MH_CreateHook(reinterpret_cast<void*>(target), hook->closure_code, &trampoline);
    if (status != MH_OK) {
        ffi_closure_free(hook->closure);
        delete hook;
        return 0;
    }

    hook->trampoline = reinterpret_cast<uintptr_t>(trampoline);

    // Enable hook
    status = MH_EnableHook(reinterpret_cast<void*>(target));
    if (status != MH_OK) {
        MH_RemoveHook(reinterpret_cast<void*>(target));
        ffi_closure_free(hook->closure);
        delete hook;
        return 0;
    }

    hook->enabled = true;

    // Store callback reference
    lua->pushvalue(L, 3); // push callback
    hook->callback_ref = lua->ref(L, LUA_REGISTRYINDEX);

    // Track hook
    s_hooks[target] = hook;

    // Create userdata with pointer to hook
    auto** ud = static_cast<HookInfo**>(lua->newuserdata(L, sizeof(HookInfo*)));
    *ud = hook;

    // Set metatable
    lua->rawgeti(L, LUA_REGISTRYINDEX, s_metatable_ref);
    lua->setmetatable(L, -2);

    return 1;
}

static HookInfo* get_hook(lua_State* L, int idx) {
    auto lua = g_api->lua;
    auto** ud = static_cast<HookInfo**>(lua->touserdata(L, idx));
    if (!ud || !*ud || (*ud)->destroyed) {
        return nullptr;
    }
    return *ud;
}

// hook.remove(hook: userdata) -> boolean
static int remove(lua_State* L) {
    auto lua = g_api->lua;
    auto* hook = get_hook(L, 1);

    if (!hook) {
        lua->pushboolean(L, 0);
        return 1;
    }

    cleanup_hook(hook, L);

    lua->pushboolean(L, 1);
    return 1;
}

// hook.enable(hook: userdata) -> boolean
static int enable(lua_State* L) {
    auto lua = g_api->lua;
    auto* hook = get_hook(L, 1);

    if (!hook || hook->enabled) {
        lua->pushboolean(L, 0);
        return 1;
    }

    MH_STATUS status = MH_EnableHook(reinterpret_cast<void*>(hook->target));
    hook->enabled = (status == MH_OK);
    lua->pushboolean(L, hook->enabled ? 1 : 0);
    return 1;
}

// hook.disable(hook: userdata) -> boolean
static int disable(lua_State* L) {
    auto lua = g_api->lua;
    auto* hook = get_hook(L, 1);

    if (!hook || !hook->enabled) {
        lua->pushboolean(L, 0);
        return 1;
    }

    MH_STATUS status = MH_DisableHook(reinterpret_cast<void*>(hook->target));
    if (status == MH_OK) {
        hook->enabled = false;
    }
    lua->pushboolean(L, status == MH_OK ? 1 : 0);
    return 1;
}

void register_all(lua_State* L) {
    auto lua = g_api->lua;

    s_lua_state = L;

    // Create metatable for hook userdata and store ref
    lua->createtable(L, 0, 1);
    lua->pushcclosure(L, reinterpret_cast<void*>(gc), 0);
    lua->setfield(L, -2, "__gc");
    s_metatable_ref = lua->ref(L, LUA_REGISTRYINDEX);

    lua->createtable(L, 0, 4);

    lua->pushcclosure(L, reinterpret_cast<void*>(create), 0);
    lua->setfield(L, -2, "create");

    lua->pushcclosure(L, reinterpret_cast<void*>(remove), 0);
    lua->setfield(L, -2, "remove");

    lua->pushcclosure(L, reinterpret_cast<void*>(enable), 0);
    lua->setfield(L, -2, "enable");

    lua->pushcclosure(L, reinterpret_cast<void*>(disable), 0);
    lua->setfield(L, -2, "disable");

    lua->setfield(L, -2, "hook");
}

} // namespace api::hook
