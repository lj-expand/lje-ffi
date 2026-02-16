#include "hook.hpp"
#include "../util/call-auth.hpp"
#include "ffi-helpers.hpp"

#include <MinHook.h>
#include <cstring>
#include <unordered_map>
#include <vector>

using namespace api::ffi_helpers;

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
    int original_bound_ref; // Registry ref to bound original closure (create_bind only)
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

// Global Lua state for closure callbacks (set during hook creation)
static lua_State* s_lua_state = nullptr;

// Push hook args onto the Lua stack from libffi args array
static void push_hook_args(lua_State* L, HookInfo* hook, void** args) {
    const char* arg_types_str = hook->signature + 1;
    size_t arg_count = strlen(arg_types_str);
    for (size_t i = 0; i < arg_count; i++) {
        push_arg(L, arg_types_str[i], args[i]);
    }
}

// Call the Lua callback via pcall; on error, call the original via trampoline.
// Expects the callback + all args already pushed on the stack.
static bool pcall_or_original(lua_State* L, HookInfo* hook, void* ret, void** args) {
    auto lua = g_api->lua;
    const char* arg_types_str = hook->signature + 1;
    size_t arg_count = strlen(arg_types_str);
    char ret_type = hook->signature[0];
    int nresults = (ret_type == 'v') ? 0 : 1;

    if (lua->pcall(L, static_cast<int>(1 + arg_count), nresults, 0) != LUA_OK) {
        lua->settop(L, -2);
        ffi_call(&hook->cif, reinterpret_cast<void(*)()>(hook->trampoline), ret, args);
        return false;
    }

    if (ret_type != 'v') {
        read_return(L, ret_type, ret);
        lua->settop(L, -2);
    }
    return true;
}

// Call the original function directly via trampoline
static void call_original(HookInfo* hook, void* ret, void** args) {
    ffi_call(&hook->cif, reinterpret_cast<void(*)()>(hook->trampoline), ret, args);
}

// Returns the Lua state if the hook should proceed, or nullptr if it should fall through to original
static lua_State* check_hook_preconditions(HookInfo* hook, void* ret, void** args) {
    if (GetCurrentThreadId() != s_main_thread_id) {
        printf("[LJE FFI]: Warning - Lua hook called from a different thread! This is unsafe. Calling original function.\n");
        call_original(hook, ret, args);
        return nullptr;
    }
    if (!s_lua_state || hook->callback_ref == LUA_NOREF) {
        call_original(hook, ret, args);
        return nullptr;
    }
    return s_lua_state;
}

// This is called by libffi when the hooked function is invoked
// NOTE: Sometimes, this can run during a Lua C call by the engine,
// which is why we dont do lua_settop(L, 0), but lua_settop(L, -2).
static void closure_handler(ffi_cif* cif, void* ret, void** args, void* userdata) {
    auto* hook = static_cast<HookInfo*>(userdata);
    auto lua = g_api->lua;

    lua_State* L = check_hook_preconditions(hook, ret, args);
    if (!L) return;

    lua->rawgeti(L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua->pushnumber(L, static_cast<double>(hook->trampoline));
    push_hook_args(L, hook, args);
    pcall_or_original(L, hook, ret, args);
}

// Same as above, but passes the original as a bound closure instead of a raw address
static void closure_handler_bound(ffi_cif* cif, void* ret, void** args, void* userdata) {
    auto* hook = static_cast<HookInfo*>(userdata);
    auto lua = g_api->lua;

    lua_State* L = check_hook_preconditions(hook, ret, args);
    if (!L) return;

    lua->rawgeti(L, LUA_REGISTRYINDEX, hook->callback_ref);
    lua->rawgeti(L, LUA_REGISTRYINDEX, hook->original_bound_ref);
    push_hook_args(L, hook, args);
    pcall_or_original(L, hook, ret, args);
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

    if (hook->original_bound_ref != LUA_NOREF && L) {
        g_api->lua->unref(L, LUA_REGISTRYINDEX, hook->original_bound_ref);
        hook->original_bound_ref = LUA_NOREF;
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

static void ensure_mh_initialized() {
    if (!s_mh_initialized) {
        if (MH_Initialize() != MH_OK) return;
        s_mh_initialized = true;
        s_main_thread_id = GetCurrentThreadId();
    }
}

// Shared hook setup logic. Returns the HookInfo on success (already enabled and tracked), or nullptr.
static HookInfo* setup_hook(lua_State* L, uintptr_t target, const char* sig,
                            void (*handler)(ffi_cif*, void*, void**, void*)) {
    auto lua = g_api->lua;

    ensure_mh_initialized();
    if (!s_mh_initialized) return nullptr;

    s_lua_state = L;

    if (s_hooks.count(target)) return nullptr;

    char ret_type = sig[0];
    const char* arg_types_str = sig + 1;
    size_t arg_count = strlen(arg_types_str);

    ffi_type* ffi_ret = char_to_ffi_type(ret_type);
    if (!ffi_ret) return nullptr;

    std::vector<ffi_type*> ffi_args(arg_count);
    for (size_t i = 0; i < arg_count; i++) {
        ffi_args[i] = char_to_ffi_type(arg_types_str[i]);
        if (!ffi_args[i]) return nullptr;
    }

    auto* hook = new HookInfo();
    hook->target = target;
    hook->trampoline = 0;
    hook->callback_ref = LUA_NOREF;
    hook->original_bound_ref = LUA_NOREF;
    hook->enabled = false;
    hook->destroyed = false;
    hook->closure = nullptr;
    hook->closure_code = nullptr;
    hook->arg_types = std::move(ffi_args);
    strncpy(hook->signature, sig, sizeof(hook->signature) - 1);
    hook->signature[sizeof(hook->signature) - 1] = '\0';

    if (ffi_prep_cif(&hook->cif, FFI_DEFAULT_ABI, static_cast<unsigned>(arg_count),
                     ffi_ret, arg_count ? hook->arg_types.data() : nullptr) != FFI_OK) {
        delete hook;
        return nullptr;
    }

    hook->closure = static_cast<ffi_closure*>(ffi_closure_alloc(sizeof(ffi_closure), &hook->closure_code));
    if (!hook->closure) {
        delete hook;
        return nullptr;
    }

    if (ffi_prep_closure_loc(hook->closure, &hook->cif, handler, hook, hook->closure_code) != FFI_OK) {
        ffi_closure_free(hook->closure);
        delete hook;
        return nullptr;
    }

    void* trampoline = nullptr;
    MH_STATUS status = MH_CreateHook(reinterpret_cast<void*>(target), hook->closure_code, &trampoline);
    if (status != MH_OK) {
        ffi_closure_free(hook->closure);
        delete hook;
        return nullptr;
    }

    hook->trampoline = reinterpret_cast<uintptr_t>(trampoline);

    status = MH_EnableHook(reinterpret_cast<void*>(target));
    if (status != MH_OK) {
        MH_RemoveHook(reinterpret_cast<void*>(target));
        ffi_closure_free(hook->closure);
        delete hook;
        return nullptr;
    }

    hook->enabled = true;
    s_hooks[target] = hook;

    return hook;
}

// Pushes hook userdata onto the stack. Returns the HookInfo** userdata pointer.
static HookInfo** push_hook_userdata(lua_State* L, HookInfo* hook) {
    auto lua = g_api->lua;
    auto** ud = static_cast<HookInfo**>(lua->newuserdata(L, sizeof(HookInfo*)));
    *ud = hook;
    lua->rawgeti(L, LUA_REGISTRYINDEX, s_metatable_ref);
    lua->setmetatable(L, -2);
    return ud;
}

// hook.create(target: number, signature: string, callback: function) -> userdata
static int create(lua_State* L) {
    auto lua = g_api->lua;
    FFI_AUTH_CALL(lua, L);

    auto target = static_cast<uintptr_t>(lua->tonumber(L, 1));
    const char* sig = lua->tolstring(L, 2, nullptr);

    if (!sig || !sig[0]) return 0;

    auto* hook = setup_hook(L, target, sig, closure_handler);
    if (!hook) return 0;

    lua->pushvalue(L, 3); // push callback
    hook->callback_ref = lua->ref(L, LUA_REGISTRYINDEX);

    push_hook_userdata(L, hook);
    return 1;
}

// hook.create_bind(bound_fn: function, callback: function) -> userdata, function
// Takes a bound closure (from call.bind), extracts sig/address from its upvalues,
// hooks it, and returns the hook userdata + a bound original (trampoline) function.
static int create_bind(lua_State* L) {
    auto lua = g_api->lua;

    // arg 1: bound function (created by call.bind)
    // arg 2: callback function

    // Extract upvalues from the bound closure:
    //   upvalue 1: signature (string)
    //   upvalue 2: address (number)
    //   upvalue 3: CachedCif* (lightuserdata)
    const char* uv_name;

    uv_name = lua->getupvalue(L, 1, 1); // pushes sig string
    if (!uv_name) return 0;
    const char* sig = lua->tolstring(L, -1, nullptr);
    lua->pop(L, 1);

    uv_name = lua->getupvalue(L, 1, 2); // pushes address number
    if (!uv_name) return 0;
    auto target = static_cast<uintptr_t>(lua->tonumber(L, -1));
    lua->pop(L, 1);

    if (!sig || !sig[0]) return 0;

    auto* hook = setup_hook(L, target, sig, closure_handler_bound);
    if (!hook) return 0;

    // Store callback ref
    lua->pushvalue(L, 2);
    hook->callback_ref = lua->ref(L, LUA_REGISTRYINDEX);

    // Create bound original (trampoline) closure and ref it for the handler
    auto* cached = get_or_prep_cif(sig);
    push_bound_closure(L, sig, hook->trampoline, cached);
    hook->original_bound_ref = lua->ref(L, LUA_REGISTRYINDEX); // pops it

    // Return 1: hook userdata
    push_hook_userdata(L, hook);

    // Return 2: bound original closure (from the ref we just stored)
    lua->rawgeti(L, LUA_REGISTRYINDEX, hook->original_bound_ref);

    return 2;
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
    FFI_AUTH_CALL(lua, L);
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
    FFI_AUTH_CALL(lua, L);
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
    FFI_AUTH_CALL(lua, L);
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

    lua->createtable(L, 0, 5);

    lua->pushcclosure(L, reinterpret_cast<void*>(create), 0);
    lua->setfield(L, -2, "create");

    lua->pushcclosure(L, reinterpret_cast<void*>(create_bind), 0);
    lua->setfield(L, -2, "create_bind");

    lua->pushcclosure(L, reinterpret_cast<void*>(remove), 0);
    lua->setfield(L, -2, "remove");

    lua->pushcclosure(L, reinterpret_cast<void*>(enable), 0);
    lua->setfield(L, -2, "enable");

    lua->pushcclosure(L, reinterpret_cast<void*>(disable), 0);
    lua->setfield(L, -2, "disable");

    lua->setfield(L, -2, "hook");
}

} // namespace api::hook
