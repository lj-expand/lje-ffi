#include "detour.hpp"
#include "../globals.hpp"
#include "../util/call-auth.hpp"
#include "../util/minhook-shared.hpp"
#include "tcc.hpp"

#include <MinHook.h>

static int s_metatable_ref = LUA_NOREF;

// Both must be present in the detour program
#define DETOUR_ENTRYPOINT_SYMBOL "detour"
#define DETOUR_ORIGINAL_SYMBOL "original"

struct DetourSymbols {
  uintptr_t detour;
  uintptr_t original;
};

static DetourSymbols get_detour_symbols(TCCState *program) {
  DetourSymbols symbols{};

  void *detour_sym = api::tcc::internal::symbol(program, DETOUR_ENTRYPOINT_SYMBOL);
  void *original_sym = api::tcc::internal::symbol(program, DETOUR_ORIGINAL_SYMBOL);

  if (detour_sym && original_sym) {
    symbols.detour = reinterpret_cast<uintptr_t>(detour_sym);
    symbols.original = reinterpret_cast<uintptr_t>(original_sym);
  } else {
    // If either symbol is missing, treat as failure (caller should handle)
    symbols.detour = 0;
    symbols.original = 0;
  }

  return symbols;
}

struct DetourState {
  uintptr_t target;
  uintptr_t trampoline;
  TCCState *program;
  bool enabled;
  bool destroyed;
};

static int gc(lua_State *L) {
  auto lua = g_api->lua;
  auto **ud = static_cast<DetourState **>(lua->touserdata(L, 1));
  if (ud && *ud) {
    auto *state = *ud;
    if (!state->destroyed) {
      // MH_CreateHook always ran, so always tear down regardless of enabled.
      MH_DisableHook(reinterpret_cast<void *>(state->target)); // harmless if already disabled
      MH_RemoveHook(reinterpret_cast<void *>(state->target));
      minhook_shared::release_target(state->target);

      api::tcc::internal::destroy(state->program);
      state->destroyed = true;
      state->program = nullptr;
      delete state;
      *ud = nullptr;
    }
  }
  return 0;
}

static DetourState *get_detour(lua_State *L, int idx) {
  auto lua = g_api->lua;
  auto **ud = static_cast<DetourState **>(lua->touserdata(L, idx));
  if (!ud || !*ud || (*ud)->destroyed) {
    return nullptr;
  }
  return *ud;
}

// Just like tcc's method_get.
static int method_get(lua_State *L) {
  auto lua = g_api->lua;
  auto *detour = get_detour(L, 1);

  if (!detour) {
    lua->pushnil(L);
    return 1;
  }

  const char *name = lua->tolstring(L, 2, nullptr);
  if (!name) {
    lua->pushnil(L);
    return 1;
  }

  void *sym = api::tcc::internal::symbol(detour->program, name);
  if (!sym) {
    lua->pushnil(L);
    return 1;
  }

  lua->pushnumber(L, static_cast<double>(reinterpret_cast<uintptr_t>(sym)));
  return 1;
}

static int method_enable(lua_State *L) {
  auto lua = g_api->lua;
  auto *detour = get_detour(L, 1);

  if (!detour) {
    lua->pushboolean(L, 0);
    return 1;
  }

  if (detour->enabled) {
    lua->pushboolean(L, 0);
    return 1;
  }

  MH_STATUS status = MH_EnableHook(reinterpret_cast<void *>(detour->target));
  detour->enabled = (status == MH_OK);
  lua->pushboolean(L, detour->enabled ? 1 : 0);
  return 1;
}

static int method_disable(lua_State *L) {
  auto lua = g_api->lua;
  auto *detour = get_detour(L, 1);

  if (!detour) {
    lua->pushboolean(L, 0);
    return 1;
  }

  if (!detour->enabled) {
    lua->pushboolean(L, 0);
    return 1;
  }

  MH_STATUS status = MH_DisableHook(reinterpret_cast<void *>(detour->target));
  detour->enabled = (status == MH_OK);
  lua->pushboolean(L, detour->enabled ? 1 : 0);
  return 1;
}

static void push_detour_userdata(lua_State *L, DetourState *state) {
  auto lua = g_api->lua;
  auto **ud = static_cast<DetourState **>(lua->newuserdata(L, sizeof(DetourState *)));
  *ud = state;
  lua->rawgeti(L, LUA_REGISTRYINDEX, s_metatable_ref);
  lua->setmetatable(L, -2);
}

static int create(lua_State *L) {
  auto lua = g_api->lua;
  FFI_AUTH_CALL(lua, L);

  auto target = static_cast<uintptr_t>(lua->tonumber(L, 1));
  size_t code_len;
  const char *code = lua->tolstring(L, 2, &code_len);

  if (!minhook_shared::ensure_initialized()) {
    lua->pushnil(L);
    lua->pushstring(L, "failed to initialize MinHook");
    return 2;
  }

  if (!code || code_len == 0) {
    lua->pushnil(L);
    lua->pushstring(L, "code must be a non-empty string");
    return 2;
  }

  if (minhook_shared::is_target_claimed(target)) {
    lua->pushnil(L);
    lua->pushstring(L, "target address is already hooked");
    return 2;
  }

  std::string error;
  TCCState *program = api::tcc::internal::compile(L, code, true, error);
  if (!program) {
    lua->pushnil(L);
    lua->pushstring(L, error.c_str());
    return 2;
  }

  DetourSymbols symbols = get_detour_symbols(program);
  if (symbols.detour == 0 || symbols.original == 0) {
    api::tcc::internal::destroy(program);
    lua->pushnil(L);
    lua->pushstring(L, "detour program must define 'detour' and 'original' symbols");
    return 2;
  }

  printf("[LJE FFI] Detour symbols: detour=0x%p, original=0x%p\n", symbols.detour, symbols.original);
  void *trampoline = nullptr;
  MH_STATUS status = MH_CreateHook(reinterpret_cast<void *>(target),
                                   reinterpret_cast<void *>(symbols.detour), &trampoline);
  if (status != MH_OK) {
    api::tcc::internal::destroy(program);
    lua->pushnil(L);
    lua->pushstring(L, "failed to create detour hook");
    return 2;
  }
  minhook_shared::claim_target(target);

  // Write trampoline to symbol
  *reinterpret_cast<uintptr_t *>(symbols.original) = reinterpret_cast<uintptr_t>(trampoline);

  status = MH_EnableHook(reinterpret_cast<void *>(target));
  if (status != MH_OK) {
    MH_RemoveHook(reinterpret_cast<void *>(target));
    minhook_shared::release_target(target);
    api::tcc::internal::destroy(program);
    lua->pushnil(L);
    lua->pushstring(L, "failed to enable detour hook");
    return 2;
  }

  auto *state = new DetourState{.target = target,
                                .trampoline = reinterpret_cast<uintptr_t>(trampoline),
                                .program = program,
                                .enabled = true,
                                .destroyed = false};

  printf("[LJE FFI] Created detour on target 0x%X with trampoline 0x%X\n", state->target, state->trampoline);
  push_detour_userdata(L, state);
  return 1;
}

namespace api::detour {

void register_all(lua_State *L) {
  auto lua = g_api->lua;

  // Detour metatable
  lua->createtable(L, 0, 5);
  lua->pushcclosure(L, reinterpret_cast<void *>(gc), 0);
  lua->setfield(L, -2, "__gc");
  lua->pushvalue(L, -1);
  lua->setfield(L, -2, "__index");
  lua->pushcclosure(L, reinterpret_cast<void *>(method_get), 0);
  lua->setfield(L, -2, "get");
  lua->pushcclosure(L, reinterpret_cast<void *>(method_enable), 0);
  lua->setfield(L, -2, "enable");
  lua->pushcclosure(L, reinterpret_cast<void *>(method_disable), 0);
  lua->setfield(L, -2, "disable");
  s_metatable_ref = lua->ref(L, LUA_REGISTRYINDEX);

  // The detour module table.
  lua->createtable(L, 0, 1);
  lua->pushcclosure(L, reinterpret_cast<void *>(create), 0);
  lua->setfield(L, -2, "create");

  lua->setfield(L, -2, "detour");
}

} // namespace api::detour
