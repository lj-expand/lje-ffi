#pragma once
#include "lje_sdk.h"

#include <string>

struct TCCState;

namespace api::tcc {
void register_all(lua_State* L);

// Internal compile pipeline, shared with the detour module. These drive the
// same dynamically-loaded libtcc + bundle runtime that backs ffi.tcc.compile.
namespace internal {
// Ensure libtcc is unpacked + loaded. Returns false with `error` set on failure.
bool ensure_runtime(std::string& error);

// Compile + relocate `source` into a fresh program. `use_prelude` injects the
// LJE/Lua prelude (g_api, L, lua_* macros). On success returns a relocated
// TCCState* the caller owns (free via destroy); on failure returns nullptr with
// `error` set to libtcc's diagnostics. `L` becomes the state compiled code sees
// as the global `L`.
TCCState* compile(lua_State* L, const char* source, bool use_prelude, std::string& error);

// Address of an external-linkage symbol (function or global), or nullptr.
void* symbol(TCCState* state, const char* name);

// Free a program (frees its compiled code too).
void destroy(TCCState* state);
} // namespace internal

} // namespace api::tcc
