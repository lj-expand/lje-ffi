#pragma once
#include "../globals.hpp"

// We force-allow FFI hook callbacks to be authenticated since
// TCO (tail-call optimization) will likely remove the frame link
// before we can check it. So any tail-called return will return as unauthenticated
// even if it was originally authenticated.
#define FFI_AUTH_CALL(lua, state) \
  if (!lua->is_lje_involved(state, 0, 3) && !g_in_ffi_hook) { \
    printf("[LJE FFI]: Unauthorized call to " __FUNCTION__ " detected. Call ignored.\n"); \
    return 0; \
  }
