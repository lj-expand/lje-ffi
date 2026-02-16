#pragma once

#define FFI_AUTH_CALL(lua, state) \
  if (!lua->is_lje_involved(state, 1, 1)) { \
    printf("[LJE FFI]: Unauthorized call to " __FUNCTION__ " detected. Call ignored.\n"); \
    return 0; \
  }
