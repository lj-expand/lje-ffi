#include <lje_sdk.h>
#include "version.h"

// Global LJE API pointer - use this to interact with LJE
LjeApi *g_api = nullptr;

// Called after Lua state is initialized
// Use this for any setup that needs the full environment
LJE_MODULE_INIT() {
  g_api = api;

  // TODO: Initialize your module here
  if (api->version < LJE_SDK_VERSION) {
    return LJE_RESULT_INCOMPATIBLE_SDK_VERSION;
  }

  return LJE_RESULT_OK;
}

// Called before Lua state is fully initialized
// Use this to register your Lua API functions
LJE_MODULE_PREINIT() {
  // TODO: Register your Lua functions here
  // lua_State is passed as 'L'

  return LJE_RESULT_OK;
}

// Called when module is unloaded
// Clean up any resources here
LJE_MODULE_SHUTDOWN() {
  // TODO: Cleanup your module here
  g_api = nullptr;

  return LJE_RESULT_OK;
}
