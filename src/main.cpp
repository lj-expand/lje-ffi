#define LJE_SDK_IMPLEMENTATION
#include "api/call.hpp"
#include "api/callback.hpp"
#include "api/disasm.hpp"
#include "api/hook.hpp"
#include "api/mem.hpp"
#include "api/module.hpp"
#include "api/struct.hpp"
#include "api/vtable.hpp"
#include "util/watchdog.hpp"
#include "version.h"

#include <cstdio>
#include <ffi.h>
#include <lje_sdk.h>

LjeApi *g_api = nullptr;
bool g_in_ffi_hook = false;

LJE_MODULE_INIT() {
  g_api = api;

  if (api->version < LJE_SDK_VERSION) {
    return LJE_RESULT_INCOMPATIBLE_SDK_VERSION;
  }

  printf("[LJE]: LJE FFI v" LJE_MODULE_VERSION " initialized!\n");
  return LJE_RESULT_OK;
}

LJE_MODULE_PREINIT() {
  api::watchdog::init();
  printf("[LJE]: Watchdog initialized!\n");

  const auto* lua = g_api->lua;
  lua->pushljeenv(L);
  lua->createtable(L, 0, 0);
  api::module::register_all(L);
  api::call::register_all(L);
  api::mem::register_all(L);
  api::disasm::register_all(L);
  api::cstruct::register_all(L);
  api::vtable::register_all(L);
  api::hook::register_all(L);
  api::callback::register_all(L);
  lua->setfield(L, -2, "ffi");
  lua->pop(L, 1); // Pop lje env

  return LJE_RESULT_OK;
}

LJE_MODULE_SHUTDOWN() {
  g_api = nullptr;
  api::watchdog::shutdown();

  return LJE_RESULT_OK;
}
