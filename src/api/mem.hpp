#pragma once
#include "lje_sdk.h"
#include <csetjmp>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace api::mem {

// VEH protection state (shared with other modules)
extern thread_local jmp_buf t_jmp_buf;
extern thread_local bool t_protected;
extern thread_local DWORD t_exception_code;
extern thread_local uintptr_t t_exception_addr;

void install_veh();
void register_all(lua_State *L);
} // namespace api::mem
