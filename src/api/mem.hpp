#pragma once
#include "lje_sdk.h"
#include <csetjmp>

namespace api::mem {

// VEH protection state (shared with other modules)
extern thread_local jmp_buf t_jmp_buf;
extern thread_local bool t_protected;

void install_veh();
void register_all(lua_State *L);
} // namespace api::mem
