#include "minhook-shared.hpp"

#include <MinHook.h>
#include <unordered_set>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace minhook_shared {

static bool s_initialized = false;
static DWORD s_main_thread_id = 0;
static std::unordered_set<uintptr_t> s_targets;

bool ensure_initialized() {
    if (s_initialized) return true;
    if (MH_Initialize() != MH_OK) return false;
    s_initialized = true;
    s_main_thread_id = GetCurrentThreadId();
    return true;
}

unsigned long main_thread_id() {
    return s_main_thread_id;
}

bool claim_target(uintptr_t target) {
    return s_targets.insert(target).second;
}

void release_target(uintptr_t target) {
    s_targets.erase(target);
}

bool is_target_claimed(uintptr_t target) {
    return s_targets.count(target) != 0;
}

} // namespace minhook_shared
