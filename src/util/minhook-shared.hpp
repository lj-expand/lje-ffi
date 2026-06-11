#pragma once
#include <cstdint>

// Shared MinHook bootstrap + a cross-module registry of hooked targets, so the
// libffi-based `hook` module and the native `detour` module share one MinHook
// init and never double-hook the same address.
namespace minhook_shared {

// Initialize MinHook once (idempotent). On first success, records the calling
// thread as the main/Lua thread. Returns true if MinHook is ready.
bool ensure_initialized();

// Thread id captured at first successful init (the main/Lua thread).
unsigned long main_thread_id();

// Returns true if no one has hooked `target` yet (and is now claimed by you);
// false if it was already claimed. Pair with release_target on teardown.
bool claim_target(uintptr_t target);
void release_target(uintptr_t target);
bool is_target_claimed(uintptr_t target);

} // namespace minhook_shared
