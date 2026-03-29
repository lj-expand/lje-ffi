#pragma once

#include <atomic>
#include <chrono>
#include <thread>
#include <windows.h>

#include "../api/mem.hpp"

namespace api::watchdog {

constexpr DWORD EXCEPTION_WATCHDOG_TIMEOUT = 0xE0004C4A;

struct RedirectCtx {
  uintptr_t original_rip;
  DWORD exception_code;
};

struct WatchdogState {
  std::atomic<bool> active{false};
  std::atomic<bool> running{true};
  std::atomic<uint64_t> deadline_ms{0};
  HANDLE main_thread{INVALID_HANDLE_VALUE};
};

extern WatchdogState g_watchdog;
extern RedirectCtx g_redirect_ctx;

void init();
void shutdown();
void arm(uint32_t timeout_ms);
void disarm();

// Runs on the main thread via RIP redirect — sets TLS then raises to break out of the function.
// Meant to use as minimal state as possible since *all* registers will be indeterminate at this
// point.
void __stdcall raise_thunk();

} // namespace api::watchdog
