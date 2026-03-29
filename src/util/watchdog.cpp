#include "watchdog.hpp"
#include <chrono>
#include <processthreadsapi.h>

namespace api::watchdog {
WatchdogState g_watchdog;
RedirectCtx g_redirect_ctx{};

static uint64_t now_ms() {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count());
}

// Executes on the main thread after RIP redirect.
// Thread-locals here are the main thread's, so it will correctly interact with the protected call
// machinery and jmp_buf.
void __stdcall raise_thunk() {
  api::mem::t_exception_code = g_redirect_ctx.exception_code;
  api::mem::t_exception_addr = g_redirect_ctx.original_rip;
  RaiseException(g_redirect_ctx.exception_code, 0, 0, nullptr);
}

static void watchdog_thread_fn() {
  while (g_watchdog.running.load(std::memory_order_relaxed)) {
    if (g_watchdog.active.load(std::memory_order_acquire)) {
      if (now_ms() > g_watchdog.deadline_ms.load(std::memory_order_relaxed)) {
        if (g_watchdog.main_thread != INVALID_HANDLE_VALUE) {
          DWORD suspend_count = SuspendThread(g_watchdog.main_thread);
          if (suspend_count == static_cast<DWORD>(-1)) {
            OutputDebugStringA("[LJE Watchdog] Failed to suspend main thread.\n");
            DWORD error = GetLastError();
            char buffer[256] = {};
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, sizeof(buffer), nullptr);
            OutputDebugStringA(buffer);
            // Also output thread id
            DWORD thread_id = GetThreadId(g_watchdog.main_thread);
            char thread_id_buffer[64] = {};
            snprintf(thread_id_buffer, sizeof(thread_id_buffer), "Thread ID: %lu\n", thread_id);
            OutputDebugStringA(thread_id_buffer);

            g_watchdog.active.store(false, std::memory_order_release);
            Sleep(1);
            continue;
          }

          CONTEXT ctx = {};
          ctx.ContextFlags = CONTEXT_CONTROL;

          if (!GetThreadContext(g_watchdog.main_thread, &ctx)) {
            // Couldn't get context, resume and give up this cycle
            OutputDebugStringA("[LJE Watchdog] Failed to get main thread context.\n");
            DWORD error = GetLastError();
            char buffer[256] = {};
            FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error,
                           MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, sizeof(buffer), nullptr);
            OutputDebugStringA(buffer);
            ResumeThread(g_watchdog.main_thread);
            g_watchdog.active.store(false, std::memory_order_release);
            Sleep(1);
            continue;
          }

          // Only redirect if the main thread is actually in a protected call.
          // Without this check we could fire between disarm() and the next arm(),
          // redirecting innocent code.
          if (!api::mem::g_protected_shared.load(std::memory_order_acquire)) {
            OutputDebugStringA("[LJE Watchdog] Main thread not in protected call, skipping redirect.\n");
            ResumeThread(g_watchdog.main_thread);
            g_watchdog.active.store(false, std::memory_order_release);
            Sleep(1);
            continue;
          }

          // Write redirect context before ResumeThread (release barrier)
          g_redirect_ctx.original_rip = ctx.Rip;
          g_redirect_ctx.exception_code = EXCEPTION_WATCHDOG_TIMEOUT;

          // Set up a call to our raise_thunk.
          // Stack is not really meaningful in this case, we just add a fake return address which
          // will be ignored.
          ctx.Rsp -= 8;
          *reinterpret_cast<uint64_t *>(ctx.Rsp) = ctx.Rip;
          ctx.Rip = reinterpret_cast<uint64_t>(&raise_thunk); // call raise_thunk

          SetThreadContext(g_watchdog.main_thread, &ctx);
          // The current writes to g_redirect_ctx
          // should be visible after ResumeThread (release barrier), ensuring raise_thunk sees the
          // correct context.
          ResumeThread(g_watchdog.main_thread);

          g_watchdog.active.store(false, std::memory_order_release);
        }
      }
    }

    Sleep(1); // 1ms polling resolution
  }
}

void init() {
  g_watchdog.main_thread = OpenThread(
      THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
      FALSE,
      GetCurrentThreadId()  // ID of the calling (main) thread
  );

  g_watchdog.running.store(true, std::memory_order_relaxed);
  auto thread = std::thread(watchdog_thread_fn);
  SetThreadDescription(thread.native_handle(), L"LJEWatchdogThread");
  SetThreadPriority(thread.native_handle(), THREAD_PRIORITY_HIGHEST);
  thread.detach();
}

void shutdown() {
  g_watchdog.running.store(false, std::memory_order_relaxed);
  // Detached thread will exit on next Sleep(1) wakeup
}

void arm(uint32_t timeout_ms) {
  g_watchdog.deadline_ms.store(now_ms() + timeout_ms, std::memory_order_relaxed);
  g_watchdog.active.store(true, std::memory_order_release);
}

void disarm() { g_watchdog.active.store(false, std::memory_order_release); }

} // namespace api::watchdog
