#include "memscan.hpp"
#include "sigscan.hpp"

#include <algorithm>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace util {

// SEH-wrapped scan_memory — returns 0 on access violation instead of crashing.
// Must be a standalone function because __try can't coexist with C++ destructors.
static uintptr_t safe_scan_memory(uintptr_t start, size_t size, const uint8_t *bytes,
                                  const uint8_t *mask, size_t pat_len) {
  __try {
    return scan_memory(start, size, bytes, mask, pat_len);
  } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER
                                                               : EXCEPTION_CONTINUE_SEARCH) {
    return 0;
  }
}

std::vector<uintptr_t> scan_process_memory(const std::vector<uint8_t> &bytes,
                                           const std::vector<uint8_t> &mask, size_t min_size,
                                           uintptr_t exclude_start, uintptr_t exclude_end) {
  struct Region {
    uintptr_t base;
    size_t size;
  };
  std::vector<Region> regions;

  // Enumerate all committed rw- non-image pages, coalescing adjacent ones
  uintptr_t addr = 0;
  MEMORY_BASIC_INFORMATION mbi;
  while (VirtualQuery(reinterpret_cast<void *>(addr), &mbi, sizeof(mbi))) {
    uintptr_t region_base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    uintptr_t region_end = region_base + mbi.RegionSize;

    if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE &&
        (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY)) &&
        !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
      if (!regions.empty() && regions.back().base + regions.back().size == region_base)
        regions.back().size += mbi.RegionSize;
      else
        regions.push_back({region_base, mbi.RegionSize});
    }

    if (region_end <= addr)
      break;
    addr = region_end;
  }

  // Filter by min_size
  if (min_size > 0) {
    regions.erase(std::remove_if(regions.begin(), regions.end(),
                                 [min_size](const Region &r) { return r.size < min_size; }),
                  regions.end());
  }

  // Split into 1MB chunks for balanced parallelization
  constexpr size_t CHUNK_SIZE = 0x100000;

  struct Chunk {
    uintptr_t base;
    size_t size;
  };
  std::vector<Chunk> chunks;
  for (auto &r : regions) {
    uintptr_t b = r.base;
    size_t rem = r.size;
    while (rem > 0) {
      size_t cs = rem > CHUNK_SIZE ? CHUNK_SIZE : rem;
      chunks.push_back({b, cs});
      b += cs;
      rem -= cs;
    }
  }

  if (chunks.empty())
    return {};

  // Capture raw pointers for SEH-safe scanning
  const uint8_t *raw_bytes = bytes.data();
  const uint8_t *raw_mask = mask.data();
  size_t pat_len = bytes.size();

  // Distribute across worker threads
  unsigned int n_workers = std::thread::hardware_concurrency();
  if (n_workers == 0)
    n_workers = 4;
  if (n_workers > chunks.size())
    n_workers = static_cast<unsigned int>(chunks.size());

  std::vector<std::vector<uintptr_t>> per_worker(n_workers);
  std::vector<std::thread> threads;
  threads.reserve(n_workers);

  auto worker = [raw_bytes, raw_mask, pat_len, &chunks, exclude_start, exclude_end](
                    size_t start, size_t end, std::vector<uintptr_t> &out) {
    for (size_t i = start; i < end; i++) {
      uintptr_t cursor = chunks[i].base;
      uintptr_t chunk_end = chunks[i].base + chunks[i].size;
      while (cursor < chunk_end) {
        uintptr_t found = safe_scan_memory(cursor, chunk_end - cursor, raw_bytes, raw_mask, pat_len);
        if (found == 0)
          break;
        if (found < exclude_start || found >= exclude_end)
          out.push_back(found);
        cursor = found + 1;
      }
    }
  };

  size_t per = chunks.size() / n_workers;
  size_t rem = chunks.size() % n_workers;
  size_t off = 0;
  for (unsigned int i = 0; i < n_workers; i++) {
    size_t count = per + (i < rem ? 1 : 0);
    threads.emplace_back(worker, off, off + count, std::ref(per_worker[i]));
    off += count;
  }

  for (auto &t : threads)
    t.join();

  // Flatten results
  std::vector<uintptr_t> results;
  for (auto &w : per_worker)
    for (uintptr_t a : w)
      results.push_back(a);

  return results;
}

} // namespace util
