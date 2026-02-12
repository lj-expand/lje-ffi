#pragma once

#include <cstdint>
#include <vector>

namespace util {

// Scan all committed rw- (non-image) pages in the process for a byte pattern.
// Coalesces adjacent pages, filters by min_size, parallelizes across cores.
// exclude_start/exclude_end can be used to skip a range (e.g., the pattern buffer itself).
std::vector<uintptr_t> scan_process_memory(const std::vector<uint8_t> &bytes,
                                           const std::vector<uint8_t> &mask, size_t min_size,
                                           uintptr_t exclude_start = 0,
                                           uintptr_t exclude_end = 0);

} // namespace util
