#pragma once

#include <cstdint>
#include <vector>

namespace util {

// Parse pattern like "41 ?? 2F 49" into bytes and mask
bool parse_pattern(const char *pattern, std::vector<uint8_t> &bytes, std::vector<uint8_t> &mask);

// Scan memory for pattern, returns address or 0 if not found
uintptr_t scan_memory(uintptr_t start, size_t size, const uint8_t *bytes, const uint8_t *mask,
                      size_t pat_len);

// Vector convenience overload
inline uintptr_t scan_memory(uintptr_t start, size_t size, const std::vector<uint8_t> &bytes,
                              const std::vector<uint8_t> &mask) {
  return scan_memory(start, size, bytes.data(), mask.data(), bytes.size());
}

// Convenience: parse + scan in one call
uintptr_t sigscan(uintptr_t start, size_t size, const char *pattern);

} // namespace util
