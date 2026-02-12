#include "sigscan.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdlib>
#include <cstring>
#include <emmintrin.h> // SSE2
#include <intrin.h>    // _BitScanForward

namespace util {

bool parse_pattern(const char *pattern, std::vector<uint8_t> &bytes, std::vector<uint8_t> &mask) {
  bytes.clear();
  mask.clear();

  while (*pattern) {
    while (*pattern == ' ')
      pattern++;
    if (!*pattern)
      break;

    if (pattern[0] == '?' && pattern[1] == '?') {
      bytes.push_back(0);
      mask.push_back(0); // wildcard
      pattern += 2;
    } else {
      char hex[3] = {pattern[0], pattern[1], 0};
      char *end;
      auto byte = static_cast<uint8_t>(strtoul(hex, &end, 16));
      if (end != hex + 2)
        return false;
      bytes.push_back(byte);
      mask.push_back(1); // must match
      pattern += 2;
    }
  }
  return !bytes.empty();
}

uintptr_t scan_memory(uintptr_t start, size_t size, const uint8_t *bytes, const uint8_t *mask,
                      size_t pat_len) {
  auto data = reinterpret_cast<const uint8_t *>(start);

  if (size < pat_len || pat_len == 0)
    return 0;

  size_t scan_end = size - pat_len;

  // Find first two non-wildcard bytes for SIMD filtering
  size_t first_idx = SIZE_MAX;
  size_t second_idx = SIZE_MAX;
  for (size_t i = 0; i < pat_len; i++) {
    if (mask[i]) {
      if (first_idx == SIZE_MAX)
        first_idx = i;
      else if (second_idx == SIZE_MAX) {
        second_idx = i;
        break;
      }
    }
  }

  // All wildcards — first position matches
  if (first_idx == SIZE_MAX)
    return start;

  const uint8_t *pat_bytes = bytes;
  const uint8_t *pat_mask = mask;

  // SSE2: check 16 candidate positions at once
  __m128i first_byte_v = _mm_set1_epi8(static_cast<char>(bytes[first_idx]));
  bool has_second = second_idx != SIZE_MAX;
  __m128i second_byte_v;
  if (has_second)
    second_byte_v = _mm_set1_epi8(static_cast<char>(bytes[second_idx]));

  // SIMD loop: we load 16 bytes from data[i + first_idx], so we need i + first_idx + 16 <= size
  size_t max_load_offset = has_second ? (first_idx > second_idx ? first_idx : second_idx) : first_idx;
  size_t simd_limit = 0;
  if (size >= max_load_offset + 16)
    simd_limit = (size - max_load_offset - 16 < scan_end) ? size - max_load_offset - 16 : scan_end;

  size_t i = 0;
  for (; i <= simd_limit; i += 16) {
    __m128i chunk1 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(data + i + first_idx));
    int candidates = _mm_movemask_epi8(_mm_cmpeq_epi8(chunk1, first_byte_v));

    if (has_second) {
      __m128i chunk2 = _mm_loadu_si128(reinterpret_cast<const __m128i *>(data + i + second_idx));
      candidates &= _mm_movemask_epi8(_mm_cmpeq_epi8(chunk2, second_byte_v));
    }

    while (candidates) {
      unsigned long bit;
      _BitScanForward(&bit, candidates);
      size_t pos = i + bit;

      if (pos <= scan_end) {
        const uint8_t *mem = data + pos;
        bool match = true;
        for (size_t j = 0; j < pat_len; j++) {
          if (pat_mask[j] && mem[j] != pat_bytes[j]) {
            match = false;
            break;
          }
        }
        if (match)
          return start + pos;
      }

      candidates &= candidates - 1; // clear lowest set bit
    }
  }

  // Scalar tail for remaining positions
  for (; i <= scan_end; i++) {
    const uint8_t *mem = data + i;
    bool match = true;
    for (size_t j = 0; j < pat_len; j++) {
      if (pat_mask[j] && mem[j] != pat_bytes[j]) {
        match = false;
        break;
      }
    }
    if (match)
      return start + i;
  }

  return 0;
}

uintptr_t sigscan(uintptr_t start, size_t size, const char *pattern) {
  std::vector<uint8_t> bytes;
  std::vector<uint8_t> mask;

  if (!parse_pattern(pattern, bytes, mask)) {
    return 0;
  }

  return scan_memory(start, size, bytes, mask);
}

} // namespace util
