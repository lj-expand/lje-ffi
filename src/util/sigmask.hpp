#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace util {

// Takes a raw hex byte pattern (e.g. "48 89 5C 24 08 E8 AB CD EF 01"),
// disassembles it with Capstone, and returns a masked pattern with
// immediates and displacements replaced by "??".
// Returns the original pattern unchanged if disassembly fails.
std::string auto_mask_pattern(const std::vector<uint8_t> &bytes);

} // namespace util
