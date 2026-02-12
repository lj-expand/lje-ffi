#include "sigmask.hpp"

#include <capstone/capstone.h>
#include <cstdio>

namespace util {

static csh s_handle = 0;

static bool ensure_init() {
  if (s_handle)
    return true;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &s_handle) != CS_ERR_OK)
    return false;
  cs_option(s_handle, CS_OPT_DETAIL, CS_OPT_ON);
  return true;
}

std::string auto_mask_pattern(const std::vector<uint8_t> &bytes) {
  if (bytes.empty() || !ensure_init())
    return "";

  // Build a per-byte mask: true = keep, false = wildcard
  std::vector<uint8_t> mask(bytes.size(), true);

  cs_insn *insns;
  size_t count =
      cs_disasm(s_handle, bytes.data(), bytes.size(), 0, 0, &insns);

  if (count == 0) {
    // Disassembly failed - return unmasked pattern
    std::string result;
    for (size_t i = 0; i < bytes.size(); i++) {
      if (i > 0)
        result += ' ';
      char hex[4];
      snprintf(hex, sizeof(hex), "%02X", bytes[i]);
      result += hex;
    }
    return result;
  }

  // Walk each instruction and mask imm/disp bytes
  size_t byte_offset = 0;
  for (size_t i = 0; i < count; i++) {
    const cs_insn &insn = insns[i];
    if (insn.detail) {
      const cs_x86_encoding &enc = insn.detail->x86.encoding;

      if (enc.disp_offset > 0 && enc.disp_size > 0) {
        for (uint8_t j = 0; j < enc.disp_size; j++)
          mask[byte_offset + enc.disp_offset + j] = false;
      }

      if (enc.imm_offset > 0 && enc.imm_size > 0) {
        for (uint8_t j = 0; j < enc.imm_size; j++)
          mask[byte_offset + enc.imm_offset + j] = false;
      }
    }
    byte_offset += insn.size;
  }

  cs_free(insns, count);

  // Any trailing bytes that weren't disassembled stay as-is

  // Build the output pattern
  std::string result;
  result.reserve(bytes.size() * 3);
  for (size_t i = 0; i < bytes.size(); i++) {
    if (i > 0)
      result += ' ';
    if (mask[i]) {
      char hex[4];
      snprintf(hex, sizeof(hex), "%02X", bytes[i]);
      result += hex;
    } else {
      result += "??";
    }
  }

  return result;
}

} // namespace util
