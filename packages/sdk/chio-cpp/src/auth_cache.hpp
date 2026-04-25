#pragma once

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>

#include "chio/invariants.hpp"

namespace chio::detail {

inline std::string bearer_cache_key(std::string_view token) {
  auto digest = invariants::sha256_hex_utf8(token);
  if (digest) {
    return "sha256:" + digest.value();
  }

  std::uint64_t fallback = 1469598103934665603ull;
  for (unsigned char ch : token) {
    fallback ^= ch;
    fallback *= 1099511628211ull;
  }
  std::ostringstream out;
  out << "fallback-fnv1a64:" << token.size() << ":" << std::hex << fallback;
  return out.str();
}

}  // namespace chio::detail
