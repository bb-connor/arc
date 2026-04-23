#include "chio/invariants.hpp"

#include <cstring>

#include "chio/chio_ffi.h"

namespace chio::invariants {
namespace {

Result<std::string> from_ffi(ChioFfiResult result) {
  std::string payload;
  if (result.data.ptr != nullptr && result.data.len > 0) {
    payload.assign(reinterpret_cast<const char*>(result.data.ptr), result.data.len);
  }
  chio_buffer_free(result.data);
  if (result.status == CHIO_FFI_STATUS_OK) {
    return Result<std::string>::success(std::move(payload));
  }
  return Result<std::string>::failure(
      Error{static_cast<ErrorCode>(result.error_code), std::move(payload)});
}

Result<bool> bool_from_ffi(ChioFfiResult result) {
  auto text = from_ffi(result);
  if (!text) {
    return Result<bool>::failure(text.error());
  }
  return Result<bool>::success(text.value() == "true");
}

std::string owned(std::string_view input) {
  return std::string(input.data(), input.size());
}

}  // namespace

Result<std::string> canonicalize_json(std::string_view input_json) {
  auto input = owned(input_json);
  return from_ffi(chio_canonicalize_json(input.c_str()));
}

Result<std::string> sha256_hex_utf8(std::string_view input_utf8) {
  auto input = owned(input_utf8);
  return from_ffi(chio_sha256_hex_utf8(input.c_str()));
}

Result<std::string> sha256_hex_bytes(const std::vector<std::uint8_t>& input) {
  return from_ffi(chio_sha256_hex_bytes(input.data(), input.size()));
}

Result<std::string> sign_utf8_message_ed25519(std::string_view input_utf8,
                                              std::string_view seed_hex) {
  auto input = owned(input_utf8);
  auto seed = owned(seed_hex);
  return from_ffi(chio_sign_utf8_message_ed25519(input.c_str(), seed.c_str()));
}

Result<bool> verify_utf8_message_ed25519(std::string_view input_utf8,
                                         std::string_view public_key_hex,
                                         std::string_view signature_hex) {
  auto input = owned(input_utf8);
  auto key = owned(public_key_hex);
  auto sig = owned(signature_hex);
  return bool_from_ffi(
      chio_verify_utf8_message_ed25519(input.c_str(), key.c_str(), sig.c_str()));
}

Result<std::string> sign_json_ed25519(std::string_view input_json,
                                      std::string_view seed_hex) {
  auto input = owned(input_json);
  auto seed = owned(seed_hex);
  return from_ffi(chio_sign_json_ed25519(input.c_str(), seed.c_str()));
}

Result<bool> verify_json_signature_ed25519(std::string_view input_json,
                                           std::string_view public_key_hex,
                                           std::string_view signature_hex) {
  auto input = owned(input_json);
  auto key = owned(public_key_hex);
  auto sig = owned(signature_hex);
  return bool_from_ffi(
      chio_verify_json_signature_ed25519(input.c_str(), key.c_str(), sig.c_str()));
}

Result<std::string> verify_capability_json(std::string_view input_json,
                                           std::uint64_t now_secs,
                                           std::uint32_t max_delegation_depth) {
  auto input = owned(input_json);
  return from_ffi(
      chio_verify_capability_json(input.c_str(), now_secs, max_delegation_depth));
}

Result<std::string> verify_receipt_json(std::string_view input_json) {
  auto input = owned(input_json);
  return from_ffi(chio_verify_receipt_json(input.c_str()));
}

Result<std::string> verify_manifest_json(std::string_view input_json) {
  auto input = owned(input_json);
  return from_ffi(chio_verify_manifest_json(input.c_str()));
}

}  // namespace chio::invariants
