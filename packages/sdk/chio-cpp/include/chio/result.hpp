#pragma once

#include <optional>
#include <string>
#include <utility>

namespace chio {

enum class ErrorCode {
  None = 0,
  InvalidPublicKey = 1,
  InvalidHex = 2,
  InvalidSignature = 3,
  Json = 4,
  CanonicalJson = 5,
  CapabilityExpired = 6,
  CapabilityNotYetValid = 7,
  CapabilityRevoked = 8,
  DelegationChainBroken = 9,
  AttenuationViolation = 10,
  ScopeMismatch = 11,
  SignatureVerificationFailed = 12,
  DelegationDepthExceeded = 13,
  InvalidHashLength = 14,
  MerkleProofFailed = 15,
  EmptyTree = 16,
  InvalidProofIndex = 17,
  EmptyManifest = 18,
  DuplicateToolName = 19,
  UnsupportedSchema = 20,
  ManifestVerificationFailed = 21,
  Transport = 200,
  Protocol = 201,
  Internal = 255,
};

struct Error {
  ErrorCode code = ErrorCode::None;
  std::string message;

  static Error none() { return {}; }
};

template <typename T>
class Result {
 public:
  static Result success(T value) { return Result(std::move(value)); }
  static Result failure(Error error) { return Result(std::move(error)); }

  bool ok() const { return value_.has_value(); }
  explicit operator bool() const { return ok(); }

  const T& value() const { return *value_; }
  T& value() { return *value_; }
  T&& move_value() { return std::move(*value_); }

  const Error& error() const { return error_; }

 private:
  explicit Result(T value) : value_(std::move(value)) {}
  explicit Result(Error error) : error_(std::move(error)) {}

  std::optional<T> value_;
  Error error_{ErrorCode::Internal, "result has no value"};
};

}  // namespace chio
