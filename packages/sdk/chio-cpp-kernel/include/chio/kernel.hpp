#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace chio {
namespace kernel {

struct KernelOptions {
  std::string kernel_id = "chio-cpp-kernel";
  std::string policy_json;
  std::uint64_t default_now_secs = 0;
  bool fail_closed = true;
};

struct EvaluateRequest {
  std::string request_json;
  std::string capability_json;
  std::vector<std::string> trusted_issuers_hex;
  std::uint64_t now_secs = 0;
};

struct EvaluateResult {
  bool ok = false;
  std::string verdict = "deny";
  std::string reason;
  std::string error_code;
  std::string error_message;
  std::string result_json;
};

class Kernel {
 public:
  explicit Kernel(KernelOptions options = {});

  const KernelOptions& options() const;

  EvaluateResult evaluate(const EvaluateRequest& request) const;

  static const char* version();
  static bool ffi_enabled();

 private:
  KernelOptions options_;
};

}  // namespace kernel
}  // namespace chio
