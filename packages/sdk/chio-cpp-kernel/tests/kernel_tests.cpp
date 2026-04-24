#include "chio/kernel.hpp"

#include <cassert>
#include <string>

int main() {
  chio::kernel::Kernel kernel;

  assert(std::string(chio::kernel::Kernel::version()) == "0.1.0");
  assert(kernel.options().kernel_id == "chio-cpp-kernel");

  {
    chio::kernel::EvaluateRequest request;
    auto result = kernel.evaluate(request);
    assert(!result.ok);
    assert(result.verdict == "deny");
    assert(result.error_code == "invalid_argument");
    assert(result.result_json.find("\"ok\":false") != std::string::npos);
    assert(result.result_json.find("\"verdict\":\"deny\"") != std::string::npos);
  }

  {
    chio::kernel::EvaluateRequest request;
    request.request_json = "{\"request_id\":\"req-1\",\"tool_name\":\"echo\"}";
    request.capability_json = "{\"id\":\"cap-1\"}";
    request.trusted_issuers_hex.push_back("00");

    auto first = kernel.evaluate(request);
    auto second = kernel.evaluate(request);
    assert(!first.ok);
    assert(first.verdict == "deny");
    if (chio::kernel::Kernel::ffi_enabled()) {
      assert(first.error_code == "invalid_json");
    } else {
      assert(first.error_code == "unsupported");
    }
    assert(first.result_json == second.result_json);
  }

  return 0;
}
