#include "chio/kernel.hpp"

#include <cassert>
#include <string>

#include "../src/json_field.hpp"
#include "../src/kernel_request_json.hpp"

int main() {
  chio::kernel::Kernel kernel;

  assert(std::string(chio::kernel::Kernel::version()) == "0.1.0");
  assert(kernel.options().kernel_id == "chio-cpp-kernel");
  assert(!kernel.options().default_now_secs.has_value());

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
    auto escaped = chio::kernel::detail::json_string_field(
        "{\"reason\":\"line\\nslash\\\\tab\\tunicode\\u0041\"}", "reason");
    assert(escaped.has_value());
    assert(*escaped == "line\nslash\\tab\tunicode\\u0041");
    assert(!chio::kernel::detail::json_string_field("{\"reason\":\"\\uZZZZ\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field("{\"reason\":\"\\q\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        std::string("{\"reason\":\"line\nbreak\"}"), "reason"));
    auto real = chio::kernel::detail::json_string_field(
        "{\"message\":\"\\\"reason\\\":\\\"fake\\\"\",\"reason\":\"real\"}", "reason");
    assert(real.has_value());
    assert(*real == "real");
    assert(!chio::kernel::detail::json_string_field(
        "{\"message\":\"\\\"reason\\\":\\\"fake\\\"\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        "{\"ignored\":tru e,\"reason\":\"wrong\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        "{\"ignored\":@#$,\"reason\":\"wrong\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        "{\"ignored\":{\"bad\":tru e},\"reason\":\"wrong\"}", "reason"));
    assert(!chio::kernel::detail::json_string_field(
        "{\"ignored\":[true false],\"reason\":\"wrong\"}", "reason"));
  }

  {
    chio::kernel::KernelOptions options;
    options.default_now_secs = 77;
    chio::kernel::EvaluateRequest request;
    request.request_json = "{\"request_id\":\"req-epoch\",\"tool_name\":\"echo\"}";
    request.capability_json = "{\"id\":\"cap-epoch\"}";
    request.trusted_issuers_hex.push_back("00");

    request.now_secs = 0;
    auto explicit_epoch =
        chio::kernel::detail::build_kernel_request_json(options, request);
    assert(explicit_epoch.find("\"now_secs\":0") != std::string::npos);
    assert(explicit_epoch.find("\"now_secs\":77") == std::string::npos);

    request.now_secs.reset();
    auto default_time =
        chio::kernel::detail::build_kernel_request_json(options, request);
    assert(default_time.find("\"now_secs\":77") != std::string::npos);

    options.default_now_secs.reset();
    auto system_time =
        chio::kernel::detail::build_kernel_request_json(options, request);
    assert(system_time.find("\"now_secs\"") == std::string::npos);
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
