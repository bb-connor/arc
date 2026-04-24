#include "chio/kernel.hpp"

#include <optional>
#include <sstream>
#include <utility>

#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
#include "chio/chio_kernel_ffi.h"
#endif

namespace chio {
namespace kernel {
namespace {

std::string escape_json(const std::string& input) {
  std::ostringstream out;
  for (unsigned char c : input) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (c < 0x20) {
          static const char* digits = "0123456789abcdef";
          out << "\\u00" << digits[(c >> 4) & 0x0f] << digits[c & 0x0f];
        } else {
          out << static_cast<char>(c);
        }
        break;
    }
  }
  return out.str();
}

#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
std::string code_name(int code) {
  switch (code) {
    case CHIO_KERNEL_FFI_ERROR_NONE:
      return "";
    case CHIO_KERNEL_FFI_ERROR_INVALID_JSON:
      return "invalid_json";
    case CHIO_KERNEL_FFI_ERROR_INVALID_HEX:
      return "invalid_hex";
    case CHIO_KERNEL_FFI_ERROR_INVALID_CAPABILITY:
      return "invalid_capability";
    case CHIO_KERNEL_FFI_ERROR_INVALID_PASSPORT:
      return "invalid_passport";
    case CHIO_KERNEL_FFI_ERROR_KEY_MISMATCH:
      return "key_mismatch";
    case CHIO_KERNEL_FFI_ERROR_SIGNING_FAILED:
      return "signing_failed";
    case CHIO_KERNEL_FFI_ERROR_INTERNAL:
      return "internal";
    default:
      return "ffi_error";
  }
}

std::optional<std::string> json_string_field(const std::string& json,
                                             const std::string& key) {
  const std::string needle = "\"" + key + "\":";
  std::size_t pos = json.find(needle);
  if (pos == std::string::npos) {
    return std::nullopt;
  }
  pos += needle.size();
  while (pos < json.size() &&
         (json[pos] == ' ' || json[pos] == '\n' || json[pos] == '\r' ||
          json[pos] == '\t')) {
    ++pos;
  }
  if (pos >= json.size() || json[pos] != '"') {
    return std::nullopt;
  }
  ++pos;
  std::string out;
  while (pos < json.size()) {
    char c = json[pos++];
    if (c == '"') {
      return out;
    }
    if (c == '\\' && pos < json.size()) {
      char escaped = json[pos++];
      switch (escaped) {
        case '"':
        case '\\':
        case '/':
          out.push_back(escaped);
          break;
        case 'b':
          out.push_back('\b');
          break;
        case 'f':
          out.push_back('\f');
          break;
        case 'n':
          out.push_back('\n');
          break;
        case 'r':
          out.push_back('\r');
          break;
        case 't':
          out.push_back('\t');
          break;
        default:
          out.push_back('\\');
          out.push_back(escaped);
          break;
      }
    } else {
      out.push_back(c);
    }
  }
  return std::nullopt;
}
#endif

std::string result_json(const EvaluateResult& result) {
  std::ostringstream out;
  out << "{";
  out << "\"ok\":" << (result.ok ? "true" : "false");
  out << ",\"verdict\":\"" << escape_json(result.verdict) << "\"";
  out << ",\"reason\":\"" << escape_json(result.reason) << "\"";
  out << ",\"error_code\":\"" << escape_json(result.error_code) << "\"";
  out << ",\"error_message\":\"" << escape_json(result.error_message) << "\"";
  out << "}";
  return out.str();
}

EvaluateResult failure(std::string code, std::string message, std::string reason) {
  EvaluateResult result;
  result.ok = false;
  result.verdict = "deny";
  result.reason = std::move(reason);
  result.error_code = std::move(code);
  result.error_message = std::move(message);
  result.result_json = result_json(result);
  return result;
}

#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
std::string build_kernel_request_json(const KernelOptions& options,
                                      const EvaluateRequest& request) {
  const std::uint64_t now_secs =
      request.now_secs == 0 ? options.default_now_secs : request.now_secs;

  std::ostringstream out;
  out << "{";
  out << "\"capability\":" << request.capability_json;
  out << ",\"trusted_issuers\":[";
  for (std::size_t i = 0; i < request.trusted_issuers_hex.size(); ++i) {
    if (i != 0) {
      out << ",";
    }
    out << "\"" << escape_json(request.trusted_issuers_hex[i]) << "\"";
  }
  out << "]";
  out << ",\"request\":" << request.request_json;
  if (now_secs != 0) {
    out << ",\"now_secs\":" << now_secs;
  }
  out << "}";
  return out.str();
}

class KernelFfiBuffer {
 public:
  explicit KernelFfiBuffer(ChioKernelFfiBuffer buffer) : buffer_(buffer) {}
  KernelFfiBuffer(const KernelFfiBuffer&) = delete;
  KernelFfiBuffer& operator=(const KernelFfiBuffer&) = delete;
  ~KernelFfiBuffer() { chio_kernel_buffer_free(buffer_); }

  std::string str() const {
    if (buffer_.ptr == nullptr || buffer_.len == 0) {
      return {};
    }
    return std::string(reinterpret_cast<const char*>(buffer_.ptr),
                       buffer_.len);
  }

 private:
  ChioKernelFfiBuffer buffer_;
};

EvaluateResult from_ffi_result(const ChioKernelFfiResult& ffi_result) {
  KernelFfiBuffer data(ffi_result.data);
  std::string body = data.str();
  if (ffi_result.status == CHIO_KERNEL_FFI_STATUS_OK) {
    EvaluateResult result;
    result.ok = true;
    result.result_json = body;
    result.verdict = json_string_field(body, "verdict").value_or("deny");
    result.reason = json_string_field(body, "reason").value_or("");
    return result;
  }

  return failure(code_name(ffi_result.error_code), body, body);
}
#endif

}  // namespace

Kernel::Kernel(KernelOptions options) : options_(std::move(options)) {}

const KernelOptions& Kernel::options() const { return options_; }

const char* Kernel::version() { return "0.1.0"; }

bool Kernel::ffi_enabled() {
#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
  return true;
#else
  return false;
#endif
}

EvaluateResult Kernel::evaluate(const EvaluateRequest& request) const {
  if (!options_.fail_closed) {
    return failure(
        "unsupported_options",
        "chio-cpp-kernel only supports fail-closed evaluation",
        "in-process kernel FFI is not linked in this package skeleton");
  }

  if (request.request_json.empty()) {
    return failure(
        "invalid_argument",
        "EvaluateRequest.request_json must not be empty",
        "request payload missing");
  }

  if (request.capability_json.empty()) {
    return failure(
        "invalid_argument",
        "EvaluateRequest.capability_json must not be empty",
        "capability payload missing");
  }

  if (request.trusted_issuers_hex.empty()) {
    return failure(
        "invalid_argument",
        "EvaluateRequest.trusted_issuers_hex must not be empty",
        "trusted issuer set missing");
  }

#ifdef CHIO_CPP_KERNEL_ENABLE_FFI
  const std::string envelope = build_kernel_request_json(options_, request);
  return from_ffi_result(chio_kernel_evaluate_json(envelope.c_str()));
#else
  return failure(
      "unsupported",
      "chio-cpp-kernel was built without chio-cpp-kernel-ffi",
      "fail-closed until the Rust kernel FFI backend is linked");
#endif
}

}  // namespace kernel
}  // namespace chio
