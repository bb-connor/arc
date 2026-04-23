#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace chio::guard {

struct Verdict {
  enum class Kind {
    Allow,
    Deny,
  };

  Kind kind = Kind::Deny;
  std::string reason;

  static Verdict allow() { return Verdict{Kind::Allow, {}}; }
  static Verdict deny(std::string message) { return Verdict{Kind::Deny, std::move(message)}; }
};

struct GuardRequest {
  std::string tool_name;
  std::string server_id;
  std::string agent_id;
  std::string arguments_json;
  std::vector<std::string> scopes;
  std::optional<std::string> action_type;
  std::optional<std::string> extracted_path;
  std::optional<std::string> extracted_target;
  std::vector<std::string> filesystem_roots;
  std::optional<std::uint32_t> matched_grant_index;
};

class Guard {
 public:
  virtual ~Guard() = default;
  virtual Verdict evaluate(const GuardRequest& request) = 0;
};

}  // namespace chio::guard
