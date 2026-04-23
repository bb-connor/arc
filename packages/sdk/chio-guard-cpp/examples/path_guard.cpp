#include "chio/guard.hpp"

#include <string>

class PathGuard final : public chio::guard::Guard {
 public:
  chio::guard::Verdict evaluate(const chio::guard::GuardRequest& request) override {
    if (!request.extracted_path) {
      return chio::guard::Verdict::allow();
    }
    if (request.extracted_path->find("..") != std::string::npos) {
      return chio::guard::Verdict::deny("path traversal denied");
    }
    return chio::guard::Verdict::allow();
  }
};
