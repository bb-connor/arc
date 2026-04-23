#pragma once

#include <map>
#include <memory>
#include <string>

#include "chio/result.hpp"

namespace chio {

struct HttpRequest {
  std::string method;
  std::string url;
  std::map<std::string, std::string> headers;
  std::string body;
};

struct HttpResponse {
  int status = 0;
  std::map<std::string, std::string> headers;
  std::string body;
};

class HttpTransport {
 public:
  virtual ~HttpTransport() = default;
  virtual Result<HttpResponse> send(const HttpRequest& request) = 0;
};

#ifdef CHIO_CPP_HAS_CURL
class CurlHttpTransport final : public HttpTransport {
 public:
  Result<HttpResponse> send(const HttpRequest& request) override;
};
#endif

using HttpTransportPtr = std::shared_ptr<HttpTransport>;

}  // namespace chio
