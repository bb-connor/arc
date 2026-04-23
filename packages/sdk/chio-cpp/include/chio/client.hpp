#pragma once

#include <memory>
#include <string>

#include "chio/result.hpp"
#include "chio/session.hpp"
#include "chio/transport.hpp"

namespace chio {

struct ClientOptions {
  std::string base_url;
  std::string bearer_token;
  std::string client_name = "chio-cpp";
  std::string client_version = "0.1.0";
  std::string protocol_version = "2025-11-25";
};

class Client {
 public:
  Client(ClientOptions options, HttpTransportPtr transport);

  static Client with_static_bearer(std::string base_url,
                                   std::string bearer_token,
                                   HttpTransportPtr transport);

  Result<Session> initialize() const;

 private:
  ClientOptions options_;
  HttpTransportPtr transport_;
};

}  // namespace chio
