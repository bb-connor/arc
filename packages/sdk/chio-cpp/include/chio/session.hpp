#pragma once

#include <atomic>
#include <memory>
#include <string>

#include "chio/result.hpp"
#include "chio/transport.hpp"

namespace chio {

class Session {
 public:
  Session(std::string base_url,
          std::string bearer_token,
          std::string session_id,
          std::string protocol_version,
          HttpTransportPtr transport);

  Session(Session&& other) noexcept;
  Session& operator=(Session&& other) noexcept;

  Session(const Session&) = delete;
  Session& operator=(const Session&) = delete;

  Result<std::string> send_envelope(std::string body_json) const;
  Result<std::string> request(std::string method, std::string params_json = "{}") const;
  Result<std::string> notification(std::string method, std::string params_json = "{}") const;

  Result<std::string> list_tools() const;
  Result<std::string> call_tool(std::string name, std::string arguments_json = "{}") const;
  Result<std::string> list_resources() const;
  Result<std::string> read_resource(std::string uri) const;
  Result<std::string> list_prompts() const;
  Result<std::string> get_prompt(std::string name, std::string arguments_json = "{}") const;
  Result<std::string> list_tasks() const;
  Result<std::string> get_task(std::string task_id) const;
  Result<std::string> get_task_result(std::string task_id) const;
  Result<std::string> cancel_task(std::string task_id) const;
  Result<HttpResponse> close() const;

  const std::string& session_id() const { return session_id_; }
  const std::string& protocol_version() const { return protocol_version_; }

 private:
  HttpRequest make_post(std::string body_json) const;
  std::int64_t next_id() const;

  std::string base_url_;
  std::string bearer_token_;
  std::string session_id_;
  std::string protocol_version_;
  HttpTransportPtr transport_;
  mutable std::atomic<std::int64_t> next_request_id_{2};
};

}  // namespace chio
