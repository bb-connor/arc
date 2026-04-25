#include <cstdlib>
#include <functional>
#include <memory>
#include <string>

#include <drogon/drogon.h>

#include "chio/drogon.hpp"

namespace {

std::string env_or_default(const char* name, const char* fallback) {
  const char* value = std::getenv(name);
  if (value == nullptr || std::string(value).empty()) {
    return fallback;
  }
  return value;
}

drogon::HttpResponsePtr json_response(const Json::Value& body) {
  auto response = drogon::HttpResponse::newHttpJsonResponse(body);
  response->setContentTypeCode(drogon::CT_APPLICATION_JSON);
  return response;
}

Json::Value base_body(const drogon::HttpRequestPtr& request) {
  Json::Value body(Json::objectValue);
  body["receipt_id"] = chio::drogon::receipt_id(request);
  body["handled_by"] = "drogon";
  return body;
}

void write_bad_request(const std::function<void(const drogon::HttpResponsePtr&)>& callback,
                       const std::string& error) {
  Json::Value body(Json::objectValue);
  body["error"] = error;
  auto response = json_response(body);
  response->setStatusCode(drogon::k400BadRequest);
  callback(response);
}

}  // namespace

int main() {
  chio::drogon::Options options;
  options.sidecar_url = env_or_default("CHIO_SIDECAR_URL", "http://127.0.0.1:9090");
  options.sidecar_failure_mode = chio::drogon::SidecarFailureMode::FailClosed;
  chio::drogon::configure(options);

  drogon::app().registerHandler(
      "/healthz",
      [](const drogon::HttpRequestPtr&,
         std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        Json::Value body(Json::objectValue);
        body["status"] = "ok";
        callback(json_response(body));
      },
      {drogon::Get});

  drogon::app().registerHandler(
      "/hello",
      [](const drogon::HttpRequestPtr& request,
         std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        Json::Value body = base_body(request);
        body["message"] = "hello from drogon";
        callback(json_response(body));
      },
      {drogon::Get, "chio::drogon::ChioMiddleware"});

  drogon::app().registerHandler(
      "/echo",
      [](const drogon::HttpRequestPtr& request,
         std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
        const auto payload = request->getJsonObject();
        if (!payload) {
          write_bad_request(callback, "expected JSON body");
          return;
        }

        Json::Value body = base_body(request);
        body["message"] = payload->isMember("message") ? (*payload)["message"].asString() : "";
        body["count"] = payload->isMember("count") ? (*payload)["count"].asInt() : 1;
        callback(json_response(body));
      },
      {drogon::Post, "chio::drogon::ChioMiddleware"});

  const auto port = static_cast<unsigned short>(
      std::stoi(env_or_default("HELLO_DROGON_PORT", "8020")));
  drogon::app().addListener("127.0.0.1", port);
  drogon::app().run();
}
