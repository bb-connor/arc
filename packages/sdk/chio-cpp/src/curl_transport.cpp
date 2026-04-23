#include "chio/transport.hpp"

#ifdef CHIO_CPP_HAS_CURL

#include <curl/curl.h>

#include <memory>

namespace chio {
namespace {

std::size_t write_body(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
  auto* body = static_cast<std::string*>(userdata);
  body->append(ptr, size * nmemb);
  return size * nmemb;
}

std::size_t write_header(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
  const std::size_t len = size * nitems;
  auto* headers = static_cast<std::map<std::string, std::string>*>(userdata);
  std::string line(buffer, len);
  const auto colon = line.find(':');
  if (colon != std::string::npos) {
    auto key = line.substr(0, colon);
    auto value = line.substr(colon + 1);
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
      value.erase(value.begin());
    }
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) {
      value.pop_back();
    }
    (*headers)[key] = value;
  }
  return len;
}

}  // namespace

Result<HttpResponse> CurlHttpTransport::send(const HttpRequest& request) {
  std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
  if (!curl) {
    return Result<HttpResponse>::failure(Error{ErrorCode::Transport, "curl_easy_init failed"});
  }

  std::string body;
  std::map<std::string, std::string> headers;
  curl_easy_setopt(curl.get(), CURLOPT_URL, request.url.c_str());
  curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, write_body);
  curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &body);
  curl_easy_setopt(curl.get(), CURLOPT_HEADERFUNCTION, write_header);
  curl_easy_setopt(curl.get(), CURLOPT_HEADERDATA, &headers);

  if (request.method == "POST") {
    curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, request.body.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, request.body.size());
  } else if (request.method != "GET") {
    curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, request.method.c_str());
    if (!request.body.empty()) {
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, request.body.c_str());
      curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, request.body.size());
    }
  }

  curl_slist* raw_headers = nullptr;
  for (const auto& header : request.headers) {
    const auto line = header.first + ": " + header.second;
    raw_headers = curl_slist_append(raw_headers, line.c_str());
  }
  std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> header_guard(raw_headers,
                                                                           curl_slist_free_all);
  if (raw_headers != nullptr) {
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, raw_headers);
  }

  const auto code = curl_easy_perform(curl.get());
  if (code != CURLE_OK) {
    return Result<HttpResponse>::failure(
        Error{ErrorCode::Transport, curl_easy_strerror(code)});
  }
  long status = 0;
  curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
  return Result<HttpResponse>::success(
      HttpResponse{static_cast<int>(status), std::move(headers), std::move(body)});
}

}  // namespace chio

#endif
