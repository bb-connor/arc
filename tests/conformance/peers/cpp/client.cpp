#include "chio/chio.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <unistd.h>

namespace {

struct Args {
  std::string base_url;
  std::string auth_mode = "static-bearer";
  std::string auth_token;
  std::string scenarios_dir;
  std::string results_output;
  std::string artifacts_dir;
};

struct Scenario {
  std::string id;
  std::string category;
};

struct Result {
  Scenario scenario;
  std::string status;
  std::string assertion_name;
  std::string assertion_status;
  std::string message;
  std::uint64_t duration_ms = 0;
};

std::string json_escape(const std::string& input) {
  std::ostringstream out;
  for (unsigned char c : input) {
    switch (c) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
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
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c) << std::dec << std::setfill(' ');
        } else {
          out << static_cast<char>(c);
        }
    }
  }
  return out.str();
}

std::string quote(const std::string& input) {
  return "\"" + json_escape(input) + "\"";
}

std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path);
  if (!input) {
    throw std::runtime_error("failed to read " + path.string());
  }
  return std::string((std::istreambuf_iterator<char>(input)),
                     std::istreambuf_iterator<char>());
}

void write_file(const std::filesystem::path& path, const std::string& value) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream output(path);
  if (!output) {
    throw std::runtime_error("failed to write " + path.string());
  }
  output << value;
}

std::string extract_string_field(const std::string& json, const std::string& field) {
  const std::string needle = "\"" + field + "\"";
  auto pos = json.find(needle);
  if (pos == std::string::npos) {
    return {};
  }
  pos = json.find(':', pos + needle.size());
  if (pos == std::string::npos) {
    return {};
  }
  pos = json.find('"', pos + 1);
  if (pos == std::string::npos) {
    return {};
  }
  std::string out;
  bool escaped = false;
  for (std::size_t i = pos + 1; i < json.size(); ++i) {
    const char c = json[i];
    if (escaped) {
      out.push_back(c);
      escaped = false;
      continue;
    }
    if (c == '\\') {
      escaped = true;
      continue;
    }
    if (c == '"') {
      return out;
    }
    out.push_back(c);
  }
  return {};
}

std::vector<Scenario> load_scenarios(const std::filesystem::path& root) {
  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
    if (entry.is_regular_file() && entry.path().extension() == ".json") {
      files.push_back(entry.path());
    }
  }
  std::sort(files.begin(), files.end());

  std::vector<Scenario> scenarios;
  for (const auto& file : files) {
    const auto contents = read_file(file);
    Scenario scenario;
    scenario.id = extract_string_field(contents, "id");
    scenario.category = extract_string_field(contents, "category");
    if (!scenario.id.empty()) {
      scenarios.push_back(std::move(scenario));
    }
  }
  return scenarios;
}

Args parse_args(int argc, char** argv) {
  Args args;
  std::map<std::string, std::string*> fields{
      {"--base-url", &args.base_url},
      {"--auth-mode", &args.auth_mode},
      {"--auth-token", &args.auth_token},
      {"--scenarios-dir", &args.scenarios_dir},
      {"--results-output", &args.results_output},
      {"--artifacts-dir", &args.artifacts_dir},
  };

  for (int i = 1; i < argc; i += 2) {
    if (i + 1 >= argc) {
      throw std::runtime_error("missing value for " + std::string(argv[i]));
    }
    const auto found = fields.find(argv[i]);
    if (found == fields.end()) {
      continue;
    }
    *found->second = argv[i + 1];
  }
  if (args.base_url.empty() || args.auth_token.empty() || args.scenarios_dir.empty() ||
      args.results_output.empty() || args.artifacts_dir.empty()) {
    throw std::runtime_error("missing required C++ conformance peer arguments");
  }
  return args;
}

Result pass(Scenario scenario, std::uint64_t duration_ms, std::string assertion_name) {
  return Result{std::move(scenario),
                "pass",
                std::move(assertion_name),
                "pass",
                {},
                duration_ms};
}

Result fail(Scenario scenario,
            std::uint64_t duration_ms,
            std::string assertion_name,
            std::string message) {
  return Result{std::move(scenario),
                "fail",
                std::move(assertion_name),
                "fail",
                std::move(message),
                duration_ms};
}

Result unsupported(Scenario scenario, std::uint64_t duration_ms, std::string message) {
  return Result{std::move(scenario),
                "unsupported",
                "scenario_supported_by_cpp_peer",
                "fail",
                std::move(message),
                duration_ms};
}

bool contains(const std::string& value, const std::string& needle) {
  return value.find(needle) != std::string::npos;
}

std::string shell_quote(const std::string& value) {
  std::string out = "'";
  for (char c : value) {
    if (c == '\'') {
      out += "'\\''";
    } else {
      out.push_back(c);
    }
  }
  out += "'";
  return out;
}

std::string trim_header_value(std::string value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.erase(value.begin());
  }
  while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) {
    value.pop_back();
  }
  return value;
}

std::map<std::string, std::string> parse_headers(const std::string& header_blob) {
  std::map<std::string, std::string> headers;
  std::istringstream input(header_blob);
  std::string line;
  while (std::getline(input, line)) {
    const auto colon = line.find(':');
    if (colon == std::string::npos) {
      continue;
    }
    headers[line.substr(0, colon)] = trim_header_value(line.substr(colon + 1));
  }
  return headers;
}

class CommandCurlTransport final : public chio::HttpTransport {
 public:
  chio::Result<chio::HttpResponse> send(const chio::HttpRequest& request) override {
    const auto body_path = write_temp_body(request.body);
    std::string command =
        "curl --silent --show-error --include --write-out '\\nCHIO_HTTP_STATUS:%{http_code}\\n'";
    command += " --request " + shell_quote(request.method);
    command += " --url " + shell_quote(request.url);
    for (const auto& header : request.headers) {
      command += " --header " + shell_quote(header.first + ": " + header.second);
    }
    if (!request.body.empty()) {
      command += " --data-binary @" + shell_quote(body_path.string());
    }

    std::array<char, 4096> buffer{};
    std::string output;
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) {
      std::filesystem::remove(body_path);
      return chio::Result<chio::HttpResponse>::failure(
          chio::Error{chio::ErrorCode::Transport, "failed to spawn curl"});
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
      output += buffer.data();
    }
    const int rc = pclose(pipe);
    std::filesystem::remove(body_path);
    if (rc != 0) {
      return chio::Result<chio::HttpResponse>::failure(
          chio::Error{chio::ErrorCode::Transport, "curl exited unsuccessfully"});
    }

    const std::string marker = "\nCHIO_HTTP_STATUS:";
    const auto marker_pos = output.rfind(marker);
    if (marker_pos == std::string::npos) {
      return chio::Result<chio::HttpResponse>::failure(
          chio::Error{chio::ErrorCode::Transport, "curl output did not include HTTP status"});
    }
    const auto status_text = output.substr(marker_pos + marker.size(), 3);
    const int status = std::atoi(status_text.c_str());
    const auto response_blob = output.substr(0, marker_pos);

    auto split = response_blob.rfind("\r\n\r\n");
    auto delimiter_size = std::string("\r\n\r\n").size();
    if (split == std::string::npos) {
      split = response_blob.rfind("\n\n");
      delimiter_size = std::string("\n\n").size();
    }
    if (split == std::string::npos) {
      return chio::Result<chio::HttpResponse>::success(
          chio::HttpResponse{status, {}, response_blob});
    }

    auto headers = parse_headers(response_blob.substr(0, split));
    auto body = response_blob.substr(split + delimiter_size);
    return chio::Result<chio::HttpResponse>::success(
        chio::HttpResponse{status, std::move(headers), std::move(body)});
  }

 private:
  static std::filesystem::path write_temp_body(const std::string& body) {
    auto path = std::filesystem::temp_directory_path() /
                ("chio-cpp-peer-body-" + std::to_string(getpid()) + ".json");
    write_file(path, body);
    return path;
  }
};

std::uint64_t elapsed_ms(std::chrono::steady_clock::time_point started) {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::steady_clock::now() - started)
          .count());
}

Result run_scenario(const Scenario& scenario, chio::Session& session) {
  const auto started = std::chrono::steady_clock::now();

  if (scenario.id == "initialize") {
    return pass(scenario, elapsed_ms(started), "session_initialized");
  }

  if (scenario.id == "tools-list") {
    auto response = session.list_tools();
    if (response && contains(response.value(), "echo_text")) {
      return pass(scenario, elapsed_ms(started), "tools_list_contains_echo_text");
    }
    return fail(scenario,
                elapsed_ms(started),
                "tools_list_contains_echo_text",
                response ? response.value() : response.error().message);
  }

  if (scenario.id == "tools-call-simple-text") {
    auto response = session.call_tool("echo_text", "{\"message\":\"hello from cpp peer\"}");
    if (response && contains(response.value(), "hello from cpp peer")) {
      return pass(scenario, elapsed_ms(started), "tool_result_matches_input_text");
    }
    return fail(scenario,
                elapsed_ms(started),
                "tool_result_matches_input_text",
                response ? response.value() : response.error().message);
  }

  if (scenario.id == "resources-list") {
    auto response = session.list_resources();
    if (response && contains(response.value(), "fixture://docs/alpha")) {
      return pass(scenario, elapsed_ms(started), "resources_list_contains_fixture_uri");
    }
    return fail(scenario,
                elapsed_ms(started),
                "resources_list_contains_fixture_uri",
                response ? response.value() : response.error().message);
  }

  if (scenario.id == "prompts-list") {
    auto response = session.list_prompts();
    if (response && contains(response.value(), "summarize_fixture")) {
      return pass(scenario, elapsed_ms(started), "prompts_list_contains_fixture_prompt");
    }
    return fail(scenario,
                elapsed_ms(started),
                "prompts_list_contains_fixture_prompt",
                response ? response.value() : response.error().message);
  }

  if (scenario.id == "tasks-call-get-result") {
    auto create = session.request(
        "tools/call",
        "{\"name\":\"echo_text\",\"arguments\":{\"message\":\"hello from cpp task peer\"},\"task\":{}}");
    if (!create || !contains(create.value(), "taskId")) {
      return fail(scenario,
                  elapsed_ms(started),
                  "task_created",
                  create ? create.value() : create.error().message);
    }
    const auto task_id = extract_string_field(create.value(), "taskId");
    auto result = session.get_task_result(task_id);
    if (result && contains(result.value(), "hello from cpp task peer")) {
      return pass(scenario,
                  elapsed_ms(started),
                  "tasks_result_returns_related_terminal_payload");
    }
    return fail(scenario,
                elapsed_ms(started),
                "tasks_result_returns_related_terminal_payload",
                result ? result.value() : result.error().message);
  }

  if (scenario.id == "tasks-cancel") {
    auto create = session.request(
        "tools/call",
        "{\"name\":\"slow_echo\",\"arguments\":{\"message\":\"hello from cpp cancel peer\"},\"task\":{}}");
    if (!create || !contains(create.value(), "taskId")) {
      return fail(scenario,
                  elapsed_ms(started),
                  "task_created",
                  create ? create.value() : create.error().message);
    }
    const auto task_id = extract_string_field(create.value(), "taskId");
    auto cancel = session.cancel_task(task_id);
    if (cancel && contains(cancel.value(), "cancelled")) {
      return pass(scenario, elapsed_ms(started), "tasks_cancel_marks_cancelled");
    }
    return fail(scenario,
                elapsed_ms(started),
                "tasks_cancel_marks_cancelled",
                cancel ? cancel.value() : cancel.error().message);
  }

  if (scenario.id == "catalog-list-changed-notifications") {
    auto response = session.call_tool(
        "emit_fixture_notifications",
        "{\"message\":\"hello from cpp notification peer\",\"uri\":\"fixture://docs/alpha\"}");
    if (response && contains(response.value(), "notifications/resources/list_changed") &&
        contains(response.value(), "notifications/tools/list_changed")) {
      return pass(scenario, elapsed_ms(started), "catalog_notifications_forwarded");
    }
    return fail(scenario,
                elapsed_ms(started),
                "catalog_notifications_forwarded",
                response ? response.value() : response.error().message);
  }

  if (scenario.id == "resources-subscribe-updated-notification") {
    return unsupported(scenario,
                       elapsed_ms(started),
                       "C++ streaming subscription helpers are not implemented yet");
  }

  return unsupported(scenario,
                     elapsed_ms(started),
                     "C++ peer does not yet implement OAuth discovery or nested callbacks");
}

std::string result_to_json(const Result& result, const std::string& transcript_path) {
  std::string out = "{";
  out += "\"scenarioId\":" + quote(result.scenario.id);
  out += ",\"peer\":\"cpp\"";
  out += ",\"peerRole\":\"client_to_chio_server\"";
  out += ",\"deploymentMode\":\"remote_http\"";
  out += ",\"transport\":\"streamable-http\"";
  out += ",\"specVersion\":\"2025-11-25\"";
  out += ",\"category\":" + quote(result.scenario.category);
  out += ",\"status\":" + quote(result.status);
  out += ",\"durationMs\":" + std::to_string(result.duration_ms);
  out += ",\"assertions\":[{\"name\":" + quote(result.assertion_name) +
         ",\"status\":" + quote(result.assertion_status);
  if (!result.message.empty()) {
    out += ",\"message\":" + quote(result.message);
  }
  out += "}]";
  if (result.status != "pass") {
    out += ",\"failureKind\":" + quote(result.status == "unsupported" ? "unsupported"
                                                                       : "assertion-failed");
    out += ",\"failureMessage\":" + quote(result.message);
  }
  out += ",\"artifacts\":{\"transcript\":" + quote(transcript_path) + "}";
  out += "}";
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const Args args = parse_args(argc, argv);
    std::cerr << "cpp peer: loading scenarios from " << args.scenarios_dir << "\n";
    const auto scenarios = load_scenarios(args.scenarios_dir);
    std::cerr << "cpp peer: loaded " << scenarios.size() << " scenarios\n";
    std::filesystem::create_directories(args.artifacts_dir);
    const auto transcript_path = std::filesystem::path(args.artifacts_dir) / "transcript.jsonl";
    write_file(transcript_path, "{\"peer\":\"cpp\",\"event\":\"started\"}\n");

    std::vector<Result> results;
    if (args.auth_mode != "static-bearer") {
      for (const auto& scenario : scenarios) {
        results.push_back(
            unsupported(scenario, 0, "C++ peer currently supports static bearer only"));
      }
    } else {
      auto transport = std::make_shared<CommandCurlTransport>();
      auto client = chio::Client::with_static_bearer(args.base_url, args.auth_token, transport);
      std::cerr << "cpp peer: initializing session\n";
      auto initialized = client.initialize();
      if (!initialized) {
        for (const auto& scenario : scenarios) {
          results.push_back(
              fail(scenario, 0, "session_initialized", initialized.error().message));
        }
      } else {
        auto session = initialized.move_value();
        for (const auto& scenario : scenarios) {
          results.push_back(run_scenario(scenario, session));
        }
        (void)session.close();
      }
    }

    std::string output = "[\n";
    for (std::size_t i = 0; i < results.size(); ++i) {
      if (i != 0) {
        output += ",\n";
      }
      output += "  " + result_to_json(results[i], transcript_path.string());
    }
    output += "\n]\n";
    write_file(args.results_output, output);
  } catch (const std::exception& error) {
    std::cerr << "C++ conformance peer failed: " << error.what() << "\n";
    return 1;
  }

  return 0;
}
