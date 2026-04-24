#include "chio/features.hpp"

#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>
#include <utility>

#include "chio/client.hpp"
#include "chio/invariants.hpp"
#include "json.hpp"

namespace chio {
namespace {

std::string random_hex(std::size_t bytes) {
  std::random_device rng;
  std::ostringstream out;
  for (std::size_t i = 0; i < bytes; ++i) {
    out << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<unsigned int>(rng() & 0xffU);
  }
  return out.str();
}

std::string capability_id_from_json(const std::string& capability_json) {
  auto parsed = detail::parse_json(capability_json);
  if (parsed) {
    auto id = parsed->string_field("id");
    if (!id.empty()) {
      return id;
    }
    id = parsed->string_field("capability_id");
    if (!id.empty()) {
      return id;
    }
  }
  auto id = detail::extract_json_string_field(capability_json, "id");
  if (!id.empty()) {
    return id;
  }
  return detail::extract_json_string_field(capability_json, "capability_id");
}

}  // namespace

std::uint64_t SystemClock::now_unix_secs() const {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(now).count());
}

Result<std::string> RandomNonceGenerator::generate_nonce() {
  return Result<std::string>::success(random_hex(16));
}

StaticSeedKeyProvider::StaticSeedKeyProvider(std::string seed_hex)
    : seed_hex_(std::move(seed_hex)) {}

Result<std::string> StaticSeedKeyProvider::ed25519_seed_hex() {
  if (seed_hex_.empty()) {
    return Result<std::string>::failure(
        Error{ErrorCode::Protocol, "seed is empty",
              "StaticSeedKeyProvider::ed25519_seed_hex"});
  }
  return Result<std::string>::success(seed_hex_);
}

DpopProofBuilder& DpopProofBuilder::capability_id(std::string value) {
  params_.capability_id = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::tool_server(std::string value) {
  params_.tool_server = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::tool_name(std::string value) {
  params_.tool_name = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::action_args_json(std::string value) {
  params_.action_args_json = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::key_provider(KeyProviderPtr value) {
  key_provider_ = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::nonce_generator(NonceGeneratorPtr value) {
  nonce_generator_ = std::move(value);
  return *this;
}

DpopProofBuilder& DpopProofBuilder::clock(ClockPtr value) {
  clock_ = std::move(value);
  return *this;
}

Result<DpopProof> DpopProofBuilder::build() const {
  if (!key_provider_) {
    return Result<DpopProof>::failure(
        Error{ErrorCode::Protocol, "key provider is required", "DpopProofBuilder::build"});
  }
  auto params = params_;
  auto seed = key_provider_->ed25519_seed_hex();
  if (!seed) {
    return Result<DpopProof>::failure(seed.error());
  }
  params.agent_seed_hex = seed.value();
  if (params.nonce.empty()) {
    auto generator = nonce_generator_ ? nonce_generator_
                                      : std::make_shared<RandomNonceGenerator>();
    auto nonce = generator->generate_nonce();
    if (!nonce) {
      return Result<DpopProof>::failure(nonce.error());
    }
    params.nonce = nonce.value();
  }
  if (params.issued_at == 0) {
    auto clock = clock_ ? clock_ : std::make_shared<SystemClock>();
    params.issued_at = clock->now_unix_secs();
  }
  return sign_dpop_proof(params);
}

ReceiptVerifier::ReceiptVerifier(std::shared_ptr<ReceiptQueryClient> remote_query)
    : remote_query_(std::move(remote_query)) {}

Result<std::string> ReceiptVerifier::verify_local(std::string receipt_json) const {
  return invariants::verify_receipt_json(receipt_json);
}

Result<std::string> ReceiptVerifier::verify(
    std::string receipt_json,
    const std::map<std::string, std::string>& fallback_query) const {
  auto local = verify_local(std::move(receipt_json));
  if (local || !remote_query_) {
    return local;
  }
  return remote_query_->query(fallback_query);
}

CapabilityVerifier::CapabilityVerifier(ClockPtr clock,
                                       std::uint32_t max_delegation_depth,
                                       RevocationHook revocation_hook)
    : clock_(std::move(clock)),
      max_delegation_depth_(max_delegation_depth),
      revocation_hook_(std::move(revocation_hook)) {}

Result<std::string> CapabilityVerifier::verify(std::string capability_json) const {
  const auto capability_id = capability_id_from_json(capability_json);
  if (revocation_hook_ && !capability_id.empty()) {
    auto revoked = revocation_hook_(capability_id);
    if (!revoked) {
      return Result<std::string>::failure(revoked.error());
    }
    if (revoked.value()) {
      return Result<std::string>::failure(
          Error{ErrorCode::CapabilityRevoked, "capability is revoked",
                "CapabilityVerifier::verify"});
    }
  }
  const auto now = clock_ ? clock_->now_unix_secs() : SystemClock().now_unix_secs();
  return invariants::verify_capability_json(capability_json, now, max_delegation_depth_);
}

ToolClient::ToolClient(Session& session, std::string name)
    : session_(&session), name_(std::move(name)) {}

Result<std::string> ToolClient::call_json(std::string arguments_json) const {
  return session_->call_tool(name_, std::move(arguments_json));
}

Result<TypedResponse<std::string>> ToolClient::call_typed(
    std::string arguments_json) const {
  const auto id = "tools/call";
  auto raw = session_->request(id,
                               "{\"name\":" + detail::quote(name_) +
                                   ",\"arguments\":" + arguments_json + "}");
  if (!raw) {
    return Result<TypedResponse<std::string>>::failure(raw.error());
  }
  return Result<TypedResponse<std::string>>::success(
      TypedResponse<std::string>{raw.value(), raw.value(), HttpResponse{}});
}

Result<std::shared_ptr<Session>> SessionPool::get_or_initialize(const Client& client) {
  const auto& options = client.options();
  const auto key = options.base_url + "\n" + options.bearer_token + "\n" +
                   options.protocol_version;
  std::shared_ptr<std::mutex> initialization_lock;
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto found = sessions_.find(key);
    if (found != sessions_.end()) {
      auto existing = found->second.lock();
      if (existing) {
        return Result<std::shared_ptr<Session>>::success(existing);
      }
    }
    auto& pending_lock = initialization_locks_[key];
    if (!pending_lock) {
      pending_lock = std::make_shared<std::mutex>();
    }
    initialization_lock = pending_lock;
  }

  std::lock_guard<std::mutex> key_lock(*initialization_lock);
  {
    std::lock_guard<std::mutex> lock(mu_);
    auto found = sessions_.find(key);
    if (found != sessions_.end()) {
      auto existing = found->second.lock();
      if (existing) {
        initialization_locks_.erase(key);
        return Result<std::shared_ptr<Session>>::success(existing);
      }
    }
  }

  auto initialized = client.initialize();
  if (!initialized) {
    std::lock_guard<std::mutex> lock(mu_);
    initialization_locks_.erase(key);
    return Result<std::shared_ptr<Session>>::failure(initialized.error());
  }
  auto session = std::make_shared<Session>(initialized.move_value());
  std::lock_guard<std::mutex> lock(mu_);
  sessions_[key] = session;
  initialization_locks_.erase(key);
  return Result<std::shared_ptr<Session>>::success(std::move(session));
}

void SessionPool::clear() {
  std::lock_guard<std::mutex> lock(mu_);
  sessions_.clear();
  initialization_locks_.clear();
}

}  // namespace chio
