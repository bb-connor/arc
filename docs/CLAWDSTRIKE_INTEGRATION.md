# ClawdStrike Integration Plan

How to port shared code from ClawdStrike into ARC and restructure the dependency
relationship so that ClawdStrike depends on ARC, not the other way around.

## 1. Architecture: Protocol vs Product

ARC is HTTP. ClawdStrike is nginx.

ARC defines the protocol layer: capability tokens, delegation chains, receipts,
guards, and canonical serialization. It is a minimal reference implementation
suitable for standards submissions (IETF, W3C, OpenSSF). It ships zero
application-layer opinions about fleet management, SIEM, or threat intelligence.

ClawdStrike is the batteries-included production deployment. It adds a policy
engine, 13 guards, SIEM exporters, a control console, fleet enrollment, posture
management, compliance templates, threat intel feeds, and desktop agents. It is
the commercial product built on top of the protocol.

Why the separation matters:

- **Standards submissions.** ARC must be vendor-neutral. Standards bodies will
  not adopt a spec that requires a specific product. The reference
  implementation must be self-contained.
- **Ecosystem adoption.** Third parties should be able to build their own
  "powered by ARC" products without pulling in ClawdStrike's application code,
  SIEM integrations, or fleet management.
- **Vendor neutrality.** ARC's crypto primitives (Ed25519, SHA-256, canonical
  JSON RFC 8785, RFC 6962 Merkle trees) are standard, auditable, and
  reproducible across languages. They belong in arc-core, not behind a
  product-specific namespace.

## 2. Dependency Direction

The target dependency graph. Arrows point from consumer to dependency.

```
arc-core (types, crypto, merkle, canonical JSON)
  ^
  |-- arc-kernel (capability validation, guard pipeline, receipt signing)
  |     ^
  |     |-- arc-guards (7 protocol-level guards)
  |     |-- arc-policy (policy compiler, resolver, evaluator)
  |     |-- arc-mcp-adapter, arc-cli, arc-conformance
  |     |
  |     |-- ClawdStrike (imports arc-core + arc-kernel as workspace deps)
  |           |-- adds: 6 application-layer guards (Jailbreak, PromptInjection,
  |           |         ComputerUse, InputInjectionCapability,
  |           |         RemoteDesktopSideChannel, SpiderSense)
  |           |-- adds: broker-specific HTTP adapters around shared ARC DPoP
  |           |-- adds: SIEM exporters (Splunk, Elastic, Datadog, Sumo Logic,
  |           |         Webhooks, Alerting)
  |           |-- adds: control console, fleet management, posture commands
  |           |-- adds: compliance templates, threat intel, marketplace
  |           |-- adds: async guard runtime (circuit breakers, caching, retry)
  |           |-- adds: telemetry bridges (Tetragon, Hubble, auditd, k8s-audit,
  |                     Darwin)
```

Today both projects maintain parallel implementations of the same crypto
primitives:

| Concept            | ARC module            | ClawdStrike module         |
|--------------------|------------------------|----------------------------|
| Ed25519 signing    | `arc_core::crypto`    | `hush_core::signing`       |
| SHA-256 hashing    | `arc_core::hashing`   | `hush_core::hashing`       |
| Canonical JSON     | `arc_core::canonical` | `hush_core::canonical`     |
| Merkle trees       | `arc_core::merkle`    | `hush_core::merkle`        |
| Receipts           | `arc_core::receipt`   | `hush_core::receipt`       |
| Capability tokens  | `arc_core::capability`| `hush_multi_agent::token`  |

After integration, arc-core is the single canonical source for all of these.

## 3. What to Port FROM ClawdStrike INTO ARC, and What Must Still Be Built Natively

### 3.1 DPoP Proof-of-Possession Binding

**Source (ClawdStrike):**
- `crates/services/clawdstrike-brokerd/src/capability.rs` -- `validate_dpop_binding()` (lines 233-324)
- `crates/libs/clawdstrike-broker-protocol/src/lib.rs` -- `binding_proof_message()`, `ProofBindingMode`, `ProofBinding`, `BindingProof` types

**Target (ARC):**
- `crates/arc-kernel/src/dpop.rs` (new module)
- Re-export from `arc_kernel::dpop`

**What to port:**
- `validate_dpop_binding()` -- verifies that a DPoP proof matches the key thumbprint bound into the capability, checks timestamp freshness, and validates the Ed25519 signature over a domain-separated message.
- `binding_proof_message()` -- use the broker's canonical message builder as a reference pattern, not as-is. Its current fields are HTTP-specific: `capability_id || method || url || body_sha256? || issued_at || nonce`.
- `ProofBindingMode` enum (`Loopback`, `Dpop`, `Mtls`) -- extensible binding modes.
- `ProofBinding` struct -- the binding constraint embedded in a capability token (mode + key_thumbprint + binding_sha256).
- `BindingProof` struct -- the proof the agent sends at invocation time (public_key + signature + issued_at + nonce).

**Adaptations needed:**
- Replace `BrokerCapability` references with `arc_core::CapabilityToken`. ARC's `CapabilityToken` already has a `subject: PublicKey` field that serves as the sender constraint. DPoP extends this with ephemeral proof freshness.
- Replace HTTP-request-shaped proof binding inputs (`method`, `url`, `body_sha256`) with a ARC invocation binding such as `capability_id`, `tool_server`, `tool_name`, canonical action/content hash, and optional request/session context.
- Replace `hush_core::{PublicKey, Signature}` with `arc_core::crypto::{PublicKey, Signature}`.
- Replace `hush_core::sha256_hex` with `arc_core::hashing::sha256_hex`.
- Replace `ApiError` returns with `arc_kernel::KernelError` variants.
- Remove `chrono` dependency -- use `u64` Unix timestamps to match ARC's existing convention.
- Add a `DpopConfig` struct with `proof_ttl_secs: u64` (default 60) and `max_clock_skew_secs: u64` (default 5).
- Add a replay-prevention store keyed by proof thumbprint + nonce (or equivalent). ClawdStrike's current source checks freshness but does not persist or reject nonce reuse.
- Keep SDK proof generation helpers in scope; porting only the verifier is not enough.

**Effort:** ~1-2 weeks (including replay protection, tests, and integration with the kernel's capability validation path).

### 3.2 Receipt Query API

**Source (ClawdStrike):**
- `crates/services/control-api/src/routes/receipts.rs` -- `ReceiptStore`, `StoredReceipt`, pagination, chain queries, batch verification

**Target (ARC):**
- `crates/arc-kernel/src/receipt_query.rs` (new module) -- query types and trait
- `crates/arc-kernel/src/receipt_store.rs` -- extend existing `SqliteReceiptStore` with query methods

**What to port:**
- **Pagination:** offset/limit list queries with tenant-scoped isolation. ClawdStrike's `list()` and `chain()` methods (lines 138-187 of `receipts.rs`) are useful references for paging and ordering.
- **Payload-size validation:** `MAX_RECEIPTS_PER_TENANT`, `MAX_RECEIPT_PAYLOAD_BYTES`, and `validate_payload_size()`.
- **Verification pattern:** signature verification over canonical receipt JSON.

**Adaptations needed:**
- Replace ClawdStrike's `StoredReceipt` with ARC's `ArcReceipt` (already defined in `arc_core::receipt`).
- Replace `hush_core::receipt::{SignedReceipt, VerificationResult, PublicKeySet}` with `arc_core::receipt::ArcReceipt` (which embeds `kernel_key` and `signature`).
- Replace Axum route handlers with a trait-based query API (`ReceiptQueryStore`) that can be consumed by arc-cli or any HTTP framework.
- Do not treat ClawdStrike's `(tenant_id, policy_name)` chain index as a ARC lineage model. In ARC, tool-receipt queries should remain keyed by capability/tool/time/decision and child-request queries by session/request lineage; agent-level joins come later via the capability lineage index.
- Add SQLite FTS or LIKE queries for receipt search (tool name, decision, timestamp range).

**Effort:** ~1 week.

### 3.3 Rate Limit / Velocity Guard

**Source (ClawdStrike):**
- `crates/libs/clawdstrike/src/async_guards/rate_limit.rs` -- `TokenBucket` struct (68 lines)

**Target (ARC):**
- `crates/arc-guards/src/velocity.rs` (new guard module)
- Register in `crates/arc-guards/src/lib.rs`

**What to port:**
- `TokenBucket` struct -- token-bucket rate limiter with fractional rates (e.g., 4 requests per 60 seconds), burst capacity, and refill math.
- `refill_locked()` -- computes elapsed time and adds tokens up to capacity.

**What not to port directly:**
- `acquire()` -- async waiting semantics are useful for service-internal throttling, but ARC guards should normally deny immediately rather than block a kernel evaluation path.

**Adaptations needed:**
- Wrap `TokenBucket` in a `VelocityGuard` that implements `arc_kernel::Guard`.
- The guard's `evaluate()` method uses `std::sync::Mutex` (not `tokio::Mutex`) since `arc_kernel::Guard::evaluate()` is synchronous. Use `try_acquire()` that returns `Verdict::Deny` immediately when the bucket is empty rather than blocking.
- Add per-agent and per-grant rate tracking: e.g. `HashMap<(AgentId, grant_index), TokenBucket>` or an equivalent keyed structure. Per-agent buckets alone do not cover grant-scoped spend windows.
- Capture `GuardEvidence` with `tokens_remaining`, `rate_per_sec`, `burst`, and `wait_estimate_ms`.
- Add `VelocityConfig` with `rate_per_interval`, `interval_secs`, `burst`, and `per_agent: bool`.
- For monetary velocity limits, derive debits from ARC budget/cost metadata rather than the ClawdStrike token bucket alone.

**Effort:** ~4-5 days.

### 3.4 SIEM Exporters

**Source (ClawdStrike):**
- `crates/services/hushd/src/siem/exporters/splunk.rs` -- Splunk HEC exporter
- `crates/services/hushd/src/siem/exporters/elastic.rs` -- Elasticsearch bulk API exporter
- `crates/services/hushd/src/siem/exporters/datadog.rs` -- Datadog agent exporter
- `crates/services/hushd/src/siem/exporters/sumo_logic.rs` -- Sumo Logic HTTP source exporter
- `crates/services/hushd/src/siem/exporters/webhooks.rs` -- Generic webhook exporter
- `crates/services/hushd/src/siem/exporters/alerting.rs` -- Alert rule engine
- `crates/services/hushd/src/siem/exporter.rs` -- `Exporter` trait, `ExporterConfig`, `RetryConfig`, `RateLimitConfig`
- `crates/services/hushd/src/siem/manager.rs` -- `ExporterManager`, `ExporterHandle`, `ExporterHealth`
- `crates/services/hushd/src/siem/dlq.rs` -- `DeadLetterQueue`, `DeadLetterEntry`
- `crates/services/hushd/src/siem/ratelimit.rs` -- `ExportRateLimiter`
- `crates/services/hushd/src/siem/filter.rs` -- `EventFilter`
- `crates/services/hushd/src/siem/types.rs` -- `SecurityEvent`

**Target (ARC):**
- New `crates/arc-siem/` crate with the following modules:
  - `src/lib.rs` -- crate root, re-exports
  - `src/exporter.rs` -- `Exporter` trait, `ExporterConfig`, `RetryConfig`
  - `src/exporters/splunk.rs`, `elastic.rs`, `datadog.rs`, `sumo_logic.rs`, `webhooks.rs`, `alerting.rs`
  - `src/manager.rs` -- `ExporterManager` for fan-out to multiple exporters
  - `src/dlq.rs` -- dead letter queue
  - `src/ratelimit.rs` -- per-exporter rate limiting
  - `src/filter.rs` -- event filtering
  - `src/event.rs` -- `SecurityEvent` type, built from `ArcReceipt`

**Adaptations needed:**
- Replace `SecurityEvent` with a ARC-native `ReceiptEvent` that wraps `ArcReceipt` plus routing metadata (exporter name, schema format, tenant context).
- Replace `hush_core` types in the event payload with `arc_core` types.
- Support schema formats: ECS, CEF, OCSF, Native (matching ClawdStrike's `SchemaFormat` enum).
- The `Exporter` trait's `export_batch()` method should accept `Vec<ReceiptEvent>` and return `ExportResult`.
- Batch processing: configurable `batch_size` (default 100) and `flush_interval_ms` (default 5000).
- Retry with exponential backoff: `max_retries`, `initial_backoff_ms`, `max_backoff_ms`, `backoff_multiplier`.
- Dead letter queue: filesystem-backed, size-capped, with structured `DeadLetterEntry` records.
- Make the crate optional behind a `siem` feature flag in arc-cli.

**Effort:** ~2 weeks.

### 3.5 Checkpoint Statement Pattern (Merkle Wiring)

**Source (ClawdStrike):**
- `crates/libs/spine/src/checkpoint.rs` -- `checkpoint_statement()`, `checkpoint_hash()`, `checkpoint_witness_message()`, `sign_checkpoint_statement()`, `verify_witness_signature()`

**Target (ARC):**
- `crates/arc-kernel/src/checkpoint.rs` (new module)
- Extend `crates/arc-kernel/src/receipt_store.rs` (`SqliteReceiptStore`)

**What to port:**
- `checkpoint_statement()` -- builds an unsigned checkpoint JSON object containing `log_id`, `checkpoint_seq`, `prev_checkpoint_hash`, `merkle_root`, `tree_size`, and `issued_at`.
- `checkpoint_hash()` -- computes SHA-256 over the canonical JSON of a checkpoint statement.
- `checkpoint_witness_message()` -- useful as a domain-separation pattern if ARC later adds witness co-signatures.
- `sign_checkpoint_statement()` / `verify_witness_signature()` -- useful reference for checkpoint signature envelopes.

**Adaptations needed:**
- Do not port Merkle tree construction itself. ARC already has `arc_core::merkle::MerkleTree`; this work is about checkpoint schema, hashing, persistence, and verification.
- Replace `hush_core::{canonicalize_json, sha256, Hash, Keypair, PublicKey, Signature}` with `arc_core::{canonicalize, sha256, Hash, Keypair, PublicKey, Signature}`.
- Change the domain separation tag from `"AegisNetCheckpointHashV1"` to `"ArcCheckpointHashV1"`.
- Change the schema identifier from `"aegis.spine.checkpoint_statement.v1"` to `"arc.checkpoint_statement.v1"`.
- Wire into `SqliteReceiptStore`: after every N receipts (configurable), build a `MerkleTree` from the batch, call `checkpoint_statement()`, sign it with the kernel's keypair, and store the checkpoint row.
- Add a `checkpoints` table to the SQLite schema: `(seq, checkpoint_seq, merkle_root, tree_size, checkpoint_hash, statement_json, signature_json)`.
- Expose `SqliteReceiptStore::latest_checkpoint()`, `SqliteReceiptStore::verify_checkpoint()`, and inclusion-proof query methods.
- Treat witness co-signatures as optional future work. Q2 only requires kernel-signed checkpoints so Merkle commitment becomes externally verifiable.

**Effort:** ~1 week.

### 3.6 Capability Lineage Index (ARC-Native Companion Work)

**Source (ClawdStrike):**
- No direct equivalent. ClawdStrike does not currently provide the capability snapshot index ARC needs for agent-centric joins.

**Target (ARC):**
- `crates/arc-kernel/src/capability_index.rs` (new module) or equivalent persistence integrated with the authority/store layer

**Why it matters:**
- Agent-centric receipt queries, local reputation, and per-grant budget attribution all depend on a deterministic join from `receipt.capability_id` to capability subject, issuer, grants, and delegation metadata.

**What must be built natively:**
- Persist issued capability snapshots keyed by `capability_id`
- Record subject, issuer, grants, and delegation metadata needed for joins
- Provide a deterministic join path from receipts to the matched grant context
- Make the index queryable without replaying issuance logs

**Phase:** Q3 2026 native ARC work. This is a prerequisite for reputation and agent-level analytics, and it is not supplied by any direct ClawdStrike code port.

## 4. What ClawdStrike Should Import FROM ARC

Once arc-core becomes the canonical source of truth, ClawdStrike should add
`arc-core` and `arc-kernel` as workspace dependencies and replace its internal
implementations.

| ClawdStrike module                | Replaced by                  | Notes                                                    |
|-----------------------------------|------------------------------|----------------------------------------------------------|
| `hush_core::signing`              | `arc_core::crypto`          | `Keypair`, `PublicKey`, `Signature`, `Signer` trait       |
| `hush_core::hashing`             | `arc_core::hashing`         | `sha256()`, `sha256_hex()`, `Hash` type                  |
| `hush_core::canonical`           | `arc_core::canonical`       | `canonicalize()`, `canonical_json_bytes()`                |
| `hush_core::merkle`              | `arc_core::merkle`          | `MerkleTree`, `MerkleProof`                              |
| `hush_core::receipt`             | `arc_core::receipt`         | `ArcReceipt` replaces `SignedReceipt`; `Decision` replaces `Verdict` |
| `hush_multi_agent::token`        | `arc_core::capability`      | `CapabilityToken` replaces `DelegationClaims`; `DelegationLink` replaces `chn` chains |
| `hush_multi_agent::revocation`   | `arc_kernel::revocation_store` | `SqliteRevocationStore` with the same bloom + SQLite pattern |

Additional imports ClawdStrike should make:

- `arc_kernel::Guard` trait replaces `clawdstrike::guards::Guard` trait. ClawdStrike's `GuardResult` maps to `arc_kernel::Verdict` + `arc_core::GuardEvidence`.
- `arc_kernel::CapabilityAuthority` replaces ad-hoc token issuance in `hush_multi_agent`.
- `arc_core::ToolManifest` replaces any internal tool discovery schemas.

ClawdStrike should re-export selected ARC types under its own namespace for
backwards compatibility during the transition, while keeping adapters for
incompatible wire formats:

```rust
// In clawdstrike/crates/libs/hush-core/src/lib.rs (transitional)
pub use arc_core::crypto::{Keypair, PublicKey, Signature};
pub use arc_core::hashing::{sha256, sha256_hex, Hash};
pub use arc_core::canonical::canonicalize as canonicalize_json;
pub use arc_core::merkle::{MerkleTree, MerkleProof};
```

## 5. Migration Sequence

### Phase 1: Port code from ClawdStrike into ARC (Q2 2026)

Target: ARC gains the shared building blocks from Sections 3.1-3.5, with full
test coverage and no runtime dependency on ClawdStrike. The capability lineage
index in Section 3.6 remains native Q3 work.

| Week | Deliverable                         | Owner | Validation                                         |
|------|-------------------------------------|-------|-----------------------------------------------------|
| 1-2  | DPoP proof-of-possession module     | --    | Unit tests; replay/nonce rejection tests; integration test with arc-cli |
| 2-3  | Receipt query API + SQLite indexes  | --    | Query tests; arc-cli `receipt list` subcommand      |
| 3    | Velocity guard in arc-guards       | --    | Guard pipeline tests; conformance test               |
| 4-5  | Checkpoint statement pattern        | --    | Checkpoint sign/verify tests; Merkle batch test      |
| 5-6  | Integration test: full receipt flow | --    | End-to-end: issue cap, invoke tool, sign receipt, verify checkpoint |

### Phase 2: Add arc-core as a workspace dependency in ClawdStrike + SIEM (Q3 2026)

**SIEM exporter porting** (moved from Phase 1 to align with Strategic Roadmap Q3 placement):

| Week | Deliverable                         | Owner | Validation                                         |
|------|-------------------------------------|-------|-----------------------------------------------------|
| 1-2  | arc-siem crate (6 exporters)       | --    | Mock SIEM endpoint tests; DLQ round-trip test        |

**ClawdStrike dependency restructure:**

Target: ClawdStrike's `Cargo.toml` workspace members include `arc-core` and
`arc-kernel` as path or git dependencies.

Steps:
1. Add `arc-core` and `arc-kernel` to the ClawdStrike workspace `[dependencies]`.
2. Create a `hush-core` compatibility shim with selective re-exports and
   adapter types. Do not use a blanket `pub use arc_core::*`; preserve the
   module structure while adapting incompatible types and wire formats.
3. Run the full ClawdStrike test suite. Fix type mismatches (e.g., `Verdict` vs
   `Decision`, `SignedReceipt` vs `ArcReceipt`).
4. Update the ClawdStrike CI pipeline to build both workspaces.

Risk mitigation: use a feature flag `arc-backend` (default off) during this
phase. ClawdStrike CI runs tests with both `arc-backend` on and off.

### Phase 3: Replace hush-core internals with arc-core re-exports (Q3-Q4 2026)

Target: `hush-core` becomes a thin facade over arc-core. No duplicated crypto
code remains.

Steps:
1. Remove `hush_core::signing` implementation; replace with `pub use arc_core::crypto::*`.
2. Remove `hush_core::hashing` implementation; replace with `pub use arc_core::hashing::*`.
3. Remove `hush_core::canonical` implementation; replace with `pub use arc_core::canonical::*`.
4. Remove `hush_core::merkle` implementation; replace with `pub use arc_core::merkle::*`.
5. Keep `hush_core::tpm` (TPM-sealed key support is ClawdStrike-specific).
6. Keep `hush_core::duration` (human duration parsing is application-level).
7. Remove `hush_core::receipt` implementation; replace with adapter types that
   convert between `ArcReceipt` and ClawdStrike's `SignedReceipt` wire format.

### Phase 4: ClawdStrike fully depends on arc-core + arc-kernel (Q4 2026)

Target: `hush-core` is deprecated as the source of shared primitives. All
ClawdStrike crates import directly from `arc_core` and `arc_kernel` for
shared protocol types. Only ClawdStrike-specific helpers or compatibility
adapters remain in `hush-core` (or a successor compat crate).

Steps:
1. Replace all `use hush_core::` with `use arc_core::` across the ClawdStrike
   workspace (`hushd`, `control-api`, `clawdstrike-brokerd`, all bridges).
2. Replace `hush_multi_agent::token::DelegationClaims` with
   `arc_core::capability::CapabilityToken`. Write a migration for any
   persisted delegation tokens.
3. Replace ClawdStrike's `Guard` trait with `arc_kernel::Guard`. Adapt
   the async guard runtime to wrap synchronous ARC guards with
   `tokio::task::spawn_blocking`.
4. Move the remaining ClawdStrike-specific `hush-core` modules (`tpm`,
   duration parsing, wire-format adapters) into a small compatibility crate or
   leave them as the only surviving `hush-core` modules.
5. Delete `hush-multi-agent` crate (delegation logic now in arc-core/arc-kernel).
6. Update ClawdStrike documentation and SDK references.

## 6. What Stays in ClawdStrike Only

The following components are application-layer concerns that do not belong in a
protocol specification. They remain exclusively in ClawdStrike.

### Application-Layer Guards

| Guard                          | Source file                                                        | Why it stays                                      |
|--------------------------------|--------------------------------------------------------------------|---------------------------------------------------|
| `JailbreakGuard`               | `crates/libs/clawdstrike/src/guards/jailbreak.rs`                 | ML-based detection, model-specific heuristics      |
| `PromptInjectionGuard`         | `crates/libs/clawdstrike/src/guards/prompt_injection.rs`          | NLP pipeline, vendor-specific scoring              |
| `ComputerUseGuard`             | `crates/libs/clawdstrike/src/guards/computer_use.rs`              | CUA-specific policy (screenshot, click, type)      |
| `InputInjectionCapabilityGuard`| `crates/libs/clawdstrike/src/guards/input_injection_capability.rs` | Desktop input event filtering                      |
| `RemoteDesktopSideChannelGuard`| `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs`| RDP/VNC side-channel detection                     |
| `SpiderSense`                  | `crates/libs/clawdstrike/src/spider_sense.rs`                     | Behavioral anomaly scoring                         |
| `CustomGuardRegistry`          | `crates/libs/clawdstrike/src/guards/custom.rs`                    | User-defined guard loading via WASM/plugin         |

### Async Guard Runtime

| Component          | Source file                                                    | Why it stays                          |
|--------------------|----------------------------------------------------------------|---------------------------------------|
| `AsyncGuardRuntime`| `crates/libs/clawdstrike/src/async_guards/runtime.rs`         | Tokio-specific orchestration          |
| Circuit breakers   | `crates/libs/clawdstrike/src/async_guards/circuit_breaker.rs` | Production resilience pattern         |
| Guard caching      | `crates/libs/clawdstrike/src/async_guards/cache.rs`           | Result memoization                    |
| Guard retry        | `crates/libs/clawdstrike/src/async_guards/retry.rs`           | Retry with backoff for external calls |
| Threat intel feed  | `crates/libs/clawdstrike/src/async_guards/threat_intel/`      | External threat feed integration      |

### Fleet Management and Control Plane

- Control API (`crates/services/control-api/`) -- tenant management, agent enrollment, policy CRUD, delegation graph visualization, compliance checks, billing, hunt queries, response actions, case management
- Posture commands (`crates/libs/clawdstrike/src/posture.rs`) -- agent health posture, compliance scoring
- RBAC (`crates/services/hushd/src/rbac/`) -- role-based access control for the control plane itself
- Policy engine cache (`crates/services/hushd/src/policy_engine_cache.rs`)
- Certification webhooks (`crates/services/hushd/src/certification_webhooks.rs`)

### Telemetry Bridges

| Bridge                  | Source directory                              |
|-------------------------|-----------------------------------------------|
| Tetragon bridge         | `crates/bridges/tetragon-bridge/`             |
| Hubble bridge           | `crates/bridges/hubble-bridge/`               |
| auditd bridge           | `crates/bridges/auditd-bridge/`               |
| k8s-audit bridge        | `crates/bridges/k8s-audit-bridge/`            |
| Darwin telemetry bridge | `crates/bridges/darwin-telemetry-bridge/`      |

### Other Product-Specific Components

- Desktop/agent apps (`apps/`)
- WASM guard runtime (`crates/libs/hush-wasm/`)
- Guard SDK and macros (`crates/libs/clawdstrike-guard-sdk/`, `crates/libs/clawdstrike-guard-sdk-macros/`)
- OCSF event schema (`crates/libs/clawdstrike-ocsf/`)
- Policy event types (`crates/libs/clawdstrike-policy-event/`)
- Spine NATS transport (`crates/libs/spine/src/nats_transport.rs`)
- Spine marketplace facts (`crates/libs/spine/src/marketplace_spine.rs`, `marketplace_facts.rs`)
- Threat intelligence correlations (`crates/libs/hunt-correlate/`, `hunt-query/`, `hunt-scan/`)
- Registry service (`crates/services/clawdstrike-registry/`)
- EAS anchor service (`crates/services/eas-anchor/`)
- Logos Z3 solver integration (`crates/libs/logos-z3/`)
- Output sanitizer (`crates/libs/clawdstrike/src/output_sanitizer.rs`)
- Watermarking (`crates/libs/clawdstrike/src/watermarking.rs`)
- Marketplace feed (`crates/libs/clawdstrike/src/marketplace_feed.rs`)
- Instruction hierarchy (`crates/libs/clawdstrike/src/instruction_hierarchy.rs`)

## 7. Type Mapping Reference

Quick reference for developers porting code between the two projects.

| ClawdStrike type                          | ARC equivalent                              |
|-------------------------------------------|----------------------------------------------|
| `hush_core::Keypair`                      | `arc_core::crypto::Keypair`                 |
| `hush_core::PublicKey`                    | `arc_core::crypto::PublicKey`               |
| `hush_core::Signature`                    | `arc_core::crypto::Signature`               |
| `hush_core::Hash`                         | `arc_core::hashing::Hash`                   |
| `hush_core::sha256()`                     | `arc_core::hashing::sha256()`               |
| `hush_core::sha256_hex()`                | `arc_core::hashing::sha256_hex()`           |
| `hush_core::canonicalize_json()`         | `arc_core::canonical::canonicalize()`       |
| `hush_core::MerkleTree`                  | `arc_core::merkle::MerkleTree`              |
| `hush_core::MerkleProof`                 | `arc_core::merkle::MerkleProof`             |
| `hush_core::SignedReceipt`               | `arc_core::receipt::ArcReceipt`            |
| `hush_core::Verdict`                     | `arc_core::receipt::Decision`               |
| `hush_core::Receipt`                     | `arc_core::receipt::ArcReceiptBody`        |
| `hush_multi_agent::DelegationClaims`     | `arc_core::capability::CapabilityToken`     |
| `hush_multi_agent::AgentCapability`      | `arc_core::capability::ArcScope`           |
| `hush_multi_agent::AgentId`             | `arc_core::AgentId` (`String`)              |
| `clawdstrike::guards::Guard` (trait)     | `arc_kernel::Guard` (trait)                 |
| `clawdstrike::guards::GuardResult`       | `arc_kernel::Verdict` + `arc_core::GuardEvidence` |
| `clawdstrike::guards::GuardAction`       | `arc_kernel::GuardContext`                  |
| `clawdstrike::guards::GuardContext`      | `arc_kernel::GuardContext` (different shape) |
| `clawdstrike::guards::Severity`          | No direct equivalent; map to `GuardEvidence::details` |

## 8. Risk Register

| Risk                                  | Impact | Mitigation                                                        |
|---------------------------------------|--------|-------------------------------------------------------------------|
| Type divergence during parallel dev   | High   | Freeze arc-core public API before Phase 2; semver guarantees     |
| ClawdStrike test suite regression     | High   | Feature flag (`arc-backend`) with dual CI runs                   |
| Canonical JSON output differs         | Critical | Property-based fuzz tests comparing `hush_core::canonicalize_json` vs `arc_core::canonicalize` output on 10k random JSON values |
| Merkle tree compatibility             | Critical | Cross-validate tree roots: same leaves must produce same root in both implementations before deleting hush-core version |
| Ed25519 signature compatibility       | Critical | Sign with hush-core, verify with arc-core (and vice versa) in CI |
| Performance regression in guard eval  | Medium | Benchmark `Guard::evaluate()` latency before and after migration  |
| DPoP replay protection missing from source port | High   | Treat broker DPoP code as verifier source material only; add a ARC-specific proof message and nonce replay store before claiming completion |
| Capability lineage index assumed to come from ClawdStrike | High   | Build the capability snapshot/index natively in ARC; do not couple agent analytics or reputation work to ClawdStrike control-api indexes |
| SIEM exporter API surface too large   | Medium | Put arc-siem behind a feature flag; keep arc-core/arc-kernel lean |
| Breaking changes in arc-core affect ClawdStrike releases | Medium | Pin arc-core version in ClawdStrike; bump deliberately          |
