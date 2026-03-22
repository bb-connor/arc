# Architecture Research

**Domain:** Agent economy infrastructure -- secure capability transport with monetary metering and compliance observability
**Researched:** 2026-03-21
**Confidence:** HIGH (based on direct codebase analysis, not external sources)

---

## Standard Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Agent Layer (untrusted)                      │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────────┐    │
│  │  LLM Agent    │  │  SDK Client   │  │  DPoP Proof Generator │    │
│  │  (any lang)   │  │  (TS/Py/Go)   │  │  (per-invocation)     │    │
│  └───────┬───────┘  └───────┬───────┘  └──────────┬────────────┘    │
└──────────┼──────────────────┼───────────────────────┼───────────────┘
           │  capability token + DPoP proof            │
           ▼                                           │
┌─────────────────────────────────────────────────────────────────────┐
│                   Trusted Kernel (TCB) -- pact-kernel                │
│                                                                      │
│  ┌──────────────────┐   ┌─────────────────┐   ┌──────────────────┐  │
│  │ Capability        │   │  Guard Pipeline │   │  Receipt Signer  │  │
│  │ Validation        │   │  (pact-guards)  │   │  + Checkpointer  │  │
│  │ + DPoP Verify     │   │  (pact-policy)  │   │  (Merkle batch)  │  │
│  └────────┬─────────┘   └────────┬────────┘   └────────┬─────────┘  │
│           │                      │                      │            │
│  ┌────────▼──────────────────────▼──────────────────────▼─────────┐  │
│  │                    Kernel Execution Core                        │  │
│  │   validate_cap → run_guards → dispatch → sign_receipt           │  │
│  │   debit_monetary_budget (new) → checkpoint_if_batch_full        │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                                                                      │
│  Stores (SQLite, WAL mode)                                           │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┐  │
│  │ receipt_store│ │ budget_store │ │ revoc_store  │ │ authority  │  │
│  │ + checkpoints│ │ + cost_debit │ │              │ │ + cap_idx  │  │
│  │   (new)      │ │   (new)      │ │              │ │   (new Q3) │  │
│  └──────────────┘ └──────────────┘ └──────────────┘ └────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
┌────────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│  Tool Servers  │  │  Receipt Query   │  │  SIEM / Dashboard    │
│  (sandboxed)   │  │  API (new Q2)    │  │  (pact-siem, new Q3) │
│  + cost report │  │  pact-cli serve  │  │  + receipt dashboard │
└────────────────┘  └──────────────────┘  └──────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Crate / Location |
|-----------|----------------|------------------|
| `pact-core` | Canonical types: capabilities, receipts, Merkle, canonical JSON, crypto, `ToolGrant` with monetary fields | `crates/pact-core` |
| `pact-kernel` | TCB: cap validation, guard dispatch, receipt signing, Merkle checkpointing, budget debiting, DPoP verification | `crates/pact-kernel` |
| `pact-guards` | Guard implementations including velocity (new) | `crates/pact-guards` |
| `pact-policy` | HushSpec compiler, policy evaluator, guard bridge | `crates/pact-policy` |
| `pact-manifest` | Tool server manifest format, pricing metadata (new Q3) | `crates/pact-manifest` |
| `pact-mcp-adapter` | MCP server wrapping with secured edge | `crates/pact-mcp-adapter` |
| `pact-cli` | CLI binary: `serve`, `receipt list` (new), trust-control host | `crates/pact-cli` |
| `pact-bindings-core` | Shared SDK plumbing for TS/Python/Go bindings | `crates/pact-bindings-core` |
| `pact-siem` | SIEM exporter fan-out: Splunk, Elastic, Datadog, Sumo, Webhooks, Alerting (new Q3 crate) | `crates/pact-siem` (new) |

---

## New Components: Integration Points

### 1. Monetary Budgets

**Where it lives:** Extends existing types across two crates.

**pact-core additions:**
- `MonetaryAmount` type: `{ amount_micro: u64, currency: String }` -- using micro-units avoids floating-point in signed payloads. Single currency in Q2; multi-currency deferred to Q4.
- `ToolGrant` new optional fields: `max_cost_per_invocation: Option<MonetaryAmount>` and `max_total_cost: Option<MonetaryAmount>`.
- `ToolInvocationCost` type: tool server reports actual cost per invocation, attached to the receipt.
- Schema migration: remove `deny_unknown_fields` from `ToolGrant`, `CapabilityToken`, `CapabilityTokenBody`, `PactScope`, `DelegationLink`, `PactReceipt`, `PactReceiptBody`. Add `#[serde(default)]` + `#[serde(skip_serializing_if = "...")]` guards on new fields so old kernels round-trip cleanly.

**pact-kernel additions (budget_store.rs):**
- `try_charge_cost(capability_id, grant_index, cost: MonetaryAmount, max_total: MonetaryAmount) -> Result<bool, BudgetStoreError>` method on `BudgetStore` trait.
- `SqliteBudgetStore` schema: add `cost_micro` and `currency` columns to `capability_grant_budgets`. Existing `invocation_count` path is unchanged.
- `CostUsageRecord` alongside existing `BudgetUsageRecord`.
- Monetary debit occurs in the kernel execution path after cap validation, before guard pipeline (so guards can inspect remaining budget if needed), fail-closed if the charge fails.

**Data flow (monetary path):**
```
Agent invocation
  → Kernel validates capability signature + time + revocation
  → Kernel calls try_charge_cost() atomically (IMMEDIATE transaction)
      [deny immediately if budget exhausted or currency mismatch]
  → Guard pipeline runs (velocity guard can inspect remaining budget via GuardContext)
  → Tool dispatch
  → Tool server reports ToolInvocationCost in response
  → Receipt body includes cost_charged + cost_reported fields
  → Receipt signed and appended
```

### 2. Merkle Checkpointing

**Where it lives:** `pact-kernel/src/checkpoint.rs` (new module) + `pact-kernel/src/receipt_store.rs` (extended).

**Design:**
- After every N receipts (configurable, default 100), the kernel builds a `MerkleTree` from that batch using `pact_core::merkle::MerkleTree`.
- `checkpoint_statement()` produces a canonical JSON object: `{ schema: "pact.checkpoint_statement.v1", log_id, checkpoint_seq, prev_checkpoint_hash, merkle_root, tree_size, issued_at }`.
- Kernel signs the checkpoint with its Ed25519 keypair.
- `SqliteReceiptStore` gains a `checkpoints` table: `(seq, checkpoint_seq, merkle_root, tree_size, checkpoint_hash, statement_json, signature_json)`.
- Public API: `latest_checkpoint()`, `verify_inclusion(receipt_id)`, `checkpoints_after_seq(seq)`.

**Integration note:** The Merkle module (`pact_core::merkle::MerkleTree`) already exists and is correct. This is purely wiring work.

### 3. DPoP Proof-of-Possession

**Where it lives:** `pact-kernel/src/dpop.rs` (new module).

**Design:**
- `ProofBinding` struct embedded in `CapabilityToken` (as optional field post-schema-migration): `{ mode: ProofBindingMode, key_thumbprint: String }`.
- `BindingProof` struct sent by agent at invocation time: `{ public_key: PublicKey, signature: Signature, issued_at: u64, nonce: String }`.
- `DpopConfig`: `proof_ttl_secs: u64` (default 60), `max_clock_skew_secs: u64` (default 5).
- `validate_dpop_binding()`: verifies signature, checks freshness window, rejects replayed nonces.
- Nonce replay store: `InMemoryNonceStore` for single-node (bounded TTL map), `SqliteNonceStore` for HA deployments.
- Proof message is PACT-specific, not HTTP-shaped: `capability_id || tool_server || tool_name || content_hash_of_action || issued_at || nonce`. This departs from the ClawdStrike HTTP-verb-based shape intentionally.

**Dependency note:** DPoP validation lives in pact-kernel, not pact-core, because it requires I/O (time, nonce store). The proof generation helpers belong in the SDK layer (pact-bindings-core).

### 4. Receipt Query API

**Where it lives:** `pact-kernel/src/receipt_query.rs` (new module) extending existing `SqliteReceiptStore`.

**Design:**
- `ReceiptQuery` struct: `{ capability_id, tool_server, tool_name, decision_kind, time_range, budget_impact, limit, after_seq }` -- all fields optional.
- `ReceiptQueryResult`: paginated `Vec<PactReceipt>` with `next_cursor`.
- `SqliteReceiptStore` gains a single `query_tool_receipts(query: ReceiptQuery)` method that builds the SQL filter dynamically. The existing indexed columns (`capability_id`, `tool_server`, `tool_name`, `decision_kind`, `timestamp`) already cover all needed filter dimensions.
- `pact-cli` exposes `pact receipt list [--cap <id>] [--tool <name>] [--decision allow|deny] [--since <timestamp>]` subcommand consuming this API.

**What this is not:** Agent-level joins (e.g., "all receipts for agent X across all capabilities") require the capability lineage index, which is Q3 work. Q2 receipt query is grant/tool/time-scoped only.

### 5. Velocity Guard

**Where it lives:** `crates/pact-guards/src/velocity.rs` (new module), registered in `pact-guards/src/lib.rs`.

**Design:**
- `VelocityGuard` implements `pact_kernel::Guard` (synchronous `evaluate()`).
- Uses `try_acquire()` semantics from a token-bucket: returns `Verdict::Deny` immediately when bucket is empty, no blocking.
- `std::sync::Mutex` wrapping the bucket -- not `tokio::Mutex` -- because the guard trait is synchronous.
- Bucket keyed by `(capability_id, grant_index)` for per-grant windows, with optional `per_agent: bool` mode keying by `agent_id` instead.
- `VelocityConfig`: `max_invocations: u32`, `window_secs: u64`, `burst: Option<u32>`. Separate `max_cost_per_window: Option<MonetaryAmount>` for monetary velocity (depends on budget debit completing before guard runs).
- `GuardEvidence` captures `tokens_remaining`, `window_resets_at`, `denied_reason`.

### 6. SIEM Exporters (Q3, new crate)

**Where it lives:** `crates/pact-siem/` (new crate, behind `siem` feature flag in pact-cli).

**Design:**
```
crates/pact-siem/
  src/lib.rs         -- crate root, Exporter trait, ExporterConfig, RetryConfig
  src/event.rs       -- ReceiptEvent: PactReceipt + routing metadata + schema format
  src/manager.rs     -- ExporterManager: fan-out to configured exporters
  src/dlq.rs         -- DeadLetterQueue: filesystem-backed, size-capped
  src/ratelimit.rs   -- per-exporter rate limiter
  src/filter.rs      -- EventFilter: decision/tool/agent/time predicates
  src/exporters/
    splunk.rs        -- Splunk HEC
    elastic.rs       -- Elasticsearch bulk API
    datadog.rs       -- Datadog agent
    sumo_logic.rs    -- Sumo Logic HTTP source
    webhooks.rs      -- generic webhook
    alerting.rs      -- alert rule engine
```

- `ReceiptEvent` wraps `PactReceipt` (not ClawdStrike `SecurityEvent` types). ECS, CEF, OCSF, Native schema formats.
- `ExporterManager` reads `SqliteReceiptStore::list_tool_receipts_after_seq()` with a persisted cursor -- pull model, not push -- so SIEM export does not block the kernel hot path.
- Batch size: 100 receipts per flush (configurable). Flush interval: 5000ms (configurable).
- Retry: exponential backoff with `max_retries`, `initial_backoff_ms`, `max_backoff_ms`.

**Crate isolation rationale:** SIEM exporters pull in HTTP client dependencies (reqwest or similar) that must not touch pact-kernel or pact-core. The feature-flag approach keeps the kernel build lean for embedded and WASM targets.

### 7. Capability Lineage Index (Q3)

**Where it lives:** `crates/pact-kernel/src/capability_index.rs` (new module).

**Design (planned, not yet built):**
- Persist issued capability snapshots at issuance time via `CapabilityAuthority::issue_capability()` hook.
- SQLite table: `(capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth)`.
- Indexed on `subject_key` for agent-centric queries.
- `CapabilityIndex::resolve(capability_id) -> Option<CapabilitySnapshot>` -- synchronous lookup, O(1) by ID.
- `CapabilityIndex::receipts_for_agent(subject_key) -> Vec<CapabilityId>` -- returns IDs for subsequent receipt queries.

**Dependency:** This is a Q3 prerequisite for the receipt dashboard and analytics API. The receipt query API (Q2) does not need it -- Q2 queries are capability-ID-scoped. The lineage index adds the agent-to-capabilities layer.

---

## Component Boundaries

| Boundary | Direction | Notes |
|----------|-----------|-------|
| `pact-core` → nothing | pact-core is leaf, no I/O, no runtime deps | WASM/embedded safe. Do not add tokio or rusqlite here. |
| `pact-kernel` → `pact-core` | kernel imports core types | Monetary types (`MonetaryAmount`, `ToolInvocationCost`) must be defined in pact-core since they flow into `ToolGrant` and `PactReceipt` |
| `pact-guards` → `pact-kernel` (Guard trait) | guards implement the kernel's Guard interface | VelocityGuard belongs in pact-guards, not pact-kernel, to match the existing guard crate separation |
| `pact-policy` → `pact-kernel` | policy compiler produces guards registered on kernel | No change needed for v2 features |
| `pact-siem` → `pact-kernel` | SIEM reads from receipt store via pull cursor | One-directional: SIEM never writes to the kernel. Keeps pact-siem behind a feature flag. |
| `pact-cli` → all above | binary that wires everything | Receipt query subcommand, serve command, SIEM start command |
| DPoP | `pact-kernel::dpop` | Proof generation helpers in `pact-bindings-core` for SDK use; validation in kernel |

---

## Data Flow

### Tool Invocation with Monetary Budgets

```
Agent
  │  (capability_token + dpop_proof + tool_call)
  ▼
Kernel: validate_capability()
  │  check signature, time bounds, revocation status
  ├─ DENY → sign receipt(deny, "capability_invalid") → append → return
  │
  ▼
Kernel: validate_dpop_binding()  [if DPoP required by token]
  │  verify proof signature, freshness, nonce uniqueness
  ├─ DENY → sign receipt(deny, "dpop_invalid") → append → return
  │
  ▼
Kernel: budget_store.try_charge_cost()  [if monetary limit set]
  │  atomic debit in SQLite IMMEDIATE transaction
  ├─ DENY → sign receipt(deny, "budget_exhausted") → append → return
  │
  ▼
Guard Pipeline (pact-guards + pact-policy compiled guards)
  │  VelocityGuard, PathAllowlist, SecretLeak, etc.
  ├─ DENY → sign receipt(deny, guard_evidence) → append → return
  │
  ▼
Tool Dispatch → Tool Server
  │  tool server executes, returns result + ToolInvocationCost
  │
  ▼
Receipt Body Assembly
  │  { ..existing fields.., cost_charged, cost_reported, merkle_batch_seq }
  │
  ▼
Receipt Sign + Append to SqliteReceiptStore
  │
  ▼
Checkpoint? (if batch_size receipts accumulated)
  │  build MerkleTree over batch, sign checkpoint, persist checkpoint row
  │
  ▼
(async, separate task)
ExporterManager polls receipt_store.list_tool_receipts_after_seq(cursor)
  → fan-out to configured SIEM exporters
```

### Receipt Query Flow

```
CLI / external HTTP client
  │  GET /receipts?cap=<id>&tool=<name>&decision=allow&since=<ts>
  ▼
pact-cli receipt handler
  │
  ▼
SqliteReceiptStore::query_tool_receipts(ReceiptQuery)
  │  SQL: WHERE cap=? AND tool=? AND decision=? AND timestamp >= ?
  │  ORDER BY seq DESC LIMIT 100
  ▼
Vec<PactReceipt> → JSON response / terminal table
```

### Checkpoint Verification Flow

```
External verifier (regulator, auditor)
  │  receipt_id + claimed merkle_root
  ▼
SqliteReceiptStore::verify_inclusion(receipt_id)
  │  1. lookup receipt → get batch seq
  │  2. fetch checkpoint for that batch
  │  3. rebuild MerkleTree for batch receipts
  │  4. compute inclusion proof for receipt_id
  │  5. verify proof root matches signed checkpoint root
  │  6. verify checkpoint kernel signature
  ▼
VerificationResult { valid: bool, checkpoint_seq, merkle_root, kernel_key }
```

---

## Recommended Project Structure Changes

No new top-level crates needed in Q2. Three modules added to existing crates:

```
crates/pact-core/src/
  capability.rs       -- ADD: MonetaryAmount, ToolInvocationCost, ToolGrant new fields
  receipt.rs          -- ADD: cost_charged/cost_reported fields to PactReceiptBody
  manifest.rs         -- LATER Q3: pricing fields on ToolDefinition

crates/pact-kernel/src/
  budget_store.rs     -- ADD: try_charge_cost(), CostUsageRecord, monetary SQLite columns
  receipt_store.rs    -- ADD: checkpoints table, query_tool_receipts(), verify_inclusion()
  checkpoint.rs       -- NEW: checkpoint_statement(), sign_checkpoint(), checkpoint schema
  dpop.rs             -- NEW: ProofBinding, BindingProof, DpopConfig, validate_dpop_binding()
  receipt_query.rs    -- NEW: ReceiptQuery, ReceiptQueryResult (thin wrapper over store)

crates/pact-guards/src/
  velocity.rs         -- NEW: VelocityGuard, VelocityConfig, TokenBucket
  lib.rs              -- ADD: pub use velocity::VelocityGuard

crates/pact-cli/src/
  receipts.rs         -- NEW: `pact receipt list` subcommand
  main.rs             -- ADD: receipt subcommand registration
```

Q3 additions:

```
crates/pact-siem/               -- NEW CRATE (feature-flagged)
  Cargo.toml
  src/lib.rs
  src/event.rs
  src/manager.rs
  src/dlq.rs
  src/ratelimit.rs
  src/filter.rs
  src/exporters/{splunk,elastic,datadog,sumo_logic,webhooks,alerting}.rs

crates/pact-kernel/src/
  capability_index.rs  -- NEW Q3: CapabilityIndex, CapabilitySnapshot
```

---

## Build Order (Dependency Graph for Phases)

Items listed in strict dependency order. Each item unblocks the next.

**Layer 0: Schema foundation (must go first, everything else depends on it)**
1. `pact-core` schema migration: remove `deny_unknown_fields`, add `#[serde(default)]` guards
2. `pact-core` monetary types: `MonetaryAmount`, `ToolInvocationCost`, new `ToolGrant` fields

**Layer 1: Core enforcement (parallel after Layer 0)**
3a. `pact-kernel::budget_store` -- monetary debit path (`try_charge_cost`)
3b. `pact-kernel::checkpoint` -- Merkle checkpoint module
3c. `pact-guards::velocity` -- VelocityGuard (synchronous token-bucket)

**Layer 2: Kernel wiring (after Layer 1)**
4. Wire monetary debit into the kernel execution path (budget check before guard pipeline)
5. Wire checkpoint trigger into receipt append path (after receipt signed, check batch count)
6. Register VelocityGuard in pact-guards default pipeline

**Layer 3: Query and access surface (after Layer 1)**
7. `pact-kernel::receipt_query` -- ReceiptQuery struct + SqliteReceiptStore::query_tool_receipts()
8. `pact-cli::receipts` -- `pact receipt list` subcommand

**Layer 4: DPoP (can parallel-track with Layers 1-3, but must come after Layer 0)**
9. `pact-kernel::dpop` -- proof binding types, validate_dpop_binding(), nonce stores
10. `pact-bindings-core` -- proof generation helpers for SDK use

**Layer 5: SIEM (Q3, after Layer 2 checkpointing is stable)**
11. `pact-siem` new crate -- exporter infrastructure
12. Wire ExporterManager to SqliteReceiptStore cursor in pact-cli serve

**Layer 6: Capability lineage index (Q3, after Layer 2 is stable)**
13. `pact-kernel::capability_index` -- snapshot persistence at issuance time
14. Extend `pact-cli` receipt queries with agent-centric joins

**Layer 7: Receipt dashboard (Q3, after Layer 6)**
15. Standalone web tool or pact-cli `serve --dashboard` -- reads via receipt_query + capability_index

---

## Architectural Patterns

### Pattern 1: Schema Extension Without Breaking Old Kernels

**What:** Remove `deny_unknown_fields` from all serializable types in pact-core. Add new fields with `#[serde(default)]` and `#[serde(skip_serializing_if = "Option::is_none")]`.

**When to use:** Every v2 field addition to `ToolGrant`, `PactReceiptBody`, `CapabilityToken`.

**Trade-offs:** Old kernels deserializing new tokens silently drop unknown fields rather than returning an error. This is correct behavior for forward compatibility. The security impact is bounded: the kernel still validates what it knows. New fields that carry security semantics (DPoP binding, monetary limits) must be validated at the issuing authority before tokens are issued to old kernels.

**Example:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
// serde(deny_unknown_fields) REMOVED
pub struct ToolGrant {
    pub server_id: String,
    pub tool_name: String,
    pub operations: Vec<Operation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Constraint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_invocations: Option<u32>,
    // NEW v2 fields:
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_cost_per_invocation: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_cost: Option<MonetaryAmount>,
}
```

### Pattern 2: Fail-Closed Monetary Debit

**What:** Monetary budget checks use SQLite `IMMEDIATE` transactions. If the SQLite call fails for any reason (connection, corruption, schema mismatch), the kernel denies the invocation and signs a receipt with `decision: Deny { reason: "budget_store_error" }`.

**When to use:** All three budget checks: invocation count, monetary per-invocation, monetary total.

**Trade-offs:** Operators lose tool access if the budget store has a transient error. This is intentional -- the system must not grant access without a successful debit record. Use the in-memory budget store only in test environments.

### Pattern 3: SIEM Export as a Cursor-Based Pull

**What:** The `ExporterManager` maintains a persisted `last_exported_seq` cursor. It polls `SqliteReceiptStore::list_tool_receipts_after_seq(cursor, batch_size)` at a configurable interval. Receipts are exported, cursor advanced. The kernel never pushes to the SIEM exporter.

**When to use:** Any observability consumer (SIEM, analytics, dashboard) that reads from the receipt store.

**Trade-offs:** Slight export latency (up to `flush_interval_ms`). No backpressure risk on the kernel hot path. If the exporter is down, receipts accumulate in SQLite (bounded by retention policy) and export resumes when the exporter recovers without data loss.

### Pattern 4: Synchronous Guard Contract

**What:** All `pact_kernel::Guard::evaluate()` implementations are synchronous. Guards that need time-windowed state (VelocityGuard) use `std::sync::Mutex`, not `tokio::Mutex`. Guards that need external data (e.g., a threat-intel feed) belong in ClawdStrike's async guard runtime, not in pact-guards.

**When to use:** Every guard in pact-guards, including the new VelocityGuard.

**Trade-offs:** Guards cannot await external services. This is a deliberate protocol-level constraint: guard evaluation must be deterministic and bounded in latency. Application-layer guards with async semantics are ClawdStrike's problem, not PACT's.

---

## Anti-Patterns

### Anti-Pattern 1: Putting SIEM HTTP Dependencies in pact-kernel

**What people do:** Add `reqwest` or `hyper` directly to pact-kernel's `Cargo.toml` to "simplify" the export path.

**Why it's wrong:** pact-kernel is part of the TCB and must be auditable, lean, and safe for embedded/WASM targets. HTTP client crates add transitive dependencies (TLS stacks, DNS resolvers) that expand the audit surface and break no-std compatibility goals.

**Do this instead:** Keep pact-siem as a separate crate behind a feature flag. ExporterManager reads from the store; the kernel writes to the store. The boundary is the SQLite `seq` cursor.

### Anti-Pattern 2: Applying Monetary Cost After the Receipt Is Signed

**What people do:** Sign the receipt first, then attempt to debit the budget as a post-step to avoid holding the debit lock during tool dispatch.

**Why it's wrong:** If the debit fails after the receipt is signed and appended, the receipt says "Allow" but the budget was not debited. This produces an incorrect audit trail. The receipt is already in the log. There is no correction mechanism.

**Do this instead:** Debit atomically before guard evaluation. The kernel returns a signed deny receipt if the debit fails. Receipt content reflects the actual decision.

### Anti-Pattern 3: Using the ClawdStrike HTTP-Shaped DPoP Proof Message

**What people do:** Copy ClawdStrike's `binding_proof_message()` which encodes `method || url || body_sha256` into the DPoP proof.

**Why it's wrong:** PACT invocations are not HTTP requests. The proof binding must be over PACT-native invocation context: `capability_id || tool_server || tool_name || canonical_action_hash || issued_at || nonce`. Copying the HTTP shape creates a proof that does not actually bind to a specific tool invocation.

**Do this instead:** Define a PACT-specific proof message format in `pact_kernel::dpop::binding_proof_message()`. Use the ClawdStrike source as a structural reference for the signature scheme, not as a drop-in proof message.

### Anti-Pattern 4: Adding the Capability Lineage Index Before Q3

**What people do:** Attempt to build agent-centric receipt joins (all receipts for agent X) as part of Q2 receipt query work.

**Why it's wrong:** Agent-centric joins require knowing which capability IDs belong to an agent. That join lives in the capability lineage index, which does not exist yet. Without it, you either (a) do a full table scan of receipts filtering by agent-subject-key match, which is O(n) and requires the receipt store to index on `subject_key` (it does not), or (b) replay issuance logs at query time, which is brittle and slow.

**Do this instead:** Q2 receipt queries are capability-ID-scoped. Add a clear `// TODO(Q3): agent-centric joins require capability_index` comment in the query API. Build the lineage index in Q3 as a standalone SQLite table populated by the authority at issuance time.

---

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| Splunk HEC | HTTP POST JSON batches in pact-siem | `Authorization: Splunk <token>` header |
| Elasticsearch | Bulk API `_bulk` endpoint in pact-siem | ECS schema format recommended |
| Datadog | Agent local UDP or HTTPS in pact-siem | OCSF schema format |
| Sumo Logic | HTTP source endpoint in pact-siem | CEF or Native format |
| ClawdStrike | pact-core as upstream dep; no runtime call | Code dependency, not service call |
| Payment rails (Q4) | Bridge package separate from pact-kernel | Stripe ACP / x402; truthful settlement requires knowing allow/deny before settlement |

### Internal Crate Boundaries (key new edges)

| Boundary | Communication | Notes |
|----------|---------------|-------|
| pact-core -> (nothing) | Pure types, no I/O | MonetaryAmount, ToolInvocationCost defined here |
| pact-kernel -> pact-core | Direct import | budget_store, dpop, checkpoint all use pact-core types |
| pact-guards -> pact-kernel (Guard trait) | Implements trait | VelocityGuard returns Verdict using kernel's type |
| pact-siem -> pact-kernel (receipt_store) | pact-siem calls SqliteReceiptStore::list_tool_receipts_after_seq() | Pull model; store does not know about SIEM |
| pact-cli -> pact-siem | Feature-flagged import | `cargo build --features siem` for SIEM-enabled binary |

---

## Scaling Considerations

This is a Rust workspace targeting single-node SQLite deployments in Q2/Q3 and HA cluster deployments (already built) for larger installations.

| Scale | Architecture Notes |
|-------|--------------------|
| Single node, low volume | SQLite WAL mode, synchronous FULL pragma. Budget debit + receipt append in same process. All current v1 deployments. |
| Single node, high volume | Receipt pipeline throughput is the first bottleneck. Benchmark signing + SQLite insert under load before Q3 dashboard. Consider batched receipt inserts if > 1000 receipts/sec needed. |
| HA cluster (already built) | BudgetStore replication via delta seq cursor is already implemented. Checkpoint state needs to replicate similarly -- follow the budget_store delta-replication pattern for checkpoint rows. |
| SIEM export lag | ExporterManager cursor-based pull decouples receipt volume from SIEM backend latency. DLQ absorbs transient SIEM outages. Not a scaling concern until receipt volume >> 10K/sec. |

---

## Sources

All findings are from direct analysis of the codebase. No external sources consulted.

- `/Users/connor/Medica/backbay/standalone/pact/crates/pact-core/src/` -- canonical type definitions
- `/Users/connor/Medica/backbay/standalone/pact/crates/pact-kernel/src/` -- kernel internals, stores
- `/Users/connor/Medica/backbay/standalone/pact/crates/pact-guards/src/lib.rs` -- guard inventory
- `/Users/connor/Medica/backbay/standalone/pact/docs/CLAWDSTRIKE_INTEGRATION.md` -- port plan, type mappings
- `/Users/connor/Medica/backbay/standalone/pact/docs/STRATEGIC_ROADMAP.md` -- Q2/Q3 deliverables and debate resolution
- `/Users/connor/Medica/backbay/standalone/pact/.planning/PROJECT.md` -- milestone scope and constraints

---

*Architecture research for: PACT v2.0 Agent Economy Foundation*
*Researched: 2026-03-21*
