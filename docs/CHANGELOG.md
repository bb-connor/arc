# PACT Changelog

---

## v2.0.0 (2026-03-23)

### Enforcement

- **Monetary budget enforcement** (`pact-core`, `pact-kernel`): `ToolGrant`
  gains `max_cost_per_invocation: Option<MonetaryAmount>` and
  `max_total_cost: Option<MonetaryAmount>`. The Kernel enforces both limits
  atomically via `BudgetStore::try_charge_cost`. All monetary values use u64
  minor units with an ISO 4217 currency code. Overflow is detected with
  `checked_add` and fails closed.

- **DPoP proof-of-possession** (`pact-kernel`): Added `DpopProof`,
  `DpopProofBody`, `DpopNonceStore`, and `verify_dpop_proof`. The 8-field
  PACT-native DPoP format (`pact.dpop_proof.v1`) binds each invocation to the
  agent's Ed25519 private key. Enabled per-grant via
  `ToolGrant::dpop_required: Option<bool>`. Default TTL 300s, clock skew
  tolerance 30s, LRU nonce cache capacity 8192.

- **Receipt Merkle checkpointing** (`pact-kernel`): Added `build_checkpoint`,
  `build_inclusion_proof`, `verify_checkpoint_signature`,
  `KernelCheckpoint`, `KernelCheckpointBody`, and `ReceiptInclusionProof`.
  Checkpoints are triggered every `checkpoint_batch_size` receipts (default
  100, configurable). Each checkpoint commits a batch of canonical receipt
  bytes to a binary Merkle tree and signs the root with the Kernel's keypair.
  Schema: `pact.checkpoint_statement.v1`.

### Compliance and Audit

- **Financial receipt metadata** (`pact-core`): Added
  `FinancialReceiptMetadata` struct with 11 fields: `grant_index`,
  `cost_charged`, `currency`, `budget_remaining`, `budget_total`,
  `delegation_depth`, `root_budget_holder`, `payment_reference`,
  `settlement_status`, `cost_breakdown`, and `attempted_cost`. Attached under
  the `"financial"` key in `PactReceipt::metadata` for all monetary
  invocations. Denial receipts carry `attempted_cost` instead of
  `cost_charged`.

- **Nested flow receipts** (`pact-core`): Added `ChildRequestReceipt` and
  `ChildRequestReceiptBody`. Signed records for sub-operations spawned within
  a parent tool call (sampling, resource reads, elicitation). Fields:
  `session_id`, `parent_request_id`, `request_id`, `operation_kind`,
  `terminal_state`, `outcome_hash`, `policy_hash`. Terminal states:
  `Completed`, `Cancelled`, `Incomplete`.

### APIs

- **Receipt query API** (`pact-cli`): New `GET /v1/receipts/query` endpoint
  with 9 filter dimensions: `capabilityId`, `toolServer`, `toolName`,
  `outcome`, `since`, `until`, `minCost`, `maxCost`, `agentSubject`. Supports
  cursor-based pagination (`cursor` + `limit`). Maximum page size: 200
  receipts. Response includes `totalCount` (full filtered set), `nextCursor`,
  and `receipts` ordered by `seq` ascending.

- **Agent receipts endpoint** (`pact-cli`): New
  `GET /v1/agents/{subject_key}/receipts` endpoint for per-agent receipt
  history lookup via hex-encoded Ed25519 public key.

- **Capability lineage endpoints** (`pact-cli`): New
  `GET /v1/lineage/{capability_id}` and
  `GET /v1/lineage/{capability_id}/chain` for querying delegation chain
  snapshots.

### SDK

- **`MonetaryAmount` type** (`pact-core`): New struct with `units: u64` and
  `currency: String`. Used in `ToolGrant::max_cost_per_invocation` and
  `ToolGrant::max_total_cost`. Forward-compatible with v1.0 tokens via
  `#[serde(default, skip_serializing_if = "Option::is_none")]`.

- **`ToolGrant` attenuation** (`pact-core`): `ToolGrant::is_subset_of` updated
  to respect monetary fields. A child grant is a valid attenuation only if its
  `max_cost_per_invocation` and `max_total_cost` are no greater than the
  parent's corresponding limits.

- **`CapabilityLineage` snapshot** (`pact-kernel`): New
  `CapabilitySnapshot` and `CapabilityLineageError` types. `record_capability_snapshot`
  on `SqliteReceiptStore` captures issuer, subject, and delegation chain at
  token issuance time for the `agentSubject` filter.

### Infrastructure

- **`pact-siem` crate**: New crate providing an independent SIEM exporter
  pipeline. `ExporterManager` runs a cursor-pull loop reading from the
  Kernel's receipt SQLite database (read-only, no `pact-kernel` dependency).
  Ships with `SplunkExporter` (Splunk HEC) and `ElasticExporter`
  (Elasticsearch `_bulk` API). Includes `DeadLetterQueue` with configurable
  capacity (default 1000) and exponential backoff retry (default 3 attempts,
  base 500ms). Configurable via `SiemConfig`: `poll_interval`,
  `batch_size`, `max_retries`, `base_backoff_ms`, `dlq_capacity`.

- **SQLite budget store** (`pact-kernel`): `SqliteBudgetStore` gains
  `total_cost_charged` column (added via `ALTER TABLE` migration for existing
  databases). LWW merge strategy uses seq-based conflict resolution.

- **Checkpoint persistence** (`pact-kernel`): `SqliteReceiptStore` gains
  `store_checkpoint`, `load_checkpoint_by_seq`, and
  `receipts_canonical_bytes_range` methods for checkpoint storage and
  inclusion proof construction.

### Protocol Specification

- `spec/PROTOCOL.md` Appendix D: Receipt Financial Metadata.
- `spec/PROTOCOL.md` Appendix E: Receipt Query API.
- `spec/PROTOCOL.md` Appendix F: Receipt Checkpointing.
- `spec/PROTOCOL.md` Appendix G: Nested Flow Receipts.
- ADR-0006: Monetary Budget Semantics.
- ADR-0007: DPoP Binding Format.
- ADR-0008: Checkpoint Trigger Strategy.
- ADR-0009: SIEM Isolation Architecture.

---

## v1.0.0

Initial release. Core capability model, receipt signing, revocation store,
MCP adapter, and trust control service.
