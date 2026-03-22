# Phase 9: Compliance and DPoP - Context

**Gathered:** 2026-03-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Receipt retention is configurable with time-based and size-based rotation (archived receipts verify against Merkle checkpoints). DPoP proof-of-possession is implemented as PACT-native Ed25519-signed canonical JSON proofs with LRU nonce replay rejection. Colorado SB 24-205 and EU AI Act Article 19 compliance mapping documents are published with clause-to-test-artifact reference tables. No new APIs, dashboards, or SDK changes -- enforcement + documentation.

</domain>

<decisions>
## Implementation Decisions

### Receipt Retention Policy
- Default time-based retention is 90 days, configurable via kernel config struct field (retention_days)
- Default size-based retention is 10 GB per SQLite DB, configurable via kernel config struct field (max_size_bytes)
- Rotation archives receipts to a separate read-only SQLite file preserving Merkle checkpoint roots; original DB is compacted
- Configuration via kernel config struct fields (retention_days, max_size_bytes, archive_path) -- no new config file format
- Archived receipts must remain verifiable against stored Merkle checkpoint roots (COMP-04)

### DPoP Proof Design
- DPoP proof format: canonical JSON signed with Ed25519, consistent with all PACT signing (PACT-native per STATE.md decision, not HTTP-shaped)
- Proof message binds: capability_id + tool_server + tool_name + action_hash + nonce (per SEC-03)
- Nonce replay store: in-memory LRU with configurable capacity -- DPoP nonces are ephemeral, no persistence across restarts
- Default TTL window: 5 minutes (standard DPoP practice), configurable
- Enforcement mode: optional via `dpop_required: bool` on ToolGrant -- off by default, tool servers opt in
- Reused nonce within TTL window is rejected (SEC-04)
- Cross-invocation replay: proof for invocation A rejected when replayed for invocation B (different action_hash)

### Compliance Document Structure
- Documents are Markdown files in docs/compliance/ -- versioned in git, reviewed via PR
- Each document maps regulatory clauses to test file paths + test function names in a table
- Documents are manually written with auto-verified test references (compliance claims need human review)
- Verification: cargo test --workspace invocation confirms all referenced tests exist and pass
- Colorado SB 24-205 (COMP-01) must ship before June 30, 2026
- EU AI Act Article 19 (COMP-02) must ship before August 2, 2026

### Claude's Discretion
- DPoP proof struct field ordering and naming
- LRU capacity defaults for nonce replay store
- Receipt archive file naming convention and compaction strategy
- Compliance document section headings and clause organization
- Whether retention rotation runs on a background timer or at receipt-append time

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `pact-core/src/crypto.rs` -- Keypair, Ed25519 signing, canonical_json_bytes for proof signing
- `pact-core/src/merkle.rs` -- MerkleTree, MerkleProof for archived receipt verification
- `pact-kernel/src/receipt_store.rs` -- SqliteReceiptStore with seq-based queries, kernel_checkpoints table
- `pact-kernel/src/checkpoint.rs` -- KernelCheckpoint, build_checkpoint, verify_checkpoint_signature
- `pact-kernel/src/budget_store.rs` -- Pattern for SQLite IMMEDIATE transactions, migration helpers (ensure_* pattern)
- `pact-core/src/capability.rs` -- ToolGrant struct where dpop_required field would be added

### Established Patterns
- SQLite stores: WAL mode, SYNCHRONOUS=FULL, IMMEDIATE transactions for writes
- Migration helpers: ensure_*_column functions check PRAGMA table_info before ALTER TABLE
- Canonical JSON (RFC 8785) for all signed payloads
- Optional fields: #[serde(default, skip_serializing_if = "Option::is_none")]
- Guard pipeline for enforcement checks

### Integration Points
- ToolGrant gets new dpop_required: Option<bool> field (forward-compatible, None = not required)
- DPoP verification happens in kernel evaluation before guard pipeline (proof must be valid before checking guards)
- Receipt retention operates on SqliteReceiptStore (archive + compact)
- Compliance docs reference tests across pact-kernel, pact-core, pact-guards

</code_context>

<specifics>
## Specific Ideas

- DPoP proof message is explicitly PACT-native (not HTTP-shaped) per STATE.md decision from 2026-03-21
- Compliance documents must reference passing test artifacts, not planned features (STATE.md decision)
- Colorado deadline June 30, 2026 and EU deadline August 2, 2026 are hard gates (STATE.md blockers)
- Reference docs/CLAWDSTRIKE_INTEGRATION.md for DPoP port strategy
- Phase 8 checkpoint infrastructure (kernel_checkpoints table, verify_checkpoint_signature) is the foundation for archived receipt verification

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
