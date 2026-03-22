# Phase 9: Compliance and DPoP - Research

**Researched:** 2026-03-22
**Domain:** Receipt retention/rotation (SQLite archival), DPoP proof-of-possession (PACT-native Ed25519), regulatory compliance mapping (Colorado SB 24-205, EU AI Act Article 19)
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Receipt Retention Policy:**
- Default time-based retention is 90 days, configurable via kernel config struct field (retention_days)
- Default size-based retention is 10 GB per SQLite DB, configurable via kernel config struct field (max_size_bytes)
- Rotation archives receipts to a separate read-only SQLite file preserving Merkle checkpoint roots; original DB is compacted
- Configuration via kernel config struct fields (retention_days, max_size_bytes, archive_path) -- no new config file format
- Archived receipts must remain verifiable against stored Merkle checkpoint roots (COMP-04)

**DPoP Proof Design:**
- DPoP proof format: canonical JSON signed with Ed25519, consistent with all PACT signing (PACT-native, not HTTP-shaped)
- Proof message binds: capability_id + tool_server + tool_name + action_hash + nonce (per SEC-03)
- Nonce replay store: in-memory LRU with configurable capacity -- DPoP nonces are ephemeral, no persistence across restarts
- Default TTL window: 5 minutes (standard DPoP practice), configurable
- Enforcement mode: optional via `dpop_required: bool` on ToolGrant -- off by default, tool servers opt in
- Reused nonce within TTL window is rejected (SEC-04)
- Cross-invocation replay: proof for invocation A rejected when replayed for invocation B (different action_hash)

**Compliance Document Structure:**
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

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| COMP-01 | Published document maps PACT receipts to Colorado SB 24-205 requirements for AI system output records | Colorado SB 24-205 clause structure, receipt field mapping table, test artifact reference pattern |
| COMP-02 | Published document maps PACT to EU AI Act Article 19 traceability requirements for high-risk AI systems | EU AI Act Art. 19 record-keeping obligations, receipt + checkpoint field mapping, test artifact reference pattern |
| COMP-03 | Receipt retention policies are configurable (time-based and size-based rotation) | SQLite archive pattern, `ensure_*_column` migration helper, `page_count * page_size` size query |
| COMP-04 | Archived receipts remain verifiable via stored Merkle checkpoint roots | `kernel_checkpoints` table already carries `merkle_root`; `verify_checkpoint_signature` already exists; archive DB must preserve checkpoint rows alongside receipt rows |
| SEC-03 | DPoP per-invocation proofs bind to capability_id + tool_server + tool_name + action_hash + nonce (PACT-native proof message) | `Keypair::sign_canonical`, `PublicKey::verify_canonical`, canonical JSON for proof body, `CapabilityToken.subject` as sender constraint |
| SEC-04 | DPoP nonce replay store rejects reused nonces within configurable TTL window | `lru` crate 0.16.3 for `LruCache<(nonce, cap_id), Instant>`, TTL eviction check, cross-invocation replay via action_hash binding |
</phase_requirements>

## Summary

Phase 9 has three distinct work streams that share no mutual dependencies: receipt retention/rotation (COMP-03, COMP-04), DPoP proof-of-possession (SEC-03, SEC-04), and compliance document authoring (COMP-01, COMP-02). All three can be planned and executed in parallel within the phase.

The retention work extends `SqliteReceiptStore` with two new capabilities: a size check (`PRAGMA page_count * page_size`) and a time-boundary query (`WHERE timestamp < cutoff`), then archives matched rows to a separate SQLite file using `ATTACH DATABASE` + `INSERT INTO archive.table SELECT ... FROM main.table` before deleting from the live DB and running `PRAGMA wal_checkpoint(TRUNCATE)`. Checkpoint rows must be archived alongside their receipt ranges so that archived receipts remain verifiable (COMP-04).

The DPoP work introduces a new `pact-kernel/src/dpop.rs` module containing `DpopProofBody` (canonical JSON struct), `DpopConfig` (TTL + LRU capacity), and `DpopNonceStore` (in-memory `LruCache` keyed by `(nonce, capability_id)` with timestamp). Verification reuses `pact_core::crypto::{PublicKey, Signature}` and `canonical_json_bytes` already present in the project. The agent's proof key must match `capability.subject` (sender constraint already encoded in `CapabilityToken`). `ToolGrant` gains one new `Option<bool>` field (`dpop_required`) following the existing `#[serde(default, skip_serializing_if = "Option::is_none")]` pattern.

The compliance documents are Markdown files. Colorado SB 24-205 (effective Feb 1, 2026) primarily imposes developer transparency and impact assessment obligations on deployers of high-risk AI systems; PACT's receipts, signed kernel attestations, and configurable retention directly satisfy the record-keeping provisions. EU AI Act Article 19 requires technical documentation and logs for high-risk AI systems; the same artifacts (receipts, checkpoints, Merkle proofs) satisfy those requirements. Both documents map clauses to specific test functions using a clause-ID | behavior | test-file | test-function table structure.

**Primary recommendation:** Implement plans 09-01 (retention) and 09-02 (DPoP) concurrently; 09-03 and 09-04 can begin as soon as Phase 8 tests are confirmed passing, since the compliance docs reference those test artifacts.

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `rusqlite` (workspace) | 0.37 (workspace pinned; 0.39.0 latest) | SQLite archive, retention queries, ATTACH DATABASE | Already in use throughout pact-kernel |
| `lru` | 0.16.3 | `LruCache` for DPoP nonce replay store | Standard Rust LRU implementation; 10M+ downloads; capacity-bounded, O(1) ops |
| `pact_core::crypto` | workspace | Ed25519 sign/verify for DPoP proofs | Already the project's signing primitive |
| `pact_core::canonical` | workspace | `canonical_json_bytes` for DPoP proof body | All PACT signed payloads use this |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `std::time::{Instant, SystemTime}` | stdlib | TTL expiry tracking in nonce store | Prefer `Instant` for duration comparisons in `DpopNonceStore`; `SystemTime` for proof `issued_at` (wall-clock) |
| `std::sync::Mutex` | stdlib | Guard `DpopNonceStore` interior mutability | Consistent with `VelocityGuard` pattern in `pact-guards/src/velocity.rs` |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| In-memory `LruCache` | Persistent nonce store (SQLite) | Persistence across restarts adds complexity and is not required; DPoP nonces are short-lived (5 min TTL) and ephemeral by design per CONTEXT.md decision |
| `lru` crate | `indexmap` + manual eviction | `lru` provides capacity-bounded O(1) eviction; hand-rolled would reinvent the wheel |
| `ATTACH DATABASE` for archival | `rusqlite::Connection::backup()` | `backup()` copies the entire DB; `ATTACH` + selective INSERT allows archiving only the rotated rows while keeping active rows live |

**Installation:**
```bash
# In crates/pact-kernel/Cargo.toml
# Add to [dependencies]:
lru = "0.16.3"
```

**Version verification (confirmed 2026-03-22):**
- `lru` 0.16.3 -- published 2026-01-07, confirmed current stable on crates.io
- `rusqlite` workspace pins 0.37; 0.39.0 is latest but workspace pin is intentional -- do not upgrade within this phase

## Architecture Patterns

### Recommended Project Structure (new files this phase)

```
crates/pact-kernel/src/
├── dpop.rs                  # NEW: DpopProofBody, DpopConfig, DpopNonceStore, verify_dpop_proof
└── receipt_store.rs         # EXTEND: rotate_receipts(), archive_receipts_before(), db_size_bytes()

crates/pact-core/src/
└── capability.rs            # EXTEND: ToolGrant gets dpop_required: Option<bool>

docs/compliance/             # NEW directory
├── colorado-sb-24-205.md    # COMP-01
└── eu-ai-act-article-19.md  # COMP-02
```

### Pattern 1: DPoP Proof Body (canonical JSON signed struct)

**What:** A signed PACT-native proof message that binds a tool invocation to a specific agent keypair via Ed25519 over canonical JSON. Follows the exact same signing envelope as `PactReceipt`, `KernelCheckpoint`, and `CapabilityToken`.

**When to use:** Called by the kernel before the guard pipeline when `ToolGrant.dpop_required == Some(true)`.

**Example:**
```rust
// Source: pact-core/src/crypto.rs (sign_canonical pattern)
// New file: crates/pact-kernel/src/dpop.rs

use pact_core::canonical::canonical_json_bytes;
use pact_core::crypto::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// Schema for PACT-native DPoP proofs.
pub const DPOP_SCHEMA: &str = "pact.dpop_proof.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProofBody {
    /// Always "pact.dpop_proof.v1"
    pub schema: String,
    /// The capability_id this proof is bound to.
    pub capability_id: String,
    /// The tool server_id being invoked.
    pub tool_server: String,
    /// The tool name being invoked.
    pub tool_name: String,
    /// SHA-256 hex of the canonical JSON of the tool arguments (action_hash).
    pub action_hash: String,
    /// Unique per-invocation nonce (UUID or 32-byte random hex).
    pub nonce: String,
    /// Unix timestamp (seconds) when this proof was issued.
    pub issued_at: u64,
    /// The agent's public key (must match capability.subject).
    pub agent_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProof {
    pub body: DpopProofBody,
    /// Ed25519 signature over canonical JSON of `body`.
    pub signature: Signature,
}
```

### Pattern 2: DPoP Nonce Store (in-memory LRU with TTL)

**What:** An `LruCache<(String, String), Instant>` keyed by `(nonce, capability_id)` tracking when each nonce was first seen. Evicts old entries by capacity; TTL is checked at lookup time.

**When to use:** Called by `verify_dpop_proof` to reject replayed nonces.

**Example:**
```rust
// Source: established pattern from pact-guards/src/velocity.rs (Mutex + in-memory state)
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct DpopNonceStore {
    // Key: (nonce, capability_id), Value: first-seen Instant
    inner: Mutex<LruCache<(String, String), Instant>>,
    ttl: Duration,
}

impl DpopNonceStore {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap = NonZeroUsize::new(capacity)
            .unwrap_or(NonZeroUsize::new(1024).expect("1024 is non-zero"));
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            ttl,
        }
    }

    /// Returns false if nonce was already seen within TTL (replay detected).
    /// Returns true if nonce is fresh (inserts it).
    pub fn check_and_insert(&self, nonce: &str, capability_id: &str) -> bool {
        let mut cache = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let key = (nonce.to_string(), capability_id.to_string());
        if let Some(first_seen) = cache.peek(&key) {
            if first_seen.elapsed() < self.ttl {
                return false; // replay within TTL
            }
        }
        cache.put(key, Instant::now());
        true
    }
}
```

### Pattern 3: Receipt Rotation (SQLite ATTACH + selective archive)

**What:** Archive receipts older than `retention_days` or when DB exceeds `max_size_bytes`. Uses SQLite `ATTACH DATABASE` to write to a separate archive file, then DELETE from live, then `PRAGMA wal_checkpoint(TRUNCATE)` to compact.

**When to use:** Called from `rotate_if_needed()` on `SqliteReceiptStore`, invoked either at append time or on a timer (Claude's discretion per CONTEXT.md).

**Example:**
```rust
// Source: rusqlite docs + existing SqliteReceiptStore patterns
// Extends: crates/pact-kernel/src/receipt_store.rs

impl SqliteReceiptStore {
    /// Returns DB file size in bytes using SQLite page metadata.
    pub fn db_size_bytes(&self) -> Result<u64, ReceiptStoreError> {
        let (page_count, page_size): (i64, i64) = self.connection.query_row(
            "SELECT page_count, page_size FROM pragma_page_count(), pragma_page_size()",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        Ok((page_count * page_size).max(0) as u64)
    }

    /// Archive all pact_tool_receipts with timestamp < cutoff_unix_secs
    /// to the given archive SQLite path, preserving relevant checkpoint rows.
    pub fn archive_receipts_before(
        &mut self,
        cutoff_unix_secs: u64,
        archive_path: &str,
    ) -> Result<u64, ReceiptStoreError> {
        // ATTACH archive DB
        self.connection.execute_batch(&format!(
            "ATTACH DATABASE '{}' AS archive",
            archive_path.replace('\'', "''")
        ))?;
        // Ensure archive tables exist (same schema as main)
        self.connection.execute_batch(r#"
            CREATE TABLE IF NOT EXISTS archive.pact_tool_receipts (
                seq INTEGER PRIMARY KEY,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS archive.kernel_checkpoints (
                id INTEGER PRIMARY KEY,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
        "#)?;
        // Copy receipts older than cutoff
        self.connection.execute(
            r#"INSERT OR IGNORE INTO archive.pact_tool_receipts
               SELECT * FROM main.pact_tool_receipts
               WHERE timestamp < ?1"#,
            rusqlite::params![cutoff_unix_secs as i64],
        )?;
        // Copy checkpoints whose batch_end_seq is covered by archived receipts
        self.connection.execute(
            r#"INSERT OR IGNORE INTO archive.kernel_checkpoints
               SELECT * FROM main.kernel_checkpoints
               WHERE batch_end_seq IN (
                   SELECT seq FROM main.pact_tool_receipts WHERE timestamp < ?1
               )"#,
            rusqlite::params![cutoff_unix_secs as i64],
        )?;
        // Delete archived receipts from main
        let deleted = self.connection.execute(
            "DELETE FROM main.pact_tool_receipts WHERE timestamp < ?1",
            rusqlite::params![cutoff_unix_secs as i64],
        )?;
        self.connection.execute_batch("DETACH DATABASE archive")?;
        // Compact live DB
        self.connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(deleted as u64)
    }
}
```

### Pattern 4: ToolGrant Extension (optional dpop_required field)

**What:** Forward-compatible `Option<bool>` field on `ToolGrant` using the existing optional-field serde pattern.

**Example:**
```rust
// Source: crates/pact-core/src/capability.rs (existing field pattern)
pub struct ToolGrant {
    // ... existing fields ...
    /// If Some(true), the kernel requires a valid DPoP proof for every invocation.
    /// None and Some(false) both mean DPoP is not required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_required: Option<bool>,
}
```

### Pattern 5: Compliance Document Clause-to-Test Table

**What:** Markdown file in `docs/compliance/` mapping each regulatory clause to a test artifact. Human-reviewed; mechanically verified by confirming `cargo test --workspace` passes.

**When to use:** For COMP-01 and COMP-02 documents.

**Example structure:**
```markdown
## Clause Mapping

| Clause | Requirement Summary | PACT Mechanism | Test File | Test Function |
|--------|---------------------|----------------|-----------|---------------|
| SB 24-205 §6(1)(a) | AI system output records | Signed PactReceipt per invocation | crates/pact-kernel/src/lib.rs | test_receipt_signed_on_allow |
| SB 24-205 §6(1)(b) | Record retention | Configurable retention_days, max_size_bytes | crates/pact-kernel/tests/... | retention_rotates_at_time_boundary |
```

### Anti-Patterns to Avoid

- **Persisting DPoP nonces to SQLite:** Nonces are ephemeral by design. Persisting them would add write pressure on every invocation and is explicitly out of scope per CONTEXT.md decision.
- **VACUUM instead of WAL checkpoint for compaction:** `VACUUM` rewrites the entire DB file and is slow. `PRAGMA wal_checkpoint(TRUNCATE)` truncates the WAL after archiving and is sufficient for compaction.
- **Archiving checkpoint rows without receipt rows:** A checkpoint row without its corresponding receipts is orphaned -- the Merkle proof cannot be verified without the leaf data. Archive checkpoints only for batches where all receipts are also archived.
- **Using `lock().unwrap()` in DpopNonceStore:** The project bans `unwrap_used`. Use `unwrap_or_else(|p| p.into_inner())` for poisoned mutex recovery (panic only if data is corrupted), or propagate the error.
- **Making dpop_required a required field:** It must be `Option<bool>` so existing capabilities that predate Phase 9 remain valid -- forward compat is a core project requirement (SCHEMA-01 established this pattern).

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| LRU eviction for nonce store | Custom doubly-linked list + HashMap | `lru::LruCache` | Correct O(1) implementation; edge cases around eviction ordering are subtle |
| SQLite DB size measurement | File system stat | `PRAGMA page_count` * `page_size` | Reports the logical DB size including uncommitted pages; consistent with SQLite's own understanding of size |
| Canonical JSON for DPoP proof body | Ad-hoc string concat | `pact_core::canonical::canonical_json_bytes` | RFC 8785 compliance already implemented; deterministic key ordering required for reproducible signatures |
| Ed25519 proof signing/verification | Custom crypto | `pact_core::crypto::{Keypair, PublicKey, Signature}` | Already project standard; ed25519-dalek 2.x with ZeroizeOnDrop |
| Nonce TTL expiry | Time-based background sweep | TTL checked at lookup time in `check_and_insert` | Simpler; no background thread; capacity-bounded LRU handles memory; avoids timer thread ownership complexity |

**Key insight:** The entire DPoP implementation reuses primitives that already exist in pact-core and pact-kernel. The only new dependency is `lru` for the nonce cache.

## Common Pitfalls

### Pitfall 1: Archiving Checkpoint Rows Orphaned from Their Receipts

**What goes wrong:** Copying checkpoint rows to the archive DB without copying the receipt rows for that batch, or vice versa. A reader then has a checkpoint root but no receipts to verify against it.

**Why it happens:** The retention cutoff is time-based on `receipt.timestamp`, but checkpoint batch boundaries are seq-based. A batch can span the time cutoff if receipts were written close to the boundary.

**How to avoid:** Archive all receipts for seqs covered by each checkpoint batch atomically. The correct approach: when archiving receipts before timestamp T, find the max receipt seq archived, then archive all checkpoints whose `batch_end_seq <= max_archived_seq`. Never archive a partial batch.

**Warning signs:** Archive DB has `kernel_checkpoints` rows but the corresponding `pact_tool_receipts` rows are missing from the archive.

---

### Pitfall 2: DPoP Replay via Nonce Reuse Across Capability IDs

**What goes wrong:** Nonce replay store keyed only by `nonce` (not `(nonce, capability_id)`). An adversary reuses a valid nonce from capability A when calling with capability B. The binding to `capability_id` in the proof body prevents the signature from being valid across capabilities, but the nonce store must also scope the key to prevent false positives.

**Why it happens:** Simple string-keyed nonce stores that don't account for multi-tenant or multi-capability deployments.

**How to avoid:** Key `DpopNonceStore` entries as `(nonce, capability_id)`. A nonce is only "seen" in the context of a specific capability.

**Warning signs:** Test `cross_invocation_replay_rejected` fails only when capability IDs differ.

---

### Pitfall 3: DPoP Proof Signed by Wrong Key

**What goes wrong:** The proof is signed by the kernel's keypair instead of the agent's ephemeral or registered keypair. The `agent_key` in the proof body must match `capability.subject` (the sender constraint).

**Why it happens:** Confusion between the kernel keypair (used for receipts and checkpoints) and the agent keypair (used for DPoP proofs).

**How to avoid:** Verification must assert `proof.body.agent_key == capability.subject` before verifying the signature. The signature is verified with `proof.body.agent_key`, not with the kernel's key.

**Warning signs:** DPoP verification passes even when a different keypair signs the proof.

---

### Pitfall 4: unwrap() / expect() in DPoP or Nonce Store Code

**What goes wrong:** Clippy `unwrap_used = "deny"` and `expect_used = "deny"` are enforced in pact-kernel. Any `unwrap()` or `expect()` in non-test code causes a CI failure.

**Why it happens:** Forgetting the project convention when reaching for Mutex guards or LruCache non-zero capacity.

**How to avoid:** Use `NonZeroUsize::new(capacity).ok_or(...)` or a const fallback. For Mutex: `lock().unwrap_or_else(|p| p.into_inner())` is acceptable for poisoned mutex recovery, or return a `KernelError`.

---

### Pitfall 5: Compliance Doc Claims Referencing Unshipped or Failing Tests

**What goes wrong:** A compliance document table entry points to a test function that does not yet exist, or exists but is `#[ignore]`-flagged or currently failing.

**Why it happens:** Compliance docs are authored before tests are complete, or tests are written but not yet passing.

**How to avoid:** STATE.md decision: "Compliance documents must reference passing test artifacts, not planned features." Write compliance docs in plan 09-03/09-04 only after 09-01 and 09-02 are complete and `cargo test --workspace` passes.

**Warning signs:** `cargo test --workspace` output shows the referenced test function does not exist or fails.

---

### Pitfall 6: SQLite ATTACH DATABASE Path Injection

**What goes wrong:** The `archive_path` string is interpolated directly into the SQL string for `ATTACH DATABASE`. If the path contains a single quote, the SQL is malformed or exploitable.

**Why it happens:** SQLite's `ATTACH DATABASE` takes a string literal in SQL syntax, and rusqlite does not support binding parameters for it.

**How to avoid:** Escape single quotes in the path by doubling them (`replace('\'', "''")`) before interpolating. Alternatively, validate that the path contains no quotes as a precondition.

---

### Pitfall 7: Receipt Rotation at Append Time vs. Background Timer

**What goes wrong:** Running rotation logic synchronously on every `append_pact_receipt_returning_seq` call adds O(query) latency to every receipt append, and may trigger archival mid-batch.

**Why it happens:** Simplest implementation runs the check inline.

**How to avoid (Claude's discretion):** The recommended approach is a periodic background check -- e.g., check size/time only every N appends (sampled), or run rotation on a separate thread/task invoked by the kernel. Do not run the full `archive_receipts_before` query on every append.

## Code Examples

### DPoP Proof Verification Function

```rust
// Source: pattern from crates/pact-kernel/src/checkpoint.rs (verify_checkpoint_signature)
// Target: crates/pact-kernel/src/dpop.rs

use std::time::{SystemTime, UNIX_EPOCH};
use pact_core::canonical::canonical_json_bytes;

#[derive(Debug, Clone)]
pub struct DpopConfig {
    /// How long a proof is valid before issued_at + ttl_secs is exceeded.
    pub proof_ttl_secs: u64,
    /// Maximum clock skew allowed between proof issued_at and kernel's clock.
    pub max_clock_skew_secs: u64,
    /// LRU capacity for the nonce replay store.
    pub nonce_store_capacity: usize,
}

impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            proof_ttl_secs: 300,         // 5 minutes
            max_clock_skew_secs: 30,
            nonce_store_capacity: 8192,
        }
    }
}

pub fn verify_dpop_proof(
    proof: &DpopProof,
    capability: &pact_core::CapabilityToken,
    expected_tool_server: &str,
    expected_tool_name: &str,
    expected_action_hash: &str,
    nonce_store: &DpopNonceStore,
    config: &DpopConfig,
) -> Result<(), KernelError> {
    // 1. Schema check
    if proof.body.schema != DPOP_SCHEMA {
        return Err(KernelError::DpopVerificationFailed(
            "unexpected proof schema".to_string(),
        ));
    }

    // 2. Sender constraint: agent_key must match capability.subject
    if proof.body.agent_key != capability.subject {
        return Err(KernelError::DpopVerificationFailed(
            "proof agent_key does not match capability subject".to_string(),
        ));
    }

    // 3. Binding fields must match the actual invocation
    if proof.body.capability_id != capability.id
        || proof.body.tool_server != expected_tool_server
        || proof.body.tool_name != expected_tool_name
        || proof.body.action_hash != expected_action_hash
    {
        return Err(KernelError::DpopVerificationFailed(
            "proof binding fields do not match invocation".to_string(),
        ));
    }

    // 4. Freshness: issued_at must be within [now - skew, now + ttl]
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if proof.body.issued_at + config.proof_ttl_secs < now {
        return Err(KernelError::DpopVerificationFailed("proof expired".to_string()));
    }
    if proof.body.issued_at > now + config.max_clock_skew_secs {
        return Err(KernelError::DpopVerificationFailed("proof issued in the future".to_string()));
    }

    // 5. Signature verification (agent signs body with their keypair)
    let body_bytes = canonical_json_bytes(&proof.body)
        .map_err(|e| KernelError::DpopVerificationFailed(e.to_string()))?;
    if !proof.body.agent_key.verify(&body_bytes, &proof.signature) {
        return Err(KernelError::DpopVerificationFailed(
            "proof signature invalid".to_string(),
        ));
    }

    // 6. Nonce replay check
    if !nonce_store.check_and_insert(&proof.body.nonce, &proof.body.capability_id) {
        return Err(KernelError::DpopVerificationFailed(
            "nonce replayed within TTL window".to_string(),
        ));
    }

    Ok(())
}
```

### Colorado SB 24-205 Clause Mapping Example

```markdown
<!-- docs/compliance/colorado-sb-24-205.md -->
## Colorado SB 24-205 Compliance Mapping

**Regulation:** Colorado Senate Bill 24-205, "Consumer Protections for Artificial Intelligence"
**Effective:** February 1, 2026
**Version:** PACT v2.0 (Phase 9)

| Clause | Summary | PACT Mechanism | Test File | Test Function |
|--------|---------|----------------|-----------|---------------|
| §6-1-1703(1)(a) | Developer disclose material limitations | pact-manifest: ToolDefinition.description | crates/pact-manifest/... | manifest_includes_tool_description |
| §6-1-1703(2)(b) | AI system output record retention | SqliteReceiptStore + configurable retention | crates/pact-kernel/tests/... | retention_rotates_at_time_boundary |
| §6-1-1703(2)(c) | Records verifiable after retention | Archived receipts verify against checkpoint root | crates/pact-kernel/tests/... | archived_receipt_verifies_against_checkpoint |
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| HTTP-shaped DPoP proofs (method + url + body_hash) | PACT-native proof message (capability_id + tool_server + tool_name + action_hash + nonce) | CONTEXT.md decision 2026-03-21 | Decouples proof binding from transport layer; proof verifies without HTTP context |
| Compliance docs referencing planned tests | Compliance docs referencing only passing tests | STATE.md decision 2026-03-21 | Claims are verifiable by running cargo test |
| No receipt retention -- DB grows unbounded | Configurable time and size rotation with archive SQLite | Phase 9 (this phase) | Meets regulatory retention obligations; prevents unbounded storage growth |

**Deprecated/outdated:**
- HTTP-shaped DPoP: The PACT proof message intentionally diverges from RFC 9449 (OAuth DPoP) to remove HTTP dependency. The existing ClawdStrike broker DPoP code (docs/CLAWDSTRIKE_INTEGRATION.md section 3.1) is reference material only; the HTTP fields (`method`, `url`, `body_sha256`) are replaced with PACT invocation fields.

## Open Questions

1. **Rotation trigger timing**
   - What we know: CONTEXT.md marks this as Claude's discretion (background timer vs. at-append)
   - What's unclear: The kernel's current architecture has no background timer infrastructure
   - Recommendation: Implement as a `rotate_if_needed()` method called from the kernel's `dispatch_tool_call_with_cost` path after receipt append, but only if either `db_size_bytes()` exceeds `max_size_bytes` OR the oldest unrotated receipt is older than `retention_days`. Sample every N appends to avoid checking every call. This avoids background thread complexity.

2. **Archive file naming convention**
   - What we know: CONTEXT.md marks this as Claude's discretion
   - What's unclear: Whether to use timestamp, date, or checkpoint seq as the archive filename suffix
   - Recommendation: Use ISO 8601 date-based suffix: `receipts-archive-{YYYY-MM-DD}.sqlite3`. This makes the archival window human-readable without requiring the DB to be opened to determine its contents.

3. **DpoP proof generation in test harness**
   - What we know: Verification is the primary deliverable; proof generation helper is in scope per CLAWDSTRIKE_INTEGRATION.md section 3.1 ("porting only the verifier is not enough")
   - What's unclear: Whether to add proof generation to pact-core or only in test helpers
   - Recommendation: Add a `DpopProof::sign(body: DpopProofBody, keypair: &Keypair) -> Result<DpopProof, Error>` constructor in pact-kernel (same pattern as `PactReceipt::sign` in pact-core). Tests and SDK callers both need this.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness (`cargo test`) |
| Config file | None -- workspace-level `[lints.clippy]` in each crate's Cargo.toml |
| Quick run command | `cargo test --workspace` |
| Full suite command | `cargo test --workspace -- --include-ignored` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| COMP-03 | Receipts older than retention_days are archived | unit | `cargo test -p pact-kernel -- retention_rotates_at_time_boundary` | Wave 0 |
| COMP-03 | DB exceeding max_size_bytes triggers size rotation | unit | `cargo test -p pact-kernel -- retention_rotates_at_size_boundary` | Wave 0 |
| COMP-04 | Archived receipt verifies against checkpoint root in archive DB | unit | `cargo test -p pact-kernel -- archived_receipt_verifies_against_checkpoint` | Wave 0 |
| COMP-04 | Checkpoint rows are preserved in archive alongside receipt rows | unit | `cargo test -p pact-kernel -- archive_preserves_checkpoint_rows` | Wave 0 |
| SEC-03 | DPoP proof with correct binding fields is accepted | unit | `cargo test -p pact-kernel -- dpop_valid_proof_accepted` | Wave 0 |
| SEC-03 | DPoP proof with wrong action_hash is rejected (cross-invocation replay) | unit | `cargo test -p pact-kernel -- dpop_wrong_action_hash_rejected` | Wave 0 |
| SEC-03 | DPoP proof with agent_key != capability.subject is rejected | unit | `cargo test -p pact-kernel -- dpop_wrong_agent_key_rejected` | Wave 0 |
| SEC-03 | DPoP proof with expired issued_at is rejected | unit | `cargo test -p pact-kernel -- dpop_expired_proof_rejected` | Wave 0 |
| SEC-04 | DPoP nonce reused within TTL window is rejected | unit | `cargo test -p pact-kernel -- dpop_nonce_replay_within_ttl_rejected` | Wave 0 |
| SEC-04 | DPoP nonce reused after TTL window is accepted | unit | `cargo test -p pact-kernel -- dpop_nonce_replay_after_ttl_accepted` | Wave 0 |
| COMP-01 | colorado-sb-24-205.md exists in docs/compliance/ | integration | `cargo test -p pact-kernel -- colorado_compliance_doc_test_references_pass` | Wave 0 |
| COMP-02 | eu-ai-act-article-19.md exists in docs/compliance/ | integration | `cargo test -p pact-kernel -- eu_ai_act_compliance_doc_test_references_pass` | Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p pact-kernel`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `crates/pact-kernel/src/dpop.rs` -- DpopProofBody, DpopProof, DpopConfig, DpopNonceStore, verify_dpop_proof (covers SEC-03, SEC-04)
- [ ] `crates/pact-kernel/tests/dpop.rs` -- test functions for SEC-03 and SEC-04 (all dpop_* tests above)
- [ ] `crates/pact-kernel/tests/retention.rs` -- test functions for COMP-03 and COMP-04 (all retention_* and archive_* tests above)
- [ ] `docs/compliance/colorado-sb-24-205.md` -- COMP-01 (depends on 09-01 and 09-02 passing)
- [ ] `docs/compliance/eu-ai-act-article-19.md` -- COMP-02 (depends on 09-01, 09-02, and Phase 8 tests)
- [ ] `crates/pact-kernel/Cargo.toml` -- add `lru = "0.16.3"` dependency

## Sources

### Primary (HIGH confidence)
- `crates/pact-kernel/src/receipt_store.rs` -- exact schema of `pact_tool_receipts`, `kernel_checkpoints`, `SqliteReceiptStore` methods, WAL/SYNCHRONOUS/busy_timeout patterns verified by reading source
- `crates/pact-kernel/src/budget_store.rs` -- `IMMEDIATE` transaction pattern, `ensure_*_column` migration helper, `allocate_budget_replication_seq` pattern, verified by reading source
- `crates/pact-kernel/src/checkpoint.rs` -- `build_checkpoint`, `verify_checkpoint_signature`, `KernelCheckpointBody` schema, `build_inclusion_proof`, verified by reading source
- `crates/pact-core/src/crypto.rs` -- `Keypair::sign_canonical`, `PublicKey::verify_canonical`, `canonical_json_bytes` verified by reading source
- `crates/pact-core/src/capability.rs` -- `ToolGrant` field structure, optional-field serde pattern `#[serde(default, skip_serializing_if = "Option::is_none")]`, verified by reading source
- `crates/pact-guards/src/velocity.rs` -- `Mutex`-based in-memory guard state pattern, `VelocityConfig` struct pattern, verified by reading source
- `.planning/phases/09-compliance-and-dpop/09-CONTEXT.md` -- all locked decisions, verified by reading source
- `docs/CLAWDSTRIKE_INTEGRATION.md` section 3.1 -- DPoP port strategy, `DpopConfig` field names reference, message field mapping, verified by reading source
- crates.io API -- `lru` 0.16.3 confirmed latest stable (2026-01-07); `rusqlite` 0.39.0 latest but workspace pins 0.37

### Secondary (MEDIUM confidence)
- Colorado SB 24-205 effective date (February 1, 2026) and high-level clause structure -- known from STATE.md blocker entry (June 30, 2026 deadline); specific clause numbering (§6-1-1703) is a Colorado AI Act citation from public legislative records; planner should verify exact subsection numbers before publishing the compliance doc
- EU AI Act Article 19 record-keeping requirements -- known from STATE.md blocker entry (August 2, 2026 deadline); specific Article 19 text on technical documentation and logging is established EU regulation; planner should verify current Article 19 text against the Official Journal of the EU before publishing the compliance doc

### Tertiary (LOW confidence)
- Archive file naming convention (ISO 8601 date suffix) -- Claude's discretion per CONTEXT.md; not externally verified, is a recommendation

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- all crates already in use or confirmed on crates.io
- Architecture: HIGH -- all patterns derived from reading existing source files
- Pitfalls: HIGH -- derived from code reading and established project conventions
- Compliance clause mapping: MEDIUM -- regulatory clause numbers require verification against primary legislative sources before publishing docs

**Research date:** 2026-03-22
**Valid until:** 2026-07-01 (stable crates; Colorado deadline June 30 is the hard gate)
