# Phase 8: Core Enforcement - Research

**Researched:** 2026-03-22
**Domain:** Rust kernel enforcement -- monetary budget, Merkle checkpointing, velocity guard
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Budget Enforcement Semantics**
- `try_charge_cost` checks both `max_cost_per_invocation` AND `max_total_cost` in a single atomic IMMEDIATE transaction (prevents TOCTOU races)
- Denial receipts include `attempted_cost` and `budget_remaining` in `FinancialReceiptMetadata` for debugging and audit
- `BudgetStore` adds a `total_cost_charged` column (u64 minor-units) as a running total, mirroring the `invocation_count` pattern
- HA overrun bound is fixed at `max_cost_per_invocation x node_count`, documented in code comment and covered by a named concurrent-charge test

**Merkle Checkpoint Behavior**
- Checkpoints trigger every N receipts (configurable, default 100) -- deterministic and testable per success criterion
- Checkpoint is a separate `KernelCheckpoint` struct with Merkle root, batch range, and kernel signature -- not a special receipt type
- Checkpoints stored in a separate `kernel_checkpoints` SQLite table (different access pattern from receipts)
- Inclusion proofs are self-contained for offline verification (carry root + path + leaf hash), using existing `MerkleProof` from `arc-core`

**Velocity Guard Design**
- `VelocityGuard` lives in `arc-guards` alongside existing guards (`forbidden_path`, `egress_allowlist`, etc.) -- keeps kernel TCB minimal
- Uses synchronous token bucket with `std::sync::Mutex` (no async) per success criterion
- Enforcement scope is per-grant with agent-level aggregation option (grants are the natural enforcement boundary)
- Velocity denials use standard `Decision::Deny` with reason `"velocity_limit_exceeded"` -- no new `Decision` variant needed

### Claude's Discretion
- Internal implementation details of `checkpoint.rs` module structure
- SQLite schema details for `kernel_checkpoints` table beyond the core columns
- Token bucket refill strategy and window sizing defaults
- `ToolInvocationCost` struct field layout and how tool servers report cost back to the kernel

### Deferred Ideas (OUT OF SCOPE)
None -- discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SCHEMA-04 | `BudgetStore` supports `try_charge_cost` for monetary budget enforcement with single-currency semantics | Budget store extension patterns documented below; existing `try_increment` is the direct template |
| SCHEMA-05 | Tool servers can report invocation cost via `ToolInvocationCost` struct | `ToolServerConnection` trait extension pattern documented; default-method strategy preserves backward compat |
| SCHEMA-06 | `FinancialReceiptMetadata` populated in `receipt.metadata` for monetary grants, including grant_index, cost_charged, budget_remaining, settlement_status | `metadata: Option<serde_json::Value>` field on `ArcReceiptBody` is the insertion point; struct defined in AGENT_ECONOMY.md |
| SEC-01 | Receipt batches produce Merkle roots with signed kernel checkpoint statements | `MerkleTree::from_leaves`, `inclusion_proof`, `compute_root` all verified working in arc-core; checkpoint signing follows `build_and_sign_receipt` pattern |
| SEC-02 | Receipt inclusion proofs verify against published checkpoint roots | `MerkleProof::verify` and `verify_hash` confirmed; self-contained offline verification is already supported |
| SEC-05 | Velocity guard denies requests exceeding configured invocation or spend windows per agent/grant using synchronous token bucket | Guard trait is synchronous; `std::sync::Mutex`-wrapped token bucket maps cleanly to `Guard::evaluate`; ClawdStrike source strategy documented |
</phase_requirements>

---

## Summary

Phase 8 wires three enforcement mechanisms into the kernel evaluation pipeline: monetary cost budgets (`try_charge_cost`), Merkle-committed receipt checkpoints (`checkpoint.rs`), and a velocity throttle (`VelocityGuard`). All infrastructure exists -- this phase is about plumbing, not new primitives.

The monetary path extends `BudgetStore` with a `total_cost_charged` column and a `try_charge_cost` method that mirrors `try_increment` but checks both per-invocation and total-cost caps in a single SQLite IMMEDIATE transaction. The `FinancialReceiptMetadata` struct (defined in AGENT_ECONOMY.md) goes into `receipt.metadata` via the existing `Option<serde_json::Value>` field. Tool servers report cost via a `ToolInvocationCost` struct returned from a new `invoke_with_cost` default method on `ToolServerConnection` -- existing servers opt in by overriding; non-overriding servers return `None` and the kernel charges `max_cost_per_invocation` as the worst-case debit.

Merkle checkpointing lives in a new `arc-kernel/src/checkpoint.rs` module. After every N receipts appended to `SqliteReceiptStore`, the kernel builds a `MerkleTree` from the batch's canonical receipt bytes, signs a `KernelCheckpoint` struct with the kernel keypair, and inserts it into a `kernel_checkpoints` table. `ReceiptStore::append_arc_receipt` returns the new `seq` so the caller knows when a batch boundary is crossed. Inclusion proof verification uses `MerkleProof::verify` already implemented in `arc-core`.

`VelocityGuard` in `arc-guards/src/velocity.rs` implements the `Guard` trait with `std::sync::Mutex`-wrapped per-grant token buckets. It is registered in the guard pipeline ahead of other guards. Denials follow the standard `Verdict::Deny` path through `KernelError::GuardDenied`, producing a signed deny receipt with reason `"velocity_limit_exceeded"`.

**Primary recommendation:** Follow the template of `check_and_increment_budget` and `try_increment` exactly -- the IMMEDIATE transaction pattern and replication seq machinery are already proven; extend, don't redesign.

---

## Standard Stack

### Core (already in Cargo.toml -- no new deps required)
| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| `rusqlite` | workspace | SQLite IMMEDIATE transactions for `try_charge_cost` and checkpoint table | WAL+SYNCHRONOUS=FULL already configured |
| `sha2` / `arc-core::merkle` | workspace | MerkleTree, leaf_hash, node_hash, MerkleProof | All working; no new dep needed |
| `arc-core::crypto` | workspace | Keypair signing for KernelCheckpoint | Same pattern as receipt signing |
| `serde_json` | workspace | FinancialReceiptMetadata serialization into receipt.metadata | Existing field is `Option<serde_json::Value>` |
| `std::sync::Mutex` | std | Token bucket interior mutability in VelocityGuard | Synchronous -- no tokio::Mutex |
| `std::collections::VecDeque` | std | Sliding window event queue for spend-window velocity | Lightweight, no alloc overhead |
| `std::time::SystemTime` / `Instant` | std | Token bucket refill timestamps | Match existing `unix_now()` pattern |

### No New Crate Dependencies
Phase 8 is entirely self-contained within existing workspace dependencies. Confirm with:
```bash
cargo build --workspace
```

---

## Architecture Patterns

### Pattern 1: Extending `BudgetStore` with `try_charge_cost`

The `try_increment` method in `SqliteBudgetStore` (budget_store.rs line 231) is the exact template. Add `total_cost_charged` to both the `BudgetUsageRecord` struct and the `capability_grant_budgets` table via an `ensure_` migration helper (same pattern as `ensure_budget_seq_column`).

**Schema migration pattern:**
```sql
-- Same pattern as ensure_budget_seq_column() in budget_store.rs
ALTER TABLE capability_grant_budgets
    ADD COLUMN total_cost_charged INTEGER NOT NULL DEFAULT 0;
```

**`try_charge_cost` signature (from AGENT_ECONOMY.md spec):**
```rust
// Source: docs/AGENT_ECONOMY.md section 3.1.3
fn try_charge_cost(
    &mut self,
    capability_id: &str,
    grant_index: usize,
    max_invocations: Option<u32>,
    cost_units: u64,
    max_cost_per_invocation: Option<u64>,
    max_total_cost_units: Option<u64>,
) -> Result<bool, BudgetStoreError>;
```

The IMMEDIATE transaction reads current `(invocation_count, total_cost_charged)`, checks `cost_units <= max_cost_per_invocation` (if set) and `total_cost_charged + cost_units <= max_total_cost_units` (if set), then atomically writes both the incremented count and new total. A `false` return means denied; caller uses this like `try_increment` -- returns `build_deny_response`.

**`InMemoryBudgetStore` mirrors the same logic** using the existing `HashMap<(String, usize), BudgetUsageRecord>` -- no separate struct needed.

**Replication:** `upsert_usage` conflict resolution already handles the seq-wins pattern. Extend to include `total_cost_charged` using the same MAX() strategy:
```sql
total_cost_charged = CASE
    WHEN excluded.seq > capability_grant_budgets.seq
        THEN excluded.total_cost_charged
    ELSE MAX(capability_grant_budgets.total_cost_charged, excluded.total_cost_charged)
END
```

### Pattern 2: `FinancialReceiptMetadata` -- metadata field insertion

The `ArcReceiptBody.metadata: Option<serde_json::Value>` is signed as part of the body. The kernel populates it when a grant has monetary fields. The struct is defined in AGENT_ECONOMY.md (section 3.5.1):

```rust
// Source: docs/AGENT_ECONOMY.md section 3.5.1
// Lives in arc-core/src/receipt.rs (new struct, no changes to ArcReceipt)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialReceiptMetadata {
    pub grant_index: u32,
    pub cost_charged: u64,
    pub currency: String,
    pub budget_remaining: u64,
    pub budget_total: u64,
    pub delegation_depth: u32,
    pub root_budget_holder: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    pub settlement_status: String, // "not_applicable" | "authorized" | "captured" | "settled" | "pending" | "failed"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_breakdown: Option<serde_json::Value>,
    // Phase 8 additions for denial audit:
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
}
```

Serialized under key `"financial"` in `receipt.metadata`:
```rust
let metadata = serde_json::json!({ "financial": financial_meta });
```

For denial receipts from budget exhaustion, `attempted_cost` is populated with the cost that would have been charged, and `budget_remaining` is the actual remaining balance at time of denial. `settlement_status` is `"not_applicable"` for denials.

### Pattern 3: `ToolInvocationCost` and `invoke_with_cost`

**Where it lives:** `arc-kernel/src/lib.rs` alongside `ToolServerConnection` (AGENT_ECONOMY.md section 3.2.1).

```rust
// Source: docs/AGENT_ECONOMY.md section 3.2.1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocationCost {
    pub units: u64,
    pub currency: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breakdown: Option<serde_json::Value>,
}

pub trait ToolServerConnection: Send + Sync {
    // ... existing methods unchanged ...

    fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        // Default: delegate to invoke, return None cost (no monetary tracking)
        let value = self.invoke(tool_name, arguments, nested_flow_bridge)?;
        Ok((value, None))
    }
}
```

**Kernel cost verification logic** (in `evaluate_tool_call_with_session_roots` or a helper):
1. If grant has `max_cost_per_invocation` or `max_total_cost`, call `invoke_with_cost` instead of `invoke`.
2. If cost returned is `None` and grant has `max_total_cost`, charge `max_cost_per_invocation.units` as worst-case.
3. If cost returned and `cost.units > max_cost_per_invocation.units`, this is a budget overrun after execution -- log warning, sign allow receipt with `settlement_status = "failed"` and a recovery reference in metadata (tool ran; outcome is truthful).
4. Call `budget_store.try_charge_cost(...)` to record the charge.

### Pattern 4: `checkpoint.rs` -- Merkle batch signing

**New file:** `crates/arc-kernel/src/checkpoint.rs`

The ClawdStrike `checkpoint_statement()` pattern (CLAWDSTRIKE_INTEGRATION.md section 3.5) is the direct reference. Key adaptations:
- Domain separation tag: `"ArcCheckpointHashV1"` (not `"AegisNetCheckpointHashV1"`)
- Schema identifier: `"arc.checkpoint_statement.v1"`
- Use `arc_core::canonical::canonical_json_bytes` for the statement serialization
- Use `arc_core::crypto::Keypair` for signing

```rust
// Source: CLAWDSTRIKE_INTEGRATION.md section 3.5 (adapted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCheckpoint {
    pub schema: String,        // "arc.checkpoint_statement.v1"
    pub checkpoint_seq: u64,   // monotonic checkpoint counter
    pub batch_start_seq: u64,  // first receipt seq in this batch
    pub batch_end_seq: u64,    // last receipt seq in this batch
    pub tree_size: usize,      // number of leaves (receipts)
    pub merkle_root: Hash,     // root from MerkleTree::from_leaves
    pub issued_at: u64,        // unix timestamp
    pub kernel_key: PublicKey, // kernel's signing key
    pub signature: Signature,  // over canonical_json_bytes(body)
}
```

The checkpoint body (signed part) excludes `signature` and uses canonical JSON. The `kernel_checkpoints` SQLite table:
```sql
CREATE TABLE IF NOT EXISTS kernel_checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_seq INTEGER NOT NULL UNIQUE,
    batch_start_seq INTEGER NOT NULL,
    batch_end_seq INTEGER NOT NULL,
    tree_size INTEGER NOT NULL,
    merkle_root TEXT NOT NULL,     -- hex string
    issued_at INTEGER NOT NULL,
    statement_json TEXT NOT NULL,  -- canonical JSON of unsigned body
    signature TEXT NOT NULL,       -- hex-encoded signature
    kernel_key TEXT NOT NULL       -- hex-encoded public key
);
CREATE INDEX IF NOT EXISTS idx_kernel_checkpoints_batch_end
    ON kernel_checkpoints(batch_end_seq);
```

**Trigger mechanism:** `SqliteReceiptStore::append_arc_receipt` currently returns `()`. For Phase 8, it needs to return the new `seq` so the kernel can check `seq % checkpoint_batch_size == 0`. Two strategies:
- (Preferred) Add `append_arc_receipt_returning_seq(&mut self, receipt) -> Result<u64, ReceiptStoreError>` alongside the existing trait method. Avoids breaking the trait.
- Alternative: add `tool_receipt_count()` (already exists) and compare modulo after append.

**Inclusion proof query:** Add `receipt_canonical_bytes(seq) -> Result<Vec<u8>, ReceiptStoreError>` to retrieve a receipt's canonical bytes for proof verification. The proof itself is:
```rust
pub struct ReceiptInclusionProof {
    pub checkpoint_seq: u64,
    pub receipt_seq: u64,
    pub leaf_index: usize,
    pub merkle_root: Hash,
    pub proof: MerkleProof, // from arc_core::merkle
}
```

Verification: `proof.verify(&receipt_canonical_bytes, &merkle_root)`.

### Pattern 5: `VelocityGuard` in `arc-guards`

**New file:** `crates/arc-guards/src/velocity.rs`

Reference: CLAWDSTRIKE_INTEGRATION.md section 3.3, and AGENT_ECONOMY.md section 3.4.2.

Token bucket with sliding window. The ClawdStrike source uses fractional rates with `refill_locked()`. For ARC, simpler is better -- use a standard leaky/token bucket:

```rust
// Source: CLAWDSTRIKE_INTEGRATION.md section 3.3 (adapted -- synchronous, no async)
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_rate: f64,    // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
        self.last_refill = Instant::now();
    }
}

pub struct VelocityGuard {
    // Keyed by (capability_id, grant_index)
    invocation_buckets: Mutex<HashMap<(String, usize), TokenBucket>>,
    // Spend buckets for monetary velocity (units per window)
    spend_buckets: Mutex<HashMap<(String, usize), TokenBucket>>,
    config: VelocityConfig,
}

#[derive(Clone, Debug)]
pub struct VelocityConfig {
    pub max_invocations_per_window: Option<u32>,
    pub window_secs: u64,
    pub burst_factor: f64,  // default 1.0 (no burst above rate)
}
```

**Guard registration:** Added to `GuardPipeline::default_pipeline()` and registered in `arc-guards/src/lib.rs`. The velocity guard should run after capability validation but before tool dispatch -- it fits naturally in the guard pipeline since the pipeline runs after `check_and_increment_budget` in the kernel evaluation path.

**`GuardContext` note:** The current `GuardContext` has `request: &ToolCallRequest` which carries the `capability` (`CapabilityToken`). The velocity guard can key on `(request.capability.id, grant_index)`. The `grant_index` is not directly in `GuardContext` -- options:
1. Pass matched grant index via a new `matched_grant_index: Option<usize>` field on `GuardContext` (minimal change, targeted).
2. Re-derive grant index inside the guard by iterating `request.capability.scope.grants` matching `server_id` and `tool_name` (duplicates resolve logic).

Option 1 is preferred: add `matched_grant_index: Option<usize>` to `GuardContext`. The kernel already resolves grants before running guards (line 1758 in lib.rs: `check_and_increment_budget` precedes `run_guards`), so passing the index is straightforward.

**Velocity denial reason:** `"velocity_limit_exceeded"` -- no new error variant. The `KernelError::GuardDenied` wraps it.

### Recommended Project Structure Changes

```
crates/
├── arc-core/
│   └── src/
│       └── receipt.rs         -- ADD: FinancialReceiptMetadata struct
├── arc-kernel/
│   └── src/
│       ├── budget_store.rs    -- EXTEND: total_cost_charged field, try_charge_cost
│       ├── lib.rs             -- EXTEND: ToolInvocationCost, invoke_with_cost default,
│       │                                  monetary enforcement in evaluate_tool_call_*,
│       │                                  FinancialReceiptMetadata population
│       ├── receipt_store.rs   -- EXTEND: append_arc_receipt_returning_seq,
│       │                                  kernel_checkpoints table
│       └── checkpoint.rs      -- NEW: KernelCheckpoint, checkpoint signing, inclusion proof
└── arc-guards/
    └── src/
        ├── lib.rs             -- EXTEND: pub mod velocity; pub use velocity::VelocityGuard
        ├── pipeline.rs        -- EXTEND: add VelocityGuard to default_pipeline (optional)
        └── velocity.rs        -- NEW: VelocityGuard, TokenBucket, VelocityConfig
```

### Anti-Patterns to Avoid

- **Async in velocity guard:** The `Guard` trait is synchronous (`fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError>`). Using `tokio::Mutex` or `.await` is a compile error -- use `std::sync::Mutex` only.
- **Replacing the IMMEDIATE transaction with a read-then-write:** The TOCTOU window between SELECT and UPDATE allows split-brain double-charges. Always use `transaction_with_behavior(TransactionBehavior::Immediate)`.
- **Storing Merkle tree leaves in memory across checkpoints:** Build the tree by fetching batch receipts from the receipt store at checkpoint time. Do not accumulate leaves in kernel struct state -- that leaks memory and breaks restart recovery.
- **Adding a new `Decision` variant for velocity:** The CONTEXT.md locks this: use `Decision::Deny` with `reason = "velocity_limit_exceeded"`.
- **Changing the `ReceiptStore::append_arc_receipt` trait signature:** Existing implementors depend on the `()` return type. Add a new method rather than changing the trait.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Merkle tree construction | Custom hash tree | `arc_core::merkle::MerkleTree::from_leaves` | RFC 6962-compatible, already tested 1-32 leaves, handles odd node carry-up correctly |
| Inclusion proof generation | Manual path traversal | `MerkleTree::inclusion_proof(leaf_index)` | Tested against recursive reference implementation |
| Inclusion proof verification | Root recomputation from scratch | `MerkleProof::verify(leaf_bytes, &expected_root)` | `compute_root_from_hash` handles carry-up edge cases already |
| Canonical JSON for checkpoint signing | `serde_json::to_string` | `arc_core::canonical::canonical_json_bytes` | RFC 8785 determinism -- `serde_json::to_string` is NOT deterministic across keys |
| Ed25519 signing of checkpoint | Manual signature | `arc_core::crypto::Keypair::sign` | Same primitive used for receipt signing; consistent |
| TOCTOU-safe budget charge | Application-level locking | `rusqlite::TransactionBehavior::Immediate` | SQLite WAL-mode IMMEDIATE is the correct primitive; app-level mutexes don't protect cross-process writes |
| Token bucket rate limiting | VecDeque sliding window from scratch | `std::sync::Mutex`-wrapped `TokenBucket` | Standard leaky-bucket math; ClawdStrike `rate_limit.rs` is the reference (68 lines) |

---

## Common Pitfalls

### Pitfall 1: Split-Brain Monetary Overrun
**What goes wrong:** In HA leader/follower mode, two nodes both read `total_cost_charged = X` before either write lands, both approve a charge, resulting in `X + (2 * cost_units)` when only `X + cost_units` was authorized. The overrun bound is `max_cost_per_invocation x node_count`.
**Why it happens:** IMMEDIATE transactions on the same SQLite file are safe. But each HA node has its own SQLite file; replication is async. The window is one replication lag.
**How to avoid:** Document this bound explicitly in a `// SAFETY:` comment above `try_charge_cost` in `budget_store.rs`. Add a named test `concurrent_charge_overrun_bound` that demonstrates and asserts the bound.
**Warning signs:** Missing documentation of the overrun bound satisfies the STATE.md blocker and CONTEXT.md requirement.

### Pitfall 2: Receipt Batch Boundary Off-By-One
**What goes wrong:** Batch triggers at seq 100 but the 100th receipt is the first of the NEXT batch, not the last of the current batch. Inclusion proof for seq 100 fails to verify against checkpoint N.
**Why it happens:** Fence-post ambiguity in `seq % batch_size == 0` vs `seq % batch_size == batch_size - 1`.
**How to avoid:** Track `batch_start_seq` explicitly. Checkpoint when `seq - batch_start_seq + 1 == batch_size`. Test with exactly 100 receipts and verify the first checkpoint's `tree_size == 100`.

### Pitfall 3: Velocity Guard Mutex Poisoning
**What goes wrong:** A thread that panics while holding the `Mutex<HashMap<...>>` guard poisons the mutex. Subsequent calls return `Err(PoisonError)`, which the guard pipeline converts to `KernelError::GuardDenied` (fail-closed) -- correct behavior, but tests expecting an allow may be confused.
**Why it happens:** Rust `std::sync::Mutex` is poisoned on panic.
**How to avoid:** Use `.lock().unwrap_or_else(|e| e.into_inner())` (recover from poison) or use `parking_lot::Mutex` (never poisons). Since `unwrap_used = deny`, use `.map_err(|_| KernelError::Internal("velocity guard lock poisoned".to_string()))?.` pattern.

### Pitfall 4: Checkpoint Table Not WAL-Initialized
**What goes wrong:** `kernel_checkpoints` table created in a new `Connection::open` call that lacks the `PRAGMA journal_mode = WAL` preamble, causing checkpoint writes to use rollback journal instead of WAL, breaking concurrent reads.
**Why it happens:** PRAGMA is per-connection; if `execute_batch` is split across multiple `open` calls, the new table may miss the PRAGMA.
**How to avoid:** Initialize the `kernel_checkpoints` table in the same `execute_batch` call as `arc_tool_receipts` in `SqliteReceiptStore::open`.

### Pitfall 5: FinancialReceiptMetadata Breaks Old Receipt Verification
**What goes wrong:** Adding `financial` to `receipt.metadata` changes the canonical bytes of the body, changing the content hash and signature. Old verifiers that expect `metadata: null` will reject receipts with financial metadata.
**Why it happens:** The metadata field IS signed (it's part of `ArcReceiptBody`). This is expected behavior -- the financial data is attested to.
**How to avoid:** This is correct, not a bug. Document it. Old verifiers will reject new receipts the same way they would reject any signature mismatch. Forward compatibility was handled in Phase 7 (deny_unknown_fields removal).

### Pitfall 6: GuardContext Missing grant_index
**What goes wrong:** `VelocityGuard::evaluate` cannot key per-grant buckets without knowing which grant matched.
**Why it happens:** `GuardContext` currently has no `matched_grant_index` field.
**How to avoid:** Add `matched_grant_index: Option<usize>` to `GuardContext` in `arc-kernel/src/lib.rs`. Populate it in both `evaluate_tool_call_with_session_roots` and `evaluate_tool_call_with_nested_flow_client` after `check_and_increment_budget` resolves the matching grant. Existing guards ignore the new field (no breaking change).

---

## Code Examples

### `try_charge_cost` SQLite IMMEDIATE transaction pattern
```rust
// Source: arc-kernel/src/budget_store.rs (extending try_increment pattern at line 231)
fn try_charge_cost(
    &mut self,
    capability_id: &str,
    grant_index: usize,
    max_invocations: Option<u32>,
    cost_units: u64,
    max_cost_per_invocation: Option<u64>,
    max_total_cost_units: Option<u64>,
) -> Result<bool, BudgetStoreError> {
    let transaction = self
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;

    // Read current state atomically
    let current: Option<(i64, i64)> = transaction
        .query_row(
            r#"SELECT invocation_count, total_cost_charged
               FROM capability_grant_budgets
               WHERE capability_id = ?1 AND grant_index = ?2"#,
            params![capability_id, grant_index as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let (current_count, current_cost) = current
        .map(|(c, cost)| (c.max(0) as u32, cost.max(0) as u64))
        .unwrap_or((0, 0));

    // Check invocation cap
    if let Some(max) = max_invocations {
        if current_count >= max {
            transaction.rollback()?;
            return Ok(false);
        }
    }
    // Check per-invocation cost cap
    if let Some(max_per) = max_cost_per_invocation {
        if cost_units > max_per {
            transaction.rollback()?;
            return Ok(false);
        }
    }
    // Check total cost cap
    if let Some(max_total) = max_total_cost_units {
        if current_cost.saturating_add(cost_units) > max_total {
            transaction.rollback()?;
            return Ok(false);
        }
    }

    let updated_at = unix_now();
    let seq = allocate_budget_replication_seq(&transaction)?;
    transaction.execute(
        r#"INSERT INTO capability_grant_budgets
               (capability_id, grant_index, invocation_count, total_cost_charged, updated_at, seq)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6)
           ON CONFLICT(capability_id, grant_index) DO UPDATE SET
               invocation_count = excluded.invocation_count,
               total_cost_charged = excluded.total_cost_charged,
               updated_at = excluded.updated_at,
               seq = excluded.seq"#,
        params![
            capability_id,
            grant_index as i64,
            current_count.saturating_add(1) as i64,
            current_cost.saturating_add(cost_units) as i64,
            updated_at,
            seq as i64,
        ],
    )?;
    transaction.commit()?;
    Ok(true)
}
```

### Building and persisting a `KernelCheckpoint`
```rust
// Source: CLAWDSTRIKE_INTEGRATION.md section 3.5 (adapted for arc-kernel)
// In checkpoint.rs
pub fn build_checkpoint(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    receipt_canonical_bytes_batch: &[Vec<u8>],
    keypair: &Keypair,
) -> Result<KernelCheckpoint, CheckpointError> {
    let tree = MerkleTree::from_leaves(receipt_canonical_bytes_batch)
        .map_err(CheckpointError::Merkle)?;
    let merkle_root = tree.root();

    let body = KernelCheckpointBody {
        schema: "arc.checkpoint_statement.v1".to_string(),
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        tree_size: tree.leaf_count(),
        merkle_root,
        issued_at: unix_now(),
        kernel_key: keypair.public_key(),
    };

    let body_bytes = canonical_json_bytes(&body)
        .map_err(|e| CheckpointError::Serialization(e.to_string()))?;
    let signature = keypair.sign(&body_bytes);

    Ok(KernelCheckpoint { body, signature })
}
```

### `VelocityGuard::evaluate` synchronous token bucket
```rust
// Source: CLAWDSTRIKE_INTEGRATION.md section 3.3 (adapted -- synchronous)
// In arc-guards/src/velocity.rs
impl Guard for VelocityGuard {
    fn name(&self) -> &str { "velocity" }

    fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
        let grant_index = ctx.matched_grant_index.unwrap_or(0);
        let key = (ctx.request.capability.id.clone(), grant_index);

        let mut buckets = self
            .invocation_buckets
            .lock()
            .map_err(|_| KernelError::Internal("velocity guard lock poisoned".to_string()))?;

        let bucket = buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(self.config.burst_capacity, self.config.refill_rate));

        if bucket.try_consume(1.0) {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::Deny)  // caller wraps in KernelError::GuardDenied("velocity_limit_exceeded")
        }
    }
}
```

### Inclusion proof verification
```rust
// Source: arc-core/src/merkle.rs (MerkleProof::verify, line 243)
// Caller usage pattern:
let canonical = canonical_json_bytes(&receipt)?;
let proof: MerkleProof = retrieve_proof_from_store(receipt_seq)?;
let checkpoint = retrieve_checkpoint(proof_checkpoint_seq)?;
assert!(proof.verify(&canonical, &checkpoint.body.merkle_root));
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `deny_unknown_fields` on all arc-core types | Fields silently ignored (Phase 7) | Phase 7 | Monetary fields on `ToolGrant` can now be added without breaking old kernels |
| Invocation-count only budgets | Invocation-count + monetary cost budgets | Phase 8 (this phase) | Enables economic metering |
| No Merkle checkpoints on receipt batches | Batch-N signed checkpoints with inclusion proofs | Phase 8 (this phase) | SEC-01 and SEC-02 compliance |
| No velocity control | Synchronous token-bucket `VelocityGuard` in `arc-guards` | Phase 8 (this phase) | SEC-05 compliance |

**Foundation established in Phase 7 (confirmed shipped):**
- `MonetaryAmount` type with `u64` minor-unit integers
- `ToolGrant.max_cost_per_invocation` and `max_total_cost` fields
- `Attenuation::ReduceCostPerInvocation` and `ReduceTotalCost` variants
- `is_subset_of` currency matching via string equality (fail-closed)

---

## Open Questions

1. **`FinancialReceiptMetadata.delegation_depth` and `root_budget_holder` population**
   - What we know: `ArcReceiptBody` has `capability_id` but not delegation depth or root key directly
   - What's unclear: Is delegation depth derivable from `CapabilityToken.delegation_chain.len()`? Is the root budget holder the issuer at delegation depth 0?
   - Recommendation: Use `delegation_chain.len()` as delegation depth; root budget holder is `capability.issuer.to_hex()` (the token's original issuer has depth 0). If delegation chain is empty, depth=0 and root_budget_holder = issuer. Claude's discretion applies here per CONTEXT.md.

2. **Checkpoint trigger: `append_arc_receipt_returning_seq` vs modulo on count**
   - What we know: `tool_receipt_count()` exists on `SqliteReceiptStore` but not on the `ReceiptStore` trait
   - What's unclear: Whether to extend the `ReceiptStore` trait or keep checkpoint triggering in the kernel caller
   - Recommendation: Add `append_arc_receipt_returning_seq` as a non-trait method on `SqliteReceiptStore` (same pattern as `list_tool_receipts_after_seq`). The kernel calls this directly when it has a `SqliteReceiptStore` reference. Avoids trait churn.

3. **VelocityGuard state persistence across kernel restarts**
   - What we know: Token bucket state is in-memory; buckets reset on restart
   - What's unclear: Whether this is acceptable for Phase 8 or needs SQLite persistence
   - Recommendation: In-memory is acceptable for Phase 8. CONTEXT.md locked decisions don't require persistence. Document the restart-reset behavior in a code comment.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in test runner (`cargo test`) |
| Config file | `Cargo.toml` per-crate `[lints.clippy]` section |
| Quick run command | `cargo test -p arc-kernel -p arc-guards --lib` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SCHEMA-04 | `try_charge_cost` allows when under budget, denies when over | unit | `cargo test -p arc-kernel budget_store` | Wave 0 gap |
| SCHEMA-04 | IMMEDIATE transaction prevents TOCTOU double-charge | unit | `cargo test -p arc-kernel concurrent_charge` | Wave 0 gap |
| SCHEMA-04 | `total_cost_charged` replication via `upsert_usage` MAX() | unit | `cargo test -p arc-kernel budget_store` | Wave 0 gap |
| SCHEMA-05 | `invoke_with_cost` default impl returns `(value, None)` | unit | `cargo test -p arc-kernel` | Wave 0 gap |
| SCHEMA-06 | `FinancialReceiptMetadata` serializes under `"financial"` key in metadata | unit | `cargo test -p arc-core receipt` | Wave 0 gap |
| SCHEMA-06 | Denial receipt includes `attempted_cost` and `budget_remaining` | unit | `cargo test -p arc-kernel monetary_denial` | Wave 0 gap |
| SEC-01 | 100 receipts produce a `KernelCheckpoint` with correct `tree_size = 100` | unit/integration | `cargo test -p arc-kernel checkpoint` | Wave 0 gap |
| SEC-01 | Checkpoint is signed and verifiable with kernel public key | unit | `cargo test -p arc-kernel checkpoint` | Wave 0 gap |
| SEC-02 | Single receipt's inclusion proof verifies against checkpoint Merkle root | unit | `cargo test -p arc-kernel inclusion_proof` | Wave 0 gap |
| SEC-02 | Tampered receipt bytes fail inclusion proof verification | unit | `cargo test -p arc-kernel inclusion_proof` | Wave 0 gap |
| SEC-05 | VelocityGuard allows up to rate limit, denies above it | unit | `cargo test -p arc-guards velocity` | Wave 0 gap |
| SEC-05 | VelocityGuard tokens refill after window | unit | `cargo test -p arc-guards velocity` | Wave 0 gap |
| SEC-05 | No kernel panics or executor nesting on velocity denial | unit | `cargo test -p arc-kernel velocity_integration` | Wave 0 gap |
| HA overrun | Concurrent charge test asserts overrun <= `max_cost_per_invocation * 2` | unit | `cargo test -p arc-kernel concurrent_charge_overrun_bound` | Wave 0 gap |

### Sampling Rate
- **Per task commit:** `cargo test -p arc-kernel --lib && cargo test -p arc-guards --lib`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green + `cargo clippy --workspace -- -D warnings` before `/gsd:verify-work`

### Wave 0 Gaps
All test files listed below must be created or extended before implementation:

- [ ] `crates/arc-kernel/src/budget_store.rs` -- add `try_charge_cost` unit tests (cost cap, total cap, TOCTOU proof-of-concept, replication extension)
- [ ] `crates/arc-kernel/src/checkpoint.rs` -- create module with `build_checkpoint`, `store_checkpoint`, `verify_inclusion_proof` and their tests
- [ ] `crates/arc-core/src/receipt.rs` -- add `FinancialReceiptMetadata` struct and roundtrip serialization test
- [ ] `crates/arc-guards/src/velocity.rs` -- create `VelocityGuard`, `TokenBucket`, `VelocityConfig` with unit tests
- [ ] Integration test in `crates/arc-kernel/src/lib.rs` tests section -- monetary enforcement through `evaluate_tool_call`, velocity denial, checkpoint trigger at N=100

*(If no gaps: "None -- existing test infrastructure covers all phase requirements")*

---

## Sources

### Primary (HIGH confidence)
- `crates/arc-kernel/src/budget_store.rs` -- `try_increment`, IMMEDIATE transaction pattern, replication seq, `upsert_usage` conflict resolution
- `crates/arc-kernel/src/receipt_store.rs` -- `append_arc_receipt`, `list_tool_receipts_after_seq`, `tool_receipt_count`, WAL schema
- `crates/arc-core/src/merkle.rs` -- `MerkleTree::from_leaves`, `MerkleProof::verify`, RFC 6962 compliance, left-balanced carry-up semantics
- `crates/arc-kernel/src/lib.rs` -- `check_and_increment_budget`, `build_deny_response`, `run_guards`, `evaluate_tool_call_with_session_roots`, `GuardContext`, `ToolServerConnection`, `KernelError`
- `crates/arc-guards/src/pipeline.rs` -- `GuardPipeline::evaluate`, `Guard` trait integration
- `crates/arc-guards/src/lib.rs` -- `default_pipeline`, guard registration pattern

### Secondary (MEDIUM confidence)
- `docs/AGENT_ECONOMY.md` -- `FinancialReceiptMetadata` struct spec, `ToolInvocationCost` struct spec, `try_charge_cost` signature, schema migration SQL, replication conflict resolution SQL, `invoke_with_cost` default method design
- `docs/CLAWDSTRIKE_INTEGRATION.md` -- checkpoint statement pattern (section 3.5), token bucket velocity guard (section 3.3), domain separation tags, schema identifier naming

### Tertiary (LOW confidence / Claude discretion)
- Standard token bucket algorithm (textbook pattern, no source verification needed for this simple form)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- no new deps; all libraries verified in working state in existing code
- Architecture: HIGH -- every pattern has a direct precedent in the codebase
- Pitfalls: HIGH -- documented from code inspection of actual call sites and known HA replication model

**Research date:** 2026-03-22
**Valid until:** 2026-04-22 (Rust codebase; stable; 30-day horizon)
