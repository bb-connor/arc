# Phase 8: Core Enforcement - Context

**Gathered:** 2026-03-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Monetary budget limits, Merkle-committed receipt batches, and velocity throttling are all enforced at kernel evaluation time. This phase adds try_charge_cost to BudgetStore, FinancialReceiptMetadata to receipts, batch-N Merkle checkpoint signing, inclusion proof verification, and a synchronous VelocityGuard in arc-guards. No new APIs, CLI commands, or external integrations -- pure enforcement logic wired into the kernel pipeline.

</domain>

<decisions>
## Implementation Decisions

### Budget Enforcement Semantics
- try_charge_cost checks both max_cost_per_invocation AND max_total_cost in a single atomic IMMEDIATE transaction (prevents TOCTOU races)
- Denial receipts include attempted_cost and budget_remaining in FinancialReceiptMetadata for debugging and audit
- BudgetStore adds a total_cost_charged column (u64 minor-units) as a running total, mirroring the invocation_count pattern
- HA overrun bound is fixed at max_cost_per_invocation x node_count, documented in code comment and covered by a named concurrent-charge test

### Merkle Checkpoint Behavior
- Checkpoints trigger every N receipts (configurable, default 100) -- deterministic and testable per success criterion
- Checkpoint is a separate KernelCheckpoint struct with Merkle root, batch range, and kernel signature -- not a special receipt type
- Checkpoints stored in a separate kernel_checkpoints SQLite table (different access pattern from receipts)
- Inclusion proofs are self-contained for offline verification (carry root + path + leaf hash), using existing MerkleProof from arc-core

### Velocity Guard Design
- VelocityGuard lives in arc-guards alongside existing guards (forbidden_path, egress_allowlist, etc.) -- keeps kernel TCB minimal
- Uses synchronous token bucket with std::sync::Mutex (no async) per success criterion
- Enforcement scope is per-grant with agent-level aggregation option (grants are the natural enforcement boundary)
- Velocity denials use standard Decision::Deny with reason "velocity_limit_exceeded" -- no new Decision variant needed

### Claude's Discretion
- Internal implementation details of checkpoint.rs module structure
- SQLite schema details for kernel_checkpoints table beyond the core columns
- Token bucket refill strategy and window sizing defaults
- ToolInvocationCost struct field layout and how tool servers report cost back to the kernel

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `arc-kernel/src/budget_store.rs` -- BudgetStore trait, InMemoryBudgetStore, SqliteBudgetStore with IMMEDIATE transactions and replication seq
- `arc-kernel/src/receipt_store.rs` -- ReceiptStore trait, SqliteReceiptStore with append and filtered list methods
- `arc-core/src/merkle.rs` -- RFC 6962-compatible MerkleTree and MerkleProof with from_leaves, inclusion_proof, and verify methods
- `arc-core/src/capability.rs` -- MonetaryAmount (u64 minor-units), ToolGrant with max_cost_per_invocation/max_total_cost fields, Attenuation with ReduceCostPerInvocation/ReduceTotalCost
- `arc-guards/src/pipeline.rs` -- Guard pipeline pattern for composable enforcement
- `arc-core/src/crypto.rs` -- Keypair, signing, canonical JSON

### Established Patterns
- SQLite stores use WAL mode, SYNCHRONOUS=FULL, IMMEDIATE transactions for writes
- Budget replication uses seq-based delta queries for HA leader/follower sync
- Guard pipeline is composable -- each guard returns allow/deny evidence
- All signed payloads use canonical JSON (RFC 8785)
- Optional fields use #[serde(default, skip_serializing_if = "Option::is_none")]

### Integration Points
- BudgetStore.try_increment is called during kernel evaluation -- try_charge_cost follows the same call site pattern
- ReceiptStore.append_arc_receipt is the hook for counting toward Merkle checkpoint trigger
- Guard pipeline in arc-guards/src/pipeline.rs is where VelocityGuard plugs in
- ArcReceipt.metadata (Option<serde_json::Value>) is where FinancialReceiptMetadata attaches

</code_context>

<specifics>
## Specific Ideas

- Reference docs/CLAWDSTRIKE_INTEGRATION.md for velocity guard port strategy
- Reference docs/AGENT_ECONOMY.md for FinancialReceiptMetadata field design (grant_index, cost_charged, budget_remaining, settlement_status)
- The HA overrun bound documentation satisfies STATE.md blocker: "Monetary HA overrun bound must be explicitly documented in Phase 8"
- Success criterion 3 specifically requires "batch of 100 receipts" -- use this as the default checkpoint batch size

</specifics>

<deferred>
## Deferred Ideas

None -- discussion stayed within phase scope

</deferred>
