# Phase 1: E9 HA Trust-Control Reliability - Context

**Gathered:** 2026-03-19
**Status:** Ready for planning

<domain>
## Phase Boundary

Make clustered trust-control deterministic enough that workspace and CI runs stop failing on leader/follower visibility races. This phase is about the existing HA control-plane semantics: reproduce the flake, expose enough cluster state to debug it, tighten the forwarded-write contract, harden replication ordering, and prove the result with repeatable failover coverage.

</domain>

<decisions>
## Implementation Decisions

### Reliability target
- Treat the current `cargo test --workspace` trust-cluster failure as a release blocker, not as acceptable background flakiness.
- Optimize for deterministic read-after-write visibility and monotonic replication behavior before chasing throughput.

### Contract boundary
- Freeze the external control-plane contract before making internal timing changes.
- Returned success from a forwarded mutating write must mean the state is durably visible where the contract says it should be visible.

### Debuggability
- Add cluster observability that exposes leader identity, peer health, replication positions, and cursor state directly from the running trust service.
- Improve test failure output so a timeout reports cluster state and budget state from both nodes instead of only the timeout label.

### Replication semantics
- Treat budget replication as the highest-risk area because it currently relies on cursor ordering over mutable per-key state.
- Prefer an explicit monotonic replication position over ambiguous timestamp-only semantics for repeated same-key updates.

### Claude's Discretion
- Exact JSON field names for internal debug surfaces
- Whether budget replication uses a dedicated sequence, higher-resolution timestamps, or another monotonic cursor, as long as the cursor is explicit and testable
- Whether additional cluster diagnostics live only under internal endpoints or also surface through `/health`

</decisions>

<specifics>
## Specific Ideas

- Keep the HA model pragmatic: deterministic leader plus repair sync, not consensus.
- Preserve the existing crate seams: `arc-cli` owns control-plane HTTP behavior, `arc-kernel` owns budget/authority/receipt/revocation storage primitives.
- Treat `crates/arc-cli/tests/trust_cluster.rs` as the first proving ground, because it already demonstrates the failing scenario.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Closing-cycle scope
- `docs/POST_REVIEW_EXECUTION_PLAN.md` — Post-review findings, milestone gates, and the reason E9 is first.
- `docs/epics/E9-ha-trust-control-reliability.md` — The issue-ready E9 contract, slices, risks, and acceptance criteria.
- `docs/EXECUTION_PLAN.md` — Program-level dependency order and the E14 release path this phase feeds.

### HA control design
- `docs/HA_CONTROL_AUTH_PLAN.md` — Existing HA control, leader selection, replication, and shared-budget design constraints.

### Runtime and storage code
- `crates/arc-cli/src/trust_control.rs` — Leader selection, forwarding, cluster sync, internal status, and budget increment handlers.
- `crates/arc-kernel/src/budget_store.rs` — Budget persistence, list-after cursor logic, and upsert/try-increment semantics.
- `crates/arc-kernel/src/authority.rs` — Authority snapshot replication semantics.
- `crates/arc-kernel/src/receipt_store.rs` — Receipt append and delta sequencing semantics.
- `crates/arc-kernel/src/revocation_store.rs` — Revocation cursor and upsert semantics.

### Proving tests
- `crates/arc-cli/tests/trust_cluster.rs` — Two-node HA replication and leader failover coverage, including the visible flake site.
- `crates/arc-cli/tests/trust_revocation.rs` — Related trust-control persistence behavior.
- `.github/workflows/ci.yml` — The real workspace gate this phase must stabilize.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `handle_internal_cluster_status` in `crates/arc-cli/src/trust_control.rs`: already exposes leader and peer health, making it the right place to add richer cursor/replication diagnostics.
- `wait_until` and HTTP helpers in `crates/arc-cli/tests/trust_cluster.rs`: already centralize timeout behavior and can carry structured diagnostics on failure.
- `SqliteBudgetStore::list_usages_after` and `upsert_usage` in `crates/arc-kernel/src/budget_store.rs`: the main budget replication seam and the likely place to harden monotonic ordering.

### Established Patterns
- Trust-control endpoints use internal JSON views plus shared bearer auth.
- Replication is idempotent and state-specific rather than log-replayed across the whole control plane.
- Storage crates prefer SQLite with WAL + FULL sync and small helper methods rather than a generic persistence abstraction.

### Integration Points
- Any write-visibility change must flow through `forward_post_to_leader` and the individual mutating handlers in `crates/arc-cli/src/trust_control.rs`.
- Any replication-order hardening must keep follower repair sync compatible with the current authority, revocation, receipt, and budget stores.
- Any new diagnostics should be consumable by `crates/arc-cli/tests/trust_cluster.rs` without requiring external tooling.

</code_context>

<deferred>
## Deferred Ideas

- Full consensus or quorum-based replication
- Multi-region control-plane behavior
- General performance benchmarking beyond what is needed to prove determinism

</deferred>

---
*Phase: 01-e9-ha-trust-control-reliability*
*Context gathered: 2026-03-19*
