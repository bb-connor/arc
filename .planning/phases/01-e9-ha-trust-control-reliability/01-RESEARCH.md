# Phase 1: E9 HA Trust-Control Reliability - Research

**Researched:** 2026-03-19
**Domain:** Rust HA control-plane determinism over SQLite-backed leader/follower replication
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Treat the current `cargo test --workspace` trust-cluster failure as a release blocker, not as acceptable background flakiness.
- Returned success from a forwarded mutating write must mean the state is durably visible where the contract says it should be visible.
- Add cluster observability that exposes leader identity, peer health, replication positions, and cursor state directly from the running trust service.
- Improve test failure output so a timeout reports cluster state and budget state from both nodes instead of only the timeout label.
- Prefer an explicit monotonic replication position over ambiguous timestamp-only semantics for repeated same-key updates.

### Claude's Discretion
- Exact JSON field names for internal debug surfaces
- The concrete monotonic cursor mechanism for budget replication
- Whether extra diagnostics remain internal-only or also appear on `/health`

### Deferred Ideas (OUT OF SCOPE)
- Full consensus or quorum-based replication
- Multi-region control-plane behavior
- General performance benchmarking beyond what is needed to prove determinism

</user_constraints>

<research_summary>
## Summary

The current HA model is intentionally simple: a deterministic leader chosen from healthy peers, local SQLite state on every node, and periodic repair sync. That model is still workable for this milestone, but it depends on two things that are not currently explicit enough: a concrete read-after-write contract for forwarded writes, and monotonic replication cursors that do not lose repeated updates to the same logical record.

The highest-risk implementation seam is the budget path. `try_increment` mutates a single row per `(capability_id, grant_index)`, while follower replication currently enumerates current rows using `updated_at` plus the key tuple as a cursor. Because `updated_at` is second-resolution and the row is overwritten in place, repeated same-key updates within one second can become ambiguous for downstream replication. Even if that is not the only source of the observed flake, it is a concrete correctness hazard and should be removed.

The recommended path for E9 is:
- first, make cluster state observable enough to localize failures quickly;
- second, freeze what a successful forwarded write means and enforce that in handlers;
- third, harden budget replication around an explicit monotonic cursor or version;
- fourth, prove the result with repeat-run and failover coverage that exercises leader and follower entry points.

**Primary recommendation:** Treat budget replication and forwarded-write visibility as contract problems, not as test timing problems.
</research_summary>

<standard_stack>
## Standard Stack

The established libraries/tools for this domain:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `axum` | 0.8 | Trust-control HTTP serving | Already owns the control-plane endpoint layer in `pact-cli` |
| `rusqlite` | 0.37 | Durable authority, receipt, revocation, and budget state | Existing store layer already depends on it and uses WAL/FULL sync |
| `tokio` | 1.x | Cluster sync loop and async server runtime | Existing async control-plane execution model |
| `tracing` | 0.1 | Runtime diagnostics | Existing logging and warning surface |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `reqwest` / `ureq` | 0.12 / 2.10 | Test-time and runtime HTTP control calls | Existing peer sync and integration tests |
| `serde` / `serde_json` | 1.x | Internal status and delta payloads | Existing JSON wire format for control endpoints |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Explicit monotonic replication position | Timestamp-only ordering | Simpler shape, but ambiguous for repeated same-key updates |
| Internal debug status views | Ad hoc log scraping | Less code, but much worse for deterministic test diagnostics |
| Tight forwarded-write contract | Eventually-consistent success semantics | Higher apparent availability, but weaker operator guarantees and harder debugging |

**Installation:**
```bash
# No new libraries are required for E9 by default.
# Use the existing Rust workspace stack first.
```
</standard_stack>

<architecture_patterns>
## Architecture Patterns

### Recommended Project Structure
```text
crates/pact-cli/src/trust_control.rs     # routing, forwarding, sync orchestration, debug views
crates/pact-kernel/src/budget_store.rs   # monotonic budget persistence/cursor semantics
crates/pact-cli/tests/trust_cluster.rs   # HA proving ground and timeout diagnostics
```

### Pattern 1: Internal status views for cluster debugging
**What:** Keep operator/debug-only replication details behind internal authenticated JSON endpoints.
**When to use:** When a failure needs leader, peer, cursor, or sequence context that should not shape the public contract.
**Example:**
```rust
Json(ClusterStatusResponse {
    self_url,
    leader_url,
    peers,
})
```

### Pattern 2: Forwarded write handled by leader, read-back verified before success
**What:** After forwarding a mutating request to the leader, treat success as contingent on durable visibility at the leader according to the operation contract.
**When to use:** Budget increments, authority rotations, revocations, and receipt ingestion where correctness matters more than optimistic success.
**Example:**
```text
follower POST -> leader mutates durable store -> leader verifies visible state -> leader returns success -> follower relays success
```

### Pattern 3: Monotonic replication cursor over mutable state
**What:** Replication should advance with a strictly monotonic cursor rather than a coarse timestamp over overwritten rows.
**When to use:** Any delta endpoint where the same logical key can update multiple times between polls.
**Example:**
```text
write_version: 41 -> 42 -> 43
peer cursor stores 43, not just updated_at=1710864000
```

### Anti-Patterns to Avoid
- **Timeout-only debugging:** A failing HA test that prints only `condition not satisfied` forces code spelunking instead of exposing the cluster state directly.
- **Success-before-visibility:** Returning success from follower-forwarded writes before the leader's durable view is actually queryable creates semantic ambiguity.
- **Timestamp-only delta ordering for mutable rows:** Safe enough for append-only records, unsafe for repeated updates to one mutable budget row.
</architecture_patterns>

<dont_hand_roll>
## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HA correctness | A new distributed consensus system | The existing deterministic leader + repair sync model | E9 is about stabilizing the current design, not replacing it |
| Failure diagnostics | Log-only debugging | Structured internal status JSON + test diagnostics | Easier to assert and print on timeout |
| Budget replication position | More sleeps and longer polling | A monotonic cursor/version in the store | Sleeps hide bugs; monotonic cursors remove ambiguity |

**Key insight:** Most of E9 is contract hardening around existing seams, not a need for new infrastructure.
</dont_hand_roll>

<common_pitfalls>
## Common Pitfalls

### Pitfall 1: Mistaking eventual convergence for a write contract
**What goes wrong:** Handlers return success because replication will probably catch up soon.
**Why it happens:** Forwarding and repair sync make the system appear HA-capable even when the success semantics are underspecified.
**How to avoid:** Decide what each mutating endpoint guarantees before returning success.
**Warning signs:** Tests need arbitrary sleeps or poll for "eventual" visibility after a supposedly successful leader-routed write.

### Pitfall 2: Using coarse timestamps as replication cursors for mutable rows
**What goes wrong:** Repeated same-key updates collapse into one timestamp bucket and a peer cursor misses newer state.
**Why it happens:** Mutable-row replication is treated like append-only record replication.
**How to avoid:** Add a true monotonic write cursor or at least a higher-fidelity monotonic position tied to each mutation.
**Warning signs:** Delta endpoints sort by `(updated_at, key)` and the same key can change multiple times quickly.

### Pitfall 3: Adding observability only to logs
**What goes wrong:** Reproducers and tests cannot capture the right state at the moment of failure.
**Why it happens:** Logs feel cheaper than API surfaces.
**How to avoid:** Expose cluster status, peer cursors, and local budget views through an authenticated internal endpoint and consume it from tests.
**Warning signs:** A timeout requires rerunning with manual instrumentation to learn anything useful.
</common_pitfalls>

<code_examples>
## Code Examples

Verified patterns from local sources:

### Cluster leader computation
```rust
fn current_leader_url(state: &TrustServiceState) -> Option<String> {
    let cluster = state.cluster.as_ref()?;
    let now = Instant::now();
    let (self_url, peers) = match cluster.lock() {
        Ok(guard) => (guard.self_url.clone(), guard.peers.clone()),
        Err(poisoned) => {
            let guard = poisoned.into_inner();
            (guard.self_url.clone(), guard.peers.clone())
        }
    };
    let mut candidates = vec![self_url];
    for (peer_url, peer_state) in peers {
        if peer_state.health.is_candidate(now) {
            candidates.push(peer_url);
        }
    }
    candidates.sort();
    candidates.into_iter().next()
}
```
Source: `crates/pact-cli/src/trust_control.rs`

### Budget delta cursor today
```rust
pub fn list_usages_after(
    &self,
    limit: usize,
    after_updated_at: Option<i64>,
    after_capability_id: Option<&str>,
    after_grant_index: Option<u32>,
) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
    // ordered by updated_at ASC, capability_id ASC, grant_index ASC
}
```
Source: `crates/pact-kernel/src/budget_store.rs`

### Trust-cluster timeout proving point
```rust
wait_until("leader budget visibility", Duration::from_secs(90), || {
    let Some(budgets) = try_get_json(
        &client,
        &format!("{leader_url}/v1/budgets?capabilityId=cap-shared&limit=10"),
        service_token,
    ) else {
        return false;
    };
    budgets["count"].as_u64() == Some(1)
        && budgets["usages"][0]["invocationCount"].as_u64() == Some(1)
});
```
Source: `crates/pact-cli/tests/trust_cluster.rs`
</code_examples>

<sota_updates>
## State of the Art (Current Local Design)

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Single control service | Replicated trust-control cluster with deterministic leader | Recent HA rewrite | Reliability now depends on well-defined forwarding and repair semantics |
| Node-local invocation budgets | Shared control-plane budget store | Recent HA rewrite | Budget correctness is now part of cluster correctness |

**New tools/patterns to consider:**
- Explicit internal status JSON for cluster debugging
- Monotonic replication positions for mutable store state

**Deprecated/outdated:**
- Treating repair sync as sufficient proof of write correctness for all mutating operations
</sota_updates>

<open_questions>
## Open Questions

1. **Is the observed flake caused only by budget cursor ambiguity?**
   - What we know: the budget path is the visible failure point and the current cursor scheme is fragile.
   - What's unclear: whether leader health transitions or forwarding retries also contribute under workspace load.
   - Recommendation: land observability first so the timeout path captures cluster state before changing semantics.

2. **Should visibility guarantees be operation-specific or uniform across all forwarded writes?**
   - What we know: budgets, authority, revocations, and receipts all matter, but their storage shapes differ.
   - What's unclear: whether one uniform helper can prove visibility for all mutating handlers cleanly.
   - Recommendation: define one shared contract model, then allow per-operation read-back implementation details.
</open_questions>

<sources>
## Sources

### Primary (HIGH confidence)
- `docs/epics/E9-ha-trust-control-reliability.md` - E9 outcome, slices, and acceptance criteria
- `docs/HA_CONTROL_AUTH_PLAN.md` - HA control-plane design and non-goals
- `crates/pact-cli/src/trust_control.rs` - Current forwarding, leader selection, sync, and status code
- `crates/pact-kernel/src/budget_store.rs` - Current budget storage and delta cursor logic
- `crates/pact-cli/tests/trust_cluster.rs` - Failing/critical proving scenario

### Secondary (MEDIUM confidence)
- `crates/pact-kernel/src/authority.rs` - Authority snapshot convergence model
- `crates/pact-kernel/src/receipt_store.rs` - Receipt sequencing model
- `crates/pact-kernel/src/revocation_store.rs` - Revocation cursor model
</sources>

<metadata>
## Metadata

**Research scope:**
- Core technology: trust-control HA reliability
- Ecosystem: local Rust/Axum/SQLite implementation only
- Patterns: forwarding semantics, delta replication, timeout diagnostics
- Pitfalls: mutable-row cursor ambiguity, underspecified write success, weak observability

**Confidence breakdown:**
- Standard stack: HIGH - existing repo stack is already the right implementation surface
- Architecture: HIGH - current seams and failure points are visible in the local code
- Pitfalls: HIGH - budget cursor ambiguity is concrete in the local store code
- Code examples: HIGH - all examples are from the local codebase

**Research date:** 2026-03-19
**Valid until:** 2026-04-18
</metadata>

---
*Phase: 01-e9-ha-trust-control-reliability*
*Research completed: 2026-03-19*
*Ready for planning: yes*
