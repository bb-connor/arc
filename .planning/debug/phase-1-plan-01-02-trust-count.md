---
status: investigating
trigger: "Debug the current blocker in /Users/connor/Medica/backbay/standalone/arc for Phase 1 Plan 01-02.

Observed gate failure from independent verifier:
- command: cargo test -p arc-cli --test trust_cluster
- failing location: crates/arc-cli/tests/trust_cluster.rs:653
- symptom: follower-originated POST /v1/budgets/increment returned invocationCount = 1, but test expected 2

Context:
- This is inside the HA trust-cluster test asserting the leader-visible write contract.
- Recent changes added leader-local post-write verification and response metadata in crates/arc-cli/src/trust_control.rs.
- The failure indicates the follower-forwarded budget increment may be returning before the leader-visible count reflects both increments, or the returned count is using the wrong local view.

Your task:
1. Diagnose the root cause precisely.
2. Do not edit files yet unless needed for temporary instrumentation you will clearly describe.
3. If you find the bug, state the minimal implementation/test change needed.
4. Include the exact files/lines you think are responsible.

Focus files:
- crates/arc-cli/src/trust_control.rs
- crates/arc-cli/tests/trust_cluster.rs
- any budget-store file you need

Return a concise debugger report with hypothesis, evidence, and recommended fix."
created: 2026-03-19T00:00:00-04:00
updated: 2026-03-19T00:18:00-04:00
---

## Current Focus

hypothesis: the failure is an intermittent split-brain write path where follower forwarding is bypassed whenever the leader peer is temporarily marked unhealthy, allowing the follower to execute the increment locally against a stale budget store
test: correlate the non-reproducing gate failure with the code paths that let a follower self-elect after peer-health churn, then identify the minimal change that enforces leader-routed writes
expecting: because the test passed locally, the root cause should be a race or flake in leader selection rather than deterministic budget-store arithmetic
next_action: finalize diagnosis from the current_leader_url and forward_post_to_leader behavior and report the minimal fix

## Symptoms

expected: follower-originated POST /v1/budgets/increment should return invocationCount = 2 in the HA trust-cluster test
actual: follower-originated POST /v1/budgets/increment returned invocationCount = 1
errors: test assertion failure at crates/arc-cli/tests/trust_cluster.rs:653
reproduction: run cargo test -p arc-cli --test trust_cluster and inspect the follower-originated budget increment assertion
started: after recent changes adding leader-local post-write verification and response metadata in crates/arc-cli/src/trust_control.rs

## Eliminated

## Evidence

- timestamp: 2026-03-19T00:08:00-04:00
  checked: .planning/debug/knowledge-base.md
  found: no knowledge base file exists for prior matching incidents
  implication: this failure needs first-principles investigation

- timestamp: 2026-03-19T00:09:00-04:00
  checked: crates/arc-cli/tests/trust_cluster.rs
  found: the failing assertion expects the follower-originated increment response itself to report invocationCount = 2 immediately after a leader-originated increment returned 1
  implication: the contract is response-time leader visibility, not eventual follower replication

- timestamp: 2026-03-19T00:10:00-04:00
  checked: crates/arc-cli/src/trust_control.rs handle_try_increment_budget and forward_post_to_leader
  found: handle_try_increment_budget would return the leader store's post-commit count if forwarding occurs, but forward_post_to_leader skips forwarding whenever current_leader_url(state) resolves to self
  implication: a returned count of 1 strongly suggests the follower executed the write locally rather than forwarding to the leader

- timestamp: 2026-03-19T00:17:00-04:00
  checked: cargo test -p arc-cli --test trust_cluster -- --nocapture
  found: the test passed locally in 62.71s on this checkout
  implication: the reported gate failure is likely timing-dependent rather than a deterministic logic error in the happy path

- timestamp: 2026-03-19T00:18:00-04:00
  checked: crates/arc-cli/src/trust_control.rs current_leader_url, PeerHealth::is_candidate, and forward_post_to_leader
  found: a peer marked Unhealthy is excluded from leader election for 3 seconds, and forward_post_to_leader falls back to local handling whenever current_leader_url(state) equals self
  implication: any transient sync/transport failure can cause a follower to stop forwarding writes and return its own local budget count, which matches the observed invocationCount = 1 symptom

## Resolution

root_cause: follower write routing is not strict; transient peer-health failures let a follower self-elect and execute budget increments locally, so the response can surface stale follower state instead of the leader-visible count
fix: make forwarded control-plane writes fail closed when the elected leader is remote but temporarily unhealthy or unreachable, instead of falling back to local execution on the follower; optionally tighten the test to assert the returned leaderUrl equals the precomputed leader
verification:
files_changed: []
