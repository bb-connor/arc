# Security alert delivery reconciliation plan

> **For agentic workers:** Use superpowers:executing-plans in Root's native
> thread. Claude independently reviews the complete candidate. Root remains
> the sole integrator and publisher.

**Goal:** Close F041 by delivering the security alerts already admitted to the
durable SIEM outbox, and exposing delivery exhaustion through host readiness.

**Architecture:** Forward-port the accepted bounded design in `b216cbfdbf`:
an async delivery loop on the existing response-worker thread, at most 16
rows per pass, skipped missed cadences, typed delivery health, and a durable
pending/parked count. Worker recovery and containment expiry must continue
through a SIEM outage. The loop shares worker lifetime and shutdown custody.
No new thread, requeue API, authority change or cap waiver.

**Baseline:** Private branch `fix/security-alert-delivery`, based on reviewed
`2f4479829e`. The per-backend delivery repair is already in main. The current
host has no production caller of `SqliteSiemOutbox::deliver_due`.

**Spec:** F041, preserved Originals `f16adf1cfd` and `241af72e37`, and the
accepted mailbox design from 2026-10-07. Keep #1201 and #1202 unchanged; this
candidate has no PR or publication until the active queue advances.

## Task 1: Reproduce current host failures

Files: `crates/platform/chio-control-plane/src/security/active_defense_host_tests.rs`
and its `siem_delivery.rs` module.

- [ ] Port only the two regression tests from `241af72e37`, adapting fixture
  setup to current trusted-clock and ownership contracts without weakening
  their delivery/exhaustion assertions.
- [ ] Run the focused `siem_delivery` lib tests and preserve genuine terminal
  failures: healthy ticks with no backend delivery; exhausted alerts with
  healthy host readiness. Keep compile/environment refusals distinct.
- [ ] Commit test-only Originals before changing production code.

## Task 2: Compose the preserved bounded repair

Files: security module exports, adapters/native_evidence.rs, orchestration.rs,
orchestration/teardown.rs, scheduler_worker.rs and worker/alert-delivery modules.

- [ ] Apply the preserved production repair against current source, retaining
  the newer startup, admission-close, worker-crash and teardown ownership.
- [ ] Check the actual outbox failure/report contract and count previously
  parked rows across configuration changes. Keep durable admission distinct
  from backend delivery; preserve at-least-once semantics.
- [ ] Run both Originals to green and exercise bounded passes, pending/parked
  accounting, trusted-clock failures, hanging backend/expiry progress, and
  shutdown cancellation. Add controls where the preserved tests lack coverage.

## Task 3: Qualify and review

- [ ] Run owning host/worker and native-security-evidence tests, strict owning
  Clippy, formatting, negative assertions and structural/inventory gates.
  Broaden only for unresolved integration risk; preserve all failures.
- [ ] Ask Claude for independent complete-source review; fix confirmed issues
  and rerun affected gates. Record exact source and evidence hashes.
- [ ] Commit the bounded repair and audit; update board/claims/mailbox. Mark
  local qualification separately from future hosted/main acceptance.
