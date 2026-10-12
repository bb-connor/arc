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
No detached delivery task, requeue API, authority change or cap waiver. The
review correction below uses the existing runtime's managed blocking pool.

**Baseline:** Private branch `fix/security-alert-delivery`, based on reviewed
`2f4479829e`. The per-backend delivery repair is already in main. The current
host has no production caller of `SqliteSiemOutbox::deliver_due`.

**Spec:** F041, preserved Originals `f16adf1cfd` and `241af72e37`, and the
accepted mailbox design from 2026-10-07. Keep #1201 and #1202 unchanged; this
candidate has no PR or publication until the active queue advances.

## Task 1: Reproduce current host failures

Files: `crates/platform/chio-control-plane/src/security/active_defense_host_tests.rs`
and its `siem_delivery.rs` module.

- [x] Port only the two regression tests from `241af72e37`, adapting fixture
  setup to current trusted-clock and ownership contracts without weakening
  their delivery/exhaustion assertions.
- [x] Run the focused `siem_delivery` lib tests and preserve genuine terminal
  failures: healthy ticks with no backend delivery; exhausted alerts with
  healthy host readiness. Keep compile/environment refusals distinct.
- [x] Commit test-only Originals before changing production code.

Current test-only commit: `c8700357b7`. Both tests failed for the intended
reason: 20 healthy ticks with zero delivered alerts, and healthy host readiness
with one parked alert after both backend attempts. Evidence is retained in
`alert-delivery-original/001-host-originals` under the Root CI evidence batch.

## Task 2: Compose the preserved bounded repair

Files: security module exports, adapters/native_evidence.rs, orchestration.rs,
orchestration/teardown.rs, scheduler_worker.rs and worker/alert-delivery modules.

- [x] Apply the preserved production repair against current source, retaining
  the newer startup, admission-close, worker-crash and teardown ownership.
- [x] Check the actual outbox failure/report contract and count previously
  parked rows across configuration changes. Keep durable admission distinct
  from backend delivery; preserve at-least-once semantics.
- [x] Run both Originals to green and exercise bounded passes, pending/parked
  accounting, trusted-clock failures, hanging backend/expiry progress, and
  shutdown cancellation. Add controls where the preserved tests lack coverage.

## Task 3: Qualify and review

- [x] Run owning host/worker and native-security-evidence tests, strict owning
  Clippy, formatting, negative assertions and structural/inventory gates.
  Broaden only for unresolved integration risk; preserve all failures.
- [x] Ask Claude for independent complete-source review; fix confirmed issues
  and rerun affected gates. Record exact source and evidence hashes.
- [x] Commit the bounded repair and audit; update board/claims/mailbox. Mark
  local qualification separately from future hosted/main acceptance.

## Independent review corrections

Claude/C7's 2026-10-12T04:50:41Z basis review found two P2 defects in the
preserved producer. A backend panic unwinds the response worker; synchronous
delivery SQLite waits run on the same thread as response ticks. Before accepting
the producer, reproduce both with the composed host and repair them:

- [x] A panicking backend must leave containment expiry and clean worker
  shutdown functional. Catch each delivery pass, record a fixed health error,
  and retain the queued row. Do not expose the panic payload in health.
- [x] With a real external `BEGIN IMMEDIATE` transaction blocking confirmation,
  require expiry progress while the first delivery pass is still in flight.
  Observing progress only after SQLite's busy timeout does not pass.
- [x] Move the host's synchronous delivery storage operations into the worker
  runtime's blocking pool, with an owned delivery guard moved into each
  operation and returned only after it finishes. Backend futures remain in the worker loop. The existing runtime
  drop and thread-join ownership must drain started storage operations before
  releasing custody; cancellation must not permit overlapping delivery writes.
- [x] Keep one off-thread delivery algorithm for the public method, tests and
  host. Preserve all integrity/readiness checks; add no compatibility mode.
  This bounds dispatched rows and outstanding storage operations, not SQLite
  scan complexity or the duration of a synchronous public readiness probe.
- [x] Verify parked rows stay parked after reopening with a larger retry limit.
  Document at-least-once delivery, the library-host scope, and the absence of a
  supported requeue API.

The older producer was qualified with two additional orchestration fixes
(`37b1a7e519` and `6f4c0ade1e`) absent from this base. They remain separate
preserved obligations; none of their historical green results qualifies this
composition. The first composed test compile also lacked the host-error enum
import; retain that compile refusal separately from runtime counterexamples.

## Local completion

The 12 focused controls, 127 host/worker/simulation tests, 24 native evidence
tests and strict all-target Clippy passed. Claude/C7 approved the complete
source patch with no P0/P1/P2 findings. Formatting, Rust hygiene, negative
assertions and the security CI contract passed. The original contract refusal
from private-checkout group-write bits and both intermediate compile refusals
remain in the audit evidence. No baseline or ratchet was relaxed.

See `docs/security/audits/security-alert-delivery-20261012.json` for source
hashes, retained Originals and local evidence. Hosted qualification, landing
and production SIEM acceptance remain separate requirements.

## Actual-main composition

The F041 source composes directly onto main after #1201; its earlier SDK and
wire ancestors are separate work. The relocated `load_due` reader inventory
is carried with this wave, so its trust-boundary gate stays accurate. The
private qualification above remains historical. Focused tests and strict
Clippy are renewed on this composition before publication.
