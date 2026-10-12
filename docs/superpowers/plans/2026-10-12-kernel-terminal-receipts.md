# Kernel terminal receipts implementation plan

> **For agentic workers:** Use superpowers:executing-plans. Root implements and pushes; Claude reviews and merges. Work through the tasks below in dependency order.

**Goal:** Preserve one terminal owner for every dispatched call, including failed finalization, and sign truthful request-identity dispositions.

**Architecture:** A move-only post-effect obligation owns dispatch evidence through receipt commitment or durable saga handoff. Receipt publication distinguishes a refused append, an unknown append outcome, and an acknowledged commit with subsequent delivery failure. Non-durable evidence failures retain a reserved buffer slot and close new dispatch until supervised recovery resolves them.

**Tech stack:** Existing Rust kernel, receipt-store trait, signing backend, trusted clock, SQLite fixtures, Tokio tests and concurrency harnesses. No new dependency or store migration.

**Spec:** `docs/superpowers/specs/2026-10-04-typed-reservations-design.md`, phase 1; `2026-10-04-pure-admission-machine-design.md`, M20; `2026-10-04-durable-stop-epoch-design.md`, S15.

## Global constraints

- Base: `b1d0ee30dfcf10bdd363023522fe678f2f45febb`. Preserve already-landed admission custody, payment journaling and bounded receipt writer repairs.
- Non-durable acceptance is one committed terminal receipt OR one buffered evidence obligation with dispatch latched. Persistence eventually requires a healthy clock, signer and store. The in-memory buffer is not crash-durable.
- A durable call leaves terminal truth to its saga. Never append a competing cancellation or deny after handing off that operation.
- Unknown append outcomes retain the original receipt identity. Absence on an early read cannot establish that an in-flight write will never commit.
- No compensation, refund or release follows merely from an unknown result. Keep positive authorizations after capture error.
- Reserve 1024 evidence slots per kernel and 4096 per multi-kernel host by default, configurable with minimum 1. A buffered record retains both permits.
- Only new-dispatch admission checks the evidence latch. Compensation, recovery, receipt outboxes and session reports remain available.
- Root owns this implementation and the M20 helper. Claude owns KERN-1 stop and KERN-4 session entry; agree shared-file hunks before integration.
- One source unit for KERN-2. Do not publish partial phase-1 behavior as completion. No broad proof campaign or schema-slot change.

## Reconciled source

`evaluation/return_recording.rs` disarms the non-durable guard before ordinary finalization. Both evaluators use it. Security outcome release occurs before return recording. Durable return failure currently terminalizes unknown and writes a separate Deny; Drop similarly writes a cancellation before terminalizing. The capture-error and non-settled payment branches discard release outcomes.

`chio_runtime` is already reserved against caller metadata. Add `receipt_context`, which is not reserved. The non-settled payment path already denies delivery; preserve that behavior despite the older spec description of Allow.

## Review focus

- A timed-out append later commits: preserve its receipt id and never append a competing terminal. Task 2.
- Clock, signer and store fail together: retain the bounded obligation and refuse further dispatch, without blocking cleanup. Task 3.
- Two authenticated namespaces reuse one request id: bindings, latches and terminal counting remain isolated. Tasks 1 and 4.
- Cancellation races durable return recording: saga custody remains authoritative; neither Drop nor recovery duplicates a terminal. Task 4.
- A payment rail reports an ambiguous capture: retain its authorization and record the actual state; never imply a successful release. Task 5.

### Task 1: Original controls and identity contract

**Files:** `kernel/tests/post_effect_receipts.rs`, `kernel/tests.rs`, new `kernel/receipt_identity.rs`, the reserved metadata list in `kernel/mod.rs`, and explicit receipt-producing call sites.

**Interfaces:** Produce `IdentityDisposition::{Reusable, Retained, Terminal}` and `with_identity_disposition(Option<Value>, IdentityDisposition) -> Option<Value>`. The producing transition chooses the enum. The helper writes the snake-case signed field while preserving other kernel metadata. KERN-1 derives `retryable_after_resume` from `disposition == Reusable`; it never chooses Retained for a definite stop.

- [ ] Run the new evaluator controls on Original: malformed redaction leaves zero receipts after one actual invocation; caller `receipt_context` is accepted. Keep a successful one-receipt control.
- [ ] Add producing-row controls: early reusable denial, persisted compensated terminal, unknown submitted-commit retained denial, post-effect terminal, Allow and pending-approval exceptions. Include duplicate request ids in distinct authenticated namespaces.
- [ ] Implement the typed helper, reserve `receipt_context`, and derive namespace metadata from the existing authenticated replay binding. Do not classify by error text or infer Terminal from the verdict alone.
- [ ] Run focused identity tests. Expected: correct disposition and unchanged existing metadata; caller forgery denied before invocation. Commit the task without publishing the incomplete unit.

### Task 2: Make append acknowledgement explicit

**Files:** `kernel/responses/receipt_persistence.rs`, `kernel/responses/allow_responses.rs`, new `kernel/effect_obligation/publication.rs`, receipt-store fixtures in kernel tests.

**Interfaces:** Produce an internal publication result distinguishing `Refused`, `OutcomeUnknown { receipt_id }`, and `Committed { receipt_id }`. Only the post-effect obligation can consume the committed result into `Discharged`. Post-commit errors carry the original receipt id as `DeliveryFailedAfterReceipt`.

- [ ] Add a store fixture that commits then returns a timeout, plus a fixture whose queued append commits after timeout. Assert no replacement terminal is appended while original completion is unresolved.
- [ ] Separate the append acknowledgement from trace allocation, settlement observation, federation co-signing, provenance and nonce creation. Keep all existing ordering and authority checks before the append.
- [ ] Return post-commit delivery failures without re-entering fault-receipt construction. Unknown writes require completion/readback; unsupported authoritative readback keeps the obligation latched.
- [ ] Run publication, federation, settlement and nonce-focused controls. Expected: one persisted terminal id for every acknowledged/late commit. Commit.

### Task 3: Reserve and recover non-durable evidence

**Files:** New `kernel/effect_obligation/evidence.rs` and `recovery.rs`, kernel construction/struct fields, kernel dispatch admission checks, and hosted multi-kernel construction.

**Interfaces:** Produce move-only `EvidenceSlot`, `acquire_evidence_slot()`, `ensure_post_effect_evidence_latch_clear()`, bounded pending-record storage, and a supervised single-flight recovery owner. Recovery owns only the shared clock, signing and receipt-persistence resources it needs, never a borrowed kernel or a raw pointer.

- [ ] Add slot-exhaustion and shared-host two-slot/three-session controls. Assert refusal before invocation and permit retention while buffering.
- [ ] Add failing-clock/signer/store controls plus recovery while no new requests arrive. Assert cleanup and session reports remain usable while dispatch is latched.
- [ ] Implement fixed capacity, reserved-slot ownership, bounded fault templates, single-flight flushing with backoff and controlled shutdown. Preserve the original append identity until its outcome is settled.
- [ ] Add latch/dispatch and worker-exit races to existing concurrency tests. Run focused tests, including no-progress and recovery cases. Commit.

### Task 4: Own both evaluators through discharge

**Files:** New `kernel/effect_obligation.rs`, `evaluation/async_evaluation_core.rs`, `evaluation/nested_flow_evaluation.rs`, `evaluation/return_recording.rs`, `kernel_drop_guard.rs`, `security_dispatch.rs`.

**Interfaces:** `post_effect(obligation, returned) -> Discharged`; private discharge construction; `Discharged::deliver(self) -> Result<ToolCallResponse, KernelError>`. Ownership includes charge, admission, child receipts, security handles and the reserved evidence slot. Bind discharge to authenticated namespace, request id, operation id when present, and matched grant.

- [ ] Extend Originals across transport failures, child flush, credential commitment and durable return-recording failure. Retain the existing pre-dispatch compensation controls.
- [ ] Move the post-dispatch half of each evaluator under the obligation. Keep pre-dispatch Drop compensation unchanged. Durable Drop queues supervised reconciliation and never writes a competing receipt.
- [ ] Move `record_released` and final lifecycle release after discharge; signed terminal truth survives either callback failing. Contain callback and destructor panics.
- [ ] Add binding mismatch and compile-fail controls for forgeable/cloneable discharge and early return. Run evaluator failure matrix and existing durable/drop/security suites. Expected: one terminal owner, no premature release. Commit.

### Task 5: Preserve payment outcomes and qualify the whole unit

**Files:** `kernel/validation.rs`, `payment/types.rs`, owning payment tests, protocol receipt documentation and evidence inventories touched by source.

**Interfaces:** Settlement metadata records actual `release_outcome`; capture error records `not_released`, authorization identity and a stable error code, with an audit fault.

- [ ] Add a real evaluator control with a failing capture adapter: invocation happened, capture attempted, release was never attempted, positive authorization retained and terminal metadata truthful. Add rejected/non-settled release success/failure controls.
- [ ] Remove release on capture error; preserve the current denial of non-settled output. Resolve the spec's Pending/Captured open decision with Claude before changing that policy.
- [ ] Run the final post-effect matrix, durable admission, security dispatch, payment and receipt-focused suites, then strict owning Clippy. Reconcile touched formal-source anchors without claiming proof execution.
- [ ] Send exact source SHA, commands, outcomes and remaining acceptance to Claude. Rebase once on actual main, verify composition, then publish one KERN-2 PR.

## Progress

- `8202e93624`: five initial Original controls committed. No production edit; runtime result pending.
- Implementation awaits boundary review with Claude. Existing source/spec drift is recorded above; phase 2 escape-hatch tooling and full reservation-ledger conversion remain separate roadmap work.
