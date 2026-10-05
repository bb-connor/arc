# Design: post-effect discharge and typed reservations

- Status: PROPOSED (revision 3, re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:))
- Date: 2026-10-04
- Scope: apply the unrepresentable-defects design (Mechanisms A, C and D) to the post-effect region of the two kernel evaluators, on the surfaces that still run without durable admission. Type the per-evaluation reservation ledger, separating kernel-compensable holds from external commitments that have no compensator. Build the never-started Mechanism D escape-hatch gate. No new coordinator, participant, store schema or wire message.
- Owners: `chio-kernel` (evaluators, drop guard, credential reservation, security dispatch handles, receipt finalization), `xtask` (escape-hatch gate), work-profile installers (durability rule)
- Related: M: `docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md` (parent design); M: `docs/security/engineering-standard.md` rules 2.1, 2.3, 5.1 and 5.5; `2026-07-12-admission-operation-design.md`; M: `2026-09-07-caller-dispatch-commitment-design.md`; M: `docs/security/session-report-receipts.md`; `docs/adr/ADR-0013-async-receipt-durability.md`; `docs/adr/ADR-0019-kernel-delivery-contract.md`; R:/W: `docs/architecture/recoverable-agent-runtime/02-rust-design.md` and W: `implementation/p1`, `p4` and `p5` `OPERATIONS.md`; V: `2026-10-02-dynamic-delegation-design.md`; V: `2026-09-15-pre-settlement-execution-design.md`; `spec/PROTOCOL.md` section 6
- Citations:
  - `M:` = `origin/integration/process-security-m4` at `19df31ad9`.
  - `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac`.
  - `R:` = `origin/research/openappa-recovery-20261001` at `de84fc306` (recovery design documents).
  - `W:` = the uncommitted working tree of `standalone/arc-worktrees/recoverable-agent-runtime-20261002`: recovery P0-P5, built on the #1160 checkpoint `f25cd61f4`. Line references reflect that tree on 2026-10-04, may drift, and W: is treated as shipped.
  - Evaluator line numbers are identical on `M:` and `V:` unless stated. W1-W4 API names are contract anchors (assumed shipped).
- Origin: lessons from the FTL (nuta/ftl) review
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-closed-kernel-abi-design.md`, `2026-10-04-authority-faults-design.md`, `2026-10-04-authority-space-teardown-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-opaque-adapter-context-design.md`, `2026-10-04-microkernel-isolation-backend-design.md`

## Revision 3 changes

- **The recovery reservation is implemented, not a contract anchor.** It is `chio_process::RecoveryCallReservation` with `reserve_recovery_call` and `finalize_recovery_call` (W: `chio-process/src/recovery.rs:9`, `:83`, `:110`). It is re-cited in sections 2.5 and 4.3.
- **Two new `Commitment` kinds:** the recovery provider-lookup reservation (affine, at most 32 per workflow) and the recovery grant issuance reservation (`reserve_issuance`). Both are consumed and never refunded.
- **Rule 9 covers W:'s `RecoveryReleaseOwner`.** It holds the security lifecycle as a `SecurityRequestLifecyclePermit`, so it absorbs that permit like the other security handles. The owner runs only on the durable `Finalizing` path.
- **New precedents.**
  - Mechanism A: W:'s affine `PreparedArtifactRead`, `PreparedConfinedReturn` and `CapturedSemanticSubmissionV1`.
  - "Drop is hygiene": `LaunchCustody` and `ConfinedExecution`, whose best-effort `let _ =` quarantines join the Mechanism D allowlist.
- **Scope note.** P4 and P5 permanent consumption (retired artifact ids, confined-child reservations, release intents, pins) lives in durable control-plane runtimes, outside this spec's non-durable scope, under the same no-compensator rule.
- **Merge drift.** W: is built on an older base where the early disarm sits at `async_evaluation_core.rs:1751` (M: `:1740`). W: also edits `terminal.rs`, `security_release.rs` and `admission_coordinator.rs`. Evaluator line citations will move again when W: is rebased.

## Revision 2 changes

- **Re-baselined on the shipped security, process and work surfaces.** All evaluator citations now point at `M:`. The early disarm is still present at `M:`/`V:` `async_evaluation_core.rs:1740`, so the gap this spec closes is still real.
- **Repositioned as an application, not a new pattern.** The in-process token is a Mechanism A evidence token. `PostEffectError` is Mechanism C, and it carries `DispatchRejection` through the kernel seam, closing that design's RP2 finding on this path. The boundary check is the Mechanism D escape-hatch gate (RP6), built here with a shared allowlist, not a separate tool.
- **Renamed `TerminalEvidence` to `PostEffectDischarge`.** The old name collided with `ToolOutcomeTerminalEvidenceV1` and `PaymentTerminalEvidence`.
- **Drop restated as hygiene only.** Revision 1 said "Drop = compensate". That conflicts with R: (`02-rust-design.md:124`) and V: (`agentic-work-kernel-design.md:71`). `Drop` now only latches and requests reconciliation, and correctness comes from the saga, readback and the latch.
- **Ledger split into two entry classes.** `Compensable` entries are kernel holds the kernel may reverse before dispatch. `Commitment` entries are D1 sealed allocations, observed F1 escrow backing, process call slots, sibling shares and recovery reservations. Commitments have no compensator.
- **Scope narrowed.** Process calls and work profiles already require durable admission, so the uncovered region is limited to the MCP edge, the HTTP sidecar and direct embedders running `ReadOnly` tools under the default mode. The work-profile durability rule generalizes the shipped D1 precedent.
- **Release exits named.** `MutuallyAgreedUnknown` and `ContractualCaptureWaiver` are the only post-unknown hold releases. The latch and `fail()` never imply release.
- **New post-effect steps added.** `M:` adds fallible steps to the post-effect region: the security outcome `record_released()?` before finalization, `read_authority_time()?`, and recovery-status revalidation.
- **Dropped:**
  - the `AdmissionReservation::FaultResolution` entry, because authority-faults revision 2 moves single use to R: `reserve_recovery_call`, which is a `Commitment` here;
  - the standalone `xtask/src/post_effect_boundary.rs` and its own allowlist file;
  - "Drop = compensate";
  - merge-order open decision 5, because the security branch is now baseline.

## 1. Decision summary

FTL reserves fallibly so that its commit cannot fail. Chio already applies that rule where crash safety matters:
- `AdmissionOperation` commits `Prepared` before participants and `DispatchCommitted` before handoff.
- Process calls commit a call slot before the kernel call and retain it on failure (M: `chio-process/ARCHITECTURE.md:40-45`).
- Caller-executed delivery treats a reservation as preparation, never permission (M: caller dispatch commitment).

This design does not replace that machinery.

One region is still governed by convention: the code between "the tool returned" and "a terminal record exists" on calls without durable admission. Both evaluators disarm `PostAdmissionDropGuard` right after the credential commit, before the receipt is built (M: `async_evaluation_core.rs:1740`, `nested_flow_evaluation.rs:1495`). Several later steps fail with `?` and return a bare `KernelError`. The caller gets no output, so durable-before-allow holds, but an executed call has no audit record. This is the exact defect shape the unrepresentable-defects design names: "A correct primitive exists. Correctness depends on a convention about where it is called" (M: unrepresentable-defects `:21-22`).

The decision has five parts:

1. **Mechanism A.** A move-only `PostEffectObligation`, discharged only by a `PostEffectDischarge` token. Only a committed receipt append, a durable outcome record or a durable terminalization can construct the token.
2. **Mechanism C.** Post-effect errors have their own type, `PostEffectError`, with no `From` into `KernelError`. It wraps `DispatchRejection` where a rule fired. Its only exit is `PostEffectObligation::fail`, which records a signed fault response.
3. **Typed ledger.** `AdmissionReservations` replaces boolean cleanup flags. It has `Compensable` and `Commitment` entry classes, and an exhaustive match forces every new kind to choose one.
4. **Fail-closed latch.** If even the fault receipt cannot be persisted, the kernel buffers it and denies new dispatch at the existing readiness gate until the buffer drains.
5. **Mechanism D.** The escape-hatch gate (`cargo xtask check escape-hatches`) lands with this design. It holds every allowlisted bypass of the new types, plus the existing seven or eight named escape hatches, behind one ratcheted allowlist.

## 2. Verified current state

### 2.1 What already closes the gap

| Surface | Behavior | Evidence |
|---|---|---|
| Durable saga | Tool return recorded through `record_durable_tool_return`, then owned by `finalize_durable_tool_return_with_security_release`. A failed record leaves the operation `DispatchCommitted`, and recovery terminalizes it | M: `async_evaluation_core.rs:1896`, `:1944` |
| Process calls | `ProcessRuntime::open` requires durable admission for all calls. A call slot is committed before the kernel call and retained on failure | M: `chio-process/README.md:28`; `ARCHITECTURE.md:44` |
| Delegated work (D1) | Installation requires a durable store and sets `require_durable_request_retention`. A call whose effect class the mode does not cover is denied, not run ephemerally | V: `delegated_work.rs:44-49`; V: `kernel/admission_coordinator.rs:525-532`, `:559-569` |
| Execution evidence | `export_durable_execution_evidence` requires a Finalizing durable operation | V: `pre-settlement-execution-design.md:35` |
| Default mode | `DurableAdmissionMode::SideEffecting` is the default and does not cover `ReadOnly` | M: `admission_operation/identity.rs:368-390` |
| Move-only primitives | `BudgetChargeResult` (no `Clone`), one-time `ReceiptSigningHandle` | M: `kernel/mod.rs`; `chio-kernel-core/src/receipts.rs` |
| Evidence-token precedent | `ToolOutcomeTerminalEvidenceV1`, `PaymentTerminalEvidence` (durable saga) | M: `tool_outcome/release/terminal.rs:16`; `admission_operation/projection/participant_evidence.rs:207` |
| Affine custody precedents (W:) | `PreparedArtifactRead`, `PreparedConfinedReturn` and `CapturedSemanticSubmissionV1`: private construction, no `Clone` or `Deserialize`, with compile-fail doctests | W: `chio-control-plane/src/knowledge.rs:39`; `confinement.rs:38`; `semantic/connector.rs:25` |
| "Drop is hygiene" precedent (W:) | `LaunchCustody` and `ConfinedExecution` quarantine a confined child best-effort (`let _ =`) in `Drop`, never refund or release | W: `chio-control-plane/src/confinement/execution.rs:22-26`, `:270-277` |

### 2.2 The uncovered region on M:

After `mark_dispatch_started` (M: `async_evaluation_core.rs:1711`), these steps run in order on the non-durable path:

1. `outcome.record_released()?` for the security dispatch handle, **before finalization** (`:1727`). The security recorder can say `Released` for a call whose receipt is never written.
2. Credential commit, then `post_admission_drop_guard.disarm()` (`:1736-1740`). From here the guard's best-effort cancellation receipt in `Drop` (M: `kernel_drop_guard.rs:471`) is unreachable.
3. `revalidate_completed_recovery_status` and `self.read_authority_time()?` (`:1951`, `:1956`).
4. `finalize_ordinary_recovery_response` (`:1968`, defined at M: `evaluation_helpers.rs:219`). That function reaches:
   - stream limits and the post-invocation pipeline (M: `responses/finalization.rs:33`, `:40`);
   - receipt content (M: `responses/allow_responses.rs:69`) and receipt metadata (`:92`);
   - parameter hashing (`:106-108`) and signing (`:110-123`);
   - the append (`:125`), including the revocation re-check in persistence (M: `responses/receipt_persistence.rs:250`).
5. `SecurityRequestLifecycleHandle::finish_response` propagates a finalization error with `?` before ensuring final release (M: `security_dispatch.rs:121-130`).

By contrast, a revocation observed at `allow_responses.rs:53` correctly produces a signed deny-delivery receipt. The same shape exists in the nested-flow evaluator (M: `nested_flow_evaluation.rs:1404`, `:1495`).

On the durable path, a failed `record_durable_tool_return` tries to write a deny receipt and discards the result (`let _ =` at `async_evaluation_core.rs:1919`). That discard is harmless, because the saga row is the record. This design leaves the durable path's semantics unchanged.

### 2.3 Who is still exposed

- Hosts that call `ChioKernel` directly, through the MCP edge or the HTTP sidecar, with `ReadOnly` tools under the default mode.
- Development profiles with `allow_ephemeral_receipt_log`.

Process-hosted calls and work profiles are not exposed (section 2.1). A connection that misdeclares a mutating tool as `ReadOnly` is exposed on the first surfaces.

### 2.4 Hand-maintained bookkeeping

On M:, the evaluators maintain:
- 7 `PostAdmissionDropGuard` constructions;
- 15 `disarm()` calls;
- 43 `PreDispatchCleanupDeny {` sites;
- guard flags `armed`, `dispatch_started` and `budget_lease_acquired` (M: `kernel_drop_guard.rs:85-89`);
- credential flags `rollback_on_drop` and `retain_on_drop` (M: `credential_reservation.rs:71-72`).

This bookkeeping has already produced defects closed by runtime flags:
- RFC-0002 F02;
- holder-lease reference counting (`ad64e8f40`);
- verifier-only leases (`818d1c5c9`).

### 2.5 Reservation semantics elsewhere

Elsewhere, reservation means consumption:

| Reservation | Owner | Compensable by the kernel? |
|---|---|---|
| Process call slot | process journal | No. Retained on failure (M: `ARCHITECTURE.md:44`) |
| Sibling budget share | process journal | No. Retained after cancel (M: `ARCHITECTURE.md:23`) |
| Recovery call reservation | `RecoveryCallReservation` via `reserve_recovery_call` (W: `chio-process/src/recovery.rs:9`, `:83`) | No. Charged once before approval; `finalize_recovery_call` (`:110`) consumes it exactly once and refuses a changed continuation. "A later failure does not restore spent authority" (W: `implementation/p1/OPERATIONS.md:101`) |
| Recovery provider-lookup reservation | recovery authority store (`reserve_provider_lookup`, W: `chio-kernel/src/recovery/ports.rs:54`) | No. Affine, capped at 32 per workflow (W: `implementation/p1/OPERATIONS.md:114`) |
| Recovery grant issuance reservation | recovery authority store (`reserve_issuance`, W: `recovery/ports.rs:124`) | No. Consumed by grant v2 issuance |
| P4 and P5 consumption: retired artifact version ids, confined-child reservations, release intents, permanent pins | durable control-plane runtimes over process calls | No. These run on durable paths, outside this spec's non-durable scope; the same no-compensator rule applies |
| D1 subdivision and sealed allocation | remote allocator | No. "no reset, timeout refund ... or release of sealed allocations" (V: `dynamic-delegation-design.md:40-41`, `:86-87`) |
| F1 escrow backing | chain escrow | No. The receiver only observes backing before dispatch; budget and chain are not one transaction (V: `sections/03-contract.tex:94-102`; V: `PROTOCOL.md:63`) |
| Invocation and monetary holds, runtime admission, child budget lease, dispatch credentials | kernel stores | Yes, before `DispatchCommitted` |

### 2.6 Release authority

`PaymentReleaseAuthorityKind` (V: `payment/journal.rs:88-96`) has five kinds:
- `PreDispatchNoEffect`, `TransportNotAccepted` and `ContractualZeroCharge` are no-effect or zero-charge exits.
- `MutuallyAgreedUnknown` and `ContractualCaptureWaiver` are the only releases after an unknown terminal. The first "never establishes that execution had no effect" (V: `payment/unknown_release.rs:1-4`).

## 3. Goals and non-goals

### Goals

- Make leaving the post-effect region without a discharge a compile error, except through `fail`, which records a signed fault.
- Make the existence of a ledger entry, rather than a boolean, the thing that authorizes compensation or retention. Make double compensation a move error. Make it impossible to compensate a `Commitment`.
- Move every dispatch-independent receipt input before the effect boundary.
- Bound the window of unrecorded effects when the receipt writer itself has failed.
- Land the Mechanism D gate, so every escape hatch these types need is counted from day one.

### Non-goals

- Making I/O infallible. Here "infallible commit" means "cannot fail silently".
- Changing `AdmissionOperationV1` states, `BudgetStore` signatures, process journal semantics, D1 or F1 rules, or any store schema.
- Pre-reserving receipt-log sequence numbers or capacity (section 10).
- Crash-safe recording for non-durable calls. The remedy for crash safety is durable coverage.
- Changing `chio-kernel-core`.
- Caller-executed delivery, which M:'s start/report handshake owns. `AdmissionReservations` must never issue external execution permission.
- Pre-invocation refusals that leave no receipt (ledger item EV3). They are adjacent but out of scope.

## 4. Design

### 4.1 Mapping onto unrepresentable-defects

| Mechanism (M: unrepresentable-defects) | Here |
|---|---|
| A, evidence token (`:97`): private fields, no `Default`, no `Deserialize`, one constructor that is the check | `PostEffectDischarge`, constructed only by the three recording functions in rule 7 |
| C, structured rejection (`:370`): one variant per rule, causes preserved, registered codes | `PostEffectError { step, cause }`. When a rule fired, the cause is `DispatchRejection` (closes RP2 on this seam, `:513`) |
| D, escape-hatch gate (`:440`): ratcheted allowlist, fails on a new hatch | `cargo xtask check escape-hatches` (section 5) |
| Engineering standard 2.3 (typestate where it removes an omission class) | `AdmissionReservations` and then `PostEffectObligation` |

### 4.2 Typestate

```text
AdmissionReservations::open --reserve (fallible, pre-dispatch)--> AdmissionReservations
   |                                                    |
   | compensate_before_dispatch(self)                   | enter_effect_boundary(self)
   v                                                    v   (fallible; failure compensates)
CleanupReport                                    PostEffectObligation
(fault receipt iff a step failed)                  |                         |
                                    discharge(self, PostEffectDischarge)   fail(self, PostEffectError)
                                                   v                         v
                                                  ()                 signed fault response,
                                                                     or buffered record + latch

Drop(AdmissionReservations) = latch + request reconciliation (no compensation)
Drop(PostEffectObligation)  = best-effort fault receipt, else latch (never release)
```

### 4.3 `AdmissionReservations`

```rust
#[must_use = "reservations must be compensated or carried across the effect boundary"]
pub(crate) struct AdmissionReservations<'k> {
    kernel: &'k ChioKernel,
    request: &'k ToolCallRequest,
    entries: Vec<AdmissionReservation<'k>>, // acquisition order
    durable_operation: Option<&'k AdmissionOperationV1>,
}

pub(crate) enum AdmissionReservation<'k> {
    Compensable(CompensableReservation<'k>),
    Commitment(ExternalCommitment),
}

pub(crate) enum CompensableReservation<'k> {
    InvocationIncrement { grant_index: usize },
    InvocationHold(BudgetChargeResult),
    MonetaryCharge { charge: BudgetChargeResult, payment: Option<PaymentAuthorization> },
    ChildBudgetLease,
    RuntimeAdmission { reserved_ids: Vec<String> },
    DispatchCredentials(DispatchCredentialReservation<'k>),
}

/// A precondition the kernel checked but cannot reverse. Carried for
/// retention markers and receipts; never compensated.
pub(crate) enum ExternalCommitment {
    DelegatedAllocation { slot_id: String, permit_digest: Digest32 },  // D1 sealed
    ObservedEscrowBacking { escrow_id: String, observation_digest: Digest32 }, // F1
    ProcessCallSlot { process_id: String, operation_key: String },
    RecoveryReservation { continuation_id: String },                  // W: RecoveryCallReservation
    RecoveryProviderLookup { workflow_id: String },                   // W: reserve_provider_lookup
    RecoveryGrantIssuance { workflow_id: String },                    // W: reserve_issuance
}
```

Rules:

1. An entry is pushed in the same expression that consumes the successful reservation or verified observation. No code tests a boolean to decide whether a reservation exists. `budget_lease_acquired` and the `PreExecutionBudgetMutation` variants are replaced by entry presence.
2. `compensate_before_dispatch(self) -> CleanupReport` does two things:
   - It runs the current unwind order of `handle_pre_dispatch_drop` (M: `kernel_drop_guard.rs:235`) over `Compensable` entries only: monetary unwind, invocation reversal, runtime-admission release, child-lease release, then durable compensation only if every earlier step succeeded. Failures go into the existing `pre_dispatch_cleanup_faults` receipt (`:442`).
   - It records `Commitment` entries in the cleanup receipt as `retained_external` and never acts on them.
3. `PreDispatchCleanupDeny` takes `AdmissionReservations` by value instead of a field list. A denial builds its receipt after compensation.
4. `enter_effect_boundary(self) -> Result<(PostEffectObligation<'k>, RetainedReservations), PreDispatchFailure>` runs today's fallible boundary steps (`retain_if_dropped`, `commit_durable_dispatch` / `capture_and_commit_durable_dispatch`). On failure it compensates and returns the report. On success it moves every entry into `RetainedReservations`, which post-effect paths read to stamp retained markers and which nothing can release.
5. Every `match` over `AdmissionReservation`, `CompensableReservation` and `ExternalCommitment` is exhaustive, under `#[deny(clippy::wildcard_enum_match_arm)]`. A new kind cannot compile without choosing its class. A `Commitment` has no compensator to write.
6. `Drop` on an unconsumed `AdmissionReservations` performs no durable compensation. Per R: `02-rust-design.md:124` and V: `agentic-work-kernel-design.md:71`, `Drop` cannot refund, certify no effect or perform a critical durable transition, and `mem::forget`, abort and shutdown must stay safe. It does two things only:
   - sets the latch (section 4.8) when no durable operation covers the call, because an unconsumed ledger is a bug path;
   - schedules the existing reconciliation (durable operations are recovered by the saga; non-durable holds by the existing restart reserved-hold gate and expired-hold reaper).

### 4.4 `PostEffectObligation` and `PostEffectDischarge`

```rust
#[must_use = "a possible side effect must end in a discharge or a recorded fault"]
pub(crate) struct PostEffectObligation<'k> {
    kernel: &'k ChioKernel,
    request: &'k ToolCallRequest,
    retained: RetainedReservations,
    receipt_inputs: PreparedReceiptInputs,
    child_receipts: Vec<ChildRequestReceipt>,
    security_outcome: Option<SecurityDispatchOutcomeHandle>,
    security_lifecycle: Option<SecurityRequestLifecycleHandle>,
    durable_operation: Option<&'k AdmissionOperationV1>,
}

/// Mechanism A token. Private fields, no Default/Clone/Deserialize; constructed
/// only inside `effect_obligation.rs` by the functions in rule 7.
pub(crate) struct PostEffectDischarge(DischargeKind);
enum DischargeKind {
    ReceiptCommitted { receipt_id: String },
    DurableOutcomeRecorded { operation_id: AdmissionOperationId },
    AdmissionTerminalized { operation_id: AdmissionOperationId },
}

impl PostEffectObligation<'_> {
    pub(crate) fn discharge(self, token: PostEffectDischarge);
    pub(crate) fn fail(self, error: PostEffectError) -> Result<ToolCallResponse, KernelError>;
}
```

Rules:

7. Only these functions construct `PostEffectDischarge`, each on `Ok`:
   - `record_chio_receipt*` constructs `ReceiptCommitted`;
   - `record_durable_tool_return` constructs `DurableOutcomeRecorded`, after which the saga and `finalize_durable_tool_return_with_security_release` own the rest;
   - `terminalize_dispatch_committed_admission` constructs `AdmissionTerminalized`.

   `DurableOutcomeRecorded` wraps the operation id. It does not duplicate `ToolOutcomeTerminalEvidenceV1`, which remains the saga's evidence.
8. The obligation is minted only by `enter_effect_boundary`. It replaces `mark_dispatch_started`, `disarm`, `mark_dispatch_credential_commit_failed` and `mark_durable_operation_terminalized`. Finalization returns `(ToolCallResponse, PostEffectDischarge)`, and the evaluator discharges only after the append returns. This removes the early disarm at M: `async_evaluation_core.rs:1740` and `nested_flow_evaluation.rs:1495`.
9. The obligation absorbs both security handles:
   - `SecurityDispatchOutcomeHandle::record_released` runs only inside `discharge`, after the token exists. Today it runs before finalization (`:1727`).
   - A `fail` records `record_outcome_unknown_after_dispatch` (M: `security_dispatch.rs:64`).
   - `SecurityRequestLifecycleHandle::finish_response` consumes the discharged response, so a finalization error cannot skip final release (`:121-130`).
   - The rule is stated over `SecurityRequestLifecyclePermit`, so it covers W:'s `RecoveryReleaseOwner` (W: `kernel/admission_coordinator/security_release/recovery.rs:8-12`). That owner refuses release without the original guarded output, and runs only on the durable `Finalizing` path, so on that path discharge is `DurableOutcomeRecorded`. It never enters the non-durable region.
10. Buffered nested child receipts move from the guard into the obligation, keeping the RFC-0002 flush-first order.
11. `Drop` on an undischarged obligation, for example a panic (M: `Cargo.toml:344` is `panic = "unwind"`), attempts the existing best-effort cancellation receipt with retained markers. If that fails, it sets the latch with an unsigned `PostEffectFaultRecord`. It never releases a hold, never refunds and never terminalizes a durable operation; durable operations are reconciled by the saga.

### 4.5 `PostEffectError` (Mechanism C)

```rust
#[must_use]
#[derive(Debug, thiserror::Error)]
pub(crate) enum PostEffectError {
    #[error("post-effect step {step:?} refused")]
    Rejected { step: PostEffectStep, #[source] cause: DispatchRejection },
    #[error("post-effect step {step:?} failed")]
    Failed { step: PostEffectStep, #[source] cause: KernelError },
}
pub(crate) enum PostEffectStep {
    CredentialCommit, SecurityRelease, AuthorityTime, RecoveryRevalidation,
    StreamLimits, PostInvocation, ReceiptContent, Signing, Append, Revoked,
}
// Deliberately absent: impl From<PostEffectError> for KernelError.
```

Rules:

12. Every function that runs while an obligation is live returns `Result<_, PostEffectError>`. The evaluators return `KernelError`, so `?` on a `PostEffectError` does not compile there. The only conversion is `fail`.
13. `fail` records a signed terminal response synchronously:
    - `CredentialCommit` keeps today's `POST_DISPATCH_CREDENTIAL_COMMIT_FAILURE_REASON` cancellation receipt.
    - `PostInvocation` errors are treated as a block: a deny-delivery receipt with retained markers, matching the blocked-output arm (M: `finalization.rs:43`).
    - `Revoked` (persistence re-check, M: `receipt_persistence.rs:250`) produces a deny-delivery receipt, matching `allow_responses.rs:53`.
    - Every other step records a cancellation receipt with `chio_runtime.post_effect_fault = { step, code, retained_ids }`. `code` is the registered code of the `DispatchRejection` or kernel error.

    The fault receipt deliberately differs from M:'s session-report `trace_observation` (M: `session-report-receipts.md:16-24`). A session report records a host's claim and carries no decision. Here the kernel itself observed the tool's return and decided to withhold delivery, so it signs a decision receipt. Where the kernel cannot tell whether the tool executed (`CredentialCommit` after an ambiguous dispatch error), the metadata carries `execution_outcome: "unknown"` with the same meaning as the session report (`:36-40`).

### 4.6 Hoisted receipt inputs

14. Before `enter_effect_boundary`, the evaluator builds `PreparedReceiptInputs`:
    - request receipt metadata (M: `allow_responses.rs:92`);
    - the parameter hash (`:106-108`);
    - attribution metadata;
    - memory action classification;
    - the authority-time read currently at `async_evaluation_core.rs:1956`, taken once, before the boundary.

    A failure here is a pre-dispatch failure, so it compensates and denies. After the effect, the fallible set shrinks to recovery revalidation, stream limits, post-invocation guards, output canonicalization, signing and append.

### 4.7 Post-receipt steps

15. After `ReceiptCommitted`, the obligation is discharged and terminal truth is fixed. A memory-provenance append failure (M: `allow_responses.rs:141`) or a nonce-mint failure (`:150`) returns `KernelError::DeliveryFailedAfterReceipt { receipt_id, step }`, so caller and operator can reconcile against the committed receipt.

### 4.8 Fail-closed latch

16. When `fail` or `Drop` cannot persist its fault receipt and no durable operation covers the call:
    - the kernel pushes the signed receipt, or an unsigned `PostEffectFaultRecord` if signing failed, into a bounded `unrecorded_post_effect_receipts` buffer (capacity 256);
    - it sets `post_effect_fault_latched` at the failure point;
    - it emits `audit_fault`.
17. While latched, `ensure_receipt_persistence_ready` (M: `construction.rs:470`) returns `Err`. Every new evaluation takes the existing signed persistence deny (M: `async_evaluation_core.rs:160`). The check attempts a flush and clears the latch only when the buffer is empty.
18. The buffer can grow only from evaluations already past the gate, which is bounded by in-flight concurrency. Records beyond capacity are dropped, each with `audit_fault`. That is the only accepted silent-loss path.

### 4.9 Work-profile durability rule

19. Every work-profile installer must reuse the D1 precedent:
    - the delegated-work guard (V: `delegated_work.rs:44-49`);
    - the W1 work service, the W2 owner services and funded (F1) composition (contract anchors).

    Each one must refuse installation without a qualified durable admission store and must call `require_durable_request_retention`. With retention required, a call whose effect class the mode does not cover is denied, not run ephemerally (V: `admission_coordinator.rs:559-569`). The post-effect region of a work call is therefore always owned by the saga.

### 4.10 Release exits

20. No path in this design releases a hold. `compensate_before_dispatch` releases only `Compensable` entries, and only before `DispatchCommitted`. After an unknown terminal, the only hold releases are `MutuallyAgreedUnknown` and `ContractualCaptureWaiver` (V: `payment/journal.rs:88-96`), and both are separately authorized. Neither `fail`, `Drop`, the latch nor flush may construct a release.

### 4.11 Safety predicates

```text
entered_effect_boundary(e) ->
    exactly_one_of(
      receipt_committed(e), durable_outcome_recorded(e), admission_terminalized(e),
      post_effect_fault_receipt_committed(e),
      post_effect_fault_buffered(e) and latched)

latched -> not admits_dispatch(any new evaluation)

compensated(r) -> not entered_effect_boundary(r)
forall entry in Commitment: never compensated(entry)
forall entry: compensated_at_most_once(entry)            (move semantics)

security_released(e) -> discharged(e)
release_hold(op) after unknown(op) ->
    authority(op) in {MutuallyAgreedUnknown, ContractualCaptureWaiver}
work_profile_installed -> forall call: durable_admission(call) or denied(call)
```

## 5. Mechanism D gate: `cargo xtask check escape-hatches`

This is the gate M: unrepresentable-defects specifies (`:440-452`) and never built (RP6, `:516`). It is modeled on `xtask/src/adapter_no_bypass.rs` and is syn-based on the stable toolchain.

1. The allowlist is `formal/escape-hatches.toml`. Each entry has `path`, `item`, `kind` and `reason`. The initial entries are:
   - the existing named hatches (`for_test` x2, `from_raw`, `from_trusted_selection`, `from_trusted_context`, the Kani `assume_*` helpers, and the eighth found by RP6);
   - the durable `let _ =` discard at M: `async_evaluation_core.rs:1919`;
   - W:'s best-effort quarantine discards in `LaunchCustody::drop` and `ConfinedExecution::drop` (W: `confinement/execution.rs:26`, `:277`), which are hygiene and never authority.
2. In `chio-kernel`, outside `effect_obligation.rs`, the gate denies:
   - `impl From<PostEffectError>`;
   - `map_err` closures that discard a `PostEffectError` into `KernelError`;
   - `mem::forget`, `ManuallyDrop` or `Box::leak` applied to `PostEffectObligation` or `AdmissionReservations`;
   - `let _ =` bindings of `record_chio_receipt*` or `build_*_response*` results.
3. Workspace-wide, it denies any new function matching the escape-hatch naming families (`for_test`, `from_stored`, `from_raw`, `into_raw_*`, `from_trusted_*`) not on the allowlist.
4. A ratchet: the allowlist may shrink without review, and growth edits a CODEOWNERS-protected file. It has a self-test with a violating fixture per rule.
5. Sibling specs register their own allowlists here rather than inventing new ones, for example `2026-10-04-closed-kernel-abi-design.md` `handle_export` and `test_support` entries.

The gate inherits the hardening toolchain's GT1 limitation (hardening gates not yet in hosted CI). It lands in `scripts/ci-pr-tier.sh` in the same PR.

## 6. Failure modes

| Point of failure | Today (M:) | With this design |
|---|---|---|
| Future dropped before dispatch | guard compensates | ledger `Drop` latches and schedules reconciliation; the explicit `compensate_before_dispatch` path is used by every non-panic exit |
| Boundary step fails | per-site cleanup | `enter_effect_boundary` compensates `Compensable` entries and denies |
| Security `record_released` fails before finalization | `?` with guard armed | cannot happen early: release is recorded inside `discharge` |
| Credential commit fails after tool `Ok` | ambiguous receipt from guard `Drop` | `fail(CredentialCommit)`, synchronous |
| Authority time or recovery revalidation fails | bare `Err`, no receipt | `fail`, cancellation receipt (time read hoisted pre-boundary where possible) |
| Post-invocation error | bare `Err`, no receipt | deny-delivery receipt, retained markers |
| Revocation seen at persistence | bare `Err`, no receipt | deny-delivery receipt |
| Canonicalization, signing or append fails (non-durable) | bare `Err`, no receipt | fault receipt, else buffer and latch |
| Same failure, durable or work profile | saga recovers | unchanged; no latch |
| Post-receipt provenance or nonce failure | bare `Err` | `DeliveryFailedAfterReceipt { receipt_id }` |
| Panic in the post-effect region | guard `Drop` only if still armed | obligation `Drop`: best-effort receipt, else latch |
| Process crash, non-durable post-effect | unrecorded | unrecorded (residual; use durable coverage) |

## 7. Protocol, schema and wire impact

- `spec/PROTOCOL.md` section 6 gains one sentence: a call that reached the effect boundary without durable admission yields its terminal receipt or a cancellation receipt carrying `chio_runtime.post_effect_fault`.
- One optional receipt metadata object, `chio_runtime.post_effect_fault`. It needs no registry change, because `chio_runtime` keys are not registry-scoped.
- `PostEffectError` codes come from the `chio-errors` registry, which also advances the design's one-registry goal (CA7).
- Some calls that returned a bare error now return a signed `Deny` or `Cancelled` response. `DeliveryFailedAfterReceipt` is a new Rust API variant.
- No negotiation. Receipts stay valid under v1 verifiers.

## 8. Rollout

1. **Obligation and token.** Add `effect_obligation.rs`, port the post-dispatch half of `PostAdmissionDropGuard` at both `mark_dispatch_started` sites, move the security release into `discharge`, and remove the early disarm (rules 7-11). This fixes section 2.2.
2. **Mechanism C and D.** Add `PostEffectError`, the `fail` mapping, the persistence revocation change, and `cargo xtask check escape-hatches` with its initial allowlist.
3. **Ledger.** `AdmissionReservations` with both entry classes. Replace `PreDispatchCleanupDeny` field lists and the remaining guard flags (rules 1-6).
4. **Hoisting, post-receipt rule, work-profile rule.** Rules 14, 15 and 19.
5. **Latch.** Rules 16-18.

Following the RFC-0002 precedent, each phase ships as the only behavior. Behavior under durable admission is unchanged.

## 9. Tests and conformance evidence

- **Compile-fail** (rustdoc `compile_fail`, per M: unrepresentable-defects acceptance), each pinning its failure reason:
  - `?` on `PostEffectError` in a `KernelError` function;
  - `PostEffectObligation` is not `Clone`;
  - `PostEffectDischarge` cannot be constructed outside its module;
  - double compensation;
  - compensating an `ExternalCommitment`.
- **Proptest.** Extend `kernel/tests/drop_guard_proptest.rs` over {failing post-effect step} x {durable, non-durable, work profile} x {drop, return}. Assert the section 4.11 predicates against the receipt store, the latch and the security recorder.
- **DST.** Add `CrashBoundary::FailAppendAfterDispatch` to `tests/dst/support/durability_scenarios.rs` and a seed in `tests/dst/seeds.toml`.
- **loom.** Latch-set races readiness checks in `tests/loom_concurrency.rs`. A check ordered after the set must deny.
- **Unit:**
  - each `fail` step produces its decision, metadata and registered code;
  - the security outcome records `Released` only after discharge;
  - the ledger unwind order equals `handle_pre_dispatch_drop`;
  - work-profile installers refuse without durable coverage.
- **Gate.** One violating fixture per section 5 rule; the allowlist passes.
- **Mutation.** Per engineering standard rule 10.2: removing the discharge check, or moving `record_released` before finalization, must fail a named test.
- **Unchanged:** reservation law (`tests/property_reservation_ledger.rs`, `kernel/ledger_audit.rs`).
- **chio-conformance** `post_effect_receipt_fault`: a `ReadOnly` call whose append fails after dispatch yields a fault receipt or a latched deny on the next call, never a silent success.

## 10. Alternatives considered

- **Pre-reserve a receipt-log slot.** Rejected:
  - it moves the post-effect write instead of removing it;
  - void records for denied calls create gaps that ADR-0013 treats as audit faults;
  - it adds a pre-dispatch fsync to read-only calls.

  Revisit when ADR-0013's WAL lands.
- **Default `DurableAdmissionMode::All`.** It closes the crash window too, at about 40 durable writes and 11 authority commits per mediated call (M: `AGENT_PROCESS_DIRECTION.md:150-166`). That is left to open decision 1. This design is still needed under `All`, because rules 1-6 and 12-13 harden the durable evaluator too.
- **A generic participant trait over stores.** Rejected as a parallel abstraction; the admission design owns store contracts.
- **`trace_observation` for post-effect faults.** Rejected; see rule 13.

## 11. Residual risks and open decisions

Residual risks:

- Rust types are affine. The gate covers the obvious spellings of `forget` and leaks, not every one.
- A crash in the non-durable post-effect region stays unrecorded. The latch buffer is in memory.
- While latched, the buffer drops records beyond 256, each with `audit_fault`.
- A connection that misdeclares a mutating tool as `ReadOnly` still avoids durable admission outside work and process profiles.
- GT1: the gate is local-only until the hardening gates run in hosted CI.
- W: is built on the older #1160 checkpoint `f25cd61f4`, where the early disarm sits at `async_evaluation_core.rs:1751`. Its edits to `terminal.rs`, `security_release.rs` and `admission_coordinator.rs` will move every evaluator citation here when it is rebased onto M: head. Re-pin before implementing.

Open decisions:

1. **Default mode outside work and process profiles.** Should production profiles of the MCP edge and HTTP sidecar default to `All`? Recommendation: measure with the kernel bench first.
2. **Buffer durability.** Back the latch buffer with the ADR-0013 WAL once it exists? Recommendation: yes.
3. **Post-receipt failures.** Add a supplemental signed incident receipt linked to the allow receipt, beyond `DeliveryFailedAfterReceipt`?
4. **Directive pushback, recorded.** The revision 2 directive asked for a new rule that work profiles require durable admission. The evidence shows D1 already enforces it, fail-closed (V: `delegated_work.rs:44-49`; `admission_coordinator.rs:525-532`, `:559-569`). Rule 19 therefore generalizes the shipped mechanism to the other installers rather than adding a new one. Whether W1 and W2 reuse `install_delegated_work_with_layout`'s check directly or a shared helper is open.
5. **Escape-hatch naming families.** Is the workspace-wide family rule (section 5 item 3) too broad for the first ratchet? It could start scoped to TCB crates (`chio-kernel`, `chio-kernel-core`, `chio-core-types`, `crates/security/*`).

## Appendix A. FTL reference

What FTL does (paths relative to the FTL checkout):

- `ReserveSlot` (`libs/ftl_utils/src/reserve_slot.rs:10-13`) returns a `#[must_use]` `Slot` (`:17`) after `try_reserve(1)`, and `Slot::push` (`:31`) cannot fail.
- Kernel mutations reserve before committing:
  - handle insertion (`kernel/src/hspace.rs:52`, `:105`);
  - poll enqueue (`kernel/src/poll.rs:58`);
  - waiter registration (`:112`);
  - thread subscriptions (`kernel/src/thread.rs:121`);
  - mappings (`kernel/src/vmspace.rs:162`).
- Scheduler capacity is reserved in `Thread::new` (`kernel/src/thread.rs:90`) and released in `Drop` (`:291`).
- `sys_thread_create` closes the new thread if handle insertion fails (`:319`).

Where the analogy breaks:

- **What commit means.** FTL's commit is an in-memory push into held capacity, so it truly cannot fail. Chio's commits are durable writes, so the Chio equivalent is "cannot fail silently".
- **Drop.** FTL's `Drop` releases capacity it fully owns, under `panic = "abort"` (`Cargo.toml:26`, `:29`). Chio's reservations span stores, allocators and chains, so `Drop` may only latch and request reconciliation (rule 6). Some Chio reservations (`ExternalCommitment`) have no owner the kernel could release them to at all.
- **Ownership.** FTL's reservations live under one spinlock. Chio's ledger is only the in-process view of reservations whose truth lives in the stores.
