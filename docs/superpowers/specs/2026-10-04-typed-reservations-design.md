# Design: post-effect discharge and typed reservations

- Status: PROPOSED (revision 4, 2026-10-05, after adversarial review; revision 3 re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:))
- Date: 2026-10-04 (revised 2026-10-05)
- Scope: apply the unrepresentable-defects design (Mechanisms A, C and D) to the post-effect region of the two kernel evaluators, on every path that runs without durable admission (`durable_admission` is `None`, whatever the mode). Type the per-evaluation reservation ledger, separating kernel-compensable holds from entries that must be retained. Own the latch vocabulary that specs 4, 9 and 10 use. Build the never-started Mechanism D escape-hatch gate. Phase 1 is the D1 bug fix on the legacy evaluator. Later phases are re-specified against spec 9's phase 4 drivers (section 4.12). No new coordinator, participant, store schema or wire message.
- Owners: `chio-kernel` (evaluators, drop guard, credential reservation, security dispatch handles, receipt finalization, monetary finalization), `xtask` (escape-hatch gate), work-profile installers (durability rule)
- Related: M: `docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md` (parent design); M: `docs/security/engineering-standard.md` rules 2.1, 2.3, 5.1 and 5.5; `2026-07-12-admission-operation-design.md`; M: `2026-09-07-caller-dispatch-commitment-design.md`; M: `docs/security/session-report-receipts.md`; `docs/adr/ADR-0013-async-receipt-durability.md`; `docs/adr/ADR-0019-kernel-delivery-contract.md`; R:/W: `docs/architecture/recoverable-agent-runtime/02-rust-design.md` and W: `implementation/p1`, `p4` and `p5` `OPERATIONS.md`; V: `2026-10-02-dynamic-delegation-design.md`; V: `2026-09-15-pre-settlement-execution-design.md`; `spec/PROTOCOL.md` section 6
- Citations:
  - `M:` = `origin/integration/process-security-m4` at `19df31ad9`.
  - `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac`. `V2:` = the same branch at `acf34b074` (the current #1173 head), cited where its payment rules changed after `V:`.
  - `R:` = `origin/research/openappa-recovery-20261001` at `de84fc306` (recovery design documents).
  - `W:` = the uncommitted working tree of `standalone/arc-worktrees/recoverable-agent-runtime-20261002`: recovery P0-P5, built on the #1160 checkpoint `f25cd61f4`. Line references reflect that tree on 2026-10-04, may drift, and W: is treated as shipped.
  - Evaluator line numbers are identical on `M:` and `V:` unless stated. Unprefixed kernel paths are under M: `crates/kernel/chio-kernel/src/`. W1-W4 API names are contract anchors (assumed shipped).
- Origin: lessons from the FTL (nuta/ftl) review
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-closed-kernel-abi-design.md` (spec 1), `2026-10-04-authority-faults-design.md` (spec 2), `2026-10-04-authority-space-teardown-design.md` (spec 4), `2026-10-04-unified-event-queue-design.md` (spec 5), `2026-10-04-opaque-adapter-context-design.md` (spec 6), `2026-10-04-microkernel-isolation-backend-design.md` (spec 7), `2026-10-04-durable-stop-epoch-design.md` (spec 8), `2026-10-04-pure-admission-machine-design.md` (spec 9), `2026-10-04-crossing-primitive-design.md` (spec 10), `2026-10-04-integrity-gated-admission-design.md` (spec 11)

## Revision 4 changes

Revision 4 applies the adversarial review of revision 3 (26 findings: 3 Blocker, 13 Major, 8 Minor, 2 Nit). The disposition of each finding is in the review disposition section at the end.

- **Pre-dispatch drop compensates again (S3-01).** An unconsumed ledger is type-level proof that the effect boundary never ran. `Drop` keeps M:'s best-effort pre-dispatch compensation and never latches (rule 6).
- **Unconfirmed dispatch commits never compensate (S3-02).** `enter_effect_boundary` returns `BoundaryFailure::{RejectedBeforeCommit, CommitUnconfirmed}`, matching M:'s split (rule 4).
- **One latch vocabulary (S3-03, S3-04).** `LatchScope::{KernelEvidence, Operation, SessionRequest}` replaces the single kernel-wide latch. Only unpersisted post-effect evidence closes the kernel. That latch has its own gate at new-dispatch admission, a single-flight flusher, and readiness reporting. It never gates compensation, terminal-receipt recovery or session reports (section 4.8).
- **Discharge is bound and minted at the commit point (S3-05, S3-06).** The obligation's consuming `commit_terminal_receipt` mints `Discharged` right after the append returns `Ok`. It checks the request, operation and decision. A timed-out append is `AppendOutcomeUnknown` and is resolved by read-back before any fault receipt (rules 7 and 28).
- **Post-receipt steps are fallible and named (S3-07).** Security release, final release, trace allocation, federation co-sign, the settlement claim, provenance and nonce minting run after the receipt. They fail as `DeliveryFailedAfterReceipt` (section 4.7).
- **Full post-effect inventory (S3-08).** The inventory now covers transport-failure arms, session bookkeeping, the child-receipt flush, URL-elicitation cancellation, budget reconcile and payment settlement. The two discarded payment releases are classified (rule 27).
- **The region is a function that returns `Discharged` (S3-09).** Neither `?` on `KernelError` nor an early return type-checks inside it (rule 12).
- **Mechanism C cause corrected (S3-10).** `PostEffectRejection` replaces `DispatchRejection`, and `PostEffectError` is opaque. The RP2 claim is withdrawn.
- **Retained before dispatch (S3-11).** `ledger.retain(slot, cause)` covers credentials after an acknowledged external authorization and an unconfirmed invocation capture (rule 22).
- **Ledger entries are tokens (S3-12).** Each entry has a private constructor, no `Clone`, and is returned only by its acquiring function (rule 21).
- **Ownership that compiles (S3-13).** The obligation owns the durable admission and the charge. Finalization uses a private `into_parts` inside `effect_obligation.rs`.
- **No stranded request ids (S3-14).** A post-dispatch drop of a durable future enqueues supervised reconciliation (rule 23).
- **Division with specs 9 and 10 (S3-15).** Spec 9 decides, spec 10 executes, and spec 3 owns the affine driver contract, the latch, the post-effect error types, the ledger and the gate (section 4.12).
- **Exposure corrected (S3-16).** `Monetary` and development `Off` run mutating tools without durable admission. The obligation and latch apply whenever `durable_admission` is `None` (rule 26).
- **Minor and Nit fixes (S3-17 to S3-26).**
  - Hoisting is limited to dispatch-independent inputs.
  - `RecoveryRevalidation` is removed.
  - The recovery and process commitments move to a non-normative table.
  - The gate is specified for a syn implementation.
  - The durable discard stops writing a contradictory `Deny` receipt (rule 25).
  - The `fail` contract is specified per case.
  - `Drop` work runs under `catch_unwind` (rule 24).
  - Rule 19 states its read-denial side effect.
  - Cross-references and counts are corrected.

## Revision 3 changes

- **The recovery reservation is implemented, not a contract anchor.** It is `chio_process::RecoveryCallReservation` with `reserve_recovery_call` and `finalize_recovery_call` (W: `chio-process/src/recovery.rs:9`, `:83`, `:110`). It is re-cited in section 2.5.
- **Two new consumption kinds:** the recovery provider-lookup reservation (affine, at most 32 per workflow) and the recovery grant issuance reservation (`reserve_issuance`). Both are consumed and never refunded. Revision 4 moves them out of the ledger enum (S3-19).
- **Rule 9 covers W:'s `RecoveryReleaseOwner`.** It holds the security lifecycle as a `SecurityRequestLifecyclePermit`, so it absorbs that permit like the other security handles. The owner runs only on the durable `Finalizing` path.
- **New precedents.**
  - Mechanism A: W:'s affine `PreparedArtifactRead`, `PreparedConfinedReturn` and `CapturedSemanticSubmissionV1`.
  - "Drop is hygiene": `LaunchCustody` and `ConfinedExecution`, whose best-effort `let _ =` quarantines live in chio-control-plane.
- **Scope note.** P4 and P5 permanent consumption (retired artifact ids, confined-child reservations, release intents, pins) lives in durable control-plane runtimes, outside this spec's non-durable scope, under the same no-compensator rule.
- **Merge drift.** W: is built on an older base where the early disarm sits at `async_evaluation_core.rs:1751` (M: `:1740`). W: also edits `terminal.rs`, `security_release.rs` and `admission_coordinator.rs`. Evaluator line citations will move again when W: is rebased.

## Revision 2 changes

- **Re-baselined on the shipped security, process and work surfaces.** All evaluator citations now point at `M:`. The early disarm is still present at `M:`/`V:` `async_evaluation_core.rs:1740`, so the gap this spec closes is still real.
- **Repositioned as an application, not a new pattern.** The in-process token is a Mechanism A evidence token. `PostEffectError` is Mechanism C. The boundary check is the Mechanism D escape-hatch gate (RP6), built here with a shared allowlist, not a separate tool. (Revision 4 withdraws the claim that this closes RP2; see S3-10.)
- **Renamed `TerminalEvidence` to `PostEffectDischarge`.** The old name collided with `ToolOutcomeTerminalEvidenceV1` and `PaymentTerminalEvidence`. (Revision 4 replaces the free token with the bound `Discharged` value.)
- **Drop restated as hygiene only.** Revision 1 said "Drop = compensate". Revision 2 made `Drop` latch and request reconciliation. Revision 4 restores best-effort pre-dispatch compensation, which is safe because no effect is possible before the boundary (rule 6).
- **Ledger split into entry classes.** `Compensable` entries are kernel holds the kernel may reverse before dispatch. `Commitment` entries have no compensator.
- **Scope narrowed.** Revision 2 limited the uncovered region to `ReadOnly` tools under the default mode. Revision 4 widens it again to `Monetary` and development `Off` (S3-16).
- **Release exits named.** `MutuallyAgreedUnknown` and `ContractualCaptureWaiver` are the only post-unknown hold releases. The latch and `fail()` never imply release. (Independent review pass 5 corrects the phase: only `MutuallyAgreedUnknown` releases an unknown hold, and `ContractualCaptureWaiver` resolves a known return's pending capture; section 2.6.)
- **Dropped:** the `AdmissionReservation::FaultResolution` entry; the standalone `xtask/src/post_effect_boundary.rs` and its own allowlist file; merge-order open decision 5.

## 1. Decision summary

FTL reserves fallibly so that its commit cannot fail. Chio already applies that rule where crash safety matters:
- `AdmissionOperation` commits `Prepared` before participants and `DispatchCommitted` before handoff.
- Process calls commit a call slot before the kernel call and retain it on failure (M: `chio-process/ARCHITECTURE.md:40-45`).
- Caller-executed delivery treats a reservation as preparation, never permission (M: caller dispatch commitment).

This design does not replace that machinery.

One region is still governed by convention: the code between "the tool returned" and "a terminal record exists" on calls without durable admission. Both evaluators disarm `PostAdmissionDropGuard` right after the credential commit, before the receipt is built (M: `async_evaluation_core.rs:1740`, `nested_flow_evaluation.rs:1495`). Several later steps fail with `?` and return a bare `KernelError`. The transport-failure arms disarm first and then build their receipt fallibly. The caller gets no output, so durable-before-allow holds, but an executed call can end with no kernel decision receipt. Hosts that sign a `trace_observation` for evaluator errors (the chio-cli stdio session handler, `crates/products/chio-cli/src/cli/session/handler.rs:59-87`) record only a host claim, not a decision. This is the exact defect shape the unrepresentable-defects design names: "A correct primitive exists. Correctness depends on a convention about where it is called" (M: unrepresentable-defects `:21-22`).

The decision has six parts:

1. **Mechanism A.** A move-only `PostEffectObligation` whose region is a function that must return `Discharged`. `Discharged` has a private constructor. Only the obligation's own consuming methods produce it: a committed terminal receipt bound to this request, a recorded durable outcome, or a recorded fault.
2. **Mechanism C.** Post-effect errors have their own opaque type, `PostEffectError`, with no `From` into `KernelError`. Its cause is a `PostEffectRejection` when a rule fired, or an infrastructure fault. Its only exit is `PostEffectObligation::fail`.
3. **Typed ledger.** `AdmissionReservations` replaces boolean cleanup flags. Entries are evidence tokens returned by their acquiring functions. They are `Compensable`, `Retained` (before dispatch) or `Commitment`, and an exhaustive match forces every new kind to choose.
4. **Scoped latches.** `LatchScope` names three latches. Only unpersisted post-effect evidence closes the kernel to new dispatch, through its own gate, until a supervised flusher drains the buffer.
5. **Mechanism D.** The escape-hatch gate (`cargo xtask check escape-hatches`) lands with this design, with one ratcheted allowlist keyed by item, not line.
6. **Division of labor.** Spec 9 decides transitions, spec 10 executes commits, and this spec owns the affine contract that binds a dispatched effect to its discharge (section 4.12).

## 2. Verified current state

### 2.1 What already closes the gap

| Surface | Behavior | Evidence |
|---|---|---|
| Durable saga | Tool return recorded through `record_durable_tool_return`, then owned by `finalize_durable_tool_return_with_security_release`. A failed record leaves the operation `DispatchCommitted`, and recovery terminalizes it | M: `async_evaluation_core.rs:1896`, `:1944` |
| Unconfirmed dispatch commit | `DurableDispatchCommitError::RejectedBeforeCommit` rolls back reversible credentials. `CommitUnconfirmed` keeps every hold and credential and signs an ambiguous deny: "never optimistic refund" | M: `kernel/evaluation/dispatch_commit_failure.rs:1`, `:40-75`; call site `async_evaluation_core.rs:1646-1670` |
| Process calls | `ProcessRuntime::open` requires durable admission for all calls. A call slot is committed before the kernel call and retained on failure | M: `chio-process/README.md:28`; `ARCHITECTURE.md:44` |
| Delegated work (D1) | Installation requires a durable store and sets `require_durable_request_retention`. A call whose effect class the mode does not cover is denied, not run ephemerally | V: `delegated_work.rs:44-49`; V: `kernel/admission_coordinator.rs:525-532`, `:559-569` |
| Execution evidence | `export_durable_execution_evidence` requires a Finalizing durable operation | V: `pre-settlement-execution-design.md:35` |
| Default mode | `DurableAdmissionMode::SideEffecting` is the default and does not cover `ReadOnly` | M: `admission_operation/identity.rs:366-391` |
| Move-only primitives | `BudgetChargeResult` (no `Clone`), one-time `ReceiptSigningHandle` | M: `kernel/mod.rs`; `chio-kernel-core/src/receipts.rs` |
| Evidence-token precedent | `ToolOutcomeTerminalEvidenceV1`, `PaymentTerminalEvidence` (durable saga) | M: `tool_outcome/release/terminal.rs:16`; `admission_operation/projection/participant_evidence.rs:207` |
| Pre-dispatch drop compensation | Every pre-dispatch await is covered by a drop guard. `handle_pre_dispatch_drop` reverses the monetary hold, the invocation counter, runtime-admission leases and continuations, the reference-counted child-budget holder lease, then durable compensation | M: `kernel_drop_guard.rs:235-394`; guarded awaits at `async_evaluation_core.rs:461-492`, `:1118`, `async_nonce_preflight.rs:153`, `nested_flow_evaluation.rs:799`, `nested_flow_grant_selection.rs:99` |
| Post-dispatch drop terminalization | The guard's `Drop` terminalizes a `DispatchCommitted` operation as outcome-unknown, so its request id is not stranded until restart | M: `kernel_drop_guard.rs:530-548`; `admission_coordinator/recovery.rs:395-400` |
| Callback containment | Security callbacks run under `catch_unwind`. The recorder is dropped separately to avoid a double-panic abort | M: `security_dispatch.rs:8-36` |
| Affine custody precedents (W:) | `PreparedArtifactRead`, `PreparedConfinedReturn` and `CapturedSemanticSubmissionV1`: private construction, no `Clone` or `Deserialize`, with compile-fail doctests | W: `chio-control-plane/src/knowledge.rs:39`; `confinement.rs:38`; `semantic/connector.rs:25` |

### 2.2 The uncovered region on M:

After `mark_dispatch_started` (M: `async_evaluation_core.rs:1711`), four groups of fallible steps run on the non-durable path.

**(a) The `Ok` arm.**

1. `outcome.record_released()?` for the security dispatch handle, **before finalization** (`:1727`). The security recorder can say `Released` for a call whose receipt is never written (umbrella N2).
2. Credential commit, then `post_admission_drop_guard.disarm()` (`:1736-1740`). From here the guard's best-effort cancellation receipt in `Drop` (M: `kernel_drop_guard.rs:471`) is unreachable.
3. `self.read_authority_time()?` (`:1956`). This read feeds only the recovery revalidation. The allow receipt is stamped with `now`, the authority time read at evaluation entry (`:32-33`, passed at `:1972`), so on M: a non-durable receipt's `timestamp` predates the tool's execution. The recovery revalidation at `:1951` cannot fail on this path: finding-recovery grants force durable admission (`kernel/admission_coordinator.rs:564-581`), the durable branch returns at `:1944`, and on the only path that reaches `:1951` revalidation is `Ok(())` (`recovery_gate.rs:589-596`).
4. `finalize_ordinary_recovery_response` (`:1968`, defined at M: `evaluation_helpers.rs:219`). That function reaches:
   - stream limits and the post-invocation pipeline (M: `responses/finalization.rs:33`, `:34-40`);
   - receipt content (M: `responses/allow_responses.rs:69`) and receipt metadata (`:92`);
   - parameter hashing (`:106-108`) and signing (`:110-123`);
   - the revocation re-check (M: `responses/receipt_persistence.rs:250`, before the append) and the append (`allow_responses.rs:125`);
   - after the append, still inside `record_chio_receipt_with_federation`: trace sequence allocation (`receipt_persistence.rs:442`), the settlement claim's `read_authority_time()?` (`:467`, `:490`) and federation co-sign (`:256-260`).
5. `SecurityRequestLifecycleHandle::finish_response` propagates a finalization error with `?` before ensuring final release (M: `security_dispatch.rs:121-130`). `record_outcome` (`:24-36`) and `ensure_final_release` (`:170-177`) both return `Err`.

**(b) The transport-failure arms.** Each arm calls `terminalize_after_transport_failure()?`, disarms, and then builds its receipt fallibly:
- async: `async_evaluation_core.rs:1765-1888`, with disarms at `:1767`, `:1798`, `:1832`, `:1864`, each followed by a `build_cancelled_*`, `build_incomplete_*` or `build_deny_*` call;
- nested: `nested_flow_evaluation.rs:1543-1660`, including `with_session_mut(..)?` at `:1555-1558` after the disarm.

These are calls with an ambiguous effect that can end with no receipt. That is D1 itself.

**(c) Armed steps the obligation must classify.** The child-receipt flush (`nested_flow_evaluation.rs:1488`) and the URL-elicitation cancellation (`kernel_drop_guard.rs:197-219`).

**(d) Monetary finalization.** `finalize_budgeted_tool_output_with_cost_and_metadata` contains:
- `reconcile_budget_charge(..)?` (`kernel/validation.rs:1894`);
- payment-rail capture and release (`:1725-1748`, `:1906-1915`);
- two releases after execution whose results are discarded with `let _ = adapter.release(..)`:
  - `:1733`, after a capture error, followed by a deny response;
  - `:1747`, after any capture whose status is not `Settled` (`RailSettlementStatus` has seven values: `Authorized`, `Captured`, `Settled`, `Pending`, `Failed`, `Released`, `Refunded`, M: `payment/types.rs:89-97`).

By contrast, a revocation observed at `allow_responses.rs:53` correctly produces a signed deny-delivery receipt. Provenance (`:141`) and nonce minting (`:150`) already run after the receipt. The same shape exists in the nested-flow evaluator (M: `nested_flow_evaluation.rs:1404`, `:1495`).

**The durable path.** A failed `record_durable_tool_return` builds a deny response and discards it (`let _ =` at `async_evaluation_core.rs:1919`; nested at `nested_flow_evaluation.rs:1705`). The discard is not harmless. `build_deny_response_with_metadata_and_payee_binding` signs and records a `Deny` receipt (M: `responses/deny_responses.rs:453-520`) for a call whose tool executed. The operation stays `DispatchCommitted`, and recovery later terminalizes it as `OutcomeUnknownAfterDispatch`. The result is two contradictory terminal records. Rule 25 removes the `Deny` write.

### 2.3 Who is still exposed

The obligation and latch apply whenever `durable_admission` is `None`. That happens on these surfaces:

- **The default mode.** Hosts that call `ChioKernel` directly, through the MCP edge or the HTTP sidecar, with `ReadOnly` tools under `SideEffecting`. A connection that misdeclares a mutating tool as `ReadOnly` is exposed here.
- **`Monetary` mode.** It can be selected in production policy (`chio-control-plane/src/policy/types.rs:194`). `validate_configuration` refuses only `Off` (M: `admission_operation/identity.rs:393-404`). Under `Monetary`, `covers` is true only for `SideEffectClass::Monetary` (`:387`), so every non-monetary mutating tool takes the non-durable branch (`kernel/admission_coordinator.rs:569-581`). This is the worst D1 case: a mutating effect that can end with no receipt.
- **Development `Off`.** It is accepted only with unsafe development mode and ephemeral receipts (`identity.rs:393-404`). Every call is non-durable.
- **Development profiles** with `allow_ephemeral_receipt_log`.

Process-hosted calls and work profiles are not exposed (section 2.1).

### 2.4 Hand-maintained bookkeeping

On M:, the evaluators maintain:
- 7 `PostAdmissionDropGuard::new` calls in non-test code;
- 16 `disarm()` calls (15 in the evaluators, plus `kernel_drop_guard.rs:217`);
- 43 `PreDispatchCleanupDeny {` sites;
- guard flags `armed`, `dispatch_started` and `budget_lease_acquired` (M: `kernel_drop_guard.rs:85-89`);
- credential flags `rollback_on_drop` and `retain_on_drop` (M: `credential_reservation.rs:71-72`).

This bookkeeping has already produced defects closed by runtime flags:
- RFC-0002 F02;
- holder-lease reference counting (`ad64e8f40`);
- verifier-only leases (`818d1c5c9`).

### 2.5 Reservation semantics elsewhere (non-normative)

Elsewhere, reservation means consumption. None of the rows marked "outside the evaluation" is acquired inside a kernel tool-call evaluation, so none is a ledger entry (S3-19). They are listed so the no-compensator rule is visible in one place.

| Reservation | Owner | Compensable by the kernel? | Acquired inside a tool-call evaluation? |
|---|---|---|---|
| Process call slot | process journal | No. Retained on failure (M: `ARCHITECTURE.md:44`) | No, committed by chio-process before the kernel call (M: `ARCHITECTURE.md:40-45`), always durable |
| Sibling budget share | process journal | No. Retained after cancel (M: `ARCHITECTURE.md:23`) | No |
| Recovery call reservation | `RecoveryCallReservation` via `reserve_recovery_call` (W: `chio-process/src/recovery.rs:9`, `:83`) | No. Charged once before approval; `finalize_recovery_call` (`:110`) consumes it exactly once. "A later failure does not restore spent authority" (W: `implementation/p1/OPERATIONS.md:101`) | No, committed by chio-process before the kernel call, always durable |
| Recovery provider-lookup reservation | recovery authority store (`reserve_provider_lookup`, W: `chio-kernel/src/recovery/ports.rs:54`) | No. Affine, capped at 32 per workflow (W: `implementation/p1/OPERATIONS.md:114`) | No, a `RecoveryAuthorityPort` operation of an authenticated recovery actor (W: `recovery/ports.rs:53-60`) |
| Recovery grant issuance reservation | recovery authority store (`reserve_issuance`, W: `recovery/ports.rs:124`) | No. Consumed by grant v2 issuance | No, a recovery actor operation (`:124-131`) |
| P4 and P5 consumption: retired artifact version ids, confined-child reservations, release intents, permanent pins | durable control-plane runtimes over process calls | No | No, durable paths |
| D1 subdivision and sealed allocation | remote allocator | No. "no reset, timeout refund ... or release of sealed allocations" (V: `dynamic-delegation-design.md:40-41`, `:86-87`) | Observed before dispatch on durable delegated-work paths |
| F1 escrow backing | chain escrow | No. The receiver only observes backing before dispatch (V: `sections/03-contract.tex:94-102`; V: `PROTOCOL.md:63`) | Observed before dispatch |
| Invocation and monetary holds, runtime admission, child budget lease, dispatch credentials | kernel stores and in-memory registries | Yes, before `DispatchCommitted`, unless retained (rule 22) | Yes |

### 2.6 Release authority

`PaymentReleaseAuthorityKind` (V: `payment/journal.rs:88-96`) has five kinds; M: has three (`journal.rs:86`):
- `PreDispatchNoEffect`, `TransportNotAccepted` and `ContractualZeroCharge` are no-effect or zero-charge exits. Spec 9 calls these `MachineRelease`. `ContractualZeroCharge` needs a zero recomputed amount, or a verified, request-bound contractual delivery denial under a reversible hold (V2: `kernel/admission_coordinator/terminal_payment.rs:111-125`; `kernel/output_guard.rs:51-105`). A delivery refusal alone is never pricing authority (spec 9 M11a).
- `MutuallyAgreedUnknown` is the only release of an unknown hold. It "never establishes that execution had no effect" (V: `payment/unknown_release.rs:1-4`).
- `ContractualCaptureWaiver` is not an unknown-outcome release. It resolves a known return's positive capture pending in `Settling` or `ReconcileFailed`, while the operation is `Finalizing` with a recorded tool outcome (V2: `payment/contractual_resolution.rs:224-245`; spec 9 M7b). It never applies to an unknown terminal.

## 3. Goals and non-goals

### Goals

- Make leaving the post-effect region without a discharge fail to type-check. The region is a function that must return `Discharged`, and only the obligation's methods construct it. Rust types are affine, not linear, so `Drop` remains a runtime backstop. The gate and the compile-fail tests cover the spellings that bypass it.
- Make the existence of a ledger token, rather than a boolean, the thing that authorizes compensation or retention. Make forging an entry, double compensation and compensating a retained or committed entry compile errors.
- Move every dispatch-independent receipt input, and a pre-built fault-receipt template, before the effect boundary.
- Bound the window of unrecorded effects when the receipt writer itself has failed, without closing compensation or recovery.
- Give specs 4, 9 and 10 one latch vocabulary with a defined scope and clear condition for each latch.
- Land the Mechanism D gate, so every escape hatch these types need is counted from day one.

### Non-goals

- Making I/O infallible. Here "infallible commit" means "cannot fail silently".
- Changing `AdmissionOperationV1` states, `BudgetStore` signatures, process journal semantics, D1 or F1 rules, or any store schema.
- Deciding transitions for durable or check-only operations. Spec 9 owns the decision rows (section 4.12).
- Pre-reserving receipt-log sequence numbers or capacity (section 10).
- Crash-safe recording for non-durable calls. The remedy for crash safety is durable coverage.
- Changing `chio-kernel-core`.
- Caller-executed delivery, which M:'s start/report handshake owns. `AdmissionReservations` must never issue external execution permission.
- Pre-invocation refusals that leave no receipt (ledger item EV3). They are adjacent but out of scope.

## 4. Design

### 4.1 Mapping onto unrepresentable-defects

| Mechanism (M: unrepresentable-defects) | Here |
|---|---|
| A, evidence token (`:97`): private fields, no `Default`, no `Deserialize`, one constructor that is the check | `Discharged`, constructed only by `PostEffectObligation`'s consuming methods (rule 7), each of which performs the check it attests. Ledger tokens (rule 21) |
| C, structured rejection (`:370`): one variant per rule, causes preserved, registered codes | Opaque `PostEffectError { step, cause }`. When a rule fired, the cause is a `PostEffectRejection` with a registered `chio-errors` code. RP2 (`:513`) concerns the governed active-response seam and is not claimed here |
| D, escape-hatch gate (`:440`): ratcheted allowlist, fails on a new hatch | `cargo xtask check escape-hatches` (section 5) |
| Engineering standard 2.3 (typestate where it removes an omission class) | `AdmissionReservations`, then `PostEffectObligation`, then `Discharged` |

### 4.2 Typestate

```text
AdmissionReservations::open --push(token) (fallible acquisition, pre-dispatch)--> AdmissionReservations
   |                               |                                      |
   | compensate_before_dispatch    | retain(slot, cause)                  | enter_effect_boundary(self)
   v                               v  (pre-dispatch, rule 22)             v
CleanupReport                   entry moves to Retained:            Ok((PostEffectObligation, RetainedReservations))
(fault receipt iff a step        stamped as a marker,               Err(RejectedBeforeCommit(CleanupReport))   compensated
 failed)                         never reversed                     Err(CommitUnconfirmed(RetainedReservations)) retained,
                                                                         ambiguous deny, never compensated

fn post_effect(ob: PostEffectObligation, ..) -> Discharged
   ob.commit_terminal_receipt(signed) -> Result<Discharged, Undischarged>   (non-durable)
   ob.record_durable_outcome(ret)     -> Result<Discharged, Undischarged>   (durable)
   ob.fail(error)                     -> Discharged                         (fault receipt, operator fault, or buffer + latch)

Discharged::deliver(self) -> Result<ToolCallResponse, DeliveryFailedAfterReceipt>   (post-receipt steps, section 4.7)

Drop(AdmissionReservations) = best-effort compensate_before_dispatch with the cleanup-fault receipt; never latches (rule 6)
Drop(boundary in flight)    = dispatch commit submitted, not acknowledged: retain everything, hand the reply to reconciliation;
                              never compensates, never latches (rule 29)
Drop(PostEffectObligation)  = non-durable: best-effort fault receipt, else KernelEvidence latch (rule 11)
                              durable: enqueue supervised reconciliation (rule 23); never a durable transition in Drop
```

### 4.3 `AdmissionReservations`

```rust
#[must_use = "reservations must be compensated or carried across the effect boundary"]
pub(crate) struct AdmissionReservations<'k> {
    kernel: &'k ChioKernel,
    request: &'k ToolCallRequest,
    compensable: Vec<CompensableReservation<'k>>,     // acquisition order
    retained: Vec<RetainedEntry<'k>>,                 // retained before dispatch (rule 22)
    commitments: Vec<ExternalCommitment>,
    durable_operation: Option<&'k AdmissionOperationV1>,
}

/// Every payload is a token: private fields, no Clone, Copy, Default or
/// Deserialize, returned only by its acquiring function (rule 21).
pub(crate) enum CompensableReservation<'k> {
    InvocationIncrement(InvocationIncrementToken),
    InvocationHold(BudgetChargeResult),
    MonetaryCharge { charge: BudgetChargeResult, payment: Option<PaymentAuthorization> },
    ChildBudgetLease(ChildLeaseToken),
    RuntimeAdmission(RuntimeAdmissionLeaseToken),
    DispatchCredentials(DispatchCredentialReservation<'k>),
    EvidenceSlot(EvidenceSlot),          // rule 18; moved into the obligation at the boundary
}

pub(crate) struct RetainedEntry<'k> {
    entry: CompensableReservation<'k>,
    cause: RetentionCause,
}

pub(crate) enum RetentionCause {
    ExternalAuthorizationAcknowledged,   // M: async_evaluation_core.rs:1252-1291; credential_reservation.rs:91-103
    InvocationCaptureUnconfirmed,        // M: evaluation/invocation_capture.rs:57-77
}

/// A precondition the kernel observed but cannot reverse. Carried for
/// retention markers and receipts; never compensated.
pub(crate) enum ExternalCommitment {
    DelegatedAllocation { slot_id: String, permit_digest: Digest32 },          // D1 sealed
    ObservedEscrowBacking { escrow_id: String, observation_digest: Digest32 }, // F1
}
```

Rules:

1. An entry exists only because its acquiring function returned a token, and `push` accepts only tokens (rule 21). No code tests a boolean to decide whether a reservation exists. `budget_lease_acquired` and the `PreExecutionBudgetMutation` variants are replaced by entry presence.
2. `compensate_before_dispatch(self) -> CleanupReport` does three things:
   - It runs the current unwind order of `handle_pre_dispatch_drop` (M: `kernel_drop_guard.rs:235`) over `compensable` entries only: monetary unwind, invocation reversal, runtime-admission release, child-lease release, then durable compensation only if every earlier step succeeded. Failures go into the existing `pre_dispatch_cleanup_faults` receipt (`:442`).
   - It stamps `retained` entries into the cleanup receipt as `retained_before_dispatch { cause }` and never reverses them.
   - It records `commitments` as `retained_external` and never acts on them.
3. `PreDispatchCleanupDeny` takes `AdmissionReservations` by value instead of a field list. A denial builds its receipt after compensation.
4. `enter_effect_boundary(self) -> Result<(PostEffectObligation<'k>, RetainedReservations), BoundaryFailure>` runs today's fallible boundary steps (`retain_if_dropped`, `commit_durable_dispatch` / `capture_and_commit_durable_dispatch`).

   ```rust
   pub(crate) enum BoundaryFailure {
       RejectedBeforeCommit(CleanupReport),        // definite: nothing committed
       CommitUnconfirmed(RetainedReservations),    // the store may have committed
   }
   ```

   - `RejectedBeforeCommit` compensates the `compensable` entries and returns the report, as `build_pre_commit_credential_rejection_response` does today (M: `dispatch_commit_failure.rs:11-37`).
   - `CommitUnconfirmed` moves every entry to retained, signs the ambiguous deny with retained markers through `ambiguous_dispatch_receipt_metadata`, and calls `record_dispatch_failed`, exactly as M: does (`dispatch_commit_failure.rs:40-75`). The deny carries `identity_disposition = Retained` (spec 9 M20): it records an unresolved attempt, and recovery later supplies the request's one terminal record. It never compensates: "Do not infer nonexecution from an error returned after entering the store" (`:52-54`). If the CAS to `DispatchCommitted` landed, recovery terminalizes the operation as `OutcomeUnknownAfterDispatch` with the holds still frozen. This is the same rule as spec 9 M12: an unknown commit outcome halts the operation with no compensation.
   - On success, every entry moves into `RetainedReservations`, which post-effect paths read to stamp retained markers and which nothing can release. The one exception is the `EvidenceSlot` entry, which moves into the obligation's `evidence_slot` field (rule 18). `RejectedBeforeCommit` returns it to the pool with the rest of the compensation. `CommitUnconfirmed` carries it with the retained entries, so the ambiguous deny can buffer into it if its own append fails.
5. Every `match` over `CompensableReservation`, `RetentionCause` and `ExternalCommitment` is exhaustive, under `#[deny(clippy::wildcard_enum_match_arm)]`. A new kind cannot compile without choosing its class. A `Commitment` or a retained entry has no compensator to call.
6. **`Drop` on an unconsumed `AdmissionReservations` compensates best-effort and never latches.** An unconsumed ledger is type-level proof that `enter_effect_boundary` never ran, so no effect is possible. R: `02-rust-design.md:124` forbids `Drop` from certifying no effect after capture, not from attempting compensation before the boundary. Dropping an evaluation future before dispatch is routine: a client disconnects, or an outer timeout or `select!` fires. M: guards every pre-dispatch await for that reason (section 2.1).
   - `Drop` runs `compensate_before_dispatch` best-effort, with the existing cleanup-fault receipt, in M:'s order.
   - The in-memory items (invocation counter, runtime-admission leases and continuations, the reference-counted child-budget holder lease) have no other reclaimer. A leaked holder lease "stays permanently recorded" (M: `kernel_drop_guard.rs:328-341`). So these items are released synchronously in `Drop`.
   - The durable compensation step runs only if every earlier step succeeded, as today. When it cannot run, `Drop` enqueues the operation to the supervised reconciliation job of rule 23, whose pre-dispatch branch compensates under `PreDispatchNoEffect`. The startup sweep remains the backstop.
   - `Drop` never sets a latch. "An unconsumed ledger is a bug" survives only as a `debug_assert!` on paths that are not cancellation; there are none in the evaluators today.
   - Rule 6 covers drops before the dispatch commit is submitted. A drop after submission and before the acknowledgement follows rule 29, because the commit may still land.
   - The work runs under rule 24.

### 4.4 `PostEffectObligation` and `Discharged`

```rust
#[must_use = "a possible side effect must end in a discharge or a recorded fault"]
pub(crate) struct PostEffectObligation<'k> {
    kernel: &'k ChioKernel,
    binding: DischargeBinding,                     // request_id, operation_id, matched grant
    retained: RetainedReservations,
    receipt_inputs: PreparedReceiptInputs,         // includes the pre-built fault template (rule 14)
    child_receipts: Vec<ChildRequestReceipt>,
    security_outcome: Option<SecurityDispatchOutcomeHandle>,
    security_lifecycle: Option<SecurityRequestLifecycleHandle>,
    durable: Option<DurableToolAdmission>,         // owned, not borrowed (rule 8)
    charge: Option<BudgetChargeResult>,            // owned, not borrowed (rule 8)
    evidence_slot: Option<EvidenceSlot>,           // rule 18: Some for non-durable calls, None for durable
}

/// Mechanism A. Private fields, no Default, Clone or Deserialize; constructed
/// only inside `effect_obligation.rs` by the obligation's consuming methods.
#[must_use = "a discharged call still owes delivery or a recorded delivery failure"]
pub(crate) struct Discharged {
    binding: DischargeBinding,
    kind: DischargeKind,
    tail: PostReceiptTail,                         // security handles, provenance, nonce (section 4.7)
}

enum DischargeKind {
    ReceiptCommitted { receipt_id: ReceiptId, decision: TerminalDecision },
    DurableOutcomeRecorded { operation_id: AdmissionOperationId },
    FaultReceiptCommitted { receipt_id: ReceiptId },
    FaultBuffered { record: BufferedRecordId },          // KernelEvidence latch set (section 4.8)
    DurableHandedToSaga { operation_id: AdmissionOperationId }, // operator fault; reconciliation enqueued (rule 23)
}

pub(crate) struct Undischarged<'k> {
    obligation: PostEffectObligation<'k>,
    error: PostEffectError,
}

impl<'k> PostEffectObligation<'k> {
    pub(crate) fn commit_terminal_receipt(self, signed: SignedTerminalReceipt)
        -> Result<Discharged, Undischarged<'k>>;
    pub(crate) fn record_durable_outcome(self, ret: DurableToolReturn)
        -> Result<Discharged, Undischarged<'k>>;
    pub(crate) fn fail(self, error: PostEffectError) -> Discharged;
    fn into_parts(self) -> ObligationParts<'k>;    // private; disarms Drop by construction
}

impl Discharged {
    pub(crate) fn deliver(self) -> Result<ToolCallResponse, DeliveryFailedAfterReceipt>;
}

/// The post-effect region. Neither `?` on `KernelError` nor an early return
/// type-checks inside it, because its return type is `Discharged`.
pub(crate) fn post_effect(ob: PostEffectObligation<'_>, returned: ToolReturn) -> Discharged;
```

Rules:

7. **Minting is bound and happens at the commit point.** Only the obligation's consuming methods construct `Discharged`. The 57 `record_chio_receipt*` references in chio-kernel (pre-dispatch denials, cleanup faults, internal audit receipts, reports) mint nothing, and startup recovery's `terminalize_dispatch_committed_admission` (M: `admission_coordinator/recovery.rs:395-400`) mints nothing.
   - `commit_terminal_receipt` checks `signed.request_id == binding.request_id`, the operation id (if any), and that the decision is a terminal decision this obligation may record (`Allow`, `DenyDelivery`, `Cancelled`, `Incomplete`, `Withheld`). A mismatch is a `PostEffectError` routed to `fail`, never a discharge.
   - It appends through `record_chio_receipt_during_trace_transition` and mints `ReceiptCommitted` immediately after `append_chio_receipt_with_timeout` returns `Ok` (M: `receipt_persistence.rs:385-400`). Everything after that point is a post-receipt step (rule 15).
   - A refused append returns `Undischarged`, so the caller must call `fail`. A timed-out append is `AppendOutcomeUnknown` (rule 28).
   - **No transferable token.** `Discharged` is produced only by consuming the obligation it discharges, and it carries that obligation's `binding`. The evaluator runs the region through `run_post_effect(ob, returned)`, which copies `ob.binding` before the call and compares it with the returned `Discharged`'s binding. A mismatch can arise only if two obligations are live in one region, which the evaluator never does: nested child receipts are buffered, not discharged (rule 10). It is an invariant violation, and it fails closed. The output is withheld, the returned `Discharged` is not delivered, `audit_fault` is emitted, and the expected obligation's pre-built fault record sets `LatchScope::KernelEvidence`.
   - `record_durable_outcome` wraps `record_durable_tool_return` and mints `DurableOutcomeRecorded`. The saga and `finalize_durable_tool_return_with_security_release` own the rest. It does not duplicate `ToolOutcomeTerminalEvidenceV1`, which remains the saga's evidence.
8. **Ownership.** The obligation is minted only by `enter_effect_boundary`. It replaces `mark_dispatch_started`, `disarm`, `mark_dispatch_credential_commit_failed` and `mark_durable_operation_terminalized`, which removes the early disarm at M: `async_evaluation_core.rs:1740` and `nested_flow_evaluation.rs:1495`.
   - The disarm there is partly forced by the borrow checker: the guard borrows `&budget_mutation` and `durable_admission` (`:1692-1710`), and later code moves `budget_mutation.into_charge_result()` (`:1975`) and takes `durable_admission.as_mut()` (`:1891`).
   - So the obligation owns the `DurableToolAdmission` and the `BudgetChargeResult` instead of borrowing them. Fields cannot be moved out of a `Drop` type (E0509), so finalization takes the obligation by value inside `effect_obligation.rs` through the private `into_parts`. `into_parts` disarms `Drop` by construction, using the one allowlisted `ManuallyDrop` in chio-kernel (section 5).
   - Finalization code that consumes the charge or mutates the admission therefore lives in `effect_obligation.rs` or its submodules, and the gate's module rules (section 5 item 2) cover it.
   - Under spec 9 drivers, the obligation is minted on the acknowledgement of `Dispatch`, `DispatchCommitAcknowledged` or `CheckOnlyAcknowledged` (section 4.12).
9. **Security handles.** The obligation absorbs both handles and moves them into `Discharged`'s post-receipt tail:
   - `SecurityDispatchOutcomeHandle::record_released` runs only in `Discharged::deliver`, after the receipt commit. Today it runs before finalization (`:1727`).
   - `fail` records `record_outcome_unknown_after_dispatch` (M: `security_dispatch.rs:64`).
   - `SecurityRequestLifecycleHandle::ensure_final_release` also runs in `deliver`. Final release gates publication (M: `security_dispatch.rs:115-119`), so its failure withholds the output and the receipt stands (section 4.7).
   - The rule is stated over `SecurityRequestLifecyclePermit`, so it covers W:'s `RecoveryReleaseOwner` (W: `kernel/admission_coordinator/security_release/recovery.rs:8-12`). That owner refuses release without the original guarded output, and runs only on the durable `Finalizing` path, so on that path discharge is `DurableOutcomeRecorded`. It never enters the non-durable region.
10. Buffered nested child receipts move from the guard into the obligation, keeping the RFC-0002 flush-first order. A child-receipt flush failure is the step `ChildReceiptFlush`.
11. **`Drop` on an undischarged obligation**, for example on a panic (M: `Cargo.toml:344` is `panic = "unwind"`):
    - Non-durable: it attempts the pre-built fault receipt with retained markers, under rule 24. If that fails, it sets `LatchScope::KernelEvidence` with an unsigned `PostEffectFaultRecord`.
    - Durable: it enqueues the supervised reconciliation of rule 23 and performs no durable transition itself.
    - It never releases a hold and never refunds.

### 4.5 `PostEffectError` (Mechanism C)

```rust
/// Opaque: private fields, no accessor that yields a KernelError, no public
/// destructuring. Constructed by `PostEffectError::rejected` and
/// `PostEffectError::infrastructure`; read only inside `effect_obligation.rs`.
#[must_use]
pub(crate) struct PostEffectError {
    step: PostEffectStep,
    cause: PostEffectCause,
}

pub(crate) enum PostEffectCause {
    Rejected(PostEffectRejection),
    Infrastructure(InfraFault),            // registered code of the underlying error; no payload text
}

/// One variant per post-effect rule; each has a registered chio-errors code.
pub(crate) enum PostEffectRejection {
    Revoked,                               // persistence re-check, receipt_persistence.rs:250
    PostInvocationBlocked { guard: GuardId },
    StreamLimit,
    OutputContract,                        // an ordinary output-contract or guard refusal: no pricing authority
    ContractualDelivery(DeliveryDenialReason), // a verified, request-bound delivery contract or opted-in checked-output guard (V2: delivery_contract.rs:66-175,
                                           // output_guard.rs:51-105); the only rejection that can carry ContractualZeroCharge (spec 9 M11a)
    ReleaseRefused(CrossingRefused),       // spec 10 release crossing refusal
}

pub(crate) enum PostEffectStep {
    // all run before the receipt commit; post-receipt steps are not listed (section 4.7)
    TransportFailureReceipt, CredentialCommit, SessionBookkeeping, ChildReceiptFlush,
    UrlElicitationCancel, AuthorityTime, StreamLimits, PostInvocation, BudgetReconcile,
    PaymentSettlement, ReceiptContent, Signing, Append,
}
// Deliberately absent: impl From<PostEffectError> for KernelError.
```

`SecurityRelease` is removed from `PostEffectStep`, because security release runs after the receipt (rule 9). `RecoveryRevalidation` is removed, because it cannot fail on this path (section 2.2). The revision 3 step `Revoked` is now `(Append, Rejected(Revoked))`.

Rules:

12. **The region type-checks only when it discharges.** Every function that runs while an obligation is live returns `Result<_, PostEffectError>`. The region is `fn post_effect(..) -> Discharged`, so neither `?` on a `KernelError`, nor `return Err(..)`, nor `return Ok(..)` type-checks inside it. The evaluator maps `Discharged::deliver` to its own `Result` outside the region. A `compile_fail` test pins "return from `post_effect` without `Discharged`".
13. **Legacy phase 1 mapping.** On the legacy evaluator, `fail` records a terminal response synchronously, as follows. Spec 9 owns these decision rows going forward: it expresses the same mapping as transition rows over `PostEffectStepFailed` and `ReceiptAppendFailed`, with T8 as the discharge predicate. When spec 9's phase 4 drivers land, those rows replace this rule.

    | Step and cause | Non-durable terminal record |
    |---|---|
    | `TransportFailureReceipt` (the arm's own receipt could not be built) | `Cancelled` fault receipt from the pre-built template with `execution_outcome: "unknown"` and the arm's ambiguity cause |
    | `CredentialCommit` | today's `POST_DISPATCH_CREDENTIAL_COMMIT_FAILURE_REASON` cancellation receipt |
    | `PostInvocation`, or `Rejected(PostInvocationBlocked)` | deny-delivery receipt with retained markers, matching the blocked-output arm (M: `finalization.rs:43`) |
    | `Rejected(Revoked)` at `Append` | deny-delivery receipt, matching `allow_responses.rs:53` |
    | `Rejected(StreamLimit)`, `Rejected(OutputContract)` | deny-delivery receipt with retained markers. The refusal never releases a positive monetary authorization (rule 27) |
    | `Rejected(ContractualDelivery(..))` | not reachable: only the durable finalizer evaluates contract-bound delivery (V2: `kernel/admission_coordinator/terminal.rs:546`, `:1065`), and spec 9 M11a maps it there |
    | `Rejected(ReleaseRefused(reason))` | `Withheld { reason }` (spec 9 `ReceiptDecision::Withheld`; spec 10 X13a) |
    | `BudgetReconcile`, `PaymentSettlement` | cancellation receipt whose `financial` and settlement metadata carry the state actually reached (reconciled or not; captured, released or unknown; the rail reference) |
    | any other step, `Infrastructure` | cancellation receipt with `chio_runtime.post_effect_fault = { step, code, retained_ids, original_receipt_id }` |

    `code` is the registered code of the `PostEffectRejection` or infrastructure fault. On a durable obligation, `fail` writes nothing to receipts.db: it emits an operator fault (`audit_fault`), enqueues rule 23's reconciliation, and returns `DurableHandedToSaga`. The saga owns terminal truth.

    **Return contract.** `fail` always returns `Discharged`. `Discharged::deliver` then yields `Ok(signed fault response)` for `FaultReceiptCommitted`; `Err(KernelError::PostEffectFaultLatched { request_id })` for `FaultBuffered`; and `Err(KernelError::DurableOutcomePending { operation_id })` for `DurableHandedToSaga`.

    **Host interaction.** A host that signs a `trace_observation` for an evaluator `Err` (chio-cli, `handler.rs:59-87`) now sees `Err` only in the latched and durable-pending cases. Its `record_session_tool_failure` call goes through `ensure_receipt_persistence_ready` (M: `session_ops/reports.rs:79`). The kernel-evidence latch does not gate that call (rule 17), so the host's observation still records.

    The fault receipt deliberately differs from M:'s session-report `trace_observation` (M: `session-report-receipts.md:16-24`). A session report records a host's claim and carries no decision. Here the kernel itself observed the tool's return and decided to withhold delivery, so it signs a decision receipt. Where the kernel cannot tell whether the tool executed, the metadata carries `execution_outcome: "unknown"` with the same meaning as the session report (`:36-40`).

### 4.6 Hoisted receipt inputs

14. Before `enter_effect_boundary`, the evaluator builds `PreparedReceiptInputs` from inputs that are truly independent of the dispatch:
    - governed and model metadata;
    - attribution metadata;
    - the parameter hash (`allow_responses.rs:106-108`);
    - memory action classification;
    - the evaluation-entry authority time (M: `async_evaluation_core.rs:32-33`), carried as receipt metadata `chio_runtime.evaluation_started_at`;
    - a **pre-built, size-checked fault-receipt template**: the cancellation receipt body with retained markers, missing only the step, code and creation-time fields.

    Not hoisted, because they depend on the dispatch:
    - **the receipt `timestamp`.** It is the time the receipt was created (`spec/HTTP-SUBSTRATE.md:352`). The region reads authority time once, at step `AuthorityTime`, just before receipt content and signing. That value is the receipt `timestamp`, and it also feeds the recovery revalidation at `:1951`, which cannot fail on this path (section 2.2). This corrects M:'s entry-time stamp (section 2.2 item 3) without losing the admission instant, which `evaluation_started_at` keeps. A clock failure here is a post-effect failure, never a pre-dispatch one: the fault receipt is timestamped by its own read at creation, and if that read also fails, the unsigned record of rule 16 is buffered and signed at flush with the flush-time authority time;
    - `extra_metadata["financial"]`, produced after the effect by reconcile and settlement (`receipt_support/receipt_metadata.rs:629-643`);
    - provenance carried in the metadata the post-invocation pipeline returns (`:644`; `responses/finalization.rs:73-113`);
    - the memory-read provenance lookup (`responses/allow_responses.rs:80-85`), which means something different before the tool runs.

    A failure while building the hoisted inputs is a pre-dispatch failure, so it compensates and denies. Because the fault template is built and size-checked from hoisted inputs only, tool- or caller-controlled data cannot fail both the terminal receipt and the fault receipt. Only infrastructure (clock, key, store) can fail the fault receipt, and only infrastructure can trip the kernel-evidence latch.

### 4.7 Post-receipt steps

15. After `ReceiptCommitted`, terminal truth is fixed. These steps run in `Discharged::deliver`:
    - trace sequence allocation (`finish_record_chio_receipt`, M: `receipt_persistence.rs:442`);
    - the settlement claim's `read_authority_time()?` (`:467`, `:490`);
    - federation co-sign (`:256-260`);
    - security `record_released` (`security_dispatch.rs:24-36`) and `ensure_final_release` (`:170-177`);
    - the memory-provenance append (`allow_responses.rs:141`);
    - the nonce mint (`:150`).

    Each failure returns `DeliveryFailedAfterReceipt { receipt_id, step }`. The output is withheld, the receipt stands, and no second terminal receipt is signed. A security handle that never completes records its `OutcomeUnknownAfterDispatch` default from its own `Drop`. Caller and operator reconcile against the committed receipt.

### 4.8 Latch scopes

This section is the single definition of "latch" for specs 3, 4, 9 and 10.

```rust
pub enum LatchScope {
    KernelEvidence(BufferedRecordId), // kernel-wide new-dispatch gate; clears when that record flushes
    Operation(AdmissionOperationId),  // halts that one operation; cleared by re-projection from the store or by Cut
    SessionRequest(RequestId),        // spec 4 session-request latch
}
```

| Scope | Set by | Effect | Cleared by |
|---|---|---|---|
| `KernelEvidence(record)` | `fail` or obligation `Drop` on a non-durable call when the fault receipt cannot be persisted (rule 16), or `AppendOutcomeUnknown` (rule 28). Spec 9 effect `KernelEvidenceLatch { record }` | `ensure_post_effect_evidence_latch_clear()` denies new-dispatch admission kernel-wide | that record flushing (or, for rule 28, being discarded because the original committed). The gate opens when no `KernelEvidence` latch remains |
| `Operation(op)` | spec 9 effect `HaltOperation`: post-effect refusals (M11), `CommitOutcomeUnknown` (M12), post-effect `ReservationConflict`, and post-dispatch rows of the cut table. Also `CommitUnconfirmed` (rule 4) | that operation's driver halts; no other operation or tenant is affected | re-projection of the operation from the store, or a `Cut` |
| `SessionRequest(id)` | spec 9 effect `LatchRequest`; spec 4 drain | that request in that session makes no further progress | spec 4 drain completion |

Rules:

16. When `fail` or `Drop` cannot persist its fault receipt and no durable operation covers the call:
    - the kernel places the signed receipt, or an unsigned `PostEffectFaultRecord { observed_at: Option<UnixMillis>, evaluation_started_at, monotonic_elapsed_ms, .. }` if signing failed, into the obligation's own reserved slot of the `unrecorded_post_effect_receipts` buffer (rule 18). `observed_at` is `None` when the authority-time read itself failed; `evaluation_started_at` plus `monotonic_elapsed_ms` then bound the observation instant;
    - it sets `LatchScope::KernelEvidence(record)` at the failure point;
    - it emits `audit_fault`.
17. **A separate gate, a supervised flusher.**
    - `ensure_post_effect_evidence_latch_clear()` is checked only at new-dispatch admission: M: `async_evaluation_core.rs:160`, `nested_flow_evaluation.rs:336` and `dispatch.rs:767`. A latched kernel answers with the existing signed persistence deny.
    - It is not part of `ensure_receipt_persistence_ready` (M: `construction.rs:470`). So it never gates compensation staging with its terminal receipt (`admission_terminal_receipt.rs:285`), terminal-receipt outbox commit (`:839`) or recovery (`:974`), or session reports (`session_ops/reports.rs:79`). Holds keep draining and spec 4's drain can finish while the kernel is latched.
    - A supervised, single-flight flusher drains the buffer with exponential backoff, including while the kernel is idle. Requests never flush inline and never contend for `receipt_store_write_lock` under `receipt_append_budget` timeouts.
    - On flush, an unsigned record is signed at flush time and carries its original `observed_at` beside the signing time.
    - Readiness and status report `post_effect_fault_latched { buffered, oldest_observed_at }` beside spec 8's `host_latch` (spec 8 S20).
18. **Reserved evidence slots; no drop path.** The buffer never drops a record.
    - Each kernel owns a fixed pool of `post_effect_evidence_slots` (default 1024, configurable, at least 1). The buffer's capacity equals the pool.
    - A non-durable evaluation acquires one slot before `enter_effect_boundary`, as a ledger token (rule 21). If none is free, the call is denied before dispatch with the signed persistence deny and reason `post_effect_evidence_capacity`, and the ledger compensates. Durable calls take no slot, because the saga owns their evidence.
    - **The slot is a move-only token.** `EvidenceSlot` has private fields, no `Clone`, `Copy`, `Default` or `Deserialize`, and is returned only by `acquire_evidence_slot` (rule 21). Its `Drop` returns it to the pool. Its lifecycle is by move:
      - acquired before the boundary as the `CompensableReservation::EvidenceSlot` ledger entry, so pre-dispatch compensation, or the ledger's `Drop`, returns it;
      - moved into `PostEffectObligation::evidence_slot` by `enter_effect_boundary` (rule 4), so every obligation past the boundary owns exactly one slot;
      - dropped, and so returned, when `commit_terminal_receipt` or a fault receipt commits;
      - moved into the `BufferedPostEffectRecord` when `fail` or the obligation's `Drop` must buffer. The record owns the slot until it flushes, and flushing drops it.
    - `Drop` and `fail` can buffer only by moving their own slot, so a buffered record always has capacity and a slot can never be released while its record is pending.
    - Every evaluation past the boundary therefore holds a slot, and at most one record per slot can exist, so a buffered record always fits. The bound is per kernel, and so is the buffer. A host that builds one kernel per hosted session (M: `chio-mcp-remote` `session_core/factory.rs:381`) gets one pool and one buffer per session kernel, with no global session limit required.
    - While a `KernelEvidence` latch is set, new non-durable dispatch is already denied (rule 17), so the pool drains as records flush.

### 4.9 Work-profile durability rule

19. Every work-profile installer must reuse the D1 precedent:
    - the delegated-work guard (V: `delegated_work.rs:44-49`);
    - the W1 work service, the W2 owner services and funded (F1) composition (contract anchors).

    Each one must refuse installation without a qualified durable admission store and must call `require_durable_request_retention`. With retention required, a call whose effect class the mode does not cover is denied, not run ephemerally (V: `admission_coordinator.rs:559-569`). The post-effect region of a work call is therefore always owned by the saga.

    **Side effect.** `require_durable_request_retention` is kernel-wide (V: `kernel/construction.rs:794-795`), and with it set `requires_structured_admission` is true (V: `admission_coordinator.rs:526`). So under `SideEffecting` every `ReadOnly` call on a work-profile kernel is **denied** (`:564-569`), not run durably. A work-profile installer therefore requires a mode that covers `ReadOnly` (`All`). Spec 9's check-only eligibility excludes kernels that require retention, and such a kernel denies uncovered reads as today (section 4.12).

### 4.10 Release exits

20. No path in this design releases a hold on its own authority. `compensate_before_dispatch` releases only `compensable` entries, and only before `DispatchCommitted`. `CommitUnconfirmed` releases nothing. After an unknown terminal, the only hold release is `MutuallyAgreedUnknown` (V: `payment/journal.rs:88-96`; spec 9 M7a). `ContractualCaptureWaiver` resolves only a known return's positive pending capture in `Finalizing` (spec 9 M7b). Both are separately authorized. A post-effect refusal is not financial authority, and it never re-decides a payment the journal already records: a recorded capture, release or resolved waiver stands, an in-flight intent completes under its original identity, and only an `Open` positive hold is kept until the payment owner settles it (spec 9 M11a). Neither `fail`, `Drop`, a latch nor the flusher may construct a release. The post-execution releases inside monetary finalization are named by rule 27.

### 4.11 Safety predicates

```text
entered_effect_boundary(e) and non_durable(e) ->
    exactly_one_of(
      terminal_receipt_committed(e),
      post_effect_fault_receipt_committed(e),
      post_effect_fault_buffered(e) and latched(KernelEvidence(record(e))))

entered_effect_boundary(e) and non_durable(e) -> holds_evidence_slot(e)    (rule 18)
buffered_records(kernel) <= post_effect_evidence_slots(kernel)
receipt_timestamp(e) = authority_time_at_receipt_creation(e)              (rule 14)

entered_effect_boundary(e) and durable(e) ->
    (durable_outcome_recorded(e) or admission_terminalized(e) or reconciliation_enqueued(e))
    and receipts_db_terminal_records(e) = 0                  (rule 25; the saga owns the terminal)

append_outcome_unknown(e) -> no fault receipt for e until original_absent(e)
terminal_receipt_committed(e) -> no second terminal receipt for e     (rule 15)

latched(KernelEvidence(_)) -> not admits_new_dispatch(any evaluation)
latched(KernelEvidence(_)) -> admits(compensation, terminal_receipt_recovery, session_report)
halted(Operation(op)) -> no other operation is affected

dropped_before_boundary(r) and not dispatch_commit_submitted(r) -> compensation_attempted(r) and not latched
dropped_in_flight(r) -> retained(r) and reconciliation_enqueued(r) and not latched     (rule 29)
compensated(r) and dispatch_commit_submitted(r) -> proven_not_committed(r)
compensated(r) -> not entered_effect_boundary(r)
commit_unconfirmed(r) -> not compensated(r)
forall entry in Retained or Commitment: never compensated(entry)
forall entry: compensated_at_most_once(entry)              (move semantics)

security_released(e) -> terminal_receipt_committed(e) or durable_outcome_recorded(e)
release_hold(op) after unknown(op) -> authority(op) = MutuallyAgreedUnknown
waive_capture(op) -> finalizing(op) and known_outcome(op) and reversible_hold(op)
                     and pending_positive_capture(op)
zero_charge(op) -> recomputed_amount(op) = 0
                   or (contractual_delivery_denial(op) and reversible_hold(op))
delivery_refused(op) and payment_final(op) ->
    terminal(op) and no new settlement(op) and charge(op) = recorded_charge(op)
work_profile_installed -> forall call: durable_admission(call) or denied(call)
```

The receipts.db `exactly_one_of` predicate is scoped to non-durable calls. For durable calls, receipts.db carries no terminal record of its own, and the saga's terminal projection is the record.

Receipts are classified by spec 9 M20's signed `chio_runtime.identity_disposition`:
- **`Reusable` receipts end one attempt, not the request id.** Examples are tier-1 and fused-from-`Unbegun` stop denials (`retryable_after_resume = true`, spec 8 S15), `Overloaded`, check-only refusals and a check-only read's `Withheld { retry: AfterResume }`.
  - Within its attempt, a `Reusable` receipt still discharges that attempt's obligation: the `exactly_one_of` predicate applies per attempt.
  - The per-request predicate ("no second terminal receipt") counts only `Terminal` receipts, so a later attempt with the same request id may commit its one terminal receipt.
- **`Retained` receipts mark an unresolved attempt.** The ambiguous deny of rule 4's `CommitUnconfirmed` (spec 9 M12) is `Retained`. It is excluded from the per-request predicate, because the commit may have landed and recovery then records the request's one terminal: a compensation tombstone, or `OutcomeUnknownAfterDispatch`. If reconciliation proves that nothing committed, no terminal follows and a later attempt may commit its one terminal receipt.
- **`Terminal` receipts bind the request id.** Examples are a compensated `Prepared`-intent or slow-path stop denial, a deny tombstone, every terminal outcome, a `NonDurable` withheld effect, and the ambiguous deny of an unconfirmed non-durable invocation capture (rule 22). They are counted by every predicate above, so a stop denial on the slow path is not excluded.

```text
replay_identity(r) = (request_namespace_digest(r), request_id(r))
final(r) = decision(r) = Allow
        or decision(r) in { DenyDelivery, Cancelled, Incomplete, OutcomeUnknownAfterDispatch, NotAcceptedAfterDispatchCommit }
        or identity_disposition(r) = Terminal
        (an Allow carries no identity_disposition (spec 9 M20), so it is counted by its decision;
         Withheld is final only through its disposition: a NonDurable Withheld { retry: Never } is Terminal,
         every refused check-only read is Reusable, including retry: Never guidance (spec 9 M20);
         Retained, Reusable and PendingApproval receipts are never final)
terminal_receipts(ns, id) = { r : final(r) and replay_identity(r) = (ns, id) }
forall (ns, id): |terminal_receipts(ns, id)| <= 1
retained(r) -> eventually (exists t in terminal_receipts(replay_identity(r))) or proven_uncommitted(replay_identity(r))
```

### 4.12 Division with specs 9 and 10

Spec 3 predates specs 9 and 10 and overlapped them. The division is:

| Concern | Owner | What |
|---|---|---|
| Decisions | spec 9 | Events `PostEffectStepFailed { step: PostEffectStep, cause: PostEffectCause }` and `ReceiptAppendFailed { outcome: AppendFailure }` with `AppendFailure = { Refused, Unknown }`. A new `OperationClass::NonDurable` for calls outside the configured mode's coverage that are not check-only eligible, under `Monetary` or development `Off`. Rule 13's mapping as transition rows, with T8 as the discharge predicate. A kernel that requires durable request retention, under a mode that does not cover `ReadOnly`, denies the call as today (rule 19) |
| Execution | spec 10 | Executes discharge commits, including the receipts append for non-durable and check-only calls, and reports `Committed`, `Refused` or `Unknown` for that append |
| The affine driver contract | spec 3 | The obligation is minted on acknowledgement of `Dispatch`, `DispatchCommitAcknowledged` or `CheckOnlyAcknowledged`. It is discharged only by acknowledgement of a discharge-class effect: `OutcomeCommit`, `ReturnRecord`, `Terminalize`, an appended `SignReceipt`, or `KernelEvidenceLatch` with a buffered record |
| Latch | spec 3 | `LatchScope` (section 4.8). Spec 9 emits `HaltOperation`, `LatchRequest` and `KernelEvidenceLatch` |
| Post-effect errors | spec 3 | `PostEffectStep`, `PostEffectRejection`, and the opaque `PostEffectError` for port errors |
| Ledger | spec 3 | Limited to non-durable and slow-path in-memory participants. Each ledger kind maps to a fixed set of spec 9 participants (table below) |
| Escape hatches | spec 3 | The Mechanism D gate (section 5) |

Ledger kinds and spec 9 participants. The mapping is static. A unit test checks that it is total, so a new ledger kind cannot ship without its participants.

| Ledger kind | Spec 9 `Participant` |
|---|---|
| `InvocationIncrement` | `BudgetHold` (the counter lives in the budget store, `try_increment`, M: `budget_store.rs:646`) |
| `InvocationHold` | `BudgetHold` |
| `MonetaryCharge` | `BudgetHold`, plus `Payment` when an authorization is present |
| `RuntimeAdmission` | `RuntimeParticipantLedger` |
| `DispatchCredentials` | `DpopReplayLedger`, `GovernedApprovalLedger`, `ExecutionNoncePreflight` |
| `ChildBudgetLease` | none: an in-memory, reference-counted holder lease that is never persisted (M: `kernel_drop_guard.rs:328-341`). Spec 9 must either add a driver-local participant or state that drivers own it outside the machine |

The decision asked for a one-to-one mapping. `DispatchCredentials` bundles three participants and `MonetaryCharge` two, so the honest form is a fixed participant set per kind.

Sequencing:
- Phase 1 of this spec is the D1 fix on the legacy evaluator, in the umbrella's bug-fix lane. It needs no approval of specs 9 or 10.
- Spec 10's fused paths make pre-dispatch compensation unnecessary for fused durable calls, because the savepoint rolls back. The ledger then serves only non-durable calls and slow-path in-memory participants.
- The later phases of this spec (section 8, phases 3 onward) are re-specified against spec 9's phase 4 drivers before they are implemented.

### 4.13 Further rules

21. **Ledger tokens.** Every `CompensableReservation` payload is a token with private fields and no `Clone`, `Copy`, `Default` or `Deserialize`, returned only by its acquiring function. For example, `admit_capability_budget` returns `Option<ChildLeaseToken>`, and the invocation increment returns `InvocationIncrementToken`.
    - `push` accepts only tokens and returns a non-`Clone` `LedgerSlot`.
    - Releasing an entry consumes its token, so a duplicate release is a move error.
    - Over-releasing a holder lease "would free another evaluation's live share (a budget bypass)" (M: `kernel_drop_guard.rs:328-341`). That defect class (RFC-0002 F02, `ad64e8f40`, `818d1c5c9`) becomes unrepresentable.
    - `compile_fail` tests pin forging and duplicate release.
22. **Retained before dispatch.** `ledger.retain(slot, cause)` moves an entry from `compensable` to `retained` before the boundary. It is triggered in two cases:
    - on acknowledgement of an external payment authorization. The credentials are retained, because "retrying could duplicate a payment hold or minted authority" (M: `credential_reservation.rs:91-103`; call site `async_evaluation_core.rs:1252-1291`);
    - on an unconfirmed non-durable invocation capture, which keeps its hold and signs an ambiguous deny (M: `evaluation/invocation_capture.rs:57-77`). No durable operation exists for recovery to terminalize, so that deny is the request's one record and carries `identity_disposition = Terminal`. The retained hold is reconciled by the existing reserved-hold reaper, not by a later receipt.

    `compensate_before_dispatch` stamps retained entries as markers and never reverses them. M: already preserves "prior payment or irreversible nonce retention" on rejection (`dispatch_commit_failure.rs:8-10`).
23. **Post-dispatch drop of a durable future.** When a durable obligation is dropped, or `fail` hands a durable call to the saga, the kernel enqueues the operation to a supervised reconciliation job. No durable transition runs inside `Drop` (R: `02-rust-design.md:124`).
    - On the legacy evaluator, the job calls `terminalize_dispatch_committed_admission`. That call refuses when a durable outcome exists and freezes holds (M: `kernel_drop_guard.rs:530-548`).
    - Under spec 9, the job is a driver that feeds `Cut(DriverDropped)` or re-projects the operation.
    - The request id is not stranded until the next restart (M: `admission_coordinator/recovery.rs:395-399`).
    - A future dropped before the dispatch commit is submitted follows rule 6. One dropped after submission and before the acknowledgement follows rule 29.
24. **`Drop` work is contained.** Every `Drop` path in this design (ledger compensation, obligation fault receipt) runs inside `catch_unwind`, as `security_dispatch::callback` does (M: `security_dispatch.rs:8-22`). It skips host observers (`observe_runtime_trace` and the settlement observer, M: `responses/receipt_persistence.rs:457-492`). A panicking observer during unwinding would double-panic and abort, losing both the latch and the evidence.
25. **The durable failed-return path writes no receipts.db record.** At `async_evaluation_core.rs:1919` and `nested_flow_evaluation.rs:1705`, a failed `record_durable_tool_return` no longer builds a signed `Deny` response.
    - The evaluator returns the error. The operation stays `DispatchCommitted`, and rule 23 enqueues reconciliation.
    - The saga's `OutcomeUnknownAfterDispatch` terminal is the only terminal record.
    - Both `let _ =` discards disappear, so neither is allowlisted.
26. **Coverage follows the admission handle, not the mode.** The obligation, the fault mapping and the kernel-evidence latch apply whenever `durable_admission` is `None`, under any `DurableAdmissionMode` (section 2.3).
27. **No discarded post-execution release.** The two `let _ = adapter.release(..)` sites in monetary finalization are replaced by recorded outcomes:
    - **`validation.rs:1733` (capture failed after execution; delivery denied).** A capture failure is not pricing authority, and the executed call has no zero-charge contract, so this site no longer releases. The authorization stays open for the payment owner's reconciliation. The deny receipt's settlement metadata records `release_outcome: not_released`, the authorization id and the capture error code, with retained markers and an `audit_fault`. `ContractualZeroCharge` applies only under spec 9 M11a's conditions, a zero amount or a verified contractual delivery denial under a reversible hold, and neither holds here. A later release needs the payment owner's own authority.
    - **`validation.rs:1747` (capture returned a status other than `Settled`; output delivered under `Allow`).** This is rail settlement cleanup, not hold compensation. The release result is recorded in `ReceiptSettlement` (`release_outcome`), and a failed release emits `audit_fault`, so the stuck authorization can be reconciled.

    Whether this site should release on `Pending` or `Captured` at all is open decision 6. A fault receipt after a successful capture carries the post-reconcile financial state and the settlement reference, never stale `retained_ids`.
28. **Receipt append outcome unknown.** A bounded append that times out is inflight-preserving: the writer actor still owns the job and may commit it later (chio-store-sqlite `receipt_store.rs:918-924`; M: `receipt_persistence.rs:392-396`).
    - Such a timeout maps to `AppendOutcomeUnknown` (spec 9 `ReceiptAppendFailed { Unknown }`).
    - The kernel buffers the fault record and sets `KernelEvidence(record)`. It appends no fault receipt until the writer drains and `load_chio_receipt(original_id)` reads the original back as absent.
    - If the original is present, it stands: the fault record is discarded, and that latch clears.
    - Fault receipts always name `original_receipt_id`.
29. **Drop while the dispatch commit is in flight.** `enter_effect_boundary` tracks whether its dispatch commit (`commit_durable_dispatch` or `capture_and_commit_durable_dispatch`, or spec 10's `DispatchIntent` member) has been submitted to the store. A dropped future cannot prove that a submitted commit did not land, so this is `CommitUnconfirmed` (rule 4), never pre-dispatch compensation.
    - Before submission, the boundary still owns an unconsumed ledger, and rule 6 applies.
    - After submission and before the acknowledgement, `Drop` moves every entry to retained and hands the commit's reply (or the operation id, where there is no reply handle) to the supervised reconciliation job of rule 23. It compensates nothing, releases no in-memory lease and sets no latch.
    - The job waits for the store's terminal outcome. On `DispatchCommitted` it proceeds as rule 23, and the operation ends outcome-unknown. When the outcome proves no commit (a refusal, or a read-back at the expected version or with no row under the replay key), the job compensates as rule 6 does, including the in-memory items. On an unknown outcome, the holds stay retained and restart reconciliation decides (rule 4).
    - **Legacy window.** On M:, both dispatch-commit calls are synchronous `fn`s (M: `admission_coordinator.rs:1560`, `:1814`). An async future cannot be dropped inside them, so this window is empty on the legacy evaluator today. The rule binds as soon as the dispatch commit becomes an awaited submission: spec 10's writer loop, or any async store. Spec 9 M17 states the same rule for drivers.

## 5. Mechanism D gate: `cargo xtask check escape-hatches`

This is the gate M: unrepresentable-defects specifies (`:440-452`) and never built (RP6, `:516`). It is modeled on `xtask/src/adapter_no_bypass.rs`, which is syn-based (syn 2, `full` and `visit`) on the stable toolchain.

1. **The allowlist.** It lives in `formal/escape-hatches.toml`.

   **Entry schema.**
   - Required fields: `path`, `fn` (the enclosing item path), `ordinal` (the nth match inside that item), `kind` and `reason`.
   - Optional `expiry` (a date). It is required for spec 1's `handle_export` entries (spec 1 section 6).
   - Optional `cfg` (a predicate such as `test` or `feature = "test_support"`).

   Entries are keyed by (`path`, `fn`, `ordinal`), never by line.

   **Initial entries.**
   - The existing named hatches found by the workspace family scan:
     - `kernel/mod.rs:634`;
     - `tool_outcome/release.rs:221`;
     - `receipt_analytics.rs:87`;
     - `security_binding.rs:57` and `:70`;
     - chio-store-sqlite `economic_state_cache.rs:195` (`from_stored`).
   - Spec 1's `install_native_capture_observer_for_test`.
   - The single `ManuallyDrop` inside `PostEffectObligation::into_parts` (rule 8).

   **Not entries.**
   - The durable `let _ =` discards (removed by rule 25) and the payment-release discards (removed by rule 27).
   - W:'s quarantine discards in `LaunchCustody::drop` and `ConfinedExecution::drop`. They live in chio-control-plane and call no receipt builder, so no rule flags them.
   - The Kani `assume_*` helpers. They are not an escape-hatch family.
2. **Rules in `chio-kernel`.** The scope is the whole crate, including the five `.inc` files: `admission_operation.part1.inc` to `part3.inc`, `kernel/active_response_coordinator/execution_validation.inc` and `kernel/admission_cleanup/recovery_and_compensation.inc`. The gate follows each `include!` and parses the included file as items of the including module, closing the parent's Q1 blind spot.
   - Deny `mem::forget`, `ManuallyDrop` and `Box::leak` outright. chio-kernel has zero uses today. The only exception is the allowlisted `into_parts`.
   - Deny `impl From<PostEffectError>` anywhere.
   - Deny every discard of a result from these functions:
     - `record_chio_receipt*`, `append_chio_receipt*` and `build_*_response*`;
     - `commit_terminal_receipt` and `fail`;
     - the payment adapter methods `release`, `capture` and `refund`.

     The discard forms are `let _ = e;`, `_ = e;`, `let _name = e;` with the binding unused, `e.ok();`, `drop(e)` and `if let Ok(_) = e`. The visitor is recursive: it descends into closures, blocks and macro arguments that parse as expressions, so `let _ = f(.., || build_deny_..())` is caught.
   - No closure heuristics. The revision 3 rule about "map_err closures that discard a `PostEffectError`" needed type information that syn lacks. Its job is done by types: `PostEffectError` is opaque and has no accessor that yields a `KernelError`.
3. **Naming families, workspace-wide.** The gate denies any new function matching a family that is not on the allowlist:
   - suffix `_for_test`;
   - prefixes `from_stored`, `from_raw`, `into_raw_` and `from_trusted_`.

   Items under `#[cfg(test)]` are exempt. Items under `cfg(feature = "test_support")` need an entry with that `cfg` predicate. The workspace scan found 6 matches, so workspace scope is cheap (this resolves revision 3's open decision 5).
4. **Ratchet.** The gate compares against the merge base (`git merge-base HEAD origin/main`).
   - Removing an entry passes.
   - Adding an entry requires an edit to the CODEOWNERS-protected allowlist.
   - An entry whose target no longer exists fails as stale, so the file can only shrink without review.
   - A self-test runs one violating fixture per rule, plus one `.inc` fixture and one closure-nested discard fixture.
5. Sibling specs register their own entries here rather than inventing new allowlists (spec 1's `handle_export` and `test_support` entries).

The gate inherits the hardening toolchain's GT1 limitation (hardening gates not yet in hosted CI). It lands in `scripts/ci-pr-tier.sh` in the same PR.

## 6. Failure modes

| Point of failure | Today (M:) | With this design |
|---|---|---|
| Future dropped before dispatch (disconnect, timeout, `select!`) | guard compensates | ledger `Drop` compensates best-effort in the same order; in-memory leases released synchronously; durable step enqueued if it cannot run; never latches (rule 6) |
| Boundary step rejected before commit | per-site cleanup | `RejectedBeforeCommit`: compensates `compensable` entries and denies |
| Dispatch commit unconfirmed | holds and credentials retained, ambiguous deny | unchanged: `CommitUnconfirmed` retains everything, signs the ambiguous deny, never compensates (rule 4) |
| External authorization acknowledged, later pre-dispatch failure | credentials retained by flag | `retain(slot, ExternalAuthorizationAcknowledged)`; stamped, never reversed (rule 22) |
| Security `record_released` fails | `?` before finalization, guard armed | runs after the receipt; `DeliveryFailedAfterReceipt`, output withheld, receipt stands |
| Credential commit fails after tool `Ok` | ambiguous receipt from guard `Drop` | `fail(CredentialCommit)`, synchronous |
| Transport-failure arm cannot build its receipt | bare `Err` after disarm | `fail(TransportFailureReceipt)`: fault receipt from the template, else buffer and latch |
| Authority time fails at receipt creation | bare `Err`, no receipt | `fail(AuthorityTime)`: fault receipt timestamped by its own read; if that read also fails, the unsigned record goes into the call's reserved slot, the `KernelEvidence` latch is set, and the flusher signs it at flush time (rules 14, 16) |
| No free evidence slot | not applicable | denied before dispatch with `post_effect_evidence_capacity`; the ledger compensates (rule 18) |
| Post-invocation error, stream limit, output contract | bare `Err`, no receipt | deny-delivery receipt, retained markers |
| Revocation seen at persistence | bare `Err`, no receipt | deny-delivery receipt |
| Budget reconcile or payment settlement fails | bare `Err` or discarded release result | fault receipt carrying the reached financial and settlement state (rules 13, 27) |
| Canonicalization, signing or append refused (non-durable) | bare `Err`, no receipt | fault receipt, else buffer and `KernelEvidence` latch |
| Append times out (non-durable) | `Err`; the write may still commit | `AppendOutcomeUnknown`: buffer and latch; fault receipt only after read-back shows the original absent (rule 28) |
| Federation co-sign, trace allocation or settlement claim fails after the append | `Err` after a committed receipt | `DeliveryFailedAfterReceipt`; no second terminal receipt |
| Durable return record fails | saga recovers, plus a contradictory `Deny` receipt | saga recovers; no receipts.db record (rule 25) |
| Durable future dropped after dispatch | guard `Drop` terminalizes best-effort | supervised reconciliation job; same terminal, no transition in `Drop` (rule 23) |
| Future dropped with the dispatch commit in flight | cannot happen: both dispatch-commit calls are synchronous | `CommitUnconfirmed`: retain, reconcile from the store's outcome, compensate only when it proves no commit (rule 29) |
| Post-receipt provenance or nonce failure | bare `Err` | `DeliveryFailedAfterReceipt { receipt_id }` |
| Panic in the post-effect region | guard `Drop` only if still armed | obligation `Drop` under `catch_unwind`: best-effort fault receipt, else latch (non-durable); reconciliation (durable) |
| Panicking host observer during `Drop` | double panic, abort | observers skipped on `Drop` paths (rule 24) |
| Process crash, non-durable post-effect | unrecorded | unrecorded (residual; use durable coverage) |

## 7. Protocol, schema and wire impact

- `spec/PROTOCOL.md` section 6 gains one sentence: a call that reached the effect boundary without durable admission yields its terminal receipt or a cancellation or deny-delivery receipt carrying `chio_runtime.post_effect_fault`.
- One optional receipt metadata object, `chio_runtime.post_effect_fault = { step, code, retained_ids, original_receipt_id, observed_at }`. It needs no registry change, because `chio_runtime` keys are not registry-scoped. `observed_at` differs from the signing time only for records signed at flush.
- One optional settlement field, `release_outcome`, on the two monetary finalization paths (rule 27).
- One optional receipt metadata key, `chio_runtime.evaluation_started_at`. A non-durable receipt's `timestamp` becomes its creation time, as `spec/HTTP-SUBSTRATE.md:352` defines it, instead of M:'s evaluation-entry time (rule 14). Verifiers are unaffected, because the field's type is unchanged; consumers that ordered by admission time read `evaluation_started_at`.
- `PostEffectRejection` codes come from the `chio-errors` registry, which also advances the parent design's one-registry goal (CA7).
- Some calls that returned a bare error now return a signed `Deny`, `Cancelled` or `Withheld` response. `DeliveryFailedAfterReceipt`, `PostEffectFaultLatched` and `DurableOutcomePending` are new Rust API variants. Readiness gains `post_effect_fault_latched`.
- No negotiation. Receipts stay valid under v1 verifiers.

## 8. Rollout

1. **Phase 1, the D1 fix (bug-fix lane, legacy evaluator).**
   - Add `effect_obligation.rs` with `post_effect -> Discharged`, `commit_terminal_receipt` minting at the commit point, `into_parts`, and the post-receipt tail.
   - Port the post-dispatch half of `PostAdmissionDropGuard` at both `mark_dispatch_started` sites and in the transport-failure arms, and remove the early disarm.
   - Move the security release after the receipt.
   - Add `LatchScope::KernelEvidence` with its own gate and the supervised flusher (rules 16-18, 28).
   - Remove the durable `Deny` write (rule 25), replace the release discards (rule 27), and contain `Drop` (rule 24).

   This fixes section 2.2.
2. **Mechanism C and D.** Add the opaque `PostEffectError`, `PostEffectRejection` with registered codes, the `fail` mapping (rule 13), the persistence revocation change, and `cargo xtask check escape-hatches` with its initial allowlist.
3. **Ledger.** `AdmissionReservations` with tokens, `retain`, and the three entry classes. Replace `PreDispatchCleanupDeny` field lists and the remaining guard flags (rules 1-6, 21, 22). Pre-dispatch `Drop` compensation keeps M:'s behavior throughout.
4. **Hoisting, post-receipt rule, work-profile rule, reconciliation job.** Rules 14, 15, 19 and 23.
5. **Spec 9 drivers.** Phases 3 and 4 are re-specified against spec 9's phase 4 drivers (section 4.12) before they are implemented. From that point the obligation is minted and discharged by machine acknowledgements, and rule 13 is replaced by spec 9's rows.

Following the RFC-0002 precedent, each phase ships as the only behavior.

**Durable behavior changes in two places, and only there:**
- a failed durable return no longer writes a signed `Deny` receipt beside the saga's terminal (rule 25);
- a durable future dropped after dispatch is terminalized by the supervised reconciliation job instead of from `Drop` (rule 23). The terminal is the same, and the request id is still not stranded until restart.

`CommitUnconfirmed` keeps M:'s retain-and-ambiguous-deny exactly. Pre-dispatch drop keeps M:'s compensation.

## 9. Tests and conformance evidence

- **Compile-fail** (rustdoc `compile_fail`, per M: unrepresentable-defects acceptance), each pinning its failure reason:
  - return from `post_effect` without `Discharged` (including `?` on a `KernelError` and `return Err(..)`);
  - `?` on `PostEffectError` in a `KernelError` function;
  - destructuring or reading `PostEffectError`'s cause outside its module;
  - `PostEffectObligation` and `Discharged` are not `Clone`;
  - `Discharged` cannot be constructed outside its module;
  - forging a ledger token;
  - double compensation or duplicate release;
  - compensating a retained entry or an `ExternalCommitment`.
- **Negative tests.**
  - `CommitUnconfirmed` never reverses a hold or a credential, and signs the ambiguous deny with retained markers.
  - A retained-before-dispatch credential is never rolled back by a later pre-dispatch failure.
  - `commit_terminal_receipt` with a receipt for another request id, operation id or a non-terminal decision does not discharge.
  - A failed durable return writes no receipts.db record.
- **Proptest** (`src/kernel/tests/drop_guard_proptest.rs`):
  - drop the future at every pre-dispatch await point. Compensation runs in M:'s order, no latch is set, and no in-memory lease leaks;
  - {failing post-effect step, including transport-failure arms, budget reconcile and payment settlement} x {durable, non-durable under `SideEffecting`, `Monetary` and `Off`, work profile} x {drop, return}. Assert the section 4.11 predicates against the receipt store, the latches and the security recorder.
- **DST.**
  - `CrashBoundary::FailAppendAfterDispatch`.
  - `AppendTimeoutThenLateCommit`: no second terminal receipt, and the latch clears after read-back.
  - Post-dispatch durable drop: the request id's replay resolves without a restart.
  - Drop with the dispatch commit submitted but unacknowledged, under an awaited store: nothing is compensated before the outcome. A commit that lands ends outcome-unknown, and a refused one compensates (rule 29).

  Seeds go in `tests/dst/seeds.toml`.
- **loom** (`tests/loom_concurrency.rs`):
  - a latch set races a new-dispatch check, and a check ordered after the set must deny;
  - the flusher is single-flight under contending requests;
  - slot acquisition races a latched flush: no evaluation passes the boundary without a slot, and a record always fits;
  - compensation and outbox recovery proceed while latched.
- **Unit:**
  - each rule 13 row produces its decision, metadata and registered code;
  - the security outcome records `Released` only after the receipt commit;
  - the ledger unwind order equals `handle_pre_dispatch_drop`;
  - the ledger-to-participant mapping (section 4.12) is total;
  - a tool output large enough to fail the terminal receipt cannot fail the fault receipt;
  - a slow tool's receipt `timestamp` is at or after the tool's completion, and `evaluation_started_at` is at or before dispatch;
  - slot exhaustion denies before dispatch with `post_effect_evidence_capacity`, and compensation runs;
  - a `Discharged` whose binding differs from the region's obligation is never delivered and sets the `KernelEvidence` latch;
  - a panicking host observer during `Drop` does not abort;
  - a payment release failure is recorded in settlement metadata;
  - a capture error after execution at `validation.rs:1733` leaves the authorization open, records `release_outcome: not_released` with the authorization id, and emits `audit_fault`. No `ContractualZeroCharge` is named (rule 27);
  - work-profile installers refuse without durable coverage and refuse `SideEffecting` with retention.
- **Gate.** One violating fixture per section 5 rule, including a closure-nested discard and an `.inc` file; the allowlist passes; a stale entry fails.
- **Mutation.** Per engineering standard rule 10.2: removing the binding check, minting after federation co-sign instead of at the commit point, or moving `record_released` before the receipt must each fail a named test.
- **Unchanged:** reservation law (`tests/property_reservation_ledger.rs`, `kernel/ledger_audit.rs`).
- **chio-conformance** `post_effect_receipt_fault`: a non-durable call (`ReadOnly` under `SideEffecting`, and a mutating tool under `Monetary`) whose append fails after dispatch yields a fault receipt or a latched deny on the next call, never a silent success.

## 10. Alternatives considered

- **Pre-reserve a receipt-log slot.** Rejected:
  - it moves the post-effect write instead of removing it;
  - void records for denied calls create gaps that ADR-0013 treats as audit faults;
  - it adds a pre-dispatch fsync to read-only calls.

  Revisit when ADR-0013's WAL lands.
- **Default `DurableAdmissionMode::All`.** It closes the crash window too, at about 40 durable writes (M: `AGENT_PROCESS_DIRECTION.md:150-166`) and 10 authority commits per side-effecting call (spec 10 section 2.1, re-derived on M:). That is left to open decision 1. This design is still needed under `All`, because rules 1-6, 12-13 and 21-25 harden the durable evaluator too.
- **Latch the kernel on a pre-dispatch drop (revision 3).** Rejected: the drop is routine, and it would close the kernel or leak holds (S3-01).
- **A free-standing discharge token minted by every recorder (revision 3).** Rejected: a token from one receipt could discharge another obligation (S3-06).
- **A generic participant trait over stores.** Rejected as a parallel abstraction; the admission design owns store contracts.
- **`trace_observation` for post-effect faults.** Rejected; see rule 13.

## 11. Residual risks and open decisions

Residual risks:

- Rust types are affine. `post_effect -> Discharged` closes the evaluator body, and the gate covers the obvious spellings of `forget` and leaks, but `Drop` remains a runtime backstop.
- A crash in the non-durable post-effect region stays unrecorded. The latch buffer is in memory.
- The buffer has no drop path, because every non-durable call past the boundary holds a reserved slot (rule 18). The cost is that slot exhaustion denies new non-durable dispatch before the boundary.
- A post-receipt delivery failure leaves an `Allow` receipt for output the caller never received. That is by design: terminal truth is the decision, and `DeliveryFailedAfterReceipt` names the receipt for reconciliation.
- A connection that misdeclares a mutating tool as `ReadOnly`, or a deployment that selects `Monetary`, still avoids durable admission outside work and process profiles. This design records those calls; only durable coverage makes them crash-safe.
- GT1: the gate is local-only until the hardening gates run in hosted CI.
- W: is built on the older #1160 checkpoint `f25cd61f4`, where the early disarm sits at `async_evaluation_core.rs:1751`. Its edits to `terminal.rs`, `security_release.rs` and `admission_coordinator.rs` will move every evaluator citation here when it is rebased onto M: head. Re-pin before implementing.

Open decisions:

1. **Default mode outside work and process profiles, and `Monetary` in production.** Should production profiles of the MCP edge and HTTP sidecar default to `All`? Should production profiles refuse `Monetary`, which runs every non-monetary mutating tool without durable admission (section 2.3)? Recommendation: refuse `Monetary` in production profiles now, and measure `All` with the kernel bench before changing the default.
2. **Buffer durability.** Back the latch buffer with the ADR-0013 WAL once it exists? Recommendation: yes.
3. **Post-receipt failures.** Add a supplemental signed incident receipt linked to the allow receipt, beyond `DeliveryFailedAfterReceipt`?
4. **Directive pushback, recorded.** The revision 2 directive asked for a new rule that work profiles require durable admission. The evidence shows D1 already enforces it, fail-closed (V: `delegated_work.rs:44-49`; `admission_coordinator.rs:525-532`, `:559-569`). Rule 19 therefore generalizes the shipped mechanism to the other installers rather than adding a new one. Whether W1 and W2 reuse `install_delegated_work_with_layout`'s check directly or a shared helper is open.
5. **Escape-hatch naming families.** Resolved in revision 4: workspace-wide, because the scan finds only 6 matches (section 5 item 3).
6. **Release on a capture that is not `Settled`.** M: releases the authorization after every capture whose status is not `Settled`, including `Pending` and `Captured` (`validation.rs:1745-1748`). Should it release only on `Failed`, leaving `Pending` and `Captured` held for reconciliation through the payment journal? Recommendation: yes, after the payment owners confirm each rail's semantics for releasing a captured authorization.

## Review disposition

| Finding | Severity | Disposition |
|---|---|---|
| S3-01 pre-dispatch drop latches and leaks | Blocker | Applied: rule 6 restores best-effort compensation in M:'s order, releases in-memory leases synchronously, enqueues the durable step, never latches |
| S3-02 boundary compensates an unconfirmed commit | Blocker | Applied: `BoundaryFailure::{RejectedBeforeCommit, CommitUnconfirmed}` (rule 4), negative test |
| S3-03 "latch" means three things | Blocker | Applied: `LatchScope` in section 4.8 is the single definition; spec 9's three effects named there |
| S3-04 latch inside the readiness gate, flushed inline | Major | Applied: separate gate at new-dispatch admission only, supervised single-flight flusher, flush-time signing with `observed_at`, readiness reporting (rule 17); fault receipts built only from the hoisted template (rule 14) |
| S3-05 token minted after fallible post-append steps; timed-out append may commit | Major | Applied: minted at the commit point (rule 7); post-append steps are post-receipt (rule 15); `AppendOutcomeUnknown` with read-back (rule 28); `original_receipt_id` |
| S3-06 discharge not bound to its obligation | Major | Applied: consuming `commit_terminal_receipt` checks request, operation and decision; recorders and startup recovery mint nothing (rule 7) |
| S3-07 infallible discharge runs fallible callbacks | Major | Applied: `Discharged::deliver -> Result<_, DeliveryFailedAfterReceipt>`; `SecurityRelease` removed from `PostEffectStep`; post-receipt list in rule 15 |
| S3-08 inventory misses arms, armed steps and monetary finalization | Major | Applied: section 2.2 groups (a)-(d); new steps `TransportFailureReceipt`, `SessionBookkeeping`, `ChildReceiptFlush`, `UrlElicitationCancel`, `BudgetReconcile`, `PaymentSettlement`; release discards classified (rule 27); open decision 6 |
| S3-09 "compile error" overstated | Major | Applied: `fn post_effect(..) -> Discharged` with a private constructor (rule 12), `compile_fail` test, goal reworded |
| S3-10 wrong Mechanism C enum; RP2 claim | Major | Applied: `PostEffectRejection` with registered codes, opaque `PostEffectError`; RP2 claim withdrawn |
| S3-11 entries retained before dispatch | Major | Applied: `retain(slot, cause)` and `RetentionCause` (rule 22) |
| S3-12 ledger entries are plain values | Major | Applied: tokens with private constructors, `LedgerSlot`, `compile_fail` tests (rule 21) |
| S3-13 ownership shape does not compile | Major | Applied: the obligation owns the admission and the charge; private `into_parts` with one allowlisted `ManuallyDrop` (rule 8) |
| S3-14 strands request ids until restart | Major | Applied: supervised reconciliation job (rule 23); section 8's durable claim corrected |
| S3-15 overlap with specs 9 and 10 | Major | Applied: section 4.12 division; rule 13 kept as the legacy phase 1 mapping; later phases re-specified against spec 9 drivers |
| S3-16 `Monetary` exposure | Major | Applied: section 2.3, rule 26, open decision 1 |
| S3-17 hoists dispatch-dependent inputs | Minor | Applied: rule 14 hoists only dispatch-independent inputs plus a pre-built fault template |
| S3-18 `RecoveryRevalidation` unreachable | Minor | Applied: step removed, section 2.2 item 3 and section 6 row corrected |
| S3-19 recovery commitments have nowhere to be pushed | Minor | Applied: moved to the non-normative table in section 2.5; `ExternalCommitment` keeps only observed D1 and F1 entries |
| S3-20 gate underspecified | Minor | Applied: section 5 rewritten (schema with `fn`, `ordinal`, `expiry`, `cfg`; recursive visitor; discard forms; outright deny of `forget`/`ManuallyDrop`/`Box::leak`; `.inc` files; families with `from_stored`; merge-base ratchet; W: discards dropped) |
| S3-21 allowlisted durable discard not harmless | Minor | Applied: rule 25 removes the `Deny` write; section 4.11 scoped per path |
| S3-22 `fail` contract underspecified | Minor | Applied: rule 13 return contract per case, durable `fail` is operator fault only, host interaction documented |
| S3-23 panic in `Drop` aborts | Minor | Applied: rule 24 (`catch_unwind`, no host observers) |
| S3-24 rule 19 denies reads on work-profile kernels | Minor | Applied: rule 19 side effect stated, installer requires `All`; spec 9 eligibility exclusion delegated to spec 9 (section 4.12) |
| S3-25 stale cross-references | Nit | Applied here: 11 commits corrected to 10 (section 10). The references in specs 9, 10 and the umbrella are owned by those files; see the report to the parent |
| S3-26 counts and paths | Nit | Applied: 16 `disarm()` calls including `kernel_drop_guard.rs:217`; proptest path `src/kernel/tests/drop_guard_proptest.rs` |

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180274493 | Propagate failures from the discharge step | Already addressed in revision 4. Security release runs after the receipt in `Discharged::deliver`, which returns `Result<ToolCallResponse, DeliveryFailedAfterReceipt>`; output is withheld and the receipt stands. `fail` records `OutcomeUnknownAfterDispatch` | Section 4.4; rules 9 and 15 |
| 4180274494 | Preserve receipt creation time after tool execution | Fixed now. Authority time is no longer hoisted. The receipt `timestamp` is read at receipt creation (step `AuthorityTime`), which also corrects M:'s evaluation-entry stamp. The entry time travels as `chio_runtime.evaluation_started_at` | Section 2.2 item 3; rules 14 and 16; section 6; section 7 |
| 4180274499 | Do not discard overflowed post-effect records | Fixed now. Each non-durable evaluation reserves an evidence slot before the boundary, or is denied before dispatch. The buffer's capacity equals the slot pool, so a record always fits and the drop path is gone | Rules 16 and 18; section 4.11; section 11 |
| 4180274502 | Bind each discharge token to its obligation | Already addressed in revision 4: there is no free token. `Discharged` comes only from consuming its own obligation, and `commit_terminal_receipt` checks request id, operation id and decision. This round adds a fail-closed runtime binding check in `run_post_effect` | Rule 7; section 9 |

### Codex review (PR #1174, round 2)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180839034 (spec 9) | Do not compensate while the intent commit is still in flight | Fixed in spec 9 M17. Mirrored here as rule 29, so the affine contract matches: a drop after submission and before the acknowledgement is `CommitUnconfirmed`, retains everything, and is reconciled from the store's outcome. On M: the window is empty today, because both dispatch-commit calls are synchronous, and the rule binds once the commit becomes awaited | rules 6, 23, 29; section 4.11; section 6; section 9 |

### Independent review pass 2 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-8-02 (alignment) | Slow-path terminal stop denials are marked retryable after resume | Fixed here for the predicates. The stop-receipt exclusion now keys on spec 9 M20's `identity_disposition`. `Reusable` receipts end one attempt but not the request id. `Terminal` receipts, including compensated slow-path and `Prepared`-intent stop denials, are counted by every predicate | section 4.11 |

### Codex review (PR #1174, round 4)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180933161 | Carry the reserved evidence slot into the obligation | Fixed now. `EvidenceSlot` is a move-only token: a `CompensableReservation::EvidenceSlot` ledger entry before the boundary, moved into `PostEffectObligation::evidence_slot` by `enter_effect_boundary`, dropped (returned) when a terminal or fault receipt commits, and moved into the buffered record on `fail` or `Drop` until it flushes. `RejectedBeforeCommit` returns it; `CommitUnconfirmed` carries it | section 4.3 enum; rule 4; section 4.4 struct; rule 18 |

### Independent review pass 3 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-6-07 (counting side) | An ambiguous commit denial binds the adapter before recovery produces the terminal receipt | Fixed. Rule 4's `CommitUnconfirmed` deny carries `Retained`. Section 4.11 counts only `Terminal` receipts per request, so the ambiguous deny and the recovery terminal no longer both count. A `Retained` receipt is followed by the terminal or by a proof that nothing committed. An unconfirmed non-durable capture's deny stays `Terminal`, because no durable operation will be terminalized | rule 4; rule 22; section 4.11 |

### Codex review (PR #1174, round 14)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186767784 | Scope terminal receipts to the replay identity | Fixed now. The predicate filters by `replay_identity(r) = (request_namespace_digest, request_id)`. At most one `Terminal` receipt exists per replay identity, and legal reuse of a request id across namespaces is not conflated | section 4.11 |

### Codex review (PR #1174, round 15)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186909727 | Count successful outcomes as terminal receipts | Fixed now. The predicate counts `final(r)`: an `Allow`, which carries no disposition under spec 9 M20, any terminal outcome decision, or a `Terminal` disposition. `Retained`, `Reusable` and `PendingApproval` are never final, so an `Allow` plus a second terminal receipt for one replay identity violates the predicate | section 4.11 |

### Codex review (PR #1174, round 17)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187142778 | Exclude reusable withheld receipts from the final set | Fixed now. `Withheld` is no longer counted by decision. It is final only through its disposition: `Terminal` for a `NonDurable` `retry: Never` withheld, `Reusable` for a check-only `retry: AfterResume` withheld. A later `Allow` after a reusable withheld therefore satisfies the at-most-one invariant | section 4.11 |

### Independent review pass 5 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-9-03 (spec 3 side) | A withheld result is incorrectly sufficient authority for zero-charge settlement | Fixed with spec 9 M11a. `ContractualZeroCharge` needs a zero recomputed amount or a verified contractual delivery denial under a reversible hold. `PostEffectRejection` splits ordinary `OutputContract` from `ContractualDelivery(DeliveryDenialReason)`, which only the durable finalizer can produce. Rule 27's capture-error site no longer releases: the authorization stays open for the payment owner, with `release_outcome: not_released` and an `audit_fault` | section 2.6; section 4.5 enum and rule 13; rule 20; section 4.11 predicates; rule 27; section 9 unit test |
| R-9-04 (spec 3 side) | The machine puts contractual capture waivers in the wrong execution phase | Fixed with spec 9 M7b. Only `MutuallyAgreedUnknown` releases an unknown hold. `ContractualCaptureWaiver` resolves a known return's positive pending capture in `Finalizing`, and the predicates state each phase separately | section 2.6; rule 20; section 4.11 predicates; revision 2 note |
| R-9-05 (spec 3 side) | Delivery refusal strands a payment whose ordinary capture already completed | Fixed with spec 9 M11a. Rule 20 and the predicates say that a refusal never re-decides a journal that already records a capture, release or resolved waiver; such an operation terminalizes with the recorded charge. Only an `Open` positive hold waits for the payment owner | rule 20; section 4.11 predicates |

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
- **Drop.** FTL's `Drop` releases capacity it fully owns, under `panic = "abort"` (`Cargo.toml:26`, `:29`). Chio's pre-dispatch `Drop` may compensate best-effort, because nothing crossed the boundary, but its post-dispatch `Drop` may only record evidence, latch, or hand off to supervised reconciliation (rules 6, 11 and 23). Some Chio reservations (`ExternalCommitment`) have no owner the kernel could release them to at all.
- **Ownership.** FTL's reservations live under one spinlock. Chio's ledger is only the in-process view of reservations whose truth lives in the stores.

### PR #1174 review round 33

| Review | Issue | Disposition | Contract |
|---|---|---|---|
| 4198110084 (spec 3 side) | Align the terminal-count predicate with stateless reads | Fixed. The predicate counts a Withheld receipt only when its disposition is Terminal; all check-only refusals are Reusable even when automatic retry is discouraged | Section 4.11; spec 9 M20 |
