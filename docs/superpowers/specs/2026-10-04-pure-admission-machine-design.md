# Design: pure admission machine

- Status: PROPOSED (revision 1, baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5)
- Date: 2026-10-04
- Scope: one sans-IO transition function over one admission operation model. It becomes the single source of truth for every path that decides what happens to a mediated request:
  - the tool-dispatch evaluators;
  - nested flow;
  - startup reconciliation;
  - recovery's original-operation closure;
  - the closure drain (spec 4);
  - the stop failure path (spec 8).

  The sixteen `evaluate_tool_call_*` entry points collapse to one `evaluate` and one blocking adapter. The function is extracted to Lean, checked against a new Apalache model, and used as the deterministic simulation substrate.

  Out of scope:
  - how commits execute (`2026-10-04-crossing-primitive-design.md`);
  - integrity checks (`2026-10-04-integrity-gated-admission-design.md`).
- Owners:
  - `chio-kernel-core`: the machine, its vocabulary, and the Aeneas extraction.
  - `chio-kernel`: projection, drivers, and the evaluator entry point.
  - `chio-store-sqlite`: legacy-predicate assertions during migration.
  - `formal/`: the Lean theorems, the `AdmissionMachine` Apalache model, and trace validation.
  - `chio-kernel` `tests/dst`: the simulation harness.
- Related:
  - `2026-07-12-admission-operation-design.md` (saga rules 1-6);
  - M: `docs/security/engineering-standard.md` rules 2.3, 2.5, 5.1 and 5.6;
  - M: `docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md`;
  - M: `docs/formal/CURRENT_STATE.md`;
  - ADR-0019 (exhaustive matches);
  - ADR-0022 (kernel decomposition).
- Citation convention:
  - `M:` = `integration/process-security-m4` at `19df31ad9`.
  - `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac`.
  - `R:` = `origin/research/openappa-recovery-20261001`.
  - `W:` = the uncommitted recovery working tree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`. Its line references reflect 2026-10-04 and may drift.
  - `P:` = `feat/process-command-experience-20260924`.
  - `B:` = `origin/wip/bench-results-2026-09-13`.
- Origin: `docs/research/2026-10-04-chio-kernel-north-star.md` bet 1 (keystone). This is lever 3 of the internal assessment.
- Siblings:
  - umbrella: `2026-10-04-ftl-lessons-program-design.md`;
  - program specs: `2026-10-04-closed-kernel-abi-design.md`, `2026-10-04-authority-faults-design.md`, `2026-10-04-typed-reservations-design.md`, `2026-10-04-authority-space-teardown-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-opaque-adapter-context-design.md`, `2026-10-04-microkernel-isolation-backend-design.md`, `2026-10-04-durable-stop-epoch-design.md`;
  - north-star specs: `2026-10-04-crossing-primitive-design.md` (B) and `2026-10-04-integrity-gated-admission-design.md` (C).

## 1. Decision summary

The decisions about a mediated request are made in many places, in imperative code mixed with I/O:
- the next admission state;
- whether to compensate, terminalize, retain or wait;
- which receipt to sign.

The places are:
- two durable operation models with their own legality predicates;
- three classifiers of in-flight operations;
- two full evaluators with the same shape;
- sixteen public evaluation entry points.

Only the pure kernel core is proven (about 20 Aeneas-extracted functions). The code that decides effects is tested, not proven, and no TLA model describes the admission saga's states.

This design makes the decision a function:

```rust
pub fn transition(state: &AdmissionState, event: AdmissionEvent) -> Transition;
pub struct Transition { pub next: AdmissionState, pub effects: EffectList }
```

1. **One model.** `AdmissionState` is the union of both operation models, factored as a phase plus participant facts (section 4). Every persisted state of both models has a total, tested projection into it. Persisted state strings do not change during migration.
2. **One function.**
   - Every driver feeds events and performs effects through ports: evaluators, nested flow, startup reconciliation, recovery closure, the drain, and the stop path.
   - The three classifiers become one function evaluated on a `Cut` event with a typed cause.
   - Their known divergences become explicit cause parameters.
3. **One entry point.** `evaluate(request, EvaluationContext)` replaces sixteen methods, and blocking is an adapter (section 8).
4. **Proof reaches the decision.**
   - `transition` lives in `chio-kernel-core` inside the Aeneas-supported subset and is extracted to Lean.
   - The specs' safety predicates become Lean theorems.
   - A new `AdmissionMachine` Apalache model covers concurrent drivers.
   - Differential random testing compares the machine with both legacy legality predicates, in the style of Cedar's verification-guided development.
5. **Simulation substrate.** Deterministic simulation drives the machine directly, with fault injection on every effect (section 10).

The machine decides; it never executes. Spec B owns how `IntentCommit`, `OutcomeCommit` and the other commit effects execute as crossing transactions. Spec C contributes an integrity fact that the machine treats like any other admission precondition.

## 2. Verified current state

| Fact | Evidence |
|---|---|
| Tool-dispatch model: 19 states, three kinds (`ToolDispatch`, `GovernedActiveResponse`, `GovernedEconomicMutation`), and a separate `AdmissionDispatchState` | M: `crates/kernel/chio-kernel/src/admission_operation.rs:228-254`, `:257-277`, `:309-316`; kinds at `admission_operation/identity.rs:179-183` |
| Its legality is an imperative predicate over (from, to, kind, requirements): `is_legal_transition`. Companions: `predispatch_state_enabled` and `dispatch_state_for` | M: `admission_operation/state.rs:597`, `:498`, `:516` |
| Security model: 15 states, including `DelegatedBudgetReserved`, `PaymentAuthorized`, `CallerReservationCapturePending`, `CompensationPending` and `CallerReserved`, with its own four-valued dispatch state | M: `crates/kernel/chio-kernel/src/admission_operation.part1.inc:74-90`, `:144-149` (included by `security_admission_operation.rs:4-6`) |
| Its legality is a second predicate, `valid_state_transition`, with different participant ordering (budget, then delegated budget, then payment, then approval) | M: `admission_operation.part2.inc:798-846` |
| The store applies a transition by CAS, with the caller choosing `next_state` | M: `admission_operation/store.rs:930` (`claim_and_apply`); `kernel/admission_coordinator.rs:1904-1923` (`apply_admission_command`) |
| Sixteen public evaluation entry points: 6 async, 6 blocking, 4 nested flow | M: `kernel/evaluation/evaluation_entry.rs:98-210`; `sync_evaluation_wrapper.rs:4-96`; `session_ops/nested_tool_call.rs:36-132` |
| Two full evaluators with the same shape, duplicating the post-effect region (defect D1 appears in both) | M: `async_evaluation_core.rs` (1,988 lines), `nested_flow_evaluation.rs` (1,774 lines) |
| Startup classifier: retain an authenticated caller wait, else terminalize `DispatchCommitted`; skip live nonce or caller reservations; compensate pre-dispatch states; compensate expired `ApprovalRequired`; finalize `Finalizing` | M: `kernel/admission_coordinator/recovery.rs:133` (`reconcile_recoverable_admissions`), cases `:170-330` |
| Recovery's original-operation classifier is a second copy with two differences: it never retains a caller wait, and it closes `ApprovalRequired` when workflow control is not `Active` | W: `crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery_runtime.rs:184` (`reconcile_recovery_original`), `:212-265` |
| The spec 4 drain classifier and the spec 8 stop failure path would be a third and a fourth | `2026-10-04-authority-space-teardown-design.md` section 5; `2026-10-04-durable-stop-epoch-design.md` S15 |
| Proof hub: 20 extracted functions; 149 Lean declarations; nine positive Apalache safety models; 10 Loom models | M: `crates/kernel/chio-kernel-core/src/formal_aeneas.rs` (functions at `:88-375`); M: `docs/formal/CURRENT_STATE.md:14-34` |
| No TLA or Apalache model of the admission operation states exists. The models cover the drop guard, cancel-safe transition, receipt-before-allow, response lifecycle, revocation cut and the monotone log | M: `formal/apalache/` listing; M: `formal/MAPPING.md` (no `AdmissionOperationState` mapping) |
| DST covers two crash boundaries around receipt persistence | M: `crates/kernel/chio-kernel/tests/dst/support/durability_scenarios.rs:4-7` |

## 3. Goals and non-goals

Goals:

- One decision function for every path that changes an admission operation, with no other code choosing a next state.
- One operation model, with total projections from both legacy models and no persisted-format change during migration.
- One evaluation entry point plus a blocking adapter.
- Machine-checked theorems for the saga's safety predicates, connected to production code by extraction and differential testing.
- A deterministic simulation substrate that injects faults at every effect.

Non-goals:

- Executing commits, choosing transaction boundaries, group commit or sharding. These belong to spec B.
- Changing receipts, wire messages, release authorities or saga rules 1-6. The machine encodes them; it does not alter them.
- Proving the whole kernel. Ports, the store, dialect adapters and transports stay tested components.
- Modeling recovery workflows, process journals or work handles as admission states. They are drivers that send events (section 7).

## 4. One operation model

### 4.1 State

```rust
// chio-kernel-core::admission_machine (no_std + alloc; closed enums, no wildcard arms)
pub struct AdmissionState {
    pub kind: OperationKind,              // ToolDispatch | GovernedActiveResponse | GovernedEconomicMutation
    pub phase: Phase,
    pub plan: ParticipantPlan,            // ordered participants required for this request (data)
    pub facts: ParticipantFacts,          // which participants are acknowledged, by digest
    pub dispatch: DispatchMark,           // NotCommitted | CapturePending(CaptureKind) | Committed | Finalizing | Terminal | NotApplicable
    pub version: u64,
}

pub enum Phase {
    Prepared,
    Authorizing,                          // some, not all, participants acknowledged
    Parked { deadline: AuthorityTime },   // approval required
    Ready,                                // all participants acknowledged
    CapturePending(CaptureKind),          // Native | Caller
    DispatchCommitted,
    AwaitingCallerReport,
    Finalizing(PostReturnStage),
    Compensating,
    Mutation(MutationPhase),              // Ready | Submitted (economic mutation kind only)
    Terminal(Terminal),
}

pub enum Terminal {
    Completed, CompensatedBeforeDispatch, NotAcceptedAfterDispatchCommit,
    OutcomeUnknownAfterDispatch, DeniedAfterDelivery,
    EconomicMutationApplied, EconomicMutationNotApplied,
}

pub enum Participant {
    BrokerAttempt, BudgetHold, DelegatedBudget, Payment, ApprovalSet, ExecutionNonce,
    OutcomeEligibility, Channel, CreditExposure, CallerDispatchContext, NativeDispatchLedger,
    DpopReplay, Integrity,                // Integrity: spec C's admission precondition
}
```

`ParticipantPlan` is derived once at `Begin` from the operation kind and the requirements:
- the same inputs as today's `AdmissionRequirements`;
- spec C's integrity requirement, when the matched grant declares one.

The plan replaces the ordering that the two legality predicates hard-code. Participants are acknowledged in plan order (rule M5), so both legacy orderings are instances of one rule:
- the tool model: broker, budget, approval;
- the security model: budget, delegated budget, payment, approval.

### 4.2 Projection from both legacy models

`project(record) -> Result<AdmissionState, ProjectionError>` is total over every persisted combination. An unknown combination returns an error and is never guessed (section 12).

| Legacy state (model) | Phase | Facts and dispatch |
|---|---|---|
| `Prepared` (both) | `Prepared` | none; `NotCommitted` |
| `BrokerAttemptRegistered` (both) | `Authorizing` | `BrokerAttempt` |
| `BudgetAuthorized` (both) | `Authorizing` or `Ready` | `BudgetHold`, plus any earlier facts. `Ready` if the plan has no further participants |
| `DelegatedBudgetReserved` (security) | `Authorizing` | `BudgetHold`, `DelegatedBudget` |
| `PaymentAuthorized` (security) | `Authorizing` | `BudgetHold`, `DelegatedBudget`, `Payment` |
| `ApprovalRequired` (tool) | `Parked { deadline }` | earlier facts; the deadline comes from the parked proposal |
| `ApprovalReserved` (both) | `Authorizing` or `Ready` | `ApprovalSet`, plus earlier facts |
| `ReadyToDispatch` (both) | `Ready` | every planned participant acknowledged |
| `CapturePending` (both) | `CapturePending(Native)` | `CapturePending(Native)` |
| `CallerReservationCapturePending` (security) | `CapturePending(Caller)` | `CapturePending(Caller)` |
| `DispatchCommitted` (both) | `DispatchCommitted` | `Committed` |
| `AwaitingCallerReport` (tool), `CallerReserved` (security) | `AwaitingCallerReport` | `Committed` |
| `Finalizing` (tool) | `Finalizing(stage)` | `Finalizing`; the stage comes from the tool-outcome participant |
| `CompensationPending` (security) | `Compensating` | `NotCommitted` |
| `MutationReady`, `MutationSubmitted` (tool, economic) | `Mutation(Ready)`, `Mutation(Submitted)` | `NotApplicable` |
| Every terminal (both) | `Terminal(..)` with the same name | `Terminal` |

The inverse `persist(state) -> (kind-specific legacy state, legacy dispatch state)` is used during the compatibility period (section 9). It is the identity for every state both models share. It is a projection for facts the tool model does not name: for example, `DelegatedBudget` in a tool-model record is carried by its attachment, as today.

## 5. Events and effects

### 5.1 Events

```rust
pub enum AdmissionEvent {
    Begin { binding: BindingDigest, plan_inputs: PlanInputs, now: AuthorityTime },
    ParticipantAcknowledged { participant: Participant, digest: Digest },
    ApprovalRequired { proposal: ProposalDigest, deadline: AuthorityTime },
    ApprovalSupplied { approval_set: Digest },
    CaptureCommitted { kind: CaptureKind },
    DispatchCommitAcknowledged { committed_version: u64 },
    CallerStartAuthenticated, CallerReportAuthenticated { outcome: OutcomeDigest },
    ToolReturned { outcome: OutcomeDigest, cost: CostFact },
    PostReturnStageDone { stage: PostReturnStage },
    OutputDigestMismatch,
    NotAccepted { proof: NoEffectProof },     // TransportNotAccepted evidence
    TransportAmbiguous,                       // handoff may have happened
    CompensationAcknowledged,
    MutationResult { applied: bool },
    CommitFailed { effect: EffectId, reason: CommitFailure },  // spec B CrossingRefused: KernelStopped, AuthoritySpaceClosed, Revoked, InsufficientIntegrity, ReservationConflict; plus VersionConflict (B rule X5) and Unavailable (fast path not executable)
    Cut { cause: CutCause, liveness: LivenessFacts, now: AuthorityTime },
    Tick { now: AuthorityTime },
}

pub enum CutCause {
    StartupRecovery,
    RecoveryClosure { control: WorkflowControl },   // W: Active | CancelRequested | Cancelled | Quarantined
    AuthorityCut { trigger: TriggerDigest },        // spec 4 drain
}

pub struct LivenessFacts { pub nonce_issuance_live: bool, pub caller_reservation_live: bool, pub caller_wait_live: bool }
```

**Time is an input.** The driver reads the fallible authority clock and passes `now` in events; the machine never reads a clock.

**Liveness is an input.** Facts such as "a live issued nonce" or "a live caller reservation" are gathered by the driver from their stores and passed in `LivenessFacts`. Today the classifiers read them inline (M: `recovery.rs:206-221`).

### 5.2 Effects

```rust
pub enum Effect {
    IntentCommit(IntentCommitPlan),       // fast path: steps Prepared..DispatchCommitted in one crossing (spec B)
    ReturnRecord(ReturnRecordPlan),       // anchor-free durable tool-return record before post-return work (spec B)
    OutcomeCommit(OutcomeCommitPlan),     // fast path: post-return stages, terminal projection, receipt (spec B)
    CheckOnlyCrossing(CheckOnlyPlan),     // read-only dispatch: crossing checks with no write; receipt rides the release commit (spec B)
    ParticipantCommit(ParticipantStep),   // slow path: one participant in another store (remote budget, payment rail)
    Park { proposal: ProposalDigest, deadline: AuthorityTime },
    RequestApproval { proposal: ProposalDigest },
    Dispatch,                             // hand off to the tool; only after DispatchCommitAcknowledged
    CallerAwaitStart, CallerAwaitReport,
    Compensate { cause: CompensationCause, release: Option<MachineRelease> },
    Terminalize { terminal: Terminal, release: Option<MachineRelease> },
    SignReceipt { decision: ReceiptDecision, metadata: ReceiptMetadataPlan },
    Latch { reason: LatchReason },        // spec 3 fail-closed latch
    Hint { subject: HintSubjectRef },     // spec 5, after commit (H2)
    Retain,                               // no change; record observation (live wait, live reservation)
}

pub enum MachineRelease { PreDispatchNoEffect, TransportNotAccepted }
```

**The plan types.**
- `IntentCommitPlan` lists the ordered state steps and attachments that the fast path commits atomically: begin, participant acknowledgements, ready, then dispatch commit. The plan is data. Spec B decides whether it can execute as one transaction, which requires every participant in the admission writer. If it cannot, spec B reports `CommitFailed { reason: Unavailable }` and the driver re-feeds the machine with a slow-path flag in `PlanInputs`, so the machine emits `ParticipantCommit` steps instead.
- `IntentCommitPlan` also carries the grant's integrity requirement as the planned `Integrity` participant, so spec B evaluates `CrossingCheck::KnowledgeIntegrity` inside the same transaction (spec C, rule I15).
- `ReturnRecordPlan` makes the returned bytes and cost durable before post-return work, as the admission-operation design requires. It is anchor-free because it authorizes nothing outside Chio (spec B). Whether it can fuse into the outcome commit is spec B's open decision 1.
- `OutcomeCommitPlan` lists the post-return stages, the terminal projection, the receipt, and the output influence join that spec C records on every delivery.
- `CheckOnlyPlan` covers read-only calls: spec B runs the crossing checks without a write, and the receipt rides one durable release commit, which retires defect D1.
- Each plan carries the expected operation version for spec B's compare-and-swap (B rule X5). A version mismatch returns `CommitFailed { reason: VersionConflict }`.

**Release authorities.**
- The machine can emit only the two release authorities that need no counterparty: `PreDispatchNoEffect` and `TransportNotAccepted`.
- `MutuallyAgreedUnknown` and `ContractualCaptureWaiver` arrive as events from their own authorities and are never machine-originated (spec 3, spec 4 section 5 rule 2).

## 6. Transition rules

`transition` is total. Normative rules:

1. **M1. Purity.** `transition` performs no I/O, reads no clock, draws no randomness, allocates no identity, and never panics. It lives in `chio-kernel-core` with `no_std + alloc`. Identities (operation ids, hold ids, event ids) are deterministic derivations from the binding digest, as today. The effect list has fixed capacity (at most 8 entries), so the function stays inside the subset `formal/aeneas` supports.
2. **M2. Exhaustive.** Every match over `Phase`, `AdmissionEvent`, `CutCause`, `Participant` and `CommitFailure` is exhaustive with no wildcard arm (ADR-0019 item 6). An event that is illegal in the current phase yields `next == state` and a single `Effect::Retain`, and is counted as an illegal-event fault by the driver. It never yields an error-shaped partial state.
3. **M3. Prepared first.** No `ParticipantCommit` or `IntentCommit` step that mutates a participant precedes the `Prepared` step of the same operation (saga rule 1).
4. **M4. Commit before handoff.** `Effect::Dispatch` is emitted only in the transition consuming `DispatchCommitAcknowledged` (saga rule 3). Under the fast path, that is the acknowledgement of the `IntentCommit` that contains the dispatch-commit step.
5. **M5. Plan order.** A participant is acknowledged only when every earlier participant in the plan is acknowledged. `Ready` is entered exactly when the plan is complete.
6. **M6. Absorbing terminals.** A terminal phase accepts no event except `Tick` (which yields `Retain`). Replay of a request against a terminal returns the bound terminal (saga rule 4).
7. **M7. Unknown stays unknown.**
   - `TransportAmbiguous` after dispatch commit moves to `Terminal(OutcomeUnknownAfterDispatch)` with no release.
   - From there no `Dispatch` is ever emitted again.
   - Holds stay frozen until a counterparty release event.
8. **M8. Cut and failure classification.** For `Cut` events and pre-dispatch `CommitFailed` events:
   - **Pre-dispatch phases** (`Prepared`, `Authorizing`, `Ready`, `CapturePending` without a committed capture, `Compensating`): emit `Compensate { release: PreDispatchNoEffect }`, unless a liveness fact protects the operation (rule M9).
   - **`Parked`:** compensate when the deadline has elapsed. Also compensate when the cause is `RecoveryClosure` with control other than `Active`. Otherwise retain.
   - **`DispatchCommitted`:** retain when `caller_wait_live`; otherwise `Terminalize(OutcomeUnknownAfterDispatch)` with no release.
   - **`AwaitingCallerReport`:** retain.
   - **`Finalizing`:** emit the next post-return stage.
   - **Terminal:** retain.
9. **M9. Liveness protection.** `Prepared` with `nonce_issuance_live`, and `Ready` with `caller_reservation_live`, are retained under `StartupRecovery`, and under `RecoveryClosure` only while control is `Active`. This reproduces M: `recovery.rs:206-221` and W: `recovery_runtime.rs:213-218`.
10. **M10. Stop and fence failures.** `CommitFailed` with `KernelStopped`, `AuthoritySpaceClosed`, `InsufficientIntegrity` or `Revoked` on an `IntentCommit` is pre-dispatch by construction: spec B's crossing fails before the dispatch-commit step. It is classified by rule M8 as a pre-dispatch failure. The effect is a compensation plus a signed deny receipt carrying the refusing check's reason (spec 8 S15; spec 4 section 4.1; spec C).
11. **M11. Post-effect discharge.** From `DispatchCommitted`, every event sequence reaches exactly one of:
    - a terminal phase;
    - a durable-outcome acknowledgement;
    - a `Latch`.

    This is the machine-level form of spec 3's `entered_effect_boundary` predicate.

### 6.1 The three classifiers as one function

`classify(state, cause, liveness, now) = transition(state, Cut { cause, liveness, now }).effects`. That is a definition, not a refactor target. The legacy classifiers become drivers that compute `LivenessFacts`, call `transition`, and perform the effects:
- M: `reconcile_recoverable_admissions`;
- W: `reconcile_recovery_original`;
- the spec 4 drain.

**The two recorded divergences:**
- **Caller wait.** M: retains a live authenticated caller wait at startup. W:'s recovery closure terminalizes without checking it. The machine applies rule M8 for every cause, so the recovery closure stops refusing a caller's legitimate late report. This changes W: behavior to the conservative choice: retaining freezes nothing new and keeps the report path open. Open decision 1 asks the recovery owner to confirm.
- **Parked approval under closure.** W: closes `ApprovalRequired` when workflow control is not `Active`, even before the deadline. That rule is preserved as a property of the `RecoveryClosure` cause (rule M8), not of the state.

```text
classify(s, StartupRecovery, l, t) = transition(s, Cut(StartupRecovery, l, t)).effects
classify(s, RecoveryClosure(c), l, t) = transition(s, Cut(RecoveryClosure(c), l, t)).effects
classify(s, AuthorityCut(g), l, t) = transition(s, Cut(AuthorityCut(g), l, t)).effects
forall cause: Compensate in classify(s, cause, l, t) -> pre_dispatch(s) and not capture_committed(s)
```

## 7. Drivers and ports

| Driver | Feeds | Performs through |
|---|---|---|
| `EvaluationDriver` (async) | `Begin`, acknowledgements, capture, dispatch acknowledgement, tool return, post-return stages, failures | `CrossingPort` (spec B), `DispatchPort`, `SigningPort`, participant ports, `HintPort` |
| `BlockingAdapter` | none of its own: wraps `EvaluationDriver` on the existing blocking runtime | as above |
| `NestedFlowDriver` | the same events, with nested-flow client callbacks as an event source | as above, plus `NestedFlowClient` |
| `StartupReconciler` | `Cut(StartupRecovery)` per recoverable operation, after lease claim | `CrossingPort`, `SigningPort` |
| `RecoveryClosureDriver` (W:) | `Cut(RecoveryClosure { control })` | as above |
| `DrainDriver` (spec 4) | `Cut(AuthorityCut { trigger })` | as above |
| `CallerExecutionDriver` | `CallerStartAuthenticated`, `CallerReportAuthenticated` | `CrossingPort` |

The rules for drivers:
- Drivers own leases (the existing `mutation_sequencer.try_own_operation`), the clock, liveness lookups and every port call.
- A driver never chooses a next state. It persists `next` through the commit effects that spec B executes, with the version CAS of today's `claim_and_apply`.
- A crash between an effect and its acknowledgement is resolved by re-projecting the persisted record and re-feeding the event the driver can prove (saga participant lookup by `operation_id`). It is never resolved by assumption.

## 8. One evaluation entry point

```rust
impl ChioKernel {
    pub async fn evaluate(&self, request: &ToolCallRequest, ctx: EvaluationContext<'_>)
        -> Result<ToolCallResponse, KernelError>;
    pub fn evaluate_blocking(&self, request: &ToolCallRequest, ctx: EvaluationContext<'_>)
        -> Result<ToolCallResponse, KernelError>;   // adapter over evaluate
}

pub struct EvaluationContext<'a> {
    pub extra_metadata: Option<serde_json::Value>,
    pub security: SecuritySource<'a>,                // None | Explicit(&SecurityInvocationContext) | AuthenticatedSession { session_id, context }
    pub manifest: Option<ManifestSecurity<'a>>,      // (&VerifiedManifestRegistry, &BridgeSecurityMetadata)
    pub nested: Option<NestedFlow<'a>>,              // client plus optional proofs; selects NestedFlowDriver
}
```

| Legacy entry point (M:) | `EvaluationContext` |
|---|---|
| `evaluate_tool_call` | default |
| `evaluate_tool_call_with_metadata` | `extra_metadata` |
| `evaluate_tool_call_with_security_context` | `security: Explicit` |
| `evaluate_tool_call_with_metadata_and_security_context` | `extra_metadata`, `security: Explicit` |
| `evaluate_tool_call_with_manifest_security` | `manifest`, `extra_metadata` |
| `evaluate_tool_call_with_manifest_security_and_security_context` | `manifest`, `extra_metadata`, `security: Explicit` |
| six `evaluate_tool_call_blocking*` variants | the same fields, through `evaluate_blocking` |
| `..._blocking_with_manifest_security_and_authenticated_session_context` | `manifest`, `security: AuthenticatedSession` |
| four `evaluate_tool_call_operation_with_nested_flow_client*` (sync, async, with and without proofs) | `nested: Some(..)` |

The legacy methods stay as `#[deprecated]` one-line wrappers for one minor release, then are removed. The spec 1 entry-point budget (R6) for `EvaluateToolCall` and `EvaluateSessionOperation` falls from 16 public methods to 2. The duplicated post-effect region (D1 at M: `async_evaluation_core.rs:1740` and `nested_flow_evaluation.rs:1495`) then exists once, inside the one driver that spec 3's obligation wraps.

## 9. Migration

Each phase keeps the suite green and changes no wire, receipt or persisted format.

1. **Phase 0: model and differential.**
   - Land the vocabulary, `project`, `persist` and `transition` in `chio-kernel-core`.
   - Add a differential test over every (legacy state, legal next state, kind, requirements) tuple. The machine must permit exactly what `is_legal_transition` permits for the tool model, and exactly what `valid_state_transition` permits for the security model, modulo the factoring in section 4.2.
   - Disagreements are listed and resolved in the model before any driver moves.
2. **Phase 1: startup reconciler.** `reconcile_recoverable_admissions` becomes a driver (M: `recovery.rs:133`). Its effects must equal today's behavior on the DST seeds and the existing recovery tests.
3. **Phase 2: recovery closure.** `reconcile_recovery_original` becomes a driver (W: `recovery_runtime.rs:184`), with the caller-wait divergence resolved per open decision 1.
4. **Phase 3: drain and stop.** Spec 4's drain and spec 8's pre-dispatch failure path are built on the machine from the start.
5. **Phase 4: evaluators.** `EvaluationDriver` replaces `async_evaluation_core`, and `NestedFlowDriver` replaces `nested_flow_evaluation`. The `evaluate` entry point lands and the sixteen wrappers are deprecated.
6. **Phase 5: one persisted model.** Fold the security operation store into the tool-dispatch store, or keep both tables behind `project`/`persist` (open decision 2).

**Compatibility period.** Through phase 5, the store's CAS keeps asserting the legacy predicate for the record's model. A machine-chosen `next` that the legacy predicate rejects fails the CAS closed, records an `audit_fault`, and blocks the operation for recovery. It is never applied. The assertions are removed only after one release with zero recorded disagreements in CI, DST and production traces.

**Receipts and wire.** No change. Receipts, receipt metadata, `KernelMessage` and every HTTP surface are unchanged. The machine reproduces the decisions today's code makes.

## 10. Proof and simulation plan

**Extraction.** `transition`, `project` (restricted to its pure core) and `classify` join the Aeneas hub. Today the hub extracts 20 functions (M: `formal_aeneas.rs`). These are larger, but they are pure enum-and-struct code with fixed-capacity effects. The Lean statements live in a new module, `Chio/Admission/Machine.lean`, imported by `Chio.lean`.

**Theorems** (each named after the spec predicate it closes):

| Theorem | Statement | Closes |
|---|---|---|
| T1 `prepared_first` | no participant-mutating step precedes `Prepared` | saga rule 1 |
| T2 `commit_before_dispatch` | `Dispatch` appears only in the transition consuming `DispatchCommitAcknowledged` | saga rule 3 |
| T3 `no_compensation_after_commit` | `Compensate` only from pre-dispatch phases without a committed capture | spec 4 section 5; drain predicate |
| T4 `machine_release_authorities` | the machine emits only `PreDispatchNoEffect` or `TransportNotAccepted` | spec 3, spec 4 section 5 rule 2 |
| T5 `terminal_absorbing` | no transition leaves a terminal phase | saga rule 4 |
| T6 `unknown_stays_unknown` | no `Dispatch` after `OutcomeUnknownAfterDispatch`; no release without a counterparty event | saga rule 6 |
| T7 `fence_dominance` | a `CommitFailed` with a stop, fence, integrity or revocation reason on an intent commit never leads to `Dispatch` | spec 8 S7/S15, spec 4 section 4.1, spec C |
| T8 `post_effect_discharge` | from `DispatchCommitted`, every fair event sequence reaches a terminal phase, an outcome acknowledgement or a `Latch` | spec 3 |
| T9 `plan_order` | participants are acknowledged in plan order; `Ready` exactly when the plan is complete | both legacy orderings |
| T10 `classifier_projection` | rule M8 equals `transition` on `Cut`, by definition, plus the compensation guard of section 6.1 | spec 4 rule 5.6 |

**Model checking.**
- Add `formal/apalache/AdmissionMachine.tla`. It states the same rules as `transition` for two operations and three concurrent drivers racing through version CAS: an evaluator, the startup reconciler and the drain.
- Invariants T2, T3, T5 and T7 are checked under interleaving, with a negative model for each.
- The model registers in `formal/proof-manifest.toml` and mirrors `transition` through `formal/MAPPING.md`, so a Rust edit without a model update fails the mirror check.

**Differential random testing** (Cedar method). A property-based generator produces random event sequences per kind and plan, then runs them through:
- `transition`;
- the legacy predicates (during the compatibility period);
- an independent reference implementation in Lean, run through its executable extraction.

Agreement is required on `next` and effects.

**Trace validation.** Every production admission operation already leaves its versions and attachments in the store. The trace validator replays each operation's history through `project` and `transition` and flags any persisted step the machine would not produce. This is production validation in the style of PObserve.

**Deterministic simulation.**
- The DST harness drives the machine directly. A seeded scheduler interleaves events for many operations from all drivers, and injects faults at every effect:
  - commit failure;
  - unknown commit outcome;
  - crash between effect and acknowledgement;
  - ambiguous transport;
  - stop or fence failure from spec B;
  - clock unavailability.
- Oracles are T1-T9 as runtime assertions, plus the store's legacy predicates during compatibility.
- This replaces today's two crash boundaries with one per effect variant.

## 11. Performance

The machine is pure, allocation-bounded and in memory, so it adds no I/O. Its own cost is a few enum matches per event, negligible against a 13.9 ms kernel-only allow (B: `bilateral-admission-components.csv`). It enables, but does not deliver, the hot-path gain: emitting one `IntentCommitPlan` for a whole pre-dispatch run is what lets spec B fuse today's separate commits.

Acceptance:
- Phase 4 must not regress the M: process-mediated benchmark medians (`M:sdks/typescript/packages/ai-sdk-process/BENCHMARK.md:175-191`) by more than noise.
- The kernel-only allow p50 must stay within 5 percent.

## 12. Failure modes

| Failure | Behavior |
|---|---|
| `project` meets an unknown persisted combination | `ProjectionError`. The driver refuses the operation, records an `audit_fault`, and leaves it for operator recovery. No guessed state |
| Illegal event for the phase | `Retain`, with an illegal-event counter. Never a partial state |
| Machine and legacy predicate disagree (compatibility period) | CAS fails closed with an `audit_fault`; the operation is blocked for recovery |
| Commit effect fails | Spec B returns `CommitFailed { reason }`. The machine classifies it (rules M8 and M10) |
| Crash between effect and acknowledgement | Re-project from the store and re-feed provable events only (section 7) |
| Clock unavailable | The driver cannot construct the event, so no transition occurs. Pre-dispatch work fails closed through the existing authority-time errors |
| Effect list exceeds capacity | A type error at construction (fixed capacity), caught at compile and test time |

## 13. Rollout

| Phase | Content | Gate |
|---|---|---|
| 0 | Vocabulary, projection, machine, differential test | Zero unexplained disagreements |
| 1 | Startup reconciler driver; Lean module skeleton; `AdmissionMachine.tla` | T3, T5 proven; Apalache positive and negative pass |
| 2 | Recovery closure driver (after open decision 1) | W: recovery suites green |
| 3 | Drain and stop drivers (with specs 4 and 8) | Spec 4 and 8 conformance |
| 4 | `EvaluationDriver`, `NestedFlowDriver`, `evaluate`, deprecations | Benchmark acceptance (section 11); T1-T9 proven |
| 5 | Persisted model decision; compatibility assertions removed | One release with zero disagreements |

Gate GT1 applies: no proof or conformance claim until the lanes run in hosted CI.

## 14. Tests and conformance evidence

- **Unit:**
  - projection totality over all 19 tool-model and 15 security-model states, with their dispatch pairs;
  - `persist(project(r)) == r` for every shared state;
  - rules M1-M11 by example.
- **Differential:** the machine against `is_legal_transition` and `valid_state_transition` over the full tuple space (finite and enumerable).
- **Proptest:** random event sequences per kind and plan, checking T1-T9 as executable assertions.
- **Kani:** `transition` never panics; the effect list stays within capacity; `classify` is total.
- **Lean:** T1-T10, with mirrors registered.
- **Apalache:** `AdmissionMachine.tla`, with negative mutants (drop the T2 guard, compensate after commit, leave a terminal).
- **Loom:** two drivers racing on one operation through the CAS adapter.
- **DST:** a fault-injection seed for each effect variant, added to `tests/dst/seeds.toml`.
- **Trace validation:** replay of retained operation histories from CI and pilot stores.
- **Conformance:** the existing verdict-matrix and recovery scenarios pass unchanged through `evaluate`.

## 15. Residual risks and open decisions

Residual risks:

- **Ports stay tested, not proven.** The machine proves decisions; ports (store, transports, signer) remain tested. A port that lies about an acknowledgement defeats the proofs. That is spec 1's `fact_source` polarity.
- **Extraction limits.** Aeneas support for the needed Rust subset may require restricting the machine's types further (fixed arrays, no generic collections). Phase 0 confirms this before drivers move.
- **Migration risk.** Phase 4 touches the two largest evaluator files. The deprecation wrappers and the differential gate bound the risk, but cannot remove it.

Open decisions:

1. **Caller wait under recovery closure.** Adopt startup's rule (retain a live authenticated caller wait) for every cause, as section 6.1 proposes, or keep W:'s terminalization for recovery closure? Recommendation: retain. It is the conservative choice and keeps the caller's report path.
2. **Persisted model.** Migrate both stores to the canonical phase-plus-facts schema, or keep two tables behind `project`/`persist` indefinitely? Recommendation: keep both through phase 4, then migrate in one schema version once traces show no disagreement.
3. **Recovery and work workflows.** Should recovery workflows and work handles get their own pure machines in the same style, or stay drivers only? This spec keeps them as drivers.
4. **Extraction or model.** Extract `transition` with Aeneas (the machine is the model), or hand-write a Lean model and differentially test the Rust (Cedar's method)? Recommendation: extract the functional core, and keep an independent hand-written reference for differential testing.
5. **Governed active response.** It shares the machine but has its own executor and lifecycle (M: `formal/apalache/ResponseLifecycle.tla`). Should its response-plan lifecycle be folded into the same machine later? Not in this spec.

## Appendix A. External and FTL precedent

- **FTL.** The FTL kernel's dispatch is one exhaustive match whose fallback is `UnknownSyscall` (FTL `kernel/src/syscall.rs:19-73`), and its state changes happen in one place per object. The machine is that discipline applied to Chio's admission saga: one function and no wildcard.
- **Cedar** builds a readable executable Lean model, proves properties, then runs differential random tests of the Rust against the model. The proofs found 4 bugs and the differential and property tests found 21 more ([How We Built Cedar](https://arxiv.org/pdf/2407.01688)). Section 10 follows the same three steps.
- **Atmosphere** is an L4-style microkernel proven functionally correct in Rust with Verus (SOSP 2025; [Atmosphere](https://mars-research.github.io/projects/atmo/)). That shows proof is feasible at the scale of a pure decision core. This spec stops short of a whole-kernel proof.
- **Deterministic simulation.** TigerBeetle's VOPR runs every component under one seeded PRNG so a failing seed reproduces exactly ([VOPR](https://docs.tigerbeetle.com/about/vopr)). A sans-IO machine is what makes that cheap here.
- **AWS PObserve** validates production logs against P specifications ([Systems Correctness Practices at AWS](https://dl.acm.org/doi/abs/10.1145/3815784)). Section 10's trace validation is the same idea over admission histories.

Where the analogy breaks: FTL's dispatch has no durable state or crash recovery. Chio's machine must be re-entrant from any persisted version, which is why projection, liveness inputs and acknowledgement events exist.
