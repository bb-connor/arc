# Design: pure admission machine

- Status: PROPOSED (revision 2, after adversarial review 2026-10-04)
- Date: 2026-10-04
- Scope: one sans-IO transition function over one admission operation model. It becomes the single source of truth for every path that decides what happens to a mediated request: the tool-dispatch evaluators, nested flow, caller-execution reserve, start and report, startup reconciliation, parked-approval retirement, governed active response recovery, recovery's original-operation closure, the closure drain (spec 4) and the stop failure path (spec 8). The seventeen public evaluation methods collapse to one `evaluate` and one blocking adapter. The extractable core is lowered to Lean, checked against a new Apalache model, and used as the deterministic simulation substrate.
- Out of scope: how commits execute (`2026-10-04-crossing-primitive-design.md`) and what the integrity check means (`2026-10-04-integrity-gated-admission-design.md`).
- Owners:
  - `chio-kernel-core`: the machine, its vocabulary, and the extractable core.
  - `chio-kernel`: projection, persistence plans, drivers, and the evaluator entry point.
  - `chio-store-sqlite`: legacy-predicate assertions during migration.
  - `formal/`: the Lean theorems, the `AdmissionMachine` Apalache model, and trace validation.
  - `chio-kernel` `tests/dst`: the simulation harness.
- Related: `2026-07-12-admission-operation-design.md` (saga rules 1-6); M: `docs/security/engineering-standard.md` rules 2.3, 2.5, 5.1 and 5.6; M: `docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md`; M: `docs/formal/CURRENT_STATE.md`; ADR-0019 item 6 (no wildcard arms over `Constraint`, adopted here by extension); ADR-0022 (kernel decomposition).
- Citation convention: `M:` = `integration/process-security-m4` at `19df31ad9`, with paths under `crates/kernel/chio-kernel/src/` unless stated. `W:` = the uncommitted recovery working tree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`; its line references reflect 2026-10-04 and may drift.
- Origin: `docs/research/2026-10-04-chio-kernel-north-star.md` bet 1 (keystone), lever 3 of the internal assessment.
- Siblings: umbrella `2026-10-04-ftl-lessons-program-design.md`; program specs 1-8 (`closed-kernel-abi`, `authority-faults`, `typed-reservations`, `authority-space-teardown`, `unified-event-queue`, `opaque-adapter-context`, `microkernel-isolation-backend`, `durable-stop-epoch`, each `2026-10-04-<name>-design.md`); north-star specs `2026-10-04-crossing-primitive-design.md` (spec 10) and `2026-10-04-integrity-gated-admission-design.md` (spec 11).

## Revision 2 changes

An independent review found 3 Blocker, 15 Major, 5 Minor and 4 Nit issues (section 16 records each disposition). The main changes:

- **Caller custody is a durable transition.** At startup, M: moves `DispatchCommitted` to `AwaitingCallerReport` through a structural check. It does not "retain a live wait". The machine now emits that transition. Recovery closure under non-`Active` control keeps W:'s terminalization, and open decision 1 is rewritten.
- **The model distinguishes what the legacy models persist.** `Authorized` (plan complete) is separate from `Ready` (`ReadyToDispatch` persisted). `Parked` carries the budget hold and proposal. The cumulative-approval path is one combined acknowledgement. `Participant` covers all 12 requirement flags and every compensable attachment. `persist` takes the prior record and returns the security model's atomic forward action.
- **Commit failures split by reason and path.** A policy refusal on the fused path writes a deny tombstone, `Unavailable` replans from `Unbegun`, `VersionConflict` re-projects, and only slow-path refusals compensate. Refusals after the effect, and unknown commit outcomes, have their own rules.
- **One normative cut table.** `CutFacts` replaces `LivenessFacts`. The table covers every phase and cause, including governed active response and economic mutation, and spec 4 cites it.
- **Integrity is a crossing precondition**, not a participant. Read-only calls are their own operation class.
- **The evaluation context gains a disposition and a request source**, which covers the 17th method (`authorize_tool_call_reserving_blocking_with_metadata`), caller execution and nested flow.
- **The proof plan is honest about Aeneas.** An extractable core over codes and digests is lowered to Lean. Plans and receipt metadata live in a hydrator that is not extracted. Liveness moves to the TLA model under named fairness assumptions.

## 1. Decision summary

The decisions about a mediated request (the next admission state; whether to compensate, terminalize, transition, retain or wait; which receipt to sign) are made in imperative code mixed with I/O, across two durable operation models with their own legality predicates, at least five deciders of in-flight operations (section 2), two full evaluators with the same shape, and seventeen public evaluation methods under five evaluation dispositions. Only the pure kernel core is proven, and only over scalar projections. No TLA model describes the admission saga's states.

This design makes the decision a function:

```rust
pub fn transition(state: &AdmissionState, event: AdmissionEvent) -> Transition;
pub struct Transition { pub next: AdmissionState, pub effects: EffectList }
```

1. **One model.** `AdmissionState` covers both legacy operation models, factored as an operation class, a phase and participant facts (section 4). Every persisted record of both models has a total projection into it, and `persist` maps back exactly. Persisted state strings do not change during migration.
2. **One function.**
   - Every driver feeds events and performs effects through ports.
   - Every decider becomes one cut function over a typed cause and the facts the driver gathers.
   - The cut table in section 6.1 is normative for startup, recovery closure and the spec 4 drain.
3. **One entry point.** `evaluate(source, EvaluationContext)` replaces seventeen methods. Blocking is an adapter (section 8).
4. **Proof reaches the decision.**
   - The extractable core of `transition` (codes, bitsets, digests) is lowered to Lean through Aeneas.
   - The specs' safety predicates become Lean theorems.
   - A new `AdmissionMachine` Apalache model covers concurrent drivers and liveness under named fairness assumptions.
   - Differential random testing compares the machine with both legacy predicates, as two inclusions with listed expected disagreements (Cedar method).
5. **Simulation substrate.** Deterministic simulation drives the machine directly, injecting a fault at every effect group (section 10).

The machine decides; it never executes. Spec 10 owns how commit effects execute as crossing transactions. Spec 11 owns what the integrity check means. The machine only requires that it runs inside every dispatch-commit crossing.

## 2. Verified current state

| Fact | Evidence |
|---|---|
| Tool-dispatch model: 19 states and three kinds (`ToolDispatch`, `GovernedActiveResponse`, `GovernedEconomicMutation`), plus a separate six-valued `AdmissionDispatchState` | M: `admission_operation.rs:228-254`, `:257-277`, `:309-316`; kinds at `admission_operation/identity.rs:179-183` |
| Its legality is `is_legal_transition(from, to, kind, requirements)`, with companions `predispatch_state_enabled` and `dispatch_state_for` | M: `admission_operation/state.rs:597`, `:498`, `:516` |
| `ReadyToDispatch` is its own CAS step: `BudgetAuthorized` or `ApprovalReserved` moves to `ReadyToDispatch` with no attachments | M: `kernel/admission_coordinator.rs:1521-1539` (tool dispatch, `mark_durable_capture_pending`), `:1571-1580` (governed active response, `commit_durable_dispatch`) |
| The cumulative-approval path goes `BudgetAuthorized -> ReadyToDispatch` while `requirements.approval` is set, skipping `ApprovalReserved` | M: `state.rs:669-675` |
| `ApprovalRequired` sits between broker and budget, already holds a budget hold and a threshold proposal, and is followed by `BudgetAuthorized` | M: `state.rs:411-421`, `:640-659`; attached at `kernel/validation/cumulative.rs:210-219` |
| `AwaitingCallerReport` exits only to `Finalizing`, for tool dispatch with nonce and capture. `OutcomeUnknownAfterDispatch` is legal only from `DispatchCommitted` or `Finalizing` | M: `state.rs:686-704` |
| Startup caller custody is structural: a caller-report provider attempt plus a caller-executor profile, then a durable CAS to `AwaitingCallerReport` | M: `kernel/admission_coordinator/recovery/caller.rs:26-55` |
| Requirements have 12 flags: broker attempt, budget capture, approval, execution nonce, outcome eligibility, payment, authorization consumption, observation attempt zero, obligation, channel, credit exposure, supplemental authorization | M: `identity.rs:207-223` |
| 20 attachment kinds, including `RuntimeParticipantLedger`, `GovernedApprovalLedger`, `ExecutionNoncePreflight`, `ExecutionNonceIssuance`, `ToolOutcome` and `CallerDispatchContext` | M: `admission_operation.rs:391-412` |
| Security model: 15 states with a four-valued dispatch state. Its live writer is governed active response. `DelegatedBudgetReserved`, `PaymentAuthorized` and `CallerReserved` have no non-test writer | M: `admission_operation.part1.inc:74-90`, `:144-149`; `kernel/active_response_coordinator.rs:261-272`; `kernel/admission_cleanup/recovery_and_compensation.inc:463-466` |
| The security store refuses CAS into `CompensationPending`, `CallerReserved` or a terminal without an atomic forward action (a cleanup-action insert) | M: `admission_operation.part2.inc:282-293`, `:326-347` |
| Payment release authorities on M: are `PreDispatchNoEffect`, `TransportNotAccepted` and `ContractualZeroCharge`. Finalization releases under `ContractualZeroCharge` on denied delivery or zero amount | M: `payment/journal.rs:84-90`; `kernel/admission_coordinator/terminal_payment.rs:23-40`, `:121-125` |
| Seventeen public evaluation methods: 6 async, 6 blocking and 4 nested `evaluate_tool_call*`, plus `authorize_tool_call_reserving_blocking_with_metadata`, which `chio-api-protect` calls in production | M: `kernel/evaluation/evaluation_entry.rs:98-235`; `sync_evaluation_wrapper.rs:4-110`, `:204-222`; `session_ops/nested_tool_call.rs:36-195`; `crates/products/chio-api-protect/src/proxy/mediated.rs:591` |
| Five evaluation dispositions: kernel, legacy reservation, caller reservation, caller report, caller start. Caller execution re-runs the full evaluator under the last three | M: `kernel/evaluation/mod.rs:83-121`; `kernel/evaluation/caller_execution.rs:233`, `:412`, `:462` |
| Deciders of in-flight operations | (1) startup `reconcile_recoverable_admissions` (M: `recovery.rs:133-352`); (2) `retire_expired_parked_admission` (`recovery.rs:368-389`); (3) governed active response recovery `recover_nonterminal_active_response_operations_with_authorities`, which compensates `Prepared` and `ApprovalReserved` and converges a `DispatchCommitted` approval without terminalizing (`kernel/admission_cleanup.rs:633-709`), plus the committed-resume path that rolls a committed approval forward (`kernel/active_response_committed_recovery.rs:204`, `:424`; `admission_cleanup.rs:551-599`); (4) the post-dispatch error arms that terminalize (`async_evaluation_core.rs:1744-1761`, with matching arms in `nested_flow_evaluation.rs`); (5) W:'s `reconcile_recovery_original` (W: `kernel/admission_coordinator/recovery_runtime.rs:184-265`). Specs 4 and 8 would add a sixth and a seventh |
| Startup refuses to terminalize a `DispatchCommitted` operation that already has a durable tool outcome | M: `recovery.rs:408-418` |
| The extraction hub projects strings, vectors and runtime structs to booleans or bounded integers before the boundary. Its 18 functions are scalar. The 20-function count spans `formal_aeneas.rs` and `chio-credit/src/formal_economy.rs` | M: `crates/kernel/chio-kernel-core/src/formal_aeneas.rs:1-5`; `formal/aeneas/production.toml` |
| No TLA or Apalache model of the admission states exists, and `formal/MAPPING.md` places durable admission reconciliation out of scope | M: `formal/apalache/`; `formal/MAPPING.md` |
| DST covers two crash boundaries around receipt persistence | M: `tests/dst/support/durability_scenarios.rs:4-7` |
| `admission_operation_commits` retains sequence, version, mutation kind and operation digest per commit, not full per-version state | M: `crates/platform/chio-store-sqlite/src/admission_operation_store.sql:123-160` |

## 3. Goals and non-goals

Goals:

- One decision function for every path that changes an admission operation. No other code chooses a next state.
- One operation model, with an exact round trip to both legacy models and no persisted-format change during migration.
- One normative cut table, cited by specs 4 and 8.
- One evaluation entry point plus a blocking adapter.
- Machine-checked safety theorems, and liveness model-checked under named fairness assumptions.
- A deterministic simulation substrate that injects a fault at every effect group.

Non-goals:

- Executing commits, choosing transaction boundaries, anchors, group commit or sharding. These belong to spec 10.
- Changing receipts, wire messages, release authorities or saga rules 1-6. The machine encodes them; it does not alter them. The two places where the machine adopts one legacy behavior over another are listed in section 6.2.
- Proving the whole kernel. Ports, the store, dialect adapters and transports stay tested components.
- Modeling recovery workflows, process journals, work handles or the security cleanup-action queue as admission phases. They are driver concerns (section 7).

## 4. One operation model

### 4.1 State

```rust
// chio-kernel-core::admission_machine (no_std + alloc; closed enums, no wildcard arms)
pub struct AdmissionState {
    pub kind: OperationKind,              // ToolDispatch | GovernedActiveResponse | GovernedEconomicMutation
    pub class: OperationClass,            // Durable | ReadOnlyCheckOnly (section 4.4)
    pub phase: Phase,
    pub plan: ParticipantPlan,            // ordered participants required for this request (data)
    pub facts: ParticipantFacts,          // which participants are acknowledged, by digest
    pub capture: CaptureFact,             // NotRequired | NotCommitted | Committed | Unknown
    pub version: u64,
}

pub enum Phase {
    Unbegun,                              // no persisted row (fast path before its intent commit; read-only class)
    Prepared,
    Authorizing,                          // some, not all, planned participants acknowledged
    Parked { deadline: AuthorityTime },   // approval required; budget hold and proposal are facts
    Authorized,                           // plan complete; ReadyToDispatch not yet persisted
    Ready,                                // ReadyToDispatch persisted
    CapturePending(CaptureKind),          // Native | Caller, derived from attachments
    DispatchCommitted,
    AwaitingCallerReport,
    Finalizing(PostReturnStage),
    Compensating,                         // security model CompensationPending
    Mutation(MutationPhase),              // Ready | Submitted (economic mutation kind only)
    Terminal(Terminal),
}

pub enum Terminal {
    Completed, CompensatedBeforeDispatch, NotAcceptedAfterDispatchCommit,
    OutcomeUnknownAfterDispatch, DeniedAfterDelivery,
    EconomicMutationApplied, EconomicMutationNotApplied,
}

pub enum Participant {
    // one per requirement flag (M: identity.rs:207-223)
    BrokerAttempt, BudgetHold, ApprovalSet, ExecutionNonce, OutcomeEligibility, Payment,
    AuthorizationConsumption, ObservationAttemptZero, Obligation, Channel, CreditExposure,
    SupplementalAuthorization,
    // compensable attachments without a flag of their own (M: admission_operation.rs:391-412)
    ExecutionNoncePreflight, ExecutionNonceIssuance, RuntimeParticipantLedger,
    GovernedApprovalLedger, DpopReplayLedger, NativeDispatchLedger, CallerDispatchContext,
    // security model only (dormant on M:, section 4.3)
    DelegatedBudget,
}
```

Rules for the plan and facts:

- `ParticipantPlan` is derived once at `Begin` from the kind and the 12 requirement flags, plus the compensable attachments that the request will acquire.
- The plan does not include integrity. Integrity is a crossing precondition of every dispatch-commit step (rule M13).
- Plan order is the tool model's order: broker, then the parked approval path or the budget hold, then the approval set. The security model's order (budget, delegated budget, payment, approval) is the order for its kind.
- **The cumulative-approval path** acknowledges `BudgetHold` and `ApprovalSet` as one combined acknowledgement out of `Parked`. That is the legacy `BudgetAuthorized -> ReadyToDispatch` step with `requirements.approval` set (M: `state.rs:669-675`).
- `CaptureKind` is derived from attachments: `Caller` when a `CallerDispatchContext` attachment is present, otherwise `Native`.

### 4.2 Projection and persistence

`project(record, model) -> Result<AdmissionState, ProjectionError>` is total over every persisted combination. An unknown combination returns an error and is never guessed (section 12).

| Legacy state (model) | Phase | Facts and capture |
|---|---|---|
| no row | `Unbegun` | none |
| `Prepared` (both) | `Prepared` | none |
| `BrokerAttemptRegistered` (both) | `Authorizing` | `BrokerAttempt` |
| `ApprovalRequired` (tool) | `Parked { deadline }` | earlier facts plus `BudgetHold` and the proposal digest. The deadline comes from the `ThresholdProposal` attachment (M: `admission_operation.rs:848-866`) |
| `BudgetAuthorized` (both) | `Authorizing`, or `Authorized` if the plan has nothing after the hold | `BudgetHold` plus earlier facts |
| `DelegatedBudgetReserved` (security) | `Authorizing` | `BudgetHold`, `DelegatedBudget` |
| `PaymentAuthorized` (security) | `Authorizing` | `BudgetHold`, `DelegatedBudget`, `Payment` |
| `ApprovalReserved` (both) | `Authorized` | `ApprovalSet` plus earlier facts |
| `ReadyToDispatch` (both) | `Ready` | every planned participant |
| `CapturePending` (both) | `CapturePending(kind from attachments)` | capture `NotCommitted` |
| `CallerReservationCapturePending` (security) | `CapturePending(Caller)` | capture `NotCommitted` |
| `DispatchCommitted` (both) | `DispatchCommitted` | capture `Committed` when required |
| `AwaitingCallerReport` (tool) | `AwaitingCallerReport` | as above |
| `CallerReserved` (security, dormant) | `AwaitingCallerReport` | as above |
| `Finalizing` (tool) | `Finalizing(stage)` | stage from the tool-outcome attachment |
| `CompensationPending` (security) | `Compensating` | facts retained for release |
| `MutationReady`, `MutationSubmitted` (economic) | `Mutation(Ready)`, `Mutation(Submitted)` | `NotRequired` |
| Every terminal (both) | `Terminal(..)` with the same name | unchanged |

`persist(state, prior_record, model, kind) -> PersistPlan` is the inverse:

- It returns the legacy state, the legacy dispatch state, and the attachments to add.
- For the security model it also returns the **atomic forward action** (kind and payload digest) that every compensation, caller reservation and terminal requires (M: `part2.inc:282-293`, `:326-347`).
- `Authorized` persists as the state the prior record already holds (`BudgetAuthorized` or `ApprovalReserved`). `Ready` persists as `ReadyToDispatch`. So `Authorized -> Ready` is exactly the legacy `ReadyToDispatch` step.
- `persist(project(r), r, model, kind) == r` for every reachable record of both models. This is a unit test and a Kani harness.

### 4.3 Security model scope

The security model's live surface on M: is governed active response: `Prepared -> ApprovalReserved -> DispatchCommitted`, plus compensation and terminals. `DelegatedBudgetReserved`, `PaymentAuthorized` and `CallerReserved` have no non-test writer. The machine keeps rows for them so that `project` stays total. The differential effort in phase 0 targets the live transitions and lists the dormant ones as covered by projection only.

The cleanup-action queue (`Pending`, `Claimed`, `Completed`, with claim tokens) is a driver concern. The machine emits the forward action through `persist`, and the driver executes the queue.

### 4.4 Operation classes

- `Durable`: every phase above. Dispatch requires `DispatchCommitAcknowledged`.
- `ReadOnlyCheckOnly`: the class for spec 10's check-only read path. It is eligible only when all three hold, and the driver decides that at `Begin`:
  - the deployment's `DurableAdmissionMode` does not cover `ReadOnly`, which excludes the process host because it runs `All`;
  - `can_redispatch_unknown_read` holds (M: `kernel/validation.rs:256-305`);
  - no pre-dispatch consumable applies: no `max_invocations`, cost, DPoP, nonce, approval, aggregate or supplemental quota, runtime hook or swarm admission.

  It has no persisted row: `Unbegun`, then `CheckOnlyAcknowledged`, then dispatch, then a release outcome.

## 5. Events and effects

### 5.1 Events

```rust
pub enum AdmissionEvent {
    Begin { binding: BindingDigest, plan_inputs: PlanInputs, ids: IdentityPayload, now: AuthorityTime },
    Replan { slow_path: bool },               // from Unbegun after spec 10 reports Unavailable
    ParticipantAcknowledged { participant: Participant, digest: Digest },
    CombinedAcknowledged { participants: ParticipantSet, digests: DigestSet }, // cumulative approval
    ParticipantRefused { participant: Participant, reason: RefusalCode },
    ApprovalRequired { proposal: ProposalDigest, deadline: AuthorityTime },
    ApprovalSupplied { approval_set: Digest },
    CaptureCommitted { kind: CaptureKind },
    DispatchCommitAcknowledged { committed_version: u64 },
    CheckOnlyAcknowledged,                    // read-only class only
    EffectAcknowledged { effect: EffectId, committed_version: u64 },
    CallerStartAuthenticated, CallerReportAuthenticated { outcome: OutcomeDigest },
    ToolReturned { outcome: OutcomeDigest, cost: CostFact },
    PostReturnStageDone { stage: PostReturnStage },
    OutputDigestMismatch,
    NotAccepted { proof: NoEffectProof },     // TransportNotAccepted evidence
    TransportAmbiguous { cause: AmbiguityCause },
    MutationSubmitted,
    MutationResult { applied: bool, result_digest: Digest },
    CommitFailed { effect: EffectId, reason: CommitFailure },
    CommitOutcomeUnknown { effect: EffectId },
    Cut { cause: CutCause, facts: CutFacts, now: AuthorityTime },
    Tick { now: AuthorityTime },
}

pub enum CommitFailure {  // spec 10 CrossingRefused, plus two non-policy reasons
    KernelStopped, AuthoritySpaceClosed, Revoked, InsufficientIntegrity, ReservationConflict,
    VersionConflict, Unavailable, Overloaded,
}

pub enum AmbiguityCause {
    Cancelled { reason: ReasonCode },
    Deadline { stage: StageCode, budget_ms: u32 },
    Incomplete,
    UrlElicitation { nested_observed: bool },
}

pub enum CutCause {
    StartupRecovery,
    ApprovalRetirement,
    GovernedResponseRecovery,
    RecoveryClosure { control: WorkflowControl },   // W: Active | CancelRequested | Cancelled | Quarantined
    AuthorityCut { trigger: TriggerDigest },        // spec 4 drain
}

pub struct CutFacts {
    pub nonce_issuance_live: bool,
    pub caller_reservation_live: bool,
    pub caller_report_custody: bool,              // structural (M: recovery/caller.rs:26-40)
    pub durable_return: DurableReturn,            // None | Recoverable | Unrecoverable
    pub capture: CaptureFact,                     // NotRequired | NotCommitted | Committed | Unknown
    pub approval_reservation: ApprovalReservation, // None | Reserved | Committed (governed active response)
    pub dispatch_status: Option<DispatchStatus>,  // Accepted | NotAccepted(proof) | Unknown
}
```

Rules for inputs:
- **Time is an input.** The driver reads the fallible authority clock and passes `now`. The machine never reads a clock.
- **Facts are inputs.** Every fact the deciders read inline today is gathered by the driver from its store and passed in `CutFacts`.
- **Identities are inputs.** Values allocated with `Uuid::now_v7()` today enter only through `IdentityPayload`: nonce ids, credential reservation ids, governed reservation ids, and cleanup claim tokens (M: `admission_operation/execution_nonce/profile.rs:65`; `kernel/credential_reservation/acquisition.rs:32`; `kernel/governed_validation.rs:503`; `kernel/admission_cleanup.rs:433`).

### 5.2 Effects

```rust
pub struct EffectList { groups: [Option<EffectGroup>; 4] }   // ordered; each group is atomic
pub struct EffectGroup { effects: [Option<Effect>; 4] }      // executed as one crossing or one port call

pub enum Effect {
    IntentCommit(IntentCommitPlan),          // Prepared..DispatchCommitted, including capture, in one crossing (spec 10)
    ReturnRecord(ReturnRecordPlan),          // durable tool return before post-return work (spec 10)
    OutcomeCommit(OutcomeCommitPlan),        // post-return stages, terminal projection, receipt, influence join
    CheckOnlyCrossing(CheckOnlyPlan),        // read-only class: checks with no write (spec 10)
    ParticipantCommit(ParticipantStep),      // slow path: one participant step
    DenyTombstone { reason: CommitFailure, receipt: ReceiptPlan },   // fused-path policy refusal
    Park { proposal: ProposalDigest, deadline: AuthorityTime, expected_version: u64 },
    RequestApproval { proposal: ProposalDigest },
    Dispatch,
    CallerAwaitStart, CallerAwaitReport { expected_version: u64 },
    QueryParticipant { participant: QueryTarget },   // capture, mutation, approval reservation, dispatch status
    CancelTransport,                         // cooperative cancel where the transport supports it
    Compensate { cause: CompensationCause, release: Option<MachineRelease>, receipt: ReceiptPlan, expected_version: u64 },
    Terminalize { terminal: Terminal, release: Option<MachineRelease>, receipt: ReceiptPlan, expected_version: u64 },
    FlushChildReceipts,                      // nested flow, before the parent's receipt
    ReplayTerminal,                          // return the bound terminal result
    SignReceipt { decision: ReceiptDecision, metadata: ReceiptMetadataPlan }, // receipts not bound to a state change
    Latch { reason: LatchReason },           // spec 3 fail-closed latch
    Fault { kind: FaultKind },               // operator-visible fault; no state change
    Hint { subject: HintSubjectRef },        // spec 5, after commit (H2)
    Retain,
}

pub enum MachineRelease { PreDispatchNoEffect, TransportNotAccepted, ContractualZeroCharge }

pub enum ReceiptDecision {
    Allow, Deny { code: DenyCode }, DenyDelivery { reason: ReasonCode },
    Cancelled { reason: ReasonCode }, Incomplete, PendingApproval, Withheld { reason: ReasonCode },
}
```

**Effect-list semantics.**
- Groups execute in order. A group runs only after the previous group is acknowledged.
- Effects inside a group are atomic: one crossing, or one port call that is atomic at its authority.
- Every state-mutating effect carries the expected operation version. A mismatch returns `CommitFailed { VersionConflict }`.
- `Compensate` and `Terminalize` carry their receipt, so the terminal projection binds the no-effect proof and the receipt atomically (saga rule 5).
- A compensation that needs an external rail release first is two groups: the rail release (`ParticipantCommit`), then the projection. A partially completed compensation is driven again by the next `Cut`.
- Capacity is fixed: at most 4 groups of 4 effects. Every arm builds a literal list, so exceeding capacity is a compile error.

**The plan types.**
- `IntentCommitPlan` lists the ordered steps the fast path commits atomically: begin, participant acknowledgements, ready, capture when `budget_capture` is set (`CapturePending` and the capture itself), then the dispatch commit (M: `state.rs:676-685` requires `CapturePending` before `DispatchCommitted` under capture). It runs only when every participant has an in-transaction form in the admission writer (spec 10).
- `ReturnRecordPlan` makes the returned bytes and cost durable, and binds the post-return evaluation time, frozen steps and normalized context, before post-return work.
- `OutcomeCommitPlan` lists the pure post-return results, the terminal projection with its payment plan, the receipt, and spec 11's output influence join.
- `CheckOnlyPlan` lists the crossing checks for a read-only call. The receipt rides the release commit.
- Each plan carries the expected operation version (spec 10 rule X5).

**Release authorities.**
- The machine emits `PreDispatchNoEffect` (compensation), `TransportNotAccepted` (proven non-acceptance) and `ContractualZeroCharge`.
- `ContractualZeroCharge` is emitted only in an `OutcomeCommit` or `Terminalize` whose recomputed amount is zero, or whose terminal is `DeniedAfterDelivery` (M: `terminal_payment.rs:121-125`).
- Releases after an unknown outcome (`MutuallyAgreedUnknown`, `ContractualCaptureWaiver`) mutate the payment journal outside this machine. They never change an admission phase (spec 3; spec 4 section 5 rule 2).

**Compensation causes map to the legacy policy strings** bound into the no-effect proof:

| `CompensationCause` | Legacy policy (authority, cause) | Source |
|---|---|---|
| `StartupNoBudgetParticipant` | `startup-recovery`, `no-authoritative-budget-participant` | M: `recovery.rs:234-235` |
| `StartupApprovalDeadline` | `startup-recovery`, `approval-deadline-elapsed` | M: `recovery.rs:273-274` |
| `ApprovalRetirement` | `kernel-approval-retirement`, `approval-deadline-elapsed` | M: `recovery.rs:384-385` |
| `RecoveryOriginalClosure` | `scoped-recovery`, `original-pre-dispatch-closure` | W: `recovery_runtime.rs:226` |
| `AuthorityCut` | the spec 4 trigger digest | spec 4 section 5 |
| `PreDispatchRefusal { reason }` | the existing evaluator pre-dispatch policy strings | pinned from source in phase 0 |

## 6. Transition rules

`transition` is total. Normative rules:

1. **M1. Purity.** `transition` performs no I/O, reads no clock, draws no randomness, allocates no identity and never panics. It lives in `chio-kernel-core` with `no_std + alloc`. Identities arrive as event payloads (section 5.1).
2. **M2. Exhaustive, with idempotent arms.** Every match over `Phase`, `AdmissionEvent`, `CutCause`, `Participant` and `CommitFailure` is exhaustive with no wildcard arm (ADR-0019 item 6, adopted by extension).
   - A duplicate acknowledgement, or a re-fed event the persisted state already reflects, yields `Retain` with no fault.
   - `Begin` against a terminal yields `ReplayTerminal`.
   - Any other event illegal in the phase yields `next == state` and a `Fault { IllegalEvent }`. It never yields a partial state.
3. **M3. Prepared first.** No step that mutates a participant precedes the `Prepared` step of the same operation (saga rule 1). On the fast path both are in one `IntentCommit`.
4. **M4. Commit before handoff.** `Dispatch` is emitted only in the transition consuming `DispatchCommitAcknowledged`. For the read-only class it is emitted only on `CheckOnlyAcknowledged`.
5. **M5. Plan order.** A participant is acknowledged only when every earlier participant in the plan is acknowledged, except through the combined cumulative-approval acknowledgement. `Authorized` is entered exactly when the plan is complete. `Ready` is entered exactly when `ReadyToDispatch` is persisted.
6. **M6. Absorbing terminals.** No transition leaves a terminal phase. A terminal accepts `Tick` (`Retain`) and `Begin` (`ReplayTerminal`).
7. **M7. Unknown stays unknown.** `TransportAmbiguous` after dispatch commit moves to `Terminal(OutcomeUnknownAfterDispatch)` with no release, and the receipt carries the typed `AmbiguityCause`. No `Dispatch` follows. Holds stay frozen, and any later release happens in the payment journal outside the machine.
8. **M8. Cuts.** A `Cut` event is classified only by the normative table of section 6.1.
9. **M9. Liveness protection.** `Prepared` with `nonce_issuance_live`, and `Ready` with `caller_reservation_live`, are retained under `StartupRecovery`, and under `RecoveryClosure` only while control is `Active` (M: `recovery.rs:206-221`; W: `recovery_runtime.rs:213-218`). No other cause is protected.
10. **M10. Pre-dispatch commit failures.**

    | Failed effect | Reason | Next and effects |
    |---|---|---|
    | `IntentCommit` (fused) | `KernelStopped`, `AuthoritySpaceClosed`, `Revoked`, `InsufficientIntegrity`, `ReservationConflict` | `DenyTombstone` with the refusing reason, then `Terminal(CompensatedBeforeDispatch)`. The tombstone keeps the request id terminal (saga rule 4; spec 8 S15) |
    | `IntentCommit` | `Unavailable` | stay `Unbegun`; the driver feeds `Replan { slow_path: true }`, and the machine emits slow-path `ParticipantCommit` steps |
    | any | `VersionConflict` | `Retain`; the driver re-projects from the store and re-feeds. Never compensates |
    | `IntentCommit` | `Overloaded` | stay `Unbegun`; the driver returns the overload error with no receipt and no state, as a pre-admission refusal |
    | slow-path dispatch-commit step | any policy reason | `Compensate { PreDispatchNoEffect, receipt }` |
    | `ParticipantCommit` | `ParticipantRefused` | `Compensate { PreDispatchNoEffect, receipt }` |
    | `CheckOnlyCrossing` | any policy reason | `SignReceipt(Deny)` with the reason; nothing to compensate |

11. **M11. Refusals after the effect.** For `ReturnRecord`, `OutcomeCommit` and the release crossings:
    - `KernelStopped`: `Retain` in `Finalizing(stage)`, with output withheld. The next `Tick` or `Cut` after the stop is resumed re-emits the commit (spec 8 S14).
    - `AuthoritySpaceClosed`, `Revoked` or `InsufficientIntegrity`: `Latch`, then `Terminalize(DeniedAfterDelivery)` with a `DenyDelivery` receipt naming the reason and retained markers, matching spec 3 rule 12. The release follows the terminal payment plan.
    - `ReservationConflict`: `Latch` and `Fault`. It is unreachable after the effect, because reservations commit in the intent commit, so reaching it is an invariant violation.
    - `VersionConflict`: re-project.
    - For the read-only class: a refused release signs a `Withheld` receipt through a non-crossing commit.
12. **M12. Unknown commit outcome.** `CommitOutcomeUnknown` from any effect: `Latch`, no compensation, no dispatch and no state change. The driver halts the operation, and restart re-projects it from the store.
13. **M13. Integrity at every dispatch commit.** Every dispatch-commit step, fast or slow, and every `CheckOnlyCrossing`, is a crossing that carries spec 10's full `CrossingCheck` list, including `KnowledgeIntegrity` (spec 11 rule I15). No earlier acknowledgement satisfies it.
14. **M14. Post-effect discharge (safety form).** Every post-dispatch phase has an enabled transition to a terminal, a durable-outcome acknowledgement or a `Latch`, under the fair events named in section 10. No transition returns a post-dispatch operation to a pre-dispatch phase. The discharge set matches spec 3 section 4.8: terminal, durable outcome, terminalized admission, post-effect fault receipt, or buffered fault plus latch.

### 6.1 The normative cut table

`classify(state, cause, facts, now) = transition(state, Cut { cause, facts, now }).effects` by definition. Every decider in section 2 becomes a driver of this table. Spec 4's drain and spec 8's stop path cite it rather than restating it.

Columns: `S` = `StartupRecovery`; `A` = `RecoveryClosure` with control `Active`; `N` = `RecoveryClosure` with control other than `Active`; `X` = `AuthorityCut`. `ApprovalRetirement` applies only to `Parked`, and `GovernedResponseRecovery` only to governed active response.

| Phase (kind) | S | A | N | X |
|---|---|---|---|---|
| `Prepared` | Retain if `nonce_issuance_live`, else Compensate | as S | Compensate | Compensate |
| `Authorizing`, `Authorized` | Compensate | Compensate | Compensate | Compensate |
| `Ready` | Retain if `caller_reservation_live`, else Compensate | as S | Compensate | Compensate |
| `Parked` | Compensate if the deadline elapsed, else `Retain` plus `Fault { QuiescentParked }` (M: `recovery.rs:260-266`) | Compensate if elapsed, else Retain | Compensate | Compensate |
| `CapturePending`, capture `NotCommitted` | Compensate | Compensate | Compensate | Compensate |
| `CapturePending`, capture `Committed` | `IntentCommit` remainder to `DispatchCommitted` (no handoff happened yet), then as `DispatchCommitted` | as S | as S | as S |
| `CapturePending`, capture `Unknown` | `QueryParticipant(Capture)`, Retain | as S | as S | as S |
| `DispatchCommitted`, durable return `Recoverable` | `Finalizing`: the next post-return stage (never terminalize; M: `recovery.rs:408-418`) | as S | as S | `Latch`, then as S |
| `DispatchCommitted`, `caller_report_custody` | `CallerAwaitReport` to `AwaitingCallerReport` | as S | `Terminalize(OutcomeUnknownAfterDispatch)` (W:) | `Latch`, `CancelTransport`, then as S |
| `DispatchCommitted`, otherwise | `NotAccepted` proof in `dispatch_status`: `Terminalize(NotAcceptedAfterDispatchCommit, TransportNotAccepted)`; else `Terminalize(OutcomeUnknownAfterDispatch)` | as S | as S | `Latch`, `CancelTransport`, then as S |
| `AwaitingCallerReport` | Retain | Retain | `Latch` plus `Fault { UnsettledCallerCustody }` (open decision 1) | `Latch` plus the same fault |
| `Finalizing`, return `Recoverable` | next post-return stage | as S | as S | `Latch`, then as S |
| `Finalizing`, return `Unrecoverable` | Retain plus `Fault { UnrecoverableReturn }` (M: claims recovery and continues, `recovery.rs:308-318`) | as S | as S | as S |
| `Compensating` | Compensate (drive again) | as S | as S | as S |
| `Mutation(Ready)` | `QueryParticipant(Mutation)`, then Applied or NotApplied by result | as S | as S | as S |
| `Mutation(Submitted)` | `QueryParticipant(Mutation)`, Retain until the result | as S | as S | as S |
| `Authorized` (governed active response), approval reservation `Committed` | roll forward to `DispatchCommitted`; a committed approval cannot be cancelled (M: `admission_cleanup.rs:551-599`, `:602-607`) | as S | as S | as S, then `Latch`; the closed space refuses the execution crossing |
| `Authorized` (governed active response), approval reservation `None` or `Reserved` | Compensate (M: `admission_cleanup.rs:661-676`) | Compensate | Compensate | Compensate |
| `DispatchCommitted` (governed active response) | `QueryParticipant(ApprovalReservation)`, commit it if still `Reserved`, Retain; never terminalize while the executor can resume (M: `admission_cleanup.rs:602-627`) | as S | as S | `Latch`, then as S |
| Terminal | Retain | Retain | Retain | Retain |

`ApprovalRetirement` on `Parked` with an elapsed deadline compensates with cause `ApprovalRetirement`. `GovernedResponseRecovery` uses the `S` column. For the governed active response kind, its own rows take precedence over the generic `Authorized` and `DispatchCommitted` rows.

```text
forall cause: Compensate in classify(s, cause, f, t) -> pre_dispatch(s) and f.capture != Committed
forall cause: Terminalize(OutcomeUnknownAfterDispatch) in classify(s, cause, f, t) -> s.phase = DispatchCommitted and f.durable_return = None
```

### 6.2 Decisions where the legacy deciders disagree

| Divergence | M: startup | W: recovery closure | Machine |
|---|---|---|---|
| Caller-report custody at `DispatchCommitted` | durable transition to `AwaitingCallerReport` | terminalizes | transition under S and A; terminalize under N (W:) |
| `Parked` before the deadline | retain, plus a deferred quiescent fault | close when control is not `Active` | S retains with `Fault`; N compensates |
| `Finalizing` without a recovery request | claims recovery and continues | errors | Retain plus `Fault` (M:) |
| Wildcard phases | `claim_admission_recovery` | no action | no wildcard; every phase has a row |
| Governed `ApprovalReserved` with a committed approval | startup recovery stages compensation (`admission_cleanup.rs:661-676`); the resume path rolls forward (`:551-599`) | not covered | roll forward under every cause |
| Clock | fallible authority clock | infallible system clock (W: `admission_coordinator.rs:192-194`) | authority clock only (umbrella N15) |

## 7. Drivers and ports

| Driver | Feeds | Performs through |
|---|---|---|
| `EvaluationDriver` (async) | `Begin`, acknowledgements, capture, dispatch acknowledgement, tool return, post-return stages, failures | `CrossingPort` (spec 10), `DispatchPort`, `SigningPort`, participant ports, `HintPort` |
| `BlockingAdapter` | none of its own: wraps `EvaluationDriver` on the existing blocking runtime | as above |
| `NestedFlowDriver` | the same events, with nested-flow client callbacks as an event source | as above, plus `NestedFlowClient` |
| `CallerExecutionDriver` | reserve, `CallerStartAuthenticated` and `CallerReportAuthenticated`, under the caller dispositions | `CrossingPort` |
| `StartupReconciler` | `Cut(StartupRecovery)` per recoverable operation, after the lease claim | `CrossingPort`, `SigningPort` |
| `ApprovalRetirementDriver` | `Cut(ApprovalRetirement)` | as above |
| `GovernedResponseRecoveryDriver` | `Cut(GovernedResponseRecovery)`, and the committed active-response resume (M: `kernel/active_response_committed_recovery.rs:204`, `:424`) | as above |
| `RecoveryClosureDriver` (W:) | `Cut(RecoveryClosure { control })` | as above |
| `DrainDriver` (spec 4) | `Cut(AuthorityCut { trigger })` | as above |
| `ReservationReconcileDriver` | settlement of a reserved authorization by nonce (M: `kernel/reconciliation.rs:148`) | as above |

The rules for drivers:
- Drivers own leases (the existing `mutation_sequencer.try_own_operation`), the clock, fact lookups, identity allocation, and every port call.
- A driver never chooses a next state. It persists `next` through the commit effects that spec 10 executes, using `persist` and the version CAS.
- A crash between an effect and its acknowledgement is resolved by re-projecting the persisted record and re-feeding only the events the driver can prove (participant lookup by `operation_id`). It is never resolved by assumption.

## 8. One evaluation entry point

```rust
impl ChioKernel {
    pub async fn evaluate(&self, source: RequestSource<'_>, ctx: EvaluationContext<'_>)
        -> Result<ToolCallResponse, KernelError>;
    pub fn evaluate_blocking(&self, source: RequestSource<'_>, ctx: EvaluationContext<'_>)
        -> Result<ToolCallResponse, KernelError>;   // adapter over evaluate
}

pub enum RequestSource<'a> {
    Direct(&'a ToolCallRequest),
    Nested(NestedFlow<'a>),     // { context: &OperationContext, operation: &ToolCallOperation,
                                //   client: &mut dyn NestedFlowClient, proofs: Option<..> }
}

pub struct EvaluationContext<'a> {
    pub disposition: Disposition,                    // Kernel | LegacyReservation | CallerReservation | CallerStart | CallerReport(conn)
    pub extra_metadata: Option<serde_json::Value>,
    pub security: SecuritySource<'a>,                // None | Explicit(&SecurityInvocationContext) | AuthenticatedSession { session_id, context }
    pub manifest: Option<ManifestSecurity<'a>>,      // (&VerifiedManifestRegistry, &BridgeSecurityMetadata)
}
```

`Nested` builds the `ToolCallRequest` internally, after `reject_conflicting_session_authorization` and `begin_or_resume_tool_request`. It finishes with `finish_session_tool_request`, including `Cancelled` bookkeeping, exactly as today (M: `session_ops/nested_tool_call.rs:52-112`, `:132-195`).

| Legacy entry point (M:) | `RequestSource` and `EvaluationContext` |
|---|---|
| `evaluate_tool_call` | `Direct`, defaults |
| `evaluate_tool_call_with_metadata` | `Direct`, `extra_metadata` |
| `evaluate_tool_call_with_security_context` | `Direct`, `security: Explicit` |
| `evaluate_tool_call_with_metadata_and_security_context` | `Direct`, `extra_metadata`, `security: Explicit` |
| `evaluate_tool_call_with_manifest_security` | `Direct`, `manifest`, `extra_metadata` |
| `evaluate_tool_call_with_manifest_security_and_security_context` | `Direct`, `manifest`, `extra_metadata`, `security: Explicit` |
| five blocking variants matching the async ones that exist in blocking form | as the async row, through `evaluate_blocking` |
| `..._blocking_with_manifest_security_and_authenticated_session_context` | `Direct`, `manifest`, `security: AuthenticatedSession`, through `evaluate_blocking` |
| four `evaluate_tool_call_operation_with_nested_flow_client*` (sync and async, with and without proofs) | `Nested` |
| `authorize_tool_call_reserving_blocking_with_metadata` | `Direct`, `extra_metadata`, `disposition: LegacyReservation`, through `evaluate_blocking` |
| caller reservation, start and report re-entries | `Direct`, `disposition: CallerReservation`, `CallerStart` or `CallerReport` |

The blocking mapping is pinned in phase 4 from the six blocking methods on M:. There is no blocking `metadata_and_security_context` form.

**Metadata validation per source:**
- Non-manifest sources run `reject_reserved_receipt_metadata` (M: `evaluation_entry.rs:118`, `:154`; `sync_evaluation_wrapper.rs:46`).
- Manifest sources run `registry_validated_manifest_security_metadata` instead.

**Combination validity.** Combinations with no legacy equivalent are refused at construction with `KernelError::InvalidEvaluationContext`. That covers caller dispositions with `Nested`, and `AuthenticatedSession` without `manifest`.

**Budgets.** The legacy methods stay as `#[deprecated]` one-line wrappers for one minor release, then are removed. Spec 1's entry-point budget for `EvaluateToolCall` and `EvaluateSessionOperation` falls from 17 public methods to 2. The duplicated post-effect region (D1 at M: `async_evaluation_core.rs:1740` and `nested_flow_evaluation.rs:1495`) then exists once, inside the one driver that spec 3's obligation wraps.

## 9. Migration

Each phase keeps the suite green and changes no wire, receipt or persisted format.

1. **Phase 0: model, prototype extraction and differential.**
   - Land the vocabulary, `project`, `persist` and `transition`.
   - Extract a prototype of the core through Aeneas before committing to the theorem list (section 10).
   - Run the differential as two inclusions over the live transitions of both models:
     - every machine-reachable step persists to a step the legacy predicate allows;
     - every legacy-legal step under the record's plan is machine-reachable.
   - Expected disagreements are listed before the run:
     - the cumulative combined acknowledgement;
     - the governed active response `ReadyToDispatch` insertion;
     - the dormant security states, covered by projection only;
     - the five divergences of section 6.2.
2. **Phase 1: startup reconciler and approval retirement.** Effects must equal today's behavior on the DST seeds and the existing recovery tests, including the durable `AwaitingCallerReport` transition.
3. **Phase 2: recovery closure and governed active response recovery.** These follow the section 6.1 rows.
4. **Phase 3: drain and stop.** Spec 4's drain and spec 8's stop path are built on the machine from the start.
5. **Phase 4: evaluators.** `EvaluationDriver`, `NestedFlowDriver`, `CallerExecutionDriver` and `ReservationReconcileDriver` replace their legacy code. The `evaluate` entry point lands and the seventeen wrappers are deprecated.
6. **Phase 5: one persisted model** (open decision 2).

**Compatibility period.** Through phase 5, the store's CAS keeps asserting the legacy predicate for the record's model. When the predicate rejects a machine-chosen step, that operation is handed to the retained legacy driver, with an `audit_fault`. It is never blocked, and holds are never stranded. The assertions and the legacy drivers are removed only after one release with zero recorded disagreements in CI, DST and production traces.

**Receipts and wire.** No change. The machine reproduces the decisions today's code makes, except the section 6.2 rows. Those are decided explicitly, and each is covered by a conformance case.

## 10. Proof and simulation plan

**Extraction.** The machine splits into two parts:
- `admission_machine::core`: phases and participants as codes, facts as fixed-width bitsets, digests as `[u8; 32]`, effects as codes. It is extractable: no `serde_json`, no attachments and no heap collections, consistent with the hub's rule (M: `formal_aeneas.rs:1-5`).
- `admission_machine::hydrate`: builds `IntentCommitPlan`, receipt metadata and attachments from core codes. It is not extracted, and it is covered by differential tests and Kani.

Phase 0 extracts a prototype core with payload-carrying enums before committing T1-T10. The Lean statements live in `Chio/Admission/Machine.lean`.

**Theorems** (safety, over the extracted core):

| Theorem | Statement | Closes |
|---|---|---|
| T1 `prepared_first` | no participant-mutating step precedes `Prepared` | saga rule 1 |
| T2 `commit_before_dispatch` | `Dispatch` only on `DispatchCommitAcknowledged`, or on `CheckOnlyAcknowledged` for the read-only class | saga rule 3 |
| T3 `no_compensation_after_commit` | `Compensate` only from pre-dispatch phases with capture not committed | spec 4 section 5 |
| T4 `machine_release_authorities` | the machine emits only `PreDispatchNoEffect`, `TransportNotAccepted` or `ContractualZeroCharge`, and the last only on a zero recomputed amount or `DeniedAfterDelivery` | saga rule 6 |
| T5 `terminal_absorbing` | no transition leaves a terminal phase | saga rule 4 |
| T6 `unknown_stays_unknown` | no `Dispatch` and no machine release after `OutcomeUnknownAfterDispatch` | saga rule 6 |
| T7 `fence_dominance` | a policy refusal on any dispatch-commit step (fast or slow) or check-only crossing never leads to `Dispatch`; a refusal on an outcome or release commit never leads to an `Allow` receipt | spec 8 S7/S15, spec 4 section 4.1, spec 11 |
| T8 `post_effect_discharge` | every post-dispatch phase has an enabled discharge transition under the named fair events, and none returns to a pre-dispatch phase | spec 3 section 4.8 |
| T9 `plan_order` | participants are acknowledged in plan order or by the combined acknowledgement; `Authorized` exactly when the plan is complete | both legacy orderings |
| T10 `replay_uniqueness` | an operation in a terminal phase, including a deny tombstone, never reaches `Dispatch` again for the same binding | saga rule 4 and its predicates |

**Model checking.**
- Add `formal/apalache/AdmissionMachine.tla` for two operations and these concurrent drivers racing through version CAS: evaluator, startup reconciler, recovery closure, caller execution, the drain, and the governed active response resume.
- Safety invariants T2, T3, T5, T7 and T10 are checked under interleaving, with a negative model for each.
- **Liveness** is checked here, not in Lean, under weak fairness on these events:
  - eventually a caller report, or the open decision 1 deadline edge;
  - eventually a transport answer or ambiguity;
  - eventually a driver re-feed after a crash.
- The model registers in `formal/proof-manifest.toml` and mirrors the core through `formal/MAPPING.md`.

**Differential random testing** (Cedar method). A property-based generator produces random event sequences per kind, class and plan. It runs them through the extracted core, the hydrator, and, during compatibility, the legacy predicates. Agreement is required on `next` and on effect codes.

**Trace validation.** Today's commit log retains digests, not states (section 2). Phase 1 validates that machine-produced states hash to the retained operation digests. Full replay of production histories needs per-version snapshots or an event log (open decision 6).

**Deterministic simulation.**
- The DST harness drives the machine directly. A seeded scheduler interleaves events for many operations from all drivers, and injects at every effect group: commit failure for each reason, unknown commit outcome, a crash between effect and acknowledgement, ambiguous transport for each cause, post-effect refusal, and clock unavailability.
- The oracles are T1-T10 as runtime assertions, plus the legacy predicates during compatibility.

## 11. Performance

The machine is pure, allocation-bounded and in memory, so it adds no I/O. Its cost is a few code matches per event. It enables, but does not deliver, the hot-path gain: emitting one `IntentCommitPlan` for a whole pre-dispatch run is what lets spec 10 fuse today's separate commits.

Acceptance:
- Phase 4 must not regress the process-mediated benchmark medians (M: `sdks/typescript/packages/ai-sdk-process/BENCHMARK.md:176-188`) by more than noise.
- The kernel-only allow p50 must stay within 5 percent.

## 12. Failure modes

| Failure | Behavior |
|---|---|
| `project` meets an unknown persisted combination | `ProjectionError`. The driver refuses the operation, records an `audit_fault`, and leaves it for operator recovery |
| Illegal event for the phase | `Fault { IllegalEvent }` and no state change. Duplicates and replays are idempotent, not faults (M2) |
| Machine and legacy predicate disagree (compatibility) | the operation is handed to the legacy driver, with an `audit_fault`; never blocked |
| Commit effect refused | M10 before the effect, M11 after it |
| Commit outcome unknown | M12: latch and halt; re-project at restart |
| Crash between effect and acknowledgement | re-project and re-feed provable events only (section 7) |
| Clock unavailable | the driver cannot construct the event, so no transition occurs. Pre-dispatch work fails closed through the existing authority-time errors |
| Partially completed compensation | the next `Cut` drives it again from `Compensating` or the persisted phase |

## 13. Rollout

| Phase | Content | Gate |
|---|---|---|
| 0 | Vocabulary, projection, persistence, prototype extraction, differential | Prototype extracts; zero unexplained disagreements |
| 1 | Startup and approval-retirement drivers; Lean skeleton; `AdmissionMachine.tla` | T3, T5, T10 proven; Apalache positive and negative pass |
| 2 | Recovery closure and governed active response drivers | W: recovery suites and governed active response recovery tests green |
| 3 | Drain and stop drivers (with specs 4 and 8) | Spec 4 and 8 conformance |
| 4 | Evaluation, nested, caller-execution and reservation-reconcile drivers; `evaluate`; deprecations | Benchmark acceptance; T1-T10 proven; liveness checked |
| 5 | Persisted model decision; compatibility assertions and legacy drivers removed | One release with zero disagreements |

Gate GT1 applies: no proof or conformance claim until the lanes run in hosted CI.

## 14. Tests and conformance evidence

- **Unit:** projection totality over all 19 tool-model and 15 security-model states with their dispatch pairs; `persist(project(r), r, ..) == r` for every reachable record, including security forward actions; rules M1-M14 by example; every row of the cut table.
- **Differential:** the two inclusions of phase 0, over the live transition space.
- **Proptest:** random event sequences per kind, class and plan, checking T1-T10 as executable assertions.
- **Kani:** `transition` never panics; `classify` is total; the hydrator's plans are well formed.
- **Lean:** T1-T10, with mirrors registered.
- **Apalache:** `AdmissionMachine.tla`, with negative mutants: drop the T2 guard, compensate after commit, leave a terminal, dispatch after a deny tombstone.
- **Loom:** two drivers racing on one operation through the CAS adapter; a cut racing a caller report.
- **DST:** one fault-injection seed per effect group and failure reason, added to `tests/dst/seeds.toml`.
- **Conformance:** the existing verdict-matrix and recovery scenarios pass unchanged through `evaluate`; one case for each section 6.2 decision; fused-path deny tombstone replay; read-only class eligibility refusal.

## 15. Residual risks and open decisions

Residual risks:

- **Ports stay tested, not proven.** A port that lies about an acknowledgement defeats the proofs. That is spec 1's `fact_source` polarity.
- **Extraction limits.** If the prototype fails to extract, the core's types narrow further, or the plan falls back to a hand-written Lean reference with differential tests (open decision 4).
- **Migration risk.** Phase 4 touches the two largest evaluator files. The legacy-driver fallback and the differential gate bound the risk, but cannot remove it.
- **Unsettled caller custody.** Under recovery closure with non-`Active` control, an `AwaitingCallerReport` operation stays non-terminal until a caller report arrives, with its holds frozen. It is visible through a fault, not resolved, until open decision 1.

Open decisions:

1. **Deadline for caller custody.** Should `AwaitingCallerReport` gain a deadline-bounded edge to `OutcomeUnknownAfterDispatch`, so that a quarantined or cancelled workflow can settle? This is a saga change and needs the admission-operation owners. Without it, the machine keeps W:'s terminalization for `DispatchCommitted` under non-`Active` closure, and latches with a fault for `AwaitingCallerReport` (section 6.1).
2. **Persisted model.** Migrate both stores to the canonical schema, or keep two tables behind `project`/`persist`? Recommendation: keep both through phase 4, then migrate in one schema version.
3. **Recovery and work machines.** Should recovery workflows and work handles get pure machines in the same style? This spec keeps them as drivers.
4. **Extraction or model.** Extract the core with Aeneas, or hand-write a Lean model and test the Rust differentially? Recommendation: extract the core if the phase 0 prototype succeeds, and keep a hand-written reference either way.
5. **Governed active response lifecycle.** The response-plan lifecycle (M: `formal/apalache/ResponseLifecycle.tla`) stays separate. This spec covers only its admission rows.
6. **Trace replay.** Add per-version snapshots or an event log to `admission_operation_commits`, so production histories can be replayed through the machine?
7. **Overload receipts.** Today's pre-admission overload returns an error with no receipt. Keep that (this draft), or sign an overload deny receipt without a tombstone?

## 16. Review disposition

| Finding | Severity | Disposition |
|---|---|---|
| S9-01 caller wait is a durable transition | Blocker | Applied: `CallerAwaitReport` transition (section 6.1); N terminalizes; open decision 1 rewritten as a saga decision |
| S9-02 projection collapses distinct states | Blocker | Applied: `Authorized` versus `Ready`; `Parked` facts; combined acknowledgement; 12 flags plus compensable attachments; `persist` with prior record; capture kind from attachments; two-inclusion differential |
| S9-03 `CommitFailed` classification contradicts the fast path | Blocker | Applied (shared decision 1): deny tombstone, `Unbegun` and `Replan`, `VersionConflict` re-projects; M10 table |
| S9-04 post-dispatch `CommitFailed` has no rule | Major | Applied: M11 |
| S9-05 missing cut inputs | Major | Applied: `CutFacts`; table rows for durable return, capture and dispatch status |
| S9-06 disagreement with spec 4's drain table | Major | Applied: section 6.1 is the normative table; `CancelTransport`, `QueryParticipant` and mutation rows added; `Parked` under `X` compensates |
| S9-07 deciders undercounted | Major | Applied differently: governed active response rows added instead of excluding it; every decider listed and given a driver |
| S9-08 security model live surface and atomic forward actions | Major | Applied: section 4.3; `persist` returns the forward action; cleanup queue is a driver concern |
| S9-09 single `evaluate` cannot express every path | Major | Applied: `RequestSource`, `Disposition`, the 17th method, metadata validation and combination validity |
| S9-10 missing events | Major | Applied: `Unbegun`, `EffectAcknowledged`, `CommitOutcomeUnknown`, `ParticipantRefused`, mutation events, `Tick` and `ApprovalRetirement` for `Parked` |
| S9-11 events too coarse for receipts | Major | Applied: `AmbiguityCause`, compensation cause mapping, `FlushChildReceipts`, `ReceiptDecision` |
| S9-12 integrity as a participant | Major | Applied (shared decision 6): M13 |
| S9-13 check-only conflicts | Major | Applied (shared decision 3): read-only class, `CheckOnlyAcknowledged`, T2 restated, M10 row |
| S9-14 release vocabulary incomplete | Major | Applied (shared decision 8): `ContractualZeroCharge`; T4 restated; M7 reworded |
| S9-15 liveness claims false | Major | Applied: M14 and T8 in safety form; liveness in TLA under named fairness; discharge set aligned with spec 3 |
| S9-16 effect-list semantics unspecified | Major | Applied: ordered atomic groups; receipts inside `Compensate` and `Terminalize`; expected versions |
| S9-17 fused plan omits `CapturePending`; compatibility strands holds | Major | Applied: capture in `IntentCommitPlan`; legacy-driver fallback |
| S9-18 Aeneas plan understated | Major | Applied: core and hydrator split; phase 0 prototype extraction |
| S9-19 more W:/M: divergences | Minor | Applied: section 6.2 |
| S9-20 trace validation overstated | Minor | Applied: digest validation in phase 1; replay as open decision 6 |
| S9-21 Apalache drivers omitted | Minor | Applied: recovery closure, caller execution and governed active response resume added |
| S9-22 illegal-event counter on legitimate inputs | Minor | Applied: idempotent arms and `ReplayTerminal` (M2, M6) |
| S9-23 identities not all deterministic | Minor | Applied: `IdentityPayload` (section 5.1) |
| S9-24 T10 tautological | Nit | Applied: T10 replaced with `replay_uniqueness` |
| S9-25 proof-hub citation | Nit | Applied: both sources cited; startup range corrected to `:133-352` |
| S9-26 ADR-0019 scope | Nit | Applied: adopted by extension |
| S9-27 umbrella says `Vec<Effect>` | Nit | Applied differently: this spec uses `EffectList`. The umbrella is outside this revision's file scope, so the parent aligns it |

## Appendix A. External and FTL precedent

- **FTL.** FTL's dispatch is one exhaustive match whose fallback is `UnknownSyscall` (FTL `kernel/src/syscall.rs:19-73`), and each object's state changes in one place. The machine applies that discipline to Chio's admission saga: one function, no wildcard.
- **Cedar** builds a readable executable Lean model, proves properties, then runs differential random tests of the Rust against it. The proofs found 4 bugs and the tests found 21 more ([How We Built Cedar](https://arxiv.org/pdf/2407.01688)). Section 10 follows the same three steps over the extracted core.
- **Atmosphere** is an L4-style microkernel proven functionally correct in Rust with Verus (SOSP 2025; [Atmosphere](https://mars-research.github.io/projects/atmo/)). It shows proof is feasible at the scale of a pure decision core.
- **Deterministic simulation.** TigerBeetle's VOPR runs every component under one seeded PRNG, so a failing seed reproduces exactly ([VOPR](https://docs.tigerbeetle.com/about/vopr)). A sans-IO machine makes that cheap.
- **AWS PObserve** validates production logs against P specifications ([Systems Correctness Practices at AWS](https://dl.acm.org/doi/abs/10.1145/3815784)). Section 10's trace validation is the same idea, limited today by the digest-only commit log.

Where the analogy breaks: FTL's dispatch has no durable state or crash recovery. Chio's machine must be re-entrant from any persisted version, which is why projection, persistence plans, cut facts and acknowledgement events exist.
