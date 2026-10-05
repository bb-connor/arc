# Design: pure admission machine

- Status: PROPOSED (revision 3, after the wave 2 cross-spec review of specs 3, 5 and 8, 2026-10-05)
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

## Revision 3 changes

The adversarial reviews of specs 3, 5 and 8 (`review-spec3`, `review-spec5`, `review-spec8`) found contradictions with this spec. The wave 2 shared decisions resolve them here; section 16 records each finding under "Wave 2 (cross-spec)". The main changes:

- **The latch has three scopes (S3-03).** `Effect::Latch` is gone. `HaltOperation` halts one operation, `LatchRequest` latches one session request (spec 4), and `KernelEvidenceLatch` closes new dispatch kernel-wide only while an unpersisted post-effect evidence record is buffered (spec 3 section 4.8). Every refusal after the effect, every unknown commit outcome and every post-dispatch cut row uses `HaltOperation`, so a revocation or a drain never closes the kernel to other tenants.
- **Spec 9 decides post-effect receipts (S3-15).**
  - New events: `PostEffectStepFailed` and `ReceiptAppendFailed { Refused | Unknown }`.
  - A new `NonDurable` class for calls under `Monetary` or development `Off` that no durable or check-only path covers (S3-16).
  - The step-to-receipt mapping is now transition rows (M16). T8 is the discharge predicate.
  - Spec 3 keeps the affine driver contract, the latch scopes and the ledger. Spec 10 executes the commits.
- **Driver drop (S3-01, S3-14).**
  - A future dropped before the dispatch-commit acknowledgement compensates and never latches.
  - A future dropped after it enqueues supervised reconciliation through `Cut(DriverDropped)`, so request ids are not stranded until restart.
- **Receipt append outcomes (S3-05).** An append that times out may still commit. It is `ReceiptAppendFailed { Unknown }`, which buffers a fault record behind `KernelEvidenceLatch` and appends nothing until a read-back shows the original absent.
- **A stop is a temporary refusal (S8-01, S8-12, S8-17, S8-18, S8-19).**
  - `KernelStopped` writes no deny tombstone and burns no request id.
  - A parked operation is retained.
  - A caller report is a progress-only return record that is never stop-checked.
  - A two-commit read refused at its outcome commit writes a return record, so it is never re-dispatched.
  - The legacy startup reconciler adopts the M11 retain rule in spec 8 phase 1, so a host restarted during a stop still starts.
- **Hints are typed and trail commits (S5-11).** `Effect::Hint { hint: Hint }` uses spec 5's `HintPort` vocabulary and runs only in a trailing group after the commit group's `Committed` acknowledgement. The port is a no-op until spec 5 Part B lands.
- **Check-only eligibility excludes `require_durable_request_retention` (S3-24).** Kernels with that setting deny reads outside durable coverage, as today.

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
    pub class: OperationClass,            // Durable | ReadOnlyCheckOnly | NonDurable (section 4.4)
    pub phase: Phase,
    pub plan: ParticipantPlan,            // ordered participants required for this request (data)
    pub facts: ParticipantFacts,          // which participants are acknowledged, by digest
    pub capture: CaptureFact,             // NotRequired | NotCommitted | Committed | Unknown
    pub unknown_hold: UnknownHold,        // None | Frozen | Releasing { .. } | Released(UnknownOutcomeRelease); M7a
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
- **Driver-local in-memory items are not participants.** The invocation counter, runtime-admission leases and continuations, and the reference-counted child-budget holder lease hold no persisted state. The driver owns them as spec 3 ledger tokens (spec 3 section 4.12). A `Compensate` effect releases them through the driver's ledger, in M:'s pre-dispatch order, and the machine never sees them.

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
- `ReadOnlyCheckOnly`: the class for spec 10's check-only read path. It is eligible only when all five hold, and the driver decides that at `Begin`:
  - the deployment's `DurableAdmissionMode` does not cover `ReadOnly`, which excludes the process host because it runs `All`;
  - the kernel does not set `require_durable_request_retention` (V: `kernel/construction.rs:794-795`);
  - `can_redispatch_unknown_read` holds (M: `kernel/validation.rs:256-305`);
  - no pre-dispatch consumable applies: no `max_invocations`, cost, DPoP, nonce, approval, aggregate or supplemental quota, runtime hook or swarm admission;
  - integrity tracking (spec 11 I4, rollout flag `integrity-tracking`) is not enabled for the calling context's knowledge scope. I4 joins every delivered output into that context in the same writer transaction as the outcome commit or release. A check-only release writes no authority row, so it has nowhere to commit the join, and the bytes would enter the context untainted. Such reads take spec 10's durable three-commit path, whose `OutcomeCommit` writes the join before the bytes are delivered.

  It has no persisted row: `Unbegun`, then `CheckOnlyAcknowledged`, then dispatch, then a release outcome.
- **Retention kernels deny uncovered reads, as today.** When `require_durable_request_retention` is set and the mode does not cover `ReadOnly`, a read is in no class. The driver denies it before `Begin`, with the existing structured-admission refusal (V: `admission_coordinator.rs:526`, `:564-569`). Such kernels need a mode that covers `ReadOnly`, such as `All` (spec 3 rule 19).
- `NonDurable`: the class for calls that no durable path covers and that are not check-only eligible. It exists only in two configurations:
  - under `Monetary`, whose `covers` excludes `SideEffecting`, every non-monetary side-effecting tool runs here (M: `admission_operation/identity.rs:387`; `kernel/admission_coordinator.rs:569-581`);
  - under `Off` with unsafe development mode, every call that is not check-only eligible runs here.

  Reads that are not check-only eligible under `Monetary` take spec 10's durable three-commit path, as they do under `SideEffecting`.

  When integrity tracking is enabled for the calling context, a call that would be `NonDurable` takes the durable three-commit path instead, for the same reason as the check-only exclusion: the I4 join needs an authority write before delivery.

  A `NonDurable` operation has no persisted row:
  - Its participants are spec 3's in-memory ledger entries, mapped one to one to `Participant`, and they are acknowledged through participant ports.
  - Dispatch still requires `CheckOnlyAcknowledged`: a spec 10 check-only crossing that runs every `CrossingCheck` with no write. Its integrity check covers grant-declared requirements too, because this class does not exclude grant constraints.
  - Discharge is the receipt append (M16, T8), under spec 3's obligation.

  `NonDurable` is the region where D1 is worst, because a mutating effect can end with no receipt. Spec 3 phase 1 closes that region on the legacy evaluator. Spec 3's open decisions consider forbidding `Monetary` in production profiles.

## 5. Events and effects

### 5.1 Events

```rust
pub enum AdmissionEvent {
    Begin { binding: BindingDigest, plan_inputs: PlanInputs, ids: IdentityPayload, now: AuthorityTime },
    Replan { slow_path: bool },               // from Unbegun or Prepared (intent) or Finalizing (outcome) after spec 10 reports Unavailable
    ParticipantAcknowledged { participant: Participant, digest: Digest },
    CombinedAcknowledged { participants: ParticipantSet, digests: DigestSet }, // cumulative approval
    ParticipantRefused { participant: Participant, reason: RefusalCode },
    ApprovalRequired { proposal: ProposalDigest, deadline: AuthorityTime },
    ApprovalSupplied { approval_set: Digest },
    CaptureCommitted { kind: CaptureKind },
    DispatchCommitAcknowledged { committed_version: u64 },
    CheckOnlyAcknowledged,                    // read-only and NonDurable classes only
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
    StoreUnavailable { effect: EffectId },    // M19: spec 10 X21 known-not-committed store failure (retry exhaustion, poisoned owner)
    PostEffectStepFailed { step: PostEffectStep, cause: PostEffectCause },  // M16
    ReceiptAppendFailed { outcome: AppendFailure },                         // M16; spec 10 receipts append
    ReceiptReadBack { original_present: bool },                             // after AppendFailure::Unknown drains
    ReleaseAuthorized { authority: UnknownOutcomeRelease, evidence: Digest }, // M7a: counterparty-authorized hold release
    Cut { cause: CutCause, facts: CutFacts, now: AuthorityTime },
    Tick { now: AuthorityTime },
}

pub enum CommitFailure {  // spec 10 CrossingRefused, plus two non-policy reasons
    KernelStopped, AuthoritySpaceClosed, Revoked, InsufficientIntegrity, ReservationConflict,
    VersionConflict, Overloaded,
    Unavailable,          // the fused form is ineligible (its preconditions do not hold): re-plan. Never a storage failure (M19)
}

pub enum UnknownOutcomeRelease {  // the counterparty-authorized release kinds (V: payment/journal.rs:88-96)
    MutuallyAgreedUnknown,
    ContractualCaptureWaiver,
}

pub enum UnknownHold {
    None,                                 // no hold, or the operation did not end outcome-unknown
    Frozen,                               // entered with Terminal(OutcomeUnknownAfterDispatch) while a hold is retained
    Releasing { authority: UnknownOutcomeRelease, evidence: Digest }, // ReleaseHold emitted, not yet acknowledged; never persisted
    ReleaseSubmitted { authority: UnknownOutcomeRelease, idempotency_key: Digest }, // rail-held release prepared durably; outcome at the rail unknown
    Released(UnknownOutcomeRelease),      // set only by the acknowledgement of the ReleaseHold for this authority
}

pub enum AppendFailure {   // spec 10 reports the receipts append as Committed, Refused or Unknown
    Refused,              // known not committed
    Unknown,              // timed out or lost; the writer may still commit it (spec 3, S3-05)
}

pub enum PostEffectCause {
    Rejected(PostEffectRejection), // spec 3 section 4.5: a typed post-effect rule refused the step
    Infrastructure,                // clock, key, store or I/O failure; no policy meaning
}
// PostEffectStep and PostEffectRejection are spec 3's closed enums (spec 3 section 4.5).

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
    DriverDropped,                                  // M17: a driver future dropped after the dispatch-commit acknowledgement
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
    ReturnRecord(ReturnRecordPlan),          // durable tool return before post-return work; also the caller report (progress-only, never stop-checked, M11)
    OutcomeCommit(OutcomeCommitPlan),        // post-return stages, terminal projection, receipt, influence join
    CheckOnlyCrossing(CheckOnlyPlan),        // read-only and NonDurable classes: checks with no write (spec 10)
    ParticipantCommit(ParticipantStep),      // slow path: one participant step
    DenyTombstone { reason: CommitFailure, receipt: ReceiptPlan },   // fused-path policy refusal, except KernelStopped (M15)
    Park { proposal: ProposalDigest, deadline: AuthorityTime, expected_version: u64 },
    RequestApproval { proposal: ProposalDigest },
    Dispatch,
    CallerAwaitStart, CallerAwaitReport { expected_version: u64 },
    QueryParticipant { participant: QueryTarget },   // capture, mutation, approval reservation, dispatch status
    CancelTransport,                         // cooperative cancel where the transport supports it
    Compensate { cause: CompensationCause, release: Option<MachineRelease>, receipt: ReceiptPlan, expected_version: u64 },
    Terminalize { terminal: Terminal, release: Option<MachineRelease>, receipt: ReceiptPlan, expected_version: u64 },
    ReleaseHold { authority: UnknownOutcomeRelease, evidence: Digest, expected_version: u64 }, // M7a; payment-journal port
    FlushChildReceipts,                      // nested flow, before the parent's receipt
    ReplayTerminal,                          // return the bound terminal result
    SignReceipt { decision: ReceiptDecision, metadata: ReceiptMetadataPlan }, // receipts not bound to a state change
    HaltOperation { reason: HaltReason },    // spec 3 LatchScope::Operation: halts this operation only
    LatchRequest { request_id: RequestId, reason: LatchReason },  // spec 3 LatchScope::SessionRequest (spec 4)
    KernelEvidenceLatch { record: BufferedRecordId },             // spec 3 LatchScope::KernelEvidence (spec 3 section 4.8)
    Fault { kind: FaultKind },               // operator-visible fault; no state change
    Hint { hint: Hint },                     // spec 5 Part B HintPort; trailing group only (M18)
    Retain,
}

pub enum HaltReason {
    CommitOutcomeUnknown,                    // M12
    RefusedAfterEffect(CommitFailure),       // M11, before the DeniedAfterDelivery terminal
    RefusedAfterCapture(CommitFailure),      // M10, intent remainder refused after a committed capture
    InvariantViolation,                      // M11 ReservationConflict after the effect
    AuthorityCut,                            // cut table, X column, post-dispatch rows and committed capture
    UnsettledCallerCustody,                  // cut table, AwaitingCallerReport under N and X
}

pub enum LatchReason { AuthorityCut }        // spec 4 session-request latch

pub enum MachineRelease { PreDispatchNoEffect, TransportNotAccepted, ContractualZeroCharge }

pub enum ReceiptDecision {
    Allow, Deny { code: DenyCode }, DenyDelivery { reason: ReasonCode },
    Cancelled { reason: ReasonCode }, Incomplete, PendingApproval, Withheld { reason: ReasonCode },
}

/// M20. Signed as `chio_runtime.identity_disposition` on every receipt whose decision is not
/// `Allow` or `PendingApproval`. The machine derives it from the row that produced the receipt;
/// it is never a driver choice or a caller claim.
pub enum IdentityDisposition {
    Reusable, // the attempt was refused before any operation row, tombstone or custody exists; the same request id may be retried
    Terminal, // the request id is bound to a terminal record (tombstone, compensated row, terminal outcome) or to an executed effect
}
```

**Effect-list semantics.**
- Groups execute in order. A group runs only after the previous group is acknowledged.
- Effects inside a group are atomic: one crossing, or one port call that is atomic at its authority.
- Every state-mutating effect carries the expected operation version. A mismatch returns `CommitFailed { VersionConflict }`.
- `Compensate` and `Terminalize` carry their receipt, so the terminal projection binds the no-effect proof and the receipt atomically (saga rule 5).
- Every `ReceiptPlan` and every `SignReceipt` whose decision is not `Allow` or `PendingApproval` carries the `IdentityDisposition` that M20 assigns to the producing row.
- A compensation that needs an external rail release first is two groups: the rail release (`ParticipantCommit`), then the projection. A partially completed compensation is driven again by the next `Cut`.
- Capacity is fixed: at most 4 groups of 4 effects. Every arm builds a literal list, so exceeding capacity is a compile error. A trailing hint group (M18) counts toward the four.
- `HaltOperation` changes no persisted state. The driver stops acting on that operation; a later re-projection from the store or a `Cut` clears the halt. It never gates other operations or new dispatch. Only `KernelEvidenceLatch` gates new dispatch, and only while its buffered record is unpersisted (spec 3 section 4.8).
- `Hint` effects form the last group of a list and run only after the commit group before them is acknowledged with `Committed`. They never run after a savepoint, `Retry`, a refusal or `CommitOutcomeUnknown` (M18).

**The plan types.**
- `IntentCommitPlan` lists the ordered steps the fast path commits atomically: begin, participant acknowledgements, ready, capture when `budget_capture` is set (`CapturePending` and the capture itself), then the dispatch commit (M: `state.rs:676-685` requires `CapturePending` before `DispatchCommitted` under capture). It runs only when every participant has an in-transaction form in the admission writer (spec 10).
- `ReturnRecordPlan` makes the returned bytes and cost durable, and binds the post-return evaluation time, frozen steps and normalized context, before post-return work. The same plan records an authenticated caller report, and the bytes of a two-commit read whose outcome commit a stop refused (M11). It is a progress-only commit with no `StopEpoch` check.
- `OutcomeCommitPlan` lists the pure post-return results, the terminal projection with its payment plan, the receipt, and spec 11's output influence join.
- `CheckOnlyPlan` lists the crossing checks for a read-only or `NonDurable` call. The receipt rides the release commit for a read, and the receipt append (M16) for a `NonDurable` call.
- Each plan carries the expected operation version (spec 10 rule X5).

**Release authorities.**
- The machine emits `PreDispatchNoEffect` (compensation), `TransportNotAccepted` (proven non-acceptance) and `ContractualZeroCharge`.
- `ContractualZeroCharge` is emitted only in an `OutcomeCommit` or `Terminalize` whose recomputed amount is zero, or whose terminal is `DeniedAfterDelivery` (M: `terminal_payment.rs:121-125`).
- Releases after an unknown outcome (`MutuallyAgreedUnknown`, `ContractualCaptureWaiver`) are counterparty-authorized, never machine-originated. They arrive as the typed event `ReleaseAuthorized` and drive the `ReleaseHold` effect (M7a). The payment-journal port executes it and records the release kind (V: `payment/journal.rs:88-96`). When the hold sits on an external rail, the port first runs an `ExternalPrepare { Settle }` crossing (spec 10). The admission phase never changes: `Terminal(OutcomeUnknownAfterDispatch)` stays absorbing, and only the `unknown_hold` fact moves, from `Frozen` through `Releasing` to `Released`. `Released` is recorded only on the `ReleaseHold` acknowledgement (M7a; spec 3; spec 4 section 5 rule 2).

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
4. **M4. Commit before handoff.** `Dispatch` is emitted only in the transition consuming `DispatchCommitAcknowledged`. For the read-only and `NonDurable` classes it is emitted only on `CheckOnlyAcknowledged`.
5. **M5. Plan order.** A participant is acknowledged only when every earlier participant in the plan is acknowledged, except through the combined cumulative-approval acknowledgement. `Authorized` is entered exactly when the plan is complete. `Ready` is entered exactly when `ReadyToDispatch` is persisted.
6. **M6. Absorbing terminals.** No transition leaves a terminal phase. A terminal accepts `Tick` (`Retain`) and `Begin` (`ReplayTerminal`). `Terminal(OutcomeUnknownAfterDispatch)` also accepts `ReleaseAuthorized` (M7a), which changes only the `unknown_hold` fact, never the phase.
7. **M7. Unknown stays unknown.** `TransportAmbiguous` after dispatch commit moves to `Terminal(OutcomeUnknownAfterDispatch)` with no release, and the receipt carries the typed `AmbiguityCause`. No `Dispatch` follows. A retained hold sets `unknown_hold = Frozen`, and only M7a can release it.
   - **M7a. Counterparty-authorized release.** `ReleaseAuthorized { authority, evidence }` is accepted only in `Terminal(OutcomeUnknownAfterDispatch)` with `unknown_hold = Frozen`.
     - It moves `unknown_hold` to `Releasing { authority, evidence }` and emits `ReleaseHold { authority, evidence, expected_version }`.
     - **Acknowledged.** `EffectAcknowledged { effect: ReleaseHold, .. }` in `Releasing { authority, .. }` sets `unknown_hold = Released(authority)`. No other event records a release, so a release that failed is never recorded as done.
     - **Failed.** `CommitFailed` for the `ReleaseHold` returns `unknown_hold` to `Frozen` with `Retain`, and a later `ReleaseAuthorized` may retry. `VersionConflict` re-projects first. A refused `ExternalPrepare { Settle }` ahead of a rail-held release counts as a failure.
     - **Unknown.** `CommitOutcomeUnknown` for the `ReleaseHold` yields `HaltOperation { CommitOutcomeUnknown }` and keeps `Releasing`. Re-projection then resolves it from the store. For a writer-held hold, a committed release entry gives `Released(kind)` and its absence gives `Frozen`. For a rail-held hold, a `release_submitted` row without completion gives `ReleaseSubmitted`, which is reconciled at the rail as described under persistence below. It is never treated as `Frozen`.
     - **Repeats.** While `Releasing`, a `ReleaseAuthorized` with the same authority and evidence yields `Retain` and emits no second effect. One with a different authority or evidence is illegal (M2). After `Released`, a duplicate yields `Retain`. In any other phase, or with no frozen hold, the event is illegal and releases nothing.
     - **Persistence, writer-held holds.** `Releasing` is never persisted. The `ReleaseHold` member (spec 10 X17b) writes the payment-journal release entry and the operation's released fact in one writer transaction, keyed by `operation_id`, so at most one release exists per frozen hold. Because the release is a single local transaction, absence of the entry after an unknown outcome proves it did not commit, and projection yields `Frozen` or `Released`.
     - **Persistence, rail-held holds.** A release that needs an external rail call is two-phase, and absence of a local completion never means "not released":
       - **One key per frozen hold.** The idempotency key is fixed when the hold freezes: `hold_release_key = H("chio.unknown-release.v1" || operation_id || hold_id)`. It does not depend on the authority or the evidence, so every later authorization for the same hold reuses it. There is at most one frozen hold per operation.
       - **Prepare.** An `ExternalPrepare { Settle }` crossing commits a durable `release_submitted` row before the external call, carrying `hold_release_key`, the authority and the evidence digest. Projection of that row yields the persisted `ReleaseSubmitted { authority, idempotency_key }`.
       - **Adapter capability (spec 10 X17b).** The prepare crossing refuses, before any rail call, when the hold's rail adapter declares neither capability below. The hold stays `Frozen`, and the driver raises `Fault { RailCapabilityMissing }` for operator settlement outside the machine.
         - **`IdempotentPerKey`.** The rail executes at most one release per key for as long as the hold can exist, whatever request body carries the key. Re-submitting with the key is safe and returns the original outcome.
         - **`FenceByKey`.** The rail offers a terminal non-acceptance operation. Once `fence(key)` succeeds, no request carrying the key can be accepted afterwards, and status reports a terminal `NotReleasedFenced`.
       - **External call.** The rail call carries `hold_release_key`.
       - **Completion.** The completion commit writes the payment-journal release entry and sets `Released(authority)`.
       - **Unknown or crash.** From `ReleaseSubmitted`, `UnknownReleaseDriver` resolves the release only through the adapter's declared capability:
         - `IdempotentPerKey`: it re-submits with the same key. "Released" commits the completion. A definitive rejection of the keyed request commits a `release_abandoned` record and returns to `Frozen`. A delayed copy of the original request carries the same key, so the rail deduplicates it against any later release of the same hold.
         - `FenceByKey`: it calls `fence(key)`. "Already released" commits the completion. A successful fence with no release commits `release_abandoned` and returns to `Frozen`; the original request can no longer be accepted.
         - An ordinary status query that reports "not released", "unknown key" or no answer is not terminal. It keeps `ReleaseSubmitted` with bounded backoff and an operator incident. A query alone never returns the hold to `Frozen`, and the driver never re-submits an ambiguous request except under `IdempotentPerKey`.
         - If the adapter's declared capability is lost after submission (a configuration change), only a "released" answer is acted on. Every other answer keeps `ReleaseSubmitted`.
       - **No re-release.** While `ReleaseSubmitted` holds, a new `ReleaseAuthorized` is illegal (M2). After a return to `Frozen`, a new authorization reuses `hold_release_key`, so the original request is either deduplicated (`IdempotentPerKey`) or fenced (`FenceByKey`) before a replacement can execute.
       - **Required semantics, answering the owner's rail question.** An adapter qualifies for unknown-outcome releases only if it provides at-most-once execution per caller-supplied key for the hold's lifetime, or a terminal fence by key whose success excludes later acceptance. A current-state lookup does not qualify. Chio names no specific rail here. Each adapter declares its capability, and its conformance test covers a delayed original request delivered after a negative status query, both before and after a replacement request.
     - The driver verifies the evidence (the counterparty's signed agreement, or the contract's capture-waiver term) before it feeds the event. The machine checks only the phase and the hold fact.
     - This is how a hold frozen by M7, M12 or the cut table is released after migration. It never moves money on the machine's own authority (T4, T6).
8. **M8. Cuts.** A `Cut` event is classified only by the normative table of section 6.1.
9. **M9. Liveness protection.** `Prepared` with `nonce_issuance_live`, and `Ready` with `caller_reservation_live`, are retained under `StartupRecovery`, and under `RecoveryClosure` only while control is `Active` (M: `recovery.rs:206-221`; W: `recovery_runtime.rs:213-218`). No other cause is protected.
10. **M10. Pre-dispatch commit failures.** Rows match on the failed effect, its starting phase and the reason. The reason is inspected before any generic row applies, so a non-policy reason (`Unavailable`, `VersionConflict`, `Overloaded`) never compensates. Every `CommitFailure` reason has a row for every pre-dispatch effect, so none reaches M2's illegal-event arm. A store failure arrives as `StoreUnavailable`, not as a `CommitFailure`, and M19 handles it for every effect. M20 assigns each row's identity disposition.

    | Failed effect | Reason | Next and effects |
    |---|---|---|
    | `IntentCommit` (fused, from `Unbegun`) | `AuthoritySpaceClosed`, `Revoked`, `InsufficientIntegrity`, `ReservationConflict` | `DenyTombstone` with the refusing reason, then `Terminal(CompensatedBeforeDispatch)`. The tombstone keeps the request id terminal (saga rule 4). Nothing was acquired outside the savepoint, so nothing needs compensation |
    | `IntentCommit` (fused, from `Unbegun`) | `KernelStopped` | stay `Unbegun`; `SignReceipt(Deny { KernelStopped })` with the head's `observed_epoch`. No tombstone, so the request id stays usable after resume (M15) |
    | `IntentCommit` (from `Prepared`, spec 10 X10) | any policy reason, `KernelStopped` included | `Compensate { PreDispatchRefusal { reason }, PreDispatchNoEffect, receipt }` against the persisted operation. It releases every participant acquired against `Prepared` before the fused steps, including the nonce preflight and an operation-owned runtime hook (`RuntimeParticipantLedger`), as the slow path does; a hook held outside the writer is released in a first `ParticipantCommit` group. No deny tombstone is written, because the compensated row is the tombstone. The id is terminal, as on M: today |
    | `IntentCommit` (from `Unbegun` or `Prepared`) | `Unavailable` | stay in the phase; the driver feeds `Replan { slow_path: true }`, and the machine emits slow-path `ParticipantCommit` steps. Never compensates |
    | any pre-dispatch effect | `VersionConflict` | `Retain`; the driver re-projects from the store and re-feeds. Never compensates |
    | `IntentCommit` (from `Unbegun`), `CheckOnlyCrossing` | `Overloaded` | stay `Unbegun`; the driver signs a deny receipt (`Overloaded`) before admission and persists no state (spec 10 X15); the request id stays usable. A `NonDurable` call first releases its in-memory ledger entries (`Compensate` against spec 3's ledger) |
    | `IntentCommit` (from `Prepared`), slow-path `ParticipantCommit` or dispatch-commit step | `Overloaded` | `Retain`; the driver re-submits the same planned step with bounded backoff. If the caller abandons the call first, M17's before-acknowledgement rule compensates. Never compensates on its own |
    | slow-path `ParticipantCommit` or dispatch-commit step | `Unavailable` | Not produced: a slow-path step has no fused form, and store failures arrive as `StoreUnavailable` (M19). If received, it is handled like `Overloaded`: `Retain` and re-submit. Never compensates |
    | slow-path dispatch-commit step from `Parked` (approval resume) | `KernelStopped` | `Retain` in `Parked`. Never compensates, so the pending approval survives the stop (M15) |
    | `IntentCommit` remainder from `CapturePending` with capture `Committed` | `KernelStopped` | `Retain` in `CapturePending`; re-emitted after the stop is resumed. Never compensates |
    | `IntentCommit` remainder from `CapturePending` with capture `Committed` | any other policy reason (`AuthoritySpaceClosed`, `Revoked`, `InsufficientIntegrity`, `ReservationConflict`) | Post-dispatch, as the section 6.1 `X` row: `HaltOperation { RefusedAfterCapture(reason) }`, then `Terminalize(OutcomeUnknownAfterDispatch)` with holds frozen, as a restrictive, non-crossing commit. Never `Compensate`: a committed capture cannot be undone under `PreDispatchNoEffect` (T3). This row takes precedence over the generic slow-path row below |
    | slow-path `ParticipantCommit` or dispatch-commit step, otherwise | any policy reason | `Compensate { PreDispatchNoEffect, receipt }`. The request id is terminal, as on M: today |
    | `ParticipantCommit` | the `ParticipantRefused` event | `Compensate { PreDispatchNoEffect, receipt }` |
    | `CheckOnlyCrossing` (read-only class) | any policy reason | `SignReceipt(Deny)` with the reason; nothing to compensate |
    | `CheckOnlyCrossing` (`NonDurable`) | any policy reason | `Compensate { PreDispatchRefusal, PreDispatchNoEffect, receipt }`, which the driver executes against spec 3's in-memory ledger; there is no row to project |
    | `CheckOnlyCrossing` | `Unavailable`, `VersionConflict` | Not produced: the crossing writes nothing and plans no version (spec 10 X13). If received, it fails closed: `Fault { IllegalEvent }`, then the read-only and `NonDurable` policy rows above with reason `Unavailable` |

11. **M11. Refusals after the effect.** For `ReturnRecord`, `OutcomeCommit` and the release crossings. Spec 9 owns these rows. Spec 3 rule 13 is the same mapping, implemented on the legacy evaluator in spec 3 phase 1.
    - **`KernelStopped`.** The release crossings carry spec 8's `Withhold` disposition (spec 10 section 4.2).
      - From `Finalizing(stage)`: `Retain` with output withheld. The next `Tick` or `Cut` after the stop is resumed re-emits the commit (spec 8 S14). `FinalizingRetryDriver` feeds that `Tick` from spec 8's `StopHeads` watch.
      - On the outcome commit of a two-commit read (spec 10 X14), from `DispatchCommitted` with no return record: emit `ReturnRecord` with the returned bytes, which moves the operation to `Finalizing(stage)` with output withheld. The driver returns `OutputWithheld { operation_id, reason: KernelStopped }` (spec 8). The read is never re-dispatched (S8-18).
      - `ReturnRecord` is progress-only and never stop-checked, so a stop cannot refuse it. That includes the caller report: `CallerReportAuthenticated` in `AwaitingCallerReport` emits `ReturnRecord` and moves to `Finalizing`. Only the later `OutputRelease` inside `OutcomeCommit` is stop-checked (S8-12).
      - The legacy startup reconciler adopts this rule in spec 8 phase 1, before this machine replaces it. The stop heads load before the sweep, and a `KernelStopped` finalization error during the sweep retains the operation instead of failing startup (S8-01; M: `kernel/admission_coordinator/recovery.rs:295-358`).
    - **`AuthoritySpaceClosed`, `Revoked` or `InsufficientIntegrity`.** `HaltOperation { RefusedAfterEffect(reason) }`, then `Terminalize(DeniedAfterDelivery)` with a `DenyDelivery` receipt naming the reason and retained markers. The release follows the terminal payment plan, and the terminal clears the halt.
      - The `OutputRelease` closure-fence check is spec 4 section 4.1 rule 3a. For operations marked `legacy_unindexed` it includes spec 4 rule 1a's legacy predicate, so an operation admitted before the authority-ref index existed is still fenced.
      - The mapping holds for every driver that emits the commit. When `StartupReconciler` or `FinalizingRetryDriver` re-emits a retained finalization and the release is refused with `AuthoritySpaceClosed`, the operation terminalizes as `DeniedAfterDelivery`. It is never retained indefinitely, and it is never compensated.
    - **`ReservationConflict`.** `HaltOperation { InvariantViolation }` and `Fault`. It is unreachable after the effect, because reservations commit in the intent commit, so reaching it is an invariant violation.
    - **`VersionConflict`.** Re-project.
    - **`Overloaded`.** Not produced for post-effect members, because spec 10 X17b admits them past the queue bound. If received: `Retain`, and the driver re-submits the same plan. Never compensates.
    - **`Unavailable`.** The fused outcome commit's preconditions no longer hold, for example because settlement needs an external rail capture. `Unavailable` never means the store failed; that is `StoreUnavailable` (M19). From `Finalizing`, the driver feeds `Replan { slow_path: true }`. The machine then emits the settlement as `ParticipantCommit` groups (spec 10 `ExternalPrepare { Settle }`), followed by the rest of the `OutcomeCommit`. On a two-commit read with no return record (spec 10 X14), `ReturnRecord` comes first.
    - **Totality.** Every `CommitFailure` reason has a row here for every post-effect effect, so none reaches M2's illegal-event arm.
      - `Terminalize`, `Compensate` and `ReleaseHold` are non-crossing commits. They run no policy check, so only `VersionConflict` (re-project), `CommitOutcomeUnknown` (M12) and `StoreUnavailable` (M19) can fail them. A refused or unknown `ReleaseHold` follows M7a: back to `Frozen`, or `HaltOperation` while `Releasing`. A `StoreUnavailable` keeps `Releasing` and re-submits the same `ReleaseHold` (M19).
      - Every `Retain` above has a re-feed source. The `FinalizingRetryDriver` (section 7) feeds `Tick` when the stop is resumed and with bounded backoff. `StartupReconciler` covers restart.
    - **Classes with no row** (read-only and `NonDurable`). A refused release signs a `Withheld` receipt through a non-crossing commit, `KernelStopped` included. There is no durable custody to retain the output in, so the output is dropped and the receipt records that. Whether a retry is safe differs by class:
      - **Read-only (check-only).** The call is eligible only when `can_redispatch_unknown_read` holds (section 4.4), so a retry after resume is safe. The driver returns `OutputWithheld { retry: AfterResume }` (spec 8).
      - **`NonDurable`.** The effect has executed and nothing binds a retry to it. A retry would redispatch the side effect, as spec 5 confirms for non-durable calls. The `Withheld` receipt therefore records `effect_executed: true`, and its stop block sets `retryable_after_resume: false` (spec 8 S15). The driver returns the terminal `OutputWithheld { retry: Never, effect_executed: true }`, and the result is final for that request. `KernelStopped` is temporary only for refusals before dispatch. A deployment that cannot accept dropped output must not run `Monetary` or development `Off` modes (spec 3 open decision 1).
12. **M12. Unknown commit outcome.** `CommitOutcomeUnknown` from any effect yields `HaltOperation { CommitOutcomeUnknown }`, with no compensation, no dispatch and no state change.
    - This is the machine form of spec 3's `BoundaryFailure::CommitUnconfirmed`: every hold and credential is retained.
    - When the unknown commit is pre-dispatch (an `IntentCommit` or a slow-path dispatch-commit step), a second group signs the ambiguous `SignReceipt(Deny)` with retained markers, as M: does today (M: `kernel/evaluation/dispatch_commit_failure.rs:40-75`).
    - When the unknown commit is post-effect, no receipt is signed, because the unknown commit may hold it.
    - Restart re-projects the operation from the store.
13. **M13. Integrity at every dispatch commit.** Every dispatch-commit step, fast or slow, and every `CheckOnlyCrossing`, is a crossing that carries spec 10's full `CrossingCheck` list, including `KnowledgeIntegrity` (spec 11 rule I15). No earlier acknowledgement satisfies it.
14. **M14. Post-effect discharge (safety form).** Every post-dispatch phase has an enabled transition to a discharge, or to `HaltOperation`, under the fair events named in section 10. No transition returns a post-dispatch operation to a pre-dispatch phase.
    - The discharge set is the acknowledgement of one of these:
      - `OutcomeCommit`;
      - `ReturnRecord`, after which the saga owns the rest;
      - `Terminalize`;
      - an appended `SignReceipt`, for classes with no row;
      - `KernelEvidenceLatch` with a buffered record, for classes with no row.

      This is spec 3 section 4.11's `exactly_one_of` and spec 3's affine driver contract.
    - `HaltOperation` is not a discharge. For a durable operation, the persisted record is the evidence, and restart or the next `Cut` re-projects it.
15. **M15. A stop is a temporary refusal (spec 8 S15).** `KernelStopped` never writes a deny tombstone, never terminalizes, and never compensates a parked or post-dispatch operation.

    | Path | Behavior |
    |---|---|
    | Tier-1 early stop check, before `Begin` | A driver pre-check outside the machine, like `Overloaded`. It signs `Deny { KernelStopped }` with `observed_epoch`, persists no state, and leaves the request id usable after resume |
    | Fused `IntentCommit` | M10: receipt only, id usable after resume |
    | `CheckOnlyCrossing` | M10: receipt only; the read-only class has no id to burn |
    | Fused `IntentCommit` from `Prepared` (spec 10 X10) | M10: compensates the persisted operation; the id is terminal, as on M: today |
    | Slow path with a persisted begin row, not parked | M10: compensates; the id is terminal, as on M: today |
    | `Parked` | `Retain`. While the driver's stop read says stopped, approval resolutions are refused at the edge before any event, without consuming the approval (S8-19). `ApprovalSupplied` is therefore never fed during a stop |
    | After the effect | M11: withheld and retained, or a `Withheld` receipt for classes with no row |

    Consequence for processes: chio-process retries with the same request id (M: `crates/kernel/chio-process/ARCHITECTURE.md:40-45`). A tier-1 or fused stop denial leaves that id usable after resume. A slow-path or `Prepared`-intent compensation burns it, as today.

    "Temporary" describes the stop, not every receipt it causes. The receipt's identity disposition is assigned by M20: the tier-1, fused-from-`Unbegun` and check-only rows are `Reusable`; the `Prepared` and slow-path rows are `Terminal`, because a compensated row now holds the request id; the `NonDurable` withheld effect is `Terminal`. The parked and durable post-effect rows sign no stop receipt at the point of refusal: the operation stays live, and its later terminal receipt carries `Terminal`. Spec 8 S15's `retryable_after_resume` equals `identity_disposition == Reusable`.
16. **M16. Post-effect step failures and receipt appends.** These rows are the step-to-receipt mapping. Spec 3 owns the closed `PostEffectStep` and `PostEffectRejection` enums; spec 10 executes the commits. Durable means a class with a persisted row.

    | Event | Durable class | Classes with no row (read-only, `NonDurable`) |
    |---|---|---|
    | `PostEffectStepFailed { cause: Rejected(PostInvocationBlocked or OutputContract or StreamLimit) }` | the pure result enters `OutcomeCommit`, which terminalizes `DeniedAfterDelivery` with a `DenyDelivery` receipt and retained markers (M: `responses/finalization.rs:43`) | `SignReceipt(DenyDelivery)` with retained markers, appended |
    | `PostEffectStepFailed { cause: Rejected(Revoked) }` | as M11 `Revoked` | `SignReceipt(DenyDelivery)`, matching M: `allow_responses.rs:53` |
    | `PostEffectStepFailed { cause: Rejected(ReleaseRefused(r)) }` | as M11 for `r` | as M11 for `r` |
    | `PostEffectStepFailed { step: CredentialCommit, .. }` | not reachable: the intent commit holds the credentials | `SignReceipt(Cancelled)` with today's `POST_DISPATCH_CREDENTIAL_COMMIT_FAILURE_REASON` and `execution_outcome: "unknown"` |
    | `PostEffectStepFailed { cause: Infrastructure }` | With a return record: `Retain` in `Finalizing(stage)` plus `Fault { PostEffectInfrastructure }`. The next `Tick` or `Cut` re-runs from the frozen inputs (spec 10 X11). Without one (X14): `ReturnRecord` first, then the same | `SignReceipt(Cancelled)` with `chio_runtime.post_effect_fault = { step, code, retained_ids }`, appended |
    | `ReceiptAppendFailed { Refused }` | not reachable: the receipt rides the terminal projection, and the mover materializes it (spec 10 section 11) | append the fault receipt (`Cancelled`, step `Append`). If that append also fails, `KernelEvidenceLatch { record }` buffers it |
    | `ReceiptAppendFailed { Unknown }` | not reachable, as above | `KernelEvidenceLatch { record }` buffers the fault record. Nothing is appended until `ReceiptReadBack`. `original_present: true` makes the original the discharge, and the buffered record is dropped with an `audit_fault`. `original_present: false` appends the fault receipt naming the original receipt id |

    Failures after the receipt (spec 3 rule 15) never re-enter the machine: security release, final release, provenance append and nonce mint. The receipt stands, and the driver returns `DeliveryFailedAfterReceipt`.
17. **M17. Driver drop.** No durable transition runs inside `Drop`.
    - **Submission state.** The driver tracks a `SubmissionState` for its dispatch-commit crossing, which is the fused `IntentCommit` or the slow-path dispatch-commit step. The state is `NotSubmitted` until spec 10's writer accepts the member into its queue, then `Submitted { member }`. A crossing refused with `Overloaded` before enqueue was never submitted. Spec 10's writer runs a queued member independently of its reply waiter (X17), so a submitted member can still commit after its driver is gone. The rules below therefore key on submission, not on whether an acknowledgement was observed.
    - **Before submission.** A driver future dropped before its dispatch-commit crossing is submitted (or before `CheckOnlyAcknowledged` for classes with no row, whose check-only crossing writes nothing) compensates pre-dispatch participants under `PreDispatchNoEffect`. The compensation runs best-effort from `Drop` with the cleanup-fault receipt, or as a supervised job enqueued from `Drop` (spec 3, S3-01). It never latches.
      - With a persisted row, the job drives this machine's `Compensate` row.
      - On the fused path before the intent commit, nothing was persisted, so only spec 3's in-memory ledger entries are released.
    - **Submitted, not acknowledged.** The outcome is unknown to the driver. This is spec 3's `BoundaryFailure::CommitUnconfirmed` (spec 3 rule 29): nothing is compensated and nothing latches.
      - Every in-memory ledger entry moves to retained. `Drop` hands the member's reply handle to a `DropReconcileJob`.
      - The job awaits the writer's reply and feeds it to the machine as the driver would have: `DispatchCommitAcknowledged`, `CommitFailed { reason }` (M10 rows apply), or `CommitOutcomeUnknown` (M12). `Retry` is known not committed.
      - It then feeds `Cut { cause: DriverDropped, .. }`. The `S` column classifies the phase actually committed: a pre-dispatch phase compensates, and `DispatchCommitted` terminalizes as outcome-unknown.
      - On a fused intent from `Unbegun`, compensation happens only after a terminal reply of `Refused` or `Retry` and a read-back that finds no row under the replay key. Only then are the in-memory entries released under `PreDispatchNoEffect`.
      - If the reply is lost (crash), startup reconciliation re-projects from the store, as for any unknown outcome.
    - **After the acknowledgement.** A driver future dropped after the acknowledgement enqueues a supervised reconciliation job. The job takes the lease and feeds `Cut { cause: DriverDropped, .. }`, which the cut table classifies by its `S` column.
      - A `DispatchCommitted` operation with no return record therefore terminalizes as outcome-unknown, as M:'s guard does today (M: `kernel_drop_guard.rs:530-548`), without waiting for a restart (S3-14).
      - For classes with no row, spec 3's obligation `Drop` applies: a best-effort cancellation receipt, else `KernelEvidenceLatch`.
18. **M18. Hints trail commits (spec 5 Part B).**
    - `Effect::Hint { hint }` carries spec 5's `Hint { subject: HintSubject, kind: HintKind, audience: HintAudience }`. It is posted through `HintPort::post`, which is infallible, non-blocking and best-effort. The machine fills `audience` from the request's owner: `HintAudience::Owner(HintOwnerRef::Session | Process | Operation)`.
    - A hint group is the last group of its `EffectList`. It runs only after the commit group before it is acknowledged `Committed`, and never after a savepoint, `Retry`, a refusal or `CommitOutcomeUnknown`.
    - **Spec 5 H2, per spec 10 commit class.**
      - After a crossing-authorizing or restrictive commit, `Committed` implies anchored, so a re-read observes the hinted change.
      - After a progress-only commit (return record, park), a `Restore(k)` can undo the change. Consumers re-read and treat absence as a resync.
    - No `AdmissionEvent` is derived from a hint (spec 5 H1). The differential suite drops and forges hints and asserts identical transitions.
    - Until spec 5 Part B lands, drivers install a no-op `HintPort`.
19. **M19. Store unavailability is not a policy outcome.** Spec 10 X21 answers `StoreUnavailable` when a member fails `member_fault_retries` times with the transaction still active, or when the owner is poisoned or the connection-recovery fence fails. The member is known not committed. `Refused(Unavailable)` keeps its one meaning: the fused form is ineligible, so re-plan.

    | Effect | Next and effects |
    |---|---|
    | `IntentCommit` from `Unbegun`, `CheckOnlyCrossing` before dispatch | stay `Unbegun`; no dispatch. The driver signs `Deny { StoreUnavailable }` with `Reusable` (M20) if the receipt path is up; otherwise it returns a fail-closed error with no effect. Nothing was persisted, so nothing is compensated |
    | `DenyTombstone` | stay `Unbegun`; the deny receipt is signed `Reusable`, because no tombstone committed. A retry re-evaluates and meets the same committed fences |
    | Every other pre-dispatch effect (`IntentCommit` from `Prepared`, `ParticipantCommit`, slow-path dispatch-commit step, `Park`) | `Retain` the same planned member with its expected version. Every hold stays. Never `Compensate` because of the failure. If the caller abandons the call, M17's rules apply: the member is known not committed, so abandonment compensates through its own `Compensate` member, which M19 retains in turn while the store is down |
    | Post-effect crossings (`ReturnRecord`, `OutcomeCommit`, release crossings) | `Retain` in the phase with output withheld in custody; the same plan is re-submitted. Never terminalize because of the failure |
    | Post-effect `CheckOnlyCrossing` (release of a read-only or `NonDurable` call) | fail closed as an unverifiable release: the output is withheld. A check-only read gets `Withheld { retry: AfterResume }` (`Reusable`); a `NonDurable` effect gets the terminal `Withheld { retry: Never }` (`Terminal`), as in M11 |
    | Non-crossing effects (`Terminalize`, `Compensate`, `ReleaseHold`) | `Retain` the same planned member, the same expected version and every hold. `ReleaseHold` keeps `Releasing`, and a rail-held release keeps `ReleaseSubmitted`. Never convert to another terminal, never release |

    - **Re-feed.** `StoreRecoveryDriver` (section 7) re-feeds every operation retained under this rule: with bounded backoff, and at once on the writer's `store_healthy` signal, which spec 10 emits after its next successful batch commit. A poisoned owner stops writes until restart (spec 10 X22), so `StartupReconciler` re-projects and re-drives those operations.
    - **Totality.** `StoreUnavailable` has a row for every effect, so M2's illegal-event arm is never reached.
20. **M20. Identity disposition.** Every non-allow receipt carries `IdentityDisposition` (section 5.2), assigned by the row that produced it:

    | Producing row | Disposition |
    |---|---|
    | Tier-1 early denials before `Begin` (stop, `Overloaded`, any pre-admission check that persists no state) | `Reusable` |
    | Fused `IntentCommit` from `Unbegun` refused with `KernelStopped` (M10, M15) | `Reusable` |
    | `Overloaded` before admission (M10) | `Reusable` |
    | `CheckOnlyCrossing` refusals before dispatch, for both read-only and `NonDurable` classes (M10); nothing is persisted | `Reusable` |
    | A check-only read's `Withheld { retry: AfterResume }` (M11, M19) | `Reusable` |
    | `StoreUnavailable` deny before any row (M19) | `Reusable` |
    | `DenyTombstone` (M10, spec 10 X15) | `Terminal` |
    | `Compensate` of a persisted operation: `Prepared`-intent refusals and slow-path refusals for any reason, `KernelStopped` included (M10, M15), cut-table compensations, drop compensations | `Terminal` |
    | `Terminalize` for any terminal, including `DeniedAfterDelivery`, `OutcomeUnknownAfterDispatch` and `NotAcceptedAfterDispatchCommit` | `Terminal` |
    | Post-effect receipts of classes with no row (M16): `DenyDelivery`, `Cancelled`, a `NonDurable` `Withheld { retry: Never }` | `Terminal` |
    | The ambiguous deny for an unknown pre-dispatch commit (M12) | `Terminal`: the store may hold a row for the id |

    - The rule: `Reusable` exactly when the refusal leaves no operation row, tombstone, custody or executed effect bound to the request id. Every other non-allow receipt is `Terminal`.
    - Spec 8 S15's `chio_runtime.stop.retryable_after_resume` must equal `identity_disposition == Reusable`. Spec 3's per-request predicates count only `Terminal` receipts (spec 3 section 4.11). Spec 6 rule 10 binds a sealed submission only on a `Terminal` disposition or an allow or terminal outcome; on `Reusable` it lowers the deny and leaves the record sealed.
    - **Kernel-reserved metadata keys.** Two receipt-metadata keys are written only by the kernel. Caller-supplied metadata that carries either is rejected before evaluation through the existing `reject_reserved_receipt_metadata` path:
      - `receipt_context`, which gains a kernel-written `receipt_context.request_namespace_digest`. The kernel derives it from the authenticated evaluation context, exactly as `AuthenticatedRequestNamespace::bind` derives the replay-key namespace (M: `admission_operation/identity.rs:154`). Spec 6 R-6-05 compares it.
      - `chio_runtime`, including `chio_runtime.identity_disposition`, `chio_runtime.stop` (spec 8) and `chio_runtime.crossing` (spec 10).

      This is a kernel change. M: reserves seven keys today, and neither of these is among them (M: `kernel/mod.rs:151-159`, `RESERVED_RECEIPT_METADATA_KEYS`). Without it, a caller could pre-set an identity disposition or a namespace digest that a verifier would trust.

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
| `CapturePending`, capture `Committed` | `IntentCommit` remainder to `DispatchCommitted` (no handoff happened yet), then as `DispatchCommitted` | as S | as S | Post-dispatch with holds frozen (spec 4 drain table: a committed capture is post-dispatch). `HaltOperation { AuthorityCut }`; no `IntentCommit`, because the new closure fence would refuse it; never `Compensate` (T3). When owned, `Terminalize(OutcomeUnknownAfterDispatch)` as a restrictive, non-crossing commit that the fence cannot refuse. Holds are released only through `ReleaseAuthorized` (M7a) |
| `CapturePending`, capture `Unknown` | `QueryParticipant(Capture)`, Retain | as S | as S | as S |
| `DispatchCommitted`, durable return `Recoverable` | `Finalizing`: the next post-return stage (never terminalize; M: `recovery.rs:408-418`) | as S | as S | `HaltOperation { AuthorityCut }`, then as S |
| `DispatchCommitted`, `caller_report_custody` | `CallerAwaitReport` to `AwaitingCallerReport` | as S | `Terminalize(OutcomeUnknownAfterDispatch)` (W:) | `HaltOperation { AuthorityCut }`, `CancelTransport`, then as S |
| `DispatchCommitted`, otherwise | `NotAccepted` proof in `dispatch_status`: `Terminalize(NotAcceptedAfterDispatchCommit, TransportNotAccepted)`; else `Terminalize(OutcomeUnknownAfterDispatch)` | as S | as S | `HaltOperation { AuthorityCut }`, `CancelTransport`, then as S |
| `AwaitingCallerReport` | Retain | Retain | `HaltOperation { UnsettledCallerCustody }` plus `Fault { UnsettledCallerCustody }` (open decision 1) | `HaltOperation { UnsettledCallerCustody }` plus the same fault |
| `Finalizing`, return `Recoverable` | next post-return stage | as S | as S | `HaltOperation { AuthorityCut }`, then as S |
| `Finalizing`, return `Unrecoverable` | Retain plus `Fault { UnrecoverableReturn }` (M: claims recovery and continues, `recovery.rs:308-318`) | as S | as S | as S |
| `Compensating` | Compensate (drive again) | as S | as S | as S |
| `Mutation(Ready)` | `QueryParticipant(Mutation)`, then Applied or NotApplied by result | as S | as S | as S |
| `Mutation(Submitted)` | `QueryParticipant(Mutation)`, Retain until the result | as S | as S | as S |
| `Authorized` (governed active response), approval reservation `Committed` | roll forward to `DispatchCommitted`; a committed approval cannot be cancelled (M: `admission_cleanup.rs:551-599`, `:602-607`) | as S | as S | as S, then `HaltOperation { AuthorityCut }`; the closed space refuses the execution crossing |
| `Authorized` (governed active response), approval reservation `None` or `Reserved` | Compensate (M: `admission_cleanup.rs:661-676`) | Compensate | Compensate | Compensate |
| `DispatchCommitted` (governed active response) | `QueryParticipant(ApprovalReservation)`, commit it if still `Reserved`, Retain; never terminalize while the executor can resume (M: `admission_cleanup.rs:602-627`) | as S | as S | `HaltOperation { AuthorityCut }`, then as S |
| Terminal | Retain | Retain | Retain | Retain |

`ApprovalRetirement` on `Parked` with an elapsed deadline compensates with cause `ApprovalRetirement`. `GovernedResponseRecovery` and `DriverDropped` (M17) use the `S` column. Under `X`, every row whose operation has a live session request also emits `LatchRequest { request_id, AuthorityCut }` in its first group, so the session cannot re-submit the request into the closed space (spec 4 section 5). Every `HaltOperation` in this table halts only the named operation; none gates other operations or new dispatch. For the governed active response kind, its own rows take precedence over the generic `Authorized` and `DispatchCommitted` rows.

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
| `Finalizing` while the kernel is stopped | the finalization error fails startup (M: `recovery.rs:295-358`), so a host restarted during a stop never starts | not covered | Retain with output withheld (M11); spec 8 phase 1 adopts this in the legacy reconciler (S8-01) |

## 7. Drivers and ports

| Driver | Feeds | Performs through |
|---|---|---|
| `EvaluationDriver` (async) | `Begin`, acknowledgements, capture, dispatch acknowledgement, tool return, post-return stages, failures | `CrossingPort` (spec 10), `DispatchPort`, `SigningPort`, participant ports, `HintPort` |
| `BlockingAdapter` | none of its own: wraps `EvaluationDriver` on the existing blocking runtime | as above |
| `NestedFlowDriver` | the same events, with nested-flow client callbacks as an event source | as above, plus `NestedFlowClient` |
| `CallerExecutionDriver` | reserve, `CallerStartAuthenticated` and `CallerReportAuthenticated`, under the caller dispositions | `CrossingPort` |
| `StartupReconciler` | `Cut(StartupRecovery)` per recoverable operation, after the lease claim and after spec 8's stop heads load | `CrossingPort`, `SigningPort` |
| `ApprovalRetirementDriver` | `Cut(ApprovalRetirement)` | as above |
| `GovernedResponseRecoveryDriver` | `Cut(GovernedResponseRecovery)`, and the committed active-response resume (M: `kernel/active_response_committed_recovery.rs:204`, `:424`) | as above |
| `RecoveryClosureDriver` (W:) | `Cut(RecoveryClosure { control })` | as above |
| `DrainDriver` (spec 4) | `Cut(AuthorityCut { trigger })` | as above |
| `ReservationReconcileDriver` | settlement of a reserved authorization by nonce (M: `kernel/reconciliation.rs:148`) | as above |
| `DropReconcileJob` | for a driver dropped after submitting its dispatch-commit crossing: the writer's reply for that member, then `Cut(DriverDropped)` (M17) | as above |
| `FinalizingRetryDriver` | `Tick` to every operation retained in `Finalizing` (stop-withheld output, infrastructure fault, re-submitted plan). It fires on the `StopHeads` watch when a stop is resumed, and with bounded backoff otherwise (M11, M16) | `CrossingPort` |
| `UnknownReleaseDriver` | `ReleaseAuthorized` after it verifies a counterparty agreement or contractual capture waiver for a frozen hold. From `ReleaseSubmitted` it resolves the release only through the adapter's declared `IdempotentPerKey` or `FenceByKey` capability, never from a status query alone (M7a) | payment-journal port, `CrossingPort` |
| `StoreRecoveryDriver` | re-feeds every operation retained under M19 with its same planned member: with bounded backoff, and at once on spec 10's `store_healthy` signal. After a poisoned owner, `StartupReconciler` takes over at restart | `CrossingPort` |

The rules for drivers:
- Drivers own leases (the existing `mutation_sequencer.try_own_operation`), the clock, fact lookups, identity allocation, and every port call.
- A driver never chooses a next state. It persists `next` through the commit effects that spec 10 executes, using `persist` and the version CAS.
- A crash between an effect and its acknowledgement is resolved by re-projecting the persisted record and re-feeding only the events the driver can prove (participant lookup by `operation_id`). It is never resolved by assumption.
- **Affine driver contract (spec 3).** A driver that hands off to a tool holds spec 3's obligation. It is minted on the acknowledgement of `Dispatch`, `DispatchCommitAcknowledged` or `CheckOnlyAcknowledged`, and it is discharged only by the acknowledgement of an M14 discharge effect. Spec 3 owns the obligation type, the latch scopes and the ledger; this spec owns the decisions; spec 10 executes the commits.
- **Drop** follows M17. No durable transition runs inside `Drop`, and a pre-dispatch drop never latches.
- **Halts.** A driver that receives `HaltOperation` stops acting on that operation and releases its lease. It keeps serving every other operation.
- **Hints.** The `HintPort` is a no-op until spec 5 Part B lands (M18).

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
     - the divergences of section 6.2.
2. **Phase 1: startup reconciler and approval retirement.** Effects must equal today's behavior on the DST seeds and the existing recovery tests, including the durable `AwaitingCallerReport` transition. The one intended difference is the stop row of section 6.2, which spec 8 phase 1 has already landed in the legacy reconciler.
3. **Phase 2: recovery closure and governed active response recovery.** These follow the section 6.1 rows.
4. **Phase 3: drain and stop.** Spec 4's drain is built on the machine from the start. Spec 8 phase 1 lands earlier, in the bug-fix lane, on the legacy code: it adopts the M11 retain rule in the legacy reconciler and needs nothing else from this spec. Spec 8 phase 2 (the `StopEpoch` crossing check, with spec 10) and its later phases are built on the machine.
5. **Phase 4: evaluators.** `EvaluationDriver`, `NestedFlowDriver`, `CallerExecutionDriver`, `ReservationReconcileDriver` and `DropReconcileJob` replace their legacy code. The `evaluate` entry point lands and the seventeen wrappers are deprecated. Spec 3 phase 1 lands earlier, in the bug-fix lane, as the D1 fix on the legacy evaluator. Spec 3's later phases are re-specified against these drivers.
6. **Phase 5: one persisted model** (open decision 2).

**Compatibility period.** Through phase 5, the store's CAS keeps asserting the legacy predicate for the record's model. When the predicate rejects a machine-chosen step, that operation is handed to the retained legacy driver, with an `audit_fault`. It is never blocked, and holds are never stranded. The assertions and the legacy drivers are removed only after one release with zero recorded disagreements in CI, DST and production traces.

**Receipts and wire.** No change. The machine reproduces the decisions today's code makes, except the section 6.2 rows. Those are decided explicitly, and each is covered by a conformance case.

## 10. Proof and simulation plan

**Extraction.** The machine splits into two parts:
- `admission_machine::core`: phases and participants as codes, facts as fixed-width bitsets, digests as `[u8; 32]`, effects as codes. It is extractable: no `serde_json`, no attachments and no heap collections, consistent with the hub's rule (M: `formal_aeneas.rs:1-5`).
- `admission_machine::hydrate`: builds `IntentCommitPlan`, receipt metadata and attachments from core codes. It is not extracted, and it is covered by differential tests and Kani.

Phase 0 extracts a prototype core with payload-carrying enums before committing T1-T14. The Lean statements live in `Chio/Admission/Machine.lean`.

**Theorems** (safety, over the extracted core):

| Theorem | Statement | Closes |
|---|---|---|
| T1 `prepared_first` | no participant-mutating step precedes `Prepared` | saga rule 1 |
| T2 `commit_before_dispatch` | `Dispatch` only on `DispatchCommitAcknowledged`, or on `CheckOnlyAcknowledged` for the read-only and `NonDurable` classes | saga rule 3 |
| T3 `no_compensation_after_commit` | `Compensate` only from pre-dispatch phases with capture not committed, and never while a submitted dispatch-commit crossing has no terminal reply | spec 4 section 5 |
| T4 `machine_release_authorities` | the machine emits only `PreDispatchNoEffect`, `TransportNotAccepted` or `ContractualZeroCharge`, and the last only on a zero recomputed amount or `DeniedAfterDelivery`; it emits `ReleaseHold` only on a `ReleaseAuthorized` event in `Terminal(OutcomeUnknownAfterDispatch)` with a frozen hold | saga rule 6 |
| T5 `terminal_absorbing` | no transition leaves a terminal phase; `ReleaseAuthorized` changes only `unknown_hold` | saga rule 4 |
| T6 `unknown_stays_unknown` | no `Dispatch` and no `MachineRelease` after `OutcomeUnknownAfterDispatch`; the only hold release is a counterparty-authorized `ReleaseHold`; `unknown_hold = Released(a)` only on the acknowledgement of the `ReleaseHold` for `a`, with at most one `ReleaseHold` outstanding per operation; `ReleaseSubmitted` returns to `Frozen` only on a definitive keyed rejection or a successful fence, and every release of one hold carries the same `hold_release_key` | saga rule 6 |
| T7 `fence_dominance` | a policy refusal on any dispatch-commit step (fast or slow) or check-only crossing never leads to `Dispatch`; a refusal on an outcome or release commit never leads to an `Allow` receipt | spec 8 S7/S15, spec 4 section 4.1, spec 11 |
| T8 `post_effect_discharge` | every post-dispatch phase has an enabled transition to the M14 discharge set, or to `HaltOperation`, under the named fair events; none returns to a pre-dispatch phase; each handed-off operation acknowledges exactly one discharge | spec 3 section 4.11 |
| T9 `plan_order` | participants are acknowledged in plan order or by the combined acknowledgement; `Authorized` exactly when the plan is complete | both legacy orderings |
| T10 `replay_uniqueness` | an operation in a terminal phase, including a deny tombstone, never reaches `Dispatch` again for the same binding | saga rule 4 and its predicates |
| T11 `stop_is_temporary` | a `KernelStopped` refusal never emits `DenyTombstone` or `Terminalize`, and never emits `Compensate` from `Parked` or a post-dispatch phase | spec 8 S14, S15 |
| T12 `hints_trail_commits` | a `Hint` effect appears only in the last group of a list, after a group whose commit was acknowledged `Committed`; no transition reads a hint | spec 5 H1, H2 |
| T13 `store_failure_is_not_policy` | `StoreUnavailable` never yields `Compensate`, `Terminalize`, `DenyTombstone`, `ReleaseHold` or a phase change; the next state retains the same planned member with its expected version | spec 10 X21 |
| T14 `identity_disposition_truthful` | a receipt is `Reusable` exactly when its producing transition leaves no operation row, tombstone, custody or executed effect bound to the request id | spec 8 S15, spec 6 rule 10, spec 3 section 4.11 |

**Model checking.**
- Add `formal/apalache/AdmissionMachine.tla` for two operations and these concurrent drivers racing through version CAS: evaluator, startup reconciler, recovery closure, caller execution, the drain, the drop-reconcile job, and the governed active response resume.
- Safety invariants T2, T3, T5, T7, T10, T11 and T13 are checked under interleaving, with a negative model for each. The model includes a stop committed and resumed at any point, so T11 is checked against a parked operation and a stop-withheld release.
- **Liveness** is checked here, not in Lean, under weak fairness on these events:
  - eventually a caller report, or the open decision 1 deadline edge;
  - eventually a transport answer or ambiguity;
  - eventually a driver re-feed after a crash.
- The model registers in `formal/proof-manifest.toml` and mirrors the core through `formal/MAPPING.md`.

**Differential random testing** (Cedar method). A property-based generator produces random event sequences per kind, class and plan. It runs them through the extracted core, the hydrator, and, during compatibility, the legacy predicates. Agreement is required on `next` and on effect codes.

**Trace validation.** Today's commit log retains digests, not states (section 2). Phase 1 validates that machine-produced states hash to the retained operation digests. Full replay of production histories needs per-version snapshots or an event log (open decision 6).

**Deterministic simulation.**
- The DST harness drives the machine directly. A seeded scheduler interleaves events for many operations from all drivers, and injects at every effect group: commit failure for each reason, unknown commit outcome, a crash between effect and acknowledgement, ambiguous transport for each cause, post-effect refusal, post-effect step failure for each `PostEffectCause`, receipt append `Refused` and `Unknown` (with a late commit of the original), driver drop before and after the dispatch-commit acknowledgement, a stop committed and resumed around a parked operation, a refused fused intent from `Prepared` holding a runtime hook, a counterparty release of a frozen hold (including a duplicate), a rail-held release whose original request is delivered after a negative status query (before and after a replacement request), member retry exhaustion and owner poisoning on every effect (`StoreUnavailable`), and clock unavailability.
- The oracles are T1-T14 as runtime assertions, plus the legacy predicates during compatibility.

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
| Commit outcome unknown | M12: `HaltOperation`, holds retained, ambiguous deny if pre-dispatch; re-project at restart |
| Store unavailable (member retry exhaustion, poisoned owner) | M19: the same planned member is retained with every hold; never compensated or terminalized because of the failure; `StoreRecoveryDriver` re-feeds on `store_healthy` and with backoff, and `StartupReconciler` after restart |
| Rail answers "not released" to a status query | M7a: not terminal; `ReleaseSubmitted` is kept. Only a keyed rejection (`IdempotentPerKey`) or a successful fence (`FenceByKey`) returns the hold to `Frozen` |
| Post-effect step failure | M16: durable classes retain and re-run from frozen inputs or terminalize `DeniedAfterDelivery`; classes with no row append a fault receipt |
| Receipt append outcome unknown | M16: `KernelEvidenceLatch` with the buffered fault record; nothing appended until the read-back |
| Driver future dropped | M17: compensate before submission. If submitted but unacknowledged, retain, then reconcile from the writer's reply and `Cut(DriverDropped)`. After the acknowledgement, `Cut(DriverDropped)`. Never a durable transition in `Drop` |
| Kernel stopped | M15: receipt only, no tombstone; parked and post-effect operations retained; a host restarted during a stop still starts (section 6.2) |
| Crash between effect and acknowledgement | re-project and re-feed provable events only (section 7) |
| Clock unavailable | the driver cannot construct the event, so no transition occurs. Pre-dispatch work fails closed through the existing authority-time errors |
| Partially completed compensation | the next `Cut` drives it again from `Compensating` or the persisted phase |

## 13. Rollout

| Phase | Content | Gate |
|---|---|---|
| 0 | Vocabulary, projection, persistence, prototype extraction, differential | Prototype extracts; zero unexplained disagreements |
| 1 | Startup and approval-retirement drivers; Lean skeleton; `AdmissionMachine.tla` | T3, T5, T10 proven; Apalache positive and negative pass |
| 2 | Recovery closure and governed active response drivers | W: recovery suites and governed active response recovery tests green |
| 3 | Drain driver (spec 4) and the stop path from spec 8 phase 2 onward; spec 8 phase 1 has already landed on the legacy reconciler | Spec 4 and 8 conformance |
| 4 | Evaluation, nested, caller-execution, reservation-reconcile and drop-reconcile drivers; `evaluate`; deprecations | Benchmark acceptance; T1-T14 proven; liveness checked |
| 5 | Persisted model decision; compatibility assertions and legacy drivers removed | One release with zero disagreements |

Gate GT1 applies: no proof or conformance claim until the lanes run in hosted CI.

## 14. Tests and conformance evidence

- **Unit:** projection totality over all 19 tool-model and 15 security-model states with their dispatch pairs; `persist(project(r), r, ..) == r` for every reachable record, including security forward actions; rules M1-M20 by example; every row of the cut table, including `DriverDropped` and the `LatchRequest` emissions under `X`; every M16 row for both class groups.
- **Differential:** the two inclusions of phase 0, over the live transition space.
- **Proptest:** random event sequences per kind, class and plan, checking T1-T14 as executable assertions.
- **Kani:** `transition` never panics; `classify` is total; the hydrator's plans are well formed.
- **Lean:** T1-T14, with mirrors registered.
- **Apalache:** `AdmissionMachine.tla`, with negative mutants: drop the T2 guard, compensate after commit, leave a terminal, dispatch after a deny tombstone, tombstone a `KernelStopped` refusal, compensate a parked operation on `KernelStopped`, compensate or terminalize on `StoreUnavailable`, return a rail-held release to `Frozen` on a status query.
- **Loom:** two drivers racing on one operation through the CAS adapter; a cut racing a caller report; a driver dropped while its dispatch-commit acknowledgement is in flight, racing the drop-reconcile job.
- **DST:** one fault-injection seed per effect group and failure reason, added to `tests/dst/seeds.toml`.
- **Conformance:**
  - the existing verdict-matrix and recovery scenarios pass unchanged through `evaluate`;
  - one case for each section 6.2 decision;
  - fused-path deny tombstone replay;
  - read-only class eligibility refusal, including a kernel with `require_durable_request_retention`;
  - an integrity-tracked read takes the durable path, and its influence join commits before delivery;
  - a driver dropped after submitting its intent and before the acknowledgement. Nothing is compensated. If the writer then commits, the operation ends outcome-unknown; if it refuses, it compensates. Loom and DST cover a writer that commits after the reply waiter is gone;
  - `ReleaseAuthorized` then an acknowledged `ReleaseHold` gives `Released`. A failed release returns to `Frozen` and a retry succeeds. A duplicate while `Releasing` emits no second effect. A crash after the release commit re-projects as `Released`;
  - a `KernelStopped` fused denial followed by resume and a retry with the same request id, which is admitted;
  - a parked operation that survives a stop and an approval refused at the edge during it;
  - a caller report accepted during a stop and released after resume;
  - a two-commit read refused at its outcome commit, which returns `OutputWithheld` and is never re-dispatched;
  - restart during a stop with caller, native and ordinary operations in `Finalizing` (spec 8 S8-01);
  - a receipt append that times out and then commits, which yields exactly one terminal receipt;
  - a `NonDurable` call under `Monetary` with every M16 failure;
  - `Terminalize` and `Compensate` answered `StoreUnavailable` after member retry exhaustion: the same member is retained with its holds, and after `store_healthy` it commits exactly once. The same after owner poisoning, resolved by `StartupReconciler` at restart. No compensation or terminal is ever produced by the failure itself (T13);
  - an `IntentCommit` from `Unbegun` answered `StoreUnavailable`: no dispatch, a `Reusable` deny, and a retry with the same id after recovery is admitted;
  - rail-held release with `IdempotentPerKey`: the original request is lost, re-submission with the same key resolves it, and a delayed original delivered after a replacement authorization is deduplicated by the rail;
  - rail-held release with `FenceByKey`: a negative status query keeps `ReleaseSubmitted`; a successful fence returns to `Frozen`; the original request delivered afterwards is refused by the rail;
  - a rail adapter with neither capability: the prepare crossing refuses before any rail call and the hold stays `Frozen`;
  - identity disposition per path, each case separate: tier-1 stop denial (`Reusable`), fused stop denial from `Unbegun` (`Reusable`), fused intent from `Prepared` refused by a stop (`Terminal`, compensated), slow-path stop compensation (`Terminal`), parked operation during a stop (no stop receipt; later terminal receipt `Terminal`), durable post-effect withhold (no stop receipt; later terminal receipt `Terminal`), check-only read withheld (`Reusable`), `NonDurable` effect withheld (`Terminal`), `Overloaded` (`Reusable`). Each asserts `retryable_after_resume == (identity_disposition == Reusable)` (T14);
  - caller-supplied metadata carrying `receipt_context` or `chio_runtime` is rejected before evaluation.

## 15. Residual risks and open decisions

Residual risks:

- **Ports stay tested, not proven.** A port that lies about an acknowledgement defeats the proofs. That is spec 1's `fact_source` polarity.
- **Extraction limits.** If the prototype fails to extract, the core's types narrow further, or the plan falls back to a hand-written Lean reference with differential tests (open decision 4).
- **Migration risk.** Phase 4 touches the two largest evaluator files. The legacy-driver fallback and the differential gate bound the risk, but cannot remove it.
- **Unsettled caller custody.** Under recovery closure with non-`Active` control, an `AwaitingCallerReport` operation stays non-terminal until a caller report arrives, with its holds frozen. It is visible through a fault, not resolved, until open decision 1.
- **Withheld output in classes with no row.** A stop or fence that refuses the release of a read-only or `NonDurable` call drops the output, because there is no durable custody to hold it. The `Withheld` receipt records that. Durable coverage (`All`) is the remedy.
- **Unknown commit outcomes halt one operation, not the kernel.** A halted operation keeps its holds frozen until restart re-projects it. The blast radius is spec 10's batch bound (X22).

Open decisions:

1. **Deadline for caller custody.** Should `AwaitingCallerReport` gain a deadline-bounded edge to `OutcomeUnknownAfterDispatch`, so that a quarantined or cancelled workflow can settle? This is a saga change and needs the admission-operation owners. Without it, the machine keeps W:'s terminalization for `DispatchCommitted` under non-`Active` closure, and halts the operation with a fault for `AwaitingCallerReport` (section 6.1).
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

### Wave 2 (cross-spec)

Findings from the reviews of specs 3, 5 and 8 that this spec had to absorb, per the wave 2 shared decisions:

| Finding | Severity | Disposition |
|---|---|---|
| S3-01 pre-dispatch drop latches and leaks holds | Blocker | Applied: M17, a drop before the acknowledgement compensates under `PreDispatchNoEffect` and never latches |
| S3-02 compensation on an unconfirmed dispatch commit | Blocker | Applied: M12 is the machine form of `BoundaryFailure::CommitUnconfirmed`; holds and credentials retained; ambiguous deny only for pre-dispatch commits |
| S3-03 "latch" means three things | Blocker | Applied: `Effect::Latch` split into `HaltOperation`, `LatchRequest` and `KernelEvidenceLatch` (section 5.2); M11, M12 and every post-dispatch cut row use `HaltOperation`; `LatchRequest` under `X` |
| S3-05 receipt append can commit after a timeout | Major | Applied: `ReceiptAppendFailed { Unknown }` and `ReceiptReadBack`; M16 buffers behind `KernelEvidenceLatch` and appends nothing until the read-back |
| S3-14 drop after dispatch strands request ids | Major | Applied: M17, `CutCause::DriverDropped`, `DropReconcileJob` |
| S3-15 overlap with specs 9 and 10 | Major | Applied: spec 9 decides (M16 rows, `PostEffectStepFailed`, `ReceiptAppendFailed`, `NonDurable`); spec 10 executes; spec 3 owns the affine driver contract, latch scopes and ledger (section 7); spec 3 phase 1 sequenced in the bug-fix lane (section 9) |
| S3-16 `Monetary` runs mutating tools without durable admission | Major | Applied: `OperationClass::NonDurable` (section 4.4) |
| S3-24 retention kernels deny uncovered reads | Minor | Applied: check-only eligibility excludes `require_durable_request_retention`; such reads are denied as today (section 4.4) |
| S3-25 stale cross-references | Nit | Applied: M11 owns the mapping and cites spec 3 rule 13 as the legacy phase 1 form; M14 and T8 cite spec 3 section 4.11 |
| S5-11 hint integration undefined | Major | Applied: `Effect::Hint { hint: Hint }` over spec 5 Part B's `HintPort` vocabulary; trailing group after `Committed` (M18); H2 per commit class; T12 |
| S5-24 H1 not enforced | Minor | Applied in part: no `AdmissionEvent` is hint-derived, and the differential suite drops and forges hints (M18). The crate dependency ban belongs to spec 5 |
| S8-01 restart during a stop never starts | Blocker | Applied: M11 retain adopted by the legacy reconciler in spec 8 phase 1; section 6.2 row; `StartupReconciler` runs after the stop heads load |
| S8-12 caller report lost when refused | Major | Applied: the caller report is a progress-only `ReturnRecord`, never stop-checked (M11) |
| S8-17 S15 stale for fused, check-only and tier-1 paths | Minor | Applied: M15 per path; `KernelStopped` writes no tombstone (M10) |
| S8-18 two-commit read re-dispatched after a stop | Minor | Applied: `ReturnRecord` on a stop-refused outcome commit; `OutputWithheld` (M11) |
| S8-19 parked operation killed by a stop | Minor | Applied: `Parked` plus `KernelStopped` retains (M10); approvals refused at the edge without consumption (M15); T11 |
| S8-24 spec 9 dependency of spec 8 phases unstated | Minor | Applied: section 9 phase 3 names spec 8 phase 1 (legacy, bug-fix lane) and phase 2 onward (on the machine) |

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180435329 | Route unavailable intent commits to the slow path | Already addressed in revision 2: `Unavailable` re-plans with `Replan { slow_path: true }` and never compensates. Tightened now: M10 matches the reason before any generic row, and covers `Unavailable`, `Overloaded` and `VersionConflict` on slow-path steps and from `Prepared`. No `CommitFailure` reason reaches the illegal-event arm | M10 |
| 4180435341 | Handle outcome-commit failures after dispatch | Fixed now. Revision 3's M11 covered the policy reasons and `VersionConflict`; this round adds `Overloaded` and `Unavailable` (slow-path settlement re-plan), a totality rule, and the `FinalizingRetryDriver`, which re-feeds every retained `Finalizing` operation on stop resume and with backoff | M11, section 7 |
| 4180435358 | Add events for counterparty-authorized releases | Fixed now. New `ReleaseAuthorized { authority, evidence }`, `UnknownOutcomeRelease`, the `unknown_hold` fact and the `ReleaseHold` effect, accepted only in `Terminal(OutcomeUnknownAfterDispatch)` with a frozen hold. The phase stays absorbing, and `UnknownReleaseDriver` verifies the evidence | sections 4.1, 5.1, 5.2; M6, M7a; T4-T6 |
| 4180731780 (spec 10) | Compensate hooks acquired before the fused intent | Fixed now. A fused intent from `Prepared` refused for a policy reason compensates the persisted operation, releasing its hook and nonce, with no deny tombstone | M10; spec 10 X10 |

### Codex review (PR #1174, round 2)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180839034 | Do not compensate while the intent commit is still in flight | Fixed now. The driver tracks `SubmissionState` for its dispatch-commit crossing. A drop before submission compensates. A drop after submission and before the acknowledgement is `CommitUnconfirmed`: everything is retained, and a `DropReconcileJob` takes the reply handle, feeds the writer's reply, then `Cut(DriverDropped)`. Compensation happens only once the reply or a read-back proves the intent did not commit | M17; T3; section 7 table; section 12; section 14; spec 3 rule 29; spec 10 X17 |
| 4180839038 | Carry the release authority through acknowledgement | Fixed now. New transient `UnknownHold::Releasing { authority, evidence }`. `Released(authority)` is set only by the `ReleaseHold` acknowledgement. A failed release returns to `Frozen` and may be retried. An unknown outcome halts and re-projects from the store. A duplicate while releasing emits no second effect. The release entry is keyed by `operation_id` in one writer transaction | sections 4.1, 5.1, 5.2; M7a; M11; T6; section 14 |
| 4180839013 (spec 10) | Persist influence joins before check-only output release | Fixed now. Check-only eligibility gains a fifth condition: integrity tracking is not enabled for the calling context. Such reads take the durable path, whose `OutcomeCommit` writes the I4 join before delivery. Would-be `NonDurable` calls under integrity tracking do the same, because they have the same gap | section 4.4; section 14; spec 10 X13 |

### Codex review (PR #1174, round 3)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180886724 | Treat a committed capture as post-dispatch at a cut | Fixed now. Under `AuthorityCut`, `CapturePending` with capture `Committed` is post-dispatch with holds frozen: `HaltOperation`, no `IntentCommit`, never `Compensate`, and, when owned, `Terminalize(OutcomeUnknownAfterDispatch)` as a restrictive, non-crossing commit. Two new M10 rows cover a refused intent remainder from that state (`KernelStopped` retains; other policy reasons take the same post-dispatch path) and take precedence over the generic slow-path compensation row | section 6.1 table; M10 |
| 4180886727 (spec 10) | Recheck revocation before releasing tool output | Fixed in spec 10 section 4.2. The post-effect `Revoked` row of M11 already maps a refused release to `DeniedAfterDelivery` | M11 (unchanged); spec 10 section 4.2, X16 |

### Codex review (PR #1174, round 5)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180993960 | Make stopped non-durable effects terminal to retries | Fixed now. A `NonDurable` call whose release is refused by a stop has executed its effect, so its `Withheld` receipt records `effect_executed: true` and `retryable_after_resume: false`. The driver returns the terminal `OutputWithheld { retry: Never }`. Only check-only reads, which are redispatch-safe by eligibility, get `retry: AfterResume` | M11 "Classes with no row"; spec 8 S15 and `OutputWithheld`; spec 10 X16 |
| 4180993966 | Reconcile an external hold release before retrying it | Fixed now. Rail-held releases are two-phase. A durable `release_submitted` row with an idempotency key commits before the external call, and projects to the persisted `ReleaseSubmitted`. `UnknownReleaseDriver` resolves it only from an authoritative rail answer by key, and a new `ReleaseAuthorized` is illegal meanwhile. Writer-held releases stay single-transaction, so absence still proves non-commit there | `UnknownHold`; M7a persistence and unknown rules |

### Independent review pass 2 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-9-01 | A negative rail status query is not proof that an in-flight release can never arrive | Fixed. One `hold_release_key` per frozen hold, independent of authority and evidence. A rail adapter must declare `IdempotentPerKey` or `FenceByKey`, or the prepare crossing refuses before any rail call. From `ReleaseSubmitted`, only a definitive keyed rejection or a successful fence returns the hold to `Frozen`. A status query alone keeps `ReleaseSubmitted`, and no ambiguous request is re-submitted except under `IdempotentPerKey`. Answers the owner's open question 2 with the required semantics | M7a; T6; section 7 `UnknownReleaseDriver`; section 12; section 14; spec 10 X17b |
| R-9-02 | Writer escalation produces Unavailable for effects whose machine declares that result impossible | Fixed. New event `StoreUnavailable` (spec 10 X21's distinct result) with an M19 row for every effect. The same planned member is retained with every hold, never compensated or terminalized because of the failure, and re-fed by the new `StoreRecoveryDriver` on `store_healthy` or with backoff, or by `StartupReconciler` after a poisoned owner. `CommitFailure::Unavailable` now means only "fused form ineligible". T13 | section 5.1; M10; M11 totality; M19; section 7; T13; sections 12 and 14 |
| R-8-02 | Slow-path terminal stop denials are marked retryable after resume | Fixed through the shared contract. M20 `IdentityDisposition` is assigned per producing row. Compensated slow-path and `Prepared`-intent stop denials are `Terminal`, and spec 8's `retryable_after_resume` equals `identity_disposition == Reusable`. M15 gains the missing `Prepared` row. T14; separate tests for early, fused, prepared, slow, parked and post-effect cases | M15; M20; section 5.2; T14; section 14; spec 8 S15 |
| R-6-06 (contract part) | Retryable admission denials other than stops have no binding disposition | Fixed here for the producing side. `Overloaded`, check-only refusals, `StoreUnavailable` before any row and every other pre-admission refusal that persists no state are `Reusable`, signed in `chio_runtime.identity_disposition`. Spec 6 consumes it | M20 |
| R-6-05 / R-6-06 (cross-reference) | Kernel-reserved receipt metadata | Fixed. `receipt_context`, with a new kernel-written `request_namespace_digest` derived like `AuthenticatedRequestNamespace::bind`, and `chio_runtime` become kernel-reserved keys. This is a kernel change: M: reserves seven other keys today (`kernel/mod.rs:151-159`) | M20 |

## Appendix A. External and FTL precedent

- **FTL.** FTL's dispatch is one exhaustive match whose fallback is `UnknownSyscall` (FTL `kernel/src/syscall.rs:19-73`), and each object's state changes in one place. The machine applies that discipline to Chio's admission saga: one function, no wildcard.
- **Cedar** builds a readable executable Lean model, proves properties, then runs differential random tests of the Rust against it. The proofs found 4 bugs and the tests found 21 more ([How We Built Cedar](https://arxiv.org/pdf/2407.01688)). Section 10 follows the same three steps over the extracted core.
- **Atmosphere** is an L4-style microkernel proven functionally correct in Rust with Verus (SOSP 2025; [Atmosphere](https://mars-research.github.io/projects/atmo/)). It shows proof is feasible at the scale of a pure decision core.
- **Deterministic simulation.** TigerBeetle's VOPR runs every component under one seeded PRNG, so a failing seed reproduces exactly ([VOPR](https://docs.tigerbeetle.com/about/vopr)). A sans-IO machine makes that cheap.
- **AWS PObserve** validates production logs against P specifications ([Systems Correctness Practices at AWS](https://dl.acm.org/doi/abs/10.1145/3815784)). Section 10's trace validation is the same idea, limited today by the digest-only commit log.

Where the analogy breaks: FTL's dispatch has no durable state or crash recovery. Chio's machine must be re-entrant from any persisted version, which is why projection, persistence plans, cut facts and acknowledgement events exist.
