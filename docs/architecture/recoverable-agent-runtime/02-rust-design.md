# Rust structure and contracts

## Design rules

Retain Rust 2021. The workspace now pins Rust 1.95.0 for the supported Wasmtime 48.0.5 security migration; see `supply-chain/reviews/wasmtime-runtime-upgrade.md`. Preserve the existing Rust 1.93 minimum of `chio-core-types` and `chio-security-types`, including the former's Kani compatibility; workspace toolchain selection does not authorize raising these crates' minimum supported version. Historical standalone formal-model qualification retains its recorded compiler. Edition changes are independent. New code forbids unsafe Rust, follows existing `unwrap_used`/`expect_used` denial, uses checked arithmetic and closed validated wire types, and preserves source-size and generated-code checks. No new cryptographic primitive or serialization framework is required.

Use algebraic data types for mutually exclusive outcomes and private constructors for verified objects. Prefer small modules organized around one authority or invariant. Use static dispatch inside pure evaluation; use narrow object-safe ports only where deployment genuinely selects an implementation. Avoid a universal context object containing every service or a generic event bus that can mutate security state.

## Ownership and dependency graph

| Component | Ownership | Change |
|---|---|---|
| Existing `chio-security-types` | Bounded data-only recovery, semantic, provenance and return contracts | Add modules; no kernel/store/transport dependency |
| Existing `chio-core-types` | Canonical signed envelopes and domain separation | Add grant v2, offer/proposal/report envelope verification using existing primitives |
| Existing `chio-flow` | Pure confidentiality, influence and scoped-exception verification | Extend exact binding; retain current label algebra |
| Proposed `chio-recovery` in `crates/security/` | Finite remedy search and pure workflow decision reduction | New small crate; no filesystem, network, runtime, clock reads or store |
| Proposed `chio-semantic-contracts` in `crates/security/` | Resolve validated contract AST/evidence into flow and integrity requirements | New small crate; no executable plugin loading or provider I/O |
| Existing `chio-kernel` | Recovery participant, effect observations, closure and native capture ownership | Extend admission/tool-outcome modules and ports |
| Existing `chio-store-sqlite` | Transactional recovery records and provenance release records under serving ownership | Implement kernel-owned ports and schema transitions |
| Existing `chio-control-plane` | Authenticated recovery service, approval presentation, provider fact resolution, scheduling | Compose pure components and kernel ports |
| Existing `chio-process` | Stable process-call reservation, workflow references, labeled checkpoint/blob integration | Add host-owned bindings; preserve original operation derivation |
| Existing manifest/policy/egress crates | Verified package deployment and actual route enforcement | Extend admission contract and coverage inventory |
| Existing SDK/CLI/codegen/replay tooling | Common recovery protocol, diagnostics and conformance | Generate shared types; keep authority in Rust |

The two new pure crates may depend on `chio-security-types`, `chio-core-types` and `chio-flow` as necessary. None may depend on `chio-kernel`, `chio-control-plane`, `chio-process`, SQLite or an SDK. The kernel must not import the control plane to validate recovery. Signed body types remain below the kernel in the existing dependency graph.

Match `chio-flow`: the new pure crates default to `no_std + alloc`, with an additive, explicit `std` feature. Preserve downstream no-default-feature and supported WASM builds. Use dependency declarations that actually disable default features; do not assume a workspace-inherited declaration can disable defaults enabled upstream. Qualify crates in isolation as well as under the workspace's unified feature graph. Existing crypto dependencies expose random/signing facilities even on some alloc-only paths, so `no_std` alone does not prove purity. Pure modules receive time, IDs and verified observations as values; ambient RNG, key generation, signing, provider access and environment reads are forbidden in their call graph.

Determinism includes iteration and tie-breaking. Canonical sets/maps use validated ordering, and candidate ordering ends in a specified stable key. No `HashMap` iteration, randomized seed, platform float comparison or scheduler completion order may choose a remedy. Cost arithmetic uses bounded integer units with checked operations; estimated costs remain advisory.

The existing `chio-workflow` may consume recovery status and emit aggregate workflow receipts. It may not allocate native execution identity, decide that an effect is absent or own single-use grant consumption. Existing disclosure-lineage structures are adapted through explicit verified conversions, not reinterpreted as live permits.

## Proposed module layout

```text
chio-recovery/src/
  lib.rs                 narrow public facade
  decision.rs            finite decision vocabulary
  planner.rs             bounded enumeration and deterministic ordering
  remedies/              disclosure, destination, transform, prerequisite, return
  basis.rs               exact vs freshness-qualified observations
  workflow.rs            pure reduction over authenticated observations
  explain.rs             audience-qualified explanation projection

chio-control-plane/src/security/recovery/
  service.rs             authenticated commands and idempotency
  resolve.rs             operator-bound observation gathering
  approval.rs            approval intent and signer routing
  driver.rs              native admission and reconciliation orchestration
  projection.rs          safe SDK/operator views

chio-kernel/src/admission_operation/recovery/
  binding.rs             exact intent/continuation/grant binding
  participant.rs         protected native participant evidence
  close.rs               irreversible verified closure
  capture.rs             recovery checks inside existing capture
```

Split storage schemas and adapters by authority responsibility. Do not solve file-size limits through generated include fragments that hide coupled logic. Existing include-based modules may remain; new logic should use ordinary Rust modules with explicit visibility.

## Types and proposed interfaces

The following is an interface sketch; supporting bounded types and lifetimes are defined by the implementation and schema contracts, not available APIs today.

```rust
pub enum PlanDecision {
    FeasibleUnderSnapshot,
    Candidates(NonEmptyBounded<CandidatePlanV1, 16>),
    NoRegisteredRemedy(ReasonCode),
    SearchBoundReached(SearchLimit),
    Refused(RefusalCode),
}

pub enum WorkflowDirective {
    Materialize(StepRef),
    RequestApproval(ApprovalIntentRef),
    ResolveAdmission(AdmissionIntentRef),
    AwaitOutcome(OperationRef),
    Reconcile(OperationRef),
    ProjectOutcome(OutcomeRef),
    Halt(ControlRef),
}

pub fn plan(
    intent: &ValidatedIntent,
    basis: &ResolvedRecoveryBasis,
    registry: &CompiledRemedyRegistry,
    limits: PlannerLimits,
) -> Result<PlanDecision, PlanningError>;

pub struct PreparedContinuation<'a> {
    authority: &'a RecoveryAuthorityBinding,
    selected: VerifiedSelection,
    basis: VerifiedCaptureBasis,
}

pub enum ResumeResult {
    Progress(RecoveryView),
    Outcome(AuthorizedOutcomeView),
    Refused(RefusalCode),
}
```

Keep planning, durable reduction and native execution as separate APIs. `plan` returns advisory candidates; the host materializes and signs exact offers. The pure reducer returns a `WorkflowDirective` from verified historical observations. A directive requests work from an owning adapter and supplies no authority to do it. Neither a snapshot-feasible result nor `Reconcile` is an execution permit. Resolving an admission intent must work before an operation reference has been projected into workflow state. This separation avoids making the planner a second runtime state machine.

`PreparedContinuation` has no public constructor, `Clone`, `Copy`, `Serialize` or `Deserialize`. It binds preparation to its authority context. It still does not authorize connector execution. Its only effectful consumer enters the existing native capture path. The actual captured owner remains kernel-private. No public `execute_unchecked`, `mark_complete`, `reset_unknown` or general store mutation method is exposed.

These handles are affine: Rust prevents an ordinary move from being used twice, but cannot require the value to be consumed. Use `#[must_use]` for review diagnostics, never as a security guarantee. Keep preparation short-lived and consume it through the native handoff. Avoid encoding the entire durable workflow in generic typestate; persisted history needs a closed, versioned sum type with verified reconstruction and transactional preconditions. Typestate is useful only for local transitions such as untrusted input to verified preparation.

Execution entry points consume the owned dispatch handle or require exclusive access; they do not expose repeatable `&self` dispatch. New ownership wrappers must have deliberate `Send`/`Sync` behavior and compile-time checks. An owned kernel dispatch task may need `Send`, while simultaneous shared execution must remain impossible. Private fields and absence of `Clone` alone do not prevent incorrect auto-trait exposure. Reuse native owner types rather than adding unsafe trait implementations or manufacturing a parallel permit hierarchy.

Wire types carry `Untrusted<T>` semantics until authenticated and bound. Do not implement `From<WireGrant> for VerifiedGrant`. Verification returns distinct private-field types. Historical verified evidence may be serializable for audit; deserializing it still produces an untrusted envelope requiring fresh verification. Match the repository's existing canonical signed-JSON reader before typed decoding, including duplicate-key and integer handling.

Use distinct newtypes for `WorkflowId`, `StepId`, `ContinuationId`, `IntentDigest`, `CanonicalPayloadDigest`, `ProcessRequestDigest`, `ProcessCallBindingDigest`, `NativeAdmissionDigest`, `AuthorizationRequirementsDigest`, `ArtifactVersionId`, `PolicyGeneration` and `ServingEpoch`. Equal bytes do not make these interchangeable. A symbolic `CandidatePlan` is distinct from a verified materialized action; no unchecked conversion can turn future-output references into approval-ready input. Digest functions specify their exact domain string and canonical body. Error messages expose bounded reason codes; protected diagnostics stay in classified records.

The conversion from a kernel request to its reviewed action must exhaustively account for every field. Use explicit field construction/destructuring without `..` at this boundary, so adding a request field forces a retention, review and binding decision. Classify each field as reviewed semantics, an exact fixed authorization artifact, or an explicitly supported native-owned attachment. Examples of reviewed semantics include governed intent, model constraints and federation identity, not merely tool arguments. An exclusion from one native hash does not make a field refreshable in the process hash. Do not implement projection as a generic JSON map with signatures or unfamiliar fields removed. Keep field-level mutation vectors alongside the owning derivation.

## Async, cancellation and resource discipline

Pure planning is synchronous and deterministic. Provider/approval/clock observations occur before planning through bounded ports. Runtime orchestration may be async, but never holds a SQLite transaction, store mutex, borrowed preparation/capture authority or secret-bearing lock across arbitrary network awaits. After the synchronous protected handoff, the kernel-owned dispatch task may own the captured operation across its bounded connector await. That ownership is necessary; the prohibition concerns borrowed authority/locks, not the actual operation owner's lifetime.

For dynamically selected ports use explicit boxed `Send` futures or the repository's established object-safe pattern. For statically composed components prefer generic traits/native futures. Do not introduce boxing, trait erasure or an async runtime into label arithmetic or state reduction for convenience.

Cancellation is an input to a persisted protocol, not Rust future destruction. Before native capture it may close an unissued selection through an authoritative CAS. After capture it schedules reconciliation and retains the original identity. `Drop` only releases process-local resources; it cannot refund a grant, certify no effect or perform a critical durable transition. `mem::forget`, process abort and runtime shutdown must remain safe.

External payloads and secrets have redacted `Debug`; no argument values in tracing fields by default. Reuse keyring/broker secret custody and established zeroization types. Panics in untrusted extension execution become bounded failures at the isolation boundary; they do not silently convert a failed classifier into public data.

Preparation and capture execute on the owning bounded blocking executor where the existing SQLite integration requires it; never run blocking store work on an async reactor or start unbounded `spawn_blocking` jobs. Supervision retains every spawned task's join/cancellation state. Stop intake, persist cancellation intent as appropriate, and drain or hand off reconciliation on shutdown. `catch_unwind` is neither a sandbox nor a guarantee under `panic=abort`; a panic after an ambiguous mutation requires readback/quarantine, not assumed rollback.

Bounded wire types need checked constructors and decoding visitors that enforce collection length before growth. Do not deserialize an unbounded `Vec` and validate it afterward. Do not expose `DerefMut`, unchecked setters, generic `Deserialize` for verified types, or `#[non_exhaustive]` as a substitute for closed wire versioning. Byte, nesting, aggregate collection and verification-work limits apply together, including recursive evidence and dependency expansion.

## Obligations

| ID | Normative obligation | Proposed acceptance test | Phase |
|---|---|---|---|
| RUST-01 | Pure planner/contracts crates MUST have no effectful platform dependencies or ambient state reads. | `architecture::pure_dependency_graph` | P0 |
| RUST-02 | Live preparation/ownership types MUST be unconstructible from public wire data. | `compile_fail::wire_to_live_owner` | P0 |
| RUST-03 | Security variants and identifiers MUST be bounded, closed and non-interchangeable. | `wire::bounds_and_identifier_domains` | P0 |
| RUST-04 | Cancellation and unwinding MUST preserve durable ownership and consumed authority. | `runtime::abort_at_every_await` | P1 |
| RUST-05 | Async orchestration MUST NOT hold a store transaction across provider awaits. | `storage::blocked_provider_does_not_hold_writer` | P1 |
| RUST-06 | New code MUST pass owning Clippy, formatting, feature-matrix and dependency-direction checks without relaxed baselines. | `architecture::owning_quality_gates` | P0 |
| RUST-07 | Debug, tracing and public errors MUST exclude protected payloads and secret material. | `observability::secret_and_payload_canaries` | P0 |
| RUST-08 | Pure/substrate changes MUST preserve declared MSRV, no_std/alloc builds and deterministic behavior under isolated and unified features. | `architecture::portable_feature_and_determinism_matrix` | P0 |
| RUST-09 | Live handle auto traits, consuming APIs and supervised task lifetimes MUST preserve exclusive dispatch without relying on Drop or must_use. | `compile_fail::owner_autotraits_and_consumption` | P1 |
| RUST-10 | Decoding and evidence expansion MUST enforce aggregate limits before allocation or unbounded verification work. | `wire::nested_allocation_and_verification_budget` | P0 |
| RUST-11 | Planner results and workflow directives MUST remain non-authorizing, and request projections MUST account explicitly for every field and digest meaning. | `architecture::planner_driver_types_and_exhaustive_projection` | P0 |
