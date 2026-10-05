# Design: authority fault classification for the recovery lane

- Status: PROPOSED (revision 3, re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:))
- Date: 2026-10-04
- Scope:
  - Classify recoverable authority denials (missing scope, exhausted budget, expired capability, required approval) into a closed, kernel-signed fault class with anti-oracle rules.
  - Name which protected authority can answer each class.
  - Give the recovery planner one new remedy kind, `Authority`. Today an unsatisfied capability fact is terminal (`BlockedByCapability`). With this kind it becomes answerable through a linked recovery workflow.
  - This spec adds no second offer, approval, continuation, outbox or replay participant.
- Owners:
  - `chio-security-types`: remedy kind, assessment, and template.
  - `chio-recovery`: the planner rule.
  - `chio-kernel`: classifier, deny-receipt block, and capture-time checks for linked workflows.
  - `chio-store-sqlite`: predecessor link validation.
  - `chio-core-types`: fault block and binding constraint.
  - Process host and SDKs: operator-mediated resolution.
- Related:
  - W: `docs/architecture/recoverable-agent-runtime/02-rust-design.md`, `03-recovery-protocol.md`, `08-protocol-operations.md`, and `implementation/p1`, `p2`, `p3` `OPERATIONS.md`.
  - V: `2026-10-02-dynamic-delegation-design.md` (D1), `2026-10-03-work-runtime-design.md`, `2026-10-03-work-owner-services-design.md`.
  - M: `docs/security/threshold-approval-collection.md` (AP2/AP3), `2026-10-02-issuer-lifecycle-approval-authority-design.md`, and `crates/security/chio-security-kernel` (freeze, suspension).
  - `spec/PROTOCOL.md` sections 5, 6 and 8.
- Citation convention:
  - M: = `origin/integration/process-security-m4` @ `19df31ad9`.
  - V: = `origin/work/verifiable-work-session-20261003` @ `14477aaac`.
  - R: = `origin/research/openappa-recovery-20261001` @ `de84fc306` (recovery design docs).
  - W: = the uncommitted working tree at `arc-worktrees/recoverable-agent-runtime-20261002`, with recovery P0-P5 implemented locally on the #1160 checkpoint `f25cd61f4`. Line references reflect the working tree on 2026-10-04 and may drift.
  - All four are treated as shipped.
  - Recovery doc features with no code in W: are marked "doc-only". V: W1-W4 work APIs remain contract anchors.
- Origin: lessons from the FTL (nuta/ftl) review
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-closed-kernel-abi-design.md`, `2026-10-04-typed-reservations-design.md`, `2026-10-04-authority-space-teardown-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-opaque-adapter-context-design.md`, `2026-10-04-microkernel-isolation-backend-design.md`

## Revision 3 changes

- **Integration point corrected.** Implemented recovery never consumes deny receipts. It observes native flow state (W: `chio-kernel/src/recovery/ports.rs:115-123`; effect facts are "never derived from a receipt verdict", W: `chio-security-types/src/recovery/observation.rs:76`). The fault class now enters as a planner fact. The deny-receipt block stays as audit and client evidence.
- **Remedy kind made concrete against code.**
  - `ExplanationRemedyKind` is closed at four variants (W: `chio-security-types/src/recovery/explanation/registry.rs:6-11`).
  - An unsatisfied `ExplanationFactKind::Capability` short-circuits to `BlockedByCapability` (W: `chio-recovery/src/evaluation.rs:195-206`).
  - This spec adds `Authority` as the only kind that may address a capability fact, and a new assessment `RequiresAuthority`.
- **Linked workflow, not capability swap.** The store pins every action to the seed's capability (W: `.../recovery/issuance.rs:76-81`). An `Authority` remedy therefore creates a new recovery workflow whose seed carries the new capability and whose record names its predecessor.
- **Offer chain renamed to implemented types.** The signed `RemedyOfferV1` is doc-only. The implemented chain is: template, `ActionIntentV1`, derived `OfferDigest`, approval intent, then grant v2.
- **Operator-mediated resolution.** Recovery actors must hold direct, undelegated tokens (W: `chio-kernel/src/recovery/ports.rs:193-212`). A delegator produces the new delegation out of band, and an operator-assigned actor drives the linked workflow.
- **Obligations stay information-flow only.** Authority evidence lives in the prerequisite step, not in a new `AuthorityObligationV1` variant (section 6.2, open decision 3).
- **Explanations defer to P2.** P2's rules are stricter than A1-A3. `ExplainIntent` is the endpoint `POST /v1/recovery/explain` under `Inspect`, not a command.
- **N7 and N8 restated.** Implemented recovery reuses the seed capability, so ordinary capture revocation already covers it. Step 3a and `RecoveryContinuationBinding` remain necessary only for the new `Authority` kind.
- **Dependency added.** A recovery deployment covers one process scope with one server, tool, recipient and purpose, and `RecoveryTemplateV1` has one variant. `Authority` remedies require that profile to be generalized (section 6.9).

Revision 2 recast revision 1's parallel remedy path as a classification layer that feeds recovery. It added resolvers by authority class, and dropped the fault-resolution replay participant, `fault_id`/TTL, the A2A `AuthRequired` state and the receipt-index lookup.

## 1. Decision summary

Three things already exist in W:
1. Every denial carries a stable code and suggested fix (M: `crates/kernel/chio-kernel/src/kernel/error.rs:416`).
2. Recovery P1-P3 implement the remedy loop for information-flow problems: template selection, exact `ActionIntentV1`, derived offer and plan digests, scoped approval through grant v2, a reserved continuation and native capture.
3. The P2 planner (`chio-recovery`) evaluates facts and ranks remedies without execution authority.

What none of them provides:
1. A uniform, kernel-attested classification of authority denials.
2. Any remedy for a missing capability. The planner treats an unsatisfied capability fact as terminal (`BlockedByCapability`), and P3 states "every executed step still requires its own current capability" (W: `implementation/p3/OPERATIONS.md:28`).
3. A capture-time rule that a remedy whose capability is a sibling of the denied one dies with the denied capability.

This design adds exactly those:
1. **A closed `AuthorityFaultClass`** and an exhaustive classifier over `KernelError`. It is recorded as an `authority_fault` block on the signed deny receipt (audit and client evidence) and exported to the recovery observation as a `Capability` fact with its fault class.
2. **`ExplanationRemedyKind::Authority`**, the only kind allowed to address a `Capability` fact. With a registered `Authority` template, the planner returns `RequiresAuthority` instead of `BlockedByCapability`. Without one, the result is unchanged.
3. **A linked recovery workflow.** The resolver's new authority becomes the seed capability of a new workflow (`RecoveryTemplateV1::AuthorityContinuation`) whose record names the predecessor workflow. Every existing recovery invariant then applies unchanged, including the single-capability pin, `reserve_recovery_call` and capture.
4. **Capture-time checks** for linked workflows: predecessor-capability revocation (step 3a), suspension, freeze, issuer lifecycle and shape.

The kernel never mints authority. Its only "kernel tier" resolution is materialization it already performs: sibling-grant selection, and root-first lineage restoration for process calls (M: `crates/kernel/chio-process/README.md:30`).

## 2. Verified current state

| Fact | Evidence |
|---|---|
| Recoverable conditions are distinct `KernelError` variants with stable codes and suggested fixes | M: `kernel/error.rs:126` (`CapabilityExpired`), `:147` (`OutOfScope`), `:156` (`BudgetExhausted`); `report()` `:416` |
| Check order: signature, time, revocation, delegation and subject run before grant resolution, and durable admission starts after it | M: `kernel/evaluation/async_evaluation_core.rs:223`, `:239`, `:251`, `:263`, `:267`, grants `:279`, admission `:356` |
| Threshold or cumulative approval parks the operation and returns `PendingApproval` with a signed deny receipt carrying `threshold_approval` | M: `async_evaluation_core.rs:604`; M: `kernel/responses/pending_responses.rs:38` |
| A recorded budget denial outranks a sibling grant's guard denial | M: `async_evaluation_core.rs:716-717` |
| An absent single approval token is a stringly typed `GovernedTransactionDenied` | M: `kernel/governed_validation.rs:489`, `:494` |
| Exact approvals bind a `BoundToolInvocation`. Approver rosters are separate from issuers. Capability or ancestor revocation withdraws approval at fresh admission | M: `docs/security/threshold-approval-collection.md:338-341`, `:355-356` |
| Only an active issuer head may issue. "Capability issuers authorize capabilities, configured approvers authorize exact invocations" | M: `2026-10-02-issuer-lifecycle-approval-authority-design.md:5-6`, `:11-12` |
| Issuance is exhaustive over `Constraint` (KG4) | M: `crates/kernel/chio-kernel/src/authority.rs:102` |
| No `Constraint` binds a capability to exact arguments | M: `crates/core/chio-core-types/src/capability/scope.rs:331`, `:591` |
| The issuance freeze is never consulted with `Delegate`. Suspension is a guard keyed on the exact presented capability id | M: `crates/platform/chio-store-sqlite/src/security_state/issuance_freeze.rs:1290`; M: `chio-security-kernel/src/capability_set_suspension.rs:41-60` |
| Recovery observes native flow, not receipts. `materialize` takes a `NativeSecurityFlowObservationV1`, and effect facts are never derived from a receipt verdict | W: `chio-kernel/src/recovery/ports.rs:115-123`; W: `chio-security-types/src/recovery/observation.rs:76` |
| Remedy kinds are closed: `ExistingDestination`, `ExactApproval`, `Transformation`, `Prerequisite` | W: `chio-security-types/src/recovery/explanation/registry.rs:6-11` |
| An unsatisfied capability fact short-circuits to `BlockedByCapability`. The assessments are `FeasibleUnderSnapshot`, `RequiresExactApproval`, `RequiresTransformation`, `RequiresPrerequisite`, `NeedsFreshEvidence`, `BlockedByCapability`, `UnknownOutcome`, `NoRegisteredRemedy`, `SearchBoundReached` | W: `chio-recovery/src/evaluation.rs:195-206`; W: `.../explanation/result.rs:5-15` |
| Templates are closed with one variant, `SupportTicketPublicIssue`. Commands are seven variants: `CreateWorkflow`, `InspectWorkflow`, `SelectOffer`, `SubmitApproval`, `ResumeWorkflow`, `CancelWorkflow`, `ReportDecision` | W: `chio-security-types/src/recovery/commands.rs:12-14`, `:26-58` |
| Every action is pinned to the seed's capability id and body digest | W: `chio-store-sqlite/src/admission_operation_store/recovery/issuance.rs:76-81` |
| The offer is a derived digest: `OfferDigest = H("chio.recovery.offer.v1", (intent, basis, scope))`. No signed `RemedyOfferV1` exists in code (doc-only, R: `03-recovery-protocol.md:55`) | W: `chio-control-plane/src/recovery/materialize.rs:303-306` |
| `AuthorizationRequirementsV1` obligations are information-flow only: `OwnerRelease`, `CompartmentRelease`, `UserAcceptance`, `IntegrityEndorsement` | W: `chio-security-types/src/recovery/authorization.rs:40-45`, `:49-63` |
| Grant v2 (`RecoveryGrantBodyV2` over `RecoveryGrantBindingV1`) is a disclosure grant bound to the exact continuation, living at most 60 s | W: `chio-core-types/src/recovery/authority.rs:49`, `:177`; W: `chio-security-types/src/recovery/authorization.rs:94` |
| `reserve_recovery_call` charges the process slot once before approval. `finalize_recovery_call` refuses any changed binding | W: `chio-process/src/recovery.rs:9`, `:83`, `:110` |
| Recovery actors must hold direct tokens: no delegation chain, caveats, attenuation or DPoP. Assignments come from the operator-installed `RecoveryDeploymentV1` | W: `chio-kernel/src/recovery/ports.rs:193-212`, `:252`; W: `chio-kernel/src/recovery/records.rs:100-123` |
| A deployment covers one scope `(authority_domain, tenant_id, process_id)` with one `server_id`, `tool_name`, `recipient` and `purpose` | W: `chio-kernel/src/recovery/records.rs:104-123`; W: `chio-security-types/src/recovery/observation.rs:10` |
| Revoking or expiring the initiating capability prevents new capture | W: `implementation/p1/OPERATIONS.md:119-120` |
| Recovery paths consult no suspension or freeze authority directly; only ordinary native guards on the reused capability apply | grep over W: recovery kernel, control-plane and store paths (no matches) |
| Explanation is `POST /v1/recovery/explain` under the existing `Inspect` permission. Inaccessible candidates are filtered before search or ranking. Probes are limited to 32 per actor per 60 s, process-local | W: `chio-control-plane/src/recovery/explanation/transport.rs:37`; W: `implementation/p2/OPERATIONS.md:22-25`, `:73-77`, `:107-110` |
| Intake quotas: 64 workflows per tenant | W: `implementation/p1/OPERATIONS.md:131-135` |
| `Drop` cannot refund, certify no effect or perform a critical transition | R: `02-rust-design.md:124` |
| D1 selection binds a receiver-issued capability (`max_invocations=1`) and request id into a sealed permit. There is no release of sealed allocations | V: `dynamic-delegation-design.md:55`, `:77`, `:86`, `:116-121` |
| A process has one immutable capability. `spawn` needs one signed hop from the exact parent. The worker protocol has no capability replacement and carries no approval token | M: `chio-process/README.md:30`; M: `chio-process/WORKER_PROTOCOL.md:59-62`, `:71` |
| A2A maps `PendingApproval` to `Working` | M: `chio-a2a-edge/src/conversion.rs:99` |

## 3. Goals and non-goals

Goals:
- Every recoverable authority denial carries a kernel-signed class that names the resolving authority class and discloses nothing beyond today's structured error report.
- The planner can answer a capability fact with an `Authority` remedy whose new authority is a subset of what the resolver holds, drives exactly one continuation, and dies with the denied capability.
- One remedy path: every resolution flows through recovery workflows, `ActionIntentV1`, grant v2, `reserve_recovery_call` and capture.

Non-goals:
- Kernel-minted, renewed or standing authority (open decision 2).
- Guard-driven faults. Guard reasons are policy and stay plain denies.
- Resource and prompt scope faults in v1.
- Wiring the single-approver `ApprovalGuard` (umbrella D7).
- A new `Verdict` variant or A2A task state.
- Cross-owner liveness push (`2026-10-04-unified-event-queue-design.md`).
- Relaxing recovery's single-capability invariant.

## 4. Fault taxonomy

| Existing error | Fault class | Resolution |
|---|---|---|
| `OutOfScope { tool, server }` | `InsufficientScope` | `Authority` remedy |
| `CapabilityExpired` | `CapabilityExpired` | `Authority` remedy |
| `BudgetExhausted(_)` (grant, aggregate family, monetary, D1 allocation) | `BudgetExhausted` | `Authority` remedy |
| threshold or cumulative approval (`PendingApproval`) | `ApprovalRequired` | existing native resume (REC-15) |
| absent required single approval (new typed `KernelError::GovernedApprovalRequired`, replacing M: `governed_validation.rs:489`, `:494`) | `ApprovalRequired` | AP2/AP3 exact approval, then a fresh request |

**Never resolvable** (plain deny, no block):
- `CapabilityRevoked`, `DelegationChainRevoked`, `InvalidSignature`, `UntrustedIssuer`, `SubjectMismatch`, `DelegationInvalid`, `CapabilityNotYetValid`, `CapturedBudgetReplay`, `DpopVerificationFailed`, `GuardDenied`;
- every other `GovernedTransactionDenied`;
- infrastructure errors;
- any denial of a request whose capability carries `RecoveryContinuationBinding`, or that was issued by an `AuthorityContinuation` workflow.

**Classification rules:**

1. **R1. Exhaustive.** `classify_authority_fault(&KernelError, &FaultContext) -> Option<AuthorityFaultClass>` is pure and exhaustive, with no wildcard arm returning `Some`.
2. **R2. Scope.** `InsufficientScope` is emitted only when the signature, time, revocation, delegation and subject checks passed (M: `async_evaluation_core.rs:223-267`).
3. **R3. Expiry.** `CapabilityExpired` is detected before revocation (`:239` precedes `:251`). On the fault path the kernel MUST also run the revocation, delegation and subject checks against the expired token; any failure yields a plain deny with that error.
4. **R4. Budget.** `BudgetExhausted` is emitted only when it is the final selected error, no candidate grant recorded a guard or governed denial, and no runtime reservation was retained. This closes the precedence at `:716`.
5. **R5. No fault on a fault.** A request carrying `RecoveryContinuationBinding`, a D1 permit for a recovery continuation, or a capability issued for an `AuthorityContinuation` workflow never yields a fault.
6. **R6. Active defense.** With active-defense authorities installed, a plain deny results if:
   - the faulted capability id is suspended;
   - an issuance freeze covers its tenant and lineage; or
   - either authority is unavailable.

   The response is indistinguishable from any other non-classified deny.
7. **R7. Caller-executed start.** Denials at the authenticated start of a caller-executed tool never classify (M: `2026-09-07-caller-dispatch-commitment-design.md`).

## 5. Fault block, planner fact, and anti-oracle rules

The block is written into the metadata of the signed deny receipt, which is already persisted (pattern at M: `pending_responses.rs:38`). The decision stays `Deny`, or `PendingApproval` for the parked class.

```rust
// crates/core/chio-core-types/src/capability/authority_fault.rs (no_std + alloc)
pub const AUTHORITY_FAULT_SCHEMA: &str = "chio.authority-fault.v2";

pub enum AuthorityFaultClass { InsufficientScope, CapabilityExpired, BudgetExhausted, ApprovalRequired }

pub enum ResolverClass {
    ReceiverIssuer,      // capability authority or treaty issuer of the receiving kernel
    Delegator,           // last delegator in the denied capability's chain (single owner)
    AllocationHolder,    // D1 holder of the denied leaf's parent slot
    Payer,               // F1 payer of the funded agreement
    Approver,            // AP2/AP3 roster or threshold collector
}

#[serde(deny_unknown_fields)]
pub struct AuthorityFaultV2 {
    pub schema: String,
    pub class: AuthorityFaultClass,
    pub resolver_classes: Vec<ResolverClass>, // closed, ordered, at most 2
    pub request_id: String,
    pub capability_id: String,
    pub subject: PublicKey,
    pub server_id: String,
    pub tool_name: String,
    pub parameter_hash: String,                        // equals the receipt's action.parameter_hash
    pub principal_path: Vec<DelegationPrincipalHop>,   // delegator/delegatee keys, root first
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_binding_digest: Option<String>,
}
```

**Planner fact.**
- When a recovery deployment covers the denied request's scope, the kernel also exposes the class through the recovery observation as the existing `ExplanationFactKind::Capability`, with value `false`. The fact gains an optional typed annotation `{ class, resolver_classes }` carrying the same values as the block.
- The fact is derived from native flow state, not from the receipt, which keeps W:'s rule that facts never come from receipt verdicts.
- The planner never reads the receipt.

**Anti-oracle rules for the block:**
1. **A1. Caller-held fields only.** Every field is supplied by the caller, held by the caller (its own capability, subject and chain principals), or an opaque digest of the caller's own security selection. The block never contains a policy id, guard name, grant index, remaining balance, family or sibling usage, required scope, or resolver availability.
2. **A2. Exhaustion sources collapse.** Grant, aggregate family, monetary and D1 allocation exhaustion all collapse into `BudgetExhausted`. `resolver_classes` may still distinguish `AllocationHolder` from `Payer`, because the caller holds its D1 permit and F1 agreement.
3. **A3. No new policy fact.** Relative to `KernelError::report` (M: `error.rs:416`), the block discloses no new policy fact.
4. **A4. Explanations follow P2.** Explanations of an `Authority` remedy follow W: P2's explanation rules, which are stricter than A1-A3:
   - inaccessible candidates are filtered before search or ranking;
   - public views carry random, recipient-bound references;
   - search has a fixed work ceiling;
   - probes are limited (W: `implementation/p2/OPERATIONS.md:73-77`, `:107-110`).

   An `Authority` candidate exposes only its resolver class and bounds, never the policy that produced the denial.
5. **A5. Configuration-blind emission.** Whether a block is emitted must not depend on resolver configuration, online status or history.

## 6. Resolution through the recovery lane

### 6.1 Resolver by authority class

| Fault class | Profile | Resolver | New authority |
|---|---|---|---|
| `InsufficientScope`, `CapabilityExpired` | single owner, delegated chain | `Delegator` | a signed delegation from the last delegator, a subset of its own grant |
| `InsufficientScope`, `CapabilityExpired` | receiver-issued (including cross-owner work) | `ReceiverIssuer` | a kernel-mediated issuance by an active issuer head |
| `BudgetExhausted` | D1 delegated work | `AllocationHolder` | subdivision of the parent slot's unused remainder into a new leaf, then a new offer, a new receiver capability and a new seal (V: `dynamic-delegation-design.md:40-41`, `:55`, `:77`) |
| `BudgetExhausted` | F1 funded work | `Payer` | a new agreement and deposit; F1 terms are immutable, so this is never a top-up |
| `BudgetExhausted` | single owner, no D1 | `Delegator`, else `ReceiverIssuer` | a delegation or issuance with a fresh `max_invocations` budget |
| `ApprovalRequired` | any | `Approver` | existing native resume, or an AP2/AP3 exact approval |

A resolver may only grant authority it holds. If it lacks that authority, it escalates to its own resolver outside the kernel. Depth is bounded by `validate_delegation_chain(.., max_depth)` (M: `crates/core/chio-core-types/src/capability/attenuation.rs:224`).

**Resolvers never drive recovery commands themselves.** Recovery control refuses delegated tokens (W: `chio-kernel/src/recovery/ports.rs:209-212`).
- A `Delegator`, `AllocationHolder` or `Payer` produces its artifact out of band: a signed delegation, a D1 subdivision and seal, or an F1 agreement.
- An operator-assigned recovery actor holding `Create`, `Select`, `Approve` and `Resume` drives the linked workflow.
- This keeps control-plane authority non-delegable, as W: intends.

### 6.2 The `Authority` remedy kind and the linked workflow

**Planner** (`chio-security-types` and `chio-recovery`):
1. `ExplanationRemedyKind` gains `Authority`, and `ExplanationAssessmentV1` gains `RequiresAuthority`.
2. In `evaluation.rs`, the capability short-circuit (W: `chio-recovery/src/evaluation.rs:204-206`) changes from "any unsatisfied capability fact means `BlockedByCapability`" to the rule below. Every other path is unchanged.

```text
capability_unsatisfied ->
  if exists registered Authority template t
       with t.addresses(fact.class) and t.resolver in fact.resolver_classes
       and t is accessible to the audience (P2 filtering)
    then RequiresAuthority(t)
    else BlockedByCapability
```

3. Only `Authority` templates may address a `Capability` fact. No other kind may clear or bypass one.

**Template.**
- `RecoveryTemplateV1` gains `AuthorityContinuation`.
- A workflow of that template is created with `CreateWorkflow { template: AuthorityContinuation, request_seed, .. }`, where the seed is a `ToolCallRequest` carrying the new capability.
- Its record also carries `predecessor_workflow: WorkflowId` and `predecessor_fault: AuthorityFaultClass`. Host setup writes both from the predecessor's observation, and the incoming command cannot choose either.

**Store validation at creation**, in addition to W:'s existing `validate_seed` rules:
1. The predecessor exists in the same `authority_domain` and tenant. Its observation recorded the matching unsatisfied `Capability` fact, and it has no successor yet: one successor per predecessor, enforced by a unique index.
2. The new seed's `server_id`, `tool_name` and canonical argument hash equal the predecessor seed's, which also equal the fault's `parameter_hash`. The subject is unchanged.
3. The new seed's capability passes section 6.3 steps 1, 2 and 4.

**Execution.** After creation, the workflow is an ordinary recovery workflow:
- the store pin (`issuance.rs:76-81`) binds every action to the new capability;
- `ActionIntentV1`, `OfferDigest`, the approval intent and grant v2 work unchanged;
- `reserve_recovery_call` reserves one slot;
- capture runs the native participants plus section 6.3.

Any information-flow obligations the continuation needs are approved as today.

**Authority evidence stays in the prerequisite step.**
- The resolver's artifact (delegation, issuance record, D1 seal, or F1 agreement and observed deposit) is verified as `HistoricalFact` prerequisite evidence of the linked workflow (W: P3 prerequisite classes).
- It does not become a new `AuthorityObligationV1` variant. Obligations stay information-flow powers, and issuers stay separate from approvers (M: issuer-lifecycle design `:11-12`). See open decision 3.

**Binding the new authority to exactly one continuation:**
- **D1 installed.** The sealed permit already binds the exact capability, request id and arguments (V: `dynamic-delegation-design.md:116-121`).
- **D1 not installed.** The new capability's single grant carries `max_invocations == Some(1)` and `Constraint::RecoveryContinuationBinding { request_namespace_digest, request_id, action_intent_digest }`, set to the linked workflow's predicted continuation identity.
  - The constraint is preserved by equality under delegation, like `OutputDigestSha256` (M: `scope.rs:591`).
  - Its enforcer is the recovery capture participant. That is the KG4 decision at M: `authority.rs:102`.
  - Ordinary admission of a capability carrying it denies unless the request is the bound continuation.
  - The portable core fails closed on it (M: `crates/kernel/chio-kernel-core/src/evaluate.rs:129-130`).

  Implemented recovery binds the continuation only through `ActionIntentV1.semantic_request`, the finalized request envelope and grant v2. None of these constrains the capability itself, so without this constraint the new capability could be presented on an ordinary path (N8).

### 6.3 Capture-time checks for linked workflows

These run in the recovery capture participant for `AuthorityContinuation` workflows only. They are in addition to W:'s own revalidation, which already rechecks fresh revocation of the workflow's seed capability (W: `implementation/p1/OPERATIONS.md:119-120`).

1. **Shape.** Exactly one grant whose server and tool equal the predecessor's. When D1 is not installed, `max_invocations == Some(1)`. The capability expires no later than the workflow's approval deadline.
2. **Subset.**
   - For `Delegator`, chain validation proves the new authority is a subset of the delegator's grant (M: `attenuation.rs:224`).
   - For `ReceiverIssuer`, the issuing key was an active head at issuance (M: issuer-lifecycle design `:11-12`).
3. **Binding.** The continuation's subject equals the fault's subject, and its canonical argument hash equals the fault's `parameter_hash`. When the fault carries `security_binding_digest`, the current trusted selection produces the same digest.

   3a. **Sibling (predecessor) revocation.** Deny if the predecessor seed's `capability_id` is revoked, or if any capability id in that capability's own delegation chain is revoked. Use the same revocation snapshot as the rest of capture.
   - **Why it is needed.** The new capability is a sibling of the denied one, issued by the resolver, not a descendant. W:'s fresh revocation predicate covers the linked workflow's own seed capability, not the predecessor's.
   - **What it prevents.** Without this step, closing the denied capability (`2026-10-04-authority-space-teardown-design.md`, `CapabilitySubtree`) would not reach an outstanding remedy.
   - **Scope.** This is not a defect of implemented recovery, which reuses the seed capability. It arises only from this kind. A remedy never outlives the authority whose denial it answers.
4. **Active defense.**
   - Deny if the predecessor seed's `capability_id` is in an active suspended set. A fresh capability id would otherwise escape suspension (M: `capability_set_suspension.rs:41-60`).
   - For `Delegator` remedies, also call the issuance-freeze authority with `CapabilityIssuanceOperation::Delegate`, using the delegation's parent capability and the trusted tenant and lineage. This is the only place an agent-signed delegation meets a freeze (umbrella D5).
   - If either authority is unavailable, deny.
   - Implemented recovery consults neither authority directly, which is why this step is needed for the new kind.
5. **Cancellation.**
   - A `CancelWorkflow` on the predecessor, recorded before the successor's capture, denies capture. The tombstone shares the serving writer (W: `.../recovery/native.rs:286-293`).
   - Revocation of the predecessor capability is covered by 3a.
   - Doc-only "emergency revocation invalidates pending approvals" (R: `08-protocol-operations.md:57`) is not relied on.

Each failure is a plain deny with stable code `CHIO-KERNEL-AUTHORITY-REMEDY-REJECTED` and sub-reason `shape`, `subset`, `binding_mismatch`, `revoked`, `suspended`, `frozen`, `cancelled` or `unavailable`. It never produces a new fault (R5).

### 6.4 Single use

Single use comes from the implemented machinery:
- one successor per predecessor (unique index);
- one selected continuation per workflow;
- `reserve_recovery_call` and `finalize_recovery_call` consume the process slot exactly once (W: `chio-process/src/recovery.rs:83`, `:110`).

In addition, the new capability allows at most one invocation, through `max_invocations` or the D1 permit. No fault-resolution replay participant is added. `2026-10-04-typed-reservations-design.md` treats `reserve_recovery_call` and D1 seals as consumption commitments with no compensator.

### 6.5 Fresh continuation, not a resumed operation

A resolution never resumes the denied request:
- Scope and expiry denials happen before durable admission (M: `async_evaluation_core.rs:279` precedes `:356`).
- A budget denial compensates the operation and leaves a terminal replay tombstone.

The linked workflow is W:'s and V:'s rule made concrete:
- a changed capability requires a new reviewed intent and continuation (R: `03-recovery-protocol.md:35`);
- the work layer requires a recovery-approved new continuation that never mutates the original sealed selection (V: `work-owner-services-design.md:69`).

### 6.6 The approval-required class

- **Parked threshold path.** Unchanged. It resumes through its native protocol (REC-15). `pending_responses.rs` also writes the block with `class = ApprovalRequired` and `resolver_classes = [Approver]`.
- **Absent single token.** It becomes the typed `KernelError::GovernedApprovalRequired`. The resolution is an AP2/AP3 exact approval over a `BoundToolInvocation` (M: `threshold-approval-collection.md:338-341`) for a fresh request. It does not need a capability-fact remedy.

### 6.7 Process workers (host-side resolution)

`chio.process.v1` carries no capability, approval token or capability replacement (M: `WORKER_PROTOCOL.md:59-62`, `:71`), and a process's capability is immutable. Recovery control is host-only (W: no recovery ops in the worker protocol).

- **Visibility.** The worker sees the fault only in the receipt returned by `invoke` (M: `WORKER_PROTOCOL.md:53`). It cannot resolve it.
- **Who acts.** An operator-assigned recovery actor follows the classification. The worker cannot issue `ReportDecision` without a host-held control token.
- **New authority means a new process.** For `Delegator`, the parent process spawns a sibling of the faulted process carrying the delegated subset, under the single-hop rule (M: `chio-process/README.md:30`).
- **Sibling deployment.** A recovery scope includes `process_id` (W: `chio-security-types/src/recovery/observation.rs:10`), and `reserve_recovery_call` binds the process's own capability digest. So the sibling needs its own recovery deployment, installed by host setup, before the linked workflow can run there.
- **Fresh identity.** A fresh operation key and tree slot are always used. The faulted process keeps its history.

### 6.8 Cross-kernel and cross-owner

- Recovery records live in the refusing receiver's serving authority, so an `Authority` remedy is presented only to that receiver.
- Rerouting to another receiver is D1 reselection before sealing, or a new child slot after sealing, never a remedy.
- Single-use state stays in the receiver's serving authority. Authority replication covers issuer sets only (M: `2026-10-02-authority-replication-design.md`).
- Independent multi-owner operation is not established, so the cross-owner rows in section 6.1 are design-only.

### 6.9 Dependency on recovery generalization

Implemented recovery is a narrow profile:
- one template, `SupportTicketPublicIssue`;
- deployments covering one process scope with one server, tool, recipient and purpose (W: `chio-kernel/src/recovery/records.rs:104-123`).

`Authority` remedies need two things it lacks:
- the `AuthorityContinuation` template;
- deployments whose server and tool match the faulted call, including sibling-process scopes.

That generalization belongs to recovery P6 or later. This spec's Phase 1 is gated on it (section 9).

## 7. Failure modes and fail-closed behavior

| Failure | Outcome |
|---|---|
| Classifier sees an unknown error | plain deny |
| Expired token fails revocation, delegation or subject on the fault path | plain deny with that error |
| Budget denial with a sibling guard denial or a retained reservation | plain deny |
| Suspended, frozen, or active-defense authority unavailable at classification | plain deny, no block |
| No recovery authority installed (`AdmissionOperationStore::recovery_authority()` is `None`), no deployment for the scope, or no registered `Authority` template | block written; planner returns `BlockedByCapability`; plain deny semantics |
| Linked-workflow creation with a mismatched predecessor, a second successor, or a changed tool or arguments | `CreateWorkflow` refused |
| New authority wrong shape, not a subset, or from a non-active issuer key | `CHIO-KERNEL-AUTHORITY-REMEDY-REJECTED` (`shape`, `subset`) |
| Predecessor capability or its chain revoked, suspended, frozen, or predecessor cancelled at capture | `...-REJECTED` (`revoked`, `suspended`, `frozen`, `cancelled`) |
| `RecoveryContinuationBinding` presented outside its bound continuation | deny at admission |
| Capture uncertain | recovery reconciliation; never a fresh identity (REC-11) |
| Portable core receives the constraint | `ConstraintError` deny |

## 8. Protocol, schema and wire impact

- `spec/PROTOCOL.md`:
  - **Section 5:** add the `recovery_continuation_binding` constraint (shape, equality preservation, enforcer) and the `GovernedApprovalRequired` classification.
  - **Section 6:** define the `authority_fault` v2 block.
  - **Section 8:** state that recoverable authority denials carry the block.
- **Recovery generated schemas** (W: closed, generated vocabulary; R: `11-contract-catalog.md`):
  - `ExplanationRemedyKind::Authority`;
  - `ExplanationAssessmentV1::RequiresAuthority`;
  - `RecoveryTemplateV1::AuthorityContinuation`;
  - the `predecessor_workflow` and `predecessor_fault` record fields;
  - the optional annotation on the `Capability` fact.

  Each needs negative vectors. Closed enums mean old readers refuse new values rather than misreading them.
- **MCP.** The tool error result carries `_meta["chio/authorityFault"]`. No new JSON-RPC code.
- **A2A.** No change: `PendingApproval` already maps to `Working` (M: `conversion.rs:99`), and delegation-mode denials stay `Failed`.
- **Negotiation.**
  - Add an `authority_fault_classification` feature. Without it, the kernel neither emits the block nor accepts the constraint.
  - The recovery deployment binds the `AuthorityContinuation` template through host setup, so it cannot be enabled by an incoming command.

## 9. Rollout

1. **Phase 0.** Classifier, typed `GovernedApprovalRequired` and the receipt block, in shadow (metrics only). No recovery dependency.
2. **Phase 1** (gated on recovery generalization, section 6.9):
   - the `Authority` kind, `RequiresAuthority` and `AuthorityContinuation`;
   - predecessor validation;
   - capture checks including 3a and the freeze `Delegate` call;
   - `RecoveryContinuationBinding` with its KG4 enforcer.

   It ships first for `ReceiverIssuer` and `Delegator`.
3. **Phase 2.** `AllocationHolder` (D1) and `Payer` (F1) templates, gated on the W1/W2 work profile.
4. **Phase 3.** MCP `_meta` surfacing, and SDK resolver helpers that verify the deny receipt and mint a narrow delegation or D1 subdivision.

## 10. Tests and conformance evidence

- **Unit:**
  - classifier exhaustiveness;
  - every never-resolvable variant yields `None`;
  - expired plus revoked yields a plain deny;
  - budget plus a sibling guard denial yields a plain deny;
  - an R5 request yields no block.
- **Planner (pure, `chio-recovery`):**
  - a `Capability` fact without an `Authority` template still yields `BlockedByCapability`;
  - with an accessible template it yields `RequiresAuthority`;
  - with an inaccessible template the public result is identical to having no template (P2 filtering);
  - no non-`Authority` kind ever addresses a `Capability` fact.
- **Store:**
  - predecessor mismatch, second successor, and changed tool or arguments are refused;
  - the seed pin (`issuance.rs:76-81`) still holds for the linked workflow.
- **Proptest.** For random chains and resolver scopes, a linked workflow accepted at capture:
  - is a subset of the resolver's grant;
  - authorizes one invocation of the faulted tool with the faulted arguments;
  - is refused after revocation of the predecessor capability or any ancestor in its chain (3a).
- **Recovery cutpoints.** Extend W:'s recovery contract and crash suites with an `AuthorityContinuation` workflow (reserve, approve, finalize, restart; basis change between review and capture). Add `denied_capability_revoked_before_capture` (3a) and `predecessor_cancelled_before_capture`.
- **Adversarial suite**, `crates/core/chio-adversarial-suite/cases/authority_remedy/`:
  - scope widening;
  - constraint stripping on re-delegation;
  - principal-path substitution;
  - argument mutation;
  - cross-subject reuse;
  - a `RecoveryContinuationBinding` capability used outside its continuation;
  - a delegator remedy minted during a freeze;
  - a suspended predecessor;
  - a delegated token attempting recovery control.
- **Anti-oracle.**
  - The block's field set equals the caller-held set (A1).
  - Blocks and explanation projections are identical with and without resolvers configured (A5).
- **Process.** A host-side sibling-spawn resolution end to end, with a sibling deployment. The worker cannot drive recovery. The faulted process's history is unchanged.
- **Fuzz.** An `authority_fault_v2` decode target.

## 11. Residual risks and open decisions

Residual risks:
- Paging pressure moves to recovery intake quotas (64 workflows per tenant; W: `implementation/p1/OPERATIONS.md:131-135`). Resolvers still need their own limits.
- A deny receipt forwarded to a resolver discloses the call's parameters, redacted per receipt mode.
- A delegator remedy minted during a freeze and presented after it lifts is accepted. Every agent-signed delegation has the same gap (umbrella D5).
- W: is uncommitted and built on an older #1160 checkpoint. Recovery type names and line references must be re-pinned when it merges.
- Recovery docs name features W: does not implement: a signed `RemedyOfferV1`, a `recovery_deliveries` outbox, an `ExplainIntent` command, and approval-invalidating emergency revocation. Nothing here depends on them.

Open decisions:
1. **Keep `RecoveryContinuationBinding`.**
   - The directive was to drop it, and this spec pushes back.
   - Recovery binds a continuation's exact intent, but no implemented mechanism stops the new capability from being presented on an ordinary path. Grant v2 is disclosure-only (W: `chio-security-types/src/recovery/authorization.rs:94`), and no `Constraint` binds exact arguments (M: `scope.rs:331`).
   - The alternative is a registry of remedy capability ids consulted at every admission path.
   - Recommendation: keep the constraint. It is self-describing and works offline for delegators.
2. **Standing resolutions.** Should a delegator or D1 holder pre-sign bounded top-ups that the recovery driver selects without a human? This is the analog of FTL's in-kernel lazy paging. Deferred, because it is equivalent to delegating more up front.
3. **Where authority evidence lives.**
   - This spec keeps authority evidence in the prerequisite step and leaves `AuthorityObligationV1` information-flow only.
   - The alternative is a `CapabilityIssuance { issuer }` obligation with a `RecoveryCoverageAssignment`, making the issuer an approver.
   - Recommendation: prerequisite evidence. It keeps issuers and approvers separate, per M:'s issuer-lifecycle rule.
4. **Linked workflow versus relaxing the seed pin.** This spec chooses linked workflows. Relaxing `issuance.rs:76-81` to allow a capability swap would touch every recovery invariant that assumes one capability per workflow. Rejected unless the linked-workflow cost (an extra deployment per sibling scope) proves prohibitive.
5. **Historical freeze windows.** Deny remedies whose issuance falls inside a recorded freeze window. This needs historical freeze queries from active defense.
6. **Resources and prompts.** Make `OutOfScopeResource` and `OutOfScopePrompt` classifiable in v2.

## Appendix A. FTL reference

FTL (`/Users/connor/Medica/backbay/ftl`) handles faults in two tiers:
- **Kernel tier.** `handle_user_page_fault` (`kernel/src/arch/x64/idt.rs:357`, called at `:487`) maps a page lazily when a mapping already authorizes the access (`kernel/src/vmspace.rs:219`). It returns `BadAccess` when the mapping exists but the access is not permitted (`vmspace.rs:230`).
- **Upcall tier.** Otherwise, `raise_user_fault` (`idt.rs:473`) writes a `FaultFrame` (`libs/ftl_types/src/thread.rs:68`) and redirects the thread to its `fault_pc` (`idt.rs:444`).
- **Fail closed.** If writing the frame fails, the thread exits (`idt.rs:483`). LX's handler currently never resolves a fault and exits the process (`lx/src/fault.rs:32`, `:43-44`).

Mapping:
- FTL's kernel tier corresponds to Chio's sibling-grant selection and root-first lineage restoration.
- W:'s `BlockedByCapability` is FTL's `BadAccess` delivered as a terminal user fault. The `Authority` kind adds the upcall tier for exactly that class: the planner pages a resolving authority instead of ending.
- "No handler means death" maps to "no `Authority` template means `BlockedByCapability` stands".

Where the analogy breaks:
1. **Who resolves.** An FTL handler runs in the faulting domain with authority it already holds. A Chio resolver is a different principal that adds authority, which is why the linked workflow and section 6.3 exist.
2. **Resuming.** FTL resumes the same instruction. Chio binds a fresh continuation in a linked workflow.
3. **Who mints.** FTL's kernel allocates memory it owns. Chio's kernel owns no authority (open decision 2).
