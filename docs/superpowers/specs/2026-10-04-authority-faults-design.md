# Design: authority fault classification for the recovery lane

- Status: PROPOSED (revision 5, 2026-10-05, after independent review pass 5 (R-2-02); revision 4 after PR #1174 review round 1; revision 3 re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:))
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

## Revision 5 changes

From the fifth independent review (R-2-02), checked against current W: origin ownership:
- **Successors join W:'s exclusive origin owner.** Current W: resolves every workflow's seed to one verified original native operation, verifies the original process request, and gives that original one durable owner (W: `chio-store-sqlite/src/admission_operation_store/recovery/origins.rs:61-164`; `commands.rs:87-94`, `:150`). A changed-capability or sibling-process successor cannot pass those checks with its own seed, and copying the origin collides with the predecessor's claim. New section 6.10 extends the existing origin claim with one bounded successor chain (O1-O8) instead of the revision 4 partial unique index and `successor_captures` row. The original request and its native and process evidence stay with the predecessor and are revalidated at every recheck point. Exactly one continuation per original may capture.
- **Denials with no native row get no remedy yet.** Scope and expiry denials are selected before durable admission, so they leave nothing for the origin owner to verify. They keep `BlockedByCapability` until a retained-denial profile exists in the native admission owner (O8, open decision 8). Phase 1 resolves only denials with a verified native origin.

## Revision 4 changes

From round 1 of the PR #1174 review (dispositions at the end of this spec):
- **R6 no longer gates emission.** Active-defense lookups never run on the classification path. Whether a block is emitted no longer depends on whether the suspension or issuance-freeze authority is installed or online, which A5 requires. The fail-closed checks stay where authority would be granted: linked-workflow creation and capture (section 6.3 step 4).
- **Integrity faults get their own block (round 2).** The classifier output is tagged as `FaultKind::Authority(class)` or `FaultKind::Integrity`. Spec 11's `InsufficientIntegrity` emits its own `IntegrityFaultV1` block and projects to `ExplanationFactKind::Integrity`. `AuthorityFaultClass` stays closed at four, and `AuthorityFaultV2` is unchanged (R1, section 5).
- **A dead successor can be replaced.** Uniqueness now covers the *open* successor and the one successor that *captures*. A successor cancelled without capture frees the slot, up to a bound (sections 6.2 and 6.4).

- **The continuation binding is non-recursive (independent review R-2-01).** Revision 3 put `action_intent_digest` in the new capability's constraint. `ActionIntentV1` hashes the capability's signing body (W: `chio-security-types/src/recovery/authorization.rs:69-90`; `issuance.rs:76-83`), and that body includes the constraint (W: `chio-core-types/src/capability/token.rs:219-242`), so no valid capability could exist. The constraint now names identities fixed before the capability is built: a successor continuation derived from the predecessor workflow and a successor ordinal, the request namespace, the request id and the argument digest. `ActionIntentV1` is then derived from the completed capability, unchanged (section 6.2, "Continuation identity").

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
3. **A linked recovery workflow.** The resolver's new authority becomes the seed capability of a new workflow (`RecoveryTemplateV1::AuthorityContinuation`) whose record names the predecessor workflow. The single-capability pin, `reserve_recovery_call` and capture then apply unchanged. Origin ownership does not: the existing origin owner gains one bounded successor chain on the original's claim, so the original stays verified and exactly one continuation per original can capture (section 6.10).
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
| Every workflow has one verified original and one owner. Creation resolves the seed's request id to a retained `ToolDispatch` in `CompensatedBeforeDispatch` with no dispatch commitment, canonically equal retained request material, and the deployment's native security context and authority; it then verifies the unchanged first-attempt process request through `RecoveryProcessOriginPort`. The claim is keyed by the original operation across every tenant and process scope, and only an identical `(scope, workflow_id, continuation_id, origin)` claim is accepted. Issuance and fresh-basis validation re-verify it, and issuance requires `action.origin == record.origin` | W: `.../recovery/origins.rs:14-24`, `:61-92`, `:94-129`, `:131-164`; `commands.rs:87-94`, `:150`; `issuance.rs:37-40`; `validation.rs:293`; W: `chio-kernel/src/recovery/ports.rs:52-62`; W: `chio-kernel/src/admission_operation/retained_request.rs:379-393` |
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
| `OutOfScope { tool, server }` | `InsufficientScope` | `Authority` remedy, once a verifiable native origin exists (section 6.10 O8) |
| `CapabilityExpired` | `CapabilityExpired` | `Authority` remedy, once a verifiable native origin exists (section 6.10 O8) |
| `BudgetExhausted(_)` (grant, aggregate family, monetary, D1 allocation) | `BudgetExhausted` | `Authority` remedy when the denial compensated a begun operation (section 6.10 O8) |
| threshold or cumulative approval (`PendingApproval`) | `ApprovalRequired` | existing native resume (REC-15) |
| absent required single approval (new typed `KernelError::GovernedApprovalRequired`, replacing M: `governed_validation.rs:489`, `:494`) | `ApprovalRequired` | AP2/AP3 exact approval, then a fresh request |
| `InsufficientIntegrity { surface }` (new typed error from spec 11's `IntegrityGuard` and crossing check 4) | none: the sibling kind `FaultKind::Integrity`, with its own block (`2026-10-04-integrity-gated-admission-design.md` I18-I20) | exact integrity endorsement, or a quarantined continuation (spec 11 I21-I22) |

**Never resolvable** (plain deny, no block):
- `CapabilityRevoked`, `DelegationChainRevoked`, `InvalidSignature`, `UntrustedIssuer`, `SubjectMismatch`, `DelegationInvalid`, `CapabilityNotYetValid`, `CapturedBudgetReplay`, `DpopVerificationFailed`, `GuardDenied`;
- every other `GovernedTransactionDenied`;
- infrastructure errors;
- any denial of a request whose capability carries `RecoveryContinuationBinding`, or that was issued by an `AuthorityContinuation` workflow.

**Classification rules:**

1. **R1. Exhaustive and tagged.** `classify_fault(&KernelError, &FaultContext) -> Option<FaultKind>` is pure and exhaustive, with no wildcard arm returning `Some`. `FaultKind` is closed:

   ```rust
   pub enum FaultKind {
       Authority(AuthorityFaultClass), // emits the authority_fault block (AuthorityFaultV2, section 5)
       Integrity,                      // emits the integrity_fault block (IntegrityFaultV1, spec 11 I19)
   }
   ```

   `AuthorityFaultClass` stays closed at four variants, and the `Integrity` kind is never one of them.
2. **R2. Scope.** `InsufficientScope` is emitted only when the signature, time, revocation, delegation and subject checks passed (M: `async_evaluation_core.rs:223-267`).
3. **R3. Expiry.** `CapabilityExpired` is detected before revocation (`:239` precedes `:251`). On the fault path the kernel MUST also run the revocation, delegation and subject checks against the expired token; any failure yields a plain deny with that error.
4. **R4. Budget.** `BudgetExhausted` is emitted only when it is the final selected error, no candidate grant recorded a guard or governed denial, and no runtime reservation was retained. This closes the precedence at `:716`.
5. **R5. No fault on a fault.** A request carrying `RecoveryContinuationBinding`, a D1 permit for a recovery continuation, or a capability issued for an `AuthorityContinuation` workflow never yields a fault. A request that presents an integrity endorsement never yields `FaultKind::Integrity` (spec 11 I18).
6. **R6. Active defense acts at resolution, never at emission.** Classification never consults the suspension or issuance-freeze authority. For a given selected error, whether a block is emitted is the same whether those authorities are absent, installed, online, unavailable or holding history (A5).
   - **Fail closed where authority is granted.** Active defense is enforced at the two points where new authority could take effect:
     - linked-workflow creation (section 6.2, store validation step 3, which runs section 6.3 step 4);
     - capture (section 6.3 step 4).

     Both refuse when the predecessor capability is suspended, a freeze covers its tenant and lineage, or either authority is unavailable. A successor capability is also ordinary issuance, so it meets the issuance freeze when it is minted.
   - **A block is an offer, not a promise.** A refusal by active defense is disclosed only to the authenticated recovery actor, as `CHIO-KERNEL-AUTHORITY-REMEDY-REJECTED` with sub-reason `suspended`, `frozen` or `unavailable`. It is never disclosed to the caller through block presence.
   - **The kernel's own denials are unchanged.** If evaluation itself denies the call because of a suspension or an unavailable authority, the selected error is that denial. It is in the never-resolvable list, so it yields no block. The caller already sees that outcome through `KernelError::report` (A3), so R6 adds no new signal.
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

**Fault kinds and blocks.** The classifier output is tagged (R1), and each kind has its own block and schema:
- `FaultKind::Authority(class)` emits the `authority_fault` block (`AuthorityFaultV2` above).
- `FaultKind::Integrity` emits the `integrity_fault` block: `IntegrityFaultV1`, schema `chio.integrity-fault.v1`, defined in spec 11 I19. It carries only the request id, the caller's own integrity requirement, the surface (`guard` or `crossing`) and remedy classes. Those remedy classes are a function of that requirement, never of deployment configuration.
- No integrity denial fills `AuthorityFaultV2`'s capability, subject, tool, parameter or principal-path fields, and no authority denial carries integrity fields.
- A deny receipt carries at most one fault block.

**Planner fact.**
- When a recovery deployment covers the denied request's scope, the kernel also exposes the class through the recovery observation as the existing `ExplanationFactKind::Capability`, with value `false`. The fact gains an optional typed annotation `{ class, resolver_classes, security_binding_digest?, origin_retained }` carrying the same values as the block. `security_binding_digest` is the opaque digest of the trusted selection, computed by the native evaluation that produced the denial and recorded in native flow state, so the planner never needs the receipt for it. `origin_retained` is true only when the denial left a native operation that `origins::resolve` can verify (section 6.10 O8). It is a planner input, never a block field, so A5 is unaffected.
- The fact is derived from native flow state, not from the receipt, which keeps W:'s rule that facts never come from receipt verdicts.
- The planner never reads the receipt.
- `FaultKind::Integrity` projects to the new `ExplanationFactKind::Integrity`, with value `false` (spec 11 I20). Only spec 11 I20's two remedy paths may address it. The `Authority` remedy kind never addresses an `Integrity` fact, and no integrity remedy addresses a `Capability` fact.

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
6. **A6. Both kinds.** A1-A5 apply to both blocks. For the integrity block, A1's caller-held set is spec 11 I19's field set, and its `remedy_classes` must not reveal which remedies a deployment has configured (A5).

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
       and fact.origin_retained                                  (section 6.10 O8)
       and t is accessible to the audience (P2 filtering)
    then RequiresAuthority(t)
    else BlockedByCapability
```

3. Only `Authority` templates may address a `Capability` fact. No other kind may clear or bypass one.

**Template.**
- `RecoveryTemplateV1` gains `AuthorityContinuation`.
- A workflow of that template is created with `CreateWorkflow { creation_key, template: AuthorityContinuation, request_seed }`, where the seed is a `ToolCallRequest` carrying the new capability. The `creation_key` is not free: it is the successor key derived from the predecessor and a successor ordinal ("Continuation identity" below).
- Its record also carries `predecessor_workflow: WorkflowId` and `predecessor_fault: AuthorityFaultClass`. Host setup writes both from the predecessor's observation, and the incoming command cannot choose either.
- Its record's `origin` is the predecessor's verified `RecoveryOriginV1`, also written by host setup. It is never resolved from the successor's own seed (section 6.10 O1).

**Store validation at creation**, in addition to W:'s existing `validate_seed` rules. W:'s `origins::resolve` and the process origin port are not run on the successor's seed; section 6.10 O6 runs them on the predecessor's original instead.
1. The predecessor exists in the same `authority_domain` and tenant. Its observation recorded the matching unsatisfied `Capability` fact, with `origin_retained` (O8). Its control is `Active` and it has not captured.
   - **One open successor.** At most one successor per predecessor is reserved or open at any time. The original's existing origin claim enforces this through its successor chain, under the claim's version check (O2, O4). There is no separate index.
   - **What retires a successor.** Its control is `Cancelled` (W: `chio-security-types/src/recovery/observation.rs:164-169`) and the store holds no capture for it. A successor whose seed capability expired during approval, or was revoked before capture, can never capture (section 6.3 steps 1 and 3a). A recovery actor cancels it, which allowed `CancelWorkflow` does. The same transaction marks its chain link `RetiredWithoutCapture`, which frees the slot for a corrected successor and keeps the link as history (O5).
   - **Bound.** A predecessor admits at most `max_successors_per_predecessor` successors in total (default 4), counting retired ones. It is the chain's length bound. The bound applies on top of recovery intake quotas.
2. The new seed's `server_id`, `tool_name` and canonical argument hash equal the predecessor seed's, which also equal the fault's `parameter_hash`. The subject is unchanged.
3. The new seed's capability passes section 6.3 steps 1, 2 and 4.
4. **Binding matches the derived identity.** The store recomputes, from the record alone, the successor creation key for `(predecessor_workflow, successor_ordinal)`, then the workflow id, continuation id and request id by W:'s existing rules, and the request namespace digest and argument digest. When D1 is not installed, it compares them field by field with the seed capability's `RecoveryContinuationBinding`. Any mismatch refuses `CreateWorkflow` with `binding_mismatch`. The ordinal must be the next unused one for the predecessor and within `max_successors_per_predecessor`. Ordinals are never reused, matching W:'s rule that closed identities are retained and never recycled (W: `commands.rs:95-97`).

**Execution.** After creation, the workflow follows the ordinary recovery path, with one exception for origin ownership:
- the store pin (`issuance.rs:76-81`) binds every action to the new capability;
- `ActionIntentV1`, `OfferDigest`, the approval intent and grant v2 work unchanged;
- every point where W: calls `origins::verify` (issuance, fresh basis, capture) calls `origins::verify_linked` for this template instead, which revalidates the predecessor's original and the successor's chain link (section 6.10 O6). Each action's `origin` still equals the record's, as `issuance.rs:38-40` requires;
- `reserve_recovery_call` reserves one slot;
- capture runs the native participants plus section 6.3, and moves the chain link to `Captured` in the same transaction (O7).

Any information-flow obligations the continuation needs are approved as today.

**Authority evidence stays in the prerequisite step.**
- The resolver's artifact (delegation, issuance record, D1 seal, or F1 agreement and observed deposit) is verified as `HistoricalFact` prerequisite evidence of the linked workflow (W: P3 prerequisite classes).
- It does not become a new `AuthorityObligationV1` variant. Obligations stay information-flow powers, and issuers stay separate from approvers (M: issuer-lifecycle design `:11-12`). See open decision 3.

**Binding the new authority to exactly one continuation:**
- **D1 installed.** The sealed permit already binds the exact capability, request id and arguments (V: `dynamic-delegation-design.md:116-121`).
- **D1 not installed.** The new capability's single grant carries `max_invocations == Some(1)` and this constraint:

  ```rust
  Constraint::RecoveryContinuationBinding {
      continuation_id: ContinuationId,               // the linked workflow's continuation
      request_namespace_digest: RequestNamespaceDigest,
      request_id: RequestId,                         // the continuation's process request id
      parameter_hash: Digest32,                      // canonical arguments; equals the fault's parameter_hash
  }
  ```

  Every field is fixed before the capability is built, and none depends on it ("Continuation identity" below). The constraint never contains an `ActionIntentV1` digest.
  - The constraint is preserved by equality under delegation, like `OutputDigestSha256` (M: `scope.rs:591`).
  - Its enforcer is the recovery capture participant. That is the KG4 decision at M: `authority.rs:102`.
  - Ordinary admission of a capability carrying it denies unless the request is the bound continuation.
  - The portable core fails closed on it (M: `crates/kernel/chio-kernel-core/src/evaluate.rs:129-130`).

  Implemented recovery binds the continuation only through `ActionIntentV1.semantic_request`, the finalized request envelope and grant v2. None of these constrains the capability itself, so without this constraint the new capability could be presented on an ordinary path (N8).

**Continuation identity (non-recursive).** This answers which identity the binding names, how it survives replay, and why it is not circular.
- **Why not the action intent.** `ActionIntentV1` carries `capability_body`, the hash of the capability's signing body (W: `chio-security-types/src/recovery/authorization.rs:69-90`), and the store checks that hash against the seed capability (W: `chio-store-sqlite/src/admission_operation_store/recovery/issuance.rs:76-83`). The signing body includes the grant scope and so the constraint (W: `chio-core-types/src/capability/token.rs:219-242`). Naming the action-intent digest inside the capability would require `x = H(ActionIntent(capability_body = H(Capability(.. x ..))))`, which has no constructible solution.
- **The identity chain.** Each value is computed from the previous ones and from deployment facts, never from the capability:
  1. `successor_creation_key = "authority-successor:" + hex(SHA-256("chio.recovery.authority-successor.v1" || predecessor_workflow || successor_ordinal))`. `predecessor_workflow` is written by host setup (above).
     - **The ordinal is stable across retries.** It is allocated once, durably, by `reserve_successor_ordinal(predecessor_workflow, resolution_attempt_id)`, which appends a `Reserved` link to the original's origin claim (section 6.10 O4). `resolution_attempt_id` is caller-held and stable across retries of one resolution, for example `H(fault receipt id, resolver principal, resolver nonce)`.
     - A repeat call with the same pair returns the ordinal it allocated before. A new attempt id first checks for the one reserved or open link of the predecessor and reuses its ordinal; it allocates the next unused ordinal only if none exists.
     - So a resolver whose `CreateWorkflow` committed but whose response was lost rebuilds the same creation key and capability binding, and the store replays the committed workflow instead of refusing a second open successor.
  2. `workflow_id = "workflow:" + sha256_hex(scope, successor_creation_key)`, W:'s existing rule (W: `recovery/commands.rs:73-77`).
  3. `continuation_id = "continuation:" + sha256_hex(scope, workflow_id)`, W:'s existing rule (`commands.rs:97-104`).
  4. `request_id = "process:" + digest(process_namespace, process_id, "recovery:" + continuation_id)`, the request id materialization already uses (W: `chio-control-plane/src/recovery/materialize.rs:28-30`, `:76-81`; `chio-process/src/lib.rs:294-305`).
  5. `request_namespace_digest = H(authenticated_tenant_id, coordinator_authority_id)` (W: `chio-kernel/src/admission_operation/identity.rs:158-178`).
  6. `parameter_hash`, the canonical argument hash of the predecessor seed, which store step 2 requires to be unchanged.
- **Construction order.** The resolver computes steps 1-6, mints and signs the capability carrying the constraint, then submits `CreateWorkflow` with `successor_creation_key`. Materialization later derives `ActionIntentV1` from the completed capability exactly as today, including `capability_body`. The dependency graph is acyclic: identity, then capability, then action intent, then offer, approval and grant v2.
- **Replay.** Steps 1-5 are deterministic, so a retried creation recomputes the same key and the same binding. W: returns the existing record for the same creation key, seed and origin, and refuses a different seed or origin as a conflict (`commands.rs:95-101`). The claim's link for the ordinal is already `Open` with the same owner, so the replay changes nothing (O4). A retried capability mint for the same ordinal yields a token with the same binding, and only one of them can become the seed. A different predecessor or ordinal yields a different continuation, which store step 4 and capture step 3 refuse.
- **Verification.** Store step 4 checks the binding against the recomputed identity at creation. Ordinary admission of a capability carrying the constraint denies unless the request's namespace digest, request id and canonical argument hash equal the bound values. Capture (section 6.3 step 3) also checks that the workflow's `continuation_id` equals the bound one. The issuance pin and the `ActionIntentV1` checks run unchanged afterwards.

### 6.3 Capture-time checks for linked workflows

These run in the recovery capture participant for `AuthorityContinuation` workflows only. They are in addition to W:'s own revalidation, which already rechecks fresh revocation of the workflow's seed capability (W: `implementation/p1/OPERATIONS.md:119-120`).

1. **Shape.** Exactly one grant whose server and tool equal the predecessor's. When D1 is not installed, `max_invocations == Some(1)`. The capability expires no later than the workflow's approval deadline.
2. **Subset.**
   - For `Delegator`, chain validation proves the new authority is a subset of the delegator's grant (M: `attenuation.rs:224`).
   - For `ReceiverIssuer`, the issuing key was an active head at issuance (M: issuer-lifecycle design `:11-12`).
3. **Binding.** The continuation's subject equals the fault's subject, and its canonical argument hash equals the fault's `parameter_hash`. When the fault carries `security_binding_digest`, the current trusted selection produces the same digest. The capture step reads the digest from the predecessor record's `predecessor_fault { class, security_binding_digest }`, copied from the native observation at linked-workflow creation. If the native observation recorded a trusted selection but the record lacks its digest, capture refuses (`binding_mismatch`), failing closed. When D1 is not installed, the capability's `RecoveryContinuationBinding` equals the workflow's `continuation_id`, request namespace digest, request id and `parameter_hash`.

   3a. **Sibling (predecessor) revocation.** Deny if the predecessor seed's `capability_id` is revoked, or if any capability id in that capability's own delegation chain is revoked. Use the same revocation snapshot as the rest of capture.
   - **Why it is needed.** The new capability is a sibling of the denied one, issued by the resolver, not a descendant. W:'s fresh revocation predicate covers the linked workflow's own seed capability, not the predecessor's.
   - **What it prevents.** Without this step, closing the denied capability (`2026-10-04-authority-space-teardown-design.md`, `CapabilitySubtree`) would not reach an outstanding remedy.
   - **Scope.** This is not a defect of implemented recovery, which reuses the seed capability. It arises only from this kind. A remedy never outlives the authority whose denial it answers.
4. **Active defense.**
   - Deny if the predecessor seed's `capability_id` is in an active suspended set. A fresh capability id would otherwise escape suspension (M: `capability_set_suspension.rs:41-60`).
   - For every resolver class, call the issuance-freeze authority, at linked-workflow creation and again at capture, with the trusted tenant and lineage. The operation follows how the successor capability was minted (M: `ports/issuance.rs:111-114`):
     - `Delegator` uses `CapabilityIssuanceOperation::Delegate`, with the delegation's parent capability. This is the only place an agent-signed delegation meets a freeze (umbrella D5).
     - `ReceiverIssuer`, `AllocationHolder` and `Payer` use `CapabilityIssuanceOperation::Issue`.
     - A successor minted before a freeze was installed is refused at capture once the freeze covers it, whatever its class.
   - If either authority is unavailable, deny.
   - Implemented recovery consults neither authority directly, which is why this step is needed for the new kind.
5. **Cancellation.**
   - A `CancelWorkflow` on the predecessor, recorded before the successor's capture, denies capture. The tombstone shares the serving writer (W: `.../recovery/native.rs:286-293`).
   - Revocation of the predecessor capability is covered by 3a.
   - Doc-only "emergency revocation invalidates pending approvals" (R: `08-protocol-operations.md:57`) is not relied on.
6. **Origin.** `origins::verify_linked` holds in the capture transaction (section 6.10 O6): the predecessor's original still resolves and verifies, including the process origin port; the successor's link is `Open` and names this workflow; no other continuation of the original has captured. Capture then moves the link to `Captured` (O7).

Each failure is a plain deny with stable code `CHIO-KERNEL-AUTHORITY-REMEDY-REJECTED` and sub-reason `shape`, `subset`, `binding_mismatch`, `revoked`, `suspended`, `frozen`, `cancelled`, `origin` or `unavailable`. It never produces a new fault (R5).

### 6.4 Single use

Single use comes from the implemented machinery plus the original's origin claim (section 6.10):
- one claim per original operation, across every tenant and process scope (W: `origins.rs:14-24`);
- at most one reserved or open successor per original, through the claim's chain (O4);
- at most one continuation per original that ever captures, the root's or one successor's. Capture moves the successor's link to `Captured` under the claim's version check, in the same serving-writer transaction as the capture (O7). A second successor's capture therefore refuses with sub-reason `cancelled`, even if an earlier successor was retired by mistake, and the superseded root continuation never captures (O3);
- one selected continuation per workflow;
- `reserve_recovery_call` and `finalize_recovery_call` consume the process slot exactly once (W: `chio-process/src/recovery.rs:83`, `:110`).

In addition, the new capability allows at most one invocation, through `max_invocations` or the D1 permit. No fault-resolution replay participant is added. `2026-10-04-typed-reservations-design.md` treats `reserve_recovery_call` and D1 seals as consumption commitments with no compensator.

### 6.5 Fresh continuation, not a resumed operation

A resolution never resumes the denied request:
- Scope and expiry denials happen before durable admission (M: `async_evaluation_core.rs:279` precedes `:356`). They therefore leave no native operation for the origin owner to verify, and get no remedy until O8's profile exists.
- A budget denial compensates the operation and leaves a terminal replay tombstone. That compensated operation is the original that the successor chain hangs from (section 6.10).

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
- **Original process provenance stays with the faulted process.** W:'s `RecoveryProcessOriginPort` verifies the unchanged first-attempt request of the original process (W: `chio-kernel/src/recovery/ports.rs:52-62`). The sibling never reproduces or owns that request. `origins::verify_linked` calls the port with the predecessor's scope and original seed, and checks the sibling's own request only as fresh successor authority (section 6.10 O6). The original's claim is keyed across process scopes, so its successor chain spans the faulted process and its siblings, and two siblings cannot both hold an open link (O4).
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

`Authority` remedies need three things it lacks:
- the `AuthorityContinuation` template;
- deployments whose server and tool match the faulted call, including sibling-process scopes;
- the linked-successor extension of the existing origin owner (section 6.10): the successor chain on `OriginClaim`, `reserve_successor_ordinal` as a claim mutation, `origins::verify_linked`, link retirement in `CancelWorkflow` and the link transfer in capture. Generalizing server and tool matching alone cannot make a successor pass W:'s current origin checks.

Remedies for denials that leave no native operation (scope and expiry) also need O8's retained-denial profile, which is a separate prerequisite in the native admission owner.

That generalization belongs to recovery P6 or later. This spec's Phase 1 is gated on it (section 9).

### 6.10 Linked-successor origin contract

Current W: gives every workflow one verified original and gives that original one owner (section 2):
- **Resolve.** `origins::resolve` loads the seed's request id as an unambiguous original. It requires a `ToolDispatch` in `CompensatedBeforeDispatch` with no dispatch commitment, retained request material canonically equal to the seed, and the deployment's native security context and authority (W: `.../recovery/origins.rs:61-92`; W: `chio-kernel/src/admission_operation/retained_request.rs:379-393`). Creation then calls `RecoveryProcessOriginPort::verify_original_request` for the unchanged first-attempt process request (W: `commands.rs:87-94`; `chio-kernel/src/recovery/ports.rs:52-62`).
- **Claim.** `origins::claim` writes one record keyed by `H("chio.recovery.origin-claim.v1", original operation id)`, exclusive across every tenant and process scope. A repeat is accepted only when it is the identical `(scope, workflow_id, continuation_id, origin)`; anything else is `Conflict` (W: `origins.rs:14-24`, `:94-129`; called at `commands.rs:150`).
- **Verify.** `origins::verify` re-resolves the record's seed and re-checks the claim at version 1 (W: `origins.rs:131-164`). Issuance and fresh-basis validation call it, and issuance requires every action's `origin` to equal the record's (W: `issuance.rs:37-40`; `validation.rs:293`).

A successor's seed carries a new capability, and for a sibling process a new scope. `resolve` on it fails exact retained-request equality, a fresh successor request id has no original row, and a copied origin is already claimed by the predecessor's workflow. Skipping those checks for the new template, or adding an independent successor index, would let two continuations own one denied action, or let a fabricated seed stand in for proven non-execution. This contract extends the existing owner, `recovery/origins.rs`, and adds no other origin store.

1. **O1. The original stays the root.** The predecessor's record keeps its seed (the original denied request), its `origin` and its claim, unchanged. A successor never resolves an origin from its own seed. Its record carries `origin = predecessor.origin`, written by host setup together with `predecessor_workflow`. Its own seed, the replacement request, is retained as its `creation_seed`. The original request and the replacement are never compared for equality and never substituted for each other.
2. **O2. One claim, one chain.** The claim at the original's key gains a bounded successor chain. It stays one row, under the same key, written by the same serving writer:

   ```rust
   struct OriginClaim {                        // W: origins.rs:7-12, extended
       scope: RecoveryScopeV1,                 // root owner (the predecessor); never rewritten
       workflow_id: WorkflowId,
       continuation_id: ContinuationId,
       origin: RecoveryOriginV1,
       chain: BoundedList<SuccessorLinkV1, MAX_SUCCESSORS>, // ordered by ordinal; omitted when empty
       chain_revision: u64,                    // +1 per chain mutation; the row version is 1 + chain_revision
   }
   struct SuccessorLinkV1 {
       ordinal: u16,
       resolution_attempt_id: Digest,
       owner: Option<SuccessorOwnerV1>,        // None while Reserved; set by CreateWorkflow
       state: SuccessorStateV1,                // Reserved | Open | RetiredWithoutCapture | Captured
   }
   struct SuccessorOwnerV1 { scope: RecoveryScopeV1, workflow_id: WorkflowId, continuation_id: ContinuationId }
   ```

   `MAX_SUCCESSORS` is `max_successors_per_predecessor`. A claim with an empty chain encodes exactly as today, so existing claims keep version 1 and need no migration. `verify`'s fixed version-1 check becomes `version == 1 + chain_revision`, with the root fields compared as today. Every chain mutation checks the expected row version, so concurrent mutations from different process scopes serialize and the loser gets `Conflict`.
3. **O3. Root exclusivity.** At most one continuation per original captures: the root's own, or one link's.
   - The root fields never change. Another workflow claiming the same origin as a root is still `Conflict`, as today.
   - The first chain mutation (a reservation) requires the predecessor to be `Active` and uncaptured, and permanently supersedes the root continuation. From then on `origins::verify` refuses the root workflow's issuance, fresh basis and capture with `superseded`. That only adds a refusal: `resolve` and `verify` are not relaxed for any record.
4. **O4. Reservation, creation and replay.** `reserve_successor_ordinal` (section 6.2 identity step 1) is a mutation of this claim:
   - the same `resolution_attempt_id` returns its link's ordinal;
   - a new attempt id reuses the ordinal of the one link in `Reserved` or `Open`, if there is one, and otherwise appends a `Reserved` link at the next ordinal, refusing beyond `MAX_SUCCESSORS`;
   - at most one link is `Reserved` or `Open` at any time.

   `CreateWorkflow` for `AuthorityContinuation` moves the link for its ordinal from `Reserved` to `Open` and sets `owner`, in the transaction that saves the successor record. A replay with the same key, seed and origin finds the link `Open` with the identical owner and returns the existing workflow (W: `commands.rs:95-101`). Any other owner for that ordinal, or a link that is not `Reserved` or identically `Open`, refuses as `Conflict`.
5. **O5. Retirement and cancellation keep history.** `CancelWorkflow` on a successor that holds no capture moves its link from `Open` to `RetiredWithoutCapture` in the cancel transaction.
   - The link, its ordinal, owner and attempt id stay in the claim permanently. Ordinals are never reused, matching W:'s rule that closed identities are retained (W: `commands.rs:109-110`).
   - Cancellation never removes a link, never rewrites the root fields, never deletes the claim and never returns the root continuation to capture.
   - Cancelling the predecessor leaves the claim in place. It refuses every later reservation, creation and capture for the chain (section 6.3 step 5).
   - A retired link frees the one reserved-or-open slot, within `MAX_SUCCESSORS` in total.
6. **O6. `origins::verify_linked` at every recheck point.** For an `AuthorityContinuation` record, every point where W: calls `origins::verify` (creation, issuance, fresh basis, capture) calls `origins::verify_linked` in the same module. It requires all of:
   - **Original provenance, revalidated.** The predecessor's record passes `origins::verify`'s provenance and root checks under the predecessor's own deployment: its original seed re-resolves through `resolve` to the same origin, and the claim's root fields name the predecessor. The O3 supersession refusal guards only the root's own continuation, so it is not applied here. `RecoveryProcessOriginPort::verify_original_request` is called with the predecessor's scope, original seed and session, never with the successor's.
   - **Chain ownership.** The link for the record's ordinal names exactly this record's scope, workflow id and continuation id, and is `Open`, or `Captured` by this record on a replay. No other link and not the root has captured.
   - **One origin.** `record.origin` equals the claim's `origin`, and every action's `origin` equals it (the existing `issuance.rs:38-40` check, unchanged).
   - **Fresh successor authority.** Section 6.3 for the successor's capability, and W:'s own fresh-basis checks for the successor's action under the successor's deployment.

   A record reaches `verify_linked` only through its host-written template and predecessor fields. Every other record still goes through `resolve` and `verify` unchanged. Any failure refuses creation, or refuses capture with sub-reason `origin`.
7. **O7. Capture is the transfer.** The capture that consumes the successor's continuation moves its link from `Open` to `Captured` under the claim's version check, in the same serving-writer transaction. The root, a second successor, or a stale retry of either then meets a chain that already records a capture, and refuses with `cancelled`. After a lost capture acknowledgement, a link `Captured` by this record means the capture committed, and the operation is reconciled from the store (REC-11). Neither the original nor the replacement is dispatched again.
8. **O8. Denials with no native row.** Scope and expiry denials are selected before durable admission begins (section 6.5), so `resolve` finds no original, and no predecessor workflow can exist for them.
   - Such a denial gets no `Authority` remedy until the native admission owner writes a retained-denial record for it in the same evaluation. That record must carry the exact request material, the native security context and authority, and a terminal non-dispatch proof that `resolve` can verify as it verifies `CompensatedBeforeDispatch`. It is a separate design reviewed with the admission owner (open decision 8), not part of this spec.
   - Until then `origin_retained` is false for such a denial, no `Authority` template addresses it, and the planner returns `BlockedByCapability`, as today. A `CreateWorkflow` naming such a request is refused by `resolve`.
   - A spec 10 deny tombstone (X15) qualifies only if it retains the request material and security binding that `resolve` reads. Otherwise it is treated as having no native row.
   - Budget denials that compensate a begun operation already have a verifiable origin. They are Phase 1's scope.
   - The block is unchanged in every case (R6, A5). Origin retention affects only the planner fact and resolution.

## 7. Failure modes and fail-closed behavior

| Failure | Outcome |
|---|---|
| Classifier sees an unknown error | plain deny |
| Expired token fails revocation, delegation or subject on the fault path | plain deny with that error |
| Budget denial with a sibling guard denial or a retained reservation | plain deny |
| Faulted capability suspended or frozen, or an active-defense authority unavailable, at classification time | Block emission unchanged (R6, A5). Resolution refuses at creation and capture with `...-REJECTED` (`suspended`, `frozen`, `unavailable`) |
| No recovery authority installed (`AdmissionOperationStore::recovery_authority()` is `None`), no deployment for the scope, or no registered `Authority` template | block written; planner returns `BlockedByCapability`; plain deny semantics |
| Linked-workflow creation with a mismatched predecessor, a second reserved or open successor, more than `max_successors_per_predecessor`, or a changed tool or arguments | `CreateWorkflow` refused |
| Capture by a second successor of the same original, or by the superseded root | `...-REJECTED` (`cancelled`); the origin claim's chain already records a capture, or the root is superseded (O3, O7) |
| Predecessor's original no longer resolves (native row, retained request, native context or authority changed), or the process origin port refuses the original request, at creation or capture | `CreateWorkflow` refused, or `...-REJECTED` (`origin`) (O6) |
| Successor record whose `origin` differs from the claim's, or whose link names another owner | `CreateWorkflow` refused (`Conflict`), or `...-REJECTED` (`origin`) |
| Denial with no native row (scope, expiry, or a tombstone without retained request material) | `origin_retained` false; planner returns `BlockedByCapability`; a forced `CreateWorkflow` is refused by `resolve` (O8) |
| Two successors in different process scopes created concurrently | one link wins under the claim's version check; the other is `Conflict` (O2, O4) |
| New authority wrong shape, not a subset, or from a non-active issuer key | `CHIO-KERNEL-AUTHORITY-REMEDY-REJECTED` (`shape`, `subset`) |
| Predecessor capability or its chain revoked, suspended, frozen, or predecessor cancelled at capture | `...-REJECTED` (`revoked`, `suspended`, `frozen`, `cancelled`) |
| `RecoveryContinuationBinding` presented outside its bound continuation | deny at admission |
| Linked-workflow creation whose binding differs from the identity derived for `(predecessor_workflow, successor_ordinal)`, or that reuses an ordinal | `CreateWorkflow` refused (`binding_mismatch`) |
| Capture where the workflow's continuation differs from the bound continuation | `...-REJECTED` (`binding_mismatch`) |
| Capture uncertain | recovery reconciliation; never a fresh identity (REC-11) |
| Portable core receives the constraint | `ConstraintError` deny |

## 8. Protocol, schema and wire impact

- `spec/PROTOCOL.md`:
  - **Section 5:** add the `recovery_continuation_binding` constraint (fields `continuation_id`, `request_namespace_digest`, `request_id`, `parameter_hash`; equality preservation; enforcer) and the `GovernedApprovalRequired` classification.
  - **Section 6:** define the `authority_fault` v2 block and the tagged fault kinds. Admit the `integrity_fault` block (`chio.integrity-fault.v1`, spec 11 I19) as the sibling kind.
  - **Section 8:** state that recoverable authority denials carry the block.
- **Recovery generated schemas** (W: closed, generated vocabulary; R: `11-contract-catalog.md`):
  - `ExplanationRemedyKind::Authority`;
  - `ExplanationAssessmentV1::RequiresAuthority`;
  - `RecoveryTemplateV1::AuthorityContinuation`;
  - the `predecessor_workflow`, `predecessor_fault` and `successor_ordinal` record fields, and the `authority-successor` creation-key derivation;
  - the `OriginClaim` chain (`chain`, `chain_revision`, `SuccessorLinkV1`, `SuccessorOwnerV1`, `SuccessorStateV1`), omitted when empty so existing claims decode unchanged (section 6.10 O2);
  - the optional annotation on the `Capability` fact, including `origin_retained`.

  Each needs negative vectors. Closed enums mean old readers refuse new values rather than misreading them.
- **MCP.** The tool error result carries `_meta["chio/authorityFault"]` or, for the integrity kind, `_meta["chio/integrityFault"]`, never both. No new JSON-RPC code.
- **A2A.** No change: `PendingApproval` already maps to `Working` (M: `conversion.rs:99`), and delegation-mode denials stay `Failed`.
- **Negotiation.**
  - Add an `authority_fault_classification` feature. Without it, the kernel neither emits the block nor accepts the constraint.
  - The recovery deployment binds the `AuthorityContinuation` template through host setup, so it cannot be enabled by an incoming command.

## 9. Rollout

1. **Phase 0.** Classifier, typed `GovernedApprovalRequired` and the receipt block, in shadow (metrics only). No recovery dependency.
2. **Phase 1** (gated on recovery generalization, section 6.9):
   - the `Authority` kind, `RequiresAuthority` and `AuthorityContinuation`;
   - predecessor validation;
   - the linked-successor origin contract in `recovery/origins.rs` (section 6.10);
   - capture checks including 3a and the freeze `Delegate` call;
   - `RecoveryContinuationBinding` with its KG4 enforcer.

   It ships first for `ReceiverIssuer` and `Delegator`, and only for denials with a verifiable native origin (`BudgetExhausted` after a begun operation). Scope and expiry remedies wait for O8's retained-denial profile.
3. **Phase 2.** `AllocationHolder` (D1) and `Payer` (F1) templates, gated on the W1/W2 work profile.
4. **Phase 3.** MCP `_meta` surfacing, and SDK resolver helpers that verify the deny receipt and mint a narrow delegation or D1 subdivision.

## 10. Tests and conformance evidence

- **Unit:**
  - classifier exhaustiveness;
  - every never-resolvable variant yields `None`;
  - expired plus revoked yields a plain deny;
  - budget plus a sibling guard denial yields a plain deny;
  - an R5 request yields no block;
  - `InsufficientIntegrity` classifies as `FaultKind::Integrity`, never as an `AuthorityFaultClass`, and emits only the `integrity_fault` block;
  - a deny receipt never carries both blocks.
- **Planner (pure, `chio-recovery`):**
  - a `Capability` fact without an `Authority` template still yields `BlockedByCapability`;
  - with an accessible template it yields `RequiresAuthority`;
  - with an inaccessible template the public result is identical to having no template (P2 filtering);
  - no non-`Authority` kind ever addresses a `Capability` fact;
  - an `Integrity` fact is addressed only by spec 11 I20's two remedy paths, never by `Authority`.
- **Store:**
  - predecessor mismatch, a second reserved or open successor, the successor bound, and changed tool or arguments are refused;
  - a successor cancelled without capture (for example after its capability expired during approval) frees the slot, keeps its link as `RetiredWithoutCapture`, and a corrected successor is accepted at the next ordinal;
  - a second capture for the same original is refused by the origin claim's chain;
  - the seed pin (`issuance.rs:76-81`) still holds for the linked workflow;
  - **non-D1 construction and verification:** derive the identity chain for `(predecessor, 1)`, mint a capability carrying the binding, create the workflow, materialize `ActionIntentV1` and capture. Each step is accepted. The capability's signing body contains no action-intent digest, and `ActionIntentV1.capability_body` equals the hash of the completed capability's signing body;
  - **binding to a different continuation is refused:** a capability bound to `(predecessor, 2)`, or to another predecessor, is refused at creation of the `(predecessor, 1)` workflow with `binding_mismatch`. The same capability presented on an ordinary path with matching arguments but a different request id or namespace is denied at admission;
  - a retried creation with the same key and seed returns the existing workflow; the same key with a different capability is refused as a conflict; a reused ordinal is refused.
- **Origin ownership (section 6.10, R-2-02).** Each case starts from a real current-W: original: a native `ToolDispatch` compensated before dispatch, taken through the public recovery path (`CreateWorkflow` with `origins::resolve`, the process origin port and `origins::claim`), with no fixture shortcut around those owners. In every case exactly one continuation of the original captures, and neither the original nor a replacement is dispatched again.
  - **Changed-capability successor:** reserve, create, approve and capture a successor whose seed carries the new capability. Creation never runs `resolve` on its seed, `verify_linked` revalidates the original at issuance, fresh basis and capture, and capture moves the link to `Captured`.
  - **Sibling-process successor:** the same flow in a sibling scope. The process origin port is called only for the original process request; the sibling's request is checked only as fresh successor authority.
  - **Lost creation acknowledgement:** `CreateWorkflow` commits and its response is lost; the retry with the same attempt id gets the same ordinal and returns the existing workflow, with the link unchanged.
  - **Cancelled uncaptured replacement:** cancel an open successor; its link becomes `RetiredWithoutCapture` and stays in the claim, the root stays superseded, and the next successor gets a new ordinal. The cancelled successor can never capture.
  - **Captured predecessor:** a root that already captured refuses reservation; a successor that captured refuses every later reservation and every other capture.
  - **Two concurrent successors across process scopes:** two reservations or creations race; exactly one link becomes `Open` and the other is `Conflict`.
  - **Fabricated seed:** a successor naming a predecessor without a verified origin, an `origin` not equal to the predecessor's claim, or a request id with no original row, is refused at creation.
  - **Mismatched native or process origin:** the predecessor's retained request, native context or native authority no longer matches, or the process origin port refuses the original request. Creation is refused, and an already created successor's capture refuses with `origin`.
  - **Early denial with no native row:** a scope or expiry denial yields the block with `origin_retained` false, the planner returns `BlockedByCapability`, and a forced `CreateWorkflow` for it is refused by `resolve`.
  - **Root supersession:** after the first reservation, the predecessor's own continuation refuses issuance and capture with `superseded`, even after every link is retired.
- **Proptest.** For random chains and resolver scopes, a linked workflow accepted at capture:
  - is a subset of the resolver's grant;
  - authorizes one invocation of the faulted tool with the faulted arguments;
  - is refused after revocation of the predecessor capability or any ancestor in its chain (3a).
- **Recovery cutpoints.** Extend W:'s recovery contract and crash suites with an `AuthorityContinuation` workflow (reserve, approve, finalize, restart; basis change between review and capture). Add `denied_capability_revoked_before_capture` (3a) and `predecessor_cancelled_before_capture`. Crash at every chain mutation (reservation, creation, retirement, capture) and assert that restart re-projects the claim and the link state from the store.
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
  - The integrity block's field set equals spec 11 I19's set, and its `remedy_classes` is the same with and without a quarantine template configured (A6).
  - Repeating one classifiable request with active-defense authorities absent, available, unavailable, and holding a suspension of the faulted capability yields the same block every time (R6, A5). Only the recovery actor's resolution result differs.
- **Process.** A host-side sibling-spawn resolution end to end, with a sibling deployment. The worker cannot drive recovery. The faulted process's history is unchanged.
- **Fuzz.** `authority_fault_v2` and `integrity_fault_v1` decode targets.

## 11. Residual risks and open decisions

Residual risks:
- Paging pressure moves to recovery intake quotas (64 workflows per tenant; W: `implementation/p1/OPERATIONS.md:131-135`). Resolvers still need their own limits.
- A deny receipt forwarded to a resolver discloses the call's parameters, redacted per receipt mode.
- A delegator remedy minted during a freeze and presented after it lifts is accepted. Every agent-signed delegation has the same gap (umbrella D5).
- W: is uncommitted and built on an older #1160 checkpoint. Recovery type names and line references must be re-pinned when it merges.
- Recovery docs name features W: does not implement: a signed `RemedyOfferV1`, a `recovery_deliveries` outbox, an `ExplainIntent` command, and approval-invalidating emergency revocation. Nothing here depends on them.
- Until O8's retained-denial profile exists, scope and expiry denials, the commonest authority faults, have no remedy. That is the fail-closed choice: a remedy without a verified original could stand in for proven non-execution.
- W:'s origin owner is new and still uncommitted. Section 6.10 is written against `origins.rs` as read on 2026-10-05 and must be re-checked when W: changes it.

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
7. **Which identity the binding names (resolved).** The successor continuation derived from `(predecessor_workflow, successor_ordinal)`, together with the request namespace, request id and argument digest (section 6.2, "Continuation identity"). It is fixed before the capability exists, survives replay because each step is deterministic, and never hashes the capability.
8. **Retained evidence for denials with no native row.** Scope and expiry denials happen before durable admission begins. To give them a remedy, the native admission owner would write a retained-denial record in the same evaluation, carrying the exact request material, native security context and authority, and a terminal non-dispatch proof that `origins::resolve` verifies like `CompensatedBeforeDispatch` (section 6.10 O8). That adds a durable write to denials that persist nothing today, on the admission owner's path, so it needs its own review with that owner. Until it exists, those denials keep `BlockedByCapability`. Recommendation: specify it with spec 9's machine, as a `Terminal(CompensatedBeforeDispatch)` record with retained request material, not as a recovery-side record.

## Review disposition

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180274506 | Keep fault-block emission independent of authority availability | Fixed now. Classification no longer consults active defense. Fail-closed checks stay at linked-workflow creation and capture, and refusals are disclosed only to the recovery actor | R6; section 7; section 10 anti-oracle tests |
| 4180731799 | Allow replacement of an unused failed successor | Fixed now. Uniqueness covers the open successor and the one successor that captures. A successor cancelled without capture frees the slot, up to `max_successors_per_predecessor` | Section 6.2 store validation step 1; section 6.4; section 7; section 10 store tests |

### Codex review (PR #1174, round 2)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180839016 (with spec 11) | Define an integrity-specific fault payload | Fixed now. The classifier returns a tagged `FaultKind` (`Authority(AuthorityFaultClass)` or `Integrity`). Each kind has its own block: `AuthorityFaultV2` unchanged, and `IntegrityFaultV1` defined in spec 11 I19. Each kind has its own planner projection (`Capability` and `Integrity`), and A1-A5 cover both (A6) | Section 4 table; R1; R5; section 5; section 8; section 10 |

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-2-01 | The new capability must contain a digest that hashes that same capability | Fixed. Verified the cycle in W: (`authorization.rs:69-90`, `issuance.rs:76-83`, `token.rs:219-242`, `materialize.rs:285-286`). `RecoveryContinuationBinding` now names `continuation_id`, `request_namespace_digest`, `request_id` and `parameter_hash`, all derived before the capability from `(predecessor_workflow, successor_ordinal)` through W:'s existing workflow, continuation and request-id rules. `ActionIntentV1` is derived afterwards, unchanged. The store and capture check the binding against the recomputed identity. Construction and negative tests added | Revision 4 changes; section 6.2 template, store step 4, binding, "Continuation identity"; section 6.3 step 3; section 7; section 8; section 10; open decision 7 |

### Codex review (PR #1174, round 12)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186364961 | Persist the selection digest in recovery state | Fixed now. The native planner fact's annotation carries `security_binding_digest` from native flow state. The predecessor record stores it in `predecessor_fault { class, security_binding_digest }` at linked-workflow creation, and capture step 3 compares against that record. Missing binding evidence refuses | section 5 planner fact; section 6.4 capture step 3 |

### Codex review (PR #1174, round 19)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187433139 | Recheck issuance freezes for every resolver class | Fixed now. Step 4 calls the issuance-freeze authority for every resolver class, at creation and again at capture: `Delegate` for `Delegator`, and `Issue` for `ReceiverIssuer`, `AllocationHolder` and `Payer`. A successor minted before a freeze cannot capture after it | section 6.4 step 4 |

### Codex review (PR #1174, round 23)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187740946 | Persist the successor ordinal before deriving retry identity | Fixed now. The ordinal is allocated once by `reserve_successor_ordinal(predecessor_workflow, resolution_attempt_id)`, keyed by a caller-held attempt id that is stable across retries, and an existing open successor is reused before a new ordinal is allocated. A lost `CreateWorkflow` response therefore replays the committed workflow | section 6.2 identity chain step 1 |

### Independent review pass 5 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-2-02 | Linked authority successors do not compose with W's new exclusive origin ownership | Fixed. Verified in W: that creation resolves the seed to one original (`origins.rs:61-92`, exact retained request at `retained_request.rs:379-393`), verifies the original process request (`commands.rs:87-94`, `ports.rs:52-62`), claims it exclusively across scopes (`origins.rs:14-24`, `:94-129`), and re-verifies at issuance and fresh basis (`issuance.rs:37-40`, `validation.rs:293`). New section 6.10 extends that one owner: the predecessor keeps the original request and its evidence (O1); the original's claim gains a bounded successor chain with version-checked mutations (O2); the first reservation permanently supersedes the root continuation (O3); reservation, creation and replay are chain mutations with at most one reserved or open link (O4); cancellation retires a link without erasing it or the claim (O5); `verify_linked` revalidates the original, including the process port on the original scope, plus chain ownership and fresh successor authority at every recheck point (O6); capture moves the link to `Captured` in the same transaction (O7). The partial unique index and `successor_captures` row are removed. Denials with no native row get no remedy until a retained-denial profile exists in the admission owner (O8, open decision 8). `resolve` and `verify` are not relaxed. Spec 11's quarantined continuation carries the same prerequisite | Revision 5 changes; sections 1, 2, 4, 5, 6.2, 6.3 step 6, 6.4, 6.5, 6.7, 6.9, 6.10; sections 7-11; spec 11 I22 |

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
