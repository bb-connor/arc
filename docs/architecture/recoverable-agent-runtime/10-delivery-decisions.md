# Delivery sequence, decisions and review closure

## Implementation units

Phases are dependency boundaries, not calendar estimates. Each must produce reviewable Rust changes, owning tests, retained evidence and a documented operational contract. A phase cannot mark an unavailable enforced profile as supported merely because its pure evaluator passes. Package/release qualification remains separate from implementation.

| Phase | Deliverable | Principal owners/modules | Exit evidence |
|---|---|---|---|
| P0: contracts and assurance baseline | Closed schemas, pure dependency graph, effect/release/control vocabulary, source-bound requirements and baseline measurements | Security/core types, kernel ports, codegen, conformance | Shared malformed-input/work-budget vectors; compile-fail ownership/auto-trait cases; MSRV/no_std feature matrix; declared resource/performance budgets |
| P1: exact durable recovery | Workflow/continuation/step identity, exact process binding/reservation bridge, durable admission intent, grant v2, native participant, bounded provider submission, support-disclosure slice and basic SDK protocol | Kernel admission/outcomes; serving store; process; control-plane recovery | One useful send, one quota charge, fresh-process recovery, all selection/admission/capture/effect/ack cutpoints, partial-effect settlement, replay authorization and no hidden resubmission |
| P2: explanations | Recovery-specific pure snapshots, bounded planner and audience-safe reports | Pure recovery crate; host read/consult adapters | Recomputed signed reports, information-leak probes, no effect dependencies, stale-basis live refusal |
| P3: semantic remedies | First two connector families, ACL facts, influence state, endorsement, alternate destinations, transformations, prerequisites and withholding | Semantic-contract crate; manifest/policy; flow; native participants; broker adapters | Complete coverage, owner/integrity tests, exact recipients, useful transformed/no-value paths and no raw fallback |
| P4: durable knowledge | Artifact publication/read, labeled checkpoints/model contexts, restore/export, retention and adoption | Kernel release ports; serving store; process blobs/checkpoints; artifact backend | Every publication/read cutpoint, mutation/alias races, retained knowledge after restore and safe GC |
| P5: confined returns | Host-issued lineage boundary, cage/broker launch, bounded parent returns and full channel mediation | Process/security profile; cage/broker; flow/artifact release; host/SDK | Verified enforced launch, useful parent decision, all return/error/log/stream canaries, restart/cancellation and aggregate limits |
| P6: product and qualification | Guided setup, policy feedback/review, two-host integration, overload tests and comparative workloads | CLI/SDK/host; conformance/evaluation; operator tooling | Source/profile-bound supported matrix, utility/effect results, installation evidence, operational and required release gates |

The current implementation state is [remediation and pending requalification](implementation/STATUS.md).
P0-P6 implementation exists, but historical phase completion flags and scoped
review closure do not qualify the changed working tree. The retained
[P0](implementation/p0/verification.json),
[P1](implementation/p1/verification.json),
[P2](implementation/p2/verification.json),
[P3](implementation/p3/verification.json) and
[P4](implementation/p4/verification.json) records preserve their exact source
inventories, local acceptance, operating limits, broader failures and unavailable
checks. Their original reviews remain historical evidence.

The [P5 review](implementation/p5/REVIEW.md),
[operating contract](implementation/p5/OPERATIONS.md) and
[verification](implementation/p5/verification.json) retain real GNU/musl Linux
acceptance for the Boolean-only, model-disabled, no-provider profile at source
binding `562a3c35`. Its ten recovery cases, 72 cage tests, 27 runtime probes,
ten helper mutants and eleven measured images describe that archived campaign.
The original review findings and author fix evidence retain separate scopes.

The [P6 review](implementation/p6/REVIEW.md),
[verification](implementation/p6/verification.json) and
[supported matrix](implementation/p6/supported-matrix.json) retain local, Linux
and finite live qualification at runtime binding `b1bcd48c` and qualification
binding `3a13a9bc`. Those records preserve all five live attempts, failed
performance profiles, unknown measurements and the limits of the original fresh
review and subsequent author fix pass. Full binding values and archived-source
hashes are in [execution status](implementation/STATUS.md).

The cumulative review found 113 of 735 P6-qualified source paths changed after
the seal through naming cleanup. That is a review-snapshot count; current runtime
repairs cause additional drift. Both retained package auditors refuse the current
tree. The next work is to complete and review remediation, supply current runnable
gates and requalify a new source/profile-bound candidate while preserving all
historical records. Hosted CI, release integration and production acceptance
remain separate gates. The architecture roadmap ends at P6.

P2 and the contract-authoring portion of P3 can follow P0 independently of P1 development, but no live semantic remedy ships before its P1 authority/capture support. Persistent transform certificates require P4. Confined returns require P3/P4 and qualified platform enforcement. No feature flag may bypass these dependencies.

P1's single connector uses a minimal pinned effect contract; the general package resolver remains P3. Every phase mediates all channels it enables and enforces bounded intake, safe diagnostics and recovery headroom. Later phases add new channels and scale qualification; they do not postpone those baseline protections. Phase gates refer to executable behavior under an explicitly supported profile.

## P1 reviewable change sequence

1. Define exact new wire contracts and version handling. Add vectors for missing binding, null/unknown version, unsafe integers, wrong authority domain and v2-to-v1 downgrade.
2. Add sealed kernel observations/closure APIs over existing admission, dispatch and outcome evidence. Cover a `Deny` receipt whose resource remains unknown before integrating continuation allocation.
3. Add protected recovery records and admission-intent closure to the serving store, migration/integrity inventory and rollback-anchor coverage. Test concurrent selection, lost admission links, late submissions and uncertain commit acknowledgement.
4. Extract the existing complete process binding and add exact reviewed-envelope custody plus the host-only reservation/finalization bridge with unchanged legacy derivation. Keep flow-payload, process and native-material digests distinct. Test binding byte equivalence, orphan reservations, restored journals and exactly one logical-call charge.
5. Extend signed grant verification, exact unsigned authorization requirements, conjunctive owner-scope coverage and durable issuer reservation/signature/publication. Integrate the recovery participant into native preflight/capture, retaining current nonce issuance, consumption and fault behavior. Include lost nonce acknowledgements, phase-specific expiry and settlement after caller revocation.
6. Implement one disclosure template and a thin authenticated host driver. Add minimal generated SDK operations and an exact approval projection.
7. Run the full support-disclosure cutpoint corpus and independently verify actual effects, retained operation identity, original receipt recovery and unchanged source restrictions.

Each change must preserve an executable positive control. Do not make integration pass by replacing native capture with a permissive fake. Pure fixture/protocol tests remain useful when labeled as such.

## Architectural decisions

| ADR | Decision | Rejected alternative and reason |
|---|---|---|
| ADR-01 | Build on Chio's existing authority and flow machinery | Embedding a second runtime would require a new cross-authority consistency protocol |
| ADR-02 | Separate workflow, step, continuation, process request and native operation identities | Mutating a frozen denied request violates current recovery identity |
| ADR-03 | Use explicit recovery-bound grant v2 | A sidecar claim or v1 content binding alone does not constrain use to the selected continuation |
| ADR-04 | Put unresolved recovery ownership inside serving authority | A host-local mutex/workflow database cannot atomically guard native capture or survive owner loss |
| ADR-05 | Bridge the separate process journal with idempotent reservations | A pretend distributed transaction or new request key after a lost acknowledgement is unsafe |
| ADR-06 | Use verified effect/no-effect evidence for closure | Terminal/denied receipts can coexist with unknown or already delivered effects |
| ADR-07 | Keep planner and semantic resolution pure and bounded | Arbitrary workflow synthesis or executable policy plugins enlarge the trusted core and defeat resource bounds |
| ADR-08 | Separate confidentiality, influence and scoped endorsement | A single confidence/trust score loses distinct authority and information-flow semantics |
| ADR-09 | Use immutable artifacts plus mediated reads/restores | A persistent label database without byte/version custody leaves substitution and restart gaps |
| ADR-10 | Require explicit confined lineage authority and complete return mediation | Session names, ordinary forks or a guarded final message do not establish isolation |
| ADR-11 | Treat counterfactual reports as advisory evidence | Reusing a simulation result as a permit bypasses fresh authority/capture |
| ADR-12 | Keep policy maintenance under independent deployment authority | Reporter/maintenance-model suggestions cannot approve their own privilege expansion |
| ADR-13 | Preserve unknown outcomes and consumed authority through cancellation | Generic compensation/refund/retry cannot establish absence of an external effect |
| ADR-14 | Require utility and effect evidence under matched trials | Denial counts and mechanism inventories do not demonstrate useful task completion |
| ADR-15 | Separate native effect settlement, output release and workflow control | A flat status enum loses partial effects and can turn unavailable output into retry permission |
| ADR-16 | Retain admission intent and use authoritative closure before releasing ownership | A missing callback/projection or negative read cannot fence a late native submission |
| ADR-17 | Reuse complete process binding and preserve portable substrate contracts | Request-only hashing, implicit feature unification or a workspace-wide MSRV bump breaks existing runtime/proof assumptions |
| ADR-18 | Make provider retries and recipient replay explicit authority boundaries | Hidden transport resubmission and cached protected replies escape otherwise correct kernel ownership |
| ADR-19 | Retain the exact reviewed process envelope and reuse native-owned attachments under distinct digest meanings | A process hash is not reconstructable request custody; native credential-free material and nonce attachments are different objects |
| ADR-20 | Review unsigned authorization requirements and compose each authority class explicitly | Independently valid signatures, sequential downgrades or a disclosure grant used as endorsement do not prove complete authority for one exact action |
| ADR-21 | Separate historical settlement authority from new execution and current output release | Requiring a renewed initiating capability strands owned work; replaying with a maintenance credential creates excess authority |

## Changes requiring focused review

The highest-risk changes are new native participant composition; process-to-authority reservation/finalization; final no-effect closure; v2 owner-scope verification; knowledge retention before byte release; profile downgrade prevention; and cross-channel confined return admission.

The existing native path may conservatively retain grant consumption before a later capture step fails. Preserve that behavior: the recovery integration must not promise all-or-nothing rollback across every participant. Retain consumption evidence, classify actual effect state through native proof, and require independently authorized new authority if another continuation is allowed. A no-effect proof does not automatically restore a consumed grant.

The serving authority validates the active continuation at native capture rather than trusting a cached host snapshot. The storage design must prove how new records enter the protected commit/integrity inventory. The process journal remains a quota/identity owner, never a substitute for the native operation ledger.

## Decisions to resolve during implementation

| Question | Default decision now | Evidence that can change it |
|---|---|---|
| Exact owner approval aggregation | P1 uses one grant from an explicitly operator-scoped aggregate issuer with native-verified all-required evidence; no implicit single-key universality | A separately qualified direct bundle or existing governed machinery represents the same obligations and consumption semantics |
| First artifact backend | Existing bounded process blob storage plus authority metadata | A larger backend demonstrates equal publication/release/rollback guarantees |
| First enforced confined platform | Only a platform/profile with current cage/broker evidence | Full required channel/confinement acceptance on another platform |
| Plan parallelism | Sequential effectful steps; bounded explicit read-only consult parallelism | Native participant and DAG tests prove no ownership/authority relaxation |
| Approval timing defaults | Bounded review window and short grant after fresh checks | Recorded completion/expiry data under the same safety contract |
| First connector families | Support read and issue creation; second unrelated workflow selected before benchmark | Product use demonstrates a better representative pair with testable provider semantics |
| Numeric performance thresholds | Declare during P0 against a measured native baseline | Preapproved workload/hardware profile change, not post-result threshold adjustment |
| Historical schema retirement | Keep read/reconcile support until references drain | Signed inventory proves no retained operation/reference requires the version |

These questions do not reopen the core invariants. The package is ready for architectural review and phase planning. Execution readiness for a phase requires its explicit contracts, schema choices, migration treatment and fixtures to be checked against the then-current source.

## Scope and closure

No mandatory OpenAPPA runtime dependency, new general-purpose policy language, unbounded planner, independent replay coordinator, model-issued authority, or automatic policy weakening is part of this design. UI polish, broad provider catalogs and cross-platform expansion follow a working native vertical slice.

Architecture acceptance requires every numbered obligation to have an owner/test/phase; source findings to be reproducible; every effect/authority transition to have a durable owner; every claimed data channel to have mediation; and unresolved assumptions to be explicit. Implementation acceptance requires the owning evidence, not a document checklist. Public availability and release qualification are separately demonstrated.

Current source names and evidence replay are described in the
[current reproduction overlay](implementation/current-reproduction.md). Original
coverage, commands and seals remain historical inputs; published P6 metadata
redactions preserve their documented original/published hash distinction. A
local source correspondence or completed finding disposition does not qualify
the changed implementation.
