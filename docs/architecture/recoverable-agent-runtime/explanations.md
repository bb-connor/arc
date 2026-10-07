# Recovery explanations

This document describes the maintained explanation contract. Historical acceptance
packages retain their original source and evidence; they do not qualify later
changes. The current verification boundary is recorded in
[implementation status](implementation/STATUS.md).

## Compose an advisory service

Construct `RecoveryExplanationService` with an explicit `RecoveryScopeV1`, an
operator-selected advisory trust domain and issuer, a separate Ed25519 signer,
and validated `ExplanationLimitsV1`. Native composition refuses the disclosure
signer as the advisory signer. The explicit-data service accepts already mediated
facts and needs no kernel, provider, process runtime, mutation port or execution
owner. The pure `chio-recovery` evaluator and planner cannot sign reports or
perform effects.

The native `RecoveryRuntime::explain` adapter authenticates the current scoped
`Inspect` capability and assignment before loading the workflow. It returns only
`SignedRecoveryExplanationViewV1`. `RecoveryRuntime::inspect_explanation` instead
requires the separate `InspectExplanationGraph` permission, whose capability tool
name is `explanation.inspect`, and a finite current preview clearance that covers
the full joined graph classification. An opaque reference or an `Inspect`
capability supplies no protected graph permission.

Fresh deployment installation rejects `Top` actor preview clearances. Retained
authenticated profiles may still decode their historical `Top` value as data;
every operational preview, native explanation projection, audience recheck and
protected explanation inspection refuses its use as a clearance. A conservative
`Top` source or graph classification does not grant access.

## Observe facts and verify advice

Native capability liveness, composite policy eligibility, the pinned recipient
contract and coverage liveness use `FreshnessQualified` observations. Their
validity comes from explicit observation and expiry intervals. They do not have a
workflow-owned version counter. The native process generation remains a separate
observed influence commitment. A versioned `Known` fact retains its original
version field and wire meaning; it is used only when the source actually supplies
that version.

Current policy eligibility includes workflow control and admission closure.
Missing, expired, unverified or inconsistent facts never establish feasibility.
The pinned recipient observation asserts no new remote provider ACL lookup.
Unknown or spent effects cannot become replacement sends. Native capture and
resume independently recheck current authority, source and custody; a report
does not renew a frozen action or release an effect.

`verify_explanation_report` recomputes the protected report using the original
authorized snapshot, registry, recipient clearance, limits and independently
selected signer, domain, issuer, scope and deployment roots. Correct signatures
alone do not establish correct recomputation. `verify_explanation_view` verifies
the selected safe projection and recipient provenance; it does not reconstruct
inaccessible inputs or establish native execution authority.

Full report classification joins every snapshot, fact, template, disclosure and
registry label. Pure audience projection filters inaccessible alternatives before
search and ranking. Hidden alternatives and their evidence deadlines do not
change the public candidate result or cause public search exhaustion. The safe
view contains no snapshot, registry, intent, evaluation or full report commitment.
Its opaque reference contains 256 random bits and is bound into the signed view.
Debug representations of protected artifacts and planner candidates are redacted.

## Resolve an original protected graph

Successful native advice retains its exact original snapshot, registry, report
and signed view under the view's original random reference. The trusted Rust host
API `RecoveryRuntime::inspect_explanation_reference` requires a separate live
`InspectExplanationGraph` capability and assignment before looking up a reference
and again before returning its classified graph. Current finite clearance must
cover both the original graph and current native source/knowledge restrictions.
Missing, wrong-scope, wrong-workflow, expired and unauthorized references refuse
without disclosing a graph. The private advice HTTP endpoint returns only its
safe view; it exposes no protected reference-inspection route.

Inspection restores the original normalized inputs and signatures. It performs
no fresh planning, signing, effect or recertification of their old timestamps and
roots. A separately authorized operator may inspect the original recipient's
classified report as data. The signed recipient view retains its original
audience. A retained report whose evidence has expired does not become current
advice by being read.

Retention lasts through the signed view's expiry, including when inaccessible
evidence gives the protected report a shorter validity interval. The cache is
process-local: restart makes earlier references unavailable. Expired references
can release capacity; live entries are never evicted. A collision refuses and
does not replace an original graph. Each service retains at most 32 live entries
and at most eight per issuing actor.

The private native representation stores its common context label once through
immutable UTF-8 bytes and checked spans. It shares equal profile labels and keeps
the original four observations, one template and signed metadata. It reconstructs
an expanded graph only after graph authorization and retains only a weak pointer
to that expansion. Concurrent readers holding the expanded artifact share its
identity; later reconstruction uses the same original inputs and signatures.

Every entry reserves the same checked maximum derived from the public flow label
caps, 256-byte identifier ceiling and protected deployment record bound. The
compact encoded ceiling is 8,831,532 bytes, rather than repeated serialization of
every common label. Resident payload accounting separately includes contiguous
label buffers/spans, profile labels, fixed typed metadata, collections and Arc
headers. Allocator overhead and expanded artifacts retained by trusted callers
are separate from service-owned payload accounting. No pure planning, wire
ingress or qualification ceiling changes. Hidden graph size cannot change the
number of admitted cache slots. Counting serialization, reconstruction and
signing occur outside metadata locks.

## Bound planning and intake

The explanation evaluator accepts at most 32 observations, 16 templates, eight
explicit dependencies per template and 16 returned alternatives. Its work limit
is at most 4096 operations. Label cardinality and identifier validation retain
their own fixed protocol bounds; a bounded label is charged as one planner label
operation. This keeps maximum valid label shapes usable without claiming that
the work counter measures wall-clock execution or cryptographic cost.

The separate pure `plan` API produces a private advisory `CandidatePlanV1` through
`PlanDecision`. Registered plans are scope-bound and intent-bound and retain their
supplied workflow and plan identities. Ceilings are 16 offers, eight top-level
steps, 32 total expanded nodes, depth eight and 4096 work units; a caller may only
lower them. The initial `DependencyGraphV1` representation has a stricter ceiling
of 16 nodes. Canonical dependency ordering is deterministic. Duplicate, missing,
cyclic or unrelated steps and cost disagreements refuse. Symbolic future steps
never establish missing current evidence. `SearchBoundReached` identifies the
offer, step, node, depth or work bound and never claims that no remedy exists.

Native advice intake allows 32 authenticated probes per actor in a 60-second fixed
window and at most 64 simultaneously active actor windows per service. Fully
elapsed windows release identity capacity. Active probe allowances and
future-start windows under clock rollback are not reset by eviction. Restart
starts new process-local abuse-control windows; intake is not durable authority.

Wire ingress remains conjunctively bounded by 64 KiB, depth 16, 4096 JSON nodes
and 32 KiB of aggregate encoded string bytes. Individual identifier and protected
text limits use UTF-8 bytes. Output transport has a separate bounded response
profile. The private HTTP explanation route accepts the closed capability and
workflow request, authenticates through its independently bounded lane, and
admits expensive work by verified principal. The native runtime reauthenticates
independently before producing advice.

## Run the focused checks

From the repository root, run the pure and native explanation tests on the same
candidate source:

```sh
cargo test --offline --locked -p chio-recovery --test explanations
cargo test --offline --locked -p chio-recovery --test plans
cargo test --offline --locked -p chio-control-plane --lib --features pq recovery::tests::explanations:: -- --test-threads=1
cargo test --offline --locked -p chio-control-plane --lib --features pq recovery::explanation:: -- --test-threads=1
```

These focused checks do not establish Linux isolation, live provider behavior,
formal-tool results, hosted CI or a production deployment. Current-source evidence
and independent review must be recorded for those separate acceptance dimensions.
