# Reusable Work Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax.

All Work-prefixed APIs and qualified work-store adapters in this plan are implementation targets. The [integration inventory](../../research/work-abstraction/INTEGRATION.md) identifies the current callable interfaces and pending substrate dependencies.

**Goal:** Make work contracts, accepted-result composition and recovery usable through the public Chio runtime without application-specific authority code.
**Architecture:** Keep D1/S1 validation and native ownership. Add a typed client, concrete control-plane composition and qualified D1 persistence; the runtime command index remains a projection.
**Tech Stack:** Rust 2021, existing SQLite authority stores, canonical JSON and native admission.
**Spec:** [work runtime](../specs/2026-10-03-work-runtime-design.md), [parent architecture](../specs/2026-10-03-agentic-work-kernel-design.md).

## Global Constraints

- Reuse existing capability, treaty, D1, S1, native custody, process and payment authorities. No second execution or recovery authority.
- Wire values are untrusted; checked/verified/private ownership types are separate.
- Preserve original request identities and distinct digest meanings. Queries, historical reconciliation and result release are different operations.
- Work request frames are at most 2 MiB and response frames at most 8 MiB. D1's 65,536-byte nested envelope and MAX_UNITS = 9,007,199,254,740,991 stay unchanged.
- No new unsafe Rust, permissive security-trait defaults, ambient clock reads or blocking store/network calls on an async reactor.
- Apply all [parent constraints](../specs/2026-10-03-agentic-work-kernel-design.md#global-constraints).

## Review Focus

- Restored/copied allocator or stale serving lease restores spendable allowance: reject before mutation (W1.2).
- Issuer commits preparation but response/index write is lost: resolve original issuance before any new artifact (W1.4).
- Seal is replayed after expiry: historical bytes remain readable under authorized history access, fresh dispatch stays denied (W1.2).
- A successful graph extension is retried after another extension: exact archived candidate identifies the original success, no fresh extension (W1.6).
- Current caller is revoked during delayed response delivery: metadata and result release recheck their owning authority, historical settlement stays separate (W1.6).

Before every implementation merge, run full library and integration suites for every changed crate, strict all-target Clippy with `-D warnings`, `cargo fmt --all --check`, and the required security/hygiene gates. Focused RED/GREEN tests supplement these checks. Hosted qualification is a separate release boundary.

All owned shapes use v1, with structural rejection of superseded shapes. Each SQLite store has one v1 schema and exact `StaleSchema` refusal for a mismatching stamp. Wipe and reprovision development databases with retired shapes; do not add importers, schema ladders or alternate writers.

## W1.0: Source and authority inventory

**Files:** [INTEGRATION.md](../../research/work-abstraction/INTEGRATION.md), [CURRENT-STATE.md](../../research/work-abstraction/CURRENT-STATE.md), [SOURCES.json](../../research/work-abstraction/SOURCES.json).

**Result:** exact source pins, real constructors and visibility, exhaustive request/custody projection, separate digest domains, issuer-original-ID gaps, feature/bound inventory, and the a/b dependency split below. Source inspection establishes no runtime or release acceptance.

- [x] Identify current main and separately pinned work/recovery inputs; distinguish existing functions from required extensions.
- [x] Inventory serving ownership, capability issuance, native process/nonce custody, D1 and S1 prerequisites, manifest/treaty verification and pending semantic/artifact owners.
- [x] Record all ToolCallRequest fields, final-request construction order and distinct digest/custody meanings.
- [x] Record current frame/substrate limits, the proposed bounded Work profile, and feature dependencies without asserting that defaults are chain-free.
- [x] Split W1.3 and W1.4 as well as W1.5 and W1.6. Bind every deferred case to its actual owner.

Baseline runtime qualification belongs to the first implementing slice after its source prerequisites land: run full `chio-workflow`, `chio-runtime-core` and `chio-kernel` library/integration suites, including the substrate's dynamic delegation and swarm-extension cases. These suites are not claimed as executed by this documentation inventory. A nonexistent test target or pending owner cannot count as a passing baseline.

Acceptance: an implementer can identify the real construction and mutation boundary for each planned operation, its missing dependency and exact refusal/recovery oracle.

## W1.1: Checked contracts and the public client boundary

**Files:**

- Modify: crates/kernel/chio-runtime/src/stores.rs, src/lib.rs, Cargo.toml.
- Modify: crates/kernel/chio-runtime-core/src/lib.rs, Cargo.toml.
- Create: crates/kernel/chio-runtime/src/work.rs.
- Create: crates/kernel/chio-runtime-core/src/work/mod.rs, wire.rs, types.rs, error.rs.
- Test: crates/kernel/chio-runtime/tests/work_public_surface.rs.
- Extend: crates/kernel/chio-runtime-core/tests/runtime_admission/swarm_evolution.rs.
- Define shared wire/schema vectors for W2/W3 using existing spec-codegen/conformance machinery.

**Interfaces:**

- Graph extension goes through the qualified issuer, SqliteWorkGraphStore::advance; runtime admission reads issued versions through chio_runtime::IssuedSwarmGraphs.
- Checked WorkPreparationV1, WorkPreparedV1, WorkCommandV1, WorkActionV1, WorkCommandResultV1, WorkQueryV1, WorkHandleV1, WorkGraphDraftRefV1, WorkCommitmentV1, WorkFundingRefV1 and WorkViewV1 follow the spec's closed outcomes.
- Add checked WorkProfileRefV1, WorkProfileV1, WorkCatalogPageV1, WorkAcceptanceV1, WorkRecoveryLinkV1, WorkJoinDraftRefV1 and WorkJoinInputsV1 using the spec's exact field/binding contracts. Native artifact/recovery reference representations stay owned by the recovery lane.
- WorkRequestV1 is the shared Prepare/Submit/Query transport body; WorkResponseV1 has the matching Prepared/Command/Query results. Use these same closed envelopes in every transport and SDK.
- WorkQueryResultV1 is Preparation(WorkPreparedV1), Command(WorkCommandResultV1), Work(WorkViewV1), Catalog(WorkCatalogPageV1), Profile(WorkProfileV1), or Unavailable with a scoped stable reason. Missing is not a native absence proof.
- WorkClient<T: WorkTransport>::prepare(proposal), submit(command) and query(query) are async and return Result<the corresponding result, WorkClientError>. inspect(handle) is only a convenience for a Work query.
- WorkTransport::exchange(&self, request: WorkRequestBytes) -> impl Future<Output = Result<WorkResponseBytes, WorkTransportError>> + Send is a bounded byte exchange. Transport errors preserve the original reference and never auto-resubmit. It has no security-policy default methods.
- Trusted errors preserve source chains. Exported rejections use distinct rule codes for schema, bounds, audience, role, binding field, stale version, expiry, revocation and unsupported profile. Unknown native effect is observation data, not an error suggesting retry.

- [ ] Add facade-import and compile-fail cases: callers cannot construct verified bindings/native owners or WorkSession from JSON. Preserve explicit exports and existing historical signed vectors.
- [ ] Add closed-outcome and checked-constructor vectors, invalid identifier/digest domain conversions, exact maximum/one-over bounds, nested duplicate keys and unknown variants. Verify rejection codes identify the exercised rule.
- [ ] Add profile generation/cursor vectors (64 entries accepted, 65 rejected), Join draft/Extend vectors, Accepted/Rejected versus unavailable acceptance, and scoped recovery links. Pin join-input canonical ordering and reject duplicate parent task/receipt identities. A client cannot turn a profile, acceptance or recovery reference into a verified owner type.
- [ ] Run cargo test --locked -p chio-runtime --features work --test work_public_surface. Expect missing feature/API before implementation.
- [ ] Implement wire/checking separation, typed client and graph extension wrapper. Use existing strict readers and canonicalization; preserve raw signed artifacts through their owner's decoder.
- [ ] Run the new test, cargo test --locked -p chio-runtime --test runtime_boundary, and owning swarm_evolution tests. Competing extensions must preserve existing consumed-continuation checks.
- [ ] Commit: feat(runtime): expose checked work contracts and client boundary.

Acceptance: AW01/AW03/AW21. A downstream client uses the public facade. A transport implementation cannot construct native authority.

## W1.2: Qualify allocation and graph issuance ownership

**Files:**

- Extract shared D1 rules into: crates/platform/chio-workflow/src/delegation/transition.rs; update mod.rs and store.rs.
- Create: crates/platform/chio-store-sqlite/src/delegation_store.rs and delegation_store/schema.rs.
- Create: crates/platform/chio-store-sqlite/src/work_graph_store.rs for the qualified S1 issuer head/archive, reusing chio-swarm-authority verification and existing signed record formats. Runtime graph storage remains an evidence lookup source.
- Modify: crates/platform/chio-store-sqlite/src/lib.rs, Cargo.toml and serving_owner.rs.
- Extend owning continuity catalogs: serving_owner/global_commit_chain.rs, its schema_migration.rs, and the actual projection/snapshot/relocation modules identified in W1.0.
- Test: crates/platform/chio-store-sqlite/tests/work_delegation_authority.rs and work_graph_authority.rs.

**Interfaces:**

- SqliteAuthorityStore::delegation_store() returns a store-bound adapter using the existing serving connection and owner. No production open(path) constructor.
- SqliteDelegationStore::{subdivide, select, seal_dispatch} preserve D1 payloads and results, and require the current serving fence plus an immutable scoped command/digest binding. Use the selected source's qualified mutation entrypoints.
- historical_dispatch(&self, binding: &DispatchBinding) -> Result<Option<Signed<DispatchPermit>>, DelegationStoreError> is read-only and accessible only through authorized host history queries. It verifies stored bytes/bindings without granting fresh liveness.
- SqliteAuthorityStore::work_graph_store() exposes qualified expected-head advancement and original issuance readback. It uses verify_swarm_authority_extension and the existing S1 head/archive contract; graph signing/publication composes through W1.4.
- Route every D1/S1 producer through the qualified owner and delete superseded allocator writers. Runtime graph lookup remains an evidence projection, never an alternate issuer.

- [ ] Add tests for stale fence, changed/copy-restored store, missing table/namespace, concurrent over-allocation, changed command body and selection after seal. Assert rejection before authority expansion, not only a returned error.
- [ ] Add live seal replay, history read after expiry, and death between claim and permit persistence. Assert identical retained bytes where a permit exists; absent historical permit stays absent and capacity remains consumed. Fresh dispatch after expiry fails.
- [ ] Add graph tests for two competing drafts, copied issuer state, stale fence and missing history. Assert one committed head and unchanged allowance/history after the rejected mutation. Receiver/cache graph import cannot acquire issuer rights. W1.4 tests actual signature publication.
- [ ] Run cargo test --locked -p chio-store-sqlite --test work_delegation_authority --test work_graph_authority. Expect missing qualified adapters.
- [ ] Implement fenced transactions, SQL allowance/revision predicates and registered authority projections. Preserve all D1 validation in shared functions; colocation alone does not qualify new tables.
- [ ] Provision one v1 schema and add exact StaleSchema tests for every retired stamp, plus current-format reopen and incomplete-namespace refusal. Wipe and reprovision development databases with retired shapes. Preserve current-format namespace, digest and permit bytes on ordinary reopen.
- [ ] Run the new suite, owning serving-owner integrity/schema-refusal tests and existing chio-workflow/dynamic_delegation tests.
- [ ] Commit: feat(work): bind delegated allocation to serving authority.

Acceptance: AW02/AW03/AW22. D1 and S1 retain their contracts and gain explicit production issuance ownership. No whole-domain Byzantine rollback claim is introduced.

## W1.3a: Resolve manifest and treaty profiles

**Dependencies:** W1.1; D1-specific contract fields also require the work substrate. No recovery generation is synthesized.

**Files:** create `crates/platform/chio-control-plane/src/work/{mod,host,session,profiles}.rs`, register the opt-in feature, and add `tests/work_profiles.rs`; extend runtime-core work DTOs only for the resolved contract.

**Interfaces:** planned async `WorkService::resolve_profile(&self, session: &WorkSession, profile_ref: &WorkProfileRefV1) -> Result<WorkProfileV1, WorkServiceError>` and `catalog(&self, session: &WorkSession, catalog_ref: &AdmissionIdentifier, cursor: Option<&AdmissionIdentifier>) -> Result<WorkCatalogPageV1, WorkServiceError>`. `WorkSession` is privately constructed by authenticated ingress. Both methods are read-only projections of provisioned records.

- [ ] Add `resolved_profile_preserves_manifest_and_treaty_basis`: exact manifest/tool/account, source digest, D1 contract, evaluator procedure and configured treaty terms survive resolution; count zero issuer, dispatch and funding mutations.
- [ ] Add `catalog_scope_and_generation`: 64 entries accepted, 65 refused; private-policy/tenant canaries absent; opaque cursor binds caller and catalog generation; a changed generation returns exact stale-catalog refusal.
- [ ] Add `unsupported_semantic_profile_is_unavailable`: no synthetic generation or recovery capability fills an absent owner.
- [ ] Retain the failing tests, implement over the verified manifest registry and configured treaty scope in the inventory, then run the tests and full changed-crate merge checks.

Acceptance: bounded owner-approved manifest/treaty queries. Complete AW26/LC01 also requires W1.3b.

## W1.3b: Resolve retained semantic generations

**Dependencies:** W1.3a and qualified recovery semantic installation/registry owners.

**Files:** extend `work/profiles.rs` and `tests/work_profiles.rs`.

**Interfaces:** use the actual `read_semantic_installation` and `compile_semantic_registry` contracts from the pinned recovery source after they land. `SemanticDeploymentV1` is the pending source type. A compiled registry is evidence, not a native capture witness.

- [ ] Add `resolved_profile_preserves_each_authority_basis`, `stale_generation_refuses_resolution` and `remote_claim_is_not_local_enforcement`: preserve exact installed generation, issuer/exposure binding, package digests, acceptance policy and supported recovery behavior; reject stale/unsupported current terms.
- [ ] Resolve only owner-retained generations, redact protected rules, and carry the exact authoritative basis into preparation. A request cannot select roots, endpoints, deployment activation or registry contents.
- [ ] Run the profile tests, owning semantic-installation tests and full changed-crate merge checks. Keep AW26/LC01 open until these real-owner checks pass.

## W1.4a: Durable owner preparation and pure bindings

**Dependencies:** W1.2, W1.3a and the D1/S1 substrate. Original-ID issuance belongs to each issuer and does not wait for a generic recovery adapter.

**Files:** create runtime-core `src/work/bindings.rs`, control-plane `src/work/{preparation,allocation}.rs`, `tests/work_allocation.rs` and `tests/work_preparation.rs`; extend only the owning issuer/custody modules identified in the inventory.

**Interfaces:** planned pure `validate_work_bindings(commitment: &WorkCommitmentV1, material: &ResolvedWorkMaterial, policy: &WorkBindingPolicy) -> Result<CheckedWorkBindings, WorkBindingError>` and async `WorkService::prepare(&self, session: &WorkSession, proposal: WorkPreparationV1) -> Result<WorkPreparedV1, WorkServiceError>`. Checked bindings have private construction and grant no native authority. Graph preparation retains an unsigned draft; issuer commitment precedes publication of signed successors.

- [ ] Port receiver/request/slot/allocation/route substitution cases from the separately pinned work composition. Replace fixture root, price, currency and route assumptions with explicit owner-approved bindings; assert exact refusal and zero native dispatch.
- [ ] Add role-confusion, same-ID concurrent issuance, changed-body conflict and expired-role cases. Inject failure before issuance, after issuer commit/before index, and after index/before response; remove the coordinator index. Count actual issuer operations and assert original body, validity, signature and issuance ID are retained once.
- [ ] Add competing graph-draft tests: a losing CAS exposes no signed successor; retained original success remains readable after a subsequent extension. The existing already-signed-candidate CAS alone cannot satisfy this contract.
- [ ] Add configured-peer, stale-profile-after-lookup and wrong-treaty-participant controls using `TreatyScope`, `compute_ladder_intersection` and `evaluate_cross_boundary_admission`. Requests cannot replace trust, account, role or purpose.
- [ ] Implement issuer-local intent/readback and pure bindings. No transaction spans remote signing I/O; ambiguity queries the same issuer reference. `SqliteCapabilityAuthority::issue_capability` alone is insufficient because it creates a new UUID and exposes no original-body readback.
- [ ] Refuse preparation variants requiring absent semantic/custody owners. Use the supported D1/S1 owner operations without application signing keys, then run allocation/preparation, dynamic delegation and full changed-crate checks.

Acceptance: AW02/AW03/AW23 for the supported issuer operations. Complete AW24/AW27 also requires W1.4b. No parallel Work signing authority is introduced.

## W1.4b: Exact native request custody

**Dependencies:** W1.4a, W1.3b and qualified recovery process reservation/origin/native authority owners.

**Files:** extend `work/preparation.rs`, `work/bindings.rs`, the owning custody adapter and `tests/work_preparation.rs`.

- [ ] Add `complete_request_retains_original_custody`: reserve logical identity, assemble all 16 request fields in the inventory's order, retain the final nonce/caller/flow/semantic bindings, then sign the final request commitment. Preserve each distinct digest domain.
- [ ] Add loss between reservation, native custody creation, finalization and response. Resolve through the same reservation, request and original native operation, never another preparation or invocation.
- [ ] Add `unused_approved_peer_needs_no_application_signing`, stale semantic/profile basis, wrong receiver and changed request tests through actual native preparation. Each refusal occurs before issuance or capture as appropriate, with no unauthorized result release.
- [ ] Compose the actual `RecoveryProcessReservationPort`, `RecoveryProcessOriginPort` and `RecoveryAuthorityPort` after those interfaces land; do not implement proposed shadow ports. Use configured custody and revalidate mutable authority at native commitment.
- [ ] Run preparation, exact-binding/nonce and full changed-crate tests. Agreement preparation remains W2.3.

Acceptance: complete AW24/AW27 requires this owner-composed request, not a caller-assembled JSON envelope.

## W1.5a: Exact acceptance evidence and join input validation

**Dependencies:** W1.4a and the D1 evaluator/S1 substrate.

**Files:** create control-plane `src/work/{acceptance,joins}.rs`, tests `work_acceptance.rs` and `work_joins.rs`; extend runtime-core work types/bindings.

**Interfaces:** planned `WorkAcceptanceV1` projects the original contract's producer, artifact/version, procedure, evaluator, decision and evidence. `WorkJoinInputsV1` validation sorts unique parents by task ID and derives its RFC 8785 digest. Neither result carries release authority.

- [ ] Add `decision_binds_exact_artifact_procedure_and_evaluator`: wrong producer operation/task, artifact/version, procedure, evaluator or fabricated success returns its exact refusal. Equal bytes from another task do not establish acceptance; native Allowed leaves it unavailable without evaluator evidence.
- [ ] Add `unpaid_evaluator_is_receipted_work`: passing/failing Equals and IntegerRange, the 16-clause ceiling, changed bytes, lost evaluator acknowledgement and explicit resource accounting. Use ordinary registered-tool requests and retained native receipts, never injected Accepted observations.
- [ ] Add duplicate-parent, duplicate-receipt, canonical ordering, maximum-parent and one-over tests. Querying acceptance invokes no checker or native effect.
- [ ] Implement exact evidence projection and pure manifest validation; run these tests plus full changed-crate checks. A missing protected materializer returns unavailable and cannot produce a usable signed join.

Acceptance: exact acceptance projection only. Full AW28/LC02 requires W1.5b.

## W1.5b: Protected materialization and qualified join publication

**Dependencies:** W1.5a, W1.3b/W1.4b and qualified recovery semantic/knowledge owners.

**Files:** extend `work/joins.rs`, `work/preparation.rs`, qualified `work_graph_store.rs` and its integrity inventory, plus `work_joins.rs`.

- [ ] Add `accepted_is_not_released_or_current`: changed current resource/version, expired reservation and revoked recipient deny dependent capture/release. Historical fact, current predicate and held reservation remain distinct actual owner types.
- [ ] Add `all_success_requires_verified_parents` and `join_draft_publication_is_atomic`: validate exact producer/evaluator evidence and protected input digest before signing; lose a graph CAS and expose no usable successor; lose an acknowledgement and read the exact original artifacts.
- [ ] Retain the manifest through `NativeKnowledgeRuntime` after that owner lands, preserving source confidentiality/influence. Enforce its 16 direct dependencies and full recovery-scope equality. Cross-scope inputs remain unsupported until their owning transfer/release contract is implemented and qualified; never weaken the materializer or pretend the Boolean confined-return profile is a general artifact transport.
- [ ] Bind the protected manifest to actual native semantic prerequisites. Commit the exact Join/continuation/bundle artifacts under the qualified graph owner before publishing signatures. Revalidate recipient and prerequisite authority at release/capture.
- [ ] Run real materializer/knowledge, acceptance/join, graph-integrity and full changed-crate tests. No boolean test double closes the dependency.

Acceptance: AW28/LC02 at the composed native boundary, with no second acceptance ledger.

## W1.6a: Scoped indexes and original issuer readback

**Dependencies:** W1.4a/W1.5a and qualified work issuer owners.

**Files:** create runtime-core `src/store/sqlite/work_commands.rs`, control-plane `src/work/query.rs`, and `tests/work_queries.rs`; extend their modules.

**Interfaces:** planned `record_work_command(scope: &WorkCommandScope, command: &WorkCommandV1) -> Result<WorkCommandRecord, ChioRuntimeError>` retains immutable digest, stage and owner references only. Planned async `WorkService::query(session, query) -> Result<WorkQueryResultV1, WorkServiceError>` returns authorized projections. A missing index is not evidence of no effect.

- [ ] Add scoped command/preparation queries with no received handle, changed-body conflict, tenant/metadata canaries and current role revocation. Count zero invoke, evaluator and reconcile calls.
- [ ] Remove the projection after issuer commitment. Resolve the exact original ID at the owning issuer, preserving signed artifacts. Interleave successful graph extensions A and B, lose A's reply, and resolve A's archived candidate without changing B or continuation state.
- [ ] Expose only supported W1.3a profiles and W1.5a evidence. Absent semantic/recovery observations stay unavailable, with no new Work workflow identity.
- [ ] Use bounded blocking execution and queues for owner SQLite reads; verify a blocked owner does not starve unrelated queries. Run query/issuer tests and full changed-crate checks.

Acceptance: original issuer readback and read-only audience-safe queries. Native submission/recovery acceptance remains open.

## W1.6b: Original native submission and recovery composition

**Dependencies:** W1.6a, W1.3b/W1.4b/W1.5b and qualified REC.

**Files:** create/extend control-plane `src/work/{dispatch,recovery,query}.rs` and `tests/work_recovery.rs`.

**Interfaces:** planned async `WorkService::apply(session, command) -> Result<WorkCommandResultV1, WorkServiceError>`. The adapter consumes the actual reservation/origin/authority owners and `RecoveryRuntime` protocol in the inventory. Reconcile calls historical owners; result release calls knowledge/confined-return owners. Query never starts either operation.

- [ ] Inject lost acknowledgement after command retention, process reservation, native admission/outcome and before delivery; reopen fresh processes and delete the command projection. Preserve original process operation key, request, nonce and native operation and observe one external effect.
- [ ] Add exact UnknownEffect refusal/readback controls. Work uses `ProcessRuntime::invoke_known_only`, never ordinary `invoke`'s optional fresh read-only retry. Timeouts, cancellation and missing projection cannot trigger another dispatch.
- [ ] Add cancellation/role revocation at handoff, delayed response, denied current result read and historical settlement after caller expiry. Metadata and bytes have separate release checks and contain no protected canaries.
- [ ] Add `scoped_link_preserves_recovery_owner`: explain a refusal through its permitted native workflow, reject another audience and a stale generation, preserve the same workflow/command ID across lost responses, and assert Work query/reconcile cannot select an offer or resume an effect.
- [ ] Use bounded owner execution with blocked-provider and supervised shutdown tests: unrelated operations progress, and cancellation/drop leaves original committed ownership intact.
- [ ] Run work recovery, durable admission, exact binding/nonce/historical settlement, knowledge release and full changed-crate merge checks.

Acceptance: AW04/AW05/AW10/AW23/AW25/AW29 through the real owning stores. Execution, acceptance, recovery, current release, payment and bilateral delivery remain separate observations.

## W1.7: Public-client conversion and focused review

**Files:**

- Modify: examples/federated-work/Cargo.toml, src/funded_work/evolving.rs and evolving/graph.rs.
- Update: crates/kernel/chio-runtime/README.md and ARCHITECTURE.md.
- Create: docs/reference/WORK_PROGRAMMING.md.
- Extend: crates/kernel/chio-runtime/tests/work_public_surface.rs.

**Interfaces:** Public WorkClient and an in-process transport invoking the same authenticated WorkService entrypoint for local Rust embedding. W2 supplies remote HTTP transport and funding; W3 mounts the negotiated physical worker IPC. In-process evidence does not qualify installed SDK transport.

- [ ] Build a downstream consumer using only the facade and documented client dependencies. Convert the unpaid application path to prepare/submit/query and existing result-release operations.
- [ ] Document original-ID resolution, metadata visibility, historical reconciliation and current result access. No application-specific authority verifier or native-store write is allowed.
- [ ] Include Catalog/Profile, evaluator evidence, Join draft/Extend and existing recovery-client navigation in the downstream example. Document the a/b dependency boundaries and LC01-LC06 acceptance ownership for the W2/W3 handoff.
- [ ] Run full library and integration suites for every changed crate with the enabled work features. Run cargo clippy --locked -p chio-runtime -p chio-runtime-core -p chio-control-plane --features chio-runtime/work,chio-runtime-core/work,chio-control-plane/work --all-targets -- -D warnings and cargo fmt --all -- --check.
- [ ] Compare default/isolated/unified feature graphs against W1.0. Run the owning dependency-direction, module-size, source/secret and MSRV checks without changing baselines. No new hand-maintained include! or generic framework.
- [ ] Review public API, actual authority construction, stale-schema refusal and effects. Record exact commands/source hashes and pending W2/recovery dependencies.
- [ ] Commit: docs(runtime): document and exercise the reusable work contract.

Stop condition: W1 qualifies the reusable local contract. Remote peers, payment deployment, adapter coverage and beta release remain their own acceptance boundaries.
