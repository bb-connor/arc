# Reusable Work Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax. Preserve the designated third-lane owner and do not independently edit active security or recovery worktrees.

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

The approved lifecycle refinements add W1.3 (resolved profiles) and W1.5 (acceptance/joins). Existing preparation, query and conversion tasks move to W1.4, W1.6 and W1.7 respectively. Their original authority requirements remain in force. LC01 through LC06 are defined in the [developer specification](../specs/2026-10-03-work-developer-surface-design.md#required-composition-cases).

## W1.0: Reconcile the implementation base and authority inventory

**Files:** Update docs/research/work-abstraction/SOURCES.json and CURRENT-STATE.md in the implementation branch; create docs/research/work-abstraction/INTEGRATION.md.

**Interfaces:** One integration commit; actual landed security/recovery types, construction sites, persistence owners, mutation/readback methods, feature graph and required checks. Proposed recovery names are not executable stubs.

- [ ] Refresh accepted security/recovery commits. Record unpublished/uncommitted work and unresolved ports separately. Preserve current strict readers, clocks, qualified stores and source/module conventions while porting work changes.
- [ ] Record existing authority constructors and exports, including SqliteAuthorityStore, WorkerService/InvocationPreparer, recovery custody/ports, S1 CAS/archive and native payment journals. Identify the smallest extension at each missing seam.
- [ ] Map signed manifests, semantic registry generations, treaty intersection/admission, native evaluator receipts, S1 join minting and protected artifact materialization to their actual owners. Record which evidence establishes each acceptance claim; signature validity alone is insufficient. Map recovery protocol references and dependency categories without introducing duplicate types.
- [ ] Freeze an exhaustive ToolCallRequest field/digest/custody table against the actual joined source. Name process, retained-material, approval/flow and full F1 digest algorithms separately. Record the canonical request assembly order.
- [ ] Choose concrete aggregate collection, nesting, verification-work, queue/concurrency and deadline bounds using existing host/profile limits. Record exact values in the spec and shared vectors before W1.1 freezes a schema. Existing D1 per-parent/root limits are 64/4096; no work limit may silently increase them.
- [ ] Record baseline cargo metadata/feature trees for runtime, control-plane, process, workflow and settle. No crate cycle or new unconditional chain dependency is allowed; existing defaults are not presumed chain-free.
- [ ] Run the focused baseline: cargo test --locked -p chio-workflow; cargo test --locked -p chio-runtime-core --test runtime_admission; cargo test --locked -p chio-kernel --features admission-test-support --test dynamic_delegation. Record failures before changes.
- [ ] Commit source reconciliation with actual SHA and pending recovery dependencies.

Acceptance: implementers have concrete owner/API mappings. Pure contracts may proceed while a recovery port is pending; dependent behavior remains unaccepted.

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

- Public SQLite wrapper: extend_swarm_authority_bundle(&self, expected_bundle_sha256: &str, candidate: SwarmAuthorityBundle, trusted_keys: &[PublicKey]) -> Result<(), ChioRuntimeError>, delegating to the existing implementation.
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
- Retain legacy DelegationStore and runtime graph CAS as historical/example or trusted embedding adapters; they do not establish beta serving ownership by themselves.

- [ ] Add tests for stale fence, changed/copy-restored store, missing table/namespace, concurrent over-allocation, changed command body and selection after seal. Assert rejection before authority expansion, not only a returned error.
- [ ] Add live seal replay, history read after expiry, and death between claim and permit persistence. Assert identical retained bytes where a permit exists; absent historical permit stays absent and capacity remains consumed. Fresh dispatch after expiry fails.
- [ ] Add graph tests for two competing drafts, copied issuer state, stale fence and missing history. Assert one committed head and unchanged allowance/history after the rejected mutation. Receiver/cache graph import cannot acquire issuer rights. W1.4 tests actual signature publication.
- [ ] Run cargo test --locked -p chio-store-sqlite --test work_delegation_authority --test work_graph_authority. Expect missing qualified adapters.
- [ ] Implement fenced transactions, SQL allowance/revision predicates and registered authority projections. Preserve all D1 validation in shared functions; colocation alone does not qualify new tables.
- [ ] Implement explicit quiesced import with exact namespace/digest/permit preservation and retirement of the old writer. Add migration/reopen/downgrade-refusal vectors; do not import untrusted provenance as verified history.
- [ ] Run the new suite, owning serving-owner integrity/migration tests and existing chio-workflow/dynamic_delegation tests.
- [ ] Commit: feat(work): bind delegated allocation to serving authority.

Acceptance: AW02/AW03/AW22. D1 and S1 retain their contracts and gain explicit production issuance ownership. No whole-domain Byzantine rollback claim is introduced.

## W1.3: Resolve owner-approved working contracts

**Files:**

- Create: crates/platform/chio-control-plane/src/work/mod.rs, host.rs, session.rs and profiles.rs; register the module/feature in src/lib.rs and Cargo.toml. Define the concrete WorkService and private authenticated WorkSession here; later tasks extend their methods.
- Extend: crates/kernel/chio-runtime-core/src/work/types.rs and wire.rs from W1.1 only for defects found by the concrete resolver.
- Reuse: crates/platform/chio-manifest/src/lib.rs, crates/trust/chio-federation/src/treaty.rs, and the landed semantic registry mapped in W1.0.
- Test: crates/platform/chio-control-plane/tests/work_profiles.rs.

**Interfaces:** WorkService::resolve_profile(&self, session: &WorkSession, profile_ref: &WorkProfileRefV1) -> Result<WorkProfileV1, WorkServiceError> is async/read-only. WorkService::catalog(&self, session: &WorkSession, catalog_ref: &AdmissionIdentifier, cursor: Option<&AdmissionIdentifier>) -> Result<WorkCatalogPageV1, WorkServiceError> is async/read-only. Use semantic wrappers where the existing identifier grammar matches. Both resolve provisioned snapshots; W1.6 routes the corresponding query variants and W2.1 supplies production configuration.

- [ ] Add work_profiles::resolved_profile_preserves_each_authority_basis: assert exact manifest/tool/account, semantic generation, treaty terms, D1 bounds, acceptance procedure/evaluator and optional funding references from the configured source records.
- [ ] Add work_profiles::catalog_scope_and_generation: assert at most 64 entries/page, no cross-tenant/private-policy canaries, stable generation across pages and typed stale-catalog on reload. Changed endpoint/key/profile digest cannot be supplied as configuration by a query.
- [ ] Add work_profiles::stale_generation_refuses_resolution and work_profiles::remote_claim_is_not_local_enforcement. Assert stale/unsupported current terms refuse and a provider signature does not promote remote behavioral claims to verified local guarantees. W1.4 separately tests a generation change after successful resolution and before preparation.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_profiles. Expect the missing resolver before implementation.
- [ ] Implement a resolved projection over existing immutable registries and configured catalog references. Verify manifest identity through its existing verifier; compile no new policy language. Carry source-generation provenance into the retained preparation basis without returning credentials or protected rules.
- [ ] Re-run the suite and existing manifest/treaty checks; count zero issuer, dispatch and funding mutations during every Catalog/Profile query.
- [ ] Commit: feat(work): resolve owner-approved work profiles.

Acceptance: AW26 and the local LC01 basis. Querying working terms cannot create authority; native preparation still revalidates their applicability.

## W1.4: Owner preparation and shared binding validation

**Files:**

- Create: crates/kernel/chio-runtime-core/src/work/bindings.rs.
- Create: crates/platform/chio-control-plane/src/work/preparation.rs and allocation.rs.
- Extend: work/mod.rs, host.rs and session.rs from W1.3, plus crates/platform/chio-control-plane/src/lib.rs and Cargo.toml as needed.
- Extend only the existing issuer/signing custody module identified in W1.0 if original-ID issuance is absent.
- Test: crates/platform/chio-control-plane/tests/work_allocation.rs and work_preparation.rs.

**Interfaces:**

- Concrete WorkService composes the configured native authorities. Internal WorkSession is constructed only after worker/ingress authentication.
- validate_work_bindings(commitment: &WorkCommitmentV1, material: &ResolvedWorkMaterial, policy: &WorkBindingPolicy) -> Result<CheckedWorkBindings, WorkBindingError> is pure. The result has private construction and proves cross-record checks only. Native guards verify authority and revalidate before dispatch.
- WorkService::prepare(&self, session: &WorkSession, proposal: WorkPreparationV1) -> Result<WorkPreparedV1, WorkServiceError> is async; application and query methods are supplied in W1.6.
- Preparation uses existing holder, receiver issuer, S1 builder and agreement services. Extend preparation returns WorkGraphDraftRefV1, an unsigned retained draft. Applying Extend uses the qualified S1 issuer, signs through configured custody, and publishes only the committed successor. Each role has retained exact-body issuance, original-ID readback and checked caller/program/purpose scope.
- Offer consumes W1.3's exact profile reference and retains its original authoritative basis with the issuance ID. Treaty checks use configured TreatyScope, compute_ladder_intersection and evaluate_cross_boundary_admission; the native receiver still checks current federation context. W1.5 adds the Join draft variant without changing this issuance discipline.

- [ ] Port composition::validate's receiver/request/slot/allocation/route substitution controls. Replace fixed root name, amount 100, XTS dimension and native route strings with validated program/root/currency/dimension/route profile bindings. Assert zero native dispatches for every rejected substitution.
- [ ] Add role-confusion and issuer-loss tests: before issuance, after issuer commit/before index write, after index write/before response, concurrent same-ID requests, changed body, expired role and missing coordinator index. Count actual issuer operations and retained bodies.
- [ ] Add competing graph-draft tests through the real service/signing boundary. The losing mutation returns no usable signed successor; restart/readback returns only the exact committed artifact.
- [ ] Add work_preparation::unused_approved_peer_needs_no_application_signing, stale_profile_after_lookup, and wrong_treaty_participant. Assert a valid configured candidate can produce an exact receiver offer, while changed generation, account, trust root or scope refuses before issuance. Resolve acknowledgement loss through the same issuer reference.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_allocation --test work_preparation. Expect absent composition/preparation methods.
- [ ] Implement shared binding checks and concrete role adapters. Persist exact issuer intent before publication; ambiguity queries the owner. No transaction spans remote key/service I/O.
- [ ] Exercise subdivision, offer, selection and extension without application private keys or graph builders. Use the W1.0 complete-request order and protected custody; agreement preparation lands in W2.3.
- [ ] Re-run focused tests and dynamic_delegation. Confirm existing guards perform final authority validation; the new checker is not an admission bypass.
- [ ] Commit: feat(work): compose owner-authorized preparation and bindings.

Acceptance: AW02/AW03/AW23/AW24/AW27. Applications prepare through owner services, and coordinator state loss cannot cause fresh issuance.

## W1.5: Project accepted results and prepare qualified joins

**Files:**

- Create: crates/platform/chio-control-plane/src/work/acceptance.rs and joins.rs; register in work/mod.rs.
- Extend: work/preparation.rs, qualified chio-store-sqlite/src/work_graph_store.rs and its owning projection/migration inventory from W1.2.
- Extend: crates/kernel/chio-runtime-core/src/work/bindings.rs and types.rs.
- Reuse: chio-workflow::delegation::Acceptance, chio-swarm-authority join minting/verifier, existing native tool/receipt and recovery artifact owners.
- Test: crates/platform/chio-control-plane/tests/work_acceptance.rs and work_joins.rs.

**Interfaces:** W1.4 WorkService::prepare handles Join and returns the unsigned WorkJoinDraftRefV1. The existing Extend path consumes join_draft_refs, then commits exact join/continuation/bundle artifacts before publishing them. WorkAcceptanceV1 is projected from the original contract's retained evaluator evidence. W1.6's query method consumes this projector; W2.3 supplies the F1 evidence adapter. WorkJoinInputsV1 and all_success have the exact bounded semantics in the runtime spec, with no arbitrary signer or predicate parameter.

- [ ] Add work_acceptance::decision_binds_exact_artifact_procedure_and_evaluator: assert Accepted only for the original contract's authorized, verified decision. Reject wrong producer task/operation, artifact/version, procedure, evaluator and fabricated success; equal output bytes from another task are insufficient. Native Allowed alone leaves acceptance pending/unavailable. Querying evidence dispatches no checker.
- [ ] Add work_acceptance::unpaid_evaluator_is_receipted_work tests for passing/failing Equals/IntegerRange, the existing 16-clause ceiling, changed artifact bytes, evaluator acknowledgement loss and explicit resource accounting. Require ordinary exact native request/output receipts, not a fixture-injected Accepted observation.
- [ ] Add work_joins::all_success_requires_verified_parents and join_draft_publication_is_atomic. Assert exact unique parents, protected input-manifest digest, no signing before all checks, no usable successor from a losing CAS, and identical original artifacts after issuer acknowledgement loss/index removal.
- [ ] Add work_joins::accepted_is_not_released_or_current: current data mutation, expired reservation, wrong resource/version and revoked recipient block dependent capture/release. Preserve source confidentiality and influence through the manifest. Use recovery's real dependency/materializer contracts, not mock boolean success.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_acceptance --test work_joins. Expect absent acceptance/join service behavior; retain unlanded recovery dependencies as pending.
- [ ] Implement exact evidence projection and owner-retained Join drafts. Expose Acceptance::check through an ordinary registered native evaluator tool, under explicit authority and accounting; application-specific checkers remain configured tool work. Materialize the metadata manifest through existing protected custody, sort unique parents by task_id, and derive result_digest with existing canonical JSON. Extend verifies the full S1 candidate and atomically retains signed artifacts under the qualified issuer before publication. Retain acceptance references without another authoritative acceptance ledger.
- [ ] Re-run the suites, existing swarm_authority_stage0/additive-growth checks and qualified graph-store integrity tests. Inspect actual issuance counts, native effects and denied result channels.
- [ ] Commit: feat(work): compose accepted results through qualified swarm joins.

Acceptance: AW28 and LC02's native boundaries. A signed parent or join statement is never treated as proof of an unevaluated semantic claim.

## W1.6: Original-operation queries and recovery composition

**Files:**

- Create: crates/kernel/chio-runtime-core/src/store/sqlite/work_commands.rs; extend its module/schema.
- Create: crates/platform/chio-control-plane/src/work/dispatch.rs, query.rs, recovery.rs.
- Test: crates/platform/chio-control-plane/tests/work_recovery.rs.
- Consume actual recovery ports mapped in W1.0; do not invent parallel implementations.

**Interfaces:**

- record_work_command(scope: &WorkCommandScope, command: &WorkCommandV1) -> Result<WorkCommandRecord, ChioRuntimeError> and lookup by scoped command/preparation reference retain digest, stage, phase and owner references only.
- WorkService::apply(session, command) -> Result<WorkCommandResultV1, WorkServiceError> and query(session, query) -> Result<WorkQueryResultV1, WorkServiceError> are async, using the spec's closed outcomes.
- Reconcile calls historical settlement/evidence owners; result release uses the actual existing recovery operation. Query never starts reconciliation.
- Use existing ProcessRecoveryPort/KernelRecoveryPort reservation, exact custody and original-operation resolution. Mutable policy/version/fence checks remain at their owning commitment.
- Catalog/Profile queries call W1.3; work queries project W1.5 acceptance plus existing recovery state independently of execution/payment. Eligible refusals carry WorkRecoveryLinkV1 from the owning recovery protocol. No work-layer Explain/Approve/Resume command or workflow identifier is added.

- [ ] Add lost-ack cutpoints after command retention, D1 mutation, process reservation, native admission/outcome and before delivery. Reopen in fresh processes and remove the coordination projection.
- [ ] Assert unchanged original request/native operation IDs and one external effect. UnknownEffect must not dispatch again. A query by command/preparation ID works even if no handle was received.
- [ ] Add interleaved A/B graph extension with lost A acknowledgement: resolve A by its exact archived candidate, preserving B and consumed continuation state.
- [ ] Add cancellation/role revocation at handoff, delayed query response, metadata canaries, denied result read and historical settlement after caller expiry. No raw output or forbidden topology/error detail may escape.
- [ ] Add work_recovery::scoped_link_preserves_recovery_owner: inspect a refusal without a work handle, follow its permitted native explanation/offer path, reject another audience's link and a stale generation, and assert query/reconcile never selects an offer or resumes an effect. Preserve the same workflow/command identity through lost responses.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_recovery. Retain the failing boundary before implementation.
- [ ] Implement immutable indexing and owner-specific readback per the spec's operation table. No generic retry or fresh ID. Durable owner records remain decisive even if the index is absent or corrupt.
- [ ] Use bounded blocking execution/queues for SQLite and synchronous native adapters. Add a blocked-provider test proving unrelated operations progress, and a supervised shutdown/abort test proving original ownership survives.
- [ ] Run work_recovery, existing durable_admission_sqlite and the recovery lane's exact-binding/nonce/historical-settlement tests.
- [ ] Commit: feat(work): preserve original identity through query and recovery.

Acceptance: AW04/AW05/AW10/AW23/AW25/AW29. Execution, acceptance, recovery, release, financial and bilateral observations remain separate; all mutations resolve at their owning authority.

## W1.7: Public-client conversion and focused review

**Files:**

- Modify: examples/federated-work/Cargo.toml, src/funded_work/evolving.rs and evolving/graph.rs.
- Update: crates/kernel/chio-runtime/README.md and ARCHITECTURE.md.
- Create: docs/reference/WORK_PROGRAMMING.md.
- Extend: crates/kernel/chio-runtime/tests/work_public_surface.rs.

**Interfaces:** Public WorkClient and an in-process transport invoking the same authenticated WorkService entrypoint for local Rust embedding. W2 supplies remote HTTP transport and funding; W3 mounts the negotiated physical worker IPC. In-process evidence does not qualify installed SDK transport.

- [ ] Build a downstream consumer using only the facade and documented client dependencies. Convert the unpaid application path to prepare/submit/query and existing result-release operations.
- [ ] Document original-ID resolution, metadata visibility, historical reconciliation and current result access. No application-specific authority verifier or native-store write is allowed.
- [ ] Include Catalog/Profile, evaluator evidence, Join draft/Extend and existing recovery-client navigation in the downstream example. Document both old-to-new task numbering and the LC01-LC06 acceptance ownership for the W2/W3 handoff.
- [ ] Run cargo test --locked -p chio-runtime --features work and focused control-plane work tests. Run cargo clippy --locked -p chio-runtime -p chio-runtime-core -p chio-control-plane --features chio-runtime/work,chio-runtime-core/work,chio-control-plane/work --all-targets -- -D warnings and cargo fmt --all -- --check.
- [ ] Compare default/isolated/unified feature graphs against W1.0. Run the owning dependency-direction, module-size, source/secret and MSRV checks without changing baselines. No new hand-maintained include! or generic framework.
- [ ] Review public API, actual authority construction, migration and effects. Record exact commands/source hashes and pending W2/recovery dependencies.
- [ ] Commit: docs(runtime): document and exercise the reusable work contract.

Stop condition: W1 qualifies the reusable local contract. Remote peers, payment deployment, adapter coverage and beta release remain their own acceptance boundaries.
