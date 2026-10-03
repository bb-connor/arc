# Reusable Work Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax. Preserve the designated third-lane owner and do not independently edit active security or recovery worktrees.

**Goal:** Make existing work construction usable through the public Chio runtime without example-specific authority code.
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
- Issuer commits preparation but response/index write is lost: resolve original issuance before any new artifact (W1.3).
- Seal is replayed after expiry: historical bytes remain readable under authorized history access, fresh dispatch stays denied (W1.2).
- A successful graph extension is retried after another extension: exact archived candidate identifies the original success, no fresh extension (W1.4).
- Current caller is revoked during delayed response delivery: metadata and result release recheck their owning authority, historical settlement stays separate (W1.4).

## W1.0: Reconcile the implementation base and authority inventory

**Files:** Update docs/research/work-abstraction/SOURCES.json and CURRENT-STATE.md in the implementation branch; create docs/research/work-abstraction/INTEGRATION.md.

**Interfaces:** One integration commit; actual landed security/recovery types, construction sites, persistence owners, mutation/readback methods, feature graph and required checks. Proposed recovery names are not executable stubs.

- [ ] Refresh accepted security/recovery commits. Record unpublished/uncommitted work and unresolved ports separately. Preserve current strict readers, clocks, qualified stores and source/module conventions while porting work changes.
- [ ] Record existing authority constructors and exports, including SqliteAuthorityStore, WorkerService/InvocationPreparer, recovery custody/ports, S1 CAS/archive and native payment journals. Identify the smallest extension at each missing seam.
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
- WorkQueryResultV1 is Preparation(WorkPreparedV1), Command(WorkCommandResultV1), Work(WorkViewV1), or Unavailable with a scoped stable reason. Missing is not a native absence proof.
- WorkClient<T: WorkTransport>::prepare(proposal), submit(command) and query(query) are async and return Result<the corresponding result, WorkClientError>. inspect(handle) is only a convenience for a Work query.
- WorkTransport::exchange(&self, request: WorkRequestBytes) -> impl Future<Output = Result<WorkResponseBytes, WorkTransportError>> + Send is a bounded byte exchange. Transport errors preserve the original reference and never auto-resubmit. It has no security-policy default methods.
- Trusted errors preserve source chains. Exported rejections use distinct rule codes for schema, bounds, audience, role, binding field, stale version, expiry, revocation and unsupported profile. Unknown native effect is observation data, not an error suggesting retry.

- [ ] Add facade-import and compile-fail cases: callers cannot construct verified bindings/native owners or WorkSession from JSON. Preserve explicit exports and existing historical signed vectors.
- [ ] Add closed-outcome and checked-constructor vectors, invalid identifier/digest domain conversions, exact maximum/one-over bounds, nested duplicate keys and unknown variants. Verify rejection codes identify the exercised rule.
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
- SqliteAuthorityStore::work_graph_store() exposes qualified expected-head advancement and original issuance readback. It uses verify_swarm_authority_extension and the existing S1 head/archive contract; graph signing/publication composes through W1.3.
- Retain legacy DelegationStore and runtime graph CAS as historical/example or trusted embedding adapters; they do not establish beta serving ownership by themselves.

- [ ] Add tests for stale fence, changed/copy-restored store, missing table/namespace, concurrent over-allocation, changed command body and selection after seal. Assert rejection before authority expansion, not only a returned error.
- [ ] Add live seal replay, history read after expiry, and death between claim and permit persistence. Assert identical retained bytes where a permit exists; absent historical permit stays absent and capacity remains consumed. Fresh dispatch after expiry fails.
- [ ] Add graph tests for two competing drafts, copied issuer state, stale fence and missing history. Assert one committed head and unchanged allowance/history after the rejected mutation. Receiver/cache graph import cannot acquire issuer rights. W1.3 tests actual signature publication.
- [ ] Run cargo test --locked -p chio-store-sqlite --test work_delegation_authority --test work_graph_authority. Expect missing qualified adapters.
- [ ] Implement fenced transactions, SQL allowance/revision predicates and registered authority projections. Preserve all D1 validation in shared functions; colocation alone does not qualify new tables.
- [ ] Implement explicit quiesced import with exact namespace/digest/permit preservation and retirement of the old writer. Add migration/reopen/downgrade-refusal vectors; do not import untrusted provenance as verified history.
- [ ] Run the new suite, owning serving-owner integrity/migration tests and existing chio-workflow/dynamic_delegation tests.
- [ ] Commit: feat(work): bind delegated allocation to serving authority.

Acceptance: AW02/AW03/AW22. D1 and S1 retain their contracts and gain explicit production issuance ownership. No whole-domain Byzantine rollback claim is introduced.

## W1.3: Owner preparation and shared binding validation

**Files:**

- Create: crates/kernel/chio-runtime-core/src/work/bindings.rs.
- Create: crates/platform/chio-control-plane/src/work/mod.rs, host.rs, preparation.rs, allocation.rs, session.rs.
- Modify: crates/platform/chio-control-plane/src/lib.rs, Cargo.toml.
- Extend only the existing issuer/signing custody module identified in W1.0 if original-ID issuance is absent.
- Test: crates/platform/chio-control-plane/tests/work_allocation.rs and work_preparation.rs.

**Interfaces:**

- Concrete WorkService composes the configured native authorities. Internal WorkSession is constructed only after worker/ingress authentication.
- validate_work_bindings(commitment: &WorkCommitmentV1, material: &ResolvedWorkMaterial, policy: &WorkBindingPolicy) -> Result<CheckedWorkBindings, WorkBindingError> is pure. The result has private construction and proves cross-record checks only. Native guards verify authority and revalidate before dispatch.
- WorkService::prepare(&self, session: &WorkSession, proposal: WorkPreparationV1) -> Result<WorkPreparedV1, WorkServiceError> is async; application and query methods are supplied in W1.4.
- Preparation uses existing holder, receiver issuer, S1 builder and agreement services. Extend preparation returns WorkGraphDraftRefV1, an unsigned retained draft. Applying Extend uses the qualified S1 issuer, signs through configured custody, and publishes only the committed successor. Each role has retained exact-body issuance, original-ID readback and checked caller/program/purpose scope.

- [ ] Port composition::validate's receiver/request/slot/allocation/route substitution controls. Replace fixed root name, amount 100, XTS dimension and native route strings with validated program/root/currency/dimension/route profile bindings. Assert zero native dispatches for every rejected substitution.
- [ ] Add role-confusion and issuer-loss tests: before issuance, after issuer commit/before index write, after index write/before response, concurrent same-ID requests, changed body, expired role and missing coordinator index. Count actual issuer operations and retained bodies.
- [ ] Add competing graph-draft tests through the real service/signing boundary. The losing mutation returns no usable signed successor; restart/readback returns only the exact committed artifact.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_allocation --test work_preparation. Expect absent composition/preparation methods.
- [ ] Implement shared binding checks and concrete role adapters. Persist exact issuer intent before publication; ambiguity queries the owner. No transaction spans remote key/service I/O.
- [ ] Exercise subdivision, offer, selection and extension without application private keys or graph builders. Use the W1.0 complete-request order and protected custody; agreement preparation lands in W2.3.
- [ ] Re-run focused tests and dynamic_delegation. Confirm existing guards perform final authority validation; the new checker is not an admission bypass.
- [ ] Commit: feat(work): compose owner-authorized preparation and bindings.

Acceptance: AW02/AW03/AW23/AW24. Applications prepare through owner services, and coordinator state loss cannot cause fresh issuance.

## W1.4: Original-operation queries and recovery composition

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

- [ ] Add lost-ack cutpoints after command retention, D1 mutation, process reservation, native admission/outcome and before delivery. Reopen in fresh processes and remove the coordination projection.
- [ ] Assert unchanged original request/native operation IDs and one external effect. UnknownEffect must not dispatch again. A query by command/preparation ID works even if no handle was received.
- [ ] Add interleaved A/B graph extension with lost A acknowledgement: resolve A by its exact archived candidate, preserving B and consumed continuation state.
- [ ] Add cancellation/role revocation at handoff, delayed query response, metadata canaries, denied result read and historical settlement after caller expiry. No raw output or forbidden topology/error detail may escape.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_recovery. Retain the failing boundary before implementation.
- [ ] Implement immutable indexing and owner-specific readback per the spec's operation table. No generic retry or fresh ID. Durable owner records remain decisive even if the index is absent or corrupt.
- [ ] Use bounded blocking execution/queues for SQLite and synchronous native adapters. Add a blocked-provider test proving unrelated operations progress, and a supervised shutdown/abort test proving original ownership survives.
- [ ] Run work_recovery, existing durable_admission_sqlite and the recovery lane's exact-binding/nonce/historical-settlement tests.
- [ ] Commit: feat(work): preserve original identity through query and recovery.

Acceptance: AW04/AW05/AW10/AW23/AW25. Execution, release, financial and bilateral observations remain separate; all mutations resolve at their owning authority.

## W1.5: Public-client conversion and focused review

**Files:**

- Modify: examples/federated-work/Cargo.toml, src/funded_work/evolving.rs and evolving/graph.rs.
- Update: crates/kernel/chio-runtime/README.md and ARCHITECTURE.md.
- Create: docs/reference/WORK_PROGRAMMING.md.
- Extend: crates/kernel/chio-runtime/tests/work_public_surface.rs.

**Interfaces:** Public WorkClient and an in-process transport invoking the same authenticated WorkService entrypoint for local Rust embedding. W2 supplies remote HTTP transport and funding; W3 mounts the negotiated physical worker IPC. In-process evidence does not qualify installed SDK transport.

- [ ] Build a downstream consumer using only the facade and documented client dependencies. Convert the unpaid application path to prepare/submit/query and existing result-release operations.
- [ ] Document original-ID resolution, metadata visibility, historical reconciliation and current result access. No application-specific authority verifier or native-store write is allowed.
- [ ] Run cargo test --locked -p chio-runtime --features work and focused control-plane work tests. Run cargo clippy --locked -p chio-runtime -p chio-runtime-core -p chio-control-plane --features chio-runtime/work,chio-runtime-core/work,chio-control-plane/work --all-targets -- -D warnings and cargo fmt --all -- --check.
- [ ] Compare default/isolated/unified feature graphs against W1.0. Run the owning dependency-direction, module-size, source/secret and MSRV checks without changing baselines. No new hand-maintained include! or generic framework.
- [ ] Review public API, actual authority construction, migration and effects. Record exact commands/source hashes and pending W2/recovery dependencies.
- [ ] Commit: docs(runtime): document and exercise the reusable work contract.

Stop condition: W1 qualifies the reusable local contract. Remote peers, payment deployment, adapter coverage and beta release remain their own acceptance boundaries.
