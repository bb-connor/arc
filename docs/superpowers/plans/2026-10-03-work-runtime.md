# Reusable Work Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax. Preserve the designated third-lane owner and do not independently edit the active security or recovery worktrees.

**Goal:** Make the existing work construction usable through the public Chio runtime without example-specific authority code.
**Architecture:** Extend chio-runtime and chio-runtime-core. Reuse D1/S1 and native process/capture ownership; the new orchestration index stores command references, never execution rights.
**Tech Stack:** Rust 2021, existing SQLite stores, canonical JSON, existing native admission.
**Spec:** [work runtime](../specs/2026-10-03-work-runtime-design.md), [parent architecture](../specs/2026-10-03-agentic-work-kernel-design.md).

## Global Constraints

- Reuse the existing capability, treaty, D1 allocation, S1 graph, native custody, process and payment authorities. No second execution or recovery authority.
- A work handle and every transported commitment are evidence or references. They never mint live authority or install trust.
- Preserve complete request bindings and original operation identities. Unknown effect, unavailable output, unpaid work and missing bilateral receipt are distinct facts.
- Preserve existing canonical signing domains and encodings.
- Work command frames are at most 2 MiB; work view frames are at most 8 MiB. D1's 65,536-byte nested limit remains.
- Apply all [parent constraints](../specs/2026-10-03-agentic-work-kernel-design.md#global-constraints).

## Review Focus

- Reused command ID with different arguments or another tenant: conflict/deny before mutation (W1.2).
- Lost acknowledgement after sealing: exact original permit, no second selection (W1.2).
- Competing graph extensions: one head wins and old continuation remains consumed (W1.1).
- Missing orchestration projection with native work already admitted: read original authority, no new request (W1.3).
- Expired caller trying to collect private bytes: financial history and current release authority remain separate (W1.3).

## W1.0: Reconcile the implementation base

**Files:** Update docs/research/work-abstraction/SOURCES.json and CURRENT-STATE.md in the implementation branch; create docs/research/work-abstraction/INTEGRATION.md.
**Interfaces:** Consumes the pinned work/security sources and PR #1172 contract; produces one named integration commit and a mapping to recovery ports.

- [ ] Refresh both active agents' accepted commits and actual recovery API landing paths. Record uncommitted/unpublished work separately.
- [ ] Compare source-changing work commits against the current security candidate. Preserve current strict readers, clock ports, evidence authority, fencing and module conventions while porting D1/S1/composition fixes. Do not bulk-replace security files with paper snapshots.
- [ ] Record the selected source and any recovery-dependent task still awaiting its real port. Keep that task pending; pure contracts/facade work may proceed.
- [ ] Run the existing focused baseline: cargo test --locked -p chio-workflow; cargo test --locked -p chio-runtime-core --test runtime_admission; cargo test --locked -p chio-kernel --features admission-test-support --test dynamic_delegation. Record failures before changing behavior.
- [ ] Commit the source reconciliation and record its actual SHA. Documentation-only input changes do not qualify native behavior.

Acceptance: the implementer knows which code is authoritative; no concurrent lane was overwritten. This task does not claim all security/recovery milestones are complete.

## W1.1: Expose the existing graph lifecycle and work vocabulary

**Files:**

- Modify: crates/kernel/chio-runtime/src/stores.rs, src/lib.rs, Cargo.toml.
- Modify: crates/kernel/chio-runtime-core/src/lib.rs, Cargo.toml.
- Create: crates/kernel/chio-runtime/src/work.rs.
- Create: crates/kernel/chio-runtime-core/src/work/mod.rs, types.rs, error.rs.
- Test: crates/kernel/chio-runtime/tests/work_public_surface.rs.
- Extend: crates/kernel/chio-runtime-core/tests/runtime_admission/swarm_evolution.rs.

**Interfaces:**

- Expose the existing core signature on the public SQLite wrapper:
  extend_swarm_authority_bundle(&self, expected_bundle_sha256: &str, candidate: SwarmAuthorityBundle, trusted_keys: &[PublicKey]) -> Result<(), ChioRuntimeError>.

- Define WorkPreparationV1, WorkPreparedV1, WorkCommandV1, WorkActionV1, WorkHandleV1, WorkCommitmentV1, WorkFundingRefV1 and WorkViewV1 exactly as the spec.
- WorkCommandResultV1 = { command_id, command_revision, disposition, handle: Option<WorkHandleV1>, view: Option<WorkViewV1> }; disposition is Applied, Pending or Rejected with a bounded code. A Pending result never implies admission.
- WorkError variants: InvalidCommand, UnsupportedProfile, AudienceDenied, Conflict, CommitUnknown, Unavailable, Corrupt, StaleBasis, Revoked, Expired, BudgetUnavailable, UnknownEffect. Each carries bounded detail and, where known, the original command reference.

- [ ] Add public-import tests and existing-history vectors. Assertions include:
      assert_eq!(first.handle, after_growth.handle);
      assert_eq!(replayed.continuation_id, original.continuation_id);
      assert!(second_competing_extension.is_err());
  Use the existing swarm fixtures and their native consumed-continuation assertions, not a new mock reducer.

- [ ] Run cargo test --locked -p chio-runtime --features work --test work_public_surface. Expect missing feature/API before implementation.
- [ ] Add explicit facade exports, feature wiring and the existing store delegation. Preserve ordinary default builds and the facade-owned error boundary; do not export all of runtime-core.
- [ ] Run the new test plus cargo test --locked -p chio-runtime --test runtime_boundary and the owning swarm_evolution tests. Confirm the same core verification executes.
- [ ] Commit: feat(runtime): expose composable work contracts and graph extension.

Acceptance: AW01/AW03. A downstream crate can describe work and extend the existing graph using chio-runtime only.

## W1.2: Promote allocation and binding composition

**Files:**

- Create: crates/kernel/chio-runtime-core/src/work/bindings.rs.
- Create: crates/platform/chio-control-plane/src/work/mod.rs, host.rs, allocation.rs.
- Modify: crates/platform/chio-control-plane/src/lib.rs, Cargo.toml.
- Extend: crates/platform/chio-workflow/src/delegation/store.rs only for missing exact seal readback.
- Test: crates/platform/chio-control-plane/tests/work_allocation.rs.
- Refactor client after tests: examples/federated-work/src/funded_work/composition.rs and evolving.rs.

**Interfaces:**

- WorkHostPort and WorkCaller follow the spec; WorkCaller has no Deserialize implementation or request-supplied constructor.
- WorkHostPort::prepare verifies caller scope and delegates to the configured local holder, receiver-capability or S1 graph-authoring service. It returns only the exact signed artifact/reference for that role; no service needs another owner's private key.
- validate_work_commitment(commitment: &WorkCommitmentV1, configured: &WorkBindingPolicy) -> Result<(), WorkError> verifies cross-record consistency. WorkBindingPolicy is host configuration containing expected program, receiver, allocator and witness identities, not incoming JSON authority.
- Preserve DelegationStore::{subdivide, select, seal_dispatch} and Signed<DispatchPermit>.
- If needed, add DelegationStore::sealed_dispatch(&self, binding: &DispatchBinding) -> Result<Option<Signed<DispatchPermit>>>. A mismatched immutable binding conflicts.

- [ ] Port the composed fixture's actual receiver/request/slot/allocation/route mismatch controls into work_allocation.rs. Add exact repeated-seal and cross-tenant command tests. Assert zero native dispatches on each rejected substitution.
- [ ] Run cargo test --locked -p chio-control-plane --test work_allocation. Expect absent work adapter/functions.
- [ ] Implement the host adapter using current hardened configuration/signing services. Extract D1/S1 binding checks from composition::validate, retaining native verification and configured guards. Do not move Provision's buyer private key or connect_local_cosigner into the public API.
- [ ] Make repeated commands consult their owning allocator state. Keep selection replacement possible only before seal. A fresh host can retrieve the same permit bytes after acknowledgement loss.
- [ ] Exercise prepare for subdivision, receiver offer, selection and graph extension. Assert that wrong-role callers cannot sign, retry returns byte-identical issued artifacts, and both applications can prepare work without a private signing key or custom graph builder. Preserve the existing request/permit/graph/agreement preparation order so final signatures bind the completed request without a circular digest dependency.
- [ ] Re-run the test and existing dynamic_delegation suite; change the example to call the promoted functions and confirm its mismatch controls still fail at the same native boundary.
- [ ] Commit: feat(runtime): reuse native work allocation and commitment binding.

Acceptance: AW02 and preparation for AW07. No duplicated capability/treaty/graph verifier, permissive fallback or application-owned trust activation.

## W1.3: Durable command references and recovery integration

**Files:**

- Create: crates/kernel/chio-runtime-core/src/work/commands.rs, projection.rs.
- Create: crates/kernel/chio-runtime-core/src/store/sqlite/work_commands.rs.
- Modify: crates/kernel/chio-runtime-core/src/store/sqlite.rs and store/sqlite/schema_migrations.rs.
- Create: crates/platform/chio-control-plane/src/work/recovery.rs.
- Test: crates/platform/chio-control-plane/tests/work_recovery.rs.
- Extend: the active recovery lane's contract tests through its agreed integration owner.

**Interfaces:**

- SqliteRuntimeOrchestrationStore::record_work_command(&self, principal_scope: &str, command: &WorkCommandV1) -> Result<WorkCommandRecord, ChioRuntimeError>.
- work_command(&self, principal_scope: &str, program_id: &str, command_id: &str) -> Result<Option<WorkCommandRecord>, ChioRuntimeError>.
- WorkCommandRecord contains immutable command digest, revision, coordination phase and authority references. It is not a dispatch witness.
- WorkRuntime::prepare/submit/inspect and WorkHostPort::prepare/apply/inspect use the spec signatures. Separate preparation/application stage keys in the command index; store exact issued artifact references before acknowledging preparation.
- Recovery adapter consumes the landed ProcessRecoveryPort and KernelRecoveryPort contracts. Preserve original intent/operation resolution and settle_retained separation.

- [ ] Add fault cases after command retention, seal, process reservation, native admission and native outcome, and before response delivery. Use fresh processes and the existing native cutpoint harness.
- [ ] Assert for a lost acknowledgement:
      assert_eq!(after.original_request_id, before.original_request_id);
      assert_eq!(after.native_operation_id, before.native_operation_id);
      assert_eq!(external_effect_count, 1);
  For UnknownEffect, assert no second dispatch. For current release denial, assert no output bytes despite retained financial history.

- [ ] Run cargo test --locked -p chio-control-plane --test work_recovery and retain the failing boundary.
- [ ] Implement immutable command indexing/CAS under the existing store's integrity rules. Resolve authoritative original state before advancing a projection. Do not hold a SQLite transaction or store lock across a network await.
- [ ] Wire cancellation and collection to the existing owners. Use actual recovery ports, never fake a completed P1 with ordinary invoke under a new key.
- [ ] Run work_recovery plus the current recovery lane's exact-binding/nonce/historical-settlement tests, and cargo test --locked -p chio-kernel --test durable_admission_sqlite.
- [ ] Commit: feat(runtime): preserve work identity through command and process recovery.

Acceptance: AW04/AW05/AW10. Missing local coordination state cannot renew authority; data release, settlement and bilateral completion remain separate.

## W1.4: Public-client conversion and focused review

**Files:**

- Modify: examples/federated-work/Cargo.toml, src/funded_work/evolving.rs, evolving/graph.rs.
- Update: crates/kernel/chio-runtime/README.md and ARCHITECTURE.md.
- Create: docs/reference/WORK_PROGRAMMING.md.
- Test: crates/kernel/chio-runtime/tests/work_public_surface.rs.

**Interfaces:** Public chio_runtime::work, existing D1/S1 signed artifacts, and the W2 host port. The example may still use its explicitly named devnet funding fixture until W2.3.

- [ ] Add a downstream-consumer build fixture importing only the public facade and documented dependencies. It must not import example source or runtime-core.
- [ ] Convert the unpaid branch of the running application to the facade. Document allocate/select/seal/submit/inspect/collect, original IDs and the three authority lifetimes.
- [ ] Run cargo test --locked -p chio-runtime --features work; focused control-plane work tests; cargo clippy --locked -p chio-runtime -p chio-runtime-core -p chio-control-plane --features chio-runtime/work,chio-runtime-core/work --all-targets -- -D warnings; cargo fmt --all -- --check.
- [ ] Review the public contract, migration and actual effect evidence. Update the acceptance map with exact commands, hashes and remaining W2 dependencies.
- [ ] Commit: docs(runtime): document and exercise the work programming model.

Stop condition: W1 accepts the reusable local contract. It does not certify remote peers, deployed payment, all adapters or beta release.
