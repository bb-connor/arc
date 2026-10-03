# Sovereign Swarm Evolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Extend a running swarm using existing authority artifacts while retaining prior commitments, exact historical verification, and native replay custody.

**Architecture:** A pure extension check lives beside the existing swarm verifier. The existing SQLite runtime store atomically installs checked successors and archives parents. Native admission resolves the already supplied graph digest to its exact version.

**Tech Stack:** Rust, existing Chio canonical JSON and Ed25519 types, rusqlite, existing native kernel tests, LaTeX.

**Spec:** `docs/superpowers/specs/2026-10-02-sovereign-swarm-evolution-design.md`

## Global Constraints

- Reuse existing swarm authority, treaty, capability, and operation-owned custody.
- No new dependencies or signature/wire formats.
- Fail closed. No em dashes. Follow workspace Clippy restrictions.
- An extension adds nodes; all existing commitments are retained.
- Never reclaim an allocation or refresh a used continuation identity.
- Use caller-owned time for pure checks and the protected store clock for installation.
- Preserve interrupted paper work. Update its evidence boundaries honestly.
- Execute inline as authorized; one fresh whole-change reviewer at the end.

## Review Focus

- A successor that passes the ordinary verifier but changes a prior allocation must fail extension checks.
- A newly signed continuation for an old task must not create another native dispatch.
- Concurrent writers on separate SQLite connections must not both spend one parent's remaining declared capacity.
- Historical lookup must verify full bundle and graph/index hashes after restart.
- Historical swarm lookup must preserve the independent treaty gate and original operation-owned resources.

## Task 1: Verify extensions using the existing swarm model

**Files:** Create `crates/kernel/chio-swarm-authority/src/evolution.rs`; modify `src/lib.rs`; add `tests/swarm_authority_stage0/evolution.rs` to the existing test module.

**Interfaces:** Produces `verify_swarm_authority_extension(previous: &SwarmAuthorityBundle, candidate: &SwarmAuthorityBundle, trusted_keys: &[PublicKey], now_unix_ms: u64) -> Result<SwarmAuthorityVerifierReport, SwarmAuthorityError>`.

- [x] Write tests using the existing signed sample fixture, reduced to one worker for the parent. Assert ordinary verification accepts both snapshots; extension accepts growth; reissued old nonce, reduced old allocation, changed expiry, changed epoch, no growth, unknown signer, and duplicate allocation/task attempts reject.
- [x] Run focused tests and retain their missing-function failure.
- [x] Implement the extension invariants by reusing live verification and comparing retained typed artifacts, with checked existing budget accounting.
- [x] Run `cargo test -p chio-swarm-authority` and focused Clippy. Expected: all pass.
- [x] Commit `feat: verify commitment-preserving swarm extensions`.

## Task 2: Install and resolve swarm versions atomically

**Files:** Modify `chio-runtime-core/src/store/traits.rs`, `src/store/sqlite/schema_migrations.rs`, `src/store/sqlite/swarm_authority_bundles.rs`, `src/store/sqlite/admission_replay.rs`, and `src/admission_hook/swarm_authority.rs`; add a focused store extension test module under `tests/runtime_admission`.

**Interfaces:** Consumes Task 1 verifier. Produces `extend_swarm_authority_bundle(&self, expected_bundle_sha256: &str, candidate: SwarmAuthorityBundle, trusted_keys: &[PublicKey]) -> Result<(), ChioRuntimeError>` and trait method `swarm_authority_bundle_for_graph(&self, task_graph_id: &str, graph_sha256: &str) -> Result<Option<SwarmAuthorityBundle>, ChioRuntimeError>`.

- [x] Write tests for installation, exact parent/successor lookup after reopen, stale-head rejection, two-connection contention, failed-update rollback, unknown hash, and tampered archive rejection.
- [x] Run the focused test filter and retain the missing-method failure.
- [x] Add the archive table and immediate-transaction compare-and-swap installer; bind historical reads to index and full digest. Add compatible trait defaults and layered delegation.
- [x] Switch the existing admission resolver to the request's already bound graph digest.
- [x] Run focused store and swarm binding tests. Expected: all pass, original mismatch rejection unchanged.
- [x] Commit `feat: retain and atomically extend runtime swarm authority`.

## Task 3: Exercise native evolution and update the paper

**Files:** Extend `chio-runtime-core/tests/runtime_admission/operation_owned/live_swarm.rs` and the existing combined treaty/swarm fixture; update swarm README/architecture; add `docs/research/swarm-evolution/` evidence and protocol notes; update `docs/papers/verifiable-work/` manuscript, claims and artifact records.

**Interfaces:** Consumes Tasks 1-2 through the actual runtime hook. Uses existing native authority/receipt stores and real test server invocation counters.

- [x] Add a native trajectory: admit original worker, install checked growth, run newly added worker, replay original exact receipt after reopen, reject new invocation under the used continuation, and execute an original unstarted worker with its historical artifacts after growth.
- [x] Add a combined treaty/swarm case preserving signed bilateral evidence and all physical claim resources through growth/reopen. Keep existing combined regression coverage.
- [x] Run targeted tests and inspect terminal output; fix boundary failures at their cause.
- [x] Run full changed-crate tests, focused Clippy, and format checks. Retain commands, terminal results, and source hashes in a compact evidence record.
- [x] Explain the additive composition argument, reuse map, native result, and remaining non-additive changes in the paper. Preserve earlier D1/F1 evidence and its exact historical source boundaries.
- [x] Build the PDF and run artifact checks. If prior evidence is source-pinned, keep that pin instead of relabeling it as current.
- [x] Request one fresh review of implementation, tests, and paper claims; resolve material findings, rerun affected checks, and record remaining limits.
- [x] Commit verified code and manuscript updates; retain this isolated branch for user review.

## Execution record

The latest user instruction authorizes planning through execution and review.
No repeated design approval is requested. The native implementation is a
specific additive extension of the approved vision, with broader claims bounded
by the spec. Existing dirty manuscript/provenance files predate this plan and
belong to this same ongoing user task.

Completion: implementation, fresh combined review, regression repair and all 11
source-bound qualification commands complete. PDF and artifact checks pass.
The isolated paper branch is retained as planned; independent operators,
unified D1/S1/F1 execution and the requested breakthrough judgment remain open.
See docs/research/swarm-evolution/REVIEW.md for exact scope and evidence.
