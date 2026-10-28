# Durable Nonce Signing Identity Implementation Plan

> For agentic workers: use superpowers:executing-plans in the native thread. No subagents.

**Goal:** Allow durable operation-owned nonces under the receipt signing backend while preserving exact ownership and recovery refusal.

**Architecture:** A shared bounded signing-key claimant helper closes kernel/store ownership checks. Bounded canonical issuer storage retains full signature authority, and caller-return checks use the receipt signer.

**Tech Stack:** Rust, existing SHA-256/PublicKey types, rusqlite, existing durable nonce test fixtures.

**Spec:** docs/superpowers/specs/2026-10-28-durable-nonce-signing-identity-design.md

## Global Constraints

Native thread only. Fresh-only v1, no compatibility path. All Cargo via cslot with CARGO_INCREMENTAL=0, jobs3 and debug0. ws2 floor45GiB. No native packet or Lean/lake/Aeneas/Kani execution. Claude owns merge and coverage LAST.

## Review Focus

1. Hybrid keys sharing the classical component must have different claimant identities. Task1 pins this.
2. Failure to read the signer must not partially install durable state. Task1 pins attachment refusal.
3. Old catalogs and alternate key spellings must refuse, not normalize into authority. Task2 pins both.
4. Restart and caller-return must not restore the classical-only identity check. Task3 pins both.
5. Backend changes after attachment must not issue under stale authority. Task3 pins no issuance mutation.

## Task1: Bound the coordinator signing identity

Files: kernel/chio-kernel/src/admission_operation/execution_nonce.rs plus a focused identity test module; kernel/admission_coordinator.rs and kernel/construction.rs.

Interface: `pub fn execution_nonce_coordinator_id(issuer: &PublicKey) -> Result<AdmissionIdentifier, AdmissionOperationError>`, using the exact domain and rendering in the spec. Durable attachment reads the receipt signing identity and passes this typed claimant to its runtime constructor. Add a typed identity-unavailable setup error if the existing vocabulary cannot represent the failure accurately; preserve fail-closed setup.

- [ ] Add deterministic, changed-PQ-component and <=512-byte identity tests, plus unreadable-identity attachment refusal.
- [ ] Run focused RED through cslot; preserve exact logs.
- [ ] Implement helper and runtime attachment closure; update all fixture claimants without old aliases.
- [ ] Run focused GREEN and commit.

## Task2: Complete bounded store issuance/reservation closure

Files: store-sqlite/src/admission_operation_nonce.sql; admission_operation_store/execution_nonce.rs; execution_nonce/issuance.rs; issuance/record.rs; lifecycle.rs; corresponding execution_nonce issuance/reservation/schema tests.

Consumes execution_nonce_coordinator_id. Both issuer readers enforce <=4129 bytes before decoding, then canonical text equality. Both DDL definitions use the same bound. Every ownership comparison uses the helper.

- [ ] Add RED cases for a hybrid issuer in BOTH issuance and reservation, wrong claimant, noncanonical/oversized issuer and old catalog. Preserve valid classical control.
- [ ] Run exact focused RED; distinguish setup failures from the intended boundary.
- [ ] Change DDL, bounded readers and all five lifecycle/issuance/reservation ownership checks.
- [ ] Run GREEN, restart/load and schema-refusal controls; commit.

## Task3: Exercise the kernel/store lifecycle

Files: store-sqlite/tests/execution_nonce_kernel_lifecycle.rs and its support module/new signing_identity module; kernel/admission_coordinator/execution_nonce.rs, return_context/caller.rs, security_release/native_caller.rs.

- [ ] Extend the fixture to install a hybrid receipt backend before durable runtime attachment, using a valid admitted capability and controlled quote verifier.
- [ ] Pin hybrid issue -> restart/redelivery -> reservation -> completion with exact signed identity and effect counts. Pin caller return/reconciliation, wrong signer, classical-only signature and changed-backend/no-issuance controls.
- [ ] Run focused RED, then replace the three config-key comparisons with the authenticated receipt signing identity and keep original authority checks.
- [ ] Run focused GREEN and relevant existing lifecycle suites through cslot. No native OS-death packet.
- [ ] Run changed-crate suites, strict Clippy, locked workspace and required source gates. Record remaining unrelated failures against current main; never call partial evidence READY.
- [ ] Self-review producer/trust-root/caller closure, explicit SHA push, draft PR and lead review. Coverage LAST is lead-owned.

Self-review: all five review-focus cases are assigned. The source map includes both tables, both readers, all ownership comparisons and three caller checks. Public setup error callers and exact gate inventories must be enumerated before editing; no existing test names are renamed.

## Pre-flight ruling: shared coordinator claimant closure

The coordinator claimant authorizes terminal projection and economic staging as well as nonce ownership. The original five-check inventory was incomplete. Task2 must also update `admission_operation_store/caller_wait.rs`, `projection.rs`, both checks in `participant.rs`, and both checks in `economic_state_cache.rs`. The control-plane producer `economic_admission_cancellation.rs` and corresponding store/kernel/control-plane fixtures must use the same derived claimant. Keep receipt authority IDs, receipt namespaces and swarm kernel IDs unchanged: they are separate identities, not admission recovery claimants.

Task1 consumes the authenticated frozen receipt identity so panic, unreadable identity and below-floor keys refuse before runtime installation. Add a specific AdmissionOperationError setup variant; do not misclassify these as canonical JSON failures. Existing API result type remains unchanged.

Verification expands to terminal replay, economic cancellation/staging and caller wait, including classical valid controls. The cost of missing this closure is failure of ordinary durable terminal completion; all production claimant comparisons must be inventoried before implementation. Evidence: nonce-durable-pq/claimant-callers.txt and attachment-callers.txt.
