# Pre-settlement execution implementation plan

> Continue implementation, review and qualification in the primary agent. The user explicitly stopped further sub-agent work. Retain the completed independent reviews as historical evidence and finish local qualification and commit directly.

**Goal:** Verify original native execution before settlement without inventing financial backing.

**Architecture:** A fenced kernel projection retains one execution-only ChioReceipt. Its explicit profile feeds the existing Finding verifier and checkpoint machinery; original funding identities and the later financial successor remain authoritative.

**Tech Stack:** Rust, canonical JSON/Ed25519, qualified SQLite authority and outcome stores, existing Finding facets/checkpoints, independent Python, owned Ganache mock token.

**Spec:** [Pre-settlement execution design](../specs/2026-09-15-pre-settlement-execution-design.md)

## Global constraints

- Work only in the existing isolated integration checkout. Preserve original source and historical evidence.
- No production unwrap/expect, em dashes, unbounded artifact reads, network resolution or fabricated assurance facets.
- Local commit only. No push, merge, public network, real funds or memory writes.
- Freeze implementation before final evidence. Qualification commands must refer to the tested source and executable.

## Task 1: Kernel-qualified immutable execution receipt

Files: core `receipt/execution_evidence.rs`; kernel admission coordinator execution-evidence module, tool-outcome projection types/store methods; SQLite tool-outcome schema, projection and migration tests.

Produces:

```rust
pub const PRE_SETTLEMENT_EXECUTION_PROFILE: &str = "chio.pre_settlement_execution.v1";
pub fn verify_pre_settlement_execution_receipt(
    receipt: &ChioReceipt,
    admitted_kernel_keys: &[PublicKey],
) -> Result<ExecutionEvidenceMetadata, ExecutionEvidenceError>;
impl ChioKernel {
    pub fn export_durable_execution_evidence(
        &self, request: &ToolCallRequest,
    ) -> Result<ChioReceipt, KernelError>;
}
```

The closed metadata uses snake_case and carries schema, phase, authority_uuid,
operation_id, request_id, request_binding_hash, request_sha256, hold_id,
authorization_id, outcome_id, raw_outcome_sha256, resolved_output_sha256,
post_return_evaluation_sha256, post_guard_decision_sha256 and pricing_verdict_sha256.
The evaluation digest covers its complete canonical persisted record, including
plan and exact input commitments. Phase is `execution_confirmed`.

- [x] Write a native pending-payment integration test asserting export succeeds, exact original identities, no final operation/receipt/payment transition, strict signature, then exact-byte export after reopen. Observe the missing-behavior failure before implementation.
- [x] Add core semantic validation. Reject financial/budget authority blocks, wrong phase/schema, non-allow/advisory receipts, altered resolved hash, malformed identifiers/digests and unadmitted signatures.
- [x] Add default-denying projection methods and a non-deserializable kernel-qualified token. Implement an atomic immutable SQLite projection covered by participant commitment and exact v3-to-v4 migration.
- [x] Implement export from the original retained native request/evaluation. Revalidate the original lease/fence after signing and append without a financial observation. Reuse persisted bytes after payment and restart.
- [x] Add store tamper/rollback, migration, denial/unknown/caller/security, signer drift, expired lease and conflicting projection tests. Run selected kernel/store/core checks and obtain independent review.

## Task 2: Explicit Finding execution semantics

Files: `chio-finding-verifier/src/verify.rs`, focused profile/receipt tests, core metadata schema documentation.

Consumes Task 1's core validator. Existing profile and ChioReceipt types remain.

```rust
match required_semantics {
    MEDIATED_SPEND_PROFILE => verify_existing_nonce_and_spend(receipt),
    PRE_SETTLEMENT_EXECUTION_PROFILE => verify_execution_only(receipt),
    _ => Err(unsupported_profile()),
}
```

The snippet describes branch ownership; preserve the existing spend implementation
and errors rather than introducing duplicate wrapper functions.

- [x] Add a failing verifier test with a signed execution-only receipt and pinned checkpoint/status showing authenticity/membership can verify while both cost facets remain unavailable.
- [x] Recognize only the two explicit profiles. Keep strict raw receipt/signature/standing/chronology checks and unchanged legacy nonce enforcement. Delivery evidence retains mediated-spend semantics.
- [x] For execution-only production receipts, classify cost facets unavailable instead of treating missing financial metadata as verified or an optional failure. Retain ordinary failure for forged receipt/profile substitution.
- [x] Test wrong profile, financial metadata injection, altered source/output, revoked/unpinned signers, incomplete checkpoints and preservation of legacy mediated-spend regressions.

## Task 3: Funded custody and original policy integration

Files: funded `execution_evidence.rs`, `finding_acceptance.rs`, `evidence.rs`, `native.rs`, provisioning/lifecycle paths, focused unit tests, independent Python evidence checker.

Produces a bounded canonical `ExecutionEvidenceBundle` containing receipt,
checkpoints, inclusion wrapper and transparency records. The original agreement
already signs the context digest and required facets.

- [x] Add failing funded tests for required receipt/membership before payment and denial on changed original operation, hold, output, checkpoint or bundle.
- [x] Provision explicit v2 execution context and separate checkpoint signer before agreement. Require the four agreed facets for new execution-profile flows; retain legacy context helpers for historical fixtures.
- [x] Export the kernel receipt after native evaluation, checkpoint it before Finding issuance and retain the first exact bundle. Derive Finding references from that bundle and validate source identities against the original request/binding.
- [x] Pass the exact bundle into actual Finding evaluation and historical assessment replay. Unsupported/missing backing cannot mint either financial decision.
- [x] Extend independent Python verification for the public receipt/profile, signatures, binding and checkpoint. Test mutations with actual signatures and shared canonical inputs.
- [x] Add process cutpoints around evidence projection, checkpoint and custody retention; verify exact evidence identity and one execution/hold after restart.

## Task 4: Qualification and local closeout

- [x] Obtain independent integrated review; fix authority or recovery findings and rerun covering checks.
- [x] Run affected Rust/core/kernel/store/Finding tests, strict standalone/workspace Clippy, schema/format/hygiene/generated checks, independent Python and Node regressions, and the full fuzz build inventory.
- [x] Run the original 43 process scenarios plus new evidence and required-backing cases on the final executable. Reconcile chain events, original identities, economic balances and forced-kill counts.
- [x] Retain a new report/evidence manifest without changing historical evidence. Document verified facets and remaining independent-operator gate.
- [x] Verify source preservation, commit conventionally, confirm clean integration worktree and all committed source/evidence hashes.

Final qualification: [delivery report](../../market/open-agent-work/execution/25-pre-settlement-execution.md) and [source/evidence manifest](../../market/open-agent-work/execution/26-pre-settlement-execution-evidence.json). All work after the user stopped sub-agents was completed by the primary agent.
