# Independently Controlled Work Owners Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax. Coordinate changes at security/recovery-owned ports before editing them.

**Goal:** Let separately configured owners use the work contract without sharing private keys or application-specific authority code.
**Architecture:** Host the W1 adapter in chio-control-plane. Reuse hardened ingress, federation co-signing, native custody and the recovery agent's ports; promote F1 through existing settlement modules.
**Tech Stack:** Rust, existing authenticated HTTP/IPC, SQLite, federation DSSE, optional existing EVM devnet rail.
**Spec:** [owner services](../specs/2026-10-03-work-owner-services-design.md), [runtime](../specs/2026-10-03-work-runtime-design.md).

## Global Constraints

- Owner provisioning selects trust roots, signers, peer identities, policies, semantic contracts and rails. Incoming work cannot select administrative configuration.
- Preserve complete request bindings and original operation identities.
- No second execution or recovery authority.
- Public-money operation stays unsupported until separately qualified.
- Apply all [parent constraints](../specs/2026-10-03-agentic-work-kernel-design.md#global-constraints).

## Review Focus

- Correctly signed request from the wrong owner/tenant or a caller-chosen endpoint: deny before work or key use (W2.1).
- Arbitrary DSSE preimage presented for co-signing: reconstruct and reject without a signing oracle (W2.2).
- Lost bilateral response after a completed tool call: retain pending delivery, no new invocation/payment (W2.2).
- Reserve, amount, verifier, network or asset substituted under valid signatures: reject before funding acceptance (W2.3).
- Caller revoked after work is earned: historical settlement may progress; fresh work and unauthorized output cannot (W2.4).

## W2.1: Owner setup and authenticated work service

**Files:**

- Create: crates/platform/chio-control-plane/src/work/config.rs, service.rs, transport.rs.
- Modify: crates/platform/chio-control-plane/src/work/mod.rs and the existing trust_control.rs router composition.
- Test: crates/platform/chio-control-plane/tests/work_service.rs.
- Create: spec/schemas/chio-work/v1/command.schema.json, view.schema.json, profile.schema.json.

**Interfaces:**

- WorkDeploymentProfileV1 specifies owner/store/program identity and references to already provisioned trust, tools, recovery and payment configuration.
- WorkService::new(host: Arc<dyn WorkHostPort>, profile: WorkDeploymentProfileV1) -> Result<Self, WorkError>.
- Authenticated routes are POST /v1/work/prepare, POST /v1/work/commands and POST /v1/work/query, with the W1 request/result types. Preparation is limited to locally configured authoring roles.
- request fields cannot construct WorkCaller; the existing verified ingress context supplies it.
- Provisioning stays host-local and is separate from WorkService.

- [ ] Write service tests for two tenants, wrong peer, changed store identity, untrusted allocator, unsigned configuration and overlarge/duplicate-key requests. Include a useful command accepted by the correct owner.
- [ ] Run cargo test --locked -p chio-control-plane --test work_service. Expect missing service routes before implementation.
- [ ] Mount the service through the security lane's current authenticated/TLS listener and strict reader. Resolve IDs only inside the configured owner's domain. Do not transplant the prototype listener or allow a caller-supplied trust bundle.
- [ ] Add negotiated feature/profile responses. Unsupported recovery/funding/boundary profiles reject before any side effect.
- [ ] Re-run tests plus the owning hardened ingress/issuer tests from the selected security checkpoint.
- [ ] Commit: feat(work): serve owner-scoped work commands.

Acceptance: AW07. A network request can use approved services but cannot provision an authority.

## W2.2: Real peer co-signing and durable evidence completion

**Files:**

- Create: crates/platform/chio-control-plane/src/work/cosign.rs, peer.rs.
- Modify: crates/platform/chio-control-plane/src/work/transport.rs.
- Reuse: crates/trust/chio-federation/src/bilateral.rs and bilateral_dsse/.
- Extend, only via the owning lane: crates/kernel/chio-kernel/src/kernel/admission_coordinator/federation_context.rs.
- Test: crates/platform/chio-control-plane/tests/work_peer.rs.

**Interfaces:**

- PeerWorkClient uses configured origin, peer ID/key, TLS identity, egress policy and bounded timeouts.
- Implement the existing BilateralCoSigningProtocol::{request_cosignature, request_dsse_cosignature} signatures. Both remain synchronous trait calls; transport work must run on the established blocking/host path, never block an async executor or hold authority locks.
- Durable completion uses the existing native operation and exact statement digest. WorkViewV1 exposes LocalOnly/Pending/Complete evidence delivery states without changing native execution truth.

- [ ] Port negative framing/identity cases from funded_work/peer_client.rs, peer_https.rs and their tests; add local-context, wrong-purpose and arbitrary-preimage signing controls.
- [ ] Add a separate-process run with no peer private keys in the receiver's state directory. Kill or disconnect the co-signer after local completion, reopen, and request the same statement again.
- [ ] Run cargo test --locked -p chio-control-plane --test work_peer. Expected failure is the absent real co-signing transport/completion seam.
- [ ] Implement exact local-context reconstruction, authenticated peer exchange and original-operation reconciliation. If the current native owner cannot persist the delivery intent, add the narrow port under security/recovery review. Do not create a separate daemon that can mark native completion.
- [ ] Assert complete result signature verification, one tool call, unchanged operation/claim identities and no second payment. Also assert honest Pending state while the remote signer is absent.
- [ ] Commit: feat(work): complete bilateral evidence across owner services.

Acceptance: AW08/AW09. Two keys are not reported as two independent administrators; the service is deployable without shared private state.

## W2.3: Package the existing funded profile without kernel dependency cycles

**Files:**

- Create: crates/economy/chio-settle/src/work_claims/mod.rs, agreement.rs, observation.rs, transaction.rs.
- Modify: crates/economy/chio-settle/src/lib.rs and feature dependencies only as required.
- Create: crates/platform/chio-control-plane/src/work/funding.rs.
- Create: crates/platform/chio-store-sqlite/src/admission_operation_store/work_claims.rs and src/admission_operation_work_claims.sql.
- Modify: crates/platform/chio-store-sqlite/src/admission_operation_store.rs and admission_operation_store/schema.rs under the security lane's existing migration, fencing and integrity rules. If that lane has landed an equivalent binding table, extend it and record the actual path instead of creating a duplicate.
- Test: crates/economy/chio-settle/tests/work_claims.rs; crates/platform/chio-control-plane/tests/work_funding.rs.
- Convert: examples/federated-work/src/funded_work/{agreement,observer,rail,settlement}.rs into clients/adapters of promoted logic.
- Reuse unchanged financial contract: contracts/src/experimental/ChioWorkClaimEscrow.sol. Contract behavior is not in scope.

**Interfaces:**

- WorkClaimProfileV1: rail ID, network/asset/contract identity, currency mapping, acceptance verifier, finality/deadline policy and allowed profile.
- WorkClaimTerms and signed agreement keep the existing F1 signing/ABI derivations; no accidental signature-preimage migration.
- verify_work_reserve(profile: &WorkClaimProfileV1, terms: &WorkClaimTerms, observation: &WorkReserveObservation) -> Result<VerifiedWorkReserve, WorkClaimError>. VerifiedWorkReserve has private fields and no unchecked deserialization.
- WorkFundingAdapter in control-plane implements the existing kernel PaymentAdapter; chio-settle never depends back on chio-kernel.
- WorkFundingRefV1 remains a reference, not evidence that funds exist.
- WorkClaimBindingV1 records allocation ID, agreement digest, configured financial domain, original native operation/hold IDs and verified reserve/evidence references. Insert/read operations require the existing StoreMutationFence; changed binding under the same allocation conflicts. Protected agreement/artifact custody follows the serving store's classification and retention rules. Do not copy raw credentials or output into this index.

- [ ] Port current agreement, reserve, transaction-recovery and earned-child tests. Add non-100 amounts, two configured tools, unsigned or substituted reserves, wrong network/asset/verifier, and the unpaid profile.
- [ ] Run cargo test --locked -p chio-settle --test work_claims and cargo test --locked -p chio-control-plane --test work_funding. Expect absent promoted types before implementation.
- [ ] Extract the reusable financial construction, preserve persisted transaction identity, and replace W0 constants with validated profile values. Reuse existing transaction bytes/nonce recovery and owning payment journal.
- [ ] Implement the Agreement preparation variant using owner-approved terms. Replace the fixture's two-key Agreement::sign helper in production paths with separate owner signatures and exact-body verification. Use explicit existing rail funding operations under payer authority to establish reserves; preparation alone cannot reserve/transfer funds. SDK applications consume the resulting references without private keys or a custom signing flow.
- [ ] Make native authorization verify the agreement against the complete selected request and original operation/hold. An observation adapter supplies untrusted data; the configured verifier creates VerifiedWorkReserve.
- [ ] Run the explicit devnet child-parent-failure and lost-transaction-ack cases. Required devnet prerequisites missing is unavailable, not passed; retain the ordinary suite's skipped cases separately.
- [ ] Verify cargo check --locked -p chio-settle --no-default-features and the existing Rust 1.93 substrate/proof lane. Confirm no kernel dependency cycle or unconditional new chain dependency.
- [ ] Commit: feat(work): package funded obligations through existing settlement.

Acceptance: AW06. Paid and unpaid programs share authority semantics; the advertised initial rail remains a devnet profile until operationally qualified.

## W2.4: Join recovery continuations and protected result release

**Files:**

- Extend: crates/platform/chio-control-plane/src/work/recovery.rs.
- Create: crates/platform/chio-control-plane/src/work/projection.rs.
- Test: crates/platform/chio-control-plane/tests/work_recovery_join.rs.
- Recovery-owner files: actual P1/P3/P4/P5 landed ports recorded in INTEGRATION.md, not guessed replacements.

**Interfaces:** Uses the recovery contract's reserve/finalize, resolve_admission, observe, settle_retained, read_into and admit operations. Consumes existing D1/S1 child allocation for a changed approved continuation.

- [ ] Add the support-disclosure positive trajectory from the recovery lane, extended with a separate-owner analysis task and one new approved child allocation. Assert both original sealed work and the continuation relationship remain inspectable.
- [ ] Add cancellation/expiry after native capture, withholding after completion, a Deny receipt with unknown effect, missing original admission projection and incompatible D1 continuation binding.
- [ ] Run cargo test --locked -p chio-control-plane --test work_recovery_join. Treat unlanded recovery ports as a dependency, not a stubbed success.
- [ ] Implement the narrow join: approved changed work receives a distinct bounded allocation/request; unchanged historical settlement keeps its original operation. Enforce recipient authority at each result read/return.
- [ ] Assert one allowed publication effect, no duplicate after process loss, no raw output on denial, and no fresh execution using a historical settlement scope.
- [ ] Commit: feat(work): compose recovery and owner-controlled result release.

Acceptance: AW10/AW15. The third lane exposes recovery semantics without taking ownership of them.

## W2.5: Operator package and owner-boundary review

**Files:**

- Create: examples/owner-work/README.md, owner-profile.example.json, run.py.
- Extend: docs/papers/verifiable-work/trial/README.md by linking the new package only when implemented; preserve the old trial evidence.
- Create: docs/reference/WORK_OWNERS.md.

- [ ] Package owner-local key creation, profile validation, peer enrollment, serve, inspect and export commands. No private keys in the transferable trial bundle.
- [ ] Run three independently configured processes and the same package across separate hosts under the team's administration. Record which topology actually ran.
- [ ] Have the owner-boundary review inspect real transport, signers, native records, denial effects and financial identity. Close blocking findings with focused rechecks.
- [ ] Produce the external handoff and leave independently administered operation pending until a real outside operator supplies evidence.
- [ ] Commit: docs(work): package independently controlled owner services.

Stop condition: AW07 through AW10 accepted for the supported profile, with outside-operation status accurately recorded.
