# Independently Controlled Work Owners Implementation Plan

Status: planned implementation. Work APIs below are proposed contracts. Current main lacks the D1/S1 beta extensions and recovery APIs required by these tasks. See the [source and dependency inventory](../../research/work-abstraction/INTEGRATION.md) for actual source locations and the W1.3-W1.6 a/b task splits.

**Goal:** Let separately configured owners use the work contract without sharing private keys or application-specific authority code.
**Architecture:** Host the planned W1 adapter in chio-control-plane. Reuse hardened ingress, federation co-signing and native custody; integrate the recovery dependencies recorded in the inventory and promote F1 through existing settlement modules.
**Tech Stack:** Rust, existing authenticated HTTP/IPC, SQLite, federation DSSE, optional existing EVM devnet rail.
**Spec:** [owner services](../specs/2026-10-03-work-owner-services-design.md), [runtime](../specs/2026-10-03-work-runtime-design.md).

## Global Constraints

- Owner provisioning selects trust roots, signers, peer identities, policies, semantic contracts and rails. Incoming work cannot select administrative configuration.
- Preserve complete request bindings and original operation identities.
- No second execution or recovery authority.
- Public-money operation stays unsupported until separately qualified.
- Every Chio-owned format is v1. Change every caller and delete the old path in the same PR; no old decoders, migrations, upgrades, compatibility aliases or shims.
- Each SQLite store has one v1 schema. A schema mismatch returns exactly `StaleSchema` before serving. Wipe development databases when the schema changes; do not transform them.
- Before each implementation merge, run the full library and integration test suites for every changed crate with the affected feature sets, strict Clippy with `--all-targets -- -D warnings`, and `cargo fmt --all -- --check`. Focused tests below supplement these gates. Hosted qualification is a separate release boundary and does not block merges on hosted results.
- Apply all [parent constraints](../specs/2026-10-03-agentic-work-kernel-design.md#global-constraints).

## Review Focus

- Correctly signed request from the wrong owner/tenant or a caller-chosen endpoint: deny before work or key use (W2.1).
- Arbitrary DSSE preimage presented for co-signing: reconstruct and reject without a signing oracle (W2.2).
- Lost bilateral response after a completed tool call: retain pending delivery, no new invocation/payment (W2.2).
- Reserve, amount, verifier, network or asset substituted under valid signatures: reject before funding acceptance (W2.3).
- Caller revoked after work is earned: historical settlement may progress; fresh work and unauthorized output cannot (W2.4).

Use the [LC01-LC06 composition cases](../specs/2026-10-03-work-developer-surface-design.md#required-composition-cases) to connect these owner boundaries to the public programming model. Existing native evidence may satisfy its own boundary; public-service composition still needs an actual run.

## W2.1: Owner setup and authenticated work service

**Files:**

- Create: crates/platform/chio-control-plane/src/work/config.rs, service.rs, transport.rs.
- Modify: crates/platform/chio-control-plane/src/work/mod.rs and the existing trust_control.rs router composition.
- Test: crates/platform/chio-control-plane/tests/work_service.rs.
- Create: spec/schemas/chio-work/v1/command.schema.json, preparation.schema.json, query.schema.json, result.schema.json, view.schema.json, profile.schema.json and deployment.schema.json, through the existing schema/codegen convention. profile.schema.json describes the query view; deployment.schema.json describes privileged local configuration.

**Planned interfaces:**

- WorkDeploymentProfileV1 specifies owner/store/program identity and references to already provisioned trust, tools, recovery, payment and catalog configuration. Each catalog entry binds a configured provider/account/tool, manifest/semantic generation, treaty scope and acceptance evaluator. Deployment configuration and the non-authorizing WorkProfileV1 query view have separate schema definitions.
- Extend the concrete W1 WorkService with private configured authority fields; no WorkHostPort service locator. WorkDeploymentProfileV1 is validated host configuration, not incoming authority.
- Authenticated routes are POST /v1/work/prepare, POST /v1/work/commands, POST /v1/work/query and POST /v1/work/cosign, with W1 preparation/command/query types and a closed receipt or bilateral-DSSE co-sign request/response. Original command/preparation lookup works without a returned handle.
- Request fields cannot construct the internal WorkSession; the existing verified ingress/worker context supplies it. Resolve principal/program/root/role against current local policy; the namespace constructor is not an authenticator.
- Provisioning stays host-local and is separate from WorkService.

- [ ] Write service tests for two tenants, wrong peer, changed store identity, untrusted allocator, unsigned configuration and overlarge/nested duplicate-key requests. Include a useful command accepted by the correct owner.
- [ ] Cover all four routes, including /v1/work/cosign, through authenticated HTTP. Test an exact accepted co-sign statement and reject unauthenticated, wrong-peer, wrong-audience and locally unbound statements before signing. Reuse W2.2's reconstruction and signature controls.
- [ ] Add metadata/error canaries and queue saturation, stalled peer, timeout and disconnect cases. Assert bounded memory/tasks, unrelated-owner progress and no fresh issuance/dispatch on cancellation. Use W1.0's fixed limits.
- [ ] Add work_service::catalog_cannot_enroll_a_peer and profile_reload_invalidates_new_preparation: list only authorized configured entries, reject incoming endpoints/keys, and refuse an old basis after activation. Preserve original issued-work history and owner-authorized queries. Validate the 64-entry page bound and generation-bound cursor through the real HTTP path.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_service. Expect missing service routes before implementation.
- [ ] Mount the service through the authenticated/TLS listener and strict reader identified in the integration inventory. Resolve IDs only inside the configured owner's domain. Do not transplant the prototype listener or allow a caller-supplied trust bundle.
- [ ] Add negotiated feature/profile responses. Unsupported recovery/funding/boundary profiles reject before any side effect.
- [ ] Mount Catalog/Profile and Join through the planned query/preparation routes. Resolve candidate terms through the W1.3/W1.4 dependencies and a/b splits in the source inventory; avoid another discovery listener, trust store or treaty negotiation protocol.
- [ ] Re-run tests plus the owning hardened ingress/issuer tests from the selected security checkpoint.
- [ ] Commit: feat(work): serve owner-scoped work commands.

Acceptance: AW07/AW26/AW27. A network request can select approved collaborators and inspect authorized terms, but cannot provision an authority.

## W2.2: Real peer co-signing and durable evidence completion

**Files:**

- Create: crates/platform/chio-control-plane/src/work/cosign.rs, peer.rs.
- Modify: crates/platform/chio-control-plane/src/work/transport.rs.
- Reuse: crates/trust/chio-federation/src/bilateral.rs and bilateral_dsse/.
- Extend the native federation boundary: crates/kernel/chio-kernel/src/kernel/admission_coordinator/federation_context.rs.
- Test: crates/platform/chio-control-plane/tests/work_peer.rs.

**Planned interfaces:**

- PeerWorkClient uses configured origin, peer ID/key, TLS identity, egress policy and bounded timeouts.
- Implement the existing BilateralCoSigningProtocol::{request_cosignature, request_dsse_cosignature} signatures explicitly. Both remain synchronous trait calls; transport work must run on the established bounded blocking/host path, never block an async executor or hold authority locks. The client also implements W1 WorkTransport using existing hardened HTTP/egress facilities.
- Durable completion uses the existing native operation and exact statement digest. WorkViewV1 exposes LocalOnly/Pending/Complete evidence delivery states without changing native execution truth.

- [ ] Port negative framing/identity cases from funded_work/peer_client.rs, peer_https.rs and their tests; add local-context, wrong-purpose and arbitrary-preimage signing controls.
- [ ] Add work_peer::form_relationship_with_unused_approved_owner for LC01: select a catalog entry absent from the initial program, obtain the receiver's own offer and pass both owners' treaty/admission checks without sharing keys. Wrong participant/account, missing required evidence and expired treaty must cause zero native effects. Application source stays identical when the configured candidate changes.
- [ ] Add a separate-process run with no peer private keys in the receiver's state directory. Kill or disconnect the co-signer after local completion, reopen, and request the same statement again. Also lose the response after the remote signer commits but before local projection; resolve the original issuer record with an unchanged body/validity interval.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_peer. Expected failure is the absent real co-signing transport/completion seam.
- [ ] Implement exact local-context reconstruction, authenticated peer exchange and original-operation reconciliation. If the current native owner cannot persist the delivery intent, add the narrow port under security/recovery review. Do not create a separate daemon that can mark native completion.
- [ ] Assert complete result signature verification, one tool call, unchanged operation/claim identities and no second payment. Also assert honest Pending state while the remote signer is absent.
- [ ] Commit: feat(work): complete bilateral evidence across owner services.

Acceptance: AW08/AW09/AW27 and LC01's remote boundary. Two keys are not reported as two independent administrators; the service is deployable without shared private state.

## W2.3: Package the existing funded profile without kernel dependency cycles

**Files:**

- Create: crates/economy/chio-settle/src/work_claims/mod.rs, terms.rs, observation.rs, transaction.rs.
- Modify: crates/economy/chio-settle/src/lib.rs and feature dependencies only as required.
- Create: crates/platform/chio-control-plane/src/work/funding/mod.rs, agreement.rs, adapter.rs. The complete F1 agreement and kernel waiver integration stay here.
- Create: crates/platform/chio-store-sqlite/src/admission_operation_store/work_claims.rs and src/admission_operation_work_claims.sql.
- Modify: crates/platform/chio-store-sqlite/src/admission_operation_store.rs and admission_operation_store/schema.rs under the owning store's fencing and integrity rules. Keep one v1 schema with exact `StaleSchema` rejection on mismatch. If an equivalent binding table exists at the selected source revision, extend it and record the actual path instead of creating a duplicate.
- Test: crates/economy/chio-settle/tests/work_claims.rs; crates/platform/chio-control-plane/tests/work_funding.rs.
- Convert: examples/federated-work/src/funded_work/{agreement,observer,rail,settlement}.rs into clients/adapters of promoted logic.
- Reuse unchanged financial contract: contracts/src/experimental/ChioWorkClaimEscrow.sol. Contract behavior is not in scope.

**Planned interfaces:**

- WorkClaimProfileV1: rail ID, network/asset/contract identity, currency mapping, acceptance verifier, finality/deadline policy and allowed profile.
- WorkClaimTerms in settle contains the existing chain/ABI terms. Agreement/SignedAgreement in control-plane retain full-request validation and the existing kernel SignedContractualCaptureWaiverTermsV1. Do not duplicate that type, replace it with untyped JSON or add a production settle -> kernel dependency. Preserve exact F1/waiver signed bytes.
- verify_work_reserve(profile: &WorkClaimProfileV1, terms: &WorkClaimTerms, observation: &WorkReserveObservation) -> Result<VerifiedWorkReserve, WorkClaimError>. VerifiedWorkReserve has private fields and no unchecked deserialization.
- WorkFundingAdapter in control-plane implements the existing kernel PaymentAdapter; chio-settle never depends back on chio-kernel.
- WorkFundingRefV1 remains a reference, not evidence that funds exist.
- The F1 acceptance adapter projects WorkAcceptanceV1 from the original agreement's signed verifier decision and exact finding/artifact evidence. Settlement observation alone cannot fabricate task acceptance, and a D1 predicate decision cannot stand in for the financial verifier. Reuse W1.5's closed observation schema and the existing Finding verifier.
- WorkClaimBindingV1 is a non-authorizing index of allocation, agreement, configured financial domain and original native operation/hold/reserve/evidence references. Changed binding conflicts. Financial mutation still uses the existing payment journal and qualified authority. Integrate new authoritative records into the owning projection/global-commit/integrity catalog and single v1 schema; a fence parameter or colocated table is insufficient. Preserve protected custody/retention and do not copy raw credentials/output into the index.

- [ ] Port current agreement, reserve, transaction-recovery and earned-child tests. Add non-100 amounts, two configured tools, unsigned or substituted reserves, wrong network/asset/verifier, stale finality observation, and the unpaid profile. Freeze existing agreement/waiver signature-preimage vectors before extraction.
- [ ] Add work_funding::acceptance_is_distinct_from_payment: accepted output with pending payment, rejected output, paid-state evidence without the required task decision, and wrong artifact/checker/procedure all retain their distinct observations. Assert the original agreement's evaluator policy determines the decision.
- [ ] Run cargo test --locked -p chio-settle --test work_claims and cargo test --locked -p chio-control-plane --features work --test work_funding. Expect absent promoted types before implementation.
- [ ] Extract the reusable financial construction, preserve persisted transaction identity, and replace W0 constants with validated profile values. Reuse existing transaction bytes/nonce recovery and owning payment journal.
- [ ] Implement the Agreement preparation variant using owner-approved terms. Replace the fixture's two-key Agreement::sign helper in production paths with separate owner signatures and exact-body verification. Use explicit existing rail funding operations under payer authority to establish reserves; preparation alone cannot reserve/transfer funds. SDK applications consume the resulting references without private keys or a custom signing flow.
- [ ] Make native authorization verify the agreement against the complete selected request and original operation/hold. Assert every ToolCallRequest field has its W1.0 digest/custody mapping and no agreement self-reference. An observation adapter supplies untrusted data; the configured verifier creates VerifiedWorkReserve, and the financial owner rechecks the required freshness/finality before mutation.
- [ ] Run the explicit devnet child-parent-failure and lost-transaction-ack cases. Required devnet prerequisites missing is unavailable, not passed; retain the ordinary suite's skipped cases separately.
- [ ] Verify cargo check --locked -p chio-settle --no-default-features, the work/web3 feature combination, and the existing Rust 1.93 substrate/proof lane. Compare cargo metadata with W1.0 and confirm no production settle -> kernel edge, public kernel type leakage into settle, changed signature preimages or unconditional new chain dependency.
- [ ] Commit: feat(work): package funded obligations through existing settlement.

Acceptance: AW06/AW28 at the funded evidence boundary. Paid and unpaid programs share authority semantics; the advertised initial rail remains a devnet profile until operationally qualified.

## W2.4: Join recovery continuations and protected result release

**Files:**

- Extend: crates/platform/chio-control-plane/src/work/recovery.rs.
- Create: crates/platform/chio-control-plane/src/work/projection.rs.
- Test: crates/platform/chio-control-plane/tests/work_recovery_join.rs.
- Recovery dependencies: actual source files and status recorded in the [integration inventory](../../research/work-abstraction/INTEGRATION.md).

**Planned interfaces:** Requires recovery-owned contracts for continuation admission, native effect observation, historical settlement and protected result release. Concrete API names and source revisions must come from the integration inventory; these APIs are not present on current main. Requires the planned D1/S1 beta child-allocation extension for a changed approved continuation, WorkRecoveryLinkV1 for protocol navigation, and W1.5 acceptance/join references. Explanation, offer selection, owner approval and workflow resumption remain recovery responsibilities. Policy changes require atomic activation of an immutable semantic registry and the revocation dependencies recorded in the inventory; no work-specific policy mutation endpoint.

- [ ] Add the planned recovery support-disclosure trajectory, extended with a separate-owner analysis task and one new approved child allocation. Assert both original sealed work and the continuation relationship remain inspectable.
- [ ] Add cancellation/expiry after native capture, withholding after completion, a Deny receipt with unknown effect, missing original admission projection and incompatible D1 continuation binding.
- [ ] Add work_recovery_join::refusal_to_authorized_progress for LC03. Follow the exact scoped link through explanation, selection, owner approval and resumption. Reject unauthorized explanation/approval, stale offers and changed review inputs. Assert one publication; an unknown workflow stays blocked while a separate authorized workflow with a distinct budget makes progress.
- [ ] Add work_recovery_join::policy_reload_preserves_commitments for LC04 at pre-selection, captured-unknown and accepted-before-delivery cutpoints. Assert stale fresh work denied, original receipt/acceptance/operation hashes unchanged, current release withheld where required, and an earned backed child claim collectible after intermediary failure. Inspect inaccessible history using authorized operator credentials, never a revoked worker.
- [ ] Add work_recovery_join::dependency_category_is_enforced for LC02/LC04. A reviewed old version is only a HistoricalFact; changed CurrentPredicate and expired HeldReservation block the dependent native commitment. Labels and influence survive the join and current recipient check.
- [ ] Run cargo test --locked -p chio-control-plane --features work --test work_recovery_join. Treat unlanded recovery ports as a dependency, not a stubbed success.
- [ ] Implement the narrow join: approved changed work receives a distinct bounded allocation/request; unchanged historical settlement keeps its original operation. Enforce recipient authority at each result read/return.
- [ ] Assert one allowed publication effect, no duplicate after process loss, no raw output on denial, and no fresh execution using a historical settlement scope.
- [ ] Commit: feat(work): compose recovery and owner-controlled result release.

Acceptance: AW10/AW15/AW28/AW29/AW30 and LC03/LC04's owner boundaries. Work composes the recovery and policy contracts without introducing a second authority.

## W2.5: Operator package and owner-boundary review

W2.5 is required before outside-team handoff. Local service tests do not satisfy the packaging and review requirements below.

**Files:**

- Create: examples/owner-work/README.md, owner-profile.example.json, run.py.
- Extend: docs/papers/verifiable-work/trial/README.md by linking the new package only when implemented; preserve the old trial evidence.
- Create: docs/reference/WORK_OWNERS.md.

- [ ] Package owner-local key creation, profile validation, peer enrollment, serve, inspect and export commands. No private keys in the transferable trial bundle.
- [ ] Include bounded catalog configuration, treaty/acceptance prerequisites, exact profile-generation inspection and authorized recovery navigation. Distinguish owner enrollment from selecting an already approved collaborator, and current release from historical acceptance/settlement.
- [ ] Run three independently configured processes and the same package across separate hosts under the team's administration. Record which topology actually ran.
- [ ] Have the owner-boundary review inspect real transport, signers, native records, denial effects and financial identity. Close blocking findings with focused rechecks.
- [ ] Produce the external handoff and leave independently administered operation pending until a real outside operator supplies evidence.
- [ ] Commit: docs(work): package independently controlled owner services.

Stop condition: AW07 through AW10 accepted for the supported profile and the W2.5 operator package and review complete before outside-team handoff. Independently administered operation remains pending until an outside operator supplies evidence.
