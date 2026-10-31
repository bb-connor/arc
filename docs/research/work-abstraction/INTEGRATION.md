# Work integration inventory

This is the source contract for WORK-W1.0. The public Work client, owner service and qualified work issuers are implementation targets. This inventory does not establish a joined executable baseline or satisfy WORK-W1's runtime exit.

## Source boundary

| Input | Exact commit | Scope |
| --- | --- | --- |
| Inspected main | `10d70b88a311fbe3d51ba90254f02321cebb973b` plus the qualified D1/S1 stores | Existing native kernel, process, serving-owner, manifest and treaty APIs |
| Remaining work source | `cafdc970e4f89bddf810647e4228a605ed9f498a` ([#1173](https://github.com/bb-connor/arc/pull/1173)) | F1 funded-work example source; D1 and additive S1 are on inspected main |
| Pending recovery | `4b9229dca4329141ba3c929264ef71aee12e37c6` ([#1179](https://github.com/bb-connor/arc/pull/1179)) | Exact process reservation/origin, semantic, knowledge and confined-return interfaces; unqualified integration input |

[SOURCES.json](SOURCES.json) pins file hashes to these commits. A path in the pending sections names that commit, not a file claimed to exist on main. The [runtime plan](../../superpowers/plans/2026-10-03-work-runtime.md) owns the implementation tests and dependencies.

Every owned format is v1-only. Exact source names below describe the inspected bytes; they do not authorize preserving superseded versions during integration. Update producers, strict readers and vectors together. SQLite stores have one v1 schema and exact `StaleSchema` refusal for every mismatching stamp. Wipe and reprovision development databases with retired shapes, without conversion or an alternate writer.

## Constructors and authority ownership

All paths in this section refer to inspected main.

| Owner and source | Actual interface | Construction and exposure boundary |
| --- | --- | --- |
| `SqliteAuthorityStore`, `crates/platform/chio-store-sqlite/src/serving_owner.rs` | `provision(database_path: impl AsRef<Path>, lock_root: impl AsRef<Path>) -> Result<(), SqliteServingOwnerError>`; `open_serving(database_path, lock_root) -> Result<Self, SqliteServingOwnerError>`; `open_serving_with_clock(database_path, lock_root, Arc<dyn Clock>) -> Result<Self, SqliteServingOwnerError>`; `mutation_fence(&self) -> StoreMutationFence` | One serving connection and owner; `crates/platform/chio-control-plane/src/durable_admission.rs` composes it. `delegation_store(&self) -> SqliteDelegationStore` and `work_graph_store(&self) -> SqliteWorkGraphStore` are the only D1/S1 constructors; both share the serving connection, owner and fence. New authoritative tables must join the closed projection catalog, global-commit chain, integrity verification and relocation checks. |
| `SqliteCapabilityAuthority`, `crates/platform/chio-store-sqlite/src/authority.rs` | `open(path: impl AsRef<Path>) -> Result<Self, AuthorityStoreError>`; `open_with_clock(path, Arc<dyn Clock>)`; `CapabilityAuthority::issue_capability(&self, subject: &PublicKey, scope: ChioScope, ttl_seconds: u64) -> Result<CapabilityToken, KernelError>` | Separate issuer/key custody, not a serving-store adapter. Issuance creates a fresh UUID, signs and commits, but exposes no retained body indexed by a Work issuance ID. W1.4a must extend this owner before a lost reply can resolve without issuing again. |
| `ProcessRuntime`, `crates/kernel/chio-process/src/lib.rs` | `open(path: impl AsRef<Path>, kernel: Arc<ChioKernel>) -> Result<Self, ProcessError>`; `tool_request(&self, process_id: &str, operation_key: &str, server_id: &str, tool_name: &str, arguments: Value) -> Result<ToolCallRequest, ProcessError>` | Trusted host construction; capabilities and checkpoints remain in the protected process journal. Route/security-profile/supplemental-authority configuration is host-selected. |
| Process dispatch, same source | async `invoke_known_only(&self, process_id: &str, operation_key: &str, request: &ToolCallRequest) -> Result<ToolCallResponse, ProcessError>` | Pins no redispatch after unknown outcome, including read-only tools. Ordinary `invoke` permits bounded fresh read-only attempts and cannot implement Work's unknown-effect rule. |
| `WorkerService`, `crates/kernel/chio-process/src/worker.rs` | `new(runtime: ProcessRuntime) -> Self`; `with_invocation_preparer(self, Arc<dyn InvocationPreparer>) -> Self`; async `handle_frame(&self, frame: &[u8]) -> Vec<u8>` | Public under `worker-server`; credential authentication and wire operation enum are private. Current operations are Inspect, PrepareInvocation, Invoke, Checkpoint, BlobPut, BlobRead and Cancel. No Work envelope exists. Extend this authenticated listener. |
| `InvocationPreparer`, same source | `prepare(&self, runtime: &ProcessRuntime, request: PreparationRequest<'_>) -> Result<Value, ProcessError>` | Synchronous host-selected trait; request borrows process/operation/server/tool/arguments. It is neither an async Work transport nor a closed Work command API. CLI `native_broker/preparation.rs::Preparer` is crate-private and broker-specific. |
| `ProcessRegistry`, `crates/kernel/chio-process/src/registry.rs` | `prepare_invocation(&self, process: &str, operation_key: &str, binding: &str, prepare: impl FnOnce(&CapabilityToken, &Keypair) -> Result<Value, ProcessError>) -> Result<Value, ProcessError>` | `store/prepared.rs` retains a local callback's exact result in an immediate transaction. Same key/binding returns those bytes; changed binding conflicts. No remote signing, network operation or external effect may occur inside that callback. |
| Native custody, `crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress.rs` | `prepare_native_security_egress<'a>(&'a self, operation_id: &AdmissionOperationId, request: &'a ToolCallRequest, context: &SecurityInvocationContext) -> Result<PreparedNativeSecurityEgress<'a>, KernelError>` | Requires already admitted CapturePending and original fenced retained material. The private handle borrows the live request; it is not transferable pre-admission custody for Work preparation. |
| Native original records, `crates/kernel/chio-kernel/src/admission_operation/store.rs` | `load_by_operation_id(&AdmissionOperationId)` / `load_by_replay_key(&AdmissionReplayKey) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError>`; `load_execution_nonce_issuance(&AdmissionOperationId, &StoreMutationFence, u64) -> Result<Option<AdmissionExecutionNonceReservationV1>, AdmissionOperationStoreError>` | Records and original nonce remain owner-authoritative after response loss. Lookup grants no caller metadata access and does not renew live execution authority. |
| Kernel historical reconciliation, `crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs` | `reconcile_durable_admission_startup(&self)` and `reconcile_recoverable_admissions(&self) -> Result<usize, KernelError>` | Native historical settlement, not the scoped REC workflow protocol or a read-only Work query. |

### D1 and S1 prerequisites

`chio-workflow::delegation` defines the D1 records, signing domains and pure transition rules (`crates/platform/chio-workflow/src/delegation/{types,transition}.rs`); it owns no storage. The only allocator is `SqliteDelegationStore` in `crates/platform/chio-store-sqlite/src/delegation_store.rs`, with `create_root`, `slot`, `allocation_digest`, `subdivide`, `select`, `claim_dispatch`, `seal_dispatch` and `historical_dispatch`. Every mutation takes `(command_id: &str, ..., fence: &StoreMutationFence, trusted_now_unix_ms: u64)`, runs in one immediate transaction behind the serving fence, binds the command ID to its exact request digest (`CommandConflict` on a changed body) and appends one `work_delegation` event to the global commit chain. The kernel delegated-work guard that admits a sealed permit at a receiver is not on main; it depends on the checked-output zero-charge contract.

`seal_dispatch(&self, command_id: &str, binding: &DispatchBinding, issuer: &Keypair, fence: &StoreMutationFence, trusted_now_unix_ms: u64) -> Result<Signed<DispatchPermit>>` commits exact signed permit bytes and dispatched state together; a replayed command returns the retained bytes. `historical_dispatch(&self, binding: &DispatchBinding, issuer: &PublicKey) -> Result<Option<Signed<DispatchPermit>>>` reads a retained permit without fresh liveness, so an expired permit stays readable as history while fresh sealing refuses. Sealed allocations are never released.

Main's `crates/kernel/chio-swarm-authority/src/verifier.rs` supplies `verify_swarm_authority_for_admission` and `verify_swarm_authority_bundle`, plus `mint_swarm_join_receipt(request: SwarmJoinReceiptMintRequest, keypair: &Keypair) -> Result<SwarmJoinReceipt, SwarmAuthorityError>`. Minting signs supplied parent/result claims and retains no issuance transaction. The verifier's `all_success` parent receipt-set check is not an evaluator decision over exact producer output.

Main also has `verify_swarm_authority_extension(previous: &SwarmAuthorityBundle, candidate: &SwarmAuthorityBundle, trusted_keys: &[PublicKey], now_unix_ms: u64) -> Result<SwarmAuthorityVerifierReport, SwarmAuthorityError>` in `crates/kernel/chio-swarm-authority/src/evolution.rs`.

`SqliteWorkGraphStore` in `crates/platform/chio-store-sqlite/src/work_graph_store.rs` is the qualified S1 issuer: `provision_root(bundle, trusted_keys, fence, trusted_now_unix_ms)` and `advance(expected_bundle_sha256, candidate, trusted_keys, fence, trusted_now_unix_ms) -> Result<WorkGraphIssuance>` verify the bundle or strict additive extension, archive the predecessor by task-graph digest and retain the issuance by candidate digest under one `work_graph` global commit. `issuance(&self, bundle_sha256)` resolves an acknowledged-lost advance to its original success after later heads; `head` and `version` read the current and archived bundles. It is the only S1 writer. Runtime admission resolves the exact graph version a request references through `chio_runtime_core::SwarmGraphSource`; `chio_runtime::IssuedSwarmGraphs` serves it from `version`, and runtime stores hold no swarm graphs. W1.4a must still retain unsigned drafts and publish only the committed artifact.

### Manifest, treaty and evaluator provenance

Main's `chio_manifest::verify_manifest(&SignedManifest, &PublicKey) -> Result<(), ManifestError>` checks a canonical signed body. `VerifiedManifestRegistry::register(signed: SignedManifest, registered_key: &PublicKey, policies: &BTreeMap<String, AuthoritativeToolPolicy>, topologies: &BTreeMap<String, RuntimeToolTopology>) -> Result<(), VerifiedManifestAdmissionError>` verifies configured policy/topology before insertion (`crates/platform/chio-manifest/src/admission.rs`). `verified_manifest`, `verified_manifests` and `tool_security` expose admitted snapshots. A manifest/body/registry digest is not a semantic generation.

Two `TreatyScope` families exist: `chio_federation::treaty` and `chio_runtime_core`. Both expose `compute_ladder_intersection` and `evaluate_cross_boundary_admission`; their scope/report/error types differ. Public evidence inputs include a `verified: bool`, so a report computed from caller-supplied evidence is not native provenance. `crates/kernel/chio-runtime-core/src/admission_hook/treaty_evidence.rs::verify_treaty_reference_from_store` loads retained artifacts, verifies exact request/lineage/DSSE bindings, constructs evidence and uses the private verified kernel material. Work reuses this boundary, not a caller's evidence flags.

D1 `Acceptance::check(&self, value: &Value) -> Result<()>` in `crates/platform/chio-workflow/src/delegation/types.rs` evaluates 1 to 16 Equals/IntegerRange clauses. It creates no native invocation, receipt, resource charge or retained evaluator decision. W1.5a requires ordinary explicitly authorized evaluator work and exact producer/artifact/procedure/evaluator receipt matching.

## Complete request and custody projection

Main defines exactly 16 fields in `crates/kernel/chio-kernel/src/runtime.rs`. Optional values omit None; the approval vector omits an empty list. Retention constructs a credential-redacted request explicitly in `admission_operation/retained_request.rs`.

`P/F/L` indicates inclusion in the process, full F1 and live native canonical requests when present. `R` indicates inclusion in the generic retained request. `I` indicates inclusion in the base immutable native hash; independent capability/request/security/authority bindings still apply. The process projection normalizes the first-attempt ID and may precede nonce attachment.

| Field | Exact type | P/F/L | R | I and custody consequence |
|---|---|---|---|---|
| `request_id` | `String` | yes, P normalizes first attempt | yes | Not in base I; independently bound by `AdmissionOperationBindingV1`. Must preserve original operation identity. |
| `capability` | `CapabilityToken` | yes | yes | Base I contains selected matching grants and indices, not whole capability; full capability hash and ID are independently bound. Process journal persists host capability. |
| `tool_name` | `String` | yes | yes | yes |
| `server_id` | `ServerId` | yes | yes | yes |
| `agent_id` | `AgentId` | yes | yes | yes |
| `arguments` | `serde_json::Value` | yes | yes | yes; separate args/action and flow-payload hashes also exist. May contain protected material. |
| `dpop_proof` | `Option<dpop::DpopProof>` | yes | no | no; one-shot proof and replay authority stay with their owner, not retained request reconstruction. |
| `execution_nonce` | `Option<SignedExecutionNonce>` | yes | no | no; ProcessRuntime separately persists the original issued nonce before dispatch. |
| `governed_intent` | `Option<GovernedTransactionIntent>` | yes | yes | yes; embeds approval context, D1/S1/treaty/runtime references in composed examples. |
| `approval_token` | `Option<GovernedApprovalToken>` | yes | no | no; signed approval artifact has its own digest/consumption owner. |
| `approval_tokens` | `Vec<GovernedApprovalToken>` | yes | no | no; bounded threshold set, mutually exclusive with singular token. |
| `threshold_approval_proposal` | `Option<ThresholdApprovalProposal>` | yes | no | no; binds threshold set through a separately domain-separated digest. |
| `supplemental_authorization` | `Option<chio_core::capability::supplemental_authorization::OpaqueSupplementalAuthorization>` | yes | no | no; request wrapper is not quota authority; composition-installed verifier is decisive. |
| `model_metadata` | `Option<ModelMetadata>` | yes | yes | yes |
| `federated_origin_kernel_id` | `Option<String>` | yes | yes | yes; also in runtime admission binding. |
| `declassification_grant` | `Option<SignedDeclassificationGrant>` | yes | no | no; flow verifier and one-shot consumption own authority. |

Do not interpret R=no as a claim that no owning authority can ever retain any artifact. It means the general native retained-request artifact intentionally cannot reproduce that field. `RetainedToolAdmissionRequestV1::from_canonical_bytes` rejects such material rather than silently ignoring it (`retained_request.rs:223-244`). `RawInvocationOutcomeV1::from_committed_dispatch_with_request` uses the same credential-redacted projection (`tool_outcome.rs:519-558`).

## Distinct digest domains

The following algorithms describe the inspected source, including version labels still awaiting their owning v1 normalization. A Work adapter must not substitute one digest for another or retain an obsolete decoder to accommodate those labels.

Let `J(x)` be the existing canonical JSON bytes and `H(x)` be SHA-256. These are source algorithms, not proposed interchange rules.

1. **Arguments/action digest:** `H(J(request.arguments))`. Public runtime helper `tool_args_sha256(&Value) -> Result<String, ChioRuntimeError>` is at `crates/kernel/chio-runtime-core/src/hash.rs:68`. Native retained validation independently checks this action digest and capability digest at `retained_request.rs:395-410`. `RuntimeRequestBinding::from_tool_call_request(&ToolCallRequest, host_kernel_id: &str)` copies request ID, capability ID, server/tool, args hash, origin and host only (`admission_hook/request.rs:6-18`; type `types.rs:143-150`). It is not a full-request commitment.
2. **Process logical request ID:** `process:` plus `H(J((namespace, process_id, operation_key)))`; later admitted read-only attempts use `(namespace, process_id, operation_key, attempt)`. Public `request_id(...)` and private `request_id_for_attempt(...)` are at `crates/kernel/chio-process/src/lib.rs:297-326`.
3. **Process request/binding:** clone the entire request, replace request ID with the first-attempt ID, then `request_hash = H(J(binding))`. If known-outcome-only, hash `("chio.process.known-outcome-only.v1", request_hash)`; if a host route exists, hash `("chio.process.host-route.v1", prior_hash, route)`; if security profile exists, hash `("chio.process.security-context.v1", prior_hash, profile)`. These wrappers hash canonical tuples. See `lib.rs:408-446` and private `digest` at `651-652`. This binding is stored before kernel admission. A new or retained nonce can be attached later at `483-564`; therefore process request hash and final dispatch hash need not be equal.
4. **Retained material equality:** `H(J({schema:"chio.frozen-tool-request-material.v1", request: credential_redacted_request}))`. Private `pub(crate) fn request_material_digest(&ToolCallRequest) -> Result<AdmissionDigest, AdmissionOperationStoreError>` at `retained_request.rs:186-200`. It is in-memory equality data, not authority, and ordinary dispatch does not inherit the retained artifact size limit.
5. **Native immutable request:** base schema `chio.tool-admission-request.v1` hashes server/tool/agent/arguments/governed-intent/model/federated-origin plus matching grant indices and grants and frozen post-return steps. An optional security binding wraps the base digest in v2 or v3; an authority profile wraps that prior digest in v4. These helpers are `pub(crate)` at `retained_request.rs:80-155`. Separate admission binding includes full capability hash, capability ID, request ID and action hash (`375-410`). `derive_request_binding_hash` then hashes domain `chio.admission-request-binding.v1\0` plus canonical `{immutable_request_hash,action_parameter_hash,participant_requirements}` (`admission_operation/identity.rs:684-715`; domain `admission_operation.rs:93`).
6. **Retained artifact digest:** `H(original.canonical_bytes())` includes the retained v4 envelope, grant indices, frozen steps, security binding and authority profile, not merely its request. Used by `PreparedNativeSecurityEgress::retained_request_digest` (`kernel/admission_coordinator/native_egress.rs:265-272`) and caller dispatch context (`admission_operation/caller_dispatch_context.rs:195-201`). Native caller release instead uses `H(J(original.request_for_revalidation()))` (`native_caller_custody.rs:140-146`). These two retained digests also differ from item 4.
7. **Approval parameter hash:** `ApprovalRequest.parameter_hash` is set from `GovernedTransactionIntent::binding_hash()` (`crates/products/chio-api-protect/src/proxy/approval.rs:254`).
8. **Governed intent/approval artifacts:** `GovernedTransactionIntent::binding_hash()` is `H(J(intent))` (`crates/core/chio-core-types/src/capability/governance.rs:1223-1228`). `ToolApprovalContext::bind` inserts tenant, current policy hash, full capability hash, request ID and arguments into intent context, and makes `BoundToolInvocation` with capability ID and `H(J(arguments))` (`approval/tool_context.rs:28-49,75-104`). Public kernel `bind_tool_approval_intent(&ToolCallRequest)` first validates current capability, caller, revocation and matching grants (`kernel/governed_validation/tool_approval.rs:42-110`). Signed approval token digest is `H("chio.governed-approval-token.v1\0" || J(token))`; threshold proposal uses `chio.threshold-approval-proposal.v1\0`; set uses `chio.verified-approval-set.v1\0` and sorted unique signed token digests plus proposal/body bindings (`governance.rs:23-27,1413-1419,1714-1788`). `ToolCallRequest::approval_artifact_digest` selects singular/set and rejects conflicting/incomplete/oversized combinations (`runtime.rs:147-185`).
9. **Flow/declassification payload hash:** control-plane `FlowPolicyView::classify_arguments` canonicalizes *only arguments*, produces payload digest, then `resolve_pre_with_evidence` calls `canonical_request_hash` on those argument bytes (`crates/platform/chio-control-plane/src/security/adapters/flow_policy.rs:54-64,131-134,180-198`). Public `chio_flow::canonical_request_hash(&CanonicalBody)` requires exact canonical JSON, bounded at 16 MiB, then returns `H(canonical)` (`crates/security/chio-flow/src/declassification.rs:378-388`). Name notwithstanding, this instance is not full ToolCallRequest hash.
10. **Flow live-request digest:** separate `pub(super) live_request_digest(&ToolCallRequest) -> Result<Digest32, FlowDenial>` hashes `J(entire_request)` (`control-plane/.../flow_dispatch.rs:452-455`, byte hash helper `receipt_projection.rs:17-18`). This protects a different comparison from item 9.
11. **Native live dispatch commitment:** public `NativeSecurityDispatchRequestBindingV1::from_live_request(&ToolCallRequest,&SecurityInvocationContext)` checks a 16 MiB full canonical request then computes its full digest and dispatch commitment (`admission_operation/native_dispatch_binding.rs:12-43`). Commitment is SHA-256 over `b"chio.kernel.security-pre-dispatch.commitment.v2\0" || u64be(request_len) || request_bytes || u64be(context_len) || J(context_binding)`, prefixed `dispatch-commitment:`. Context binds version, tenant/session/principal/isolation/lineage, context generation and optional flow generation (`kernel/dispatch/security_pre_dispatch.rs:16-29,43-79`). It is not merely a request hash.
12. **DPoP invocation binding:** public `invocation_binding_digest(capability,server,tool,action_hash)` hashes canonical tuple `("chio.dpop-invocation-binding.v1", capability.id, capability.subject, server, tool, action_hash)` (`dpop/authority.rs:206-221`). Caller must still verify capability and proof signature.
13. **F1 complete final request, PR1173 only:** `Agreement.request_sha256 = digest(request)` and later `SignedAgreement::validate` recomputes it (`examples/federated-work/src/funded_work/evolving.rs:150-164`; `agreement.rs:114-124`). `common::digest<T: Serialize>` is `H(J(value))` with no extra digest domain (`common.rs:43-44`). All 16 fields are covered when serialized; no request projection or transient removal is applied. Agreement terms separately use `0x` plus `H(J(agreement_body))` (`agreement.rs:65-77`). Never insert that resulting agreement digest into the same request it hashes.

## Exact request assembly

A complete Work preparation requires this order:

1. Resolve provisioned profile/treaty/role, original process operation key, receiver capability and issuance IDs.
2. Commit D1 selection/seal and graph membership under their qualified owners. Preserve the original allocator, request and graph identities.
3. Assemble arguments, graph/treaty/governed context and approval/flow bindings using the actual owning validators. Retain the exact authoritative profile basis.
4. Reserve the original process call, obtain protected native request custody and finalize the original nonce and complete request. Recheck current authority at native commitment. No coordinator DTO can replace custody.
5. Compute the F1 full-request commitment only after the final serialized request is fixed, then create agreement/reserve through the optional funding owner. Never insert the agreement digest into the request it hashes.
6. Submit by the original known-only identity; lost replies use owner readback. An unknown effect cannot authorize a fresh attempt.

Main computes its process binding before it attaches a retained/new nonce (`chio-process/src/lib.rs`). The pending F1 example hashes the entire final request but refuses DPoP, execution nonce and approval-artifact profiles (`examples/federated-work/src/funded_work/native.rs`). Those are different supported profiles, not interchangeable hashes. W1.4b must prove the complete protected assembly for every added profile; nonce/approval support remains unavailable until that test passes.

The example journal atomically stages its full canonical request and agreement under allocation/request identity and rejects changed bytes. It is an application journal, not a public Work preparation authority. Runtime command indexes retain only immutable digests and owner references; deletion, corruption or expiry of that projection cannot renew an issuance, nonce or allocation.

## Pending recovery owners

Every path in this section refers to the pinned recovery source. None of these APIs exists on the inspected main.

| Real interface | Exact owner and behavior |
| --- | --- |
| `RecoveryProcessReservationPort::verify_reservation(&self, &RecoveryProcessReservationV1) -> Result<(), AdmissionOperationStoreError>` | `crates/kernel/chio-kernel/src/recovery/ports.rs`; proves a committed process reservation. |
| `RecoveryProcessOriginPort::verify_original_request(&self, &RecoveryScopeV1, &ToolCallRequest, expected_session: &str) -> Result<(), AdmissionOperationStoreError>` and `original_request_scope(...) -> Result<RecoveryOriginalRequestScope, RecoveryOriginalRequestError>` | Same module; verifies original process journal identity without another admission or quota charge. A refusal default is not an implemented capability and must not become a Work trait shim. |
| `RecoveryAuthorityPort::command(&self, &AuthenticatedRecoveryActor, &RecoveryCommandV1, Option<&dyn RecoveryProcessOriginPort>, &StoreMutationFence, now: u64) -> Result<RecoveryCommandResponseV1, RecoveryCommandPortError>` | Implemented by `SqliteAdmissionOperationStore` in `admission_operation_store/recovery.rs`; mutable owner authority remains at the transaction. Its recovery-grant issuance journal does not issue D1, S1, capability-offer or agreement artifacts. |
| `ProcessRuntime::reserve_recovery_call(&self, process_id: &str, operation_key: &str, &ContinuationId, IntentDigest, server_id: &str) -> Result<RecoveryCallReservation, ProcessError>` | `crates/kernel/chio-process/src/recovery.rs`; reserves the logical slot once before approval. |
| `ProcessRuntime::finalize_recovery_call(&self, &RecoveryCallReservation, &RecoveryRequestCustody) -> Result<(), ProcessError>` | Same module; checks original process, namespace, request, route, intent and full binding digests. |
| `ChioKernel::load_recovery_request_custody(&self, &AuthenticatedRecoveryActor, &WorkflowId) -> Result<RecoveryRequestCustody, KernelError>` | Kernel recovery ports; private non-Clone carrier holds the original protected envelope and nonce. Custody is not live admission. |
| async `RecoveryRuntime::execute(&self, capability: &CapabilityToken, bytes: &[u8]) -> Result<RecoveryCommandResultV1, RecoveryRuntimeError>` | `crates/platform/chio-control-plane/src/recovery/runtime.rs`; actual scoped recovery protocol. Work carries authorized references to it, without adding synonymous Explain/Approve/Resume commands. |

The proposed names `ProcessRecoveryPort`, `KernelRecoveryPort`, `ArtifactReleasePort`, `ConfinedReturnPort` and `SemanticDeploymentBindingV1` are not current Rust interfaces. Do not implement adapters against those names.

### Semantic profile and dependency ownership

The actual pending type is `SemanticDeploymentV1`, with scope, generation, native/context/exposure bindings, packages and routes (`crates/security/chio-security-types/src/semantic/package.rs`). `SqliteAdmissionOperationStore::read_semantic_installation(&self, &RecoveryScopeV1, &StoreMutationFence, now: u64) -> Result<NativeSemanticInstallationV1, AdmissionOperationStoreError>` reads the owning snapshot (`admission_operation_store/semantic/policy.rs`).

`compile_semantic_registry(deployment: &SignedSemanticDeploymentV1, packages: &[SignedSemanticPackageV1], operator_root: &PublicKey, publisher_roots: &[PublicKey], exposed: &[ExposedSemanticToolV1], budget: &mut VerificationBudget) -> Result<CompiledSemanticRegistryV1, ContractError>` lives in `crates/security/chio-semantic-contracts/src/registry.rs`. `resolve(&self, server: &str, tool: &str)` selects its route/operation contract. The compiled registry is historical evidence, not a capture witness.

`SemanticPrerequisiteKindV1::{HistoricalFact, CurrentPredicate, HeldReservation}` binds producer/resource/version/material/action/scope/purpose/lease evidence. Internal native `verify_current_prerequisites` and `verify_dispatch_prerequisites` in `admission_operation_store/semantic/materialization.rs` own current authority and freshness. Work does not duplicate their enum, evaluator or reservation state.

### Artifact and confined-return ownership

`NativeKnowledgeRuntime::new(kernel: Arc<ChioKernel>, store: Arc<SqliteAdmissionOperationStore>, broker: Arc<dyn ArtifactBlobPort>, profile: NativeKnowledgeInstallationV1, fence: StoreMutationFence) -> Result<Self, KernelError>` is the actual pending host constructor (`crates/platform/chio-control-plane/src/knowledge.rs`). Its relevant methods are:

- `publish(&self, capability: &CapabilityToken, input: &ArtifactPublicationInputV1, bytes: &[u8], certificate: Option<&SignedArtifactCertificateV1>) -> Result<ArtifactVersionRefV1, KernelError>`;
- `handle(&self, &CapabilityToken, &ArtifactVersionRefV1, &ArtifactRecipientId) -> Result<ArtifactHandleV1, KernelError>`;
- `prepare_read(&self, &CapabilityToken, &ArtifactHandleV1) -> Result<PreparedArtifactRead, KernelError>`;
- `release_into(&self, &CapabilityToken, &RequestId, PreparedArtifactRead, &dyn ArtifactReleaseSink) -> Result<ArtifactDeliveryOutcomeV1, KernelError>`.

Publication preserves producer/source/dependency confidentiality and influence. The input permits at most 16 direct dependencies, and the resolver requires their complete `RecoveryScopeV1` to match. A cross-process join cannot weaken that scope check. Such input materialization stays unsupported until the owning release/transfer contract is qualified. Work's metadata manifest supplies neither input bytes nor authorization.

Release admission commits its owner record before delivery. `release_into` reauthenticates the exact recipient/sink and marks delivery uncertain before sink I/O; an accepted result, historical settlement or query cannot substitute for current release. A generic public Work release-status resolver is still missing.

`NativeConfinedRuntime` in `crates/platform/chio-control-plane/src/confinement.rs` exposes `review_return`, `prepare_return`, and `deliver(capability, PreparedConfinedReturn, sink, disclosure, endorsement) -> Result<ReturnAdmissionV1, ConfinedDeliveryError>`. The actual profile supports one canonical Boolean in the Value channel, at most 8 bytes and one value. It is not a general Work join-input transport.

## Bounds and feature boundaries

### Existing limits

| Boundary | Inspected limit | Owner |
| --- | --- | --- |
| Worker wire | 2 MiB request / 8 MiB response including newline; body length at the request ceiling is refused | `chio-process/src/worker.rs` |
| Worker I/O | 32 connections, 5-second read and write deadlines; no outer execution deadline | `chio-process/src/worker/unix.rs` |
| Process state | Default 64 MiB / 4096 blobs; maxima 1 GiB / 16384 blobs; one blob/checkpoint at most 1 MiB | `chio-process/src/types.rs`, `store/prepared.rs` |
| Retained native request | At most 262144 bytes | `chio-kernel/src/admission_operation/retained_request.rs` |
| Full live native request | At most 16 MiB; binding ledger at most 1 MiB | `chio-kernel/src/admission_operation/native_dispatch_binding.rs` |
| S1 graph | 1024 tasks, 4096 edges, 1024 joins | `chio-swarm-authority/src/types.rs` |
| Treaty predicate | Depth 32, 1024 nodes, 64 KiB JSON, 1024-byte atom | `chio-runtime-core/src/treaty/predicate.rs` |
| Native deadlines | Default guard/dispatch deadlines are zero (unbounded); receipt append defaults to 5000 ms | `chio-kernel/src/kernel/kernel_struct.rs` |
| HTTP service | 15-second timeout; bounded blocking lanes hold permits until worker completion | `chio-control-plane/src/trust_control/service_types/{paths,blocking}.rs` |
| D1 | 64 children, 4096 slots/root, depth 32, 64 effects, 256 readers, 65536-byte nested envelope, MAX_UNITS 9007199254740991, 16 predicate clauses | `chio-workflow/src/delegation/{types,transition}.rs` |
| Pending artifact publication | 16 direct dependencies, exact recovery-scope equality | Recovery source `admission_operation_store/knowledge/{publication,traversal}.rs` |

### Work profile limits to implement

These are explicit Work-profile limits, not claims of existing enforcement. W1.1 must add exact-maximum, one-over and nested-expansion vectors before enabling the profile. A stricter native or artifact-family limit always wins.

| Work boundary | Limit and refusal contract |
| --- | --- |
| Wire | Request body at most 2097151 bytes plus one newline; response including framing at most 8388608 bytes. Refuse before decoding an oversized frame. |
| Retained invocation | At most 262144 bytes, and every nested D1 envelope at most 65536 bytes. A larger wire frame cannot widen custody limits. |
| Catalog | At most 64 entries/page; immutable caller/generation-bound continuation. |
| Command delta | At most 16 new work items, 64 dependency edges and 16 join drafts; at most 16 distinct parents per join. Full graph limits remain 1024 tasks / 4096 edges / 1024 joins. |
| Aggregate decoded input | Depth at most 32; at most 16384 JSON nodes and 8192 collection entries across the entire request and expanded embedded artifacts. Charge the cumulative budget before visiting/allocating each item. |
| Verification | At most 8192 signature-verification operations across the whole request, chain depth at most 32. Duplicates and retries cannot reset the request budget. |
| Owner execution | At most 2 active blocking Work owner operations per host; zero waiting operations in that lane. Saturation returns a typed busy refusal before mutation. Hold the permit through actual worker completion. |
| Time | 5-second frame read/write; 15-second Work response budget from the injected owner clock/deadline source. Before owner commitment, expiration refuses; after commitment or ambiguous handoff, return Pending with original references. It cannot cancel an obligation or justify fresh dispatch. |

The 16-parent limit matches the pending artifact dependency ceiling. Full-scope equality still applies; the numerical bound does not authorize cross-scope materialization. D1 aggregate allocation/quantity caps stay unchanged. No default native zero deadline or host-selected process quota is treated as a finite Work-wide budget.

### Manifest dependency graph

`cargo metadata --no-deps --offline --locked --format-version 1` identifies 182 workspace members at the main pin. It has no resolved external dependency graph. The following edges are read from manifest declarations; no compilation or isolated/unified feature qualification is claimed.

| Package | Existing declared dependencies relevant to Work |
| --- | --- |
| `chio-runtime` | No feature section; unconditional runtime-core, kernel, core-types, swarm-authority and weights |
| `chio-runtime-core` | No feature section; unconditional kernel, federation, swarm-authority, weights, runtime-proof-parity, attest-buyer-core and SQLite |
| `chio-control-plane` | Default empty; kernel enables finding-market; settle/store-sqlite unconditional; runtime-core dev-only; no normal process/workflow/runtime dependency |
| `chio-process` | Default empty; `worker-server` enables Tokio/rand/hex/base64; `mailboxes` enables async-trait/manifest/Tokio; kernel unconditional |
| `chio-workflow` | Core and workflow-preflight unconditional; no SQLite |
| `chio-store-sqlite` | Workflow (D1 rules) and swarm-authority (S1 verifiers) unconditional for the qualified stores; settle with defaults |
| `chio-settle` | Default `web3`; disabling defaults leaves secrecy as the direct normal dependency and disables the library, not an available chain-free settlement implementation |

Runtime/runtime-core/process reach default-web3 settle through kernel. Control-plane and store-sqlite also depend on settle with defaults. Workflow reaches web3 through core. A root package's `--no-default-features` does not disable transitive defaults, and an opt-in Work feature alone proves no isolation. W1.1/W1.7 must compare declared and resolved isolated/unified graphs, reject dependency cycles and keep optional funded composition out of authority-free client DTOs.

## Implementation order

| Step | Deliverable | Dependency and complete acceptance |
| --- | --- | --- |
| Substrate | D1 rules and additive S1 on main with their original tests | Landed; the kernel delegated-work guard waits for the checked-output contract |
| W1.1 / W1.2 | Strict v1 contracts and qualified single-writer work stores | On main: `chio.work.v1` contracts and the serving-owner D1/S1 stores with exact schema refusal; no parallel allocator |
| W1.3a | Manifest/treaty/catalog projection | Available native owners and D1 where referenced; unsupported semantic profiles refuse |
| W1.4a | Pure bindings plus durable role-local intent/issuance/readback | Qualified D1/S1/capability issuers; issuer durability is not deferred to generic REC |
| W1.5a / W1.6a | Exact acceptance evidence, pure join inputs, scoped indexes and issuer readback | No unavailable release/capture owner is replaced by a boolean or cache |
| W1.3b / W1.4b | Installed semantic profiles and complete original request custody | Qualified semantic installation, process reservation/origin and native authority owners |
| W1.5b / W1.6b | Protected join materialization, native submission and scoped recovery/release | Actual knowledge/prerequisite owners and known-only original identity; all post-REC tests remain mandatory |
| W1.7 | Public client conversion and complete local contract | Both halves of every required task; no local-only profile closes the full Work exit |

W1.3 and W1.4 require the split because semantic installation and exact protected request custody are absent from main. Original-ID issuance itself is issuer-local and belongs in W1.4a. W1.5a cannot publish a join requiring missing protected materialization; W1.6a cannot submit or recover an uncertain native effect. The halves are ordered acceptance boundaries, not dual APIs or permissive feature fallbacks.

### Required behavioral evidence

- Stale fence, changed command body, incomplete current namespace and mismatching schema stamp return their exact refusal before authority expansion.
- Concurrent original-ID issuance produces one retained artifact. Fail before issuance, after owner commit/before index and after index/before reply; remove the index and recover identical original bytes.
- Read an expired retained permit historically while fresh execution still refuses. A crash before permit persistence cannot invent or backdate a permit or refund consumed capacity.
- Competing graph drafts expose only the committed successor. Resolve an acknowledged-lost A extension after B advances, without altering B or its consumed continuation.
- Wrong task/operation/artifact/version/procedure/evaluator refuses acceptance; query performs zero evaluator or tool dispatches.
- Unknown effect, lost reply, cancelled transport and missing coordinator index preserve the original process key/request/nonce/native operation and produce no second dispatch.
- Revoked recipient, changed current predicate, expired reservation and wrong resource/scope deny result materialization and dependent capture. Historical settlement remains separate from current release.
- Saturated/expired queues fail before mutation; dropped response futures retain permits and original obligations until owner completion or supervised handoff.

No runtime test result is recorded by this source inventory. The first implementing slices run full library/integration suites for every changed crate and strict all-target Clippy, with genuine behavioral RED/GREEN evidence. The qualified D1/S1 store suites (`chio-store-sqlite` `work_delegation_authority`, `work_graph_authority`) and swarm-extension suites run on main; REC suites cannot be counted as passed against a main tree where they do not exist. The complete Work runtime exit and release qualification remain open.
