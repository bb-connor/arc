//! Admitted treaty call whose receipt lineage bundle is as deep as the sweep
//! asks for.
//!
//! Identical to the in-process admitted path in every respect but one: the
//! lineage bundle the request cites carries `depth` verified statements instead
//! of one. Statement zero is the edge that binds the continuation and the
//! bilateral invocation, so the two scans that look for it terminate at the
//! first statement whatever the depth; what grows with depth is the chain walk
//! that validates every edge, the per-statement digests it takes, and the
//! canonical hash of the bundle the receiver resolves from its own store.
//!
//! The depth is a property of the bundle the RECEIVER holds. A request names the
//! bundle by id and digest and cannot supply one, so this measures the cost of a
//! deep lineage the receiver has already accepted, not a bundle a peer pushed at
//! it inside the request.

use chio_core_types::capability::{
    governance::GovernedTransactionIntent,
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    metadata::ActorRef,
};
use chio_federation::bilateral::InProcessCoSigner;
use chio_federation::bilateral_dsse::{
    sign_chio_bilateral_dsse_envelope, BilateralPredicateExtensions, CapabilityLeaseRef,
    DsseEnvelope, GovernanceReceiptRef, HashRecord, PolicyEvaluationSummary, PolicyVerdict,
    TreatyBindingRef,
};
use chio_federation::trust_establishment::{KernelTrustExchange, PeerHandshakeEnvelope};
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolCallRequest, ToolServerConnection,
    Verdict, DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_runtime_core::{
    bilateral_dsse_consistency_model, bilateral_invocation_binding_sha256,
    compute_ladder_intersection, governance_ladder_manifest_sha256, ladder_intersection_sha256,
    receipt_lineage_statement_sha256, runtime_admission_bundle_sha256, runtime_peer_weights_sha256,
    tool_args_sha256, treaty_scope_sha256, verify_receipt_lineage_bundle, BilateralInvocation,
    ChioRuntimeAdmissionHook, CrossKernelContinuation, GovernanceLadderActionClass,
    GovernanceLadderManifest, InMemoryRuntimeAdmissionStore, ReceiptLineageBundle,
    ReceiptLineageStatement, RuntimeAdmissionBundle, RuntimeAdmissionProfile,
    RuntimeAdmissionStore, RuntimePeerWeight, RuntimePeerWeights, RuntimePheromonePolicy,
    RuntimePheromonePolicyRule, RuntimeRequestBinding, RuntimeTrustedVerifierKey,
    RuntimeVerifierTrustBundleV4, SignedRuntimePeerWeights, SignedRuntimePheromonePolicy,
    SignedRuntimePheromoneQueryReport, SignedRuntimeVerifierTrustBundle, TreatyScope,
    CHIO_BILATERAL_INVOCATION_SCHEMA, CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA,
    CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA, CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA,
    CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA, CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA,
    CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA, CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA,
    CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA, CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA,
    CHIO_TREATY_SCOPE_SCHEMA,
};
use chio_store_sqlite::SqliteReceiptStore;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::runtime::{Builder, Runtime};

const NOW_UNIX_MS: u64 = 1_800_000_001_000;
const ISSUED_AT_UNIX_MS: u64 = 1_800_000_000_000;
const EXPIRES_AT_UNIX_MS: u64 = 1_800_003_600_000;
const CAPABILITY_ID: &str = "cap-bench-admission-scaling";
const ACTION_CLASS_ID: &str = "workflow.destructive.vendor_call";
const ORIGIN_KERNEL_ID: &str = "kernel.buyer";
const LOCAL_KERNEL_ID: &str = "kernel.vendor-b";
const SERVER_ID: &str = "vendor-ledger";
const TOOL_NAME: &str = "close_account";
const GOVERNANCE_RECEIPT_ID: &str = "gov-bench-admission-scaling";
const VERIFIER_ID: &str = "did:chio:buyer-verifier";
const VERIFIER_KEY_ID: &str = "verifier-key-1";

type BoxError = Box<dyn std::error::Error>;

/// Result of one kernel evaluation on the scaling fixture.
#[derive(Debug)]
pub enum CallOutcome {
    /// The kernel admitted the call, the tool server ran exactly once, and a
    /// fresh allow receipt was signed.
    Admitted,
    /// The kernel denied the call before dispatch.
    Denied { failure_code: String },
}

pub struct AdmissionScalingFixture {
    depth: usize,
    lineage_bundle_bytes: usize,
    kernel: ChioKernel,
    base_request: ToolCallRequest,
    base_bundle: RuntimeAdmissionBundle,
    treaty: TreatyBase,
    store: InMemoryRuntimeAdmissionStore,
    request_sequence: AtomicU64,
    calls: AtomicU64,
    last_receipt_id: Mutex<Option<String>>,
    tool_invocations: Arc<AtomicU64>,
    runtime: Runtime,
}

impl AdmissionScalingFixture {
    /// Builds the receiver kernel around a SQLite receipt store at
    /// `receipt_store_path`, with every call's lineage bundle `depth`
    /// statements long, and admits one call to prove the path is live.
    pub fn new(receipt_store_path: &Path, depth: usize) -> Result<Self, BoxError> {
        if depth == 0 {
            return Err("a lineage bundle needs at least one statement".into());
        }
        let args = serde_json::json!({
            "record": "vendor-ledger-7",
            "value": "closed"
        });
        let binding = RuntimeRequestBinding {
            request_id: "req-bench-admission-scaling".to_string(),
            capability_id: CAPABILITY_ID.to_string(),
            server_id: SERVER_ID.to_string(),
            tool_name: TOOL_NAME.to_string(),
            tool_args_sha256: tool_args_sha256(&args)?,
            origin_kernel_id: Some(ORIGIN_KERNEL_ID.to_string()),
            host_kernel_id: LOCAL_KERNEL_ID.to_string(),
        };
        let bundle = RuntimeAdmissionBundle {
            schema: CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
            admission_id: "adm-bench-admission-scaling".to_string(),
            binding,
            workflow_id: "wf-bench-admission-scaling".to_string(),
            workflow_grant_id: "grant-bench-admission-scaling".to_string(),
            step_index: 1,
            destructive: true,
            lease_id: Some("lease-bench-admission-scaling".to_string()),
            governance_receipt_id: Some(GOVERNANCE_RECEIPT_ID.to_string()),
            trust_bundle_sha256: "b".repeat(64),
            verification_context_sha256: "c".repeat(64),
        };
        let config = kernel_config();
        let local_keypair = config.keypair.clone();
        let origin_keypair = Keypair::from_seed(&[21_u8; 32]);
        let verifier_keypair = Keypair::from_seed(&[26_u8; 32]);
        let store = InMemoryRuntimeAdmissionStore::new();
        let treaty = TreatyBase::new(&args, origin_keypair.clone(), local_keypair.clone(), &store)?;
        let request = treaty_request(args)?;
        let profile = RuntimeAdmissionProfile {
            schema: CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
            profile_id: "profile-bench-admission-scaling".to_string(),
            local_kernel_id: LOCAL_KERNEL_ID.to_string(),
            verifier_id: VERIFIER_ID.to_string(),
            issued_at_unix_ms: ISSUED_AT_UNIX_MS,
            expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
        };
        let policy = PolicyInputs::sign(&verifier_keypair, &bundle)?;
        let hook = ChioRuntimeAdmissionHook::new(profile, store.clone())
            .with_runtime_trust_input(policy.trust, policy.trusted_keys)
            .with_pheromone_query_report(policy.query_report)
            .with_runtime_pheromone_policy(policy.policy, policy.peer_weights)
            .with_fixed_now_unix_ms(NOW_UNIX_MS);
        let tool_invocations = Arc::new(AtomicU64::new(0));
        let peer_now_unix_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let trust = KernelTrustExchange::new(LOCAL_KERNEL_ID, local_keypair.clone())
            .with_trusted_peer(ORIGIN_KERNEL_ID, origin_keypair.public_key());
        let peer_envelope = PeerHandshakeEnvelope::sign(
            ORIGIN_KERNEL_ID,
            LOCAL_KERNEL_ID,
            "nonce-bench-admission-scaling-peer",
            peer_now_unix_secs,
            &origin_keypair,
        )?;
        let peer = trust.accept_envelope(&peer_envelope, ORIGIN_KERNEL_ID, peer_now_unix_secs)?;
        let mut kernel = ChioKernel::new(config).with_federation_peers(vec![peer]);
        kernel.set_federation_local_kernel_id(LOCAL_KERNEL_ID);
        kernel.set_federation_cosigner(Arc::new(InProcessCoSigner::new(
            ORIGIN_KERNEL_ID,
            origin_keypair,
            local_keypair.public_key(),
        )));
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(receipt_store_path)?))?;
        kernel.register_tool_server(Box::new(CountingToolServer {
            invocations: Arc::clone(&tool_invocations),
        }));
        kernel.set_runtime_admission_hook(Arc::new(hook));
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let lineage_bundle_bytes =
            canonical_json_bytes(&treaty.call(u64::MAX, "probe", depth)?.lineage)?.len();
        let fixture = Self {
            depth,
            lineage_bundle_bytes,
            kernel,
            base_request: request,
            base_bundle: bundle,
            treaty,
            store,
            request_sequence: AtomicU64::new(0),
            calls: AtomicU64::new(0),
            last_receipt_id: Mutex::new(None),
            tool_invocations,
            runtime,
        };
        let smoke_request = fixture.prepare_request()?;
        match fixture.evaluate_once(&smoke_request)? {
            CallOutcome::Admitted => {}
            denied => {
                return Err(format!(
                    "depth-{depth} scaling fixture smoke call was not admitted: {denied:?}"
                )
                .into())
            }
        }
        let receipt_id = fixture
            .last_receipt_id
            .lock()
            .map_err(|_| "scaling fixture receipt-id tracker is poisoned")?
            .clone()
            .ok_or("scaling fixture smoke call left no receipt id")?;
        if fixture.kernel.dual_signed_receipt(&receipt_id).is_none()
            || fixture
                .kernel
                .federation_dsse_envelope(&receipt_id)
                .is_none()
        {
            return Err("scaling fixture smoke call was not co-signed by the origin peer".into());
        }
        Ok(fixture)
    }

    /// Registers a fresh admission bundle, continuation, lease, lineage,
    /// invocation, and signed DSSE envelope in the receiver store and returns
    /// the request that references them. Untimed setup.
    pub fn prepare_request(&self) -> Result<ToolCallRequest, BoxError> {
        let sequence = self.request_sequence.fetch_add(1, Ordering::SeqCst);
        let request_id = format!("req-bench-admission-scaling-{sequence}");
        let admission_id = format!("adm-bench-admission-scaling-{sequence}");
        let lease_id = format!("lease-bench-admission-scaling-{sequence}");
        let mut bundle = self.base_bundle.clone();
        bundle.admission_id.clone_from(&admission_id);
        bundle.binding.request_id.clone_from(&request_id);
        bundle.lease_id = Some(lease_id.clone());
        let bundle_sha256 = runtime_admission_bundle_sha256(&bundle)?;
        self.store.insert_bundle(bundle)?;
        let call = self.treaty.call(sequence, &lease_id, self.depth)?;
        call.insert_into(&self.store)?;

        let mut request = self.base_request.clone();
        request.request_id = request_id;
        let intent = request
            .governed_intent
            .as_mut()
            .ok_or("benchmark governed intent is missing")?;
        intent.id = format!("intent-bench-admission-scaling-{sequence}");
        intent.context = Some(serde_json::json!({
            "chioAdmission": {
                "admissionId": admission_id,
                "bundleSha256": bundle_sha256
            },
            "chioTreaty": {
                "treatyScopeId": self.treaty.scope.treaty_id,
                "treatyScopeSha256": self.treaty.scope_sha256,
                "ladderIntersectionId": self.treaty.intersection_id,
                "ladderIntersectionSha256": self.treaty.intersection_sha256,
                "actionClassId": ACTION_CLASS_ID,
                "crossKernelContinuation": {
                    "id": call.continuation.continuation_id,
                    "sha256": call.continuation_sha256
                },
                "receiptLineageBundle": {
                    "id": call.lineage.bundle_id,
                    "sha256": call.lineage_sha256
                },
                "bilateralInvocation": {
                    "id": call.invocation.invocation_id,
                    "sha256": call.invocation_sha256
                },
                "bilateralDsse": {
                    "id": call.dsse_id,
                    "sha256": call.dsse_sha256
                }
            }
        }));
        Ok(request)
    }

    /// Runs one kernel evaluation. `Admitted` means the verdict was allow, the
    /// tool server counter moved by exactly one, and the receipt id is fresh.
    pub fn evaluate_once(&self, request: &ToolCallRequest) -> Result<CallOutcome, BoxError> {
        let invocations_before = self.tool_invocations.load(Ordering::SeqCst);
        self.calls.fetch_add(1, Ordering::SeqCst);
        let response = self
            .runtime
            .block_on(self.kernel.evaluate_tool_call(request))
            .map_err(|error| format!("kernel evaluation failed: {error}"))?;
        let invocations_after = self.tool_invocations.load(Ordering::SeqCst);
        match response.verdict {
            Verdict::Allow => {
                if invocations_after != invocations_before.saturating_add(1) {
                    return Err(format!(
                        "admitted request {} moved the tool counter from {invocations_before} to {invocations_after}",
                        request.request_id
                    )
                    .into());
                }
                if !matches!(response.receipt.decision, Some(Decision::Allow)) {
                    return Err(format!(
                        "admitted request {} carried a non-allow receipt decision",
                        request.request_id
                    )
                    .into());
                }
                let mut last_receipt_id = self
                    .last_receipt_id
                    .lock()
                    .map_err(|_| "scaling fixture receipt-id tracker is poisoned")?;
                if last_receipt_id.as_deref() == Some(response.receipt.id.as_str()) {
                    return Err(format!(
                        "request {} replayed receipt {}",
                        request.request_id, response.receipt.id
                    )
                    .into());
                }
                *last_receipt_id = Some(response.receipt.id);
                Ok(CallOutcome::Admitted)
            }
            Verdict::Deny => {
                if invocations_after != invocations_before {
                    return Err(format!(
                        "denied request {} reached the tool server",
                        request.request_id
                    )
                    .into());
                }
                let failure_code = response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata["chio_runtime"]["failure_code"].as_str())
                    .map(str::to_string)
                    .or(response.reason)
                    .unwrap_or_else(|| "unknown".to_string());
                Ok(CallOutcome::Denied { failure_code })
            }
            Verdict::PendingApproval => {
                Err(format!("request {} was suspended for approval", request.request_id).into())
            }
        }
    }

    /// Number of `evaluate_once` calls so far, including the constructor's.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }

    /// Number of times the tool server ran.
    pub fn tool_invocations(&self) -> u64 {
        self.tool_invocations.load(Ordering::SeqCst)
    }

    /// The receiver-side lineage work for one call, without the rest of
    /// admission: resolve the bundle the request names from the receiver's own
    /// store, take the digest the request's citation is compared against, walk
    /// every edge, and find the statement that binds the continuation and the
    /// invocation. This is the term that is linear in depth; everything else on
    /// the admitted path is a constant.
    ///
    /// It runs the same functions the pre-dispatch hook runs, in the same order.
    pub fn verify_lineage_once(&self, bundle_id: &str) -> Result<String, BoxError> {
        let record = RuntimeAdmissionStore::treaty_runtime_artifact(
            &self.store,
            "receipt_lineage_bundle",
            bundle_id,
        )?
        .ok_or("the receiver does not hold the named lineage bundle")?;
        let bundle: ReceiptLineageBundle = serde_json::from_value(record.raw_json)?;
        let bundle_sha256 = sha256_hex(&canonical_json_bytes(&bundle)?);
        if !verify_receipt_lineage_bundle(&bundle)? {
            return Err("the lineage bundle did not verify".into());
        }
        for statement in &bundle.statements {
            if statement.parent_receipt_sha256 == bundle.root_receipt_sha256 {
                return Ok(format!(
                    "{bundle_sha256}:{}",
                    receipt_lineage_statement_sha256(statement)?
                ));
            }
        }
        Err("the lineage bundle has no edge leaving its root".into())
    }

    /// Statements in every lineage bundle this fixture's calls cite.
    pub fn lineage_depth(&self) -> usize {
        self.depth
    }

    /// Canonical size of one of those bundles, so a cost curve can be read
    /// against bytes as well as against statements.
    pub fn lineage_bundle_bytes(&self) -> usize {
        self.lineage_bundle_bytes
    }
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::from_seed(&[25_u8; 32]),
        ca_public_keys: vec![Keypair::from_seed(&[23_u8; 32]).public_key()],
        max_delegation_depth: 5,
        policy_hash: "policy-bench-admission-scaling".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

struct CountingToolServer {
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for CountingToolServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.to_string()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "arguments": arguments
        }))
    }
}

/// Signed verifier material the hook needs to admit a destructive call.
struct PolicyInputs {
    trust: SignedRuntimeVerifierTrustBundle,
    trusted_keys: Vec<RuntimeTrustedVerifierKey>,
    query_report: SignedRuntimePheromoneQueryReport,
    policy: SignedRuntimePheromonePolicy,
    peer_weights: SignedRuntimePeerWeights,
}

impl PolicyInputs {
    fn sign(verifier: &Keypair, bundle: &RuntimeAdmissionBundle) -> Result<Self, BoxError> {
        let trusted_keys = vec![RuntimeTrustedVerifierKey {
            verifier_id: VERIFIER_ID.to_string(),
            key_id: VERIFIER_KEY_ID.to_string(),
            public_key: verifier.public_key(),
            valid_from_unix_ms: ISSUED_AT_UNIX_MS,
            valid_until_unix_ms: EXPIRES_AT_UNIX_MS,
            status: "active".to_string(),
        }];
        let trust = SignedExportEnvelope::sign(
            RuntimeVerifierTrustBundleV4 {
                schema: CHIO_RUNTIME_VERIFIER_TRUST_BUNDLE_SCHEMA.to_string(),
                verifier_id: VERIFIER_ID.to_string(),
                key_id: VERIFIER_KEY_ID.to_string(),
                version: 1,
                previous_hash_sha256: None,
                trust_bundle_sha256: bundle.trust_bundle_sha256.clone(),
                verification_context_sha256: bundle.verification_context_sha256.clone(),
                revocation_checkpoint_sha256: "d".repeat(64),
                revocation_authority_roots: vec!["did:chio:revocation-authority".to_string()],
                issued_at_unix_ms: ISSUED_AT_UNIX_MS,
                expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
            },
            verifier,
        )?;
        let weights = RuntimePeerWeights {
            schema: CHIO_RUNTIME_PEER_WEIGHTS_SCHEMA.to_string(),
            verifier_id: VERIFIER_ID.to_string(),
            key_id: VERIFIER_KEY_ID.to_string(),
            reputation_epoch: 7,
            issued_at_unix_ms: ISSUED_AT_UNIX_MS,
            expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
            weights: vec![RuntimePeerWeight {
                peer_kernel_id: LOCAL_KERNEL_ID.to_string(),
                weight: 1.0,
            }],
        };
        let policy = RuntimePheromonePolicy {
            schema: CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
            policy_id: "policy-bench-admission-scaling".to_string(),
            verifier_id: VERIFIER_ID.to_string(),
            key_id: VERIFIER_KEY_ID.to_string(),
            policy_version: 1,
            mode: "enforce".to_string(),
            issued_at_unix_ms: ISSUED_AT_UNIX_MS,
            expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
            allowed_reputation_epochs: vec![7],
            max_query_report_age_ms: 60_000,
            min_distinct_origin_pairs: 1,
            runtime_trust_bundle_sha256: bundle.trust_bundle_sha256.clone(),
            peer_weights_sha256: runtime_peer_weights_sha256(&weights)?,
            rules: vec![RuntimePheromonePolicyRule {
                rule_id: "deny-high-runtime-risk".to_string(),
                subject_class: "workflow.destructive_step".to_string(),
                subject_class_namespace: "chio.runtime".to_string(),
                action_class_id: "*".to_string(),
                direction: "deny_if_at_or_above".to_string(),
                threshold_total_strength: 0.75,
                effect: "deny".to_string(),
            }],
        };
        let query_report = SignedExportEnvelope::sign(
            serde_json::json!({
                "schema": "chio.pheromone.query-report.v1",
                "accepted": true,
                "concentration": {
                    "subjectClass": "workflow.destructive_step",
                    "subjectClassNamespace": "chio.runtime",
                    "totalStrength": 0.10,
                    "distinctOriginPairs": 1,
                    "reputationEpoch": 7,
                    "evaluatedAtUnixMs": NOW_UNIX_MS - 2_000
                }
            }),
            verifier,
        )?;
        Ok(Self {
            trust,
            trusted_keys,
            query_report,
            policy: SignedExportEnvelope::sign(policy, verifier)?,
            peer_weights: SignedExportEnvelope::sign(weights, verifier)?,
        })
    }
}

/// Treaty material shared by every call: scope, ladder intersection, the
/// origin-side receipt the DSSE subject names, and the two signing keys.
struct TreatyBase {
    scope: TreatyScope,
    scope_sha256: String,
    intersection_id: String,
    intersection_sha256: String,
    receipt: ChioReceipt,
    remote_receipt_sha256: String,
    request_sha256: String,
    dsse_consistency_model: String,
    origin_keypair: Keypair,
    local_keypair: Keypair,
}

/// Per-call treaty material: one continuation and everything bound to it.
struct TreatyCall {
    continuation: CrossKernelContinuation,
    continuation_sha256: String,
    lineage: ReceiptLineageBundle,
    lineage_sha256: String,
    invocation: BilateralInvocation,
    invocation_sha256: String,
    dsse_id: String,
    dsse: DsseEnvelope,
    dsse_sha256: String,
}

impl TreatyBase {
    fn new(
        args: &serde_json::Value,
        origin_keypair: Keypair,
        local_keypair: Keypair,
        store: &InMemoryRuntimeAdmissionStore,
    ) -> Result<Self, BoxError> {
        let origin_manifest = treaty_manifest(ORIGIN_KERNEL_ID);
        let local_manifest = treaty_manifest(LOCAL_KERNEL_ID);
        let scope = TreatyScope {
            schema: CHIO_TREATY_SCOPE_SCHEMA.to_string(),
            treaty_id: "treaty-bench-buyer-vendor".to_string(),
            participant_kernel_ids: vec![ORIGIN_KERNEL_ID.to_string(), LOCAL_KERNEL_ID.to_string()],
            participant_public_keys: vec![origin_keypair.public_key(), local_keypair.public_key()],
            ladder_manifest_sha256s: vec![
                governance_ladder_manifest_sha256(&origin_manifest)?,
                governance_ladder_manifest_sha256(&local_manifest)?,
            ],
            allowed_action_classes: vec![ACTION_CLASS_ID.to_string()],
            issued_at_unix_ms: ISSUED_AT_UNIX_MS,
            expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
            revocation_epoch_sha256: "d".repeat(64),
            trust_bundle_sha256: "b".repeat(64),
        };
        let scope_sha256 = treaty_scope_sha256(&scope)?;
        let intersection =
            compute_ladder_intersection(&scope, &[origin_manifest, local_manifest], NOW_UNIX_MS)?;
        let intersection_sha256 = ladder_intersection_sha256(&intersection)?;
        store.insert_treaty_runtime_artifact("treaty_scope", &scope.treaty_id, &scope)?;
        store.insert_treaty_runtime_artifact(
            "ladder_intersection",
            &intersection.intersection_id,
            &intersection,
        )?;
        let request_sha256 = tool_args_sha256(args)?;
        let outcome_sha256 = "5".repeat(64);
        let receipt = ChioReceipt::sign(
            ChioReceiptBody {
                id: "invoke-bench-admission-scaling".to_string(),
                timestamp: NOW_UNIX_MS / 1_000,
                capability_id: CAPABILITY_ID.to_string(),
                tool_server: SERVER_ID.to_string(),
                tool_name: TOOL_NAME.to_string(),
                action: ToolCallAction::from_parameters(args.clone())?,
                decision: Some(Decision::Allow),
                receipt_kind: ReceiptKind::MediatedDecision,
                boundary_class: BoundaryClass::Prevent,
                observation_outcome: None,
                tool_origin: ToolOrigin::CallerExecuted,
                redaction_mode: RedactionMode::None,
                actor_chain: vec![ActorRef {
                    actor_id: "agent:bench/treaty-admission".to_string(),
                    actor_kind: Some("agent".to_string()),
                }],
                content_hash: outcome_sha256,
                policy_hash: "policy-bench-admission-scaling".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: TrustLevel::default(),
                tenant_id: None,
                kernel_key: local_keypair.public_key(),
                bbs_projection_version: None,
            },
            &local_keypair,
        )?;
        let remote_receipt_sha256 = sha256_hex(&canonical_json_bytes(&receipt)?);
        let dsse_consistency_model =
            bilateral_dsse_consistency_model("totally_ordered")?.to_string();
        Ok(Self {
            scope,
            scope_sha256,
            intersection_id: intersection.intersection_id,
            intersection_sha256,
            receipt,
            remote_receipt_sha256,
            request_sha256,
            dsse_consistency_model,
            origin_keypair,
            local_keypair,
        })
    }

    fn call(&self, sequence: u64, lease_id: &str, depth: usize) -> Result<TreatyCall, BoxError> {
        let continuation = CrossKernelContinuation {
            schema: CHIO_CROSS_KERNEL_CONTINUATION_SCHEMA.to_string(),
            continuation_id: format!("continue-bench-admission-scaling-{sequence}"),
            source_kernel_id: ORIGIN_KERNEL_ID.to_string(),
            target_kernel_id: LOCAL_KERNEL_ID.to_string(),
            parent_receipt_sha256: "1".repeat(64),
            parent_session_anchor_sha256: "2".repeat(64),
            capability_id: CAPABILITY_ID.to_string(),
            action_class_id: ACTION_CLASS_ID.to_string(),
            audience_tool: format!("{SERVER_ID}.{TOOL_NAME}"),
            nonce: format!("nonce-bench-admission-scaling-{sequence}"),
            issued_at_unix_ms: ISSUED_AT_UNIX_MS,
            expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
        };
        let continuation_sha256 = sha256_hex(&canonical_json_bytes(&continuation)?);
        let mut invocation = BilateralInvocation {
            schema: CHIO_BILATERAL_INVOCATION_SCHEMA.to_string(),
            invocation_id: format!("invoke-bench-admission-scaling-{sequence}"),
            treaty_id: self.scope.treaty_id.clone(),
            ladder_intersection_sha256: self.intersection_sha256.clone(),
            continuation_sha256: continuation_sha256.clone(),
            lineage_statement_sha256: String::new(),
            action_class_id: ACTION_CLASS_ID.to_string(),
            consistency_model: "totally_ordered".to_string(),
            capability_id: CAPABILITY_ID.to_string(),
            request_sha256: self.request_sha256.clone(),
            outcome_sha256: self.receipt.content_hash.clone(),
            local_receipt_sha256: continuation.parent_receipt_sha256.clone(),
            remote_receipt_sha256: self.remote_receipt_sha256.clone(),
            signer_kernel_ids: self.scope.participant_kernel_ids.clone(),
        };
        let invocation_sha256 = bilateral_invocation_binding_sha256(&invocation)?;
        // The root and the leaf are fixed by the invocation: the chain must start
        // at the receipt the continuation descends from and end at the receipt the
        // call produces. Depth is the number of verified edges between them.
        let root_receipt_sha256 = invocation.local_receipt_sha256.clone();
        let leaf_receipt_sha256 = invocation.remote_receipt_sha256.clone();
        let mut statements = Vec::with_capacity(depth);
        let mut parent = root_receipt_sha256.clone();
        for hop in 0..depth {
            let child = if hop + 1 == depth {
                leaf_receipt_sha256.clone()
            } else {
                sha256_hex(format!("lineage-hop-{sequence}-{hop}").as_bytes())
            };
            statements.push(ReceiptLineageStatement {
                schema: CHIO_RECEIPT_LINEAGE_STATEMENT_SCHEMA.to_string(),
                statement_id: format!("lineage-bench-admission-scaling-{sequence}-{hop}"),
                parent_receipt_sha256: parent.clone(),
                child_receipt_sha256: child.clone(),
                continuation_sha256: continuation_sha256.clone(),
                bilateral_invocation_sha256: invocation_sha256.clone(),
                evidence_class: "verified".to_string(),
                source_kernel_id: continuation.source_kernel_id.clone(),
                target_kernel_id: continuation.target_kernel_id.clone(),
            });
            parent = child;
        }
        // The invocation binds the edge that starts at the root, which is the one
        // the two hot-path scans look for. Its digest is taken once the chain is
        // complete, so it is stable whatever the depth.
        let Some(binding_statement) = statements.first() else {
            return Err("a lineage bundle needs at least one statement".into());
        };
        invocation.lineage_statement_sha256 = sha256_hex(&canonical_json_bytes(binding_statement)?);
        if bilateral_invocation_binding_sha256(&invocation)? != invocation_sha256 {
            return Err("bilateral invocation binding changed after lineage completion".into());
        }
        let lineage = ReceiptLineageBundle {
            schema: CHIO_RECEIPT_LINEAGE_BUNDLE_SCHEMA.to_string(),
            bundle_id: format!("lineage-bundle-bench-admission-scaling-{sequence}"),
            root_receipt_sha256,
            leaf_receipt_sha256,
            statements,
        };
        let lineage_sha256 = sha256_hex(&canonical_json_bytes(&lineage)?);
        let dsse = sign_chio_bilateral_dsse_envelope(
            &self.receipt,
            &self.origin_keypair,
            &self.local_keypair,
            ORIGIN_KERNEL_ID,
            LOCAL_KERNEL_ID,
            TOOL_NAME,
            NOW_UNIX_MS,
            BilateralPredicateExtensions {
                capability_lease_ref: Some(CapabilityLeaseRef {
                    lease_id: lease_id.to_string(),
                    issuer: ORIGIN_KERNEL_ID.to_string(),
                    expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
                    scope_digest: None,
                }),
                policy_evaluation_summary: Some(unanimous_allow_summary()),
                governance_receipt_ref: Some(GovernanceReceiptRef {
                    receipt_id: GOVERNANCE_RECEIPT_ID.to_string(),
                    kernel_id: LOCAL_KERNEL_ID.to_string(),
                    digest: HashRecord {
                        alg: "sha256".to_string(),
                        value: "6".repeat(64),
                    },
                }),
                consistency_anchor: Some("anchor-bench-admission-scaling".to_string()),
                consistency_model: Some(self.dsse_consistency_model.clone()),
                cross_org_visibility: Some("treaty_only".to_string()),
                treaty_binding_ref: Some(TreatyBindingRef {
                    treaty_id: self.scope.treaty_id.clone(),
                    treaty_scope_sha256: self.scope_sha256.clone(),
                    ladder_intersection_sha256: self.intersection_sha256.clone(),
                    admission_report_sha256: "7".repeat(64),
                    continuation_sha256: continuation_sha256.clone(),
                    lineage_bundle_sha256: lineage_sha256.clone(),
                    action_class_id: ACTION_CLASS_ID.to_string(),
                    consistency_model: self.dsse_consistency_model.clone(),
                    request_sha256: self.request_sha256.clone(),
                    outcome_sha256: invocation.outcome_sha256.clone(),
                    local_receipt_sha256: invocation.local_receipt_sha256.clone(),
                    remote_receipt_sha256: invocation.remote_receipt_sha256.clone(),
                    lease_refs: vec![lease_id.to_string()],
                    governance_refs: vec![GOVERNANCE_RECEIPT_ID.to_string()],
                    signer_kernel_ids: invocation.signer_kernel_ids.clone(),
                }),
            },
        )?;
        let dsse_sha256 = sha256_hex(&canonical_json_bytes(&dsse)?);
        Ok(TreatyCall {
            continuation,
            continuation_sha256,
            lineage,
            lineage_sha256,
            invocation,
            invocation_sha256,
            dsse_id: format!("bilateral-dsse-bench-admission-scaling-{sequence}"),
            dsse,
            dsse_sha256,
        })
    }
}

impl TreatyCall {
    fn insert_into(&self, store: &InMemoryRuntimeAdmissionStore) -> Result<(), BoxError> {
        store.insert_treaty_runtime_artifact(
            "cross_kernel_continuation",
            &self.continuation.continuation_id,
            &self.continuation,
        )?;
        store.insert_treaty_runtime_artifact(
            "receipt_lineage_bundle",
            &self.lineage.bundle_id,
            &self.lineage,
        )?;
        store.insert_treaty_runtime_artifact(
            "bilateral_invocation",
            &self.invocation.invocation_id,
            &self.invocation,
        )?;
        store.insert_treaty_runtime_artifact(
            "bilateral_dsse_envelope",
            &self.dsse_id,
            &self.dsse,
        )?;
        Ok(())
    }
}

fn treaty_manifest(kernel_id: &str) -> GovernanceLadderManifest {
    GovernanceLadderManifest {
        schema: CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA.to_string(),
        manifest_id: format!("ladder-{kernel_id}"),
        kernel_id: kernel_id.to_string(),
        issuer: format!("did:chio:{kernel_id}"),
        key_id: "ladder-key-1".to_string(),
        issued_at_unix_ms: ISSUED_AT_UNIX_MS,
        expires_at_unix_ms: EXPIRES_AT_UNIX_MS,
        destructive_floor: "receipt_backed".to_string(),
        default_unknown_mode: "deny".to_string(),
        action_classes: vec![GovernanceLadderActionClass {
            action_class_id: ACTION_CLASS_ID.to_string(),
            mode: "receipt_backed".to_string(),
            destructive: true,
            consistency_model: "totally_ordered".to_string(),
            co_sign: "bilateral_required".to_string(),
            co_sign_quorum: None,
            evidence_required: vec![
                "bilateral_dsse".to_string(),
                "bilateral_invocation".to_string(),
                "receipt_lineage".to_string(),
            ],
            aliases: Vec::new(),
        }],
    }
}

fn unanimous_allow_summary() -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-buyer".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        server_b_verdict: PolicyVerdict {
            verdict: "allow".to_string(),
            policy_id: "policy-vendor".to_string(),
            policy_version: "v1".to_string(),
            rationale_code: None,
        },
        joint_disposition: Some("allow".to_string()),
    }
}

fn treaty_request(args: serde_json::Value) -> Result<ToolCallRequest, BoxError> {
    let issuer = Keypair::from_seed(&[23_u8; 32]);
    let subject = Keypair::from_seed(&[24_u8; 32]);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: CAPABILITY_ID.to_string(),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER_ID.to_string(),
                    tool_name: TOOL_NAME.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            issued_at: 1_700_000_000,
            expires_at: 1_900_000_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    Ok(ToolCallRequest {
        request_id: "req-bench-admission-scaling".to_string(),
        capability: capability.clone(),
        tool_name: TOOL_NAME.to_string(),
        server_id: SERVER_ID.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: args,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(GovernedTransactionIntent {
            id: "intent-bench-admission-scaling".to_string(),
            server_id: SERVER_ID.to_string(),
            tool_name: TOOL_NAME.to_string(),
            purpose: "benchmark receiver-owned treaty admission".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: Default::default(),
        }),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: Some(ORIGIN_KERNEL_ID.to_string()),
    })
}
