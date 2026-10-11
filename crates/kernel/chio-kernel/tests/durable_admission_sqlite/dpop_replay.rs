//! A proof released before dispatch stays spent for every other operation.
use super::*;
use chio_kernel::admission_operation::dpop_claim::{
    DpopReplayClaimDisposition, DpopReplayClaimHistoryV1, DpopReplayClaimPhase,
};
use chio_kernel::admission_operation::{
    AdmissionDigest, AdmissionIdentifier, AdmissionOperationV1,
};
use chio_kernel::dpop::authority::{
    DpopReplayAuthorityInputV1, DpopReplayAuthorityV1, DPOP_AUTHORITY_SCHEMA,
};
use chio_kernel::dpop::replay_source::{DpopReplaySourceBinding, DpopReplaySourcePort};
use chio_kernel::dpop::{DpopNonceStore, DpopProof, DpopProofBody};
use chio_store_sqlite::SqliteAdmissionOperationStore;

const SERVER: &str = "sqlite-dpop-server";
const TOOL: &str = "mutate";
const SPENT_PROOF_REASON: &str = "durable admission failed: admission operation invariant failed: DPoP replay identity is already owned or historically spent";

/// Refuses only its first delivery preparation, which is a pre-dispatch failure.
struct PrepareOnceServer {
    prepares: Arc<AtomicU64>,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for PrepareOnceServer {
    fn server_id(&self) -> &str {
        SERVER
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL.to_owned()]
    }

    async fn prepare_delivery(
        &self,
        _context: &chio_kernel::ToolDispatchContext,
    ) -> Result<(), KernelError> {
        if self.prepares.fetch_add(1, Ordering::SeqCst) == 0 {
            return Err(KernelError::ToolServerError(
                "first delivery preparation refused".to_owned(),
            ));
        }
        Ok(())
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"echo": arguments}))
    }
}

struct DpopRoute {
    _temp: tempfile::TempDir,
    _authority: SqliteAuthorityStore,
    operations: Arc<SqliteAdmissionOperationStore>,
    fence: StoreMutationFence,
    domain: DpopReplayAuthorityV1,
    kernel: ChioKernel,
    agent: Keypair,
    capability: CapabilityToken,
    prepares: Arc<AtomicU64>,
    invocations: Arc<AtomicU64>,
}

impl DpopRoute {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temp = tempfile::tempdir()?;
        secure_directory(temp.path())?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority = SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &lock_root,
            chio_test_support::clock::clock(),
        )?;
        let fence = authority.mutation_fence();
        let operations = Arc::new(authority.admission_operation_store());
        let domain = activate_domain(&operations, &fence)?;
        let mut kernel = ChioKernel::new_with_clock(
            kernel_config(Keypair::generate()),
            chio_test_support::clock::clock(),
        );
        kernel.set_durable_admission_store(
            operations.clone(),
            Arc::new(authority.tool_outcome_store()),
            fence.clone(),
        )?;
        kernel.set_budget_store_handle(Arc::new(authority.budget_store()));
        kernel.set_operation_owned_dpop_authority(domain.clone())?;
        let prepares = Arc::new(AtomicU64::new(0));
        let invocations = Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(PrepareOnceServer {
            prepares: prepares.clone(),
            invocations: invocations.clone(),
        }));
        let agent = Keypair::generate();
        let capability = kernel.issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER.to_owned(),
                    tool_name: TOOL.to_owned(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: Some(true),
                }],
                ..ChioScope::default()
            },
            300,
        )?;
        Ok(Self {
            _temp: temp,
            _authority: authority,
            operations,
            fence,
            domain,
            kernel,
            agent,
            capability,
            prepares,
            invocations,
        })
    }

    fn proof(&self, nonce: &str) -> Result<DpopProof, Box<dyn Error>> {
        Ok(DpopProof::sign(
            DpopProofBody {
                schema: DPOP_AUTHORITY_SCHEMA.into(),
                replay_authority: Some(self.domain.clone()),
                capability_id: self.capability.id.clone(),
                tool_server: SERVER.into(),
                tool_name: TOOL.into(),
                action_hash: sha256_hex(&canonical_json_bytes(&arguments())?),
                nonce: nonce.into(),
                issued_at: now_unix_ms()? / 1000,
                agent_key: self.agent.public_key(),
            },
            &self.agent,
        )?)
    }

    fn request(&self, request_id: &str, proof: &DpopProof) -> ToolCallRequest {
        ToolCallRequest {
            request_id: request_id.to_owned(),
            capability: self.capability.clone(),
            tool_name: TOOL.to_owned(),
            server_id: SERVER.to_owned(),
            agent_id: self.capability.subject.to_hex(),
            arguments: arguments(),
            dpop_proof: Some(proof.clone()),
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
            declassification_grant: None,
        }
    }

    fn history(
        &self,
        request_id: &str,
    ) -> Result<(AdmissionOperationV1, Vec<DpopReplayClaimHistoryV1>), Box<dyn Error>> {
        let now = now_unix_ms()?;
        let (operation, retained) = self
            .operations
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", request_id)?,
                &self.fence,
                now,
            )?
            .ok_or("retained original operation")?;
        assert_eq!(retained.request_for_revalidation().request_id, request_id);
        Ok(self
            .operations
            .load_dpop_replay_claim_history(operation.binding().operation_id(), &self.fence, now)?
            .ok_or("admitted operation history")?)
    }
}

fn arguments() -> serde_json::Value {
    serde_json::json!({"record": "dpop-ledger", "value": "spent-once"})
}

fn activate_domain(
    operations: &SqliteAdmissionOperationStore,
    fence: &StoreMutationFence,
) -> Result<DpopReplayAuthorityV1, Box<dyn Error>> {
    let source = DpopNonceStore::new(8, std::time::Duration::from_secs(3600))?;
    let authority_id = AdmissionIdentifier::try_new("dpop_authority", "sqlite-dpop-authority")?;
    let snapshot = source.preview_unsealed(&DpopReplaySourceBinding {
        dpop_authority_id: authority_id.clone(),
        destination_authority_id: AdmissionIdentifier::try_new(
            "destination",
            fence.store_uuid.as_str(),
        )?,
    })?;
    let instance = AdmissionIdentifier::try_new("instance", snapshot.instance_id())?;
    let now = now_unix_ms()?;
    let pinned =
        operations.expect_dpop_replay_source(&instance, &authority_id, &source, fence, now)?;
    let imported = operations.import_dpop_replay_source(
        &authority_id,
        pinned.expectation_id(),
        &source,
        fence,
        now,
    )?;
    let domain = DpopReplayAuthorityV1::new(DpopReplayAuthorityInputV1 {
        destination_store_uuid: AdmissionIdentifier::try_new(
            "destination",
            imported.snapshot().destination_authority_id(),
        )?,
        dpop_authority_id: authority_id,
        expectation_id: AdmissionDigest::try_new(
            "expectation",
            imported.expectation_id().as_str(),
        )?,
        proof_ttl_secs: 60,
        max_clock_skew_secs: 30,
    })?;
    assert!(operations
        .activate_dpop_replay_source(&domain, &source, fence, now)?
        .is_active());
    Ok(domain)
}

#[test]
fn sqlite_released_dpop_proof_is_refused_for_a_different_operation() -> Result<(), Box<dyn Error>> {
    let route = DpopRoute::new()?;
    let proof = route.proof("released-before-dispatch")?;
    let proof_digest = sha256_hex(&canonical_json_bytes(&proof)?);

    let first = route
        .kernel
        .evaluate_tool_call_blocking(&route.request("dpop-original", &proof))?;
    assert_eq!(first.verdict, Verdict::Deny, "{:?}", first.reason);
    assert_eq!(route.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(route.invocations.load(Ordering::SeqCst), 0);
    let (original, original_history) = route.history("dpop-original")?;
    assert_eq!(
        original.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(original_history.len(), 1);
    assert_eq!(
        original_history[0].disposition,
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(
        original_history[0].intent.phase(),
        DpopReplayClaimPhase::Dispatch
    );
    assert_eq!(
        original_history[0]
            .intent
            .credential()
            .proof_digest()
            .as_str(),
        proof_digest
    );

    let replay = route
        .kernel
        .evaluate_tool_call_blocking(&route.request("dpop-other-operation", &proof))?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    assert_eq!(replay.reason.as_deref(), Some(SPENT_PROOF_REASON));
    assert_eq!(route.prepares.load(Ordering::SeqCst), 1);
    assert_eq!(route.invocations.load(Ordering::SeqCst), 0);
    let (other, other_history) = route.history("dpop-other-operation")?;
    assert_ne!(
        other.binding().operation_id(),
        original.binding().operation_id()
    );
    assert_eq!(
        other.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(other_history.is_empty());
    assert_eq!(
        route.history("dpop-original")?,
        (original, original_history)
    );

    let fresh = route.proof("fresh-for-same-capability")?;
    let accepted = route
        .kernel
        .evaluate_tool_call_blocking(&route.request("dpop-fresh-operation", &fresh))?;
    assert_eq!(accepted.verdict, Verdict::Allow, "{:?}", accepted.reason);
    assert_eq!(route.prepares.load(Ordering::SeqCst), 2);
    assert_eq!(route.invocations.load(Ordering::SeqCst), 1);
    let (_, fresh_history) = route.history("dpop-fresh-operation")?;
    assert_eq!(fresh_history.len(), 1);
    assert_eq!(
        fresh_history[0].disposition,
        DpopReplayClaimDisposition::RetainedAfterDispatchCommit
    );
    Ok(())
}
