//! Configured kernel routes against physical SQLite custody. The activated
//! volatile source is destroyed before any invocation is allowed to begin.
use super::*;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_kernel::{
    ChioKernel, KernelConfig, NestedFlowBridge, ToolCallRequest, ToolServerConnection, Verdict,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "kernel_routes/boundaries.rs"]
mod boundaries;
#[path = "kernel_routes/composition.rs"]
mod composition;
#[path = "kernel_routes/configuration.rs"]
mod configuration;
#[path = "kernel_routes/lifecycle.rs"]
mod lifecycle;
#[path = "kernel_routes/nested_session.rs"]
mod nested_session;
#[path = "kernel_routes/recovery.rs"]
mod recovery;

struct Server(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "dpop-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["tool".into()]
    }
    fn tool_is_read_only(&self, _: &str) -> bool {
        true
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"ok": true}))
    }
}

fn kernel(fixture: &Fixture, signer: Keypair) -> AnchoredTestResult<ChioKernel> {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: signer,
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"dpop-custody-kernel"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    kernel.set_durable_admission_store(
        Arc::new(fixture.store.clone()),
        Arc::new(fixture.authority.tool_outcome_store()),
        fixture.fence.clone(),
    )?;
    kernel.set_budget_store_handle(Arc::new(fixture.authority.budget_store()));
    Ok(kernel)
}

struct Route {
    fixture: Fixture,
    domain: DpopReplayAuthorityV1,
    signer: Keypair,
    agent: Keypair,
    kernel: ChioKernel,
    calls: Arc<AtomicUsize>,
}
impl Route {
    fn new() -> AnchoredTestResult<Self> {
        let fixture = fixture();
        let source = Source::new(&fixture, false)?;
        let domain = activate(&fixture, &source)?;
        drop(source);
        let signer = Keypair::generate();
        let mut kernel = kernel(&fixture, signer.clone())?;
        kernel.set_operation_owned_dpop_authority(domain.clone())?;
        // An independently retired legacy cache is deliberately installed
        // afterwards. Neither its config nor its availability can downgrade v2.
        kernel.set_dpop_store(
            DpopNonceStore::new(8, Duration::from_secs(60)),
            chio_kernel::dpop::DpopConfig::default(),
        );
        let legacy = kernel.dpop_replay_source()?;
        let snapshot = legacy.preview_unsealed(&DpopReplaySourceBinding {
            dpop_authority_id: identifier("unused_legacy", "unused-retired-cache"),
            destination_authority_id: identifier("destination", &fixture.fence.store_uuid),
        })?;
        legacy.seal_exact(&snapshot)?;
        let calls = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(Server(calls.clone())));
        Ok(Self {
            fixture,
            domain,
            signer,
            agent: Keypair::generate(),
            kernel,
            calls,
        })
    }

    fn request(&self, id: &str, limits: &[u32]) -> AnchoredTestResult<ToolCallRequest> {
        let capability = self.kernel.issue_capability(
            &self.agent.public_key(),
            ChioScope {
                grants: limits
                    .iter()
                    .map(|limit| ToolGrant {
                        server_id: "dpop-server".into(),
                        tool_name: "tool".into(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: Some(*limit),
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: Some(true),
                    })
                    .collect(),
                ..Default::default()
            },
            300,
        )?;
        let arguments = serde_json::json!({"record": id});
        let proof = DpopProof::sign(
            DpopProofBody {
                schema: DPOP_AUTHORITY_SCHEMA.into(),
                replay_authority: Some(self.domain.clone()),
                capability_id: capability.id.clone(),
                tool_server: "dpop-server".into(),
                tool_name: "tool".into(),
                action_hash: sha256_hex(&canonical_json_bytes(&arguments)?),
                nonce: format!("nonce-{id}"),
                issued_at: now_ms() / 1000,
                agent_key: self.agent.public_key(),
            },
            &self.agent,
        )?;
        Ok(serde_json::from_value(serde_json::json!({
            "request_id": id, "capability": capability, "agent_id": self.agent.public_key().to_hex(),
            "server_id": "dpop-server", "tool_name": "tool", "arguments": arguments, "dpop_proof": proof,
        }))?)
    }

    fn history(
        &self,
        request: &ToolCallRequest,
    ) -> AnchoredTestResult<(AdmissionOperationV1, Vec<DpopReplayClaimHistoryV1>)> {
        let id: String = self.fixture.store.connection()?.query_row(
            "SELECT operation_id FROM admission_operations WHERE request_id = ?1",
            [&request.request_id],
            |row| row.get(0),
        )?;
        self.fixture
            .store
            .load_dpop_replay_claim_history(
                &AdmissionOperationId::from_persisted(id)?,
                &self.fixture.fence,
                now_ms(),
            )?
            .ok_or_else(|| "operation absent".into())
    }

    fn counts(&self) -> AnchoredTestResult<(i64, i64)> {
        Ok(self.fixture.store.connection()?.query_row("SELECT (SELECT COUNT(*) FROM dpop_replay_claim_episodes), (SELECT COUNT(*) FROM budget_authorization_holds)", [], |row| Ok((row.get(0)?, row.get(1)?)))?)
    }
}

#[test]
fn configured_v2_dispatch_claims_before_budget_and_never_uses_retired_legacy_cache(
) -> AnchoredTestResult {
    let route = Route::new()?;
    let request = route.request("normal-dpop", &[1])?;
    let response = route.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    let (operation, history) = route.history(&request)?;
    assert!(operation.state().is_terminal());
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].disposition,
        DpopReplayClaimDisposition::RetainedAfterDispatchCommit
    );
    assert_eq!(
        history[0].intent.credential().proof_digest().as_str(),
        sha256_hex(&canonical_json_bytes(
            request.dpop_proof.as_ref().ok_or("proof absent")?
        )?)
    );
    let (claim_sequence, budget_sequence): (i64, i64) = route.fixture.store.connection()?.query_row(
        "SELECT (SELECT MIN(commit_sequence) FROM admission_operation_commits WHERE mutation_kind = 'dpop_replay_claim'), (SELECT MIN(commit_sequence) FROM admission_operation_commits WHERE mutation_kind = 'participant_update')", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
    assert!(claim_sequence < budget_sequence);
    let _ = route.kernel.evaluate_tool_call_blocking(&request);
    assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    assert_eq!(route.history(&request)?.1.len(), 1);
    let mut replay = request.clone();
    replay.request_id = "same-proof-new-operation".into();
    let response = route.kernel.evaluate_tool_call_blocking(&replay)?;
    assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
    assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    assert_eq!(route.counts()?, (1, 1));
    Ok(())
}

#[test]
fn invalid_missing_and_legacy_proofs_deny_before_any_claim_or_budget() -> AnchoredTestResult {
    for invalid in ["missing", "signature", "domain", "expired", "legacy"] {
        let route = Route::new()?;
        let mut request = route.request(invalid, &[1])?;
        let mut proof = request.dpop_proof.take().ok_or("proof absent")?;
        match invalid {
            "missing" => {}
            "signature" => {
                proof.body.nonce.push_str("-unsigned");
                request.dpop_proof = Some(proof);
            }
            _ => {
                if invalid == "domain" {
                    let mut value = serde_json::to_value(&route.domain)?;
                    value["max_clock_skew_secs"] = 31.into();
                    proof.body.replay_authority = Some(serde_json::from_value(value)?);
                } else if invalid == "expired" {
                    proof.body.issued_at = now_ms() / 1000 - 62;
                } else {
                    proof.body.schema = "chio.dpop_proof.v1".into();
                    proof.body.replay_authority = None;
                }
                request.dpop_proof = Some(DpopProof::sign(proof.body, &route.agent)?);
            }
        }
        let response = route.kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Deny, "{invalid}");
        assert_eq!(route.counts()?, (0, 0), "{invalid}");
        assert_eq!(route.calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
