use super::*;
use chio_core::capability::scope::{Operation, ToolGrant};
use chio_kernel::{
    ChioKernel, KernelConfig, NestedFlowBridge, ToolCallRequest, ToolCallResponse,
    ToolServerConnection, Verdict,
};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingServer(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "expiry-effect"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["write".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(arguments)
    }
}

fn config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: chio_core::sha256_hex(b"remote-authority-expiry-regression"),
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
    }
}

fn dispatch_after_refresh(
    value: Result<u64, ClockError>,
) -> TestResult<(Result<ToolCallResponse, KernelError>, usize)> {
    let root = chio_test_support::private_tempdir()?;
    let source = SqliteCapabilityAuthority::open_with_clock(
        root.path().join("issuer.db"),
        Arc::new(chio_security_types::clock::FixedClock::new(100)),
    )?;
    let capability = source.issue_capability(
        &Keypair::generate().public_key(),
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "expiry-effect".into(),
                tool_name: "write".into(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        10,
    )?;
    assert!(capability.verify_signature()?);
    assert_eq!((capability.issued_at, capability.expires_at), (100, 110));
    assert_eq!(source.authority_public_key(), capability.issuer);
    let status = crate::trust_control::report_validation::authority_status_response(
        "sqlite".into(),
        source.status()?,
    );
    assert_eq!(status.trusted_public_keys, vec![capability.issuer.to_hex()]);
    let clock = Arc::new(MutableClock::new());
    let mut kernel = ChioKernel::new_with_clock(config(), clock.clone());
    // The first HTTP status lookup belongs to initial admission. Hold the
    // next real lookup in the ordinary final dispatch revalidation.
    let mut server = StatusServer::new(&status, 2)?;
    kernel.set_capability_authority(Box::new(remote(
        &status,
        &server.endpoint(),
        kernel.authority_clock(),
        false,
    )?));
    let effects = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingServer(effects.clone())));
    let request = ToolCallRequest {
        request_id: "expiry-during-final-status-refresh".into(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "write".into(),
        server_id: "expiry-effect".into(),
        arguments: serde_json::json!({"write": "observed"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = std::thread::scope(|scope| -> TestResult<_> {
        let worker = scope.spawn(|| kernel.evaluate_tool_call_blocking(&request));
        assert_eq!(server.pause_and_change(&clock, value)?, 2);
        worker
            .join()
            .map_err(|_| "native dispatch worker panicked".into())
    })?;
    assert_eq!(server.finish()?, 2);
    Ok((response, effects.load(Ordering::SeqCst)))
}

#[test]
fn native_dispatch_refresh_accepts_before_token_expiry() -> TestResult {
    let (response, effects) = dispatch_after_refresh(Ok(109_999))?;
    let response = response?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(effects, 1);
    assert!(response.output.is_some());
    assert!(response.receipt.verify_signature()?);
    Ok(())
}

fn rejects_expired_token(value: u64) -> TestResult {
    let (response, effects) = dispatch_after_refresh(Ok(value))?;
    let response = response?;
    assert_eq!(
        (response.verdict, effects),
        (Verdict::Deny, 0),
        "{:?}",
        response.reason
    );
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("expired")));
    assert!(response.output.is_none());
    assert!(response.receipt.verify_signature()?);
    Ok(())
}

#[test]
fn native_dispatch_refresh_rejects_exact_token_expiry() -> TestResult {
    rejects_expired_token(110_000)
}

#[test]
fn native_dispatch_refresh_rejects_after_token_expiry() -> TestResult {
    rejects_expired_token(111_000)
}

#[test]
fn native_dispatch_refresh_keeps_clock_failure_effect_free() -> TestResult {
    let (response, effects) = dispatch_after_refresh(Err(ClockError::Unavailable))?;
    assert_eq!(effects, 0);
    match response {
        Err(KernelError::Clock(ClockError::Unavailable)) => {}
        Ok(response) => {
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
            let cause = KernelError::Clock(ClockError::Unavailable).to_string();
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains(&cause)),
                "clock cause must survive the denial projection: {:?}",
                response.reason,
            );
            assert!(response.receipt.verify_signature()?);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
