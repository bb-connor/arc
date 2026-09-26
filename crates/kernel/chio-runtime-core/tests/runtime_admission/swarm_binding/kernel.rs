use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

struct CountingTool(Arc<AtomicU64>);

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for CountingTool {
    fn server_id(&self) -> &str {
        "vendor-ledger"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["close_account".to_string()]
    }
    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"closed": true}))
    }
}

fn kernel(
    hook: ChioRuntimeAdmissionHook<InMemoryRuntimeAdmissionStore>,
    invocations: Arc<AtomicU64>,
) -> chio_kernel::ChioKernel {
    let mut kernel = chio_kernel::ChioKernel::new(chio_kernel::KernelConfig {
        keypair: Keypair::from_seed(&[90; 32]),
        ca_public_keys: trusted_swarm_witness_keys(),
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"required swarm kernel policy"),
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
    kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    kernel.set_federation_local_kernel_id("kernel.vendor-b");
    kernel.require_swarm_admission();
    kernel.set_runtime_admission_hook(Arc::new(hook));
    kernel.register_tool_server(Box::new(CountingTool(invocations)));
    kernel
}

#[test]
fn required_swarm_kernel_dispatches_verified_capability_and_signs_binding() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(1_800_000_001, []);
    let fixture = BindingFixture::new()?;
    let invocations = Arc::new(AtomicU64::new(0));
    let kernel = kernel(fixture.hook, invocations.clone());
    let response = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(
        response.verdict,
        chio_kernel::Verdict::Allow,
        "{response:#?}"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(response.receipt.verify_signature()?);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| io::Error::other("missing receipt metadata"))?;
    let binding = &metadata["chio_runtime"]["verified_swarm_request_binding"];
    assert_eq!(binding["task_id"], "task-child-a");
    assert_eq!(
        binding["capability_sha256"],
        canonical_test_hash(&fixture.request.capability)?
    );
    Ok(())
}

#[test]
fn required_swarm_kernel_denies_omission_or_capability_substitution_before_tool() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(1_800_000_001, []);
    for substitution in [false, true] {
        let fixture = BindingFixture::new()?;
        let invocations = Arc::new(AtomicU64::new(0));
        let kernel = kernel(fixture.hook, invocations.clone());
        let mut request = fixture.request;
        let expected = if substitution {
            let mut body = request.capability.body();
            body.expires_at -= 1;
            request.capability = CapabilityToken::sign(body, &swarm_witness_keypair())?;
            "chio_swarm_authority_rejected"
        } else {
            request.governed_intent = None;
            "missing_chio_swarm_context"
        };
        let response = kernel
            .evaluate_tool_call_blocking_with_metadata(&request, Some(swarm_route_metadata()))?;
        assert_eq!(
            response.verdict,
            chio_kernel::Verdict::Deny,
            "{response:#?}"
        );
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(response.receipt.verify_signature()?);
        assert_eq!(
            response
                .receipt
                .metadata
                .ok_or_else(|| io::Error::other("missing deny metadata"))?["chio_runtime"]
                ["failure_code"],
            expected
        );
    }
    Ok(())
}
