use super::*;

#[test]
fn production_response_coordinator_rejects_a_kernel_without_governed_runtime() {
    let kernel = Arc::new(chio_kernel::ChioKernel::new(chio_kernel::KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "ungoverned-response-test-policy".to_string(),
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
    }));
    let executor = chio_kernel::ActiveResponseExecutorAuthorityIdentity::new(
        Keypair::from_seed(&[92_u8; 32]).public_key(),
        1,
    )
    .unwrap_or_else(|error| panic!("executor identity: {error}"));
    let coordinator = KernelAttestedFindingResponseCoordinator::new_unbound(
        executor,
        Arc::new(FixedClock(1)),
        super::super::super::ActiveResponseExecutionProfile::Live,
    );
    let unbound = rejected(
        coordinator.ensure_ready(),
        "an unbound response coordinator must not report ready",
    );
    assert_eq!(
        unbound.kind(),
        chio_security_types::ports::PortErrorKind::Unavailable
    );
    let error = match coordinator.bind_kernel(kernel) {
        Ok(()) => panic!("a kernel without the atomic governed runtime was accepted"),
        Err(error) => error,
    };
    assert_eq!(
        error.kind(),
        chio_security_types::ports::PortErrorKind::Unavailable
    );
}
