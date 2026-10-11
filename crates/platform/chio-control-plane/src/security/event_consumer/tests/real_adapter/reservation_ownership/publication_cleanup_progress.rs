//! Cold governed runtime publication over the real durable stores must finish
//! every recovery pass before refusing cleanup that another lease holder owns.
use super::*;
use chio_kernel::approval::{ApprovalReservationMember, ApprovalSetReservationInput};
use chio_kernel::security_admission_operation::{
    AdmissionCleanupAction, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionCreateOutcome, AdmissionCleanupActionKind, AdmissionCleanupActionState,
    AdmissionOperation, PreparedAdmissionOperation,
};

const CLEANUP_LEASE_MS: u64 = 30_000;
const FOREIGN_CLAIM_TOKEN: &str = "other";
const ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA: &str =
    "chio.admission-cleanup.active-response-approval.v2";

fn cold_kernel(fixture: &RealAdapterFixture) -> ChioKernel {
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: fixture.operator_authority.clone(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: hex::encode(fixture.plan.response_plan().policy_hash.as_bytes()),
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
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        },
        chio_test_support::clock::clock(),
    );
    kernel
        .set_active_response_submission_authority(fixture.submission_authority.public_key())
        .unwrap_or_else(|error| panic!("install cold submission authority: {error}"));
    kernel
}

fn cold_publication(
    fixture: &RealAdapterFixture,
    budgets: &Arc<dyn chio_kernel::budget_store::BudgetStore>,
) -> GovernedSecurityRuntimePublication {
    GovernedSecurityRuntimePublication {
        active_response_requirement_resolver: Arc::new(
            |_: &chio_kernel::ActiveResponsePolicyRequest,
             _: &str|
             -> Result<ActiveResponseRequirement, ActiveResponsePolicyResolutionError> {
                Err(ActiveResponsePolicyResolutionError::Invalid(
                    "cold publication resolves no plan".to_string(),
                ))
            },
        ),
        threshold_approval_requirement_resolver: Arc::new(
            |_: &str, _: &str, _: &str| -> Result<Option<ThresholdApprovalRequirement>, String> {
                Err("cold publication resolves no threshold".to_string())
            },
        ),
        admission_operation_store: fixture.runtime.admission_operations.clone(),
        approval_store: fixture.runtime.approvals.clone(),
        budget_store: Arc::clone(budgets),
        finding_authority: Arc::new(TestFindingAuthority::new(std::slice::from_ref(
            &fixture.finding,
        ))),
        executor_authority: fixture.runtime.executor.clone(),
        capability_issuance_admission_authority: Arc::new(RealAdapterIssuanceAuthority),
        threshold_policy_authorities: vec![fixture.threshold_policy_authority.public_key()],
        guards: Vec::new(),
        pre_dispatch_hook: Arc::new(RealAdapterPreDispatch),
        post_invocation_pipeline: chio_kernel::PostInvocationPipeline::new(),
    }
}

fn seed_reserved_operation(
    fixture: &RealAdapterFixture,
    request_id: &str,
    authorized_at_unix_ms: u64,
) -> AdmissionOperation {
    let executor = fixture.runtime.executor.identity();
    let token = format!("{request_id}-approval-token");
    let approval_set = ApprovalSetReservationInput::new(
        chio_core::sha256_hex(format!("{request_id}-approval-set").as_bytes()),
        vec![ApprovalReservationMember::new(
            token.clone(),
            chio_core::sha256_hex(token.as_bytes()),
        )
        .unwrap_or_else(|error| panic!("approval member: {error}"))],
        authorized_at_unix_ms / 1_000 + 300,
    )
    .unwrap_or_else(|error| panic!("approval set: {error}"));
    let capability_hash = chio_core::sha256_hex(format!("{request_id}-capability").as_bytes());
    let operation = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: executor.authority_id().to_owned(),
        request_id: request_id.to_owned(),
        capability_id: format!("{request_id}-capability"),
        authorization_capability_hash: capability_hash.clone(),
        request_binding_hash: chio_core::sha256_hex(format!("{request_id}-binding").as_bytes()),
        policy_hash: hex::encode(fixture.plan.response_plan().policy_hash.as_bytes()),
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: Some(approval_set.approval_set_hash().to_owned()),
        execution_nonce_id: None,
        coordinator_lease_epoch: 1,
    })
    .unwrap_or_else(|error| panic!("prepared operation: {error}"));
    fixture
        .runtime
        .admission_operations
        .create_prepared(operation.clone())
        .unwrap_or_else(|error| panic!("create prepared operation: {error}"));
    let anchor = AdmissionCleanupAction::pending(
        &operation,
        AdmissionCleanupActionKind::Approval,
        &json!({
            "schema": ACTIVE_RESPONSE_APPROVAL_CLEANUP_SCHEMA,
            "operationId": operation.operation_id(),
            "dispatchAnchor": {
                "planHash": chio_core::sha256_hex(format!("{request_id}-plan").as_bytes()),
                "executorAuthorityId": executor.authority_id(),
                "executorAuthorityGeneration": executor.generation(),
                "authorizedAtUnixMs": authorized_at_unix_ms,
                "authorizationCapabilityHash": capability_hash,
                "governedIntentHash":
                    chio_core::sha256_hex(format!("{request_id}-intent").as_bytes()),
                "policyDecisionHash":
                    chio_core::sha256_hex(format!("{request_id}-decision").as_bytes()),
                "approvalSetHash": approval_set.approval_set_hash(),
            },
            "approvalSet": approval_set,
        }),
    )
    .unwrap_or_else(|error| panic!("approval anchor: {error}"));
    let created = fixture
        .runtime
        .admission_operations
        .create_cleanup_action(anchor.clone())
        .unwrap_or_else(|error| panic!("journal approval anchor: {error}"));
    assert!(
        matches!(&created, AdmissionCleanupActionCreateOutcome::Created(action) if *action == anchor),
        "{created:?}"
    );
    fixture
        .runtime
        .approvals
        .reserve_approval_set(operation.operation_id(), &approval_set)
        .unwrap_or_else(|error| panic!("reserve approval set: {error}"));
    operation
}

fn approval_action(
    fixture: &RealAdapterFixture,
    operation: &AdmissionOperation,
) -> AdmissionCleanupAction {
    fixture
        .runtime
        .admission_operations
        .load_cleanup_actions(operation.operation_id())
        .unwrap_or_else(|error| panic!("load cleanup actions: {error}"))
        .into_iter()
        .find(|action| action.kind() == AdmissionCleanupActionKind::Approval)
        .unwrap_or_else(|| panic!("approval cleanup action missing"))
}

fn operation_state(
    fixture: &RealAdapterFixture,
    operation: &AdmissionOperation,
) -> AdmissionOperationState {
    fixture
        .runtime
        .admission_operations
        .load(operation.operation_id())
        .unwrap_or_else(|error| panic!("load operation: {error}"))
        .unwrap_or_else(|| panic!("operation missing"))
        .state()
}

fn reservation_state(
    fixture: &RealAdapterFixture,
    operation: &AdmissionOperation,
) -> ReplayReservationState {
    fixture
        .runtime
        .approvals
        .get_approval_reservation(operation.operation_id())
        .unwrap_or_else(|error| panic!("load approval reservation: {error}"))
        .unwrap_or_else(|| panic!("approval reservation missing"))
        .state()
}

fn assert_foreign_lease_retained(
    fixture: &RealAdapterFixture,
    operation: &AdmissionOperation,
    deadline: u64,
) {
    let action = approval_action(fixture, operation);
    assert_eq!(action.state(), AdmissionCleanupActionState::Claimed);
    assert_eq!(action.claim_token(), Some(FOREIGN_CLAIM_TOKEN));
    assert_eq!(action.claim_deadline_unix_ms(), Some(deadline));
    assert_eq!(
        operation_state(fixture, operation),
        AdmissionOperationState::CompensationPending
    );
    assert_eq!(
        reservation_state(fixture, operation),
        ReplayReservationState::Reserved
    );
}

fn assert_cleanup_pending(result: Result<(), KernelError>, operation: &AdmissionOperation) {
    assert!(
        matches!(&result, Err(KernelError::Internal(detail))
        if *detail == format!(
            "active-response cleanup remains pending for {}",
            operation.operation_id()
        )),
        "{result:?}"
    );
}

#[test]
fn cold_publication_recovers_healthy_rows_before_refusing_a_busy_cleanup_lease() {
    let fixture = real_adapter_fixture_with_options(
        chio_security_types::ResponseExecutionMode::Live,
        true,
        RealAdapterFixtureOptions {
            publish_runtime: false,
            ..Default::default()
        },
    );
    let budgets: Arc<dyn chio_kernel::budget_store::BudgetStore> = Arc::new(
        SqliteBudgetStore::open(&fixture.paths.budgets)
            .unwrap_or_else(|error| panic!("open cold budget store: {error}")),
    );
    let started_at_secs = real_adapter_now_unix_seconds() + 1;
    let started_at_ms = started_at_secs * 1_000;
    let lease_deadline = started_at_ms + CLEANUP_LEASE_MS;
    let _started = chio_test_support::clock::scope_unix_secs(started_at_secs);
    let mut kernel = cold_kernel(&fixture);
    let unpublished = kernel.governed_security_runtime_status();

    let busy = seed_reserved_operation(&fixture, "cold-busy-cleanup", started_at_ms);
    let claimed = fixture
        .runtime
        .admission_operations
        .claim_cleanup_action(
            approval_action(&fixture, &busy).action_id(),
            FOREIGN_CLAIM_TOKEN,
            started_at_ms,
            lease_deadline,
        )
        .unwrap_or_else(|error| panic!("hold foreign cleanup lease: {error}"));
    assert!(
        matches!(&claimed, AdmissionCleanupActionClaimOutcome::Claimed(action)
            if action.claim_token() == Some(FOREIGN_CLAIM_TOKEN)),
        "{claimed:?}"
    );
    assert_cleanup_pending(
        kernel.publish_governed_security_runtime(cold_publication(&fixture, &budgets)),
        &busy,
    );
    assert_foreign_lease_retained(&fixture, &busy, lease_deadline);

    let healthy = seed_reserved_operation(&fixture, "cold-healthy-cleanup", started_at_ms);
    assert_eq!(
        operation_state(&fixture, &healthy),
        AdmissionOperationState::Prepared
    );
    assert_eq!(
        reservation_state(&fixture, &healthy),
        ReplayReservationState::Reserved
    );

    assert_cleanup_pending(
        kernel.publish_governed_security_runtime(cold_publication(&fixture, &budgets)),
        &busy,
    );
    assert_eq!(kernel.governed_security_runtime_status(), unpublished);
    assert!(!kernel.has_installed_flow_runtime());
    assert_foreign_lease_retained(&fixture, &busy, lease_deadline);
    assert_eq!(
        operation_state(&fixture, &healthy),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        reservation_state(&fixture, &healthy),
        ReplayReservationState::Cancelled
    );

    let _before_deadline = chio_test_support::clock::scope_unix_secs(started_at_secs + 29);
    assert_cleanup_pending(
        kernel.publish_governed_security_runtime(cold_publication(&fixture, &budgets)),
        &busy,
    );
    assert_foreign_lease_retained(&fixture, &busy, lease_deadline);
    assert_eq!(kernel.governed_security_runtime_status(), unpublished);

    let _at_deadline = chio_test_support::clock::scope_unix_secs(lease_deadline / 1_000);
    kernel
        .publish_governed_security_runtime(cold_publication(&fixture, &budgets))
        .unwrap_or_else(|error| panic!("publish after the foreign lease expired: {error}"));
    assert_eq!(
        operation_state(&fixture, &busy),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        reservation_state(&fixture, &busy),
        ReplayReservationState::Cancelled
    );
    let published = kernel.governed_security_runtime_status();
    assert_eq!(published.publication_generation, 1);
    assert!(published.active_response_enabled);
    assert_eq!(fixture.runtime.executor.calls(), 0);
    assert_eq!(fixture.runtime.effects.executions(), 0);
}
