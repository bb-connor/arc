//! Validated model frames for codec tests, not qualified storage provenance.
//! Live capture, replay and restart are tested in the SQLite integration suite.

use super::*;
use crate::admission_operation::{
    immutable_tool_request_hash, qualify_recovery_claim_for_test,
    AdmissionExecutionNonceReservationV1, AdmissionOperationBindingInputV1, AdmissionOperationKind,
    AdmissionParticipantRequirements, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
    UntrustedAdmissionRecoveryClaim,
};
use crate::execution_nonce::ExecutionNonceConfig;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};

fn identifier(field: &'static str, value: impl Into<String>) -> TestResult<AdmissionIdentifier> {
    Ok(AdmissionIdentifier::try_new(field, value.into())?)
}

fn advance(
    operation: AdmissionOperationV1,
    attachments: Vec<AdmissionAttachment>,
    state: AdmissionOperationState,
    now: u64,
) -> TestResult<AdmissionOperationV1> {
    let fence = crate::admission_operation::StoreMutationFence {
        store_uuid: "codec-model-authority".into(),
        lease_id: "model-owner".into(),
        owner_epoch: 1,
    };
    let claim = UntrustedAdmissionRecoveryClaim::new(
        operation.binding().operation_id().clone(),
        identifier("claimant", "codec-model")?,
        identifier("coordinator_lease", "model-lease")?,
        operation.coordinator_lease_epoch(),
        operation.version(),
        now + 60_000,
        fence.clone(),
    )?;
    let lease = qualify_recovery_claim_for_test(&operation, claim, now, &fence)?;
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(state),
        None,
        None,
    )?;
    Ok(operation.apply_command(&command, now)?.into_operation())
}

pub(super) fn fixture() -> TestResult<Fixture> {
    let key = chio_core::Keypair::generate();
    let kernel = ChioKernel::new(KernelConfig {
        keypair: key.clone(),
        ca_public_keys: vec![key.public_key()],
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"caller-context-codec-test"),
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
        deadlines: HotPathDeadlineConfig::default(),
    });
    let subject = chio_core::Keypair::generate().public_key();
    let capability = kernel.issue_capability(
        &subject,
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "caller-context-server".into(),
                tool_name: "mutate".into(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(1),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            ..ChioScope::default()
        },
        600,
    )?;
    let mut request: ToolCallRequest = serde_json::from_value(serde_json::json!({
        "request_id": "caller-context-request", "capability": capability,
        "tool_name": "mutate", "server_id": "caller-context-server",
        "agent_id": subject.to_hex(), "arguments": {"protected_input": "private-request-input"}
    }))?;
    let matching = resolve_required_matching_grants(
        &request.capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        None,
    )?;
    let original = RetainedToolAdmissionRequestV1::from_admission(&request, &matching, &[], None)?;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
            "authority",
            "codec-model-authority",
        )?)?,
        request_id: identifier("request_id", &request.request_id)?,
        capability_id: identifier("capability_id", &request.capability.id)?,
        authorization_capability_hash: AdmissionDigest::try_new(
            "capability",
            sha256_hex(&canonical_json_bytes(&request.capability)?),
        )?,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            immutable_tool_request_hash(&request, &matching, &[], None)?,
            AdmissionDigest::try_new(
                "action",
                sha256_hex(&canonical_json_bytes(&request.arguments)?),
            )?,
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                execution_nonce: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )?,
        policy_hash: AdmissionDigest::try_new("policy", kernel.config.policy_hash.clone())?,
        effect_class: SideEffectClass::SideEffecting,
    })?;
    let now = current_unix_timestamp_ms();
    let mut operation = AdmissionOperationV1::prepare(binding, 1)?;
    let nonce = AdmissionExecutionNonceReservationV1::mint_for_operation(
        &operation,
        &original,
        &key,
        &ExecutionNonceConfig::default(),
        now,
    )?;
    let attempt = ProviderAttemptBindingV1 {
        operation_id: operation.binding().operation_id().as_str().into(),
        attempt_id: "caller-attempt".into(),
        transport_id: "caller-report:caller-context-server".into(),
        transport_key_epoch: 1,
    };
    let hold = identifier(
        "hold",
        format!(
            "admission-budget:{}:0",
            operation.binding().operation_id().as_str()
        ),
    )?;
    for (state, attachments) in [
        (
            AdmissionOperationState::Prepared,
            vec![AdmissionAttachment::ExecutionNonceIssuanceDigest(
                AdmissionDigest::try_new("issuance", sha256_hex(nonce.canonical_bytes()))?,
            )],
        ),
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(attempt)],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(hold)],
        ),
        (
            AdmissionOperationState::ReadyToDispatch,
            vec![AdmissionAttachment::ExecutionNonceId(
                nonce.nonce_id().clone(),
            )],
        ),
        (AdmissionOperationState::CapturePending, vec![]),
    ] {
        operation = advance(operation, attachments, state, now)?;
    }
    request.execution_nonce = Some(nonce.signed_nonce().clone());
    let admission = DurableToolAdmission {
        _live_owner: None,
        operation,
        retained_request: Some(original),
        aggregate_quota: None,
        supplemental_quota: None,
        issued_nonce: Some(nonce.clone()),
        nonce_preflight: None,
    };
    let frozen = kernel.freeze_durable_tool_return_context(
        &admission,
        DurableToolReturnContextInput {
            request: &request,
            matched_grant_index: 0,
            extra_receipt_metadata: None,
            pre_invocation_guard_evidence: &[],
            verified_payee_binding: None,
            verified_purchase: None,
            verified_recovery: None,
            trusted_now_unix_ms: now,
            security_invocation_context: None,
            security_release_required: false,
        },
    )?;
    let frame = kernel
        .frame_caller_return_context(&admission, &frozen, now)?
        .ok_or("caller model frame")?;
    Ok(Fixture {
        kernel,
        admission,
        frame,
        nonce: nonce.signed_nonce().clone(),
    })
}
