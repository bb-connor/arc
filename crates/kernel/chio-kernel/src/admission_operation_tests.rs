use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use chio_core::{capability::scope::MonetaryAmount, crypto::Keypair};
use proptest::prelude::*;

use crate::receipt_store::AuthorizationReceiptConsumption;

use super::*;

const AUTH_HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REQUEST_HASH: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const POLICY_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const CONTENT_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const EMPTY_PARAMETER_HASH: &str =
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const TOOL_SERVER: &str = "test-server";
const TOOL_NAME: &str = "test-tool";

fn identifier(field: &'static str, value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new(field, value).expect("test identifier must be valid")
}

fn digest(field: &'static str, value: &str) -> AdmissionDigest {
    AdmissionDigest::try_new(field, value).expect("test digest must be valid")
}

fn namespace(tenant: &str) -> AuthenticatedRequestNamespace {
    AuthenticatedRequestNamespace::from_authentication_context(
        identifier("coordinator_authority_id", "https://coordinator.example"),
        tenant,
    )
    .expect("test namespace must derive")
}

fn binding_with(
    kind: AdmissionOperationKind,
    tenant: &str,
    request_id: &str,
    capability_id: &str,
    authorization_hash: &str,
    request_hash: &str,
) -> AdmissionOperationBindingV1 {
    let participant_requirements = match kind {
        AdmissionOperationKind::ToolDispatch => AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        },
        AdmissionOperationKind::GovernedActiveResponse => AdmissionParticipantRequirements {
            approval: true,
            ..AdmissionParticipantRequirements::NONE
        },
        AdmissionOperationKind::GovernedEconomicMutation => AdmissionParticipantRequirements::NONE,
    };
    AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind,
        namespace: namespace(tenant),
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", capability_id),
        authorization_capability_hash: digest("authorization_capability_hash", authorization_hash),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", request_hash),
            participant_requirements,
        )
        .expect("test request binding must derive"),
        policy_hash: digest("policy_hash", POLICY_HASH),
        effect_class: SideEffectClass::SideEffecting,
    })
    .expect("test binding must derive")
}

fn binding(kind: AdmissionOperationKind) -> AdmissionOperationBindingV1 {
    binding_with(
        kind,
        "tenant-123",
        "req-123",
        "cap-123",
        AUTH_HASH,
        REQUEST_HASH,
    )
}

fn prepared(kind: AdmissionOperationKind) -> AdmissionOperationV1 {
    AdmissionOperationV1::prepare(binding(kind), 7).expect("test operation must prepare")
}

fn provider_attempt(
    operation: &AdmissionOperationV1,
    attempt_id: &str,
) -> ProviderAttemptBindingV1 {
    ProviderAttemptBindingV1 {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        attempt_id: attempt_id.to_owned(),
        transport_id: "transport-1".to_owned(),
        transport_key_epoch: 1,
    }
}

fn fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "store-1".to_string(),
        lease_id: "owner-lease-1".to_string(),
        owner_epoch: 3,
    }
}

fn lease(operation: &AdmissionOperationV1, version: u64) -> AdmissionRecoveryLease {
    let claim = UntrustedAdmissionRecoveryClaim::new(
        operation.binding.operation_id.clone(),
        identifier("claimant_id", "worker-1"),
        identifier("coordinator_lease_id", "coordinator-lease-1"),
        operation.coordinator_lease_epoch,
        version,
        2_000,
        fence(),
    )
    .expect("test claim must be valid");
    qualify_recovery_claim_for_test(operation, claim, 1_000, &fence())
        .expect("test lease must qualify")
}

fn projection_context(operation: &AdmissionOperationV1) -> AdmissionProjectionContext {
    AdmissionProjectionContext {
        operation_id: operation.binding.operation_id.clone(),
        request_id: operation.binding.request_id.clone(),
        expected_operation_version: operation.version,
        trusted_time_unix_ms: 1_000,
        coordinator_lease_id: identifier("coordinator_lease_id", "coordinator-lease-1"),
        coordinator_lease_epoch: operation.coordinator_lease_epoch,
        store_fence: operation
            .dispatch_commit
            .as_ref()
            .map(|commit| commit.store_fence.clone())
            .unwrap_or_else(fence),
    }
}

fn full_projection_capabilities() -> AdmissionProjectionCapabilities {
    AdmissionProjectionCapabilities {
        operation_terminal: true,
        incident_terminal: true,
        tool_outcome: true,
        payment_terminal: true,
        authorization_consumption: true,
        outcome_eligibility: true,
        observation_attempt_zero: true,
        obligation: true,
        economic_mutation_terminal: true,
    }
}

fn receipt_metadata(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    projected_state: AdmissionOperationState,
    compensation_status: AdmissionCompensationStatus,
) -> AdmissionReceiptMetadataV1 {
    AdmissionReceiptMetadataV1 {
        schema: AdmissionReceiptSchema::V1,
        operation_id: operation.binding.operation_id.clone(),
        request_id: operation.binding.request_id.clone(),
        request_namespace_digest: operation.binding.request_namespace_digest.clone(),
        request_binding_hash: operation.binding.request_binding_hash().clone(),
        projected_operation_version: next_version(operation.version)
            .expect("test operation version must increment"),
        projected_state,
        projected_dispatch_state: dispatch_state_for(operation.binding.kind, projected_state)
            .expect("test projected state must match kind"),
        trusted_time_unix_ms: context.trusted_time_unix_ms,
        coordinator_lease_id: context.coordinator_lease_id.clone(),
        coordinator_lease_epoch: operation.coordinator_lease_epoch,
        store_fence: context.store_fence.clone(),
        retained_dispatch_commit: operation.dispatch_commit.clone(),
        compensation_status,
        tool_outcome_id: None,
        tool_outcome_version: None,
    }
}

fn signed_projection_receipt(
    operation: &AdmissionOperationV1,
    metadata: Option<AdmissionReceiptMetadataV1>,
    keypair: &Keypair,
) -> ChioReceipt {
    let tenant_id = (operation.binding.authenticated_tenant_id.as_str() != LOCAL_SYSTEM_TENANT_ID)
        .then(|| {
            operation
                .binding
                .authenticated_tenant_id
                .as_str()
                .to_owned()
        });
    signed_projection_receipt_with_tenant(operation, metadata, tenant_id, keypair)
}

fn signed_projection_receipt_with_tenant(
    operation: &AdmissionOperationV1,
    metadata: Option<AdmissionReceiptMetadataV1>,
    tenant_id: Option<String>,
    keypair: &Keypair,
) -> ChioReceipt {
    let timestamp = metadata
        .as_ref()
        .map_or(1, |value| value.trusted_time_unix_ms / 1_000);
    let body = ChioReceiptBody {
        id: "test-receipt".to_string(),
        timestamp,
        capability_id: operation.binding.capability_id.as_str().to_owned(),
        tool_server: TOOL_SERVER.to_string(),
        tool_name: TOOL_NAME.to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({}))
            .expect("test action must be valid"),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: CONTENT_HASH.to_string(),
        policy_hash: operation.binding.policy_hash.as_str().to_owned(),
        evidence: Vec::new(),
        metadata: metadata
            .map(|value| serde_json::json!({ ADMISSION_RECEIPT_METADATA_KEY: value })),
        trust_level: Default::default(),
        tenant_id,
        kernel_key: keypair.public_key(),
        bbs_projection_version: None,
    };
    ChioReceipt::sign(body, keypair).expect("test receipt must sign")
}

fn verify_completed_receipt(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    receipt: ChioReceipt,
    keypair: &Keypair,
    tool_outcome: Option<(&AdmissionDigest, u64)>,
) -> Result<VerifiedAdmissionReceipt, AdmissionOperationError> {
    VerifiedAdmissionReceipt::from_kernel_verified_for_test(
        receipt,
        &keypair.public_key(),
        &Decision::Allow,
        TOOL_SERVER,
        TOOL_NAME,
        &digest("expected_parameter_hash", EMPTY_PARAMETER_HASH),
        &digest("expected_content_hash", CONTENT_HASH),
        operation,
        context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
        tool_outcome,
    )
}

fn transition_command(
    operation: &AdmissionOperationV1,
    next_state: AdmissionOperationState,
    terminal_replay: Option<AdmissionTerminalReplay>,
) -> AdmissionOperationCommand {
    let attachments = match (operation.state, next_state) {
        (_, AdmissionOperationState::BrokerAttemptRegistered) => {
            vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                operation,
                "attempt-1",
            ))]
        }
        (_, AdmissionOperationState::BudgetAuthorized) => {
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "budget_hold_id",
                "hold-1",
            ))]
        }
        (_, AdmissionOperationState::ApprovalReserved) => {
            vec![
                AdmissionAttachment::ThresholdProposalHash(digest(
                    "threshold_proposal_hash",
                    REQUEST_HASH,
                )),
                AdmissionAttachment::ApprovalSetHash(digest("approval_set_hash", POLICY_HASH)),
            ]
        }
        (AdmissionOperationState::ApprovalReserved, AdmissionOperationState::ReadyToDispatch) => {
            if operation.binding.participant_requirements().execution_nonce {
                vec![AdmissionAttachment::ExecutionNonceId(identifier(
                    "execution_nonce_id",
                    "nonce-1",
                ))]
            } else {
                Vec::new()
            }
        }
        (_, AdmissionOperationState::Finalizing)
            if operation.binding.kind == AdmissionOperationKind::ToolDispatch =>
        {
            vec![AdmissionAttachment::ToolOutcomeId(digest(
                "tool_outcome_id",
                POLICY_HASH,
            ))]
        }
        _ => Vec::new(),
    };
    AdmissionOperationCommand::new(
        operation.binding.operation_id.clone(),
        operation.version,
        lease(operation, operation.version),
        attachments,
        Some(next_state),
        terminal_replay,
        None,
    )
    .expect("test command must be valid")
}

fn finalizing_active_operation() -> AdmissionOperationV1 {
    let mut operation = prepared(AdmissionOperationKind::GovernedActiveResponse);
    for next in [
        AdmissionOperationState::ApprovalReserved,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::DispatchCommitted,
        AdmissionOperationState::Finalizing,
    ] {
        let command = transition_command(&operation, next, None);
        operation = operation
            .apply_command(&command, 1_000)
            .expect("active response transition must apply")
            .into_operation();
    }
    operation
}

fn finalizing_tool_operation_with(
    participant_requirements: AdmissionParticipantRequirements,
) -> AdmissionOperationV1 {
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: namespace("tenant-123"),
        request_id: identifier("request_id", "req-participants"),
        capability_id: identifier("capability_id", "cap-participants"),
        authorization_capability_hash: digest("authorization_hash", AUTH_HASH),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", REQUEST_HASH),
            participant_requirements,
        )
        .expect("participant requirements must bind"),
        policy_hash: digest("policy_hash", POLICY_HASH),
        effect_class: SideEffectClass::Monetary,
    })
    .expect("participant-backed tool binding must be valid");
    let mut operation =
        AdmissionOperationV1::prepare(binding, 7).expect("tool operation must prepare");
    for next in [
        AdmissionOperationState::BrokerAttemptRegistered,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
        AdmissionOperationState::DispatchCommitted,
        AdmissionOperationState::Finalizing,
    ] {
        let command = if next == AdmissionOperationState::ReadyToDispatch {
            let mut attachments = Vec::new();
            if participant_requirements.outcome_eligibility {
                attachments.push(AdmissionAttachment::OutcomeEligibilityDigest(digest(
                    "outcome_eligibility_digest",
                    POLICY_HASH,
                )));
            }
            if participant_requirements.payment {
                attachments.push(AdmissionAttachment::PaymentParticipantId(identifier(
                    "payment_participant_id",
                    "payment-1",
                )));
            }
            AdmissionOperationCommand::new(
                operation.binding.operation_id.clone(),
                operation.version,
                lease(&operation, operation.version),
                attachments,
                Some(next),
                None,
                None,
            )
            .expect("participant-ready command must be valid")
        } else {
            transition_command(&operation, next, None)
        };
        operation = operation
            .apply_command(&command, 1_000)
            .expect("tool dispatch transition must apply")
            .into_operation();
    }
    operation
}

#[test]
fn canonical_namespace_and_operation_id_vectors_are_stable() {
    let binding = binding(AdmissionOperationKind::ToolDispatch);
    assert_eq!(
        binding.request_namespace_digest.as_str(),
        "094f38cf0fff47773c60c30b1619b5d1d3605bbb7e79d1eeb8da254afada2176"
    );
    let request_binding_hash = digest("request_binding_hash", REQUEST_HASH);
    let formula_vector = derive_operation_id(OperationIdInput {
        kind: binding.kind,
        coordinator_authority_id: &binding.coordinator_authority_id,
        request_namespace_digest: &binding.request_namespace_digest,
        request_id: &binding.request_id,
        capability_id: &binding.capability_id,
        authorization_capability_hash: &binding.authorization_capability_hash,
        request_binding_hash: &request_binding_hash,
        policy_hash: &binding.policy_hash,
        effect_class: binding.effect_class,
    })
    .expect("operation id vector must derive");
    assert_eq!(
        formula_vector.as_str(),
        "364d1715ba255f03e25ce0364b36a1f1481532f45d75bf221db87111122f17f1"
    );
}

#[test]
fn persisted_binding_recomputes_authenticated_namespace() {
    let binding = binding(AdmissionOperationKind::ToolDispatch);
    let persisted = PersistedAdmissionOperationBindingV1 {
        kind: binding.kind,
        operation_id: binding.operation_id.clone(),
        coordinator_authority_id: binding.coordinator_authority_id.clone(),
        authenticated_tenant_id: BoundedAdmissionText::try_new(
            "authenticated_tenant_id",
            "different-tenant",
        )
        .expect("test tenant must be bounded"),
        request_namespace_digest: binding.request_namespace_digest.clone(),
        request_id: binding.request_id.clone(),
        capability_id: binding.capability_id.clone(),
        authorization_capability_hash: binding.authorization_capability_hash.clone(),
        request_binding: binding.request_binding.clone(),
        policy_hash: binding.policy_hash.clone(),
        effect_class: binding.effect_class,
    };
    assert_eq!(
        AdmissionOperationBindingV1::from_persisted(persisted),
        Err(AdmissionOperationError::RequestNamespaceMismatch)
    );
}

#[test]
fn persistence_round_trip_is_checked_and_versioned() {
    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let persisted = operation.to_persisted();
    assert_eq!(
        AdmissionOperationV1::from_persisted(persisted.clone())
            .expect("valid persisted operation must restore"),
        operation
    );

    let mut corrupt = persisted.clone();
    corrupt.binding.request_binding.request_binding_hash = digest(
        "request_binding_hash",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    assert_eq!(
        AdmissionOperationV1::from_persisted(corrupt),
        Err(AdmissionOperationError::RequestBindingMismatch)
    );

    let mut encoded =
        serde_json::to_value(persisted).expect("persisted operation must serialize for the test");
    encoded["schema"] = serde_json::Value::String("chio.admission-operation.v2".to_string());
    assert!(serde_json::from_value::<PersistedAdmissionOperationV1>(encoded).is_err());
}

#[test]
fn persisted_policy_and_effect_substitution_change_operation_identity() {
    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let persisted = operation.to_persisted();

    let mut changed_policy = persisted.clone();
    changed_policy.binding.policy_hash = digest(
        "policy_hash",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    assert_eq!(
        AdmissionOperationV1::from_persisted(changed_policy),
        Err(AdmissionOperationError::OperationIdMismatch)
    );

    let mut changed_effect = persisted;
    changed_effect.binding.effect_class = SideEffectClass::Monetary;
    assert_eq!(
        AdmissionOperationV1::from_persisted(changed_effect),
        Err(AdmissionOperationError::OperationIdMismatch)
    );
}

#[test]
fn every_identity_component_separates_operation_ids() {
    let baseline = binding(AdmissionOperationKind::ToolDispatch);
    let policy_or_effect = |policy_hash: &str, effect_class| {
        AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::ToolDispatch,
            namespace: namespace("tenant-123"),
            request_id: identifier("request_id", "req-123"),
            capability_id: identifier("capability_id", "cap-123"),
            authorization_capability_hash: digest("authorization_capability_hash", AUTH_HASH),
            request_binding: AdmissionRequestBindingV1::new(
                digest("immutable_request_hash", REQUEST_HASH),
                AdmissionParticipantRequirements {
                    broker_attempt: true,
                    budget_capture: true,
                    ..AdmissionParticipantRequirements::NONE
                },
            )
            .expect("test request binding must derive"),
            policy_hash: digest("policy_hash", policy_hash),
            effect_class,
        })
        .expect("identity variant must derive")
    };
    let variants = [
        binding_with(
            AdmissionOperationKind::GovernedActiveResponse,
            "tenant-123",
            "req-123",
            "cap-123",
            AUTH_HASH,
            REQUEST_HASH,
        ),
        binding_with(
            AdmissionOperationKind::ToolDispatch,
            "tenant-456",
            "req-123",
            "cap-123",
            AUTH_HASH,
            REQUEST_HASH,
        ),
        binding_with(
            AdmissionOperationKind::ToolDispatch,
            "tenant-123",
            "req-456",
            "cap-123",
            AUTH_HASH,
            REQUEST_HASH,
        ),
        binding_with(
            AdmissionOperationKind::ToolDispatch,
            "tenant-123",
            "req-123",
            "cap-456",
            AUTH_HASH,
            REQUEST_HASH,
        ),
        binding_with(
            AdmissionOperationKind::ToolDispatch,
            "tenant-123",
            "req-123",
            "cap-123",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            REQUEST_HASH,
        ),
        binding_with(
            AdmissionOperationKind::ToolDispatch,
            "tenant-123",
            "req-123",
            "cap-123",
            AUTH_HASH,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        ),
        policy_or_effect(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            SideEffectClass::SideEffecting,
        ),
        policy_or_effect(POLICY_HASH, SideEffectClass::Monetary),
    ];
    for variant in variants {
        assert_ne!(baseline.operation_id, variant.operation_id);
    }
}

#[test]
fn participant_requirements_are_kind_checked_and_identity_bound() {
    let make = |kind, requirements| {
        AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind,
            namespace: namespace("tenant-123"),
            request_id: identifier("request_id", "req-123"),
            capability_id: identifier("capability_id", "cap-123"),
            authorization_capability_hash: digest("authorization_hash", AUTH_HASH),
            request_binding: AdmissionRequestBindingV1::new(
                digest("immutable_request_hash", REQUEST_HASH),
                requirements,
            )
            .expect("test requirements must be internally valid"),
            policy_hash: digest("policy_hash", POLICY_HASH),
            effect_class: SideEffectClass::SideEffecting,
        })
    };
    let budget_only = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let with_payment = AdmissionParticipantRequirements {
        payment: true,
        ..budget_only
    };
    assert_ne!(
        make(AdmissionOperationKind::ToolDispatch, budget_only)
            .expect("budget-backed tool dispatch must be valid")
            .operation_id,
        make(AdmissionOperationKind::ToolDispatch, with_payment)
            .expect("payment-backed tool dispatch must be valid")
            .operation_id,
    );
    for requirements in [
        AdmissionParticipantRequirements {
            authorization_consumption: true,
            ..budget_only
        },
        AdmissionParticipantRequirements {
            observation_attempt_zero: true,
            ..budget_only
        },
        AdmissionParticipantRequirements {
            obligation: true,
            ..budget_only
        },
    ] {
        assert_ne!(
            make(AdmissionOperationKind::ToolDispatch, budget_only)
                .expect("baseline tool dispatch must be valid")
                .operation_id,
            make(AdmissionOperationKind::ToolDispatch, requirements)
                .expect("sidecar-backed tool dispatch must be valid")
                .operation_id,
        );
    }
    assert_eq!(
        make(
            AdmissionOperationKind::ToolDispatch,
            AdmissionParticipantRequirements::NONE,
        ),
        Err(AdmissionOperationError::InvalidParticipantRequirements)
    );
    assert_eq!(
        make(AdmissionOperationKind::GovernedActiveResponse, budget_only,),
        Err(AdmissionOperationError::InvalidParticipantRequirements)
    );
    assert_eq!(
        make(
            AdmissionOperationKind::GovernedEconomicMutation,
            AdmissionParticipantRequirements {
                approval: true,
                ..AdmissionParticipantRequirements::NONE
            },
        ),
        Err(AdmissionOperationError::InvalidParticipantRequirements)
    );
}

#[test]
fn admission_numeric_bindings_reject_non_ijson_integers() {
    let unsafe_integer = I_JSON_MAX_SAFE_INTEGER + 1;
    assert!(matches!(
        AdmissionOperationV1::prepare(
            binding(AdmissionOperationKind::ToolDispatch),
            unsafe_integer
        ),
        Err(AdmissionOperationError::UnsafeInteger {
            field: "coordinator_lease_epoch"
        })
    ));

    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let mut persisted = operation.to_persisted();
    persisted.version = unsafe_integer;
    assert!(matches!(
        AdmissionOperationV1::from_persisted(persisted),
        Err(AdmissionOperationError::UnsafeInteger {
            field: "operation_version"
        })
    ));

    let mut unsafe_fence = fence();
    unsafe_fence.owner_epoch = unsafe_integer;
    assert_eq!(
        UntrustedAdmissionRecoveryClaim::new(
            operation.binding().operation_id().clone(),
            identifier("claimant_id", "worker-unsafe-integer"),
            identifier("coordinator_lease_id", "coordinator-unsafe-integer"),
            1,
            1,
            1,
            unsafe_fence,
        ),
        Err(AdmissionOperationError::InvalidStoreFence)
    );
}

#[test]
fn payment_participant_is_required_before_ready_to_dispatch() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        payment: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: namespace("tenant-123"),
        request_id: identifier("request_id", "req-payment"),
        capability_id: identifier("capability_id", "cap-payment"),
        authorization_capability_hash: digest("authorization_hash", AUTH_HASH),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", REQUEST_HASH),
            requirements,
        )
        .expect("payment requirements must bind"),
        policy_hash: digest("policy_hash", POLICY_HASH),
        effect_class: SideEffectClass::Monetary,
    })
    .expect("payment-backed tool dispatch must be valid");
    let operation =
        AdmissionOperationV1::prepare(binding, 7).expect("payment-backed operation must prepare");
    let broker = transition_command(
        &operation,
        AdmissionOperationState::BrokerAttemptRegistered,
        None,
    );
    let operation = operation
        .apply_command(&broker, 1_000)
        .expect("broker attempt transition must apply")
        .into_operation();
    let budget = transition_command(&operation, AdmissionOperationState::BudgetAuthorized, None);
    let operation = operation
        .apply_command(&budget, 1_000)
        .expect("budget transition must apply")
        .into_operation();
    let missing = transition_command(&operation, AdmissionOperationState::ReadyToDispatch, None);
    assert_eq!(
        operation.apply_command(&missing, 1_000),
        Err(AdmissionOperationError::MissingParticipantAttachment {
            field: "payment_participant_id"
        })
    );
    let exact = AdmissionOperationCommand::new(
        operation.binding.operation_id.clone(),
        operation.version,
        lease(&operation, operation.version),
        vec![AdmissionAttachment::PaymentParticipantId(identifier(
            "payment_participant_id",
            "payment-1",
        ))],
        Some(AdmissionOperationState::ReadyToDispatch),
        None,
        None,
    )
    .expect("payment attachment command must be valid");
    assert!(operation.apply_command(&exact, 1_000).is_ok());
}

#[test]
fn approval_requires_the_proposal_and_verified_set_on_transition_and_restore() {
    let operation = prepared(AdmissionOperationKind::GovernedActiveResponse);
    let missing_proposal = AdmissionOperationCommand::new(
        operation.binding.operation_id.clone(),
        operation.version,
        lease(&operation, operation.version),
        vec![AdmissionAttachment::ApprovalSetHash(digest(
            "approval_set_hash",
            POLICY_HASH,
        ))],
        Some(AdmissionOperationState::ApprovalReserved),
        None,
        None,
    )
    .expect("approval command must be structurally valid");
    assert_eq!(
        operation.apply_command(&missing_proposal, 1_000),
        Err(AdmissionOperationError::MissingParticipantAttachment {
            field: "threshold_proposal_hash"
        })
    );

    let valid = transition_command(&operation, AdmissionOperationState::ApprovalReserved, None);
    let reserved = operation
        .apply_command(&valid, 1_000)
        .expect("proposal and approval set must reserve approval")
        .into_operation();
    let mut persisted = reserved.to_persisted();
    persisted
        .attachments
        .0
        .retain(|attachment| !matches!(attachment, AdmissionAttachment::ThresholdProposalHash(_)));
    assert_eq!(
        AdmissionOperationV1::from_persisted(persisted),
        Err(AdmissionOperationError::MissingParticipantAttachment {
            field: "threshold_proposal_hash"
        })
    );

    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        approval: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let proposal =
        AdmissionAttachment::ThresholdProposalHash(digest("threshold_proposal_hash", REQUEST_HASH));
    assert!(attachment_allowed(
        AdmissionOperationKind::ToolDispatch,
        requirements,
        AdmissionOperationState::Prepared,
        &proposal,
    ));
    assert!(attachment_allowed(
        AdmissionOperationKind::ToolDispatch,
        requirements,
        AdmissionOperationState::BudgetAuthorized,
        &proposal,
    ));
}

#[test]
fn governed_economic_mutations_reject_every_attachment_on_write_and_restore() {
    let operation = prepared(AdmissionOperationKind::GovernedEconomicMutation);
    let attachments = vec![
        AdmissionAttachment::ThresholdProposalHash(digest("threshold_hash", POLICY_HASH)),
        AdmissionAttachment::SupplementalAuthorizationDigest(digest(
            "supplemental_authorization_digest",
            POLICY_HASH,
        )),
        AdmissionAttachment::BrokerAttempt(provider_attempt(&operation, "attempt-1")),
        AdmissionAttachment::BudgetHoldId(identifier("budget_hold_id", "hold-1")),
        AdmissionAttachment::ApprovalSetHash(digest("approval_set_hash", POLICY_HASH)),
        AdmissionAttachment::ExecutionNonceId(identifier("execution_nonce_id", "nonce-1")),
        AdmissionAttachment::OutcomeEligibilityDigest(digest(
            "outcome_eligibility_digest",
            POLICY_HASH,
        )),
        AdmissionAttachment::PaymentParticipantId(identifier(
            "payment_participant_id",
            "payment-1",
        )),
        AdmissionAttachment::ToolOutcomeId(digest("tool_outcome_id", POLICY_HASH)),
    ];
    for attachment in attachments {
        let operation = operation.clone();
        let field = attachment.field_name();
        let command = AdmissionOperationCommand::new(
            operation.binding.operation_id.clone(),
            operation.version,
            lease(&operation, operation.version),
            vec![attachment.clone()],
            None,
            None,
            None,
        )
        .expect("forbidden attachment command must be structurally valid");
        assert_eq!(
            operation.apply_command(&command, 1_000),
            Err(AdmissionOperationError::ForbiddenAttachment { field }),
            "command path accepted {field}"
        );

        let mut persisted = operation.to_persisted();
        persisted.attachments = AdmissionOperationAttachmentsV1(vec![attachment]);
        assert_eq!(
            AdmissionOperationV1::from_persisted(persisted),
            Err(AdmissionOperationError::ForbiddenAttachment { field }),
            "restore path accepted {field}"
        );
    }
}

#[test]
fn attachment_scope_is_derived_from_kind_and_participant_requirements() {
    let tool = prepared(AdmissionOperationKind::ToolDispatch);
    let forbidden = vec![
        AdmissionAttachment::ThresholdProposalHash(digest("threshold_hash", POLICY_HASH)),
        AdmissionAttachment::ApprovalSetHash(digest("approval_set_hash", POLICY_HASH)),
        AdmissionAttachment::ExecutionNonceId(identifier("execution_nonce_id", "nonce-1")),
        AdmissionAttachment::OutcomeEligibilityDigest(digest(
            "outcome_eligibility_digest",
            POLICY_HASH,
        )),
        AdmissionAttachment::PaymentParticipantId(identifier(
            "payment_participant_id",
            "payment-1",
        )),
    ];
    for attachment in forbidden {
        let field = attachment.field_name();
        let command = AdmissionOperationCommand::new(
            tool.binding.operation_id.clone(),
            tool.version,
            lease(&tool, tool.version),
            vec![attachment],
            None,
            None,
            None,
        )
        .expect("forbidden tool attachment command must be structurally valid");
        assert_eq!(
            tool.apply_command(&command, 1_000),
            Err(AdmissionOperationError::ForbiddenAttachment { field })
        );
    }

    let active = prepared(AdmissionOperationKind::GovernedActiveResponse);
    for attachment in [
        AdmissionAttachment::SupplementalAuthorizationDigest(digest(
            "supplemental_authorization_digest",
            POLICY_HASH,
        )),
        AdmissionAttachment::ToolOutcomeId(digest("tool_outcome_id", POLICY_HASH)),
    ] {
        let field = attachment.field_name();
        let command = AdmissionOperationCommand::new(
            active.binding.operation_id.clone(),
            active.version,
            lease(&active, active.version),
            vec![attachment],
            None,
            None,
            None,
        )
        .expect("forbidden active attachment command must be structurally valid");
        assert_eq!(
            active.apply_command(&command, 1_000),
            Err(AdmissionOperationError::ForbiddenAttachment { field })
        );
    }

    let tool_outcome = AdmissionAttachment::ToolOutcomeId(digest("tool_outcome_id", POLICY_HASH));
    let command = AdmissionOperationCommand::new(
        tool.binding.operation_id.clone(),
        tool.version,
        lease(&tool, tool.version),
        vec![tool_outcome],
        None,
        None,
        None,
    )
    .expect("tool outcome command must be structurally valid");
    assert_eq!(
        tool.apply_command(&command, 1_000),
        Err(AdmissionOperationError::AttachmentPhase {
            field: "tool_outcome_id",
            state: AdmissionOperationState::Prepared,
        })
    );
}

proptest! {
    #[test]
    fn request_ids_separate_operation_ids(suffix in "[a-z0-9]{1,24}") {
        prop_assume!(suffix != "123");
        let baseline = binding(AdmissionOperationKind::ToolDispatch);
        let request_id = format!("req-{suffix}");
        let changed = binding_with(
            AdmissionOperationKind::ToolDispatch,
            "tenant-123",
            &request_id,
            "cap-123",
            AUTH_HASH,
            REQUEST_HASH,
        );
        prop_assert_ne!(baseline.operation_id, changed.operation_id);
    }
}

#[test]
fn replay_requires_complete_immutable_binding() {
    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let same = prepared(AdmissionOperationKind::ToolDispatch);
    assert_eq!(
        operation.classify_replay(&same),
        AdmissionReplayClassification::Exact {
            terminal_replay: None
        }
    );

    let mut different_policy = same.clone();
    different_policy.binding.policy_hash = digest(
        "policy_hash",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    );
    assert_eq!(
        operation.classify_replay(&different_policy),
        AdmissionReplayClassification::Conflict
    );

    let mut different_effect = same;
    different_effect.binding.effect_class = SideEffectClass::Monetary;
    assert_eq!(
        operation.classify_replay(&different_effect),
        AdmissionReplayClassification::Conflict
    );
}

#[test]
fn attachments_are_null_once_idempotent_and_conflict_on_replacement() {
    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let broker = transition_command(
        &operation,
        AdmissionOperationState::BrokerAttemptRegistered,
        None,
    );
    let operation = operation
        .apply_command(&broker, 1_000)
        .expect("broker attempt transition must apply")
        .into_operation();
    let attachment = AdmissionAttachment::BudgetHoldId(identifier("hold_id", "hold-1"));
    let command = AdmissionOperationCommand::new(
        operation.binding.operation_id.clone(),
        operation.version,
        lease(&operation, operation.version),
        vec![attachment.clone()],
        Some(AdmissionOperationState::BudgetAuthorized),
        None,
        None,
    )
    .expect("attachment command must be valid");
    let updated = operation
        .apply_command(&command, 1_000)
        .expect("first attachment must apply")
        .into_operation();
    assert_eq!(updated.version, 3);
    assert_eq!(updated.state, AdmissionOperationState::BudgetAuthorized);

    let replay_command = AdmissionOperationCommand::new(
        updated.binding.operation_id.clone(),
        updated.version,
        lease(&updated, updated.version),
        vec![attachment.clone()],
        Some(AdmissionOperationState::BudgetAuthorized),
        None,
        None,
    )
    .expect("current-version replay must be structurally valid");
    let replay = updated
        .apply_command(&replay_command, 1_000)
        .expect("matching attachment must replay");
    assert!(matches!(replay, AdmissionCommandResult::Idempotent(_)));

    let conflicting = AdmissionOperationCommand::new(
        updated.binding.operation_id.clone(),
        updated.version,
        lease(&updated, updated.version),
        vec![AdmissionAttachment::BudgetHoldId(identifier(
            "hold_id", "hold-2",
        ))],
        None,
        None,
        None,
    )
    .expect("conflict command must be structurally valid");
    assert!(matches!(
        updated.apply_command(&conflicting, 1_000),
        Err(AdmissionOperationError::AttachmentConflict {
            field: "budget_hold_id"
        })
    ));
}

#[test]
fn transition_matrix_is_exhaustive() {
    for kind in AdmissionOperationKind::ALL {
        let requirements = binding(kind).participant_requirements();
        for from in AdmissionOperationState::ALL {
            for to in AdmissionOperationState::ALL {
                let expected = expected_transition(kind, requirements, from, to);
                assert_eq!(
                    is_legal_transition(kind, requirements, from, to),
                    expected,
                    "unexpected transition for {kind:?}: {from:?} -> {to:?}"
                );
            }
        }
    }
}

fn expected_transition(
    kind: AdmissionOperationKind,
    requirements: AdmissionParticipantRequirements,
    from: AdmissionOperationState,
    to: AdmissionOperationState,
) -> bool {
    if kind == AdmissionOperationKind::GovernedEconomicMutation {
        return [
            (
                AdmissionOperationState::Prepared,
                AdmissionOperationState::MutationReady,
            ),
            (
                AdmissionOperationState::MutationReady,
                AdmissionOperationState::MutationSubmitted,
            ),
            (
                AdmissionOperationState::Prepared,
                AdmissionOperationState::EconomicMutationNotApplied,
            ),
            (
                AdmissionOperationState::MutationReady,
                AdmissionOperationState::EconomicMutationNotApplied,
            ),
            (
                AdmissionOperationState::MutationSubmitted,
                AdmissionOperationState::EconomicMutationNotApplied,
            ),
            (
                AdmissionOperationState::MutationSubmitted,
                AdmissionOperationState::EconomicMutationApplied,
            ),
        ]
        .contains(&(from, to));
    }
    let mut path = vec![AdmissionOperationState::Prepared];
    if requirements.broker_attempt {
        path.push(AdmissionOperationState::BrokerAttemptRegistered);
    }
    if requirements.budget_capture {
        path.push(AdmissionOperationState::BudgetAuthorized);
    }
    if requirements.approval {
        path.push(AdmissionOperationState::ApprovalReserved);
    }
    path.push(AdmissionOperationState::ReadyToDispatch);
    if requirements.budget_capture {
        path.push(AdmissionOperationState::CapturePending);
    }
    path.extend([
        AdmissionOperationState::DispatchCommitted,
        AdmissionOperationState::Finalizing,
        AdmissionOperationState::Completed,
    ]);
    let mut edges = path
        .windows(2)
        .map(|edge| (edge[0], edge[1]))
        .collect::<Vec<_>>();
    edges.extend([
        (
            AdmissionOperationState::DispatchCommitted,
            AdmissionOperationState::NotAcceptedAfterDispatchCommit,
        ),
        (
            AdmissionOperationState::DispatchCommitted,
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
        ),
        (
            AdmissionOperationState::Finalizing,
            AdmissionOperationState::OutcomeUnknownAfterDispatch,
        ),
    ]);
    for state in path
        .into_iter()
        .take_while(|state| *state != AdmissionOperationState::DispatchCommitted)
    {
        edges.push((state, AdmissionOperationState::CompensatedBeforeDispatch));
    }
    edges.contains(&(from, to))
}

#[test]
fn lease_and_version_fences_apply_before_mutation() {
    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let attachment = AdmissionAttachment::BudgetHoldId(identifier("hold_id", "hold-1"));

    let stale_version = UntrustedAdmissionRecoveryClaim::new(
        operation.binding.operation_id.clone(),
        identifier("claimant_id", "worker-1"),
        identifier("coordinator_lease_id", "coordinator-lease-1"),
        operation.coordinator_lease_epoch,
        2,
        2_000,
        fence(),
    )
    .expect("stale claim must be structurally valid");
    assert!(matches!(
        qualify_recovery_claim_for_test(&operation, stale_version, 1_000, &fence()),
        Err(AdmissionOperationError::StaleVersion {
            expected: 2,
            actual: 1
        })
    ));

    let stale_epoch = UntrustedAdmissionRecoveryClaim::new(
        operation.binding.operation_id.clone(),
        identifier("claimant_id", "worker-1"),
        identifier("coordinator_lease_id", "coordinator-lease-1"),
        8,
        1,
        2_000,
        fence(),
    )
    .expect("stale epoch claim must be structurally valid");
    assert_eq!(
        qualify_recovery_claim_for_test(&operation, stale_epoch, 1_000, &fence()),
        Err(AdmissionOperationError::CoordinatorFenced)
    );

    let expired = AdmissionOperationCommand::new(
        operation.binding.operation_id.clone(),
        1,
        lease(&operation, 1),
        vec![attachment.clone()],
        None,
        None,
        None,
    )
    .expect("expired command must be structurally valid");
    assert_eq!(
        operation.apply_command(&expired, 2_000),
        Err(AdmissionOperationError::LeaseExpired)
    );

    let other = prepared(AdmissionOperationKind::GovernedActiveResponse);
    let wrong_operation = AdmissionOperationCommand::new(
        other.binding.operation_id.clone(),
        1,
        lease(&other, 1),
        vec![attachment],
        None,
        None,
        None,
    )
    .expect("wrong operation command must be structurally valid");
    assert_eq!(
        operation.apply_command(&wrong_operation, 1_000),
        Err(AdmissionOperationError::WrongOperation)
    );

    let invalid_fence = StoreMutationFence {
        store_uuid: String::new(),
        lease_id: "owner-lease-1".to_string(),
        owner_epoch: 3,
    };
    assert_eq!(
        UntrustedAdmissionRecoveryClaim::new(
            operation.binding.operation_id.clone(),
            identifier("claimant_id", "worker-1"),
            identifier("coordinator_lease_id", "coordinator-lease-1"),
            7,
            1,
            2_000,
            invalid_fence,
        ),
        Err(AdmissionOperationError::InvalidStoreFence)
    );
}

#[test]
fn durable_mode_membership_is_cumulative_and_defaults_side_effecting() {
    assert_eq!(
        DurableAdmissionMode::default(),
        DurableAdmissionMode::SideEffecting
    );
    assert_eq!(
        serde_json::to_value(DurableAdmissionMode::Monetary).expect("serialize rollout mode"),
        serde_json::json!("monetary")
    );
    assert!(!DurableAdmissionMode::Off.covers(SideEffectClass::ReadOnly));
    assert!(!DurableAdmissionMode::Off.covers(SideEffectClass::SideEffecting));
    assert!(!DurableAdmissionMode::Off.covers(SideEffectClass::Monetary));
    assert!(!DurableAdmissionMode::Monetary.covers(SideEffectClass::ReadOnly));
    assert!(!DurableAdmissionMode::Monetary.covers(SideEffectClass::SideEffecting));
    assert!(DurableAdmissionMode::Monetary.covers(SideEffectClass::Monetary));
    assert!(!DurableAdmissionMode::SideEffecting.covers(SideEffectClass::ReadOnly));
    assert!(DurableAdmissionMode::SideEffecting.covers(SideEffectClass::SideEffecting));
    assert!(DurableAdmissionMode::SideEffecting.covers(SideEffectClass::Monetary));
    assert!(DurableAdmissionMode::All.covers(SideEffectClass::ReadOnly));
    assert!(DurableAdmissionMode::All.covers(SideEffectClass::SideEffecting));
    assert!(DurableAdmissionMode::All.covers(SideEffectClass::Monetary));

    assert_eq!(
        DurableAdmissionMode::Off
            .validate_configuration(true, AdmissionReceiptPersistence::Ephemeral),
        Ok(DurableAdmissionMode::Off)
    );
    assert_eq!(
        DurableAdmissionMode::Off
            .validate_configuration(false, AdmissionReceiptPersistence::Ephemeral),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
    assert_eq!(
        DurableAdmissionMode::Off
            .validate_configuration(true, AdmissionReceiptPersistence::Durable),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
    assert_eq!(
        DurableAdmissionMode::Monetary
            .validate_configuration(false, AdmissionReceiptPersistence::Durable),
        Ok(DurableAdmissionMode::Monetary)
    );
}

#[test]
fn bounded_identifiers_reject_padding() {
    assert_eq!(
        AdmissionIdentifier::try_new("request_id", " req-1"),
        Err(AdmissionOperationError::Padded {
            field: "request_id"
        })
    );
    assert_eq!(
        AdmissionIdentifier::try_new("request_id", "req-1 "),
        Err(AdmissionOperationError::Padded {
            field: "request_id"
        })
    );
    assert_eq!(
        AuthenticatedRequestNamespace::from_authentication_context(
            identifier("coordinator_authority_id", "coordinator"),
            LOCAL_SYSTEM_TENANT_ID,
        ),
        Err(AdmissionOperationError::ReservedLocalSystemTenant)
    );
}

#[test]
fn verified_projection_sidecars_reject_operation_substitution() {
    let operation = prepared(AdmissionOperationKind::ToolDispatch);
    let context = projection_context(&operation);
    let incident = AdmissionIncident::from_verified(
        &operation,
        &context,
        AdmissionOperationState::CompensatedBeforeDispatch,
        identifier("incident_id", "incident-1"),
        digest("incident_digest", POLICY_HASH),
    )
    .expect("valid incident must bind to the operation snapshot");
    assert!(incident
        .validate_against(
            &operation,
            &context,
            AdmissionOperationState::CompensatedBeforeDispatch,
        )
        .is_ok());
    let mut substituted_time = context.clone();
    substituted_time.trusted_time_unix_ms += 1;
    assert_eq!(
        incident.validate_against(
            &operation,
            &substituted_time,
            AdmissionOperationState::CompensatedBeforeDispatch,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    let mut substituted_coordinator = context.clone();
    substituted_coordinator.coordinator_lease_id =
        identifier("coordinator_lease_id", "coordinator-lease-other");
    assert_eq!(
        incident.validate_against(
            &operation,
            &substituted_coordinator,
            AdmissionOperationState::CompensatedBeforeDispatch,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );

    let other = AdmissionOperationV1::prepare(
        binding_with(
            AdmissionOperationKind::ToolDispatch,
            "tenant-123",
            "req-other",
            "cap-123",
            AUTH_HASH,
            REQUEST_HASH,
        ),
        7,
    )
    .expect("other operation must prepare");
    assert_eq!(
        incident.validate_against(
            &other,
            &projection_context(&other),
            AdmissionOperationState::CompensatedBeforeDispatch,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
}

#[test]
fn completed_projection_requires_exact_signed_admission_receipt_metadata() {
    let operation = finalizing_active_operation();
    let mut context = projection_context(&operation);
    context.trusted_time_unix_ms = 1_999;
    let kernel = Keypair::generate();
    let completed = |receipt: VerifiedAdmissionReceipt| {
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context: context.clone(),
            receipt,
            tool_outcome: None,
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: None,
            obligation: None,
        }))
    };
    let verify = |receipt| verify_completed_receipt(&operation, &context, receipt, &kernel, None);

    assert!(matches!(
        verify(signed_projection_receipt(&operation, None, &kernel)),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let mut substituted = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    substituted.request_id = identifier("request_id", "substituted-request");
    assert!(matches!(
        verify(signed_projection_receipt(
            &operation,
            Some(substituted),
            &kernel,
        )),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let mut substituted_time = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    substituted_time.trusted_time_unix_ms = 1_998;
    assert!(matches!(
        verify(signed_projection_receipt(
            &operation,
            Some(substituted_time),
            &kernel,
        )),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let exact_metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    assert!(matches!(
        verify(signed_projection_receipt_with_tenant(
            &operation,
            Some(exact_metadata),
            None,
            &kernel,
        )),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let exact = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    let exact = verify(signed_projection_receipt(&operation, Some(exact), &kernel))
        .expect("exact signed admission receipt must qualify");
    let exact = completed(exact);
    let terminal = operation
        .apply_terminal_projection(&exact, &full_projection_capabilities())
        .expect("exact signed admission metadata must terminalize");
    assert_eq!(terminal.state, AdmissionOperationState::Completed);
    assert_eq!(terminal.version, operation.version + 1);
}

#[test]
fn admission_receipt_qualification_pins_kernel_and_exact_signed_body() {
    let operation = finalizing_active_operation();
    let context = projection_context(&operation);
    let kernel = Keypair::generate();
    let metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    let receipt = signed_projection_receipt(&operation, Some(metadata), &kernel);
    let qualify =
        |candidate| verify_completed_receipt(&operation, &context, candidate, &kernel, None);
    qualify(receipt.clone()).expect("exact kernel receipt must qualify");

    let rogue = Keypair::generate();
    let rogue_receipt = signed_projection_receipt(
        &operation,
        receipt
            .metadata
            .as_ref()
            .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok()),
        &rogue,
    );
    assert!(matches!(
        qualify(rogue_receipt),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let mut invalid_id = receipt.clone();
    invalid_id.id = POLICY_HASH.to_string();
    assert!(matches!(
        qualify(invalid_id),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let resign = |mutate: fn(&mut ChioReceiptBody)| {
        let mut body = receipt.body();
        mutate(&mut body);
        ChioReceipt::sign(body, &kernel).expect("substituted test receipt must sign")
    };
    for substituted in [
        resign(|body| body.tool_server = "other-server".to_string()),
        resign(|body| body.tool_name = "other-tool".to_string()),
        resign(|body| {
            body.action = ToolCallAction::from_parameters(serde_json::json!({ "other": true }))
                .expect("alternate action must hash")
        }),
        resign(|body| body.content_hash = REQUEST_HASH.to_string()),
        resign(|body| body.capability_id = "other-capability".to_string()),
        resign(|body| body.policy_hash = REQUEST_HASH.to_string()),
        resign(|body| body.tenant_id = Some("other-tenant".to_string())),
        resign(|body| {
            body.decision = Some(Decision::Deny {
                reason: "denied".to_string(),
                guard: "test".to_string(),
            })
        }),
    ] {
        assert!(matches!(
            qualify(substituted),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        ));
    }

    let invalid_parameter_hash = resign(|body| {
        body.action.parameter_hash = REQUEST_HASH.to_string();
    });
    assert!(matches!(
        VerifiedAdmissionReceipt::from_kernel_verified_for_test(
            invalid_parameter_hash,
            &kernel.public_key(),
            &Decision::Allow,
            TOOL_SERVER,
            TOOL_NAME,
            &digest("expected_parameter_hash", REQUEST_HASH),
            &digest("expected_content_hash", CONTENT_HASH),
            &operation,
            &context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
            None,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let denied = resign(|body| {
        body.decision = Some(Decision::Deny {
            reason: "denied".to_string(),
            guard: "test".to_string(),
        });
    });
    assert!(matches!(
        VerifiedAdmissionReceipt::from_kernel_verified_for_test(
            denied,
            &kernel.public_key(),
            &Decision::Deny {
                reason: "denied".to_string(),
                guard: "test".to_string(),
            },
            TOOL_SERVER,
            TOOL_NAME,
            &digest("expected_parameter_hash", EMPTY_PARAMETER_HASH),
            &digest("expected_content_hash", CONTENT_HASH),
            &operation,
            &context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
            None,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}

#[test]
fn completed_projection_cannot_omit_required_atomic_sidecars() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        authorization_consumption: true,
        observation_attempt_zero: true,
        obligation: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let mut metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    metadata.tool_outcome_id = Some(outcome_id.clone());
    metadata.tool_outcome_version = Some(outcome_version);
    let kernel = Keypair::generate();
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        Some((&outcome_id, outcome_version)),
    )
    .expect("exact consumer receipt must qualify");
    let mut mismatched_metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    mismatched_metadata.tool_outcome_id = Some(outcome_id.clone());
    mismatched_metadata.tool_outcome_version = Some(outcome_version);
    assert!(matches!(
        verify_completed_receipt(
            &operation,
            &context,
            signed_projection_receipt(&operation, Some(mismatched_metadata), &kernel),
            &kernel,
            Some((&outcome_id, outcome_version + 1)),
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
    let obligation = ObligationProjection::from_source_verified(
        &operation,
        &context,
        &receipt,
        identifier("obligation_id", "obligation-1"),
        digest("obligation_atom_digest", POLICY_HASH),
        identifier("debtor_id", "debtor-1"),
        identifier("original_creditor_id", "creditor-1"),
        MonetaryAmount {
            units: 10,
            currency: "USD".to_string(),
        },
        2_000,
        ObligationDispositionV1::PerCall,
        digest("credit_authority_digest", AUTH_HASH),
        outcome_id.clone(),
        outcome_version,
    )
    .expect("obligation must bind to the exact terminal projection");
    let source_tenant = identifier("source_tenant_id", "tenant-123");
    let authorization = VerifiedAuthorizationReceiptConsumption::from_source_verified(
        &operation,
        &context,
        &receipt,
        AuthorizationReceiptConsumption {
            authorization_receipt_id: "authorization-1".to_string(),
            consumer_receipt_id: receipt.receipt().id.clone(),
            request_id: operation.binding.request_id.as_str().to_string(),
            session_id: "session-1".to_string(),
            tool_call_id: "tool-call-1".to_string(),
            tenant_id: Some("tenant-123".to_string()),
            parameter_hash: POLICY_HASH.to_string(),
            consumed_at_unix_ms: context.trusted_time_unix_ms,
        },
        &identifier("authorization_receipt_id", "authorization-1"),
        &identifier("session_id", "session-1"),
        &identifier("tool_call_id", "tool-call-1"),
        Some(&source_tenant),
        &digest("parameter_hash", POLICY_HASH),
        digest("authorization_receipt_digest", AUTH_HASH),
        outcome_id.clone(),
        outcome_version,
    )
    .expect("authorization consumption must be source verified");
    let observer_work = ObservationAttemptZero::from_verified(
        &operation,
        &context,
        &receipt,
        outcome_id,
        outcome_version,
    )
    .expect("attempt zero must bind immediate visibility");
    let completed = AdmissionCompletedProjection {
        context: context.clone(),
        authorization: Some(authorization),
        observer_work: Some(observer_work),
        obligation: Some(obligation),
        receipt,
        tool_outcome: None,
        payment_evidence: None,
        eligibility: None,
    };
    validate_completed_participant_presence(requirements, &completed)
        .expect("all immutable participant requirements are present");

    let mut missing_authorization = completed.clone();
    missing_authorization.authorization = None;
    let mut missing_observer = completed.clone();
    missing_observer.observer_work = None;
    let mut missing_obligation = completed.clone();
    missing_obligation.obligation = None;
    for missing in [
        &missing_authorization,
        &missing_observer,
        &missing_obligation,
    ] {
        assert_eq!(
            validate_completed_participant_presence(requirements, missing),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        );
    }

    let projection = AdmissionTerminalProjection::Completed(Box::new(completed));
    for (capabilities, capability) in [
        (
            AdmissionProjectionCapabilities {
                authorization_consumption: false,
                ..full_projection_capabilities()
            },
            "authorization_consumption",
        ),
        (
            AdmissionProjectionCapabilities {
                observation_attempt_zero: false,
                ..full_projection_capabilities()
            },
            "observation_attempt_zero",
        ),
        (
            AdmissionProjectionCapabilities {
                obligation: false,
                ..full_projection_capabilities()
            },
            "obligation",
        ),
    ] {
        assert_eq!(
            operation.apply_terminal_projection(&projection, &capabilities),
            Err(AdmissionOperationError::MissingProjectionCapability { capability })
        );
    }
    full_projection_capabilities()
        .validate_for(&operation, &projection)
        .expect("store capabilities cover every immutable participant requirement");
}

#[test]
fn terminal_participant_evidence_rejects_cross_binding_and_substitution() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        outcome_eligibility: true,
        payment: true,
        obligation: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let mut metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    metadata.tool_outcome_id = Some(outcome_id.clone());
    metadata.tool_outcome_version = Some(outcome_version);
    let kernel = Keypair::generate();
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        Some((&outcome_id, outcome_version)),
    )
    .expect("exact consumer receipt must qualify");
    let payment_from = |participant_id, recorded_at| {
        PaymentTerminalEvidence::from_source_verified(
            &operation,
            &context,
            &receipt,
            identifier("payment_participant_id", participant_id),
            digest("payment_authority_digest", AUTH_HASH),
            identifier("payment_record_id", "payment-record-1"),
            digest("payment_record_digest", REQUEST_HASH),
            recorded_at,
            outcome_id.clone(),
            outcome_version,
        )
    };
    let payment =
        payment_from("payment-1", 900).expect("exact payment participant evidence must qualify");
    assert!(payment
        .validate_against(&operation, &context, &receipt, &outcome_id, outcome_version,)
        .is_ok());
    assert!(matches!(
        payment_from("payment-2", 900),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
    assert!(matches!(
        payment_from("payment-1", context.trusted_time_unix_ms + 1),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
    assert_eq!(
        payment.validate_against(
            &operation,
            &context,
            &receipt,
            &outcome_id,
            outcome_version + 1,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    let other_kernel = Keypair::generate();
    let mut other_metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    other_metadata.tool_outcome_id = Some(outcome_id.clone());
    other_metadata.tool_outcome_version = Some(outcome_version);
    let substituted_receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(other_metadata), &other_kernel),
        &other_kernel,
        Some((&outcome_id, outcome_version)),
    )
    .expect("alternate pinned kernel receipt must qualify independently");
    assert_eq!(
        payment.validate_against(
            &operation,
            &context,
            &substituted_receipt,
            &outcome_id,
            outcome_version,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );

    assert!(OutcomeEligibilityFinalization::from_source_verified(
        &operation,
        &context,
        &receipt,
        digest("outcome_eligibility_digest", POLICY_HASH),
        digest("eligibility_authority_digest", AUTH_HASH),
        identifier("eligibility_record_id", "eligibility-1"),
        digest("eligibility_record_digest", REQUEST_HASH),
        950,
        outcome_id.clone(),
        outcome_version,
    )
    .is_ok());
    assert!(matches!(
        OutcomeEligibilityFinalization::from_source_verified(
            &operation,
            &context,
            &receipt,
            digest("outcome_eligibility_digest", REQUEST_HASH),
            digest("eligibility_authority_digest", AUTH_HASH),
            identifier("eligibility_record_id", "eligibility-1"),
            digest("eligibility_record_digest", REQUEST_HASH),
            950,
            outcome_id.clone(),
            outcome_version,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));

    let obligation = ObligationProjection::from_source_verified(
        &operation,
        &context,
        &receipt,
        identifier("obligation_id", "obligation-1"),
        digest("obligation_atom_digest", REQUEST_HASH),
        identifier("debtor_id", "debtor-1"),
        identifier("original_creditor_id", "creditor-1"),
        MonetaryAmount {
            units: 25,
            currency: "USD".to_string(),
        },
        2_000,
        ObligationDispositionV1::PerCall,
        digest("credit_authority_digest", AUTH_HASH),
        outcome_id.clone(),
        outcome_version,
    )
    .expect("canonical obligation atom must qualify");
    let encoded = serde_json::to_value(&obligation).expect("obligation evidence must serialize");
    assert_eq!(encoded["debtor_id"], "debtor-1");
    assert_eq!(encoded["original_creditor_id"], "creditor-1");
    assert_eq!(encoded["amount"]["units"], 25);
    assert_eq!(encoded["due_at_unix_ms"], 2_000);
    assert_eq!(encoded["source"]["outcome_id"], POLICY_HASH);
    assert!(matches!(
        ObligationProjection::from_source_verified(
            &operation,
            &context,
            &receipt,
            identifier("obligation_id", "obligation-2"),
            digest("obligation_atom_digest", REQUEST_HASH),
            identifier("debtor_id", "debtor-1"),
            identifier("original_creditor_id", "creditor-1"),
            MonetaryAmount {
                units: 25,
                currency: "usd".to_string(),
            },
            2_000,
            ObligationDispositionV1::PerCall,
            digest("credit_authority_digest", AUTH_HASH),
            outcome_id,
            outcome_version,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}

#[test]
fn authorization_and_attempt_zero_are_exact_source_verified_contracts() {
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        authorization_consumption: true,
        observation_attempt_zero: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let operation = finalizing_tool_operation_with(requirements);
    let context = projection_context(&operation);
    let outcome_id = digest("outcome_id", POLICY_HASH);
    let outcome_version = 3;
    let mut metadata = receipt_metadata(
        &operation,
        &context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    metadata.tool_outcome_id = Some(outcome_id.clone());
    metadata.tool_outcome_version = Some(outcome_version);
    let kernel = Keypair::generate();
    let receipt = verify_completed_receipt(
        &operation,
        &context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        Some((&outcome_id, outcome_version)),
    )
    .expect("exact consumer receipt must qualify");
    let source_authorization_id = identifier("authorization_receipt_id", "authorization-1");
    let source_session_id = identifier("session_id", "session-1");
    let source_tool_call_id = identifier("tool_call_id", "tool-call-1");
    let source_tenant_id = identifier("tenant_id", "tenant-123");
    let source_parameter_hash = digest("parameter_hash", POLICY_HASH);
    let base = AuthorizationReceiptConsumption {
        authorization_receipt_id: source_authorization_id.as_str().to_string(),
        consumer_receipt_id: receipt.receipt().id.clone(),
        request_id: operation.binding.request_id.as_str().to_string(),
        session_id: source_session_id.as_str().to_string(),
        tool_call_id: source_tool_call_id.as_str().to_string(),
        tenant_id: Some(source_tenant_id.as_str().to_string()),
        parameter_hash: source_parameter_hash.as_str().to_string(),
        consumed_at_unix_ms: context.trusted_time_unix_ms,
    };
    let verify = |consumption| {
        VerifiedAuthorizationReceiptConsumption::from_source_verified(
            &operation,
            &context,
            &receipt,
            consumption,
            &source_authorization_id,
            &source_session_id,
            &source_tool_call_id,
            Some(&source_tenant_id),
            &source_parameter_hash,
            digest("authorization_receipt_digest", AUTH_HASH),
            outcome_id.clone(),
            outcome_version,
        )
    };
    let verified = verify(base.clone()).expect("exact source consumption must qualify");
    assert_eq!(verified.consumption(), &base);
    assert_eq!(
        verified.validate_against(&operation, &context, &receipt, &outcome_id, 4),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    let mut substitutions = Vec::new();
    macro_rules! substitute {
        ($field:ident, $value:expr) => {{
            let mut value = base.clone();
            value.$field = $value;
            substitutions.push(value);
        }};
    }
    substitute!(authorization_receipt_id, "authorization-2".to_string());
    substitute!(consumer_receipt_id, "receipt-2".to_string());
    substitute!(request_id, "request-2".to_string());
    substitute!(session_id, "session-2".to_string());
    substitute!(tool_call_id, "tool-call-2".to_string());
    substitute!(tenant_id, Some("tenant-2".to_string()));
    substitute!(parameter_hash, REQUEST_HASH.to_string());
    substitute!(consumed_at_unix_ms, context.trusted_time_unix_ms + 1);
    for substitution in substitutions {
        assert!(matches!(
            verify(substitution),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        ));
    }

    let attempt_zero = ObservationAttemptZero::from_verified(
        &operation,
        &context,
        &receipt,
        outcome_id.clone(),
        outcome_version,
    )
    .expect("attempt zero must qualify");
    assert_eq!(
        attempt_zero.pending().next_visible_at_ms,
        context.trusted_time_unix_ms
    );
    let delayed = attempt_zero.with_visibility_for_test(context.trusted_time_unix_ms + 1);
    assert_eq!(
        delayed.validate_against(&operation, &context, &receipt, &outcome_id, outcome_version,),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
}

#[test]
fn terminal_projection_accepts_new_owner_fence_only_on_the_same_store() {
    let operation = finalizing_active_operation();
    let retained_dispatch_commit = operation
        .dispatch_commit
        .clone()
        .expect("finalizing operation must retain dispatch commit");
    let mut recovered_context = projection_context(&operation);
    recovered_context.store_fence = StoreMutationFence {
        store_uuid: retained_dispatch_commit.store_fence.store_uuid.clone(),
        lease_id: "owner-lease-2".to_string(),
        owner_epoch: retained_dispatch_commit.store_fence.owner_epoch + 1,
    };
    let kernel = Keypair::generate();
    let metadata = receipt_metadata(
        &operation,
        &recovered_context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    let receipt = verify_completed_receipt(
        &operation,
        &recovered_context,
        signed_projection_receipt(&operation, Some(metadata), &kernel),
        &kernel,
        None,
    )
    .expect("same-store recovery receipt must qualify");
    let recovered =
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context: recovered_context.clone(),
            receipt,
            tool_outcome: None,
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: None,
            obligation: None,
        }));
    let terminal = operation
        .apply_terminal_projection(&recovered, &full_projection_capabilities())
        .expect("same-store recovery fence must terminalize");
    assert_eq!(
        terminal.dispatch_commit.as_ref(),
        Some(&retained_dispatch_commit)
    );

    for fence in [
        StoreMutationFence {
            store_uuid: retained_dispatch_commit.store_fence.store_uuid.clone(),
            lease_id: "different-lease-at-same-epoch".to_string(),
            owner_epoch: retained_dispatch_commit.store_fence.owner_epoch,
        },
        StoreMutationFence {
            store_uuid: retained_dispatch_commit.store_fence.store_uuid.clone(),
            lease_id: "older-owner-lease".to_string(),
            owner_epoch: retained_dispatch_commit.store_fence.owner_epoch - 1,
        },
    ] {
        let mut stale_context = recovered_context.clone();
        stale_context.store_fence = fence;
        let metadata = receipt_metadata(
            &operation,
            &stale_context,
            AdmissionOperationState::Completed,
            AdmissionCompensationStatus::NotCompensated,
        );
        assert!(matches!(
            verify_completed_receipt(
                &operation,
                &stale_context,
                signed_projection_receipt(&operation, Some(metadata), &kernel),
                &kernel,
                None,
            ),
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
        ));
    }

    let mut foreign_context = recovered_context;
    foreign_context.store_fence.store_uuid = "different-store".to_string();
    let metadata = receipt_metadata(
        &operation,
        &foreign_context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
    );
    assert!(matches!(
        verify_completed_receipt(
            &operation,
            &foreign_context,
            signed_projection_receipt(&operation, Some(metadata), &kernel),
            &kernel,
            None,
        ),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    ));
}

#[test]
fn tool_outcome_attachment_is_required_and_exact_before_finalizing() {
    assert!(
        serde_json::from_value::<AdmissionAttachment>(serde_json::json!({
            "ToolOutcomeId": "outcome-1"
        }))
        .is_err()
    );
    let mut operation = prepared(AdmissionOperationKind::ToolDispatch);
    for next in [
        AdmissionOperationState::BrokerAttemptRegistered,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
        AdmissionOperationState::DispatchCommitted,
    ] {
        let command = transition_command(&operation, next, None);
        operation = operation
            .apply_command(&command, 1_000)
            .expect("tool dispatch transition must apply")
            .into_operation();
    }
    let missing = AdmissionOperationCommand::new(
        operation.binding.operation_id.clone(),
        operation.version,
        lease(&operation, operation.version),
        Vec::new(),
        Some(AdmissionOperationState::Finalizing),
        None,
        None,
    )
    .expect("finalizing command must be structurally valid");
    assert_eq!(
        operation.apply_command(&missing, 1_000),
        Err(AdmissionOperationError::MissingParticipantAttachment {
            field: "tool_outcome_id"
        })
    );

    let exact = transition_command(&operation, AdmissionOperationState::Finalizing, None);
    let operation = operation
        .apply_command(&exact, 1_000)
        .expect("attaching the outcome must allow finalizing")
        .into_operation();
    assert!(operation
        .validate_completed_tool_outcome_attachment(&digest("outcome_id", POLICY_HASH))
        .is_ok());
    assert_eq!(
        operation.validate_completed_tool_outcome_attachment(&digest(
            "outcome_id",
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    assert_eq!(
        validate_state_attachments(
            AdmissionOperationKind::ToolDispatch,
            operation.binding.participant_requirements(),
            AdmissionOperationState::NotAcceptedAfterDispatchCommit,
            &operation.attachments,
        ),
        Err(AdmissionOperationError::ForbiddenAttachment {
            field: "tool_outcome_id"
        })
    );
    assert!(validate_state_attachments(
        AdmissionOperationKind::ToolDispatch,
        operation.binding.participant_requirements(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        &operation.attachments,
    )
    .is_ok());
}

#[test]
fn terminal_replay_reference_is_typed_and_retained() {
    let mut operation = prepared(AdmissionOperationKind::ToolDispatch);
    for next in [
        AdmissionOperationState::BrokerAttemptRegistered,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
        AdmissionOperationState::DispatchCommitted,
        AdmissionOperationState::Finalizing,
    ] {
        let command = transition_command(&operation, next, None);
        operation = operation
            .apply_command(&command, 1_000)
            .expect("legal transition must apply")
            .into_operation();
    }
    let dispatch_commit = operation
        .dispatch_commit
        .clone()
        .expect("post-dispatch operation must retain its commit binding");
    assert_eq!(dispatch_commit.committed_version, 6);
    assert_eq!(dispatch_commit.coordinator_lease_epoch, 7);
    assert_eq!(
        AdmissionOperationCommand::new(
            operation.binding.operation_id.clone(),
            operation.version,
            lease(&operation, operation.version),
            Vec::new(),
            Some(AdmissionOperationState::OutcomeUnknownAfterDispatch),
            Some(AdmissionTerminalReplay::Incident {
                incident_id: identifier("incident_id", "incident-1"),
            }),
            None,
        ),
        Err(AdmissionOperationError::TerminalProjectionRequired)
    );
    let replay = AdmissionTerminalReplay::Incident {
        incident_id: identifier("incident_id", "incident-1"),
    };
    let context = AdmissionProjectionContext {
        operation_id: operation.binding.operation_id.clone(),
        request_id: operation.binding.request_id.clone(),
        expected_operation_version: operation.version,
        trusted_time_unix_ms: 1_000,
        coordinator_lease_id: identifier("coordinator_lease_id", "coordinator-lease-1"),
        coordinator_lease_epoch: operation.coordinator_lease_epoch,
        store_fence: dispatch_commit.store_fence.clone(),
    };
    let incident = AdmissionIncident::from_verified(
        &operation,
        &context,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        identifier("incident_id", "incident-1"),
        digest("incident_digest", POLICY_HASH),
    )
    .expect("incident must bind to the exact terminal projection");
    let projection = AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context,
        incident: Box::new(incident),
    };
    operation = operation
        .apply_terminal_projection(&projection, &full_projection_capabilities())
        .expect("closed terminal projection must apply");
    assert_eq!(operation.dispatch_commit.as_ref(), Some(&dispatch_commit));
    assert!(operation.has_attachment(AdmissionAttachmentKind::ToolOutcome));
    assert_eq!(operation.terminal_replay(), Some(&replay));
    assert_eq!(
        operation.classify_replay(&prepared(AdmissionOperationKind::ToolDispatch)),
        AdmissionReplayClassification::Exact {
            terminal_replay: Some(replay)
        }
    );
}
