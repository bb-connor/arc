use chio_core::capability::governance::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};

use super::*;

fn apply(
    operation: AdmissionOperationV1,
    attachments: Vec<AdmissionAttachment>,
    next: Option<AdmissionOperationState>,
) -> Result<AdmissionOperationV1, AdmissionOperationError> {
    let command = AdmissionOperationCommand::new(
        operation.binding.operation_id.clone(),
        operation.version,
        lease(&operation, operation.version),
        attachments,
        next,
        None,
        None,
    )?;
    Ok(operation.apply_command(&command, 1_000)?.into_operation())
}

#[test]
fn rich_native_caller_attachments_survive_outcome_append_and_persistence(
) -> Result<(), Box<dyn std::error::Error>> {
    // This checks the operation representation, not admission of an unsupported
    // combined caller profile. Participant selection and live custody stay with
    // their existing authorities; a larger attachment set cannot grant them.
    let requirements = AdmissionParticipantRequirements {
        approval: true,
        execution_nonce: true,
        outcome_eligibility: true,
        ..channel_requirements()
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: namespace("tenant-123"),
        request_id: identifier("request_id", "rich-attachments"),
        capability_id: identifier("capability_id", "cap-attachments"),
        authorization_capability_hash: digest("authorization_hash", AUTH_HASH),
        request_binding: AdmissionRequestBindingV1::new(
            digest("immutable_request_hash", REQUEST_HASH),
            requirements,
        )?,
        policy_hash: digest("policy_hash", POLICY_HASH),
        effect_class: SideEffectClass::Monetary,
    })?;
    let key = Keypair::from_seed(&[74; 32]);
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.into(),
            proposal_id: "proposal-attachments".into(),
            request_id: binding.request_id.as_str().into(),
            governed_intent_hash: REQUEST_HASH.into(),
            subject: key.public_key(),
            authorizing_capability_digest: AUTH_HASH.into(),
            policy_hash: POLICY_HASH.into(),
            threshold: 1,
            eligible_set_digest: CONTENT_HASH.into(),
            proposal_created_at: 900,
            proposal_deadline: 1_100,
            policy_authority: key.public_key(),
        },
        &key,
    )?;
    let hash = digest("attachment_digest", CONTENT_HASH);
    let mut operation = apply(
        AdmissionOperationV1::prepare(binding, 7)?,
        vec![
            AdmissionAttachment::ThresholdProposalHash(digest(
                "threshold_proposal_hash",
                &proposal.proposal_hash()?,
            )),
            AdmissionAttachment::ThresholdProposal(Box::new(proposal)),
            AdmissionAttachment::SupplementalAuthorizationDigest(hash.clone()),
            AdmissionAttachment::OutcomeEligibilityDigest(hash.clone()),
            AdmissionAttachment::ChannelReservationProposalDigest(hash.clone()),
            AdmissionAttachment::ExecutionNonceIssuanceDigest(hash.clone()),
            AdmissionAttachment::ExecutionNoncePreflightDigest(hash.clone()),
            AdmissionAttachment::RuntimeParticipantLedgerDigest(hash.clone()),
            AdmissionAttachment::GovernedApprovalLedgerDigest(hash.clone()),
            AdmissionAttachment::DpopReplayLedgerDigest(hash.clone()),
        ],
        None,
    )?;
    let mut attempt = provider_attempt(&operation, "attempt-attachments");
    attempt.transport_id = format!(
        "{}server",
        ProviderAttemptBindingV1::NATIVE_CALLER_REPORT_TRANSPORT_PREFIX,
    );
    for (next, attachments) in [
        (
            AdmissionOperationState::BrokerAttemptRegistered,
            vec![AdmissionAttachment::BrokerAttempt(attempt)],
        ),
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "budget_hold_id",
                "hold-1",
            ))],
        ),
        (
            AdmissionOperationState::ApprovalReserved,
            vec![
                AdmissionAttachment::ApprovalSetHash(hash.clone()),
                AdmissionAttachment::ChannelReservationDigest(hash.clone()),
                AdmissionAttachment::ExecutionNonceId(identifier("execution_nonce_id", "nonce-1")),
            ],
        ),
        (AdmissionOperationState::ReadyToDispatch, vec![]),
        (AdmissionOperationState::CapturePending, vec![]),
        (
            AdmissionOperationState::DispatchCommitted,
            vec![
                AdmissionAttachment::CallerDispatchContextDigest(hash.clone()),
                AdmissionAttachment::NativeDispatchLedgerDigest(hash.clone()),
            ],
        ),
    ] {
        operation = apply(operation, attachments, Some(next))?;
    }
    assert_eq!(operation.attachments.as_slice().len(), 17);
    assert_eq!(
        AdmissionOperationV1::from_persisted(operation.to_persisted())?,
        operation
    );
    let finalized = apply(
        operation,
        vec![AdmissionAttachment::ToolOutcomeId(hash.clone())],
        Some(AdmissionOperationState::Finalizing),
    )?;
    assert_eq!(finalized.attachments.as_slice().len(), 18);
    let bytes = serde_json::to_vec(&finalized.to_persisted())?;
    let restored = AdmissionOperationV1::from_persisted(serde_json::from_slice(&bytes)?)?;
    assert_eq!(restored, finalized);

    let mut duplicated = restored.to_persisted();
    duplicated
        .attachments
        .0
        .push(AdmissionAttachment::NativeDispatchLedgerDigest(hash));
    assert_eq!(
        AdmissionOperationV1::from_persisted(duplicated),
        Err(AdmissionOperationError::DuplicateAttachment {
            field: "persisted_attachment_set"
        }),
    );
    Ok(())
}
