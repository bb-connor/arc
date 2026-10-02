use chio_flow::{DeclassificationError, FlowDenial};
use chio_recovery_lab::{
    fixture::{Case, LabResult},
    plan, prepare_approved_offer, resolved_request, OperationState, PlanningDecision,
    RecoveryError,
};
use chio_security_types::ports::{CanonicalBody, DestinationId, Digest32, RecordId};
use chio_security_types::InformationLabel;

#[test]
fn a_private_disclosure_offers_one_exact_approval() -> LabResult<()> {
    let case = Case::new()?;
    assert!(
        matches!(plan(&case.intent, &case.host)?, PlanningDecision::Denied { offers, .. } if offers.len() == 1)
    );
    Ok(())
}

#[test]
fn a_valid_grant_prepares_only_the_exact_crossing_without_clearing_taint() -> LabResult<()> {
    let case = Case::new()?;
    let prepared = prepare_approved_offer(
        &case.offer()?,
        &case.intent,
        &case.host,
        &case.grant(200)?,
        151_000,
    )?;
    assert_ne!(
        prepared.admission().source_label,
        InformationLabel::bottom()
    );
    assert_eq!(
        prepared.admission().egress_source_label,
        InformationLabel::bottom()
    );
    assert_eq!(
        prepared.admission().taint_transition.principal_join,
        prepared.admission().source_label
    );
    assert!(prepared.declassification().is_some());
    assert!(matches!(
        prepared.into_admission(),
        Err(FlowDenial::DeclassificationStoreFailure)
    ));
    assert!(matches!(
        plan(&case.intent, &case.host)?,
        PlanningDecision::Denied { .. }
    ));
    Ok(())
}

#[test]
fn changes_in_flow_policy_authority_and_budget_basis_make_the_offer_stale() -> LabResult<()> {
    let case = Case::new()?;
    let offer = case.offer()?;
    let grant = case.grant(200)?;
    let mut variants = Vec::new();
    let mut h = case.host.clone();
    h.flow.context_generation += 1;
    variants.push(h);
    let mut h = case.host.clone();
    h.policy_digest = Digest32::new([9; 32]);
    variants.push(h);
    let mut h = case.host.clone();
    h.contract_digest = Digest32::new([9; 32]);
    variants.push(h);
    let mut h = case.host.clone();
    h.revocation_generation += 1;
    variants.push(h);
    let mut h = case.host.clone();
    h.budget_generation += 1;
    variants.push(h);
    let mut h = case.host.clone();
    h.budget_remaining += 1;
    variants.push(h);
    let mut h = case.host.clone();
    h.flow.session_label = InformationLabel::Top;
    variants.push(h);
    let mut h = case.host.clone();
    h.policy_purposes.clear();
    variants.push(h);
    let mut h = case.host.clone();
    h.trusted_authorities.clear();
    variants.push(h);
    for host in variants {
        assert!(matches!(
            prepare_approved_offer(&offer, &case.intent, &host, &grant, 151_000),
            Err(RecoveryError::StaleOffer)
        ));
    }
    Ok(())
}

#[test]
fn changed_payload_destination_capability_and_tool_cannot_reuse_the_offer() -> LabResult<()> {
    let case = Case::new()?;
    let offer = case.offer()?;
    let grant = case.grant(200)?;
    let mut variants = Vec::new();
    let mut i = case.intent.clone();
    i.canonical_request = CanonicalBody::new(br#"{"body":"changed"}"#.to_vec())?;
    variants.push(i);
    let mut i = case.intent.clone();
    i.destination = DestinationId::new("another-sink")?;
    variants.push(i);
    let mut i = case.intent.clone();
    i.capability_id = RecordId::new("another-capability")?;
    variants.push(i);
    let mut i = case.intent.clone();
    i.tool_name = RecordId::new("another-tool")?;
    variants.push(i);
    for intent in variants {
        assert!(matches!(
            prepare_approved_offer(&offer, &intent, &case.host, &grant, 151_000),
            Err(RecoveryError::StaleOffer)
        ));
    }
    Ok(())
}

#[test]
fn passage_of_time_allows_fresh_checks_but_not_offer_or_grant_expiry() -> LabResult<()> {
    let case = Case::new()?;
    let offer = case.offer()?;
    let mut later = case.host.clone();
    later.now_unix_ms = 152_000;
    assert!(
        prepare_approved_offer(&offer, &case.intent, &later, &case.grant(200)?, 153_000).is_ok()
    );
    assert!(matches!(
        prepare_approved_offer(&offer, &case.intent, &later, &case.grant(200)?, 180_000),
        Err(RecoveryError::OfferExpired)
    ));
    assert!(matches!(
        prepare_approved_offer(&offer, &case.intent, &later, &case.grant(160)?, 160_000),
        Err(RecoveryError::Grant(DeclassificationError::Expired))
    ));
    assert!(matches!(
        prepare_approved_offer(&offer, &case.intent, &later, &case.grant(200)?, 151_000),
        Err(RecoveryError::ClockMovedBackward)
    ));
    Ok(())
}

#[test]
fn revocation_and_exhausted_budget_are_refusals_without_approval_offers() -> LabResult<()> {
    let case = Case::new()?;
    let mut revoked = case.host.clone();
    revoked.capability_revoked = true;
    let mut exhausted = case.host.clone();
    exhausted.budget_remaining = 0;
    for (host, expected) in [
        (revoked, RecoveryError::CapabilityRevoked),
        (exhausted, RecoveryError::BudgetUnavailable),
    ] {
        assert!(matches!(
            plan(&case.intent, &host)?,
            PlanningDecision::Refused { .. }
        ));
        assert!(matches!(prepare_approved_offer(
            &case.offer()?,
            &case.intent,
            &host,
            &case.grant(200)?,
            151_000
        ), Err(error) if error == expected));
    }
    Ok(())
}

#[test]
fn unknown_and_complete_operations_do_not_receive_a_new_dispatch_offer() -> LabResult<()> {
    let case = Case::new()?;
    let mut host = case.host.clone();
    host.operation_state = OperationState::OutcomeUnknown;
    assert!(matches!(
        plan(&case.intent, &host)?,
        PlanningDecision::Reconcile { .. }
    ));
    assert!(matches!(
        prepare_approved_offer(
            &case.offer()?,
            &case.intent,
            &host,
            &case.grant(200)?,
            151_000
        ),
        Err(RecoveryError::UnknownOutcome)
    ));
    host.operation_state = OperationState::Complete;
    assert!(matches!(
        plan(&case.intent, &host)?,
        PlanningDecision::RecoverOutcome { .. }
    ));
    Ok(())
}

#[test]
fn top_and_missing_clearance_never_get_a_disclosure_approval_offer() -> LabResult<()> {
    let case = Case::new()?;
    let mut top = case.host.clone();
    top.flow.principal_label = InformationLabel::Top;
    let mut no_clearance = case.host.clone();
    no_clearance.policy_clearances.clear();
    for host in [top, no_clearance] {
        assert!(
            matches!(plan(&case.intent, &host)?, PlanningDecision::Denied { offers, .. } if offers.is_empty())
        );
    }
    Ok(())
}

#[test]
fn a_public_request_needs_no_disclosure_exception() -> LabResult<()> {
    let mut case = Case::new()?;
    case.intent.payload_label = InformationLabel::bottom();
    case.host.flow.principal_label = InformationLabel::bottom();
    case.host.flow.lineage_label = InformationLabel::bottom();
    case.host.flow.session_label = InformationLabel::bottom();
    assert!(matches!(
        plan(&case.intent, &case.host)?,
        PlanningDecision::FlowCheckPassed
    ));
    Ok(())
}

#[test]
fn an_unrelated_operation_cannot_borrow_another_operations_host_state() -> LabResult<()> {
    let mut case = Case::new()?;
    case.intent.operation_id = RecordId::new("another-operation")?;
    assert!(matches!(
        plan(&case.intent, &case.host),
        Err(RecoveryError::OperationBindingMismatch)
    ));
    Ok(())
}

#[test]
fn noncanonical_bytes_are_rejected_before_an_offer_is_created() -> LabResult<()> {
    let mut case = Case::new()?;
    case.intent.canonical_request =
        CanonicalBody::new(br#"{ "body": "extra whitespace" }"#.to_vec())?;
    assert!(matches!(
        plan(&case.intent, &case.host),
        Err(RecoveryError::Grant(
            DeclassificationError::InvalidRequestRepresentation
        ))
    ));
    Ok(())
}

#[test]
fn frozen_denied_operations_require_a_continuation_without_reusing_the_offer() -> LabResult<()> {
    let case = Case::new()?;
    let mut host = case.host.clone();
    host.operation_state = OperationState::DeniedBeforeDispatch;
    assert!(matches!(plan(&case.intent, &host)?,
        PlanningDecision::ContinuationRequired { denied_operation_id }
        if denied_operation_id == case.intent.operation_id));
    assert!(matches!(
        prepare_approved_offer(
            &case.offer()?,
            &case.intent,
            &host,
            &case.grant(200)?,
            151_000
        ),
        Err(RecoveryError::FrozenDeniedOperation)
    ));
    Ok(())
}

#[test]
fn pending_operations_wait_without_issuing_a_new_approval_offer() -> LabResult<()> {
    let case = Case::new()?;
    let mut host = case.host.clone();
    host.operation_state = OperationState::Pending;
    assert!(matches!(plan(&case.intent, &host)?,
        PlanningDecision::WaitForOutcome { operation_id }
        if operation_id == case.intent.operation_id));
    assert!(matches!(
        prepare_approved_offer(
            &case.offer()?,
            &case.intent,
            &host,
            &case.grant(200)?,
            151_000
        ),
        Err(RecoveryError::OutcomePending)
    ));
    Ok(())
}

#[test]
fn denied_input_observation_is_restrictive_and_grants_no_egress() -> LabResult<()> {
    let case = Case::new()?;
    let request = resolved_request(&case.intent, &case.host, 150_000)?;
    let observation = request.observed_input_taint();
    assert!(!observation
        .principal_join
        .flows_to(&InformationLabel::bottom()));
    assert!(matches!(
        chio_flow::prepare_pre_invocation(request),
        Err(FlowDenial::PolicyFlowViolation)
    ));
    Ok(())
}
