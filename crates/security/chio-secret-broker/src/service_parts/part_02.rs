include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/service_parts/part_02_sections/execution_setup.inc"
));
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/service_parts/part_02_sections/execution_and_failure.inc"
));

fn execution_failure_after_capture_release(
    error: BrokerError,
    released: Result<bool>,
) -> ExecutionFailure {
    let projection = released
        .ok()
        .filter(|released| *released)
        .map(|_| FailureProjection {
            stage: BrokerFailureStage::Capture,
            outcome: failure_outcome_before_dispatch(&error),
            dispatch_knowledge: BrokerDispatchKnowledge::NotCommitted,
        });
    ExecutionFailure { error, projection }
}

fn validate_execution_projection_for_attempt(
    attempt: &AttemptRecord,
    projection: FailureProjection,
) -> Result<()> {
    let compatible = match (
        projection.stage,
        projection.outcome,
        projection.dispatch_knowledge,
    ) {
        (
            BrokerFailureStage::Capture,
            BrokerFailureOutcome::Denied | BrokerFailureOutcome::Failed,
            BrokerDispatchKnowledge::NotCommitted,
        ) => attempt.state == AttemptState::Captured && attempt.dispatch_claim_id.is_none(),
        (
            BrokerFailureStage::Dispatch,
            BrokerFailureOutcome::Unknown,
            BrokerDispatchKnowledge::Unknown,
        )
        | (
            BrokerFailureStage::Response | BrokerFailureStage::ReceiptPersistence,
            BrokerFailureOutcome::Failed,
            BrokerDispatchKnowledge::Committed,
        ) => {
            matches!(
                attempt.state,
                AttemptState::DispatchCommitted | AttemptState::UnknownOutcome
            ) && attempt_has_capture_evidence(attempt)
        }
        _ => false,
    };
    if !compatible {
        return Err(BrokerError::Conflict(
            "execution failure provenance conflicts with the durable attempt boundary".to_string(),
        ));
    }
    Ok(())
}

fn attempt_has_capture_evidence(attempt: &AttemptRecord) -> bool {
    attempt.revocation_set_digest.is_some()
        && attempt.budget_commit_index.is_some()
        && attempt.revocation_commit_index.is_some()
        && attempt.authority_commit_index.is_some()
        && attempt.leader_epoch.is_some()
}

fn failure_projection_matches_attempt(
    attempt: &AttemptRecord,
    receipt: &BrokerFailureReceiptBody,
    target: AttemptState,
) -> bool {
    match attempt.state {
        AttemptState::Registered => {
            target == AttemptState::Failed
                && receipt.stage == BrokerFailureStage::Admission
                && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotStarted
                && matches!(
                    receipt.outcome,
                    BrokerFailureOutcome::Denied | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Prepared => {
            receipt.stage == BrokerFailureStage::Hold
                && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.outcome,
                    BrokerFailureOutcome::Denied
                        | BrokerFailureOutcome::Reversed
                        | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Held => {
            receipt.stage == BrokerFailureStage::Capture
                && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.outcome,
                    BrokerFailureOutcome::Denied
                        | BrokerFailureOutcome::Reversed
                        | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::Captured => {
            target == AttemptState::Failed
                && attempt.dispatch_claim_id.is_none()
                && receipt.stage == BrokerFailureStage::Capture
                && receipt.dispatch_knowledge == BrokerDispatchKnowledge::NotCommitted
                && matches!(
                    receipt.outcome,
                    BrokerFailureOutcome::Denied | BrokerFailureOutcome::Failed
                )
        }
        AttemptState::DispatchCommitted | AttemptState::UnknownOutcome => {
            target == AttemptState::Failed
                && attempt_has_capture_evidence(attempt)
                && matches!(
                    (receipt.stage, receipt.outcome, receipt.dispatch_knowledge,),
                    (
                        BrokerFailureStage::Dispatch,
                        BrokerFailureOutcome::Unknown,
                        BrokerDispatchKnowledge::Unknown,
                    ) | (
                        BrokerFailureStage::Response | BrokerFailureStage::ReceiptPersistence,
                        BrokerFailureOutcome::Failed,
                        BrokerDispatchKnowledge::Committed,
                    )
                )
        }
        AttemptState::Failed => target == AttemptState::Failed,
        AttemptState::Reversed => target == AttemptState::Reversed,
        AttemptState::Completed => false,
    }
}

fn execution_hold_query(attempt: &AttemptRecord) -> Result<QueryExecutionHoldRequest> {
    let query = QueryExecutionHoldRequest {
        operation_id: attempt.registration.ids.operation_id.clone(),
        invocation_id: attempt.registration.invocation_id.clone(),
        parent_capability_id: attempt.registration.parent_capability_id.clone(),
        broker_capability_id: attempt.registration.broker_capability_id.clone(),
        hold_id: attempt.registration.ids.hold_id.clone(),
        authorize_event_id: attempt.registration.ids.authorize_event_id.clone(),
        reverse_event_id: attempt.registration.ids.reverse_event_id.clone(),
        capture_event_id: attempt.registration.ids.capture_event_id.clone(),
    };
    query.validate()?;
    Ok(query)
}
