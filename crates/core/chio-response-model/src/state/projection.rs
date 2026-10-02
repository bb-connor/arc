//! Pure snapshot projections shared by dispatch preparation and evidence readers.
//! These functions perform no store writes and grant no execution authority.

use super::{
    encode_response_record_with_mode, latest_evidence_id, push_mutation, request_id,
    transition_due_at, transition_mutation, validate_plan, validate_transition_request,
    ResponseTransitionRequest, StateMachineError, TransitionMutationContext,
};
use chio_security_types::ports::ResponsePlanRecord;
use chio_security_types::{
    is_legal_response_transition, DispatchRejection, ResponseMutationLog, ResponseMutationRecord,
    ResponsePlan, ResponseRequestedRecord, ResponseSnapshot, ResponseState,
    RESPONSE_STATE_SCHEMA_VERSION,
};

/// Project validated plan data into its initial evidence state, without admission.
pub fn initial_response_snapshot(
    plan: ResponsePlan,
) -> Result<ResponseSnapshot, StateMachineError> {
    validate_plan(&plan)?;
    let request_id = request_id(&plan)?;
    let mutations = ResponseMutationLog::new(vec![ResponseMutationRecord::Requested(
        ResponseRequestedRecord {
            transition_id: request_id,
            generation: 0,
            prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
            occurred_at_unix_ms: plan.created_at_unix_ms,
        },
    )])
    .map_err(StateMachineError::MutationLimit)?;
    Ok(ResponseSnapshot {
        schema_version: RESPONSE_STATE_SCHEMA_VERSION,
        execution_dispatch: None,
        dispatch_authorization_hash: None,
        state: ResponseState::Planned,
        generation: 0,
        applying_lease_expires_at_unix_ms: None,
        due_at_unix_ms: Some(plan.expires_at_unix_ms),
        operator_page_required: false,
        plan,
        mutations,
    })
}

/// Project the lifecycle rules for an already authorized dispatch. Provenance
/// admission belongs to the kernel; this data-only function cannot persist or
/// execute the projection. Direct state-machine writes still require live mode.
pub fn prepare_dispatch_transition(
    snapshot: &mut ResponseSnapshot,
    target_state: ResponseState,
    occurred_at_unix_ms: u64,
    applying_lease_expires_at_unix_ms: Option<u64>,
) -> Result<(), StateMachineError> {
    if !is_legal_response_transition(snapshot.state, target_state) {
        return Err(StateMachineError::InvalidTransition);
    }
    let request = ResponseTransitionRequest {
        expected_generation: snapshot.generation,
        target_state,
        occurred_at_unix_ms,
        applying_lease_expires_at_unix_ms,
        error_code: None,
    };
    validate_transition_request(snapshot, &request, target_state)?;
    let next_generation = snapshot
        .generation
        .checked_add(1)
        .ok_or(StateMachineError::GenerationOverflow)?;
    let due_at_unix_ms = transition_due_at(snapshot, &request, target_state)?;
    let prior_receipt_id = latest_evidence_id(snapshot)?;
    let mutation = transition_mutation(
        snapshot,
        &request,
        TransitionMutationContext {
            from_state: snapshot.state,
            actual_target: target_state,
            prior_receipt_id,
            generation: next_generation,
            scheduler_lease_owner_id: None,
            scheduler_fencing_token: None,
        },
    )?;
    push_mutation(snapshot, mutation)?;
    snapshot.state = target_state;
    snapshot.generation = next_generation;
    snapshot.applying_lease_expires_at_unix_ms = applying_lease_expires_at_unix_ms;
    snapshot.due_at_unix_ms = due_at_unix_ms;
    Ok(())
}

pub fn encode_normalized_dispatch_response_record(
    snapshot: &ResponseSnapshot,
) -> Result<ResponsePlanRecord, StateMachineError> {
    if snapshot.execution_dispatch.is_none() {
        return Err(DispatchRejection::SnapshotWithoutExecutionDispatch.into());
    }
    if snapshot.dispatch_authorization_hash.is_some() {
        return Err(DispatchRejection::SnapshotAlreadyAuthorized.into());
    }
    encode_response_record_with_mode(snapshot, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_security_types::ports::RecordId;
    use chio_security_types::ports::{
        Digest32, ResponseDispatchApproval, TenantId,
        RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
    };
    use chio_security_types::ResponseExecutionDispatchBinding;

    fn fixture_snapshot() -> ResponseSnapshot {
        let plan: ResponsePlan = serde_json::from_str(include_str!(
            "../../../../../tests/bindings/vectors/security/active-defense/positive/response-plan-v1.json"
        ))
        .unwrap_or_else(|error| panic!("response plan fixture failed: {error}"));
        ResponseSnapshot {
            schema_version: RESPONSE_STATE_SCHEMA_VERSION,
            plan,
            execution_dispatch: None,
            dispatch_authorization_hash: None,
            state: ResponseState::Planned,
            generation: 0,
            applying_lease_expires_at_unix_ms: None,
            due_at_unix_ms: None,
            operator_page_required: false,
            mutations: ResponseMutationLog::new(Vec::new())
                .unwrap_or_else(|error| panic!("empty mutation log failed: {error}")),
        }
    }

    fn record_id(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
    }

    #[test]
    fn normalized_dispatch_record_refuses_a_snapshot_without_its_binding() {
        let unbound = fixture_snapshot();
        assert!(matches!(
            encode_normalized_dispatch_response_record(&unbound),
            Err(StateMachineError::InvalidDispatch(
                DispatchRejection::SnapshotWithoutExecutionDispatch
            ))
        ));
    }

    #[test]
    fn normalized_dispatch_record_refuses_a_snapshot_already_authorized() {
        let mut authorized = fixture_snapshot();
        authorized.execution_dispatch = Some(ResponseExecutionDispatchBinding {
            schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
            tenant_id: TenantId::new("tenant").unwrap_or_else(|error| panic!("{error}")),
            dispatch_id: record_id("dispatch"),
            action_id: authorized.plan.action_id.clone(),
            plan_hash: authorized.plan.plan_hash,
            executor_authority_id: record_id("executor-authority"),
            executor_authority_generation: 1,
            authorization_capability_hash: Digest32::new([1; 32]),
            governed_intent_hash: Digest32::new([2; 32]),
            policy_decision_hash: Digest32::new([3; 32]),
            approval: ResponseDispatchApproval::Automatic,
            authorized_at_unix_ms: 1,
        });
        authorized.dispatch_authorization_hash = Some(Digest32::new([4; 32]));
        assert!(matches!(
            encode_normalized_dispatch_response_record(&authorized),
            Err(StateMachineError::InvalidDispatch(
                DispatchRejection::SnapshotAlreadyAuthorized
            ))
        ));
    }
}
