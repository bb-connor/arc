//! Dispatch preparation: the one place a plan and its executor authorization
//! become the durable record and first lease an executor commits.
//!
//! Every refusal here is a [`DispatchRejection`], one per rule, so the caller,
//! the receipt and the operator log can each name what refused the dispatch.

use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{
    CanonicalBody, Digest32, RecordId, ResponseDispatchApproval, ResponseDispatchAuthorization,
    ResponseDispatchAuthorizationBody, ResponseDispatchCommitMode, ResponseDispatchCommitRequest,
    ResponseDispatchKey, ResponseDispatchLease, ResponsePlanRecord,
    RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use chio_security_types::{
    is_legal_response_transition, DispatchRejection, ResponseApprovalRequirement,
    ResponseExecutionDispatchBinding, ResponseMutationLog, ResponseMutationRecord, ResponsePlan,
    ResponseRequestedRecord, ResponseSnapshot, ResponseState, RESPONSE_STATE_SCHEMA_VERSION,
};

use super::{
    encode_response_record, encode_response_record_with_mode, latest_evidence_id, push_mutation,
    request_id, transition_due_at, transition_mutation, validate_plan, validate_transition_request,
    ResponseTransitionRequest, StateMachineError, TransitionMutationContext,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseDispatchPreparationRequest {
    pub plan: ResponsePlan,
    pub dispatch_id: RecordId,
    pub authorization_capability_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub executor_authority_id: RecordId,
    pub executor_authority_generation: u64,
    pub approval: ResponseDispatchApproval,
    pub authorized_at_unix_ms: u64,
    pub initial_lease: ResponseDispatchLease,
    pub commit_mode: ResponseDispatchCommitMode,
}

/// Build the exact durable record and first lease admitted by an executor.
///
/// This function performs no I/O. The returned request is committed atomically
/// by `ResponseDispatchStore`, which allocates the first scheduler fencing
/// token. Both approval modes start execution in `Applying`. A committed record
/// with no effect progress is recovered only through exact dispatch readback;
/// scheduler recovery begins after effect progress diverges from that record.
pub fn prepare_response_dispatch(
    request: ResponseDispatchPreparationRequest,
) -> Result<ResponseDispatchCommitRequest, StateMachineError> {
    let ResponseDispatchPreparationRequest {
        plan,
        dispatch_id,
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        executor_authority_id,
        executor_authority_generation,
        approval,
        authorized_at_unix_ms,
        initial_lease,
        commit_mode,
    } = request;
    validate_plan(&plan)?;
    match commit_mode {
        ResponseDispatchCommitMode::Fresh => {
            plan.require_live_execution()?;
        }
        ResponseDispatchCommitMode::GovernedCommittedResume
        | ResponseDispatchCommitMode::GovernedCommittedExpiredResume => {
            plan.require_live_or_legacy_execution()?;
        }
    }
    if authorization_capability_hash != plan.operator_capability.capability_digest {
        return Err(DispatchRejection::CapabilityDigestMismatch.into());
    }
    if executor_authority_generation == 0 {
        return Err(DispatchRejection::ZeroExecutorGeneration.into());
    }
    if authorized_at_unix_ms < plan.created_at_unix_ms
        || authorized_at_unix_ms >= plan.expires_at_unix_ms
    {
        return Err(DispatchRejection::AuthorizationOutsideWindow {
            authorized_at_unix_ms,
            created_at_unix_ms: plan.created_at_unix_ms,
            expires_at_unix_ms: plan.expires_at_unix_ms,
        }
        .into());
    }
    if initial_lease.lease_expires_at_unix_ms <= authorized_at_unix_ms
        || initial_lease.lease_expires_at_unix_ms > plan.expires_at_unix_ms
    {
        return Err(DispatchRejection::LeaseOutsideWindow {
            lease_expires_at_unix_ms: initial_lease.lease_expires_at_unix_ms,
            authorized_at_unix_ms,
            plan_expires_at_unix_ms: plan.expires_at_unix_ms,
        }
        .into());
    }
    let governed = match (&plan.approval_requirement, &approval) {
        (ResponseApprovalRequirement::Automatic, ResponseDispatchApproval::Automatic) => false,
        (
            ResponseApprovalRequirement::Governed { .. },
            ResponseDispatchApproval::Governed {
                admission_operation_version: 0,
                ..
            },
        ) => return Err(DispatchRejection::ZeroAdmissionOperationVersion.into()),
        (
            ResponseApprovalRequirement::Governed { .. },
            ResponseDispatchApproval::Governed { .. },
        ) => true,
        (ResponseApprovalRequirement::Automatic, ResponseDispatchApproval::Governed { .. })
        | (ResponseApprovalRequirement::Governed { .. }, ResponseDispatchApproval::Automatic) => {
            return Err(DispatchRejection::ApprovalRequirementMismatch.into());
        }
    };
    if matches!(
        commit_mode,
        ResponseDispatchCommitMode::GovernedCommittedResume
            | ResponseDispatchCommitMode::GovernedCommittedExpiredResume
    ) && !governed
    {
        return Err(DispatchRejection::ResumeRequiresGovernedApproval { commit_mode }.into());
    }

    let requested = ResponseMutationRecord::Requested(ResponseRequestedRecord {
        transition_id: request_id(&plan)?,
        generation: 0,
        prior_receipt_id: plan.trigger_finding_receipt_id.clone(),
        occurred_at_unix_ms: plan.created_at_unix_ms,
    });
    let mutations =
        ResponseMutationLog::new(vec![requested]).map_err(|_| StateMachineError::MutationLimit)?;
    let execution_dispatch = ResponseExecutionDispatchBinding {
        schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        tenant_id: plan.tenant_id.clone(),
        dispatch_id: dispatch_id.clone(),
        action_id: plan.action_id.clone(),
        plan_hash: plan.plan_hash,
        executor_authority_id: executor_authority_id.clone(),
        executor_authority_generation,
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        approval: approval.clone(),
        authorized_at_unix_ms,
    };
    let mut snapshot = ResponseSnapshot {
        schema_version: RESPONSE_STATE_SCHEMA_VERSION,
        plan,
        execution_dispatch: Some(execution_dispatch),
        dispatch_authorization_hash: None,
        state: ResponseState::Planned,
        generation: 0,
        applying_lease_expires_at_unix_ms: None,
        due_at_unix_ms: None,
        operator_page_required: false,
        mutations,
    };
    snapshot.due_at_unix_ms = Some(snapshot.plan.expires_at_unix_ms);
    if governed {
        let created_at_unix_ms = snapshot.plan.created_at_unix_ms;
        prepare_dispatch_transition(
            &mut snapshot,
            ResponseState::AwaitingApproval,
            created_at_unix_ms,
            None,
        )?;
    }
    prepare_dispatch_transition(
        &mut snapshot,
        ResponseState::Applying,
        authorized_at_unix_ms,
        Some(initial_lease.lease_expires_at_unix_ms),
    )?;
    let normalized_response_plan = encode_normalized_dispatch_response_record(&snapshot)?;
    let authorization_body = ResponseDispatchAuthorizationBody {
        schema_version: RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        key: ResponseDispatchKey {
            tenant_id: normalized_response_plan.tenant_id.clone(),
            dispatch_id,
        },
        action_id: normalized_response_plan.action_id.clone(),
        plan_hash: snapshot.plan.plan_hash,
        response_body_hash: normalized_response_plan.body_hash,
        authorization_capability_hash,
        governed_intent_hash,
        policy_decision_hash,
        executor_authority_id,
        executor_authority_generation,
        approval,
        authorized_at_unix_ms,
    };
    let authorization_bytes =
        canonical_json_bytes(&authorization_body).map_err(|_| StateMachineError::Canonical)?;
    let authorization_hash = Digest32::new(*sha256(&authorization_bytes).as_bytes());
    let canonical_authorization =
        CanonicalBody::new(authorization_bytes).map_err(|_| StateMachineError::Canonical)?;
    snapshot.dispatch_authorization_hash = Some(authorization_hash);
    let response_plan = encode_response_record(&snapshot)?;
    Ok(ResponseDispatchCommitRequest {
        mode: commit_mode,
        authorization: ResponseDispatchAuthorization {
            body: authorization_body,
            canonical_body: canonical_authorization,
            body_hash: authorization_hash,
        },
        response_plan,
        initial_lease,
    })
}

fn prepare_dispatch_transition(
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

pub(crate) fn encode_normalized_dispatch_response_record(
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
    use chio_security_types::ports::TenantId;

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
