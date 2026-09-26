use crate::executor::{DurableActiveResponseOutcome, ExecutorError};
use crate::state_machine::encode_response_record;
use chio_core_types::{canonical_json_bytes, sha256};
use chio_security_types::ports::{Digest32, ResponseDispatchAuthorization, ResponsePlanRecord};
use chio_security_types::{
    ResponseExecutionDispatchBinding, ResponseMutationLog, ResponseMutationRecord,
    ResponseSnapshot, ResponseState,
};

pub(super) fn durable_execution_proof_snapshot(
    current: &ResponseSnapshot,
) -> Result<
    (
        ResponseSnapshot,
        ResponsePlanRecord,
        DurableActiveResponseOutcome,
    ),
    ExecutorError,
> {
    let mut activation = current
        .mutations
        .as_slice()
        .iter()
        .enumerate()
        .filter(|(_, mutation)| {
            matches!(
                mutation,
                ResponseMutationRecord::Transition(transition)
                    if transition.to_state == ResponseState::Active
            )
        });
    if let Some((activation_index, ResponseMutationRecord::Transition(transition))) =
        activation.next()
    {
        if activation.next().is_some() {
            return Err(ExecutorError::InvalidActiveEvidence);
        }
        let mut snapshot = current.clone();
        snapshot.state = ResponseState::Active;
        snapshot.generation = transition.generation;
        snapshot.applying_lease_expires_at_unix_ms = None;
        snapshot.due_at_unix_ms = Some(snapshot.plan.expires_at_unix_ms);
        snapshot.operator_page_required = false;
        snapshot.mutations =
            ResponseMutationLog::new(current.mutations.as_slice()[..=activation_index].to_vec())
                .map_err(|_| ExecutorError::InvalidActiveEvidence)?;
        let record = encode_response_record(&snapshot)?;
        return Ok((snapshot, record, DurableActiveResponseOutcome::Activated));
    }

    let any_effect_applied = current
        .mutations
        .as_slice()
        .iter()
        .any(|mutation| matches!(mutation, ResponseMutationRecord::EffectApplied(_)));
    let outcome = match current.state {
        ResponseState::Failed if !any_effect_applied => {
            DurableActiveResponseOutcome::FailedBeforeAnyEffect
        }
        ResponseState::Lifted if any_effect_applied => {
            DurableActiveResponseOutcome::RolledBackAfterPartial
        }
        _ => return Err(ExecutorError::InvalidActiveEvidence),
    };
    let snapshot = current.clone();
    let record = encode_response_record(&snapshot)?;
    Ok((snapshot, record, outcome))
}

pub(super) fn validate_dispatch_authorization(
    current: &ResponseSnapshot,
    authorization: &ResponseDispatchAuthorization,
) -> Result<(), ExecutorError> {
    let canonical = canonical_json_bytes(&authorization.body)
        .map_err(|_| ExecutorError::InvalidActiveEvidence)?;
    let canonical_hash = Digest32::new(*sha256(&canonical).as_bytes());
    if canonical.as_slice() != authorization.canonical_body.as_bytes()
        || canonical_hash != authorization.body_hash
        || authorization
            .body_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || current.dispatch_authorization_hash != Some(authorization.body_hash)
    {
        return Err(ExecutorError::InvalidActiveEvidence);
    }

    let durable_binding = current
        .execution_dispatch
        .clone()
        .ok_or(ExecutorError::InvalidActiveEvidence)?;
    durable_binding
        .validate_for_plan(&current.plan)
        .map_err(|_| ExecutorError::InvalidActiveEvidence)?;
    let expected_binding = ResponseExecutionDispatchBinding {
        schema_version: authorization.body.schema_version,
        tenant_id: authorization.body.key.tenant_id.clone(),
        dispatch_id: authorization.body.key.dispatch_id.clone(),
        action_id: authorization.body.action_id.clone(),
        plan_hash: authorization.body.plan_hash,
        executor_authority_id: authorization.body.executor_authority_id.clone(),
        executor_authority_generation: authorization.body.executor_authority_generation,
        authorization_capability_hash: authorization.body.authorization_capability_hash,
        governed_intent_hash: authorization.body.governed_intent_hash,
        policy_decision_hash: authorization.body.policy_decision_hash,
        approval: authorization.body.approval.clone(),
        authorized_at_unix_ms: authorization.body.authorized_at_unix_ms,
    };
    expected_binding
        .validate_for_plan(&current.plan)
        .map_err(|_| ExecutorError::InvalidActiveEvidence)?;
    if durable_binding != expected_binding {
        return Err(ExecutorError::InvalidActiveEvidence);
    }

    let applying_record = applying_response_record(current)?;
    if authorization.body.response_body_hash != applying_record.body_hash
        || authorization
            .body
            .response_body_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(ExecutorError::InvalidActiveEvidence);
    }
    Ok(())
}

fn applying_response_record(
    current: &ResponseSnapshot,
) -> Result<ResponsePlanRecord, ExecutorError> {
    let mut applying =
        current
            .mutations
            .as_slice()
            .iter()
            .enumerate()
            .filter_map(|(index, mutation)| match mutation {
                ResponseMutationRecord::Transition(transition)
                    if transition.to_state == ResponseState::Applying
                        && transition.from_state != ResponseState::Applying =>
                {
                    Some((index, transition))
                }
                _ => None,
            });
    let (applying_index, transition) = applying
        .next()
        .ok_or(ExecutorError::InvalidActiveEvidence)?;
    if applying.next().is_some() {
        return Err(ExecutorError::InvalidActiveEvidence);
    }
    let applying_lease_expires_at_unix_ms = transition
        .applying_lease_expires_at_unix_ms
        .ok_or(ExecutorError::InvalidActiveEvidence)?;
    let mut snapshot = current.clone();
    snapshot.dispatch_authorization_hash = None;
    snapshot.state = ResponseState::Applying;
    snapshot.generation = transition.generation;
    snapshot.applying_lease_expires_at_unix_ms = Some(applying_lease_expires_at_unix_ms);
    snapshot.due_at_unix_ms = Some(applying_lease_expires_at_unix_ms);
    snapshot.operator_page_required = false;
    snapshot.mutations =
        ResponseMutationLog::new(current.mutations.as_slice()[..=applying_index].to_vec())
            .map_err(|_| ExecutorError::InvalidActiveEvidence)?;
    crate::state_machine::encode_normalized_dispatch_response_record(&snapshot)
        .map_err(ExecutorError::StateMachine)
}

#[cfg(test)]
mod tests {
    use super::validate_dispatch_authorization;
    use crate::state_machine::{
        build_response_plan, decode_response_record, prepare_response_dispatch,
        ResponseDispatchPreparationRequest,
    };
    use chio_core_types::{canonical_json_bytes, sha256};
    use chio_security_types::ports::{
        ActionId, CanonicalBody, Digest32, LeaseOwnerId, OpaqueReceiptRef, RecordId,
        ResponseDispatchApproval, ResponseDispatchAuthorization, ResponseDispatchCommitRequest,
        ResponseDispatchLease, SessionId, TenantId,
    };
    use chio_security_types::{
        OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
        ResponseEffectSpec, ResponsePlanInput, ResponseTarget,
    };

    fn digest(value: u8) -> Digest32 {
        Digest32::new([value; 32])
    }

    fn record_id(value: &str) -> RecordId {
        RecordId::new(value).unwrap_or_else(|error| panic!("invalid record id: {error}"))
    }

    fn prepared_dispatch() -> ResponseDispatchCommitRequest {
        let canonical_contribution = CanonicalBody::new(b"{\"posture_rank\":2}".to_vec())
            .unwrap_or_else(|error| panic!("invalid contribution: {error}"));
        let contribution_hash =
            Digest32::new(*sha256(canonical_contribution.as_bytes()).as_bytes());
        let plan = build_response_plan(ResponsePlanInput {
            action_id: ActionId::new("action-proof")
                .unwrap_or_else(|error| panic!("invalid action id: {error}")),
            trigger_finding_id: record_id("finding-proof"),
            trigger_finding_hash: digest(21),
            trigger_finding_receipt_id: OpaqueReceiptRef::new("finding-proof-receipt")
                .unwrap_or_else(|error| panic!("invalid finding receipt: {error}")),
            tenant_id: TenantId::new("tenant-proof")
                .unwrap_or_else(|error| panic!("invalid tenant id: {error}")),
            policy_version: record_id("policy-proof"),
            policy_hash: digest(22),
            affected_ids: vec![record_id("affected-proof")],
            effects: vec![ResponseEffectSpec {
                kind: ResponseEffectKind::ThrottleSession,
                target: ResponseTarget::Session {
                    session_id: SessionId::new("session-proof")
                        .unwrap_or_else(|error| panic!("invalid session id: {error}")),
                },
                canonical_contribution,
                contribution_hash,
                observed_base_version_hash: digest(23),
            }],
            ttl_ms: 10_000,
            created_at_unix_ms: 40_000,
            operator_capability: OperatorCapabilityBinding {
                capability_id: record_id("capability-proof"),
                capability_digest: digest(24),
                expires_at_unix_ms: 60_000,
                executor_subject: record_id("executor-subject-proof"),
            },
            approval_requirement: ResponseApprovalRequirement::Automatic,
            submitter: record_id("submitter-proof"),
            reason_hash: digest(25),
        })
        .unwrap_or_else(|error| panic!("response plan build failed: {error}"));
        prepare_response_dispatch(ResponseDispatchPreparationRequest {
            plan,
            dispatch_id: record_id("active-response-dispatch-proof"),
            authorization_capability_hash: digest(24),
            governed_intent_hash: digest(26),
            policy_decision_hash: digest(27),
            executor_authority_id: record_id("executor-authority-proof"),
            executor_authority_generation: 4,
            approval: ResponseDispatchApproval::Automatic,
            authorized_at_unix_ms: 41_000,
            initial_lease: ResponseDispatchLease {
                lease_owner_id: LeaseOwnerId::new("response-worker-proof")
                    .unwrap_or_else(|error| panic!("invalid lease owner: {error}")),
                lease_expires_at_unix_ms: 42_000,
            },
            commit_mode: chio_security_types::ports::ResponseDispatchCommitMode::Fresh,
        })
        .unwrap_or_else(|error| panic!("dispatch preparation failed: {error}"))
    }

    fn recanonicalize(authorization: &mut ResponseDispatchAuthorization) {
        let bytes = canonical_json_bytes(&authorization.body)
            .unwrap_or_else(|error| panic!("authorization canonicalization failed: {error}"));
        authorization.body_hash = Digest32::new(*sha256(&bytes).as_bytes());
        authorization.canonical_body = CanonicalBody::new(bytes)
            .unwrap_or_else(|error| panic!("authorization body is invalid: {error}"));
    }

    #[test]
    fn dispatch_bound_proof_rejects_rehashed_authorization_mismatches() {
        let prepared = prepared_dispatch();
        let snapshot = decode_response_record(&prepared.response_plan)
            .unwrap_or_else(|error| panic!("prepared response is invalid: {error}"));
        assert!(validate_dispatch_authorization(&snapshot, &prepared.authorization).is_ok());

        let mut mismatched_binding = prepared.authorization.clone();
        mismatched_binding.body.policy_decision_hash = digest(90);
        recanonicalize(&mut mismatched_binding);
        assert!(validate_dispatch_authorization(&snapshot, &mismatched_binding).is_err());

        let mut mismatched_preimage = prepared.authorization.clone();
        mismatched_preimage.body.response_body_hash = digest(91);
        recanonicalize(&mut mismatched_preimage);
        assert!(validate_dispatch_authorization(&snapshot, &mismatched_preimage).is_err());

        let mut arbitrary_hash = prepared.authorization.clone();
        arbitrary_hash.body_hash = digest(92);
        assert!(validate_dispatch_authorization(&snapshot, &arbitrary_hash).is_err());

        let mut mismatched_snapshot = snapshot;
        mismatched_snapshot.dispatch_authorization_hash = Some(digest(93));
        assert!(
            validate_dispatch_authorization(&mismatched_snapshot, &prepared.authorization).is_err()
        );
    }
}
