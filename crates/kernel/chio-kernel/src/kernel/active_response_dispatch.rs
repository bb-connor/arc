//! Kernel-owned construction of fresh or durably verified response dispatches.
//! Recovery mode is derived from a sealed execution request, never selected by
//! callers of the fresh preparation API. Quarantine owns the pure projections.

use chio_core::{canonical_json_bytes, sha256};
use chio_quarantine::state_machine::{
    encode_response_record,
    projection::{
        encode_normalized_dispatch_response_record, initial_response_snapshot,
        prepare_dispatch_transition,
    },
};
use chio_quarantine::{CanonicalFailure, StateMachineError};
use chio_security_types::ports::{
    CanonicalBody, Digest32, RecordId, ResponseDispatchApproval, ResponseDispatchAuthorization,
    ResponseDispatchAuthorizationBody, ResponseDispatchCommitMode, ResponseDispatchCommitRequest,
    ResponseDispatchKey, ResponseDispatchLease, RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
};
use chio_security_types::{
    DispatchRejection, FreshLiveAdmission, ResponseApprovalRequirement,
    ResponseExecutionDispatchBinding, ResponsePlan, ResponseState,
};

use super::{
    ActiveResponseExecutionApproval, ActiveResponseExecutionOrigin, ActiveResponseExecutionRequest,
    ActiveResponseExecutorError,
};

pub(super) fn prepare_kernel_dispatch(
    request: &ActiveResponseExecutionRequest,
    initial_lease: ResponseDispatchLease,
    now_unix_ms: u64,
) -> Result<ResponseDispatchCommitRequest, ActiveResponseExecutorError> {
    let reject =
        |reason: &str| ActiveResponseExecutorError::RejectedBeforeCommit(reason.to_owned());
    let plan = request.response_plan();
    let mode = match request.origin() {
        ActiveResponseExecutionOrigin::CommittedDispatch => {
            return Err(ActiveResponseExecutorError::OutcomeUnknown(
                "an existing dispatch must be recovered by exact readback".to_owned(),
            ))
        }
        ActiveResponseExecutionOrigin::Fresh => ResponseDispatchCommitMode::Fresh,
        ActiveResponseExecutionOrigin::CommittedAdmission
            if now_unix_ms >= plan.expires_at_unix_ms =>
        {
            ResponseDispatchCommitMode::GovernedCommittedExpiredResume
        }
        ActiveResponseExecutionOrigin::CommittedAdmission => {
            ResponseDispatchCommitMode::GovernedCommittedResume
        }
    };
    if now_unix_ms < plan.created_at_unix_ms
        || now_unix_ms < request.authorized_at_unix_ms()
        || (mode == ResponseDispatchCommitMode::Fresh && now_unix_ms >= plan.expires_at_unix_ms)
    {
        return Err(reject("active-response plan is not live"));
    }
    let digest = |value: &str| -> Result<Digest32, ActiveResponseExecutorError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(reject(
                "active-response digest is not canonical lowercase hex",
            ));
        }
        let hash = chio_core::hashing::Hash::from_hex(value)
            .map_err(|_| reject("active-response digest is invalid"))?;
        Ok(Digest32::new(*hash.as_bytes()))
    };
    let approval = match request.approval() {
        ActiveResponseExecutionApproval::Automatic => ResponseDispatchApproval::Automatic,
        ActiveResponseExecutionApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } => ResponseDispatchApproval::Governed {
            admission_operation_id: RecordId::new(admission_operation_id.clone())
                .map_err(|_| reject("governed admission operation id is invalid"))?,
            admission_operation_version: *admission_operation_version,
            approval_set_hash: digest(approval_set_hash)?,
        },
    };
    prepare_dispatch(DispatchPreparation {
        plan: plan.clone(),
        dispatch_id: request.dispatch_id().clone(),
        authorization_capability_hash: digest(request.authorization_capability_hash())?,
        governed_intent_hash: digest(request.governed_intent_hash())?,
        policy_decision_hash: digest(request.policy_decision_hash())?,
        executor_authority_id: RecordId::new(request.executor_authority_id())
            .map_err(|_| reject("active-response executor authority id is invalid"))?,
        executor_authority_generation: request.executor_authority_generation(),
        approval,
        authorized_at_unix_ms: request.authorized_at_unix_ms(),
        initial_lease,
        commit_mode: mode,
    })
    .map_err(|error| {
        ActiveResponseExecutorError::RejectedBeforeCommit(format!(
            "active-response dispatch preparation failed: {error}"
        ))
    })
}

/// Fresh preparation cannot accept an unvalidated plan or select recovery.
///
/// ```compile_fail
/// use chio_kernel::ResponseDispatchPreparationRequest;
/// use chio_security_types::ResponsePlan;
/// fn replace_plan(request: &mut ResponseDispatchPreparationRequest, plan: ResponsePlan) {
///     request.plan = plan;
/// }
/// ```
///
/// ```compile_fail
/// use chio_kernel::ResponseDispatchPreparationRequest;
/// use chio_security_types::ports::ResponseDispatchCommitMode;
/// fn select_recovery(request: &mut ResponseDispatchPreparationRequest) {
///     request.commit_mode = ResponseDispatchCommitMode::GovernedCommittedResume;
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseDispatchPreparationRequest {
    pub plan: FreshLiveAdmission,
    pub dispatch_id: RecordId,
    pub authorization_capability_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub executor_authority_id: RecordId,
    pub executor_authority_generation: u64,
    pub approval: ResponseDispatchApproval,
    pub authorized_at_unix_ms: u64,
    pub initial_lease: ResponseDispatchLease,
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
    prepare_dispatch(DispatchPreparation {
        plan: request.plan.plan().clone(),
        dispatch_id: request.dispatch_id,
        authorization_capability_hash: request.authorization_capability_hash,
        governed_intent_hash: request.governed_intent_hash,
        policy_decision_hash: request.policy_decision_hash,
        executor_authority_id: request.executor_authority_id,
        executor_authority_generation: request.executor_authority_generation,
        approval: request.approval,
        authorized_at_unix_ms: request.authorized_at_unix_ms,
        initial_lease: request.initial_lease,
        commit_mode: ResponseDispatchCommitMode::Fresh,
    })
}

struct DispatchPreparation {
    plan: ResponsePlan,
    dispatch_id: RecordId,
    authorization_capability_hash: Digest32,
    governed_intent_hash: Digest32,
    policy_decision_hash: Digest32,
    executor_authority_id: RecordId,
    executor_authority_generation: u64,
    approval: ResponseDispatchApproval,
    authorized_at_unix_ms: u64,
    initial_lease: ResponseDispatchLease,
    commit_mode: ResponseDispatchCommitMode,
}

fn prepare_dispatch(
    request: DispatchPreparation,
) -> Result<ResponseDispatchCommitRequest, StateMachineError> {
    let DispatchPreparation {
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
    let mut snapshot = initial_response_snapshot(plan)?;
    let plan = &snapshot.plan;
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
    snapshot.execution_dispatch = Some(execution_dispatch);
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
        canonical_json_bytes(&authorization_body).map_err(CanonicalFailure::Encoding)?;
    let authorization_hash = Digest32::new(*sha256(&authorization_bytes).as_bytes());
    let canonical_authorization =
        CanonicalBody::new(authorization_bytes).map_err(CanonicalFailure::Body)?;
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
