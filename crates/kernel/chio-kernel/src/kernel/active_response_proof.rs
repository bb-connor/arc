use chio_core::{canonical_json_bytes, sha256, Hash};
use chio_security_types::ports::{Digest32, RecordId, ResponseDispatchApproval};
use chio_security_types::{
    PlannedResponseEffect, ResponseExecutionDispatchBinding, ResponseMutationRecord,
    ResponseRollbackOutcome, ResponseSnapshot, ResponseState,
};

use super::{ActiveResponseExecutionEvidence, ActiveResponseExecutionRequest, KernelError};
use crate::kernel::active_response_executor::ActiveResponseExecutionApproval;
use chio_core::receipt::security::{
    ActiveDefenseEffectCommitment, ActiveDefenseEffectOutcome, ActiveDefensePolicyBinding,
    ActiveDefenseResponseBinding,
};

pub(super) fn active_response_execution_dispatch_binding(
    request: &ActiveResponseExecutionRequest,
    authorized_at_unix_ms: u64,
) -> Result<ResponseExecutionDispatchBinding, KernelError> {
    let approval = match request.approval() {
        ActiveResponseExecutionApproval::Automatic => ResponseDispatchApproval::Automatic,
        ActiveResponseExecutionApproval::Governed {
            admission_operation_id,
            admission_operation_version,
            approval_set_hash,
        } => ResponseDispatchApproval::Governed {
            admission_operation_id: RecordId::new(admission_operation_id.clone()).map_err(
                |_| active_response_internal("governed response operation ID is invalid"),
            )?,
            admission_operation_version: *admission_operation_version,
            approval_set_hash: active_response_digest_from_hex(approval_set_hash, "approval set")?,
        },
    };
    let binding = ResponseExecutionDispatchBinding {
        schema_version: chio_security_types::ports::RESPONSE_DISPATCH_AUTHORIZATION_SCHEMA_VERSION,
        tenant_id: request.response_plan().tenant_id.clone(),
        dispatch_id: request.dispatch_id().clone(),
        action_id: request.response_plan().action_id.clone(),
        plan_hash: request.response_plan().plan_hash,
        executor_authority_id: RecordId::new(request.executor_authority_id()).map_err(|_| {
            active_response_internal("active-response executor authority ID is invalid")
        })?,
        executor_authority_generation: request.executor_authority_generation(),
        authorization_capability_hash: active_response_digest_from_hex(
            request.authorization_capability_hash(),
            "authorization capability",
        )?,
        governed_intent_hash: active_response_digest_from_hex(
            request.governed_intent_hash(),
            "governed intent",
        )?,
        policy_decision_hash: active_response_digest_from_hex(
            request.policy_decision_hash(),
            "policy decision",
        )?,
        approval,
        authorized_at_unix_ms,
    };
    binding
        .validate_for_plan(request.response_plan())
        .map_err(|error| active_response_internal(error.to_string()))?;
    Ok(binding)
}

pub(super) fn verify_active_response_dispatch_authorization(
    request: &ActiveResponseExecutionRequest,
    evidence: &ActiveResponseExecutionEvidence,
    snapshot: &ResponseSnapshot,
    expected: &ResponseExecutionDispatchBinding,
) -> Result<Digest32, KernelError> {
    let authorization = evidence.dispatch_authorization();
    let canonical = canonical_json_bytes(&authorization.body).map_err(|error| {
        active_response_internal(format!(
            "active-response dispatch authorization canonicalization failed: {error}"
        ))
    })?;
    let body_hash = Digest32::new(*sha256(&canonical).as_bytes());
    let applying_body_hash = active_response_initial_applying_body_hash(snapshot)?;
    let body = &authorization.body;
    if canonical.as_slice() != authorization.canonical_body.as_bytes()
        || body_hash != authorization.body_hash
        || body_hash.is_zero()
        || snapshot.dispatch_authorization_hash != Some(body_hash)
        || body.schema_version != expected.schema_version
        || body.key.tenant_id != expected.tenant_id
        || body.key.dispatch_id != expected.dispatch_id
        || body.action_id != expected.action_id
        || body.plan_hash != expected.plan_hash
        || body.response_body_hash != applying_body_hash
        || body.authorization_capability_hash != expected.authorization_capability_hash
        || body.governed_intent_hash != expected.governed_intent_hash
        || body.policy_decision_hash != expected.policy_decision_hash
        || body.executor_authority_id != expected.executor_authority_id
        || body.executor_authority_generation != expected.executor_authority_generation
        || body.approval != expected.approval
        || body.authorized_at_unix_ms != expected.authorized_at_unix_ms
        || body.authorized_at_unix_ms < request.response_plan().created_at_unix_ms
        || body.authorized_at_unix_ms >= request.response_plan().expires_at_unix_ms
    {
        return Err(active_response_internal(
            "active-response dispatch authorization does not match its durable proof",
        ));
    }
    Ok(body_hash)
}

fn active_response_initial_applying_body_hash(
    snapshot: &ResponseSnapshot,
) -> Result<Digest32, KernelError> {
    let mut applying_transitions =
        snapshot
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
    let (index, transition) = applying_transitions.next().ok_or_else(|| {
        active_response_internal("active-response readback has no applying transition")
    })?;
    if applying_transitions.next().is_some()
        || transition.occurred_at_unix_ms
            != snapshot
                .execution_dispatch
                .as_ref()
                .map_or(0, |binding| binding.authorized_at_unix_ms)
    {
        return Err(active_response_internal(
            "active-response readback has an ambiguous applying transition",
        ));
    }
    let mut applying = snapshot.clone();
    applying.dispatch_authorization_hash = None;
    applying.state = ResponseState::Applying;
    applying.generation = transition.generation;
    applying.applying_lease_expires_at_unix_ms = transition.applying_lease_expires_at_unix_ms;
    applying.due_at_unix_ms = transition.applying_lease_expires_at_unix_ms;
    applying.operator_page_required = false;
    applying.mutations = chio_security_types::ResponseMutationLog::new(
        snapshot.mutations.as_slice()[..=index].to_vec(),
    )
    .map_err(|_| active_response_internal("active-response applying prefix is too large"))?;
    let canonical = canonical_json_bytes(&applying).map_err(|error| {
        active_response_internal(format!(
            "active-response applying prefix canonicalization failed: {error}"
        ))
    })?;
    Ok(Digest32::new(*sha256(&canonical).as_bytes()))
}

fn active_response_digest_from_hex(value: &str, label: &str) -> Result<Digest32, KernelError> {
    let digest = Hash::from_hex(value).map_err(|_| {
        active_response_internal(format!("active-response {label} hash is invalid"))
    })?;
    if digest.to_hex() != value || digest.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(active_response_internal(format!(
            "active-response {label} hash is zero or not canonical lowercase hexadecimal"
        )));
    }
    Ok(Digest32::new(*digest.as_bytes()))
}

pub(super) fn active_response_expected_effect_outcome(
    snapshot: &ResponseSnapshot,
    effect: &PlannedResponseEffect,
    lift: bool,
) -> Result<ActiveDefenseEffectOutcome, KernelError> {
    let mut outcome = ActiveDefenseEffectOutcome::Planned;
    for mutation in snapshot.mutations.as_slice() {
        outcome = match mutation {
            ResponseMutationRecord::EffectRequested(record)
                if record.effect_id == effect.effect_id =>
            {
                ActiveDefenseEffectOutcome::Requested
            }
            ResponseMutationRecord::EffectApplied(record)
                if record.effect_id == effect.effect_id =>
            {
                ActiveDefenseEffectOutcome::Applied {
                    resulting_version_hash: record.resulting_version_hash,
                }
            }
            ResponseMutationRecord::EffectFailed(record)
                if record.effect_id == effect.effect_id =>
            {
                ActiveDefenseEffectOutcome::ApplyFailed {
                    error_code: record.error_code.clone(),
                }
            }
            ResponseMutationRecord::Rollback(record) if record.effect_id == effect.effect_id => {
                match &record.outcome {
                    ResponseRollbackOutcome::Requested => {
                        ActiveDefenseEffectOutcome::RollbackRequested
                    }
                    ResponseRollbackOutcome::Restored {
                        resulting_version_hash,
                    } => ActiveDefenseEffectOutcome::Restored {
                        resulting_version_hash: *resulting_version_hash,
                    },
                    ResponseRollbackOutcome::Failed { error_code } => {
                        ActiveDefenseEffectOutcome::RollbackFailed {
                            error_code: error_code.clone(),
                        }
                    }
                }
            }
            _ => outcome,
        };
    }
    if lift
        && !effect.kind.is_reversible()
        && matches!(&outcome, ActiveDefenseEffectOutcome::Applied { .. })
    {
        outcome = ActiveDefenseEffectOutcome::NoRollbackRequired;
    }
    Ok(outcome)
}

pub(super) fn active_response_response_binding(
    plan: &chio_security_types::ResponsePlan,
) -> ActiveDefenseResponseBinding {
    ActiveDefenseResponseBinding {
        policy: ActiveDefensePolicyBinding {
            policy_version: plan.policy_version.clone(),
            policy_hash: plan.policy_hash,
        },
        plan_hash: plan.plan_hash,
        action_id: plan.action_id.clone(),
        trigger_finding_id: plan.trigger_finding_id.clone(),
        trigger_finding_hash: plan.trigger_finding_hash,
        trigger_finding_receipt_id: plan.trigger_finding_receipt_id.clone(),
        affected_set_hash: plan.affected_set_hash,
        plan_expires_at_unix_ms: plan.expires_at_unix_ms,
    }
}

pub(super) fn active_response_effect_commitment(
    effect: &PlannedResponseEffect,
) -> ActiveDefenseEffectCommitment {
    ActiveDefenseEffectCommitment {
        effect_id: effect.effect_id.clone(),
        ordinal: effect.ordinal,
        kind: effect.kind,
        target: effect.target.clone(),
        contribution_hash: effect.contribution_hash,
        observed_base_version_hash: effect.observed_base_version_hash,
    }
}

fn active_response_internal(reason: impl Into<String>) -> KernelError {
    KernelError::Internal(format!(
        "active-response admission failed: {}",
        reason.into()
    ))
}
