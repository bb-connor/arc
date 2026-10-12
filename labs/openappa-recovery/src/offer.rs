use crate::types::representation;
use crate::{
    resolved_request, DisclosureIntent, DisclosureOffer, HostSnapshot, OperationState,
    PlanningDecision, RecoveryError,
};
use chio_core_types::{canonical_json_bytes, SignedDeclassificationGrant};
use chio_flow::{
    prepare_pre_invocation, verify_declassification, DeclassificationVerificationRequest,
    FlowDenial, PreparedFlowAdmission,
};
use chio_security_types::ports::Digest32;
use sha2::{Digest, Sha256};

fn basis(intent: &DisclosureIntent, host: &HostSnapshot) -> Result<Digest32, RecoveryError> {
    let mut bytes = b"chio.recovery-lab.offer-basis.v1\0".to_vec();
    bytes.extend(canonical_json_bytes(&(intent, host)).map_err(representation)?);
    Ok(Digest32::new(Sha256::digest(bytes).into()))
}

fn bound_operation(intent: &DisclosureIntent, host: &HostSnapshot) -> Result<(), RecoveryError> {
    if host.operation_id != intent.operation_id {
        return Err(RecoveryError::OperationBindingMismatch);
    }
    Ok(())
}

fn available(intent: &DisclosureIntent, host: &HostSnapshot) -> Result<(), RecoveryError> {
    bound_operation(intent, host)?;
    match host.operation_state {
        OperationState::DeniedBeforeDispatch => return Err(RecoveryError::FrozenDeniedOperation),
        OperationState::Pending => return Err(RecoveryError::OutcomePending),
        OperationState::OutcomeUnknown => return Err(RecoveryError::UnknownOutcome),
        OperationState::Complete => return Err(RecoveryError::AlreadyCompleted),
        OperationState::BeforeAdmission => {}
    }
    if host.capability_revoked {
        return Err(RecoveryError::CapabilityRevoked);
    }
    if host.budget_remaining == 0 {
        return Err(RecoveryError::BudgetUnavailable);
    }
    Ok(())
}

pub fn plan(
    intent: &DisclosureIntent,
    host: &HostSnapshot,
) -> Result<PlanningDecision, RecoveryError> {
    bound_operation(intent, host)?;
    match host.operation_state {
        OperationState::DeniedBeforeDispatch => {
            return Ok(PlanningDecision::ContinuationRequired {
                denied_operation_id: intent.operation_id.clone(),
            })
        }
        OperationState::Pending => {
            return Ok(PlanningDecision::WaitForOutcome {
                operation_id: intent.operation_id.clone(),
            })
        }
        OperationState::OutcomeUnknown => {
            return Ok(PlanningDecision::Reconcile {
                operation_id: intent.operation_id.clone(),
            })
        }
        OperationState::Complete => {
            return Ok(PlanningDecision::RecoverOutcome {
                operation_id: intent.operation_id.clone(),
            })
        }
        OperationState::BeforeAdmission => {}
    }
    if let Err(error) = available(intent, host) {
        return Ok(PlanningDecision::Refused {
            reason: error.to_string(),
        });
    }
    match prepare_pre_invocation(resolved_request(intent, host, host.now_unix_ms)?) {
        Ok(_) => Ok(PlanningDecision::FlowCheckPassed),
        Err(reason) => {
            let can_request = matches!(
                reason,
                FlowDenial::PolicyFlowViolation | FlowDenial::ManifestFlowViolation
            ) && host.policy_purposes.contains(&intent.purpose)
                && host
                    .manifest
                    .declassification_purposes
                    .contains(&intent.purpose)
                && !host.trusted_authorities.is_empty();
            let offers = if can_request {
                vec![DisclosureOffer {
                    basis_digest: basis(intent, host)?,
                    expires_at_unix_ms: host
                        .now_unix_ms
                        .checked_add(30_000)
                        .ok_or_else(|| representation("clock overflow"))?,
                    action: "request_exact_disclosure_approval",
                }]
            } else {
                Vec::new()
            };
            Ok(PlanningDecision::Denied {
                reason: reason.to_string(),
                offers,
            })
        }
    }
}

/// Revalidate and prepare the real Chio flow. Production must commit this through
/// native admission custody. This function does not consume a grant or dispatch.
pub fn prepare_approved_offer(
    offer: &DisclosureOffer,
    intent: &DisclosureIntent,
    host: &HostSnapshot,
    grant: &SignedDeclassificationGrant,
    fresh_now_unix_ms: u64,
) -> Result<PreparedFlowAdmission, RecoveryError> {
    available(intent, host)?;
    if fresh_now_unix_ms < host.now_unix_ms {
        return Err(RecoveryError::ClockMovedBackward);
    }
    if fresh_now_unix_ms >= offer.expires_at_unix_ms {
        return Err(RecoveryError::OfferExpired);
    }
    if basis(intent, host)? != offer.basis_digest {
        return Err(RecoveryError::StaleOffer);
    }
    let mut resolved = resolved_request(intent, host, fresh_now_unix_ms)?;
    let verification = DeclassificationVerificationRequest {
        capability_id: intent.capability_id.clone(),
        tenant_id: host.flow.key.tenant_id.clone(),
        subject_id: host.flow.key.principal_id.clone(),
        agent_id: intent.agent_id.clone(),
        session_id: host.flow.key.session_id.clone(),
        source_label: resolved.observed_input_taint().principal_join,
        destination_id: intent.destination.clone(),
        tool_name: intent.tool_name.clone(),
        purpose: intent.purpose.clone(),
        policy_purposes: host.policy_purposes.clone(),
        manifest_purposes: host.manifest.declassification_purposes.clone(),
        canonical_request: intent.canonical_request.clone(),
        now_unix_ms: fresh_now_unix_ms,
        trusted_authorities: host.trusted_authorities.clone(),
    };
    resolved.declassification =
        Some(verify_declassification(grant, &verification).map_err(RecoveryError::Grant)?);
    prepare_pre_invocation(resolved).map_err(RecoveryError::Flow)
}
