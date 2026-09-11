//! Check callback identity before accepting independently read physical history.
use super::*;
use crate::budget_store::{
    BudgetCommitMetadata, BudgetHoldMutationDecision, BudgetInvocationCaptureDecision,
    BudgetInvocationState, MAX_INVOCATION_QUOTAS_PER_ADMISSION,
};

pub(super) fn verify<'a>(
    capture: &'a crate::receipt_store::AdmissionBudgetCapture,
    expected: &AdmissionOperationV1,
    request: &BudgetCaptureInvocationRequest,
    authorization: &BudgetCommitMetadata,
) -> Result<&'a BudgetHoldMutationDecision, KernelError> {
    if capture.operation != *expected {
        return Err(invalid(
            "native capture returned a different operation successor",
        ));
    }
    // This affine authority is making its only attempt. A historical replay
    // cannot be substituted for a fresh capture acknowledgement.
    let BudgetInvocationCaptureDecision::Captured(mutation) = &capture.decision else {
        return Err(invalid(
            "native capture returned a historical replay acknowledgement",
        ));
    };
    let binding = mutation
        .admission_binding
        .as_ref()
        .ok_or_else(|| invalid("native capture acknowledgement lacks admission binding"))?;
    binding
        .validate()
        .map_err(|error| invalid(&error.to_string()))?;
    let previous = authorization
        .budget_commit_index
        .filter(|index| *index > 0)
        .ok_or_else(|| invalid("native capture lost its original authorization commit"))?;
    if mutation.hold_id.as_deref() != Some(request.hold_id.as_str())
        || binding.operation_id != expected.binding().operation_id().as_str()
        || mutation.invocation_state != BudgetInvocationState::Captured
        || mutation.realized_spend_units != 0
        || request.authority.is_none()
        || mutation.metadata.authority != request.authority
        || mutation.metadata.event_id.as_deref() != Some(request.event_id.as_str())
        || mutation
            .metadata
            .budget_commit_index
            .is_none_or(|index| index <= previous)
        || mutation.metadata.recorded_at_unix_seconds.is_none()
        || mutation.metadata.guarantee_level != authorization.guarantee_level
        || mutation.metadata.budget_profile != authorization.budget_profile
        || mutation.metadata.metering_profile != authorization.metering_profile
        || mutation.invocation_quota_usages.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION
    {
        return Err(invalid(
            "native capture acknowledgement differs from actual invocation custody",
        ));
    }
    let mut keys = std::collections::BTreeSet::new();
    for usage in &mutation.invocation_quota_usages {
        usage
            .validate()
            .map_err(|error| invalid(&error.to_string()))?;
        if !keys.insert(&usage.quota.key) {
            return Err(invalid("native capture acknowledgement duplicates a quota"));
        }
    }
    Ok(mutation)
}
