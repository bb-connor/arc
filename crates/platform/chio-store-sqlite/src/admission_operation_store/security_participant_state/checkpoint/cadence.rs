use super::*;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;

/// A complete native egress call appends five anchored family events: nonce
/// preflight, input join, egress acquisition and commitment, and output join.
/// This is the maintenance trigger, not a bound on concurrent history.
const MAX_EVENTS_PER_CALL: u64 = 5;

pub(super) enum Selection<'a> {
    Initialization(&'a SecurityParticipantStateInitialization),
    Binding(&'a NativeSecurityAuthorityBindingV1),
}

impl Selection<'_> {
    pub(super) fn authority(&self) -> &str {
        match self {
            Self::Initialization(initialized) => initialized.authority.as_str(),
            Self::Binding(binding) => binding.security_authority_id().as_str(),
        }
    }

    pub(super) fn matches(
        &self,
        actual: &SecurityParticipantStateInitialization,
    ) -> Result<bool, AdmissionOperationStoreError> {
        match self {
            Self::Initialization(initialized) => Ok(*initialized == actual),
            Self::Binding(binding) => Ok(**binding == actual.admission_binding()?),
        }
    }
}

/// Maintenance runs before each invocation's fence and seals a suffix of at
/// least five events. In sequential use, fewer than five earlier events remain
/// at that observation, before the current call adds its events. This does not
/// bound events appended by concurrent invocations after maintenance.
pub(super) fn due(events: i64) -> Result<bool, AdmissionOperationStoreError> {
    Ok(u64::try_from(events).map_err(invalid)? >= MAX_EVENTS_PER_CALL)
}
