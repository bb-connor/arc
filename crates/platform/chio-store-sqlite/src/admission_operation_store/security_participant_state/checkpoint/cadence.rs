use super::*;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;

/// Most anchored family events one native call appends: nonce preflight,
/// input join, egress acquisition and commitment, and output join.
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

/// Maintenance runs before each invocation's fence. Sealing once the suffix
/// holds a full call keeps every verification inside that fence replaying at
/// most one call's events, whatever the session length.
pub(super) fn due(events: i64) -> Result<bool, AdmissionOperationStoreError> {
    Ok(u64::try_from(events).map_err(invalid)? >= MAX_EVENTS_PER_CALL)
}
