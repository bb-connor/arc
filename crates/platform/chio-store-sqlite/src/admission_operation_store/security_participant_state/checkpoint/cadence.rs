use super::*;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;

// A completed native call appends five family events. Maintenance runs before
// the next invocation's fence, retaining at most four completed calls' suffix.
const EVENTS_BETWEEN_CHECKPOINTS: u64 = 20;

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

pub(super) fn due(events: i64) -> Result<bool, AdmissionOperationStoreError> {
    Ok(u64::try_from(events).map_err(invalid)? >= EVENTS_BETWEEN_CHECKPOINTS)
}
