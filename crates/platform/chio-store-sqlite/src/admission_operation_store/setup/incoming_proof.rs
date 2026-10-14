//! Caller signature validation is distinct from retained native custody errors.
use super::*;

pub(super) fn verify(
    result: chio_core::Result<bool>,
) -> Result<bool, AdmissionOperationStoreError> {
    match result {
        Ok(valid) => Ok(valid),
        Err(chio_core::Error::InvalidSignature(_)) => {
            Err(AdmissionOperationStoreError::RecoveryAuthorityDenied)
        }
        Err(error) => Err(refused(error)),
    }
}
