//! Read the physical finalization artifacts inside the native writer transaction.
use super::*;
use chio_kernel::admission_operation::NativeSecurityOutputJoinRequestV1;
use chio_kernel::tool_outcome::PersistedRawInvocationOutcomeV1;

pub(crate) fn verify_native_output_artifacts(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    intent: &NativeSecurityOutputJoinRequestV1,
    require_payload: bool,
) -> Result<Option<PersistedRawInvocationOutcomeV1>, AdmissionOperationStoreError> {
    let verify = || -> Result<_, ToolOutcomeStoreError> {
        let id = operation.binding().operation_id().as_str();
        let projection = projection::load_verified_projection(connection, id)?;
        let evaluation = projection
            .evaluation
            .as_ref()
            .ok_or_else(|| invariant("native output has no physical evaluation"))?;
        intent
            .validate_artifacts(operation, &projection.outcome, evaluation)
            .map_err(admission_error)?;
        if !projection.has_resolved_output {
            return Err(invariant("native output has no physical signing preimage"));
        }
        match projection.raw {
            Some(raw) => {
                if raw.requires_security_release() != Ok(true) {
                    return Err(invariant(
                        "native output lacks its frozen release requirement",
                    ));
                }
                Ok(Some(raw.to_persisted()))
            }
            None if !require_payload => Ok(None),
            _ => Err(invariant("native output lost its original return payload")),
        }
    };
    verify().map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))
}
