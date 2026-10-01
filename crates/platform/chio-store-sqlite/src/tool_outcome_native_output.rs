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
        let outcome = load_outcome_connection(connection, id)?
            .ok_or_else(|| invariant("native output has no physical outcome"))?;
        let evaluation = load_evaluation_connection(connection, id)?
            .ok_or_else(|| invariant("native output has no physical evaluation"))?;
        intent
            .validate_artifacts(operation, &outcome, &evaluation)
            .map_err(admission_error)?;
        verify_outcome_projection(connection, id)?;
        if load_resolved_blob_connection(connection, &outcome)?.is_none() {
            return Err(invariant("native output has no physical signing preimage"));
        }
        match load_blob_state_connection(connection, outcome.raw_output_digest())? {
            Some(StoredInvocationBlob::Present(blob)) => {
                outcome
                    .validate_canonical_blob(operation, &blob)
                    .map_err(|error| invariant(error.to_string()))?;
                let raw = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())
                    .map_err(|error| invariant(error.to_string()))?;
                if raw.requires_security_release() != Ok(true) {
                    return Err(invariant(
                        "native output lacks its frozen release requirement",
                    ));
                }
                Ok(Some(raw.to_persisted()))
            }
            Some(StoredInvocationBlob::Compacted) if !require_payload => Ok(None),
            _ => Err(invariant("native output lost its original return payload")),
        }
    };
    verify().map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))
}
