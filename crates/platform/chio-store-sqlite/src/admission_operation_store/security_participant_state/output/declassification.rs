//! Derive the use outcome from original egress and authenticated finalization.
use super::*;

pub(super) fn expected(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    now: u64,
) -> Result<
    Option<crate::security_state::NativeDeclassificationOutcome>,
    AdmissionOperationStoreError,
> {
    expected_initialized(connection, operation, now, None)
}

pub(super) fn expected_initialized(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    now: u64,
    initialized: Option<&SecurityParticipantStateInitialization>,
) -> Result<
    Option<crate::security_state::NativeDeclassificationOutcome>,
    AdmissionOperationStoreError,
> {
    let Some(egress) = super::super::egress::load_operation_inner(
        connection,
        operation.binding().operation_id(),
        "committed",
        initialized,
    )?
    else {
        return Ok(None);
    };
    let crate::security_state::NativeEgressCommand::CommitDeclassified { consumption, .. } =
        egress.command
    else {
        return Ok(None);
    };
    let crate::security_state::NativeEgressResult::Committed(commitment) = egress.result else {
        return Err(invalid(
            "declassification outcome lost original egress commitment",
        ));
    };
    crate::security_state::NativeDeclassificationOutcome::released(&consumption, &commitment, now)
        .map(Some)
        .map_err(invalid)
}
