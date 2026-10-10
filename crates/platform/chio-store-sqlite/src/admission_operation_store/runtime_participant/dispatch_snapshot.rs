//! Exact physical claim evidence for the native dispatch ledger.
use super::*;

pub(in crate::admission_operation_store) fn dispatch_snapshot(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    grant_index: usize,
) -> Result<Option<RuntimeParticipantClaimHistoryV1>, AdmissionOperationStoreError> {
    verify_runtime_budget_selection_tx(
        connection,
        operation,
        grant_index,
        RuntimeParticipantPhase::Dispatch,
    )?;
    records::load(connection, operation)?
        .into_iter()
        .find(|record| !record.released())
        .map(|record| {
            Ok(RuntimeParticipantClaimHistoryV1 {
                reference: record.reference()?,
                intent: record.intent().clone(),
                disposition: RuntimeParticipantDisposition::ReservedBeforeDispatch,
            })
        })
        .transpose()
}

/// Verify historical reference and intent, not present-day liveness. A later
/// release must not rewrite the evidence of an earlier prepared dispatch.
pub(in crate::admission_operation_store) fn verify_dispatch_snapshot(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    expected: &Option<RuntimeParticipantClaimHistoryV1>,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if expected.disposition != RuntimeParticipantDisposition::ReservedBeforeDispatch {
        return Err(invariant(
            "native dispatch ledger has an invalid claim disposition",
        ));
    }
    for record in records::load(connection, operation)? {
        if record.reference()? == expected.reference && record.intent() == &expected.intent {
            return Ok(());
        }
    }
    Err(invariant(
        "native dispatch ledger lost its exact claim history",
    ))
}
