//! Authenticate a signed private terminal against its exact original capture.
use super::*;
use chio_kernel::tool_outcome::{
    PrivateRecoverySettlementReceiptV1, RawInvocationOutcomeV1, ResolvedToolOutcomeV1,
};

pub(in crate::admission_operation_store) fn verified_private_settlement(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
) -> Result<bool, AdmissionOperationStoreError> {
    let stored = load_by_operation_id_tx(tx, operation.binding().operation_id())?
        .ok_or_else(|| invariant("private settlement terminal operation absent"))?;
    if stored.operation != *operation
        || !matches!(
            operation.state(),
            AdmissionOperationState::Completed | AdmissionOperationState::DeniedAfterDelivery
        )
    {
        return Err(invariant(
            "private settlement requires its exact completed original",
        ));
    }
    super::super::super::projection::verify_stored_terminal_projection(tx, &stored)?;
    let bytes: Vec<u8> = tx
        .query_row(
            "SELECT record_json FROM admission_operation_terminal_records
         WHERE operation_id=?1 AND record_kind='receipt'",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let receipt: chio_core::receipt::body::ChioReceipt = decode(&bytes)?;
    let Some(settlement) = PrivateRecoverySettlementReceiptV1::from_receipt(&receipt)
        .map_err(|_| invariant("private settlement receipt metadata refused"))?
    else {
        return Ok(false);
    };
    let delivered_digest_denial = operation.state() == AdmissionOperationState::DeniedAfterDelivery;
    if delivered_digest_denial {
        let bytes: Vec<u8> = tx
            .query_row(
                "SELECT projection_json FROM admission_operation_terminal_projections WHERE operation_id=?1",
                [operation.binding().operation_id().as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        // The projection above was independently authenticated against its
        // original operation, signed receipt and exact participant records.
        let projection: serde_json::Value = decode(&bytes)?;
        let reason = projection
            .get("reason")
            .cloned()
            .ok_or_else(|| invariant("private delivery denial reason absent"))?;
        let reason: chio_kernel::admission_operation::DeliveryDenialReason =
            serde_json::from_value(reason)
                .map_err(|_| invariant("private delivery denial reason refused"))?;
        if reason != chio_kernel::admission_operation::DeliveryDenialReason::DigestMismatch {
            return Ok(false);
        }
    }
    let original = super::verify_physical_capture(tx, record, operation)?;
    let profile = match super::super::deployment_history::lookup(tx, record, fence)? {
        RecoveryCapturedDeploymentV1::Verified(profile) => profile,
        _ => {
            return Err(invariant(
                "private settlement captured verifier unavailable",
            ))
        }
    };
    super::verify_captured_roots(tx, record, operation, &original, &profile)?;
    let outcome = crate::tool_outcome_store::load_outcome_connection(
        tx,
        operation.binding().operation_id().as_str(),
    )
    .map_err(|_| invariant("private settlement original outcome refused"))?
    .ok_or_else(|| invariant("private settlement original outcome absent"))?;
    if !matches!(
        outcome.disposition(),
        ResolvedToolOutcomeV1::Resolved { .. }
    ) {
        return Err(invariant(
            "private settlement lacks its resolved original evaluation",
        ));
    }
    crate::tool_outcome_store::require_terminal_release(tx, operation)?;
    // This data-only lookup avoids quota recursion while terminal custody is
    // itself authenticating a quota pointer. It verifies the actual hold's
    // immutable source event and original workflow anchor independently.
    let hold = super::super::historical_holds::retained_hold_data(tx, record)?;
    settlement
        .validate_receipt(
            &receipt,
            operation,
            &outcome,
            record.deployment_digest,
            fence,
            hold.as_ref(),
        )
        .map_err(|_| invariant("private settlement signed original custody changed"))?;
    let raw: Option<Vec<u8>> = tx
        .query_row(
            "SELECT canonical_bytes FROM tool_outcome_blobs WHERE digest=?1",
            [outcome.raw_output_digest().as_str()],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if let Some(bytes) = raw {
        let raw = RawInvocationOutcomeV1::from_canonical_bytes(&bytes)
            .map_err(|_| invariant("private settlement original raw return refused"))?;
        let blob = raw
            .canonical_blob()
            .map_err(|_| invariant("private settlement raw return encoding refused"))?;
        outcome
            .validate_canonical_blob(operation, &blob)
            .map_err(|_| invariant("private settlement raw return binding changed"))?;
        if delivered_digest_denial {
            settlement.validate_completed_raw_return(&raw)
        } else {
            settlement.validate_raw(&raw)
        }
        .map_err(|_| {
            invariant("private settlement frozen signing identity or return shape changed")
        })?;
    }
    Ok(true)
}
