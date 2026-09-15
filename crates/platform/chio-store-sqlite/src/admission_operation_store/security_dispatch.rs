//! Dispatch authority must come from the original operation, never from a
//! lower-level capture route or historical native join/egress acknowledgements.
use super::*;

/// Generic capture cannot satisfy native participant custody. Only the private,
/// transaction-bound native capture port may advance that dispatch. Historical
/// joins, egress commitments and caller wait evidence never grant fresh capture.
pub(crate) fn verify_native_security_dispatch_tx(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    let original = retained_request::load_retained_request_tx(connection, operation)?;
    if original.is_some_and(|request| request.native_security_authority_binding().is_some()) {
        return Err(invariant("native security dispatch custody is unsupported"));
    }
    Ok(())
}

/// Resolve the physical hold's original owner before replay or mutation. A
/// supplied operation is not proof that its hold attachment belongs to it.
/// Budget-only references retain their standalone capture behavior, but a
/// missing committed admission is corruption, not a budget-only reference.
pub(crate) fn verify_dispatch_capture_owner_tx(
    transaction: &Transaction<'_>,
    hold_id: &str,
    expected: Option<&AdmissionOperationV1>,
) -> Result<(), AdmissionOperationStoreError> {
    verify_native_dispatch_capture_owner_tx(transaction, hold_id, expected, None)
}

pub(crate) fn verify_native_dispatch_capture_owner_tx(
    transaction: &Transaction<'_>,
    hold_id: &str,
    expected: Option<&AdmissionOperationV1>,
    native: Option<&VerifiedNativeCapture<'_>>,
) -> Result<(), AdmissionOperationStoreError> {
    // Budget-only references are opaque and need not be admission digests. Do
    // not allocate that untrusted text just to classify its durable membership.
    let (matches_expected, has_operation, has_history): (bool, bool, bool) = transaction
        .query_row(
            "SELECT COALESCE(hold.operation_id = ?2, 0),
                    EXISTS(SELECT 1 FROM admission_operations WHERE operation_id = hold.operation_id),
                    EXISTS(SELECT 1 FROM admission_operation_commits WHERE operation_id = hold.operation_id)
             FROM budget_authorization_holds AS hold WHERE hold.hold_id = ?1",
            params![hold_id, expected.map(|operation| operation.binding().operation_id().as_str())],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .unwrap_or((false, false, false));
    if expected.is_some() && !matches_expected {
        return Err(invariant(
            "capture hold belongs to another admission operation",
        ));
    }
    if !has_operation {
        return if expected.is_some() || has_history {
            Err(invariant(
                "capture hold lost its committed admission operation",
            ))
        } else {
            Ok(())
        };
    }
    let owner: Option<String> = transaction
        .query_row(
            "SELECT CASE WHEN length(CAST(operation.operation_id AS BLOB)) = 64 THEN operation.operation_id END
             FROM budget_authorization_holds AS hold
             JOIN admission_operations AS operation ON operation.operation_id = hold.operation_id
             WHERE hold.hold_id = ?1",
            [hold_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let owner = owner.ok_or_else(|| invariant("capture admission identity exceeds its bound"))?;
    let owner = AdmissionOperationId::from_persisted(owner)?;
    let stored = load_by_operation_id_tx(transaction, &owner)?
        .ok_or(AdmissionOperationStoreError::NotFound)?;
    if let Some(native) = native {
        native.verify_owner(transaction, &stored.operation)?;
    } else {
        verify_native_security_dispatch_tx(transaction, &stored.operation)?;
    }
    if expected.is_none()
        && stored
            .operation
            .binding()
            .participant_requirements()
            .execution_nonce
    {
        return Err(invariant(
            "nonce-backed holds require atomic admission capture",
        ));
    }
    Ok(())
}
