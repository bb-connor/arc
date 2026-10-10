//! Private caller context joins the nonce's existing physical commit chain.

use super::*;
use chio_kernel::admission_operation::AdmissionCallerDispatchContextV1;

pub(super) fn load(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<Option<AdmissionCallerDispatchContextV1>, AdmissionOperationStoreError> {
    // Bound the allocation before reading a potentially corrupt physical BLOB.
    let bytes: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(context_json) BETWEEN 1 AND 1048576
                         THEN context_json END
             FROM admission_operation_caller_contexts WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(bytes) = bytes else {
        if operation.caller_dispatch_context_digest().is_some() {
            return Err(invariant(
                "caller operation lost its physical dispatch context",
            ));
        }
        return Ok(None);
    };
    if operation.caller_dispatch_context_digest().is_none() {
        return Err(invariant(
            "caller dispatch context has no committed operation owner",
        ));
    }
    let bytes = bytes.ok_or_else(|| invariant("caller context exceeds its artifact bound"))?;
    let original = retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invariant("caller dispatch context lost its original request"))?;
    AdmissionCallerDispatchContextV1::from_canonical_bytes(&bytes, operation, &original).map(Some)
}

pub(super) fn verify_ownership(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM admission_operation_caller_contexts AS context
                WHERE NOT EXISTS (
                    SELECT 1 FROM admission_operations AS operation
                    WHERE operation.operation_id = context.operation_id
                )
            )",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "caller context has no owning admission operation",
        ));
    }
    Ok(())
}

pub(super) fn insert(
    transaction: &Transaction<'_>,
    operation: &AdmissionOperationV1,
    context: &AdmissionCallerDispatchContextV1,
) -> Result<(), AdmissionOperationStoreError> {
    transaction.execute(
        "INSERT INTO admission_operation_caller_contexts (operation_id, context_json) VALUES (?1, ?2)",
        params![operation.binding().operation_id().as_str(), context.canonical_bytes()],
    ).map_err(sqlite_error)?;
    load(transaction, operation)?
        .ok_or_else(|| invariant("caller dispatch context insertion is absent"))?;
    Ok(())
}
