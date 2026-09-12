//! Historical taint is an issuance prerequisite, never a nonce or dispatch permit.
use super::*;

pub(in crate::admission_operation_store) fn require_preflight_for_issuance(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    original: &chio_kernel::admission_operation::RetainedToolAdmissionRequestV1,
) -> Result<(), AdmissionOperationStoreError> {
    let Some(binding) = original.native_security_authority_binding() else {
        return Ok(());
    };
    let record = load_operation(connection, operation.binding().operation_id())?
        .ok_or_else(|| invalid("native nonce issuance requires original preflight taint"))?;
    let prepared = AdmissionOperationV1::from_persisted(record.operation.clone())?;
    if operation.state() != AdmissionOperationState::Prepared
        || operation.execution_nonce_preflight_digest().is_none()
        || prepared.binding() != operation.binding()
        || prepared.version() >= operation.version()
        || &record.authority != binding.security_authority_id()
        || record.initialization != binding.initialization_digest().as_str()
        || record.lease.fence.store_uuid != binding.store_uuid().as_str()
    {
        return Err(invalid(
            "native nonce issuance differs from its original preflight custody",
        ));
    }
    // The physical record is unique to this operation. Require its exact earlier
    // global commit, not merely a local row or an acknowledgement from a callback.
    // Issuance's caller independently owns the current lease, signature checks
    // and cleaned budget preflight in this same transaction.
    let references: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM authority_global_commits
         WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = ?3
           AND mutation_kind = ?4 AND projection_reference_digest = ?5
           AND store_uuid = ?6 AND store_lease_id = ?7 AND store_owner_epoch = ?8",
            params![
                PROJECTION,
                record.authority.as_str(),
                i64::try_from(record.sequence).map_err(invalid)?,
                MUTATION,
                record.digest()?,
                record.lease.fence.store_uuid,
                record.lease.fence.lease_id,
                i64::try_from(record.lease.fence.owner_epoch).map_err(invalid)?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if references != 1 {
        return Err(invalid(
            "native nonce issuance lacks exact anchored preflight custody",
        ));
    }
    Ok(())
}
