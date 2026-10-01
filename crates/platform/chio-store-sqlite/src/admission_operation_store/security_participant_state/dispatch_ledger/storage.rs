//! Bounded physical records and a bijection with the authority commit chain.
use super::*;

pub(super) fn current_operation(
    connection: &Connection,
    historical: &AdmissionOperationV1,
) -> Result<AdmissionOperationV1, AdmissionOperationStoreError> {
    let bytes: Option<Vec<u8>> = connection.query_row(
        "SELECT CASE WHEN typeof(operation_json) = 'blob' AND length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END FROM admission_operations WHERE operation_id = ?1",
        [historical.binding().operation_id().as_str()], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let bytes = bytes.ok_or_else(|| invalid("native dispatch ledger owner exceeds its bound"))?;
    let operation =
        AdmissionOperationV1::from_persisted(serde_json::from_slice(&bytes).map_err(invalid)?)?;
    if encode_operation(&operation)? != bytes
        || operation.binding() != historical.binding()
        || operation.version() < historical.version()
        || operation.runtime_participant_ledger_digest()
            != historical.runtime_participant_ledger_digest()
        || operation.governed_approval_ledger_digest()
            != historical.governed_approval_ledger_digest()
        || operation.dpop_replay_ledger_digest() != historical.dpop_replay_ledger_digest()
    {
        return Err(invalid(
            "native dispatch ledger lost its original operation owner",
        ));
    }
    Ok(operation)
}

pub(super) fn load(
    connection: &Connection,
    operation: &str,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let row: Option<(Option<Vec<u8>>, Option<String>)> = connection.query_row(
        "SELECT CASE WHEN typeof(canonical_record) = 'blob' AND length(canonical_record) BETWEEN 1 AND 1048576 THEN canonical_record END,
                CASE WHEN length(CAST(record_digest AS BLOB)) = 64 THEN record_digest END
         FROM admission_operation_native_dispatch_ledger WHERE operation_id = ?1",
        [operation], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional().map_err(sqlite_error)?;
    let Some((bytes, digest)) = row else {
        return Ok(None);
    };
    let bytes =
        bytes.ok_or_else(|| invalid("native dispatch ledger record exceeds its physical bound"))?;
    let record: Record = serde_json::from_slice(&bytes).map_err(invalid)?;
    let decoded = AdmissionOperationV1::from_persisted(record.operation.clone())?;
    if record.bytes()? != bytes
        || digest.as_deref() != Some(record.digest()?.as_str())
        || decoded.binding().operation_id().as_str() != operation
    {
        return Err(invalid("native dispatch ledger physical binding differs"));
    }
    Ok(Some(record))
}

pub(super) fn verify_coverage(connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let has_global: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits')", [], |row| row.get(0)).map_err(sqlite_error)?;
    if !has_global {
        let occupied: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_operation_native_dispatch_ledger)",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        return if occupied {
            Err(invalid(
                "native dispatch ledger has no global authority chain",
            ))
        } else {
            Ok(())
        };
    }
    let invalid: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_native_dispatch_ledger AS record
            WHERE NOT EXISTS(SELECT 1 FROM admission_operations AS operation WHERE operation.operation_id = record.operation_id)
               OR (SELECT COUNT(*) FROM authority_global_commits AS committed
                   WHERE committed.projection_kind = 'native_dispatch_ledger' AND committed.projection_key = record.operation_id
                     AND committed.projection_sequence = 1 AND committed.mutation_kind = 'retain_native_dispatch_ledger'
                     AND committed.projection_reference_digest = record.record_digest) != 1)
         OR EXISTS(SELECT 1 FROM authority_global_commits AS committed
            WHERE committed.projection_kind = 'native_dispatch_ledger' AND
                (committed.projection_sequence != 1 OR committed.mutation_kind != 'retain_native_dispatch_ledger'
                 OR NOT EXISTS(SELECT 1 FROM admission_operation_native_dispatch_ledger AS record
                    WHERE record.operation_id = committed.projection_key AND record.record_digest = committed.projection_reference_digest)))",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if invalid {
        return Err(super::invalid(
            "native dispatch ledger lost its exact global commitment",
        ));
    }
    Ok(())
}

pub(super) fn verify_reference(
    connection: &Connection,
    record: &Record,
) -> Result<(), AdmissionOperationStoreError> {
    let operation = AdmissionOperationV1::from_persisted(record.operation.clone())?;
    let fence = &record.lease.fence;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2
         AND projection_sequence = 1 AND mutation_kind = ?3 AND projection_reference_digest = ?4
         AND store_uuid = ?5 AND store_lease_id = ?6 AND store_owner_epoch = ?7",
        params![PROJECTION, operation.binding().operation_id().as_str(), MUTATION, record.digest()?.as_str(),
            fence.store_uuid, fence.lease_id, i64::try_from(fence.owner_epoch).map_err(invalid)?], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if count != 1 {
        return Err(invalid(
            "native dispatch ledger global commit changed its exact owner",
        ));
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn verify_all(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    verify_coverage(connection)?;
    let mut statement = connection.prepare("SELECT CASE WHEN length(CAST(operation_id AS BLOB)) = 64 THEN operation_id END FROM admission_operation_native_dispatch_ledger ORDER BY operation_id").map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let operation: Option<String> = row.get(0).map_err(sqlite_error)?;
        let operation = operation
            .ok_or_else(|| invalid("native dispatch ledger operation exceeds its bound"))?;
        let record = load(connection, &operation)?
            .ok_or_else(|| invalid("native dispatch ledger record is absent"))?;
        record.validate(connection)?;
        verify_reference(connection, &record)?;
    }
    Ok(())
}
