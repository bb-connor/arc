//! Immutable execution receipts anchored to the original admission participant.

use super::*;

#[cfg(test)]
#[path = "tool_outcome_execution_evidence_tests.rs"]
mod tests;

fn has_namespace(connection: &Connection) -> Result<bool, ToolOutcomeStoreError> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE lower(name) GLOB 'tool_outcome_execution_evidence*' OR lower(tbl_name) GLOB 'tool_outcome_execution_evidence*')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)
}

pub(super) fn verify_unstamped_source(
    connection: &Connection,
) -> Result<(), ToolOutcomeStoreError> {
    let app_id: i32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(sqlite_error)?;
    if app_id == 0 && has_namespace(connection)? {
        return Err(invariant(
            "unstamped execution evidence source cannot be adopted",
        ));
    }
    Ok(())
}

pub(super) fn verify_pre_migration(
    connection: &Connection,
    on_disk: i32,
) -> Result<(), ToolOutcomeStoreError> {
    if has_namespace(connection)? {
        return Err(invariant(
            "pre-v4 outcome source contains unqualified execution evidence",
        ));
    }
    if on_disk == 3 {
        let expected = Connection::open_in_memory().map_err(sqlite_error)?;
        expected
            .execute_batch(TOOL_OUTCOME_SCHEMA)
            .map_err(sqlite_error)?;
        expected
            .execute_batch(SECURITY_RELEASE_SCHEMA)
            .map_err(sqlite_error)?;
        if tool_outcome_schema_catalog(connection)? != tool_outcome_schema_catalog(&expected)? {
            return Err(invariant(
                "pre-v4 outcome schema is not the exact qualified v3 predecessor",
            ));
        }
        return Ok(());
    }
    security_release::verify_pre_migration(connection, on_disk)
}

fn participant_digest(record: &ExecutionEvidenceRecordV1) -> Result<String, ToolOutcomeStoreError> {
    #[derive(Serialize)]
    struct Commitment<'a> {
        schema: &'static str,
        record: &'a ExecutionEvidenceRecordV1,
    }
    canonical_json_bytes(&Commitment {
        schema: "chio.execution-evidence-participant.v1",
        record,
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|error| invariant(error.to_string()))
}

pub(super) fn load(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<ExecutionEvidenceRecordV1>, ToolOutcomeStoreError> {
    type Row = (i64, Option<Vec<u8>>, String, i64, String, String, i64);
    let row: Option<Row> = connection.query_row(
        "SELECT length(canonical_record),
                CASE WHEN typeof(canonical_record) = 'blob' AND length(canonical_record) BETWEEN 1 AND 1048576 THEN canonical_record END,
                CASE WHEN length(CAST(participant_digest AS BLOB)) = 64 THEN participant_digest END,
                recorded_at_unix_ms,
                CASE WHEN length(CAST(store_uuid AS BLOB)) BETWEEN 1 AND 512 THEN store_uuid END,
                CASE WHEN length(CAST(store_lease_id AS BLOB)) BETWEEN 1 AND 512 THEN store_lease_id END,
                store_owner_epoch
         FROM tool_outcome_execution_evidence WHERE operation_id = ?1",
        [operation_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
    ).optional().map_err(sqlite_error)?;
    row.map(|(length, bytes, digest, at, store_uuid, lease_id, epoch)| {
        let bytes = bytes.ok_or_else(|| invariant("execution evidence canonical record exceeds its bounds or is not a blob"))?;
        if usize::try_from(length).ok() != Some(bytes.len()) {
            return Err(invariant("execution evidence canonical record length differs"));
        }
        let record = ExecutionEvidenceRecordV1::from_canonical_bytes(&bytes)
            .map_err(|error| invariant(error.to_string()))?;
        if record.operation_id().as_str() != operation_id
            || digest != participant_digest(&record)?
            || sqlite_u64(record.recorded_at_unix_ms(), "execution evidence time")? != at
            || record.store_fence().store_uuid != store_uuid
            || record.store_fence().lease_id != lease_id
            || sqlite_u64(record.store_fence().owner_epoch, "execution evidence owner epoch")? != epoch {
            return Err(invariant("execution evidence row differs from its canonical record"));
        }
        let exact_lease: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_serving_leases WHERE store_uuid = ?1 AND lease_id = ?2 AND owner_epoch = ?3)",
            params![store_uuid, lease_id, epoch], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if !exact_lease {
            return Err(invariant("execution evidence has no exact historical serving lease"));
        }
        Ok(record)
    }).transpose()
}

fn validate_source(
    connection: &Connection,
    record: &ExecutionEvidenceRecordV1,
    operation: &AdmissionOperationV1,
    outcome: &ToolOutcomeRecordV1,
    evaluation: &PostReturnEvaluationRecordV1,
) -> Result<(), ToolOutcomeStoreError> {
    let raw_blob = match load_blob_state_connection(connection, outcome.raw_output_digest())? {
        Some(StoredInvocationBlob::Present(blob)) => blob,
        _ => {
            return Err(invariant(
                "execution evidence requires its retained original outcome",
            ))
        }
    };
    let raw = RawInvocationOutcomeV1::from_canonical_bytes(raw_blob.bytes())
        .map_err(|error| invariant(error.to_string()))?;
    let retained =
        crate::admission_operation_store::load_retained_request_tx(connection, operation)
            .map_err(admission_error)?
            .ok_or_else(|| {
                invariant("execution evidence requires its retained admission request")
            })?;
    chio_kernel::tool_outcome::validate_execution_evidence_request(
        operation, &retained, &raw, evaluation,
    )
    .map_err(|error| invariant(error.to_string()))?;
    let resolved = load_resolved_blob_connection(connection, outcome)?
        .ok_or_else(|| invariant("execution evidence requires its resolved output"))?;
    let journal = crate::budget_store::load_original_payment_journal(
        connection,
        record.operation_id().as_str(),
    )
    .map_err(|error| invariant(error.to_string()))?
    .ok_or_else(|| invariant("execution evidence requires its original payment journal"))?;
    record
        .validate_against(
            operation,
            &raw,
            outcome,
            evaluation,
            &journal,
            resolved.bytes(),
        )
        .map_err(|error| invariant(error.to_string()))
}

pub(super) fn verify_projection(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    outcome: &ToolOutcomeRecordV1,
    evaluation: Option<&PostReturnEvaluationRecordV1>,
) -> Result<Option<String>, ToolOutcomeStoreError> {
    let Some(record) = load(connection, operation.binding().operation_id().as_str())? else {
        return Ok(None);
    };
    let evaluation =
        evaluation.ok_or_else(|| invariant("execution evidence has no resolved evaluation"))?;
    validate_source(connection, &record, operation, outcome, evaluation)?;
    participant_digest(&record).map(Some)
}

fn live_write_time(selected_time: u64) -> Result<u64, ToolOutcomeStoreError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| invariant(error.to_string()))?
        .as_millis();
    Ok(u64::try_from(millis)
        .map_err(|_| invariant("execution evidence clock exceeds u64"))?
        .max(selected_time))
}

impl SqliteToolOutcomeStore {
    pub(super) fn persist_execution_evidence(
        &self,
        qualified: &QualifiedExecutionEvidenceV1,
        lease: &AdmissionRecoveryLease,
    ) -> Result<ExecutionEvidenceRecordV1, ToolOutcomeStoreError> {
        let record = qualified.record();
        let now = record.recorded_at_unix_ms();
        let fence = record.store_fence();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, fence, now)?;
        // Waiting for SQLite's writer lock may outlive the original claim.
        // Revalidate against live time after acquiring the transaction.
        let live_now = live_write_time(now)?;
        verify_trusted_time(&transaction, live_now).map_err(admission_error)?;
        let operation = load_operation_for_participant_tx(&transaction, record.operation_id())
            .map_err(admission_error)?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        crate::admission_operation_store::verify_participant_recovery_lease_tx(
            &transaction,
            &self.serving_owner,
            &operation,
            lease,
            live_now,
        )
        .map_err(admission_error)?;
        let outcome = load_outcome_tx(&transaction, record.operation_id())?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        require_finalizing_operation(&operation, &outcome)?;
        let evaluation = load_evaluation_tx(&transaction, record.operation_id())?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        validate_source(&transaction, record, &operation, &outcome, &evaluation)?;
        verify_outcome_projection(&transaction, record.operation_id().as_str())?;
        if let Some(existing) = load(&transaction, record.operation_id().as_str())? {
            if &existing != record {
                return Err(ToolOutcomeStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let bytes = record
            .canonical_bytes()
            .map_err(|error| invariant(error.to_string()))?;
        let digest = participant_digest(record)?;
        transaction.execute(
            "INSERT INTO tool_outcome_execution_evidence(operation_id, canonical_record, participant_digest, recorded_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![record.operation_id().as_str(), bytes, digest, sqlite_u64(now, "execution evidence time")?, fence.store_uuid, fence.lease_id, sqlite_u64(fence.owner_epoch, "execution evidence epoch")?],
        ).map_err(sqlite_error)?;
        let live_now = live_write_time(now)?;
        verify_trusted_time(&transaction, live_now).map_err(admission_error)?;
        append_participant_update_tx(
            &transaction,
            &self.serving_owner,
            &operation,
            lease,
            &digest,
            live_now,
        )
        .map_err(admission_error)?;
        verify_outcome_projection(&transaction, record.operation_id().as_str())?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record.clone())
    }
}
