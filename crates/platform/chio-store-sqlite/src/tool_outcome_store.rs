use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::canonical::canonical_json_bytes;
use chio_core::sha256_hex;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationState, AdmissionOperationStoreError,
    AdmissionOperationV1, AdmissionRecoveryLease, StoreMutationFence,
};
use chio_kernel::tool_outcome::{
    CanonicalInvocationBlobV1, PersistedPostReturnEvaluationRecordV1, PersistedToolOutcomeRecordV1,
    PostReturnEvaluationRecordV1, QualifiedToolOutcomeStore, RawInvocationOutcomeV1,
    ToolOutcomeInsertResultV1, ToolOutcomeRecordV1, ToolOutcomeStore, ToolOutcomeStoreError,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::admission_operation_store::{
    advance_tool_outcome_tx, append_participant_update_tx, load_operation_for_participant_tx,
    verify_active_owner, verify_trusted_time,
};
use crate::serving_owner::SqliteServingOwner;

const TOOL_OUTCOME_SCHEMA_KEY: &str = "tool_outcome";
pub(crate) const TOOL_OUTCOME_SUPPORTED_SCHEMA_VERSION: i32 = 1;
const TOOL_OUTCOME_SCHEMA_ANCHORS: &[&str] = &[
    "tool_outcomes",
    "admission_operations",
    "chio_serving_owner",
];
const TOOL_OUTCOME_SCHEMA: &str = include_str!("tool_outcome_store.sql");
const MAX_OUTCOME_RECORD_BYTES: usize = 1024 * 1024;
const MAX_EVALUATION_RECORD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct SqliteToolOutcomeStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteToolOutcomeStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, ToolOutcomeStoreError> {
        self.connection.lock().map_err(|_| {
            ToolOutcomeStoreError::Unavailable("sqlite tool outcome lock poisoned".to_owned())
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, ToolOutcomeStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| ToolOutcomeStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Transaction<'a>, ToolOutcomeStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))
            .map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| ToolOutcomeStoreError::Unavailable(error.to_string()))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms).map_err(admission_error)?;
        Ok(transaction)
    }

    fn commit_write(&self, transaction: Transaction<'_>) -> Result<(), ToolOutcomeStoreError> {
        transaction.commit().map_err(|error| {
            ToolOutcomeStoreError::Unavailable(
                self.serving_owner
                    .outcome_unknown(format!("sqlite tool outcome commit is unknown: {error}"))
                    .to_string(),
            )
        })
    }

    fn sync_after_write(&self, connection: &Connection) -> Result<(), ToolOutcomeStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(|error| ToolOutcomeStoreError::Unavailable(error.to_string()))
    }
}

impl ToolOutcomeStore for SqliteToolOutcomeStore {
    fn record_tool_returned(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        blob: &CanonicalInvocationBlobV1,
        record: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, active_fence, trusted_now_unix_ms)?;
        let stored_operation =
            load_operation_for_participant_tx(&transaction, operation.binding().operation_id())
                .map_err(admission_error)?
                .ok_or(ToolOutcomeStoreError::NotFound)?;
        if let Some(existing) = load_outcome_tx(&transaction, operation.binding().operation_id())? {
            let existing_blob = load_blob_tx(&transaction, existing.raw_output_digest())?
                .ok_or_else(|| invariant("tool outcome lost its canonical blob"))?;
            if !existing.same_immutable_outcome(record)
                || existing_blob.bytes() != blob.bytes()
                || stored_operation.tool_outcome_id() != Some(existing.outcome_id())
                || !matches!(
                    stored_operation.state(),
                    AdmissionOperationState::Finalizing | AdmissionOperationState::Completed
                )
            {
                return Err(ToolOutcomeStoreError::Conflict);
            }
            existing
                .validate_canonical_blob(&stored_operation, &existing_blob)
                .map_err(|error| invariant(error.to_string()))?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(ToolOutcomeInsertResultV1::ExactReplay {
                outcome: existing,
                operation: stored_operation,
            });
        }
        if stored_operation != *operation {
            return Err(ToolOutcomeStoreError::CasConflict);
        }
        record
            .validate_for_store_insert(operation, blob, active_fence, trusted_now_unix_ms)
            .map_err(|error| invariant(error.to_string()))?;
        let outcome_json = encode_outcome(record)?;
        let participant_digest = returned_participant_digest(record, blob, &outcome_json)?;
        insert_blob_tx(&transaction, blob, active_fence, trusted_now_unix_ms)?;
        insert_outcome_tx(
            &transaction,
            record,
            &outcome_json,
            &participant_digest,
            active_fence,
            trusted_now_unix_ms,
        )?;
        let finalizing = advance_tool_outcome_tx(
            &transaction,
            &self.serving_owner,
            operation,
            recovery_lease,
            record.outcome_id().clone(),
            &participant_digest,
            trusted_now_unix_ms,
        )
        .map_err(admission_error)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(ToolOutcomeInsertResultV1::Inserted {
            outcome: record.clone(),
            operation: finalizing,
        })
    }

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let outcome = load_outcome_tx(&transaction, operation_id)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(outcome)
    }

    fn load_raw_invocation_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let raw = match load_outcome_tx(&transaction, operation_id)? {
            Some(outcome) => load_blob_tx(&transaction, outcome.raw_output_digest())?
                .map(|blob| RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes()))
                .transpose()
                .map_err(|error| invariant(error.to_string()))?,
            None => None,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(raw)
    }

    fn lookup_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let evaluation = load_evaluation_tx(&transaction, operation_id)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(evaluation)
    }

    fn begin_post_return_evaluation(
        &self,
        recovery_lease: &AdmissionRecoveryLease,
        record: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, active_fence, trusted_now_unix_ms)?;
        let operation = load_operation_for_participant_tx(&transaction, record.operation_id())
            .map_err(admission_error)?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let outcome = load_outcome_tx(&transaction, record.operation_id())?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        require_finalizing_operation(&operation, &outcome)?;
        record
            .validate_against(&operation, &outcome)
            .and_then(|_| record.validate_for_store_mutation(trusted_now_unix_ms))
            .map_err(|error| invariant(error.to_string()))?;
        if let Some(existing) = load_evaluation_tx(&transaction, record.operation_id())? {
            if existing != *record {
                return Err(ToolOutcomeStoreError::Conflict);
            }
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let evaluation_json = encode_evaluation(record)?;
        let participant_digest = evaluation_participant_digest(record, &evaluation_json)?;
        insert_evaluation_tx(
            &transaction,
            record,
            outcome.outcome_id().as_str(),
            &evaluation_json,
            &participant_digest,
            active_fence,
            trusted_now_unix_ms,
        )?;
        append_participant_update_tx(
            &transaction,
            &self.serving_owner,
            &operation,
            recovery_lease,
            &participant_digest,
            trusted_now_unix_ms,
        )
        .map_err(admission_error)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record.clone())
    }

    fn stage_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        recovery_lease: &AdmissionRecoveryLease,
        next: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, active_fence, trusted_now_unix_ms)?;
        let operation = load_operation_for_participant_tx(&transaction, operation_id)
            .map_err(admission_error)?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let outcome =
            load_outcome_tx(&transaction, operation_id)?.ok_or(ToolOutcomeStoreError::NotFound)?;
        require_finalizing_operation(&operation, &outcome)?;
        let current = load_evaluation_tx(&transaction, operation_id)?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        if current.version() != expected_version {
            return Err(ToolOutcomeStoreError::CasConflict);
        }
        chio_kernel::tool_outcome::validate_evaluation_store_successor(&current, next)
            .and_then(|_| next.validate_against(&operation, &outcome))
            .and_then(|_| next.validate_for_store_mutation(trusted_now_unix_ms))
            .map_err(|error| invariant(error.to_string()))?;
        let evaluation_json = encode_evaluation(next)?;
        let participant_digest = evaluation_participant_digest(next, &evaluation_json)?;
        update_evaluation_tx(
            &transaction,
            operation_id,
            expected_version,
            next,
            &evaluation_json,
            &participant_digest,
            active_fence,
            trusted_now_unix_ms,
        )?;
        append_participant_update_tx(
            &transaction,
            &self.serving_owner,
            &operation,
            recovery_lease,
            &participant_digest,
            trusted_now_unix_ms,
        )
        .map_err(admission_error)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(next.clone())
    }

    fn finalize_post_return(
        &self,
        operation_id: &AdmissionOperationId,
        expected_evaluation_version: u64,
        recovery_lease: &AdmissionRecoveryLease,
        terminal_evaluation: &PostReturnEvaluationRecordV1,
        expected_outcome_version: u64,
        terminal_outcome: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, active_fence, trusted_now_unix_ms)?;
        let operation = load_operation_for_participant_tx(&transaction, operation_id)
            .map_err(admission_error)?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        let current_outcome =
            load_outcome_tx(&transaction, operation_id)?.ok_or(ToolOutcomeStoreError::NotFound)?;
        require_finalizing_operation(&operation, &current_outcome)?;
        let current_evaluation = load_evaluation_tx(&transaction, operation_id)?
            .ok_or(ToolOutcomeStoreError::NotFound)?;
        if current_evaluation.version() != expected_evaluation_version
            || current_outcome.version() != expected_outcome_version
        {
            return Err(ToolOutcomeStoreError::CasConflict);
        }
        chio_kernel::tool_outcome::validate_terminal_store_pair(
            &operation,
            &current_outcome,
            &current_evaluation,
            terminal_evaluation,
            terminal_outcome,
        )
        .and_then(|_| terminal_evaluation.validate_for_store_mutation(trusted_now_unix_ms))
        .map_err(|error| invariant(error.to_string()))?;
        let outcome_json = encode_outcome(terminal_outcome)?;
        let evaluation_json = encode_evaluation(terminal_evaluation)?;
        let participant_digest = finalization_participant_digest(
            terminal_outcome,
            terminal_evaluation,
            &outcome_json,
            &evaluation_json,
        )?;
        update_outcome_tx(
            &transaction,
            operation_id,
            expected_outcome_version,
            terminal_outcome,
            &outcome_json,
            &participant_digest,
            active_fence,
            trusted_now_unix_ms,
        )?;
        update_evaluation_tx(
            &transaction,
            operation_id,
            expected_evaluation_version,
            terminal_evaluation,
            &evaluation_json,
            &participant_digest,
            active_fence,
            trusted_now_unix_ms,
        )?;
        append_participant_update_tx(
            &transaction,
            &self.serving_owner,
            &operation,
            recovery_lease,
            &participant_digest,
            trusted_now_unix_ms,
        )
        .map_err(admission_error)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok((terminal_evaluation.clone(), terminal_outcome.clone()))
    }
}

impl QualifiedToolOutcomeStore for SqliteToolOutcomeStore {}

pub(crate) fn initialize_tool_outcome_schema(
    connection: &mut Connection,
) -> Result<(), ToolOutcomeStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        TOOL_OUTCOME_SCHEMA_KEY,
        TOOL_OUTCOME_SUPPORTED_SCHEMA_VERSION,
        TOOL_OUTCOME_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == TOOL_OUTCOME_SUPPORTED_SCHEMA_VERSION {
        return verify_tool_outcome_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(TOOL_OUTCOME_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        TOOL_OUTCOME_SCHEMA_KEY,
        TOOL_OUTCOME_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_tool_outcome_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

pub(crate) fn verify_tool_outcome_invariants(
    connection: &Connection,
) -> Result<(), ToolOutcomeStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(TOOL_OUTCOME_SCHEMA)
        .map_err(sqlite_error)?;
    if tool_outcome_schema_catalog(connection)? != tool_outcome_schema_catalog(&expected)? {
        return Err(invariant(
            "tool outcome schema differs from the canonical definition",
        ));
    }
    let mut blob_statement = connection
        .prepare(
            "SELECT digest, blob_size_bytes, canonical_bytes FROM tool_outcome_blobs ORDER BY digest",
        )
        .map_err(sqlite_error)?;
    let mut blob_rows = blob_statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = blob_rows.next().map_err(sqlite_error)? {
        let digest: String = row.get(0).map_err(sqlite_error)?;
        let size: i64 = row.get(1).map_err(sqlite_error)?;
        let bytes: Vec<u8> = row.get(2).map_err(sqlite_error)?;
        if usize::try_from(size).ok() != Some(bytes.len()) || sha256_hex(&bytes) != digest {
            return Err(invariant("tool outcome blob digest is invalid"));
        }
    }
    drop(blob_rows);
    drop(blob_statement);
    let mut statement = connection
        .prepare("SELECT operation_id FROM tool_outcomes ORDER BY operation_id")
        .map_err(sqlite_error)?;
    let operation_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    drop(statement);
    for operation_id in operation_ids {
        verify_outcome_projection(connection, &operation_id)?;
    }
    Ok(())
}

fn verify_outcome_projection(
    connection: &Connection,
    operation_id: &str,
) -> Result<(), ToolOutcomeStoreError> {
    let outcome = load_outcome_connection(connection, operation_id)?
        .ok_or_else(|| invariant("tool outcome projection disappeared"))?;
    let operation_json: Vec<u8> = connection
        .query_row(
            "SELECT operation_json FROM admission_operations WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let persisted = serde_json::from_slice(&operation_json)
        .map_err(|error| invariant(format!("admission operation decode failed: {error}")))?;
    let operation = AdmissionOperationV1::from_persisted(persisted)
        .map_err(|error| invariant(error.to_string()))?;
    if operation.tool_outcome_id() != Some(outcome.outcome_id()) {
        return Err(invariant(
            "tool outcome is not attached to its admission operation",
        ));
    }
    outcome
        .validate_against(&operation)
        .map_err(|error| invariant(error.to_string()))?;
    let blob = load_blob_connection(connection, outcome.raw_output_digest())?
        .ok_or_else(|| invariant("tool outcome canonical blob is absent"))?;
    outcome
        .validate_canonical_blob(&operation, &blob)
        .map_err(|error| invariant(error.to_string()))?;
    let returned_digest = returned_participant_digest(&outcome, &blob, &encode_outcome(&outcome)?)?;
    let stored_outcome_digest: String = connection
        .query_row(
            "SELECT participant_digest FROM tool_outcomes WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let evaluation = load_evaluation_connection(connection, operation_id)?;
    let (expected_outcome_digest, expected_evaluation_digest, expected_latest_digest) =
        if let Some(evaluation) = &evaluation {
            evaluation
                .validate_against(&operation, &outcome)
                .map_err(|error| invariant(error.to_string()))?;
            let outcome_json = encode_outcome(&outcome)?;
            let evaluation_json = encode_evaluation(evaluation)?;
            if outcome.version() > 1 {
                let digest = finalization_participant_digest(
                    &outcome,
                    evaluation,
                    &outcome_json,
                    &evaluation_json,
                )?;
                (digest.clone(), Some(digest.clone()), digest)
            } else {
                let evaluation_digest =
                    evaluation_participant_digest(evaluation, &evaluation_json)?;
                (
                    returned_digest.clone(),
                    Some(evaluation_digest.clone()),
                    evaluation_digest,
                )
            }
        } else {
            if outcome.version() != 1 {
                return Err(invariant(
                    "terminal tool outcome has no post-return evaluation",
                ));
            }
            (returned_digest.clone(), None, returned_digest)
        };
    if stored_outcome_digest != expected_outcome_digest {
        return Err(invariant(
            "tool outcome row has an invalid participant commitment",
        ));
    }
    let stored_evaluation_digest: Option<String> = connection
        .query_row(
            "SELECT participant_digest FROM post_return_evaluations WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if stored_evaluation_digest != expected_evaluation_digest {
        return Err(invariant(
            "post-return evaluation row has an invalid participant commitment",
        ));
    }
    let latest: Option<String> = connection
        .query_row(
            r#"
            SELECT participant_digest FROM admission_operation_commits
            WHERE operation_id = ?1 AND participant_digest IS NOT NULL
            ORDER BY commit_sequence DESC LIMIT 1
            "#,
            [operation_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if latest.as_deref() != Some(expected_latest_digest.as_str()) {
        return Err(invariant(
            "tool outcome projection is not bound to the admission commit chain",
        ));
    }
    Ok(())
}

fn require_finalizing_operation(
    operation: &AdmissionOperationV1,
    outcome: &ToolOutcomeRecordV1,
) -> Result<(), ToolOutcomeStoreError> {
    if operation.state() != AdmissionOperationState::Finalizing
        || operation.tool_outcome_id() != Some(outcome.outcome_id())
    {
        return Err(invariant(
            "post-return evaluation requires the attached finalizing operation",
        ));
    }
    Ok(())
}

fn insert_blob_tx(
    transaction: &Transaction<'_>,
    blob: &CanonicalInvocationBlobV1,
    fence: &StoreMutationFence,
    recorded_at_unix_ms: u64,
) -> Result<(), ToolOutcomeStoreError> {
    let size = i64::try_from(blob.bytes().len())
        .map_err(|_| invariant("tool outcome blob size overflowed SQLite"))?;
    transaction
        .execute(
            r#"
            INSERT INTO tool_outcome_blobs (
                digest, blob_size_bytes, canonical_bytes, recorded_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(digest) DO NOTHING
            "#,
            params![
                blob.blob_ref().digest().as_str(),
                size,
                blob.bytes(),
                sqlite_u64(recorded_at_unix_ms, "recorded_at_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_u64(fence.owner_epoch, "store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    let stored = load_blob_tx(transaction, blob.blob_ref().digest())?
        .ok_or_else(|| invariant("tool outcome blob insert disappeared"))?;
    if stored.bytes() != blob.bytes() {
        return Err(invariant("content-addressed blob digest collision"));
    }
    Ok(())
}

fn insert_outcome_tx(
    transaction: &Transaction<'_>,
    record: &ToolOutcomeRecordV1,
    encoded: &[u8],
    participant_digest: &str,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ToolOutcomeStoreError> {
    let persisted = record.to_persisted();
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO tool_outcomes (
                operation_id, outcome_id, request_id, raw_output_digest,
                outcome_version, lifecycle_digest, participant_digest, outcome_json,
                recorded_at_unix_ms, updated_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
            "#,
            params![
                record.operation_id().as_str(),
                record.outcome_id().as_str(),
                persisted.request_id.as_str(),
                record.raw_output_digest().as_str(),
                sqlite_u64(record.version(), "outcome_version")?,
                record.lifecycle_digest().as_str(),
                participant_digest,
                encoded,
                sqlite_u64(record.recorded_at_unix_ms(), "recorded_at_unix_ms")?,
                sqlite_u64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_u64(fence.owner_epoch, "store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant("tool outcome insert did not affect one row"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn update_outcome_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    expected_version: u64,
    next: &ToolOutcomeRecordV1,
    encoded: &[u8],
    participant_digest: &str,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ToolOutcomeStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE tool_outcomes
            SET outcome_version = ?1, lifecycle_digest = ?2,
                participant_digest = ?3, outcome_json = ?4,
                updated_at_unix_ms = ?5, store_uuid = ?6,
                store_lease_id = ?7, store_owner_epoch = ?8
            WHERE operation_id = ?9 AND outcome_version = ?10
            "#,
            params![
                sqlite_u64(next.version(), "outcome_version")?,
                next.lifecycle_digest().as_str(),
                participant_digest,
                encoded,
                sqlite_u64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_u64(fence.owner_epoch, "store_owner_epoch")?,
                operation_id.as_str(),
                sqlite_u64(expected_version, "expected_outcome_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(ToolOutcomeStoreError::CasConflict);
    }
    Ok(())
}

fn insert_evaluation_tx(
    transaction: &Transaction<'_>,
    record: &PostReturnEvaluationRecordV1,
    outcome_id: &str,
    encoded: &[u8],
    participant_digest: &str,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ToolOutcomeStoreError> {
    let persisted = record.to_persisted();
    let inserted = transaction
        .execute(
            r#"
            INSERT INTO post_return_evaluations (
                operation_id, evaluation_id, outcome_id, evaluation_version,
                lifecycle_digest, participant_digest, evaluation_json,
                created_at_unix_ms, updated_at_unix_ms,
                store_uuid, store_lease_id, store_owner_epoch
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
            params![
                record.operation_id().as_str(),
                record.evaluation_id().as_str(),
                outcome_id,
                sqlite_u64(record.version(), "evaluation_version")?,
                persisted.lifecycle_digest.as_str(),
                participant_digest,
                encoded,
                sqlite_u64(persisted.trusted_time_unix_ms, "evaluation_trusted_time")?,
                sqlite_u64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_u64(fence.owner_epoch, "store_owner_epoch")?,
            ],
        )
        .map_err(sqlite_error)?;
    if inserted != 1 {
        return Err(invariant(
            "post-return evaluation insert did not affect one row",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn update_evaluation_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
    expected_version: u64,
    next: &PostReturnEvaluationRecordV1,
    encoded: &[u8],
    participant_digest: &str,
    fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), ToolOutcomeStoreError> {
    let persisted = next.to_persisted();
    let changed = transaction
        .execute(
            r#"
            UPDATE post_return_evaluations
            SET evaluation_version = ?1, lifecycle_digest = ?2,
                participant_digest = ?3, evaluation_json = ?4,
                updated_at_unix_ms = ?5, store_uuid = ?6,
                store_lease_id = ?7, store_owner_epoch = ?8
            WHERE operation_id = ?9 AND evaluation_version = ?10
            "#,
            params![
                sqlite_u64(next.version(), "evaluation_version")?,
                persisted.lifecycle_digest.as_str(),
                participant_digest,
                encoded,
                sqlite_u64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                &fence.store_uuid,
                &fence.lease_id,
                sqlite_u64(fence.owner_epoch, "store_owner_epoch")?,
                operation_id.as_str(),
                sqlite_u64(expected_version, "expected_evaluation_version")?,
            ],
        )
        .map_err(sqlite_error)?;
    if changed != 1 {
        return Err(ToolOutcomeStoreError::CasConflict);
    }
    Ok(())
}

fn load_outcome_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
    load_outcome_connection(transaction, operation_id.as_str())
}

fn load_outcome_connection(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
    let row = connection
        .query_row(
            r#"
            SELECT outcome_id, request_id, raw_output_digest, outcome_version,
                   lifecycle_digest, outcome_json, recorded_at_unix_ms
            FROM tool_outcomes WHERE operation_id = ?1
            "#,
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((outcome_id, request_id, raw_digest, version, lifecycle, encoded, recorded_at)) = row
    else {
        return Ok(None);
    };
    let persisted: PersistedToolOutcomeRecordV1 = serde_json::from_slice(&encoded)
        .map_err(|error| invariant(format!("tool outcome decode failed: {error}")))?;
    let record = ToolOutcomeRecordV1::from_persisted(persisted)
        .map_err(|error| invariant(error.to_string()))?;
    if record.operation_id().as_str() != operation_id
        || record.outcome_id().as_str() != outcome_id
        || record.to_persisted().request_id.as_str() != request_id
        || record.raw_output_digest().as_str() != raw_digest
        || sqlite_u64(record.version(), "outcome_version")? != version
        || record.lifecycle_digest().as_str() != lifecycle
        || sqlite_u64(record.recorded_at_unix_ms(), "recorded_at_unix_ms")? != recorded_at
        || encode_outcome(&record)? != encoded
    {
        return Err(invariant(
            "tool outcome columns do not match canonical record",
        ));
    }
    Ok(Some(record))
}

fn load_evaluation_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
    load_evaluation_connection(transaction, operation_id.as_str())
}

fn load_evaluation_connection(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
    let row = connection
        .query_row(
            r#"
            SELECT evaluation_id, outcome_id, evaluation_version,
                   lifecycle_digest, evaluation_json
            FROM post_return_evaluations WHERE operation_id = ?1
            "#,
            [operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((evaluation_id, outcome_id, version, lifecycle, encoded)) = row else {
        return Ok(None);
    };
    let persisted: PersistedPostReturnEvaluationRecordV1 = serde_json::from_slice(&encoded)
        .map_err(|error| invariant(format!("post-return evaluation decode failed: {error}")))?;
    let record = PostReturnEvaluationRecordV1::from_persisted(persisted)
        .map_err(|error| invariant(error.to_string()))?;
    let canonical = record.to_persisted();
    if record.operation_id().as_str() != operation_id
        || record.evaluation_id().as_str() != evaluation_id
        || canonical.tool_outcome_id.as_str() != outcome_id
        || sqlite_u64(record.version(), "evaluation_version")? != version
        || canonical.lifecycle_digest.as_str() != lifecycle
        || encode_evaluation(&record)? != encoded
    {
        return Err(invariant(
            "post-return evaluation columns do not match canonical record",
        ));
    }
    Ok(Some(record))
}

fn load_blob_tx(
    transaction: &Transaction<'_>,
    digest: &chio_kernel::admission_operation::AdmissionDigest,
) -> Result<Option<CanonicalInvocationBlobV1>, ToolOutcomeStoreError> {
    load_blob_connection(transaction, digest)
}

fn load_blob_connection(
    connection: &Connection,
    digest: &chio_kernel::admission_operation::AdmissionDigest,
) -> Result<Option<CanonicalInvocationBlobV1>, ToolOutcomeStoreError> {
    let bytes = connection
        .query_row(
            "SELECT canonical_bytes FROM tool_outcome_blobs WHERE digest = ?1",
            [digest.as_str()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    bytes
        .map(|bytes| {
            RawInvocationOutcomeV1::from_canonical_bytes(&bytes)
                .and_then(|raw| raw.canonical_blob())
                .map_err(|error| invariant(error.to_string()))
        })
        .transpose()
}

fn encode_outcome(record: &ToolOutcomeRecordV1) -> Result<Vec<u8>, ToolOutcomeStoreError> {
    encode_bounded(
        "tool outcome",
        &record.to_persisted(),
        MAX_OUTCOME_RECORD_BYTES,
    )
}

fn encode_evaluation(
    record: &PostReturnEvaluationRecordV1,
) -> Result<Vec<u8>, ToolOutcomeStoreError> {
    encode_bounded(
        "post-return evaluation",
        &record.to_persisted(),
        MAX_EVALUATION_RECORD_BYTES,
    )
}

fn encode_bounded(
    label: &str,
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<u8>, ToolOutcomeStoreError> {
    let encoded = canonical_json_bytes(value)
        .map_err(|error| invariant(format!("{label} encoding failed: {error}")))?;
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(invariant(format!("{label} exceeds its storage bound")));
    }
    Ok(encoded)
}

#[derive(Serialize)]
struct ParticipantCommitment<'a> {
    schema: &'static str,
    mutation: &'static str,
    operation_id: &'a str,
    outcome_id: &'a str,
    outcome_record_digest: Option<String>,
    raw_output_digest: Option<&'a str>,
    evaluation_id: Option<&'a str>,
    evaluation_record_digest: Option<String>,
}

fn returned_participant_digest(
    record: &ToolOutcomeRecordV1,
    blob: &CanonicalInvocationBlobV1,
    outcome_json: &[u8],
) -> Result<String, ToolOutcomeStoreError> {
    participant_digest(&ParticipantCommitment {
        schema: "chio.tool-outcome-participant-commitment.v1",
        mutation: "record_tool_returned",
        operation_id: record.operation_id().as_str(),
        outcome_id: record.outcome_id().as_str(),
        outcome_record_digest: Some(sha256_hex(outcome_json)),
        raw_output_digest: Some(blob.blob_ref().digest().as_str()),
        evaluation_id: None,
        evaluation_record_digest: None,
    })
}

fn evaluation_participant_digest(
    record: &PostReturnEvaluationRecordV1,
    evaluation_json: &[u8],
) -> Result<String, ToolOutcomeStoreError> {
    let persisted = record.to_persisted();
    participant_digest(&ParticipantCommitment {
        schema: "chio.tool-outcome-participant-commitment.v1",
        mutation: "stage_post_return_evaluation",
        operation_id: record.operation_id().as_str(),
        outcome_id: persisted.tool_outcome_id.as_str(),
        outcome_record_digest: None,
        raw_output_digest: Some(persisted.raw_output_digest.as_str()),
        evaluation_id: Some(record.evaluation_id().as_str()),
        evaluation_record_digest: Some(sha256_hex(evaluation_json)),
    })
}

fn finalization_participant_digest(
    outcome: &ToolOutcomeRecordV1,
    evaluation: &PostReturnEvaluationRecordV1,
    outcome_json: &[u8],
    evaluation_json: &[u8],
) -> Result<String, ToolOutcomeStoreError> {
    participant_digest(&ParticipantCommitment {
        schema: "chio.tool-outcome-participant-commitment.v1",
        mutation: "finalize_post_return",
        operation_id: outcome.operation_id().as_str(),
        outcome_id: outcome.outcome_id().as_str(),
        outcome_record_digest: Some(sha256_hex(outcome_json)),
        raw_output_digest: Some(outcome.raw_output_digest().as_str()),
        evaluation_id: Some(evaluation.evaluation_id().as_str()),
        evaluation_record_digest: Some(sha256_hex(evaluation_json)),
    })
}

fn participant_digest(value: &impl Serialize) -> Result<String, ToolOutcomeStoreError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| invariant(format!("participant commitment encoding failed: {error}")))
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn tool_outcome_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, ToolOutcomeStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'tool_outcome*'
               OR tbl_name GLOB 'tool_outcome*'
               OR name GLOB 'post_return_evaluation*'
               OR tbl_name GLOB 'post_return_evaluation*'
            ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

fn sqlite_u64(value: u64, field: &str) -> Result<i64, ToolOutcomeStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite INTEGER")))
}

fn admission_error(error: AdmissionOperationStoreError) -> ToolOutcomeStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => ToolOutcomeStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => ToolOutcomeStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail)
        | AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            ToolOutcomeStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => ToolOutcomeStoreError::Invariant(detail),
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> ToolOutcomeStoreError {
    ToolOutcomeStoreError::Unavailable(error.to_string())
}

fn invariant(detail: impl Into<String>) -> ToolOutcomeStoreError {
    ToolOutcomeStoreError::Invariant(detail.into())
}

#[cfg(test)]
#[path = "tool_outcome_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
