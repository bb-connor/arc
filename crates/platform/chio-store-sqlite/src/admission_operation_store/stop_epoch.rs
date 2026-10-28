//! The durable stop chain (`chio.stop-epoch.v1`).
//!
//! Each record is appended through the serving writer, covered by the global
//! authority commit chain and anchored before the call returns. The record
//! table is append-only. Reason text lives in a separate, deletable note
//! table; the chain keeps only its salted commitment.
use chio_kernel::stop::{
    stop_reason_commitment, verify_stop_chain, DecisionTime, DurableStopError, DurableStopStore,
    StopChainError, StopEpochV1, StopScope, StopState, StopTransition, StopTransitionRequest,
    MAX_STOP_REASON_BYTES, MAX_STOP_RECORD_BYTES, STOP_CHAIN_GENERATION_BOUND, STOP_EPOCH_SCHEMA,
};
use rand_core::{OsRng, RngCore};

use super::*;

pub(super) const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admission_operation_stop_epochs (
    scope_key TEXT NOT NULL CHECK (scope_key IN ('kernel')),
    chain_generation INTEGER NOT NULL CHECK (chain_generation >= 1),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    record_digest TEXT NOT NULL CHECK (
        typeof(record_digest) = 'text' AND length(record_digest) = 64 AND instr(record_digest, char(0)) = 0 AND record_digest NOT GLOB '*[^0-9a-f]*'
    ),
    previous_digest TEXT NOT NULL CHECK (
        typeof(previous_digest) = 'text' AND length(previous_digest) = 64 AND instr(previous_digest, char(0)) = 0 AND previous_digest NOT GLOB '*[^0-9a-f]*'
    ),
    payload BLOB NOT NULL CHECK (typeof(payload) = 'blob' AND length(payload) BETWEEN 1 AND 4096),
    PRIMARY KEY (scope_key, chain_generation, epoch)
);

CREATE TRIGGER IF NOT EXISTS admission_operation_stop_epochs_immutable
BEFORE UPDATE ON admission_operation_stop_epochs
BEGIN
    SELECT RAISE(ABORT, 'stop epoch record is immutable');
END;

CREATE TRIGGER IF NOT EXISTS admission_operation_stop_epochs_no_delete
BEFORE DELETE ON admission_operation_stop_epochs
BEGIN
    SELECT RAISE(ABORT, 'stop epoch record is immutable');
END;

CREATE TABLE IF NOT EXISTS admission_operation_stop_notes (
    scope_key TEXT NOT NULL CHECK (scope_key IN ('kernel')),
    chain_generation INTEGER NOT NULL CHECK (chain_generation >= 1),
    epoch INTEGER NOT NULL CHECK (epoch >= 1),
    salt TEXT NOT NULL CHECK (typeof(salt) = 'text' AND length(salt) = 64 AND instr(salt, char(0)) = 0 AND salt NOT GLOB '*[^0-9a-f]*'),
    redacted_text TEXT NOT NULL CHECK (typeof(redacted_text) = 'text' AND length(redacted_text) <= 1024 AND octet_length(redacted_text) <= 4096 AND instr(redacted_text, char(0)) = 0),
    PRIMARY KEY (scope_key, chain_generation, epoch)
);
"#;

pub(crate) const PROJECTION: &str = "stop_epoch";
const MUTATION: &str = "append_stop_epoch";

pub(super) fn present(connection: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema
                 WHERE type = 'table' AND name = 'admission_operation_stop_epochs')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn projection_key(scope: StopScope, chain_generation: u32) -> String {
    format!("{}:{chain_generation}", scope.key())
}

struct StoredRecord {
    record: StopEpochV1,
    digest: String,
}

fn decode(
    epoch: i64,
    record_digest: &str,
    previous_digest: &str,
    payload: &[u8],
) -> Result<StoredRecord, StopChainError> {
    let record: StopEpochV1 =
        chio_core::canonical::UntrustedJsonText::from_wire(payload, MAX_STOP_RECORD_BYTES)
            .and_then(|text| text.decode_canonical())
            .map_err(|error| StopChainError(format!("stop record does not decode: {error}")))?;
    let digest = record.digest()?;
    if digest != record_digest
        || record.previous != previous_digest
        || i64::try_from(record.epoch).ok() != Some(epoch)
    {
        return Err(StopChainError(
            "stop record row disagrees with its payload".to_owned(),
        ));
    }
    Ok(StoredRecord { record, digest })
}

fn load_chain(
    connection: &Connection,
    scope: StopScope,
) -> Result<Vec<StoredRecord>, DurableStopError> {
    let mut statement = connection
        .prepare(
            "SELECT chain_generation, epoch, record_digest, previous_digest, payload
             FROM admission_operation_stop_epochs
             WHERE scope_key = ?1 ORDER BY chain_generation, epoch",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([scope.key()]).map_err(sqlite_error)?;
    let mut records = Vec::new();
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let generation: i64 = row.get(0).map_err(sqlite_error)?;
        if generation != 1 {
            return Err(StopChainError("stop chain generation is unsupported".to_owned()).into());
        }
        let epoch: i64 = row.get(1).map_err(sqlite_error)?;
        let record_digest: String = row.get(2).map_err(sqlite_error)?;
        let previous_digest: String = row.get(3).map_err(sqlite_error)?;
        let payload: Vec<u8> = row.get(4).map_err(sqlite_error)?;
        records.push(decode(epoch, &record_digest, &previous_digest, &payload)?);
    }
    Ok(records)
}

/// Verify the whole chain, its global commit references, and return its head.
fn verified_head(
    connection: &Connection,
    authority_id: &str,
    scope: StopScope,
) -> Result<Option<StopEpochV1>, DurableStopError> {
    if !present(connection)? {
        return Err(StopChainError("stop chain table is missing".to_owned()).into());
    }
    let stored = load_chain(connection, scope)?;
    let records: Vec<StopEpochV1> = stored.iter().map(|entry| entry.record.clone()).collect();
    let head = verify_stop_chain(authority_id, scope, &records)?.cloned();
    for entry in &stored {
        let referenced: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM authority_global_commits
                 WHERE projection_kind = ?1 AND projection_key = ?2
                   AND projection_sequence = ?3 AND mutation_kind = ?4
                   AND projection_reference_digest = ?5",
                params![
                    PROJECTION,
                    projection_key(scope, entry.record.chain_generation),
                    sqlite_i64(entry.record.epoch, "stop epoch")?,
                    MUTATION,
                    entry.digest,
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if referenced != 1 {
            return Err(StopChainError(
                "stop record is not covered by the global commit chain".to_owned(),
            )
            .into());
        }
    }
    Ok(head)
}

pub(crate) fn require_output_release(
    connection: &Connection,
    authority_id: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let head = verified_head(connection, authority_id, StopScope::Kernel)
        .map_err(|error| AdmissionOperationStoreError::Invariant(error.to_string()))?;
    if head.is_some_and(|head| head.state == StopState::Stopped) {
        return Err(AdmissionOperationStoreError::KernelStopped);
    }
    Ok(())
}

/// The digest the global commit chain references for one stop record.
pub(crate) fn projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    let integrity = |detail: String| SqliteServingOwnerError::Invalid(detail);
    if key != projection_key(StopScope::Kernel, 1) {
        return Err(integrity("stop epoch projection key is invalid".to_owned()));
    }
    let row: Option<(i64, String, String, Vec<u8>)> = connection
        .query_row(
            "SELECT epoch, record_digest, previous_digest, payload
             FROM admission_operation_stop_epochs
             WHERE scope_key = 'kernel' AND chain_generation = 1 AND epoch = ?1",
            [i64::try_from(sequence)
                .map_err(|_| integrity("stop epoch sequence is out of range".to_owned()))?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|error| integrity(error.to_string()))?;
    let (epoch, record_digest, previous_digest, payload) =
        row.ok_or_else(|| integrity("stop epoch projection reference is absent".to_owned()))?;
    decode(epoch, &record_digest, &previous_digest, &payload)
        .map(|stored| stored.digest)
        .map_err(|error| integrity(error.to_string()))
}

/// Every stop record has exactly one global reference, and every global
/// reference names a stop record.
pub(crate) fn verify_projection_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let integrity = |detail: &str| SqliteServingOwnerError::Invalid(detail.to_owned());
    let global: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
        [PROJECTION],
        |row| row.get(0),
    )?;
    if !present(connection).map_err(|error| integrity(&error.to_string()))? {
        return if global == 0 {
            Ok(())
        } else {
            Err(integrity("global stop epoch references have no stop chain"))
        };
    }
    let local: i64 = connection.query_row(
        "SELECT COUNT(*) FROM admission_operation_stop_epochs",
        [],
        |row| row.get(0),
    )?;
    let uncovered: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM admission_operation_stop_epochs AS local
             WHERE (
                 SELECT COUNT(*) FROM authority_global_commits AS global
                 WHERE global.projection_kind = ?1
                   AND global.projection_key = local.scope_key || ':' || local.chain_generation
                   AND global.projection_sequence = local.epoch
                   AND global.projection_reference_digest = local.record_digest
             ) <> 1
         )",
        [PROJECTION],
        |row| row.get(0),
    )?;
    if uncovered || local != global {
        return Err(integrity(
            "stop epoch records and global references disagree",
        ));
    }
    Ok(())
}

fn trusted_floor(transaction: &Transaction<'_>) -> Result<u64, AdmissionOperationStoreError> {
    let floor: i64 = transaction
        .query_row(
            "SELECT trusted_time_high_water_unix_ms FROM admission_operation_commit_meta
             WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    stored_u64(floor, "trusted_time_high_water_unix_ms")
}

fn fresh_salt() -> Result<[u8; 32], AdmissionOperationStoreError> {
    let mut salt = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|error| AdmissionOperationStoreError::Unavailable(error.to_string()))?;
    Ok(salt)
}

impl DurableStopStore for SqliteAdmissionOperationStore {
    fn load_stop_head(&self, scope: StopScope) -> Result<Option<StopEpochV1>, DurableStopError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        verified_head(&transaction, &self.serving_owner.fence.store_uuid, scope)
    }

    fn append_stop_transition(
        &self,
        request: &StopTransitionRequest,
        fence: &StoreMutationFence,
    ) -> Result<Option<StopEpochV1>, DurableStopError> {
        if request.reason.len() > MAX_STOP_REASON_BYTES {
            return Err(StopChainError("stop reason is too long".to_owned()).into());
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        let authority_id = self.serving_owner.fence.store_uuid.clone();
        let head = verified_head(&transaction, &authority_id, request.scope)?;
        let state = head.as_ref().map_or(StopState::Running, |head| head.state);
        if state == request.transition.resulting_state() {
            return Ok(head);
        }
        let head_id = head.as_ref().map(StopEpochV1::id);
        if request.transition == StopTransition::Resume && request.expected_epoch != head_id {
            return Err(DurableStopError::HeadMoved { head: head_id });
        }
        let decided_at =
            match super::schema::observe_authority_time(&transaction, &self.serving_owner) {
                Ok(observed) => DecisionTime::Observed(observed),
                Err(_) if request.transition == StopTransition::Stop => DecisionTime::Unavailable,
                Err(_) => return Err(DurableStopError::TimeUnavailable),
            };
        let expected_epoch = head_id.unwrap_or(chio_kernel::stop::StopEpochId::GENESIS);
        let epoch = expected_epoch
            .epoch
            .checked_add(1)
            .filter(|epoch| *epoch <= STOP_CHAIN_GENERATION_BOUND)
            .ok_or_else(|| StopChainError("stop chain generation is exhausted".to_owned()))?;
        let salt = fresh_salt()?;
        let record = StopEpochV1 {
            schema: STOP_EPOCH_SCHEMA.to_owned(),
            authority_id,
            scope: request.scope,
            chain_generation: expected_epoch.chain_generation,
            epoch,
            transition: request.transition,
            state: request.transition.resulting_state(),
            expected_epoch,
            reason_commitment: stop_reason_commitment(&salt, &request.reason),
            authorizer: request.authorizer.clone(),
            decided_at,
            trusted_floor_at_commit: trusted_floor(&transaction)?,
            previous: head.as_ref().map_or(
                Ok(chio_kernel::stop::STOP_ZERO_DIGEST.to_owned()),
                StopEpochV1::digest,
            )?,
            allow_containment: request.allow_containment,
            requested_via: request.requested_via.clone(),
        };
        record.verify_successor(&record.authority_id, request.scope, head.as_ref())?;
        let payload = record.canonical_bytes()?;
        if payload.len() > MAX_STOP_RECORD_BYTES {
            return Err(StopChainError("stop record exceeds its size bound".to_owned()).into());
        }
        let epoch_value = sqlite_i64(epoch, "stop epoch")?;
        transaction
            .execute(
                "INSERT INTO admission_operation_stop_epochs (
                     scope_key, chain_generation, epoch, record_digest, previous_digest, payload
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    request.scope.key(),
                    record.chain_generation,
                    epoch_value,
                    record.digest()?,
                    record.previous,
                    payload,
                ],
            )
            .map_err(sqlite_error)?;
        transaction
            .execute(
                "INSERT INTO admission_operation_stop_notes (
                     scope_key, chain_generation, epoch, salt, redacted_text
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    request.scope.key(),
                    record.chain_generation,
                    epoch_value,
                    hex::encode(salt),
                    request.reason,
                ],
            )
            .map_err(sqlite_error)?;
        self.serving_owner
            .append_global_commit(
                &transaction,
                MUTATION,
                PROJECTION,
                &projection_key(request.scope, record.chain_generation),
                epoch,
            )
            .map_err(map_owner_error)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(Some(record))
    }

    fn withheld_operations(&self) -> Result<u64, DurableStopError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM admission_operations
                 WHERE terminal = 0 AND state = 'finalizing'",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        Ok(stored_u64(count, "withheld operation count")?)
    }
}
