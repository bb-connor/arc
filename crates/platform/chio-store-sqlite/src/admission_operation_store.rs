use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::{
    AdmissionBeginResult, AdmissionCommandResult, AdmissionIdentifier, AdmissionOperationCommand,
    AdmissionOperationError, AdmissionOperationId, AdmissionOperationState,
    AdmissionOperationStore, AdmissionOperationStoreError, AdmissionOperationV1,
    AdmissionReplayClassification, AdmissionReplayKey, AdmissionTerminalReplay,
    PersistedAdmissionOperationV1, QualifiedAdmissionOperationStore,
    UntrustedAdmissionRecoveryClaim,
};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::Serialize;

use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};

mod commit_chain;

use commit_chain::append_operation_commit;
pub(crate) use commit_chain::{
    load_admission_commit_head, verify_admission_commit_chain, verify_admission_commit_suffix,
    AdmissionCommitHead, GENESIS_CHAIN_DIGEST,
};

const ADMISSION_OPERATION_SCHEMA_KEY: &str = "admission_operation";
pub(crate) const ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION: i32 = 1;
const ADMISSION_OPERATION_SCHEMA_ANCHORS: &[&str] = &[
    "admission_operations",
    "chio_serving_owner",
    "capability_grant_budgets",
];
const MAX_PERSISTED_OPERATION_BYTES: usize = 256 * 1024;
const MAX_RECOVERY_BATCH: usize = 256;
const MAX_TRUSTED_UNIX_MS: u64 = (1_u64 << 53) - 1;
const MAX_TRUSTED_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
const MAX_RECOVERY_LEASE_DURATION_MS: u64 = 5 * 60 * 1_000;

const ADMISSION_OPERATION_SCHEMA: &str = include_str!("admission_operation_store.sql");

#[derive(Clone)]
pub struct SqliteAdmissionOperationStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteAdmissionOperationStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, AdmissionOperationStoreError> {
        self.connection.lock().map_err(|_| {
            AdmissionOperationStoreError::Invariant(
                "sqlite admission operation lock poisoned".to_string(),
            )
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, AdmissionOperationStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
        fence: Option<&StoreMutationFence>,
    ) -> Result<Transaction<'a>, AdmissionOperationStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, fence)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        Ok(transaction)
    }

    fn sync_after_write(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(map_owner_error)
    }

    fn commit_write(
        &self,
        transaction: Transaction<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        transaction.commit().map_err(|error| {
            map_owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite admission operation commit outcome is unknown: {error}"
            )))
        })
    }
}

impl QualifiedAdmissionOperationStore for SqliteAdmissionOperationStore {}

impl AdmissionOperationStore for SqliteAdmissionOperationStore {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        operation.validate()?;
        if operation.state() != AdmissionOperationState::Prepared || operation.version() != 1 {
            return Err(invariant("begin requires a version-one Prepared operation"));
        }
        if operation.coordinator_lease_epoch() != fence.owner_epoch {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let encoded = encode_operation(operation)?;
        let replay_key = operation.replay_key();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;

        if let Some(existing) = load_by_replay_key_tx(&transaction, &replay_key)? {
            let result = match existing.operation.classify_replay(operation) {
                AdmissionReplayClassification::Exact { terminal_replay } => {
                    AdmissionBeginResult::ExactReplay {
                        operation: existing.operation,
                        terminal_replay,
                    }
                }
                AdmissionReplayClassification::Conflict => AdmissionBeginResult::Conflict {
                    existing_operation_id: existing.operation.binding().operation_id().clone(),
                },
            };
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        }
        if load_by_operation_id_tx(&transaction, operation.binding().operation_id())?.is_some() {
            return Err(invariant(
                "operation id is already bound to a different replay key",
            ));
        }

        let changed = transaction
            .execute(
                r#"
                INSERT INTO admission_operations (
                    operation_id, request_namespace_digest, request_id,
                    operation_json, state, terminal, coordinator_lease_epoch,
                    version, created_at_unix_ms, updated_at_unix_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7, ?8, ?8)
                "#,
                params![
                    operation.binding().operation_id().as_str(),
                    replay_key.request_namespace_digest.as_str(),
                    replay_key.request_id.as_str(),
                    encoded,
                    state_name(operation.state()),
                    sqlite_i64(
                        operation.coordinator_lease_epoch(),
                        "coordinator_lease_epoch"
                    )?,
                    sqlite_i64(operation.version(), "version")?,
                    sqlite_i64(trusted_now_unix_ms, "created_at_unix_ms")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("begin did not insert exactly one operation"));
        }
        append_operation_commit(
            &transaction,
            operation,
            &encoded,
            None,
            "begin",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionBeginResult::Created(operation.clone()))
    }

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let operation =
            load_by_operation_id_tx(&transaction, operation_id)?.map(|row| row.operation);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operation)
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let operation = load_by_replay_key_tx(&transaction, replay_key)?.map(|row| row.operation);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operation)
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let fence = command.recovery_lease().store_fence();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, command.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("trusted operation time regressed"));
        }
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            command.recovery_lease().untrusted_claim(),
            trusted_now_unix_ms,
            fence,
        )?;

        let result = stored
            .operation
            .apply_command(command, trusted_now_unix_ms)?;
        let AdmissionCommandResult::Applied(updated) = result else {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(result);
        };
        let encoded = encode_operation(&updated)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET operation_json = ?1, state = ?2, terminal = ?3,
                    coordinator_lease_epoch = ?4, version = ?5,
                    updated_at_unix_ms = ?6
                WHERE operation_id = ?7 AND version = ?8
                "#,
                params![
                    encoded,
                    state_name(updated.state()),
                    i64::from(updated.state().is_terminal()),
                    sqlite_i64(updated.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(updated.version(), "version")?,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                    updated.binding().operation_id().as_str(),
                    sqlite_i64(stored.operation.version(), "expected_version")?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        append_operation_commit(
            &transaction,
            &updated,
            &encoded,
            stored.recovery_claim.as_ref(),
            "compare_and_swap",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(AdmissionCommandResult::Applied(updated))
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        validate_trusted_now(trusted_now_unix_ms, "trusted_now_unix_ms")?;
        validate_trusted_time(expires_at_unix_ms, "expires_at_unix_ms")?;
        if expected_version == 0 {
            return Err(AdmissionOperationError::ZeroVersionOrEpoch.into());
        }
        if trusted_now_unix_ms >= expires_at_unix_ms {
            return Err(AdmissionOperationError::LeaseExpired.into());
        }
        if expires_at_unix_ms - trusted_now_unix_ms > MAX_RECOVERY_LEASE_DURATION_MS {
            return Err(invariant("recovery lease exceeds its maximum duration"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored.operation.state().is_terminal() {
            return Err(invariant("terminal operation cannot be recovery-claimed"));
        }
        if trusted_now_unix_ms < stored.updated_at_unix_ms {
            return Err(invariant("trusted operation time regressed"));
        }
        if stored.operation.version() != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: stored.operation.version(),
            }
            .into());
        }

        let coordinator_lease_id = coordinator_lease_id_for_epoch(
            &transaction,
            &self.serving_owner,
            stored.operation.coordinator_lease_epoch(),
        )?;
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation_id.clone(),
            claimant_id.clone(),
            coordinator_lease_id,
            stored.operation.coordinator_lease_epoch(),
            expected_version,
            expires_at_unix_ms,
            fence.clone(),
        )?;
        if let Some(active) = stored
            .recovery_claim
            .as_ref()
            .filter(|active| active.expires_at_unix_ms() > trusted_now_unix_ms)
        {
            if active.store_fence() == fence {
                let same_claimant = active.claimant_id() == claimant_id
                    && active.coordinator_lease_id() == claim.coordinator_lease_id()
                    && active.coordinator_lease_epoch() == claim.coordinator_lease_epoch();
                if same_claimant && active.claimed_version() == expected_version {
                    let active = active.clone();
                    transaction.commit().map_err(sqlite_error)?;
                    return Ok(active);
                }
                if !same_claimant || active.claimed_version() >= expected_version {
                    return Err(AdmissionOperationStoreError::Fenced);
                }
            }
        }

        let changed = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET recovery_claimant_id = ?1,
                    recovery_coordinator_lease_id = ?2,
                    recovery_coordinator_lease_epoch = ?3,
                    recovery_claimed_version = ?4,
                    recovery_expires_at_unix_ms = ?5,
                    recovery_store_uuid = ?6,
                    recovery_store_lease_id = ?7,
                    recovery_store_owner_epoch = ?8,
                    updated_at_unix_ms = ?9
                WHERE operation_id = ?10 AND version = ?4 AND terminal = 0
                "#,
                params![
                    claimant_id.as_str(),
                    claim.coordinator_lease_id().as_str(),
                    sqlite_i64(claim.coordinator_lease_epoch(), "coordinator_lease_epoch")?,
                    sqlite_i64(expected_version, "claimed_version")?,
                    sqlite_i64(expires_at_unix_ms, "expires_at_unix_ms")?,
                    &fence.store_uuid,
                    &fence.lease_id,
                    sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                    sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
                    operation_id.as_str(),
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let encoded = encode_operation(&stored.operation)?;
        append_operation_commit(
            &transaction,
            &stored.operation,
            &encoded,
            Some(&claim),
            "recovery_claim",
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(claim)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, Some(current_store_fence))?;
        verify_trusted_time(&transaction, trusted_now_unix_ms)?;
        let stored = load_by_operation_id_tx(&transaction, claim.operation_id())?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if stored.operation != *operation {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        verify_stored_recovery_claim(
            &transaction,
            &self.serving_owner,
            &stored,
            claim,
            trusted_now_unix_ms,
            current_store_fence,
        )?;
        transaction.commit().map_err(sqlite_error)
    }

    fn list_recoverable(
        &self,
        not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        if limit > MAX_RECOVERY_BATCH {
            return Err(invariant("recovery batch limit exceeds 256"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT operation_id, request_namespace_digest, request_id,
                       operation_json, state, terminal, coordinator_lease_epoch,
                       version, created_at_unix_ms, updated_at_unix_ms,
                       recovery_claimant_id, recovery_coordinator_lease_id,
                       recovery_coordinator_lease_epoch, recovery_claimed_version,
                       recovery_expires_at_unix_ms, recovery_store_uuid,
                       recovery_store_lease_id, recovery_store_owner_epoch
                FROM admission_operations
                WHERE terminal = 0
                  AND (recovery_expires_at_unix_ms IS NULL
                       OR recovery_expires_at_unix_ms <= ?1
                       OR recovery_store_uuid <> ?2
                       OR recovery_store_lease_id <> ?3
                       OR recovery_store_owner_epoch <> ?4)
                ORDER BY updated_at_unix_ms, operation_id
                LIMIT ?5
                "#,
            )
            .map_err(sqlite_error)?;
        let mut rows = statement
            .query(params![
                sqlite_i64(not_after_unix_ms, "not_after_unix_ms")?,
                &self.serving_owner.fence.store_uuid,
                &self.serving_owner.fence.lease_id,
                sqlite_i64(self.serving_owner.fence.owner_epoch, "store_owner_epoch")?,
                i64::try_from(limit).map_err(|_| invariant("recovery limit overflow"))?,
            ])
            .map_err(sqlite_error)?;
        let mut operations = Vec::with_capacity(limit);
        while let Some(row) = rows.next().map_err(sqlite_error)? {
            let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
            verify_latest_commit(&transaction, &stored)?;
            operations.push(stored.operation);
        }
        drop(rows);
        drop(statement);
        transaction.commit().map_err(sqlite_error)?;
        Ok(operations)
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let replay = load_by_replay_key_tx(&transaction, replay_key)?
            .and_then(|stored| stored.operation.terminal_replay().cloned());
        transaction.commit().map_err(sqlite_error)?;
        Ok(replay)
    }
}

pub(crate) fn initialize_admission_operation_schema(
    connection: &mut Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        ADMISSION_OPERATION_SCHEMA_KEY,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
        ADMISSION_OPERATION_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION {
        return verify_admission_operation_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        ADMISSION_OPERATION_SCHEMA_KEY,
        ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_admission_operation_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

pub(crate) fn verify_admission_operation_invariants(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(ADMISSION_OPERATION_SCHEMA)
        .map_err(sqlite_error)?;
    if admission_operation_schema_catalog(connection)?
        != admission_operation_schema_catalog(&expected)?
    {
        return Err(invariant(
            "admission operation schema differs from the canonical definition",
        ));
    }

    let (head, high_water, commit_count, max_commit, max_recorded_at): (i64, i64, i64, i64, i64) =
        connection
            .query_row(
                r#"
            SELECT
                (SELECT head_sequence FROM admission_operation_commit_meta
                 WHERE singleton = 1),
                (SELECT trusted_time_high_water_unix_ms
                 FROM admission_operation_commit_meta WHERE singleton = 1),
                (SELECT COUNT(*) FROM admission_operation_commits),
                (SELECT COALESCE(MAX(commit_sequence), 0)
                 FROM admission_operation_commits),
                (SELECT COALESCE(MAX(recorded_at_unix_ms), 0)
                 FROM admission_operation_commits)
            "#,
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(sqlite_error)?;
    let serving_leases_exist: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'chio_serving_leases'
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let invalid_lease = if serving_leases_exist {
        connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1 FROM admission_operation_commits AS committed
                    WHERE NOT EXISTS (
                        SELECT 1 FROM chio_serving_leases AS lease
                        WHERE lease.store_uuid = committed.store_uuid
                          AND lease.owner_epoch = committed.store_owner_epoch
                          AND lease.lease_id = committed.store_lease_id
                    )
                )
                "#,
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?
    } else {
        commit_count != 0
    };
    if head < 0
        || high_water < 0
        || u64::try_from(high_water).map_or(true, |value| value > MAX_TRUSTED_UNIX_MS)
        || high_water != max_recorded_at
        || (head == 0) != (high_water == 0)
        || commit_count != head
        || max_commit != head
        || invalid_lease
    {
        return Err(invariant(
            "admission operation commit log is not a dense fenced sequence",
        ));
    }
    let invalid_commit_order: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM (
                    SELECT mutation_kind, operation_version, recorded_at_unix_ms,
                           LAG(operation_version) OVER (
                               PARTITION BY operation_id ORDER BY commit_sequence
                           ) AS previous_version,
                           LAG(recorded_at_unix_ms) OVER (
                               PARTITION BY operation_id ORDER BY commit_sequence
                           ) AS previous_time
                    FROM admission_operation_commits
                )
                WHERE (previous_version IS NULL
                       AND (mutation_kind <> 'begin' OR operation_version <> 1))
                   OR (previous_version IS NOT NULL
                       AND (mutation_kind = 'begin'
                            OR (mutation_kind = 'recovery_claim'
                                AND operation_version <> previous_version)
                            OR (mutation_kind = 'compare_and_swap'
                                AND operation_version <> previous_version + 1)
                            OR recorded_at_unix_ms < previous_time))
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if invalid_commit_order {
        return Err(invariant(
            "admission operation commits regress version or trusted time",
        ));
    }
    let global_time_regression: bool = connection
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM (
                    SELECT recorded_at_unix_ms,
                           LAG(recorded_at_unix_ms) OVER (
                               ORDER BY commit_sequence
                           ) AS previous_time
                    FROM admission_operation_commits
                )
                WHERE previous_time IS NOT NULL
                  AND recorded_at_unix_ms < previous_time
            )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if global_time_regression {
        return Err(invariant(
            "admission operation trusted time regresses across commits",
        ));
    }
    verify_admission_commit_chain(connection)?;

    let mut statement = connection
        .prepare(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations
            "#,
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let stored = decode_row(read_raw_row(row).map_err(sqlite_error)?)?;
        verify_latest_commit(connection, &stored)?;
    }
    Ok(())
}

fn verify_trusted_time(
    transaction: &Transaction<'_>,
    trusted_now_unix_ms: u64,
) -> Result<(), AdmissionOperationStoreError> {
    validate_trusted_now(trusted_now_unix_ms, "trusted_now_unix_ms")?;
    let high_water: i64 = transaction
        .query_row(
            r#"
            SELECT trusted_time_high_water_unix_ms
            FROM admission_operation_commit_meta WHERE singleton = 1
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")? < high_water {
        return Err(invariant("trusted admission operation time regressed"));
    }
    Ok(())
}

fn validate_trusted_now(
    value: u64,
    field: &'static str,
) -> Result<(), AdmissionOperationStoreError> {
    validate_trusted_time(value, field)?;
    let system_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invariant("system clock precedes the Unix epoch"))?
        .as_millis();
    let system_now = u64::try_from(system_now)
        .map_err(|_| invariant("system clock exceeds the persisted trusted-time range"))?;
    if value.abs_diff(system_now) > MAX_TRUSTED_CLOCK_SKEW_MS {
        return Err(invariant(format!(
            "{field} exceeds the permitted system-clock skew"
        )));
    }
    Ok(())
}

fn validate_trusted_time(
    value: u64,
    field: &'static str,
) -> Result<(), AdmissionOperationStoreError> {
    if value == 0 || value > MAX_TRUSTED_UNIX_MS {
        return Err(invariant(format!(
            "{field} is outside the persisted trusted-time range"
        )));
    }
    Ok(())
}

fn verify_latest_commit(
    connection: &Connection,
    stored: &StoredOperation,
) -> Result<(), AdmissionOperationStoreError> {
    let latest = connection
        .query_row(
            r#"
            SELECT operation_version, operation_digest, recovery_claim_digest,
                   recorded_at_unix_ms
            FROM admission_operation_commits
            WHERE operation_id = ?1
            ORDER BY commit_sequence DESC
            LIMIT 1
            "#,
            [stored.operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("admission operation has no commit record"))?;
    let encoded = encode_operation(&stored.operation)?;
    let claim_digest = stored
        .recovery_claim
        .as_ref()
        .map(recovery_claim_digest)
        .transpose()?;
    if stored_u64(latest.0, "commit operation_version")? != stored.operation.version()
        || latest.1 != sha256_hex(&encoded)
        || latest.2 != claim_digest
        || stored_u64(latest.3, "commit recorded_at_unix_ms")? != stored.updated_at_unix_ms
    {
        return Err(invariant(
            "latest admission operation commit does not match its projection",
        ));
    }
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn admission_operation_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, AdmissionOperationStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'admission_operation*'
               OR tbl_name GLOB 'admission_operation*'
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

fn recovery_claim_digest(
    claim: &UntrustedAdmissionRecoveryClaim,
) -> Result<String, AdmissionOperationStoreError> {
    #[derive(Serialize)]
    struct ClaimDigestBody<'a> {
        operation_id: &'a str,
        claimant_id: &'a str,
        coordinator_lease_id: &'a str,
        coordinator_lease_epoch: u64,
        claimed_version: u64,
        expires_at_unix_ms: u64,
        store_uuid: &'a str,
        store_lease_id: &'a str,
        store_owner_epoch: u64,
    }

    let body = ClaimDigestBody {
        operation_id: claim.operation_id().as_str(),
        claimant_id: claim.claimant_id().as_str(),
        coordinator_lease_id: claim.coordinator_lease_id().as_str(),
        coordinator_lease_epoch: claim.coordinator_lease_epoch(),
        claimed_version: claim.claimed_version(),
        expires_at_unix_ms: claim.expires_at_unix_ms(),
        store_uuid: &claim.store_fence().store_uuid,
        store_lease_id: &claim.store_fence().lease_id,
        store_owner_epoch: claim.store_fence().owner_epoch,
    };
    let canonical = canonical_json_bytes(&body)
        .map_err(|error| invariant(format!("recovery claim encoding failed: {error}")))?;
    Ok(sha256_hex(&canonical))
}

fn verify_active_owner(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    requested: Option<&StoreMutationFence>,
) -> Result<(), AdmissionOperationStoreError> {
    crate::serving_owner::verify_budget_fence(transaction, Some(owner)).map_err(|error| {
        if matches!(error, chio_kernel::BudgetStoreError::Fenced { .. }) {
            AdmissionOperationStoreError::Fenced
        } else {
            AdmissionOperationStoreError::Unavailable(error.to_string())
        }
    })?;
    if requested.is_some_and(|fence| fence != &owner.fence) {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let active_lease: i64 = transaction
        .query_row(
            r#"
            SELECT COUNT(*) FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3
              AND end_head_index IS NULL
            "#,
            params![
                &owner.fence.store_uuid,
                sqlite_i64(owner.fence.owner_epoch, "store_owner_epoch")?,
                &owner.fence.lease_id,
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if active_lease != 1 {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

fn coordinator_lease_id_for_epoch(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    coordinator_lease_epoch: u64,
) -> Result<AdmissionIdentifier, AdmissionOperationStoreError> {
    let lease_id = transaction
        .query_row(
            r#"
            SELECT lease_id
            FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2
            "#,
            params![
                &owner.fence.store_uuid,
                sqlite_i64(coordinator_lease_epoch, "coordinator_lease_epoch")?,
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or_else(|| invariant("operation coordinator lease is absent from lease history"))?;
    AdmissionIdentifier::try_new("coordinator_lease_id", lease_id).map_err(Into::into)
}

fn verify_stored_recovery_claim(
    transaction: &Transaction<'_>,
    owner: &SqliteServingOwner,
    stored: &StoredOperation,
    claim: &UntrustedAdmissionRecoveryClaim,
    trusted_now_unix_ms: u64,
    current_store_fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if trusted_now_unix_ms < stored.updated_at_unix_ms {
        return Err(invariant("trusted operation time regressed"));
    }
    if trusted_now_unix_ms >= claim.expires_at_unix_ms() {
        return Err(AdmissionOperationError::LeaseExpired.into());
    }
    if stored.recovery_claim.as_ref() != Some(claim)
        || stored.operation.binding().operation_id() != claim.operation_id()
        || stored.operation.version() != claim.claimed_version()
        || stored.operation.coordinator_lease_epoch() != claim.coordinator_lease_epoch()
        || claim.store_fence() != current_store_fence
    {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    let historical_lease_id = coordinator_lease_id_for_epoch(
        transaction,
        owner,
        stored.operation.coordinator_lease_epoch(),
    )?;
    if &historical_lease_id != claim.coordinator_lease_id() {
        return Err(AdmissionOperationStoreError::Fenced);
    }
    Ok(())
}

struct StoredOperation {
    operation: AdmissionOperationV1,
    recovery_claim: Option<UntrustedAdmissionRecoveryClaim>,
    updated_at_unix_ms: u64,
}

struct RawOperationRow {
    operation_id: String,
    request_namespace_digest: String,
    request_id: String,
    operation_json: Vec<u8>,
    state: String,
    terminal: i64,
    coordinator_lease_epoch: i64,
    version: i64,
    created_at_unix_ms: i64,
    updated_at_unix_ms: i64,
    recovery_claimant_id: Option<String>,
    recovery_coordinator_lease_id: Option<String>,
    recovery_coordinator_lease_epoch: Option<i64>,
    recovery_claimed_version: Option<i64>,
    recovery_expires_at_unix_ms: Option<i64>,
    recovery_store_uuid: Option<String>,
    recovery_store_lease_id: Option<String>,
    recovery_store_owner_epoch: Option<i64>,
}

fn read_raw_row(row: &Row<'_>) -> rusqlite::Result<RawOperationRow> {
    Ok(RawOperationRow {
        operation_id: row.get(0)?,
        request_namespace_digest: row.get(1)?,
        request_id: row.get(2)?,
        operation_json: row.get(3)?,
        state: row.get(4)?,
        terminal: row.get(5)?,
        coordinator_lease_epoch: row.get(6)?,
        version: row.get(7)?,
        created_at_unix_ms: row.get(8)?,
        updated_at_unix_ms: row.get(9)?,
        recovery_claimant_id: row.get(10)?,
        recovery_coordinator_lease_id: row.get(11)?,
        recovery_coordinator_lease_epoch: row.get(12)?,
        recovery_claimed_version: row.get(13)?,
        recovery_expires_at_unix_ms: row.get(14)?,
        recovery_store_uuid: row.get(15)?,
        recovery_store_lease_id: row.get(16)?,
        recovery_store_owner_epoch: row.get(17)?,
    })
}

fn decode_row(raw: RawOperationRow) -> Result<StoredOperation, AdmissionOperationStoreError> {
    if raw.operation_json.is_empty() || raw.operation_json.len() > MAX_PERSISTED_OPERATION_BYTES {
        return Err(invariant("persisted admission operation size is invalid"));
    }
    let persisted: PersistedAdmissionOperationV1 = serde_json::from_slice(&raw.operation_json)
        .map_err(|error| invariant(format!("persisted admission operation is invalid: {error}")))?;
    let operation = AdmissionOperationV1::from_persisted(persisted)?;
    let canonical = encode_operation(&operation)?;
    if canonical != raw.operation_json {
        return Err(invariant(
            "persisted admission operation encoding is not canonical",
        ));
    }
    let replay_key = operation.replay_key();
    if operation.binding().operation_id().as_str() != raw.operation_id
        || replay_key.request_namespace_digest.as_str() != raw.request_namespace_digest
        || replay_key.request_id.as_str() != raw.request_id
        || state_name(operation.state()) != raw.state
        || i64::from(operation.state().is_terminal()) != raw.terminal
        || operation.coordinator_lease_epoch()
            != stored_u64(raw.coordinator_lease_epoch, "coordinator_lease_epoch")?
        || operation.version() != stored_u64(raw.version, "version")?
    {
        return Err(invariant(
            "admission operation columns do not match the checked record",
        ));
    }
    let created_at = stored_u64(raw.created_at_unix_ms, "created_at_unix_ms")?;
    let updated_at = stored_u64(raw.updated_at_unix_ms, "updated_at_unix_ms")?;
    validate_trusted_time(created_at, "created_at_unix_ms")?;
    validate_trusted_time(updated_at, "updated_at_unix_ms")?;
    if updated_at < created_at {
        return Err(invariant("admission operation timestamp regressed"));
    }

    let recovery_claim = match (
        raw.recovery_claimant_id,
        raw.recovery_coordinator_lease_id,
        raw.recovery_coordinator_lease_epoch,
        raw.recovery_claimed_version,
        raw.recovery_expires_at_unix_ms,
        raw.recovery_store_uuid,
        raw.recovery_store_lease_id,
        raw.recovery_store_owner_epoch,
    ) {
        (None, None, None, None, None, None, None, None) => None,
        (
            Some(claimant_id),
            Some(coordinator_lease_id),
            Some(coordinator_lease_epoch),
            Some(claimed_version),
            Some(expires_at_unix_ms),
            Some(store_uuid),
            Some(store_lease_id),
            Some(store_owner_epoch),
        ) => {
            let claimed_version = stored_u64(claimed_version, "recovery_claimed_version")?;
            if claimed_version > operation.version()
                || claimed_version
                    .checked_add(1)
                    .is_some_and(|next| next < operation.version())
            {
                return Err(invariant(
                    "recovery claim is not for the current or immediately preceding version",
                ));
            }
            let expires_at_unix_ms = stored_u64(expires_at_unix_ms, "recovery_expires_at_unix_ms")?;
            validate_trusted_time(expires_at_unix_ms, "recovery_expires_at_unix_ms")?;
            Some(UntrustedAdmissionRecoveryClaim::new(
                operation.binding().operation_id().clone(),
                AdmissionIdentifier::try_new("recovery_claimant_id", claimant_id)?,
                AdmissionIdentifier::try_new(
                    "recovery_coordinator_lease_id",
                    coordinator_lease_id,
                )?,
                stored_u64(coordinator_lease_epoch, "recovery_coordinator_lease_epoch")?,
                claimed_version,
                expires_at_unix_ms,
                StoreMutationFence {
                    store_uuid,
                    lease_id: store_lease_id,
                    owner_epoch: stored_u64(store_owner_epoch, "recovery_store_owner_epoch")?,
                },
            )?)
        }
        _ => return Err(invariant("recovery claim tuple is partial")),
    };
    Ok(StoredOperation {
        operation,
        recovery_claim,
        updated_at_unix_ms: updated_at,
    })
}

fn load_by_operation_id_tx(
    transaction: &Transaction<'_>,
    operation_id: &AdmissionOperationId,
) -> Result<Option<StoredOperation>, AdmissionOperationStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations WHERE operation_id = ?1
            "#,
            [operation_id.as_str()],
            read_raw_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored = raw.map(decode_row).transpose()?;
    if let Some(stored) = &stored {
        verify_latest_commit(transaction, stored)?;
    }
    Ok(stored)
}

fn load_by_replay_key_tx(
    transaction: &Transaction<'_>,
    replay_key: &AdmissionReplayKey,
) -> Result<Option<StoredOperation>, AdmissionOperationStoreError> {
    let raw = transaction
        .query_row(
            r#"
            SELECT operation_id, request_namespace_digest, request_id,
                   operation_json, state, terminal, coordinator_lease_epoch,
                   version, created_at_unix_ms, updated_at_unix_ms,
                   recovery_claimant_id, recovery_coordinator_lease_id,
                   recovery_coordinator_lease_epoch, recovery_claimed_version,
                   recovery_expires_at_unix_ms, recovery_store_uuid,
                   recovery_store_lease_id, recovery_store_owner_epoch
            FROM admission_operations
            WHERE request_namespace_digest = ?1 AND request_id = ?2
            "#,
            params![
                replay_key.request_namespace_digest.as_str(),
                replay_key.request_id.as_str(),
            ],
            read_raw_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    let stored = raw.map(decode_row).transpose()?;
    if let Some(stored) = &stored {
        verify_latest_commit(transaction, stored)?;
    }
    Ok(stored)
}

fn encode_operation(
    operation: &AdmissionOperationV1,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    operation.validate()?;
    let encoded = canonical_json_bytes(&operation.to_persisted())
        .map_err(|error| invariant(format!("admission operation encoding failed: {error}")))?;
    if encoded.is_empty() || encoded.len() > MAX_PERSISTED_OPERATION_BYTES {
        return Err(invariant(
            "persisted admission operation exceeds its size limit",
        ));
    }
    Ok(encoded)
}

fn state_name(state: AdmissionOperationState) -> &'static str {
    match state {
        AdmissionOperationState::Prepared => "prepared",
        AdmissionOperationState::BrokerAttemptRegistered => "broker_attempt_registered",
        AdmissionOperationState::BudgetAuthorized => "budget_authorized",
        AdmissionOperationState::ApprovalReserved => "approval_reserved",
        AdmissionOperationState::ReadyToDispatch => "ready_to_dispatch",
        AdmissionOperationState::CapturePending => "capture_pending",
        AdmissionOperationState::DispatchCommitted => "dispatch_committed",
        AdmissionOperationState::Finalizing => "finalizing",
        AdmissionOperationState::Completed => "completed",
        AdmissionOperationState::CompensatedBeforeDispatch => "compensated_before_dispatch",
        AdmissionOperationState::NotAcceptedAfterDispatchCommit => {
            "not_accepted_after_dispatch_commit"
        }
        AdmissionOperationState::OutcomeUnknownAfterDispatch => "outcome_unknown_after_dispatch",
        AdmissionOperationState::MutationReady => "mutation_ready",
        AdmissionOperationState::MutationSubmitted => "mutation_submitted",
        AdmissionOperationState::EconomicMutationApplied => "economic_mutation_applied",
        AdmissionOperationState::EconomicMutationNotApplied => "economic_mutation_not_applied",
    }
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, AdmissionOperationStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, AdmissionOperationStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn invariant(detail: impl Into<String>) -> AdmissionOperationStoreError {
    AdmissionOperationStoreError::Invariant(detail.into())
}

fn map_owner_error(error: SqliteServingOwnerError) -> AdmissionOperationStoreError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            AdmissionOperationStoreError::OutcomeUnknown(detail)
        }
        error => invariant(error.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> AdmissionOperationStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => AdmissionOperationStoreError::Unavailable(other.to_string()),
    }
}

impl From<AdmissionOperationStoreError> for SqliteServingOwnerError {
    fn from(error: AdmissionOperationStoreError) -> Self {
        Self::Invalid(error.to_string())
    }
}

#[cfg(test)]
#[path = "admission_operation_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
