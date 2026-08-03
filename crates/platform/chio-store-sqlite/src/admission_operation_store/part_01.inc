use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use chio_kernel::{
    AdmissionCleanupAction, AdmissionCleanupActionCasOutcome, AdmissionCleanupActionClaimOutcome,
    AdmissionCleanupActionCreateOutcome, AdmissionCleanupActionKind, AdmissionCleanupActionState,
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCompareAndSwap, AdmissionOperationCreateOutcome, AdmissionOperationError,
    AdmissionOperationKind, AdmissionOperationState, AdmissionOperationStore,
    AdmissionOperationStoreProfile, PersistedAdmissionCleanupAction, PersistedAdmissionOperation,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub struct SqliteAdmissionOperationStore {
    connection: Mutex<Connection>,
    authority_profile: AdmissionOperationStoreProfile,
    database_identity_file: Option<Arc<crate::durable_sqlite::DurableSqliteFile>>,
}

#[cfg(unix)]
fn create_private_plain_database_if_missing(path: &Path) -> Result<(), AdmissionOperationError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(AdmissionOperationError::Unavailable(format!(
            "failed to create private admission operation database: {error}"
        ))),
    }
}

impl SqliteAdmissionOperationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AdmissionOperationError> {
        let path = path.as_ref();
        reject_volatile_database_path(path)?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    AdmissionOperationError::Unavailable(format!(
                        "failed to prepare admission operation directory: {error}"
                    ))
                })?;
            }
        }
        #[cfg(unix)]
        create_private_plain_database_if_missing(path)?;
        let connection = Connection::open(path).map_err(sqlite_error)?;
        Self::from_connection(
            connection,
            AdmissionOperationStoreProfile::SingleNodeDurable,
        )
    }

    /// Open a durable admission-operation authority through one retained
    /// trusted parent shared with its sibling authorities.
    pub fn open_hardened(
        path: impl AsRef<Path>,
        directory: Arc<crate::durable_sqlite::TrustedSqliteDirectory>,
    ) -> Result<Self, AdmissionOperationError> {
        let database_identity_file = directory
            .open_database(path, true)
            .map_err(|error| AdmissionOperationError::Unavailable(error.to_string()))?;
        let connection = database_identity_file
            .open_connection(
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(|error| AdmissionOperationError::Unavailable(error.to_string()))?;
        Self::from_connection_with_identity(
            connection,
            AdmissionOperationStoreProfile::SingleNodeDurable,
            Some(database_identity_file),
        )
    }

    pub fn open_in_memory() -> Result<Self, AdmissionOperationError> {
        let connection = Connection::open_in_memory().map_err(sqlite_error)?;
        Self::from_connection(connection, AdmissionOperationStoreProfile::EphemeralLocal)
    }

    fn from_connection(
        connection: Connection,
        authority_profile: AdmissionOperationStoreProfile,
    ) -> Result<Self, AdmissionOperationError> {
        Self::from_connection_with_identity(connection, authority_profile, None)
    }

    fn from_connection_with_identity(
        connection: Connection,
        authority_profile: AdmissionOperationStoreProfile,
        database_identity_file: Option<Arc<crate::durable_sqlite::DurableSqliteFile>>,
    ) -> Result<Self, AdmissionOperationError> {
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;
                "#,
            )
            .map_err(sqlite_error)?;
        if let Some(database_identity_file) = database_identity_file.as_ref() {
            database_identity_file
                .validate_live_connection(&connection)
                .map_err(|error| AdmissionOperationError::Unavailable(error.to_string()))?;
        }
        connection
            .execute_batch(
                r#"

                CREATE TABLE IF NOT EXISTS admission_operations (
                    operation_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    coordinator_authority_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    authorization_capability_hash TEXT NOT NULL,
                    request_binding_hash TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    broker_attempt_id TEXT,
                    budget_hold_id TEXT,
                    approval_set_hash TEXT,
                    execution_nonce_id TEXT,
                    state TEXT NOT NULL,
                    dispatch_state TEXT NOT NULL,
                    coordinator_lease_epoch INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    last_error TEXT,
                    updated_at INTEGER NOT NULL,
                    CHECK (coordinator_lease_epoch >= 0),
                    CHECK (version >= 0)
                );

                CREATE INDEX IF NOT EXISTS idx_admission_operations_state
                    ON admission_operations(state, updated_at);

                CREATE INDEX IF NOT EXISTS idx_admission_operations_request_id
                    ON admission_operations(kind, request_id, operation_id);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_admission_operations_kind_request_unique
                    ON admission_operations(kind, request_id);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_admission_operations_budget_hold_id
                    ON admission_operations(budget_hold_id)
                    WHERE budget_hold_id IS NOT NULL;

                CREATE TABLE IF NOT EXISTS admission_cleanup_actions (
                    action_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL,
                    request_binding_hash TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    state TEXT NOT NULL,
                    claim_token TEXT,
                    claim_deadline_unix_ms INTEGER,
                    version INTEGER NOT NULL,
                    last_error TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE (operation_id, kind),
                    FOREIGN KEY (operation_id) REFERENCES admission_operations(operation_id),
                    CHECK (version >= 0),
                    CHECK (claim_deadline_unix_ms IS NULL OR claim_deadline_unix_ms >= 0),
                    CHECK (
                        (state = 'claimed' AND claim_token IS NOT NULL AND claim_deadline_unix_ms IS NOT NULL)
                        OR
                        (state IN ('pending', 'completed') AND claim_token IS NULL AND claim_deadline_unix_ms IS NULL)
                    )
                );

                CREATE INDEX IF NOT EXISTS idx_admission_cleanup_pending
                    ON admission_cleanup_actions(state, operation_id, updated_at);
                "#,
            )
            .map_err(sqlite_error)?;
        if let Some(database_identity_file) = database_identity_file.as_ref() {
            database_identity_file
                .validate_live_connection(&connection)
                .map_err(|error| AdmissionOperationError::Unavailable(error.to_string()))?;
        }
        Ok(Self {
            connection: Mutex::new(connection),
            authority_profile,
            database_identity_file,
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, AdmissionOperationError> {
        let connection = self.connection.lock().map_err(|_| {
            AdmissionOperationError::Unavailable(
                "sqlite admission operation lock poisoned".to_string(),
            )
        })?;
        if let Some(database_identity_file) = self.database_identity_file.as_ref() {
            database_identity_file
                .validate_live_connection(&connection)
                .map_err(|error| AdmissionOperationError::Unavailable(error.to_string()))?;
        }
        Ok(connection)
    }

    fn mutate_claimed_cleanup_action<F>(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
        mutation: F,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError>
    where
        F: FnOnce(
            &AdmissionCleanupAction,
        ) -> Result<AdmissionCleanupAction, AdmissionOperationError>,
    {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_cleanup_action(&transaction, action_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionCasOutcome::Missing);
        };
        if current.version() != expected_version || current.claim_token() != Some(claim_token) {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionCasOutcome::Conflict(current));
        }
        let next = mutation(&current)?;
        persist_cleanup_transition(&transaction, &current, &next, Some(claim_token))?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionCleanupActionCasOutcome::Applied(next))
    }
}

impl AdmissionOperationStore for SqliteAdmissionOperationStore {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        self.authority_profile
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        if operation.state() != AdmissionOperationState::Prepared
            || operation.dispatch_state() != AdmissionDispatchState::NotStarted
            || operation.version() != 0
        {
            return Err(AdmissionOperationError::Invalid(
                "new admission operation is not Prepared at version zero".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        if let Some(existing) = load_operation(&transaction, operation.operation_id())? {
            transaction.rollback().map_err(sqlite_error)?;
            if existing.has_same_prepared_binding(&operation) {
                return Ok(AdmissionOperationCreateOutcome::Existing(existing));
            }
            return Err(AdmissionOperationError::Invalid(
                "operation_id is already bound to different input".to_string(),
            ));
        }
        let existing_request_operation_id = transaction
            .query_row(
                r#"
                SELECT operation_id
                FROM admission_operations
                WHERE kind = ?1 AND request_id = ?2
                LIMIT 1
                "#,
                params![operation.kind().as_str(), operation.request_id()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing_operation_id) = existing_request_operation_id {
            let existing =
                load_operation(&transaction, &existing_operation_id)?.ok_or_else(|| {
                    AdmissionOperationError::Unavailable(
                        "request-id admission owner disappeared during create".to_string(),
                    )
                })?;
            transaction.rollback().map_err(sqlite_error)?;
            if existing.has_same_prepared_binding(&operation) {
                return Ok(AdmissionOperationCreateOutcome::Existing(existing));
            }
            return Err(AdmissionOperationError::Conflict(format!(
                "request_id `{}` is already owned by another {} operation",
                operation.request_id(),
                operation.kind().as_str()
            )));
        }
        if let Some(budget_hold_id) = operation.budget_hold_id() {
            if load_operation_by_budget_hold_id(&transaction, budget_hold_id)?.is_some() {
                transaction.rollback().map_err(sqlite_error)?;
                return Err(AdmissionOperationError::Invalid(format!(
                    "budget_hold_id `{budget_hold_id}` is already owned by another admission operation"
                )));
            }
        }
        insert_operation(&transaction, &operation)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionOperationCreateOutcome::Created(operation))
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        let connection = self.connection()?;
        load_operation(&connection, operation_id)
    }

    fn load_by_request_id(
        &self,
        kind: AdmissionOperationKind,
        request_id: &str,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if request_id.is_empty()
            || request_id.len() > 512
            || request_id.bytes().any(|byte| byte == 0)
        {
            return Err(AdmissionOperationError::Invalid(
                "request_id is invalid".to_string(),
            ));
        }
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow(
                "request-id admission lookup limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT operation_id
                FROM admission_operations
                WHERE kind = ?1 AND request_id = ?2
                ORDER BY operation_id ASC
                LIMIT ?3
                "#,
            )
            .map_err(sqlite_error)?;
        let operation_ids = statement
            .query_map(params![kind.as_str(), request_id, limit], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        operation_ids
            .into_iter()
            .map(|operation_id| {
                load_operation(&connection, &operation_id)?.ok_or_else(|| {
                    AdmissionOperationError::Unavailable(
                        "admission operation disappeared during request-id lookup".to_string(),
                    )
                })
            })
            .collect()
    }

    fn load_by_budget_hold_id(
        &self,
        budget_hold_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        if budget_hold_id.is_empty()
            || budget_hold_id.len() > 512
            || budget_hold_id.bytes().any(|byte| byte == 0)
        {
            return Err(AdmissionOperationError::Invalid(
                "budget_hold_id is invalid".to_string(),
            ));
        }
        let connection = self.connection()?;
        load_operation_by_budget_hold_id(&connection, budget_hold_id)
    }

    fn list_unresolved(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow(
                "unresolved admission operation inventory limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let operation_ids = if let Some(kind) = kind {
            let mut statement = connection
                .prepare(
                    r#"
                    SELECT operation_id
                    FROM admission_operations
                    WHERE kind = ?1
                      AND state NOT IN ('completed', 'compensated_before_dispatch')
                    ORDER BY updated_at ASC, operation_id ASC
                    LIMIT ?2
                    "#,
                )
                .map_err(sqlite_error)?;
            let operation_ids = statement
                .query_map(params![kind.as_str(), limit], |row| row.get::<_, String>(0))
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            operation_ids
        } else {
            let mut statement = connection
                .prepare(
                    r#"
                    SELECT operation_id
                    FROM admission_operations
                    WHERE state NOT IN ('completed', 'compensated_before_dispatch')
                    ORDER BY updated_at ASC, operation_id ASC
                    LIMIT ?1
                    "#,
                )
                .map_err(sqlite_error)?;
            let operation_ids = statement
                .query_map(params![limit], |row| row.get::<_, String>(0))
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            operation_ids
        };
        operation_ids
            .into_iter()
            .map(|operation_id| {
                load_operation(&connection, &operation_id)?.ok_or_else(|| {
                    AdmissionOperationError::Unavailable(
                        "admission operation disappeared during unresolved inventory".to_string(),
                    )
                })
            })
            .collect()
    }

    fn list_admission_recovery_candidates(
        &self,
        kind: AdmissionOperationKind,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow(
                "prioritized admission recovery limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT operation.operation_id
                FROM admission_operations AS operation
                LEFT JOIN admission_cleanup_actions AS handoff
                  ON handoff.operation_id = operation.operation_id
                 AND handoff.kind = 'caller_reservation_handoff'
                WHERE operation.kind = ?1
                  AND operation.state NOT IN (
                    'completed',
                    'compensated_before_dispatch',
                    'outcome_unknown_after_dispatch'
                  )
                ORDER BY CASE
                    WHEN operation.state != 'caller_reserved' THEN 0
                    WHEN handoff.state IS NULL OR handoff.state != 'completed' THEN 1
                    ELSE 2
                  END ASC,
                  operation.updated_at ASC,
                  operation.operation_id ASC
                LIMIT ?2
                "#,
            )
            .map_err(sqlite_error)?;
        let operation_ids = statement
            .query_map(params![kind.as_str(), limit], |row| row.get::<_, String>(0))
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        operation_ids
            .into_iter()
            .map(|operation_id| {
                load_operation(&connection, &operation_id)?.ok_or_else(|| {
                    AdmissionOperationError::Unavailable(
                        "admission operation disappeared during prioritized recovery inventory"
                            .to_string(),
                    )
                })
            })
            .collect()
    }

    fn list_caller_reservation_reap_candidates(
        &self,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AdmissionOperation>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow(
                "caller reservation reap inventory limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT operation.operation_id
                FROM admission_operations AS operation
                WHERE operation.kind = 'tool_dispatch'
                  AND (
                    (operation.state = 'caller_reserved'
                     AND operation.dispatch_state = 'committed')
                    OR
                    (operation.state = 'caller_reservation_capture_pending'
                     AND operation.dispatch_state = 'not_started')
                  )
                  AND (?1 IS NULL OR operation.operation_id > ?1)
                ORDER BY operation.operation_id ASC
                LIMIT ?2
                "#,
            )
            .map_err(sqlite_error)?;
        let operation_ids = statement
            .query_map(params![after_operation_id, limit], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        operation_ids
            .into_iter()
            .map(|operation_id| {
                load_operation(&connection, &operation_id)?.ok_or_else(|| {
                    AdmissionOperationError::Unavailable(
                        "admission operation disappeared during caller reservation reap inventory"
                            .to_string(),
                    )
                })
            })
            .collect()
    }

    fn claim_recovery(
        &self,
        operation_id: &str,
        expected_version: u64,
        expected_coordinator_lease_epoch: u64,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_operation(&transaction, operation_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version() != expected_version
            || current.coordinator_lease_epoch() != expected_coordinator_lease_epoch
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        let claimed = current.claim_recovery_checked()?;
        let updated = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET coordinator_lease_epoch = ?4,
                    version = ?5,
                    updated_at = ?6
                WHERE operation_id = ?1
                  AND version = ?2
                  AND coordinator_lease_epoch = ?3
                "#,
                params![
                    operation_id,
                    sqlite_integer(expected_version, "expected version")?,
                    sqlite_integer(
                        expected_coordinator_lease_epoch,
                        "expected coordinator lease epoch"
                    )?,
                    sqlite_integer(
                        claimed.coordinator_lease_epoch(),
                        "claimed coordinator lease epoch"
                    )?,
                    sqlite_integer(claimed.version(), "claimed version")?,
                    unix_now(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            let latest = load_operation(&transaction, operation_id)?.ok_or_else(|| {
                AdmissionOperationError::Unavailable(
                    "admission operation disappeared during recovery claim".to_string(),
                )
            })?;
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(latest));
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionOperationCasOutcome::Applied(claimed))
    }

    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        coordinator_authority_id: &str,
    ) -> Result<u64, AdmissionOperationError> {
        let connection = self.connection()?;
        let count: i64 = connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM admission_operations
                WHERE kind = ?1
                  AND coordinator_authority_id = ?2
                  AND state NOT IN ('completed', 'compensated_before_dispatch')
                "#,
                params![kind.as_str(), coordinator_authority_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        u64::try_from(count).map_err(|_| {
            AdmissionOperationError::Invalid(
                "sqlite returned a negative nonterminal operation count".to_string(),
            )
        })
    }

    fn count_unresolved(
        &self,
        kind: AdmissionOperationKind,
    ) -> Result<u64, AdmissionOperationError> {
        let connection = self.connection()?;
        let count: i64 = connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM admission_operations
                WHERE kind = ?1
                  AND state NOT IN ('completed', 'compensated_before_dispatch')
                "#,
                params![kind.as_str()],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        u64::try_from(count).map_err(|_| {
            AdmissionOperationError::Invalid(
                "sqlite returned a negative nonterminal operation count".to_string(),
            )
        })
    }

    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if request.next_state == AdmissionOperationState::CompensationPending
            || request.next_state == AdmissionOperationState::CallerReserved
            || request.next_state.is_terminal()
        {
            return Err(AdmissionOperationError::Invalid(
                "compensation, caller-reserved, and terminal admission transitions require an atomic forward action"
                    .to_string(),
            ));
        }
        let AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        } = request;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_operation(&transaction, operation_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version() != expected_version
            || current.coordinator_lease_epoch() != coordinator_lease_epoch
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        let next = current.transition_checked(
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        )?;
        let updated = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET state = ?4,
                    dispatch_state = ?5,
                    coordinator_lease_epoch = ?6,
                    version = ?7,
                    last_error = ?8,
                    updated_at = ?9
                WHERE operation_id = ?1
                  AND version = ?2
                  AND coordinator_lease_epoch = ?3
                "#,
                params![
                    operation_id,
                    sqlite_integer(expected_version, "expected version")?,
                    sqlite_integer(coordinator_lease_epoch, "coordinator lease epoch")?,
                    next.state().as_str(),
                    next.dispatch_state().as_str(),
                    sqlite_integer(
                        next.coordinator_lease_epoch(),
                        "next coordinator lease epoch"
                    )?,
                    sqlite_integer(next.version(), "next version")?,
                    next.last_error(),
                    unix_now(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            let latest = load_operation(&transaction, operation_id)?.ok_or_else(|| {
                AdmissionOperationError::Unavailable(
                    "admission operation disappeared during compare-and-swap".to_string(),
                )
            })?;
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(latest));
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionOperationCasOutcome::Applied(next))
    }

    fn compare_and_swap_with_cleanup_action(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if action.state() != AdmissionCleanupActionState::Pending || action.version() != 0 {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action is not Pending at version zero".to_string(),
            ));
        }
        let required_action_kind = if request.next_state
            == AdmissionOperationState::CompensationPending
            || request.next_state.is_terminal()
        {
            Some(AdmissionCleanupActionKind::TerminalReceipt)
        } else if request.next_state == AdmissionOperationState::CallerReserved {
            Some(AdmissionCleanupActionKind::CallerReservationHandoff)
        } else {
            None
        };
        if required_action_kind != Some(action.kind()) {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission transition has the wrong forward action kind for its target state"
                    .to_string(),
            ));
        }
        let AdmissionOperationCompareAndSwap {
            operation_id,
            expected_version,
            coordinator_lease_epoch,
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        } = request;
        if action.operation_id() != operation_id {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action references a different operation".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_operation(&transaction, operation_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Missing);
        };
        if current.version() != expected_version
            || current.coordinator_lease_epoch() != coordinator_lease_epoch
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(current));
        }
        if current.request_binding_hash() != action.request_binding_hash() {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal action request binding differs from its operation"
                    .to_string(),
            ));
        }
        if action.kind() == AdmissionCleanupActionKind::CallerReservationHandoff
            && (current.kind() != AdmissionOperationKind::ToolDispatch
                || current.state() != AdmissionOperationState::CallerReservationCapturePending
                || current.dispatch_state() != AdmissionDispatchState::NotStarted
                || next_state != AdmissionOperationState::CallerReserved
                || next_dispatch_state != AdmissionDispatchState::Committed)
        {
            return Err(AdmissionOperationError::Invalid(
                "caller reservation handoff requires the exact capture-pending to caller-reserved edge"
                    .to_string(),
            ));
        }
        let existing =
            load_cleanup_action_by_participant(&transaction, action.operation_id(), action.kind())?;
        if existing
            .as_ref()
            .is_some_and(|existing| existing != &action)
        {
            return Err(AdmissionOperationError::Invalid(
                "atomic admission journal participant is already bound to a different payload"
                    .to_string(),
            ));
        }
        let next = current.transition_checked(
            next_state,
            next_dispatch_state,
            next_coordinator_lease_epoch,
            last_error,
        )?;
        let updated = transaction
            .execute(
                r#"
                UPDATE admission_operations
                SET state = ?4,
                    dispatch_state = ?5,
                    coordinator_lease_epoch = ?6,
                    version = ?7,
                    last_error = ?8,
                    updated_at = ?9
                WHERE operation_id = ?1
                  AND version = ?2
                  AND coordinator_lease_epoch = ?3
                "#,
                params![
                    operation_id,
                    sqlite_integer(expected_version, "expected version")?,
                    sqlite_integer(coordinator_lease_epoch, "coordinator lease epoch")?,
                    next.state().as_str(),
                    next.dispatch_state().as_str(),
                    sqlite_integer(
                        next.coordinator_lease_epoch(),
                        "next coordinator lease epoch"
                    )?,
                    sqlite_integer(next.version(), "next version")?,
                    next.last_error(),
                    unix_now(),
                ],
            )
            .map_err(sqlite_error)?;
        if updated != 1 {
            let latest = load_operation(&transaction, operation_id)?.ok_or_else(|| {
                AdmissionOperationError::Unavailable(
                    "admission operation disappeared during atomic journal transition".to_string(),
                )
            })?;
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionOperationCasOutcome::Conflict(latest));
        }
        if existing.is_none() {
            insert_cleanup_action(&transaction, &action)?;
        }
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionOperationCasOutcome::Applied(next))
    }

    fn create_cleanup_action(
        &self,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionCleanupActionCreateOutcome, AdmissionOperationError> {
        if action.state() != AdmissionCleanupActionState::Pending || action.version() != 0 {
            return Err(AdmissionOperationError::Invalid(
                "new admission cleanup action is not Pending at version zero".to_string(),
            ));
        }
        if action.kind() == AdmissionCleanupActionKind::CallerReservationHandoff {
            return Err(AdmissionOperationError::Invalid(
                "caller reservation final handoff must be inserted by its atomic state transition"
                    .to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let operation = load_operation(&transaction, action.operation_id())?.ok_or_else(|| {
            AdmissionOperationError::Invalid(
                "cleanup action references a missing admission operation".to_string(),
            )
        })?;
        if operation.request_binding_hash() != action.request_binding_hash() {
            return Err(AdmissionOperationError::Invalid(
                "cleanup action request binding differs from its operation".to_string(),
            ));
        }
        if action.kind() == AdmissionCleanupActionKind::CallerReservationHandoffIntent
            && (operation.kind() != AdmissionOperationKind::ToolDispatch
                || !matches!(
                    operation.state(),
                    AdmissionOperationState::BudgetAuthorized
                        | AdmissionOperationState::DelegatedBudgetReserved
                        | AdmissionOperationState::ReadyToDispatch
                )
                || operation.dispatch_state() != AdmissionDispatchState::NotStarted)
        {
            return Err(AdmissionOperationError::Invalid(
                "caller reservation handoff intent requires a pre-capture tool dispatch operation"
                    .to_string(),
            ));
        }
        if let Some(existing) =
            load_cleanup_action_by_participant(&transaction, action.operation_id(), action.kind())?
        {
            transaction.rollback().map_err(sqlite_error)?;
            if existing == action {
                return Ok(AdmissionCleanupActionCreateOutcome::Existing(existing));
            }
            return Err(AdmissionOperationError::Invalid(
                "cleanup participant is already bound to a different immutable projection"
                    .to_string(),
            ));
        }
        insert_cleanup_action(&transaction, &action)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionCleanupActionCreateOutcome::Created(action))
    }

    fn load_cleanup_actions(
        &self,
        operation_id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT action_id, operation_id, request_binding_hash, kind,
                       payload_json, payload_hash, state, claim_token,
                       claim_deadline_unix_ms, version, last_error
                FROM admission_cleanup_actions
                WHERE operation_id = ?1
                ORDER BY kind ASC
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(params![operation_id], cleanup_action_row)
            .map_err(sqlite_error)?;
        let mut actions = Vec::new();
        for row in rows {
            actions.push(parse_cleanup_action(row.map_err(sqlite_error)?)?);
        }
        Ok(actions)
    }

    fn list_compensated_with_pending_cleanup(
        &self,
        kind: Option<AdmissionOperationKind>,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow("cleanup recovery limit exceeds i64".to_string())
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT DISTINCT operation.operation_id
                FROM admission_operations AS operation
                INNER JOIN admission_cleanup_actions AS cleanup
                    ON cleanup.operation_id = operation.operation_id
                WHERE operation.state IN (
                    'compensation_pending',
                    'compensated_before_dispatch'
                )
                  AND cleanup.state != 'completed'
                  AND cleanup.kind NOT IN (
                      'caller_reservation_handoff_intent',
                      'caller_reservation_handoff'
                  )
                  AND (?1 IS NULL OR operation.kind = ?1)
                ORDER BY operation.updated_at ASC, operation.operation_id ASC
                LIMIT ?2
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![kind.map(AdmissionOperationKind::as_str), limit],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut operation_ids = Vec::new();
        for row in rows {
            operation_ids.push(row.map_err(sqlite_error)?);
        }
        Ok(operation_ids)
    }

    fn list_operations_with_pending_cleanup_action(
        &self,
        operation_kind: AdmissionOperationKind,
        action_kind: AdmissionCleanupActionKind,
        limit: usize,
    ) -> Result<Vec<String>, AdmissionOperationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            AdmissionOperationError::Overflow(
                "pending admission journal inventory limit exceeds i64".to_string(),
            )
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT DISTINCT operation.operation_id
                FROM admission_operations AS operation
                INNER JOIN admission_cleanup_actions AS cleanup
                    ON cleanup.operation_id = operation.operation_id
                WHERE operation.kind = ?1
                  AND cleanup.kind = ?2
                  AND cleanup.state != 'completed'
                  AND NOT (
                      cleanup.kind = 'terminal_receipt'
                      AND operation.state = 'compensation_pending'
                  )
                ORDER BY operation.updated_at ASC, operation.operation_id ASC
                LIMIT ?3
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![operation_kind.as_str(), action_kind.as_str(), limit],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?;
        let mut operation_ids = Vec::new();
        for row in rows {
            operation_ids.push(row.map_err(sqlite_error)?);
        }
        Ok(operation_ids)
    }

    fn claim_cleanup_action(
        &self,
        action_id: &str,
        claim_token: &str,
        now_unix_ms: u64,
        claim_deadline_unix_ms: u64,
    ) -> Result<AdmissionCleanupActionClaimOutcome, AdmissionOperationError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let Some(current) = load_cleanup_action(&transaction, action_id)? else {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionClaimOutcome::Missing);
        };
        if current.state() == AdmissionCleanupActionState::Completed {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionClaimOutcome::Completed(current));
        }
        if current.state() == AdmissionCleanupActionState::Claimed
            && current.claim_token() != Some(claim_token)
            && current
                .claim_deadline_unix_ms()
                .is_some_and(|deadline| deadline > now_unix_ms)
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionClaimOutcome::Busy(current));
        }
        if current.state() == AdmissionCleanupActionState::Claimed
            && current.claim_token() == Some(claim_token)
            && current
                .claim_deadline_unix_ms()
                .is_some_and(|deadline| deadline > now_unix_ms)
        {
            transaction.rollback().map_err(sqlite_error)?;
            return Ok(AdmissionCleanupActionClaimOutcome::Claimed(current));
        }
        let next =
            current.claim_checked(claim_token.to_string(), now_unix_ms, claim_deadline_unix_ms)?;
        persist_cleanup_transition(&transaction, &current, &next, current.claim_token())?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(AdmissionCleanupActionClaimOutcome::Claimed(next))
    }

    fn acknowledge_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        self.mutate_claimed_cleanup_action(
            action_id,
            expected_version,
            claim_token,
            AdmissionCleanupAction::acknowledge_checked,
        )
    }

    fn abandon_cleanup_action(
        &self,
        action_id: &str,
        expected_version: u64,
        claim_token: &str,
        last_error: String,
    ) -> Result<AdmissionCleanupActionCasOutcome, AdmissionOperationError> {
        self.mutate_claimed_cleanup_action(action_id, expected_version, claim_token, |action| {
            action.abandon_checked(last_error)
        })
    }
}

fn insert_operation(
    connection: &Connection,
    operation: &AdmissionOperation,
) -> Result<(), AdmissionOperationError> {
    connection
        .execute(
            r#"
            INSERT INTO admission_operations (
                operation_id, kind, coordinator_authority_id, request_id,
                capability_id, authorization_capability_hash,
                request_binding_hash, policy_hash, broker_attempt_id,
                budget_hold_id, approval_set_hash, execution_nonce_id,
                state, dispatch_state, coordinator_lease_epoch,
                version, last_error, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
            )
            "#,
            params![
                operation.operation_id(),
                operation.kind().as_str(),
                operation.coordinator_authority_id(),
                operation.request_id(),
                operation.capability_id(),
                operation.authorization_capability_hash(),
                operation.request_binding_hash(),
                operation.policy_hash(),
                operation.broker_attempt_id(),
                operation.budget_hold_id(),
                operation.approval_set_hash(),
                operation.execution_nonce_id(),
                operation.state().as_str(),
                operation.dispatch_state().as_str(),
                sqlite_integer(
                    operation.coordinator_lease_epoch(),
                    "coordinator lease epoch"
                )?,
                sqlite_integer(operation.version(), "version")?,
                operation.last_error(),
                unix_now(),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

#[allow(clippy::type_complexity)]
fn load_operation(
    connection: &Connection,
    operation_id: &str,
) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
    type StoredOperation = (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        i64,
        i64,
        Option<String>,
    );
    let row: Option<StoredOperation> = connection
        .query_row(
            r#"
            SELECT operation_id, kind, coordinator_authority_id, request_id,
                   capability_id, authorization_capability_hash,
                   request_binding_hash, policy_hash, broker_attempt_id,
                   budget_hold_id, approval_set_hash, execution_nonce_id,
                   state, dispatch_state, coordinator_lease_epoch,
                   version, last_error
            FROM admission_operations
            WHERE operation_id = ?1
            "#,
            params![operation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let kind = AdmissionOperationKind::parse(&row.1).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!("unknown persisted operation kind `{}`", row.1))
    })?;
    let state = AdmissionOperationState::parse(&row.12).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!("unknown persisted admission state `{}`", row.12))
    })?;
    let dispatch_state = AdmissionDispatchState::parse(&row.13).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!("unknown persisted dispatch state `{}`", row.13))
    })?;
    let coordinator_lease_epoch = nonnegative_u64(row.14, "coordinator_lease_epoch")?;
    let version = nonnegative_u64(row.15, "version")?;
    Ok(Some(AdmissionOperation::from_persisted_parts(
        PersistedAdmissionOperation {
            kind,
            operation_id: row.0,
            coordinator_authority_id: row.2,
            request_id: row.3,
            capability_id: row.4,
            authorization_capability_hash: row.5,
            request_binding_hash: row.6,
            policy_hash: row.7,
            broker_attempt_id: row.8,
            budget_hold_id: row.9,
            approval_set_hash: row.10,
            execution_nonce_id: row.11,
            state,
            dispatch_state,
            coordinator_lease_epoch,
            version,
            last_error: row.16,
        },
    )?))
}

fn load_operation_by_budget_hold_id(
    connection: &Connection,
    budget_hold_id: &str,
) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
    let operation_id = connection
        .query_row(
            r#"
            SELECT operation_id
            FROM admission_operations
            WHERE budget_hold_id = ?1
            "#,
            params![budget_hold_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some(operation_id) = operation_id else {
        return Ok(None);
    };
    let operation = load_operation(connection, &operation_id)?.ok_or_else(|| {
        AdmissionOperationError::Invalid(format!(
            "budget_hold_id `{budget_hold_id}` indexed a missing admission operation"
        ))
    })?;
    if operation.budget_hold_id() != Some(budget_hold_id) {
        return Err(AdmissionOperationError::Invalid(format!(
            "budget_hold_id `{budget_hold_id}` index returned a different immutable binding"
        )));
    }
    Ok(Some(operation))
}

type StoredCleanupAction = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<i64>,
    i64,
    Option<String>,
);

fn cleanup_action_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredCleanupAction> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn parse_cleanup_action(
    row: StoredCleanupAction,
) -> Result<AdmissionCleanupAction, AdmissionOperationError> {
    let kind = AdmissionCleanupActionKind::parse(&row.3).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!(
            "unknown persisted admission cleanup kind `{}`",
            row.3
        ))
    })?;
    let state = AdmissionCleanupActionState::parse(&row.6).ok_or_else(|| {
        AdmissionOperationError::Invalid(format!(
            "unknown persisted admission cleanup state `{}`",
            row.6
        ))
    })?;
    let claim_deadline_unix_ms = row
        .8
        .map(|value| nonnegative_u64(value, "cleanup claim_deadline_unix_ms"))
        .transpose()?;
    let version = nonnegative_u64(row.9, "cleanup version")?;
    AdmissionCleanupAction::from_persisted_parts(PersistedAdmissionCleanupAction {
        action_id: row.0,
        operation_id: row.1,
        request_binding_hash: row.2,
        kind,
        payload_json: row.4,
        payload_hash: row.5,
        state,
        claim_token: row.7,
        claim_deadline_unix_ms,
        version,
        last_error: row.10,
    })
}

fn load_cleanup_action(
    connection: &Connection,
    action_id: &str,
) -> Result<Option<AdmissionCleanupAction>, AdmissionOperationError> {
    let row = connection
        .query_row(
            r#"
            SELECT action_id, operation_id, request_binding_hash, kind,
                   payload_json, payload_hash, state, claim_token,
                   claim_deadline_unix_ms, version, last_error
            FROM admission_cleanup_actions
            WHERE action_id = ?1
            "#,
            params![action_id],
            cleanup_action_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    row.map(parse_cleanup_action).transpose()
}

fn load_cleanup_action_by_participant(
    connection: &Connection,
    operation_id: &str,
    kind: AdmissionCleanupActionKind,
) -> Result<Option<AdmissionCleanupAction>, AdmissionOperationError> {
    let row = connection
        .query_row(
            r#"
            SELECT action_id, operation_id, request_binding_hash, kind,
                   payload_json, payload_hash, state, claim_token,
                   claim_deadline_unix_ms, version, last_error
            FROM admission_cleanup_actions
            WHERE operation_id = ?1 AND kind = ?2
            "#,
            params![operation_id, kind.as_str()],
            cleanup_action_row,
        )
        .optional()
        .map_err(sqlite_error)?;
    row.map(parse_cleanup_action).transpose()
}

fn insert_cleanup_action(
    connection: &Connection,
    action: &AdmissionCleanupAction,
) -> Result<(), AdmissionOperationError> {
    connection
        .execute(
            r#"
            INSERT INTO admission_cleanup_actions (
                action_id, operation_id, request_binding_hash, kind,
                payload_json, payload_hash, state, claim_token,
                claim_deadline_unix_ms, version, last_error,
                created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12
            )
            "#,
            params![
                action.action_id(),
                action.operation_id(),
                action.request_binding_hash(),
                action.kind().as_str(),
                action.payload_json(),
                action.payload_hash(),
                action.state().as_str(),
                action.claim_token(),
                action
                    .claim_deadline_unix_ms()
                    .map(|value| sqlite_integer(value, "cleanup claim deadline"))
                    .transpose()?,
                sqlite_integer(action.version(), "cleanup version")?,
                action.last_error(),
                unix_now(),
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

fn persist_cleanup_transition(
    connection: &Connection,
    current: &AdmissionCleanupAction,
    next: &AdmissionCleanupAction,
    expected_claim_token: Option<&str>,
) -> Result<(), AdmissionOperationError> {
    let updated = connection
        .execute(
            r#"
            UPDATE admission_cleanup_actions
            SET state = ?4,
                claim_token = ?5,
                claim_deadline_unix_ms = ?6,
                version = ?7,
                last_error = ?8,
                updated_at = ?9
            WHERE action_id = ?1
              AND version = ?2
              AND claim_token IS ?3
            "#,
            params![
                current.action_id(),
                sqlite_integer(current.version(), "cleanup expected version")?,
                expected_claim_token,
                next.state().as_str(),
                next.claim_token(),
                next.claim_deadline_unix_ms()
                    .map(|value| sqlite_integer(value, "cleanup claim deadline"))
                    .transpose()?,
                sqlite_integer(next.version(), "cleanup next version")?,
                next.last_error(),
                unix_now(),
            ],
        )
        .map_err(sqlite_error)?;
    if updated != 1 {
        return Err(AdmissionOperationError::Unavailable(
            "cleanup action changed during fenced transition".to_string(),
        ));
    }
    Ok(())
}

fn sqlite_integer(value: u64, label: &str) -> Result<i64, AdmissionOperationError> {
    i64::try_from(value)
        .map_err(|_| AdmissionOperationError::Overflow(format!("{label} exceeds SQLite INTEGER")))
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64, AdmissionOperationError> {
    u64::try_from(value)
        .map_err(|_| AdmissionOperationError::Invalid(format!("persisted {label} is negative")))
}

fn sqlite_error(error: rusqlite::Error) -> AdmissionOperationError {
    AdmissionOperationError::Unavailable(format!("sqlite admission operation error: {error}"))
}

fn reject_volatile_database_path(path: &Path) -> Result<(), AdmissionOperationError> {
    let path = path.to_string_lossy();
    let lower = path.to_ascii_lowercase();
    let memory_uri = lower.starts_with("file:")
        && (lower.contains("?mode=memory") || lower.contains("&mode=memory"));
    if path.is_empty() || path == ":memory:" || memory_uri || lower.starts_with("file::memory:") {
        return Err(AdmissionOperationError::Invalid(
            "volatile SQLite admission-operation paths are not durable; use open_in_memory for an explicitly ephemeral store"
                .to_string(),
        ));
    }
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}
