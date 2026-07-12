use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_kernel::{
    AdmissionDispatchState, AdmissionOperation, AdmissionOperationCasOutcome,
    AdmissionOperationCreateOutcome, AdmissionOperationError, AdmissionOperationKind,
    AdmissionOperationState, AdmissionOperationStore,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub struct SqliteAdmissionOperationStore {
    connection: Mutex<Connection>,
}

impl SqliteAdmissionOperationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AdmissionOperationError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AdmissionOperationError::Unavailable(format!(
                    "failed to prepare admission operation directory: {error}"
                ))
            })?;
        }
        let connection = Connection::open(path).map_err(sqlite_error)?;
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

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
                "#,
            )
            .map_err(sqlite_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, AdmissionOperationError> {
        self.connection.lock().map_err(|_| {
            AdmissionOperationError::Unavailable(
                "sqlite admission operation lock poisoned".to_string(),
            )
        })
    }
}

impl AdmissionOperationStore for SqliteAdmissionOperationStore {
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
            if existing == operation {
                return Ok(AdmissionOperationCreateOutcome::Existing(existing));
            }
            return Err(AdmissionOperationError::Invalid(
                "operation_id is already bound to different input".to_string(),
            ));
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

    fn compare_and_swap(
        &self,
        operation_id: &str,
        expected_version: u64,
        coordinator_lease_epoch: u64,
        next_state: AdmissionOperationState,
        next_dispatch_state: AdmissionDispatchState,
        next_coordinator_lease_epoch: u64,
        last_error: Option<String>,
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
        kind,
        row.0,
        row.2,
        row.3,
        row.4,
        row.5,
        row.6,
        row.7,
        row.8,
        row.9,
        row.10,
        row.11,
        state,
        dispatch_state,
        coordinator_lease_epoch,
        version,
        row.16,
    )?))
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

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_kernel::{AdmissionOperationKind, PreparedAdmissionOperation};

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn operation() -> AdmissionOperation {
        AdmissionOperation::prepared(PreparedAdmissionOperation {
            kind: AdmissionOperationKind::ToolDispatch,
            coordinator_authority_id: "coordinator-1".to_string(),
            request_id: "request-1".to_string(),
            capability_id: "capability-1".to_string(),
            authorization_capability_hash: "11".repeat(32),
            request_binding_hash: "22".repeat(32),
            policy_hash: "33".repeat(32),
            broker_attempt_id: Some("attempt-1".to_string()),
            budget_hold_id: Some("hold-1".to_string()),
            approval_set_hash: Some("44".repeat(32)),
            execution_nonce_id: Some("nonce-1".to_string()),
            coordinator_lease_epoch: 7,
        })
        .unwrap()
    }

    #[test]
    fn admission_operation_survives_restart_and_exact_create_retry() {
        let path = unique_db_path("chio-admission-operation-restart");
        let operation = operation();
        {
            let store = SqliteAdmissionOperationStore::open(&path).unwrap();
            assert!(matches!(
                store.create_prepared(operation.clone()).unwrap(),
                AdmissionOperationCreateOutcome::Created(_)
            ));
        }
        let reopened = SqliteAdmissionOperationStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(operation.operation_id()).unwrap(),
            Some(operation.clone())
        );
        assert!(matches!(
            reopened.create_prepared(operation).unwrap(),
            AdmissionOperationCreateOutcome::Existing(_)
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn admission_operation_compare_and_swap_is_durable_and_fenced() {
        let path = unique_db_path("chio-admission-operation-cas");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        let applied = store
            .compare_and_swap(
                &operation_id,
                0,
                7,
                AdmissionOperationState::BrokerAttemptRegistered,
                AdmissionDispatchState::NotStarted,
                7,
                None,
            )
            .unwrap();
        assert!(matches!(applied, AdmissionOperationCasOutcome::Applied(_)));
        assert!(matches!(
            store
                .compare_and_swap(
                    &operation_id,
                    0,
                    7,
                    AdmissionOperationState::BudgetAuthorized,
                    AdmissionDispatchState::NotStarted,
                    7,
                    None,
                )
                .unwrap(),
            AdmissionOperationCasOutcome::Conflict(_)
        ));
        drop(store);
        assert_eq!(
            SqliteAdmissionOperationStore::open(&path)
                .unwrap()
                .load(&operation_id)
                .unwrap()
                .unwrap()
                .version(),
            1
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn admission_operation_rejects_corrupted_state() {
        let path = unique_db_path("chio-admission-operation-corrupt");
        let store = SqliteAdmissionOperationStore::open(&path).unwrap();
        let operation = operation();
        let operation_id = operation.operation_id().to_string();
        store.create_prepared(operation).unwrap();
        store
            .connection()
            .unwrap()
            .execute(
                "UPDATE admission_operations SET state = 'future_state' WHERE operation_id = ?1",
                params![operation_id],
            )
            .unwrap();
        assert!(matches!(
            store.load(&operation_id),
            Err(AdmissionOperationError::Invalid(_))
        ));
        let _ = fs::remove_file(path);
    }
}
