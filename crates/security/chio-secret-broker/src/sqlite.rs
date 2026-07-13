use std::fs::{self, OpenOptions};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use chio_core_types::canonical_json_bytes;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::budget::ExecutionQuota;
use crate::store::{
    AttemptIds, AttemptRecord, AttemptRegistration, AttemptState, AttemptStore,
    AttemptTransitionEvidence, RegisterAttemptOutcome,
};
use crate::{validate_digest, BrokerError, Result};

pub struct SqliteAttemptStore {
    connection: Mutex<Connection>,
}

impl SqliteAttemptStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| {
                    BrokerError::Storage(format!("attempt directory creation failed: {error}"))
                })?;
            }
        }
        prepare_private_database(path)?;
        let connection = Connection::open(path).map_err(storage)?;
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory().map_err(storage)?;
        let store = Self {
            connection: Mutex::new(connection),
        };
        store.migrate()?;
        Ok(store)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| BrokerError::Storage("attempt store lock is poisoned".to_string()))
    }

    fn migrate(&self) -> Result<()> {
        let connection = self.connection()?;
        connection
            .execute_batch(
                r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS broker_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    invocation_id TEXT NOT NULL,
                    parent_capability_id TEXT NOT NULL,
                    broker_capability_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    proof_digest TEXT NOT NULL,
                    proof_key_id TEXT NOT NULL,
                    proof_nonce TEXT NOT NULL,
                    nonce_expires_at INTEGER NOT NULL CHECK(nonce_expires_at >= 0),
                    hold_id TEXT NOT NULL UNIQUE,
                    authorize_event_id TEXT NOT NULL UNIQUE,
                    reverse_event_id TEXT NOT NULL UNIQUE,
                    capture_event_id TEXT NOT NULL UNIQUE,
                    quotas_json BLOB NOT NULL,
                    authority_metadata_digest TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'prepared', 'held', 'captured', 'dispatch_committed',
                        'reversed', 'unknown_outcome', 'completed', 'failed'
                    )),
                    revocation_set_digest TEXT,
                    budget_commit_index INTEGER,
                    revocation_commit_index INTEGER,
                    authority_commit_index INTEGER,
                    leader_epoch INTEGER,
                    response_digest TEXT,
                    updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
                ) STRICT;

                CREATE TABLE IF NOT EXISTS broker_nonces (
                    proof_key_id TEXT NOT NULL,
                    proof_nonce TEXT NOT NULL,
                    attempt_id TEXT NOT NULL UNIQUE,
                    expires_at INTEGER NOT NULL CHECK(expires_at >= 0),
                    PRIMARY KEY (proof_key_id, proof_nonce),
                    FOREIGN KEY (attempt_id) REFERENCES broker_attempts(attempt_id)
                        ON DELETE RESTRICT
                ) STRICT;

                CREATE INDEX IF NOT EXISTS idx_broker_attempts_recovery
                    ON broker_attempts(state, updated_at, attempt_id);
                "#,
            )
            .map_err(storage)
    }
}

fn prepare_private_database(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(BrokerError::Storage(
                "attempt database path is not a regular file".to_string(),
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(|error| {
        BrokerError::Storage(format!("attempt database creation failed: {error}"))
    })?;
    #[cfg(unix)]
    {
        let mode = file
            .metadata()
            .map_err(|error| {
                BrokerError::Storage(format!("attempt database metadata failed: {error}"))
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    BrokerError::Storage(format!("attempt database permissions failed: {error}"))
                })?;
        }
    }
    drop(file);
    Ok(())
}

impl AttemptStore for SqliteAttemptStore {
    fn register_attempt(
        &self,
        registration: &AttemptRegistration,
        now_unix_seconds: u64,
    ) -> Result<RegisterAttemptOutcome> {
        registration.validate()?;
        if now_unix_seconds > registration.nonce_expires_at_unix_seconds {
            return Err(BrokerError::AuthorizationDenied(
                "request proof nonce is already expired".to_string(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(storage)?;
        if let Some(existing) =
            load_attempt_in_transaction(&transaction, &registration.ids.attempt_id)?
        {
            if existing.registration != *registration {
                return Err(BrokerError::Conflict(
                    "deterministic attempt ID was reused with different input".to_string(),
                ));
            }
            transaction.commit().map_err(storage)?;
            return Ok(RegisterAttemptOutcome::ExactRetry(existing));
        }

        let claimed_attempt: Option<String> = transaction
            .query_row(
                "SELECT attempt_id FROM broker_nonces WHERE proof_key_id = ?1 AND proof_nonce = ?2",
                params![registration.proof_key_id, registration.proof_nonce],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if claimed_attempt.is_some() {
            return Err(BrokerError::AuthorizationDenied(
                "request proof nonce was already consumed".to_string(),
            ));
        }

        let quotas = canonical_json_bytes(&registration.quotas).map_err(|error| {
            BrokerError::Invariant(format!("attempt quota encoding failed: {error}"))
        })?;
        transaction
            .execute(
                r#"
                INSERT INTO broker_attempts (
                    attempt_id, operation_id, invocation_id, parent_capability_id,
                    broker_capability_id, request_digest, proof_digest, proof_key_id,
                    proof_nonce, nonce_expires_at, hold_id, authorize_event_id,
                    reverse_event_id, capture_event_id, quotas_json,
                    authority_metadata_digest, state, updated_at
                ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                    ?11, ?12, ?13, ?14, ?15, ?16, 'prepared', ?17
                )
                "#,
                params![
                    registration.ids.attempt_id,
                    registration.ids.operation_id,
                    registration.invocation_id,
                    registration.parent_capability_id,
                    registration.broker_capability_id,
                    registration.request_digest,
                    registration.proof_digest,
                    registration.proof_key_id,
                    registration.proof_nonce,
                    sqlite_u64(registration.nonce_expires_at_unix_seconds, "nonce expiry")?,
                    registration.ids.hold_id,
                    registration.ids.authorize_event_id,
                    registration.ids.reverse_event_id,
                    registration.ids.capture_event_id,
                    quotas,
                    registration.authority_metadata_digest,
                    sqlite_u64(now_unix_seconds, "attempt update time")?,
                ],
            )
            .map_err(storage)?;
        transaction
            .execute(
                r#"
                INSERT INTO broker_nonces (proof_key_id, proof_nonce, attempt_id, expires_at)
                VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    registration.proof_key_id,
                    registration.proof_nonce,
                    registration.ids.attempt_id,
                    sqlite_u64(registration.nonce_expires_at_unix_seconds, "nonce expiry")?,
                ],
            )
            .map_err(storage)?;
        let record = load_attempt_in_transaction(&transaction, &registration.ids.attempt_id)?
            .ok_or_else(|| {
                BrokerError::Invariant("inserted attempt could not be reloaded".to_string())
            })?;
        transaction.commit().map_err(storage)?;
        Ok(RegisterAttemptOutcome::Inserted(record))
    }

    fn load_attempt(&self, attempt_id: &str) -> Result<Option<AttemptRecord>> {
        let connection = self.connection()?;
        load_attempt_from_connection(&connection, attempt_id)
    }

    fn transition(
        &self,
        attempt_id: &str,
        expected: AttemptState,
        next: AttemptState,
        evidence: &AttemptTransitionEvidence,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord> {
        if !expected.permits(next) {
            return Err(BrokerError::Invariant(
                "requested attempt transition is not permitted".to_string(),
            ));
        }
        validate_transition_evidence(next, evidence)?;
        let mut connection = self.connection()?;
        let transaction = connection.transaction().map_err(storage)?;
        let current = load_attempt_in_transaction(&transaction, attempt_id)?
            .ok_or_else(|| BrokerError::Storage("broker attempt was not found".to_string()))?;
        if current.state == next {
            validate_repeated_evidence(&current, evidence)?;
            transaction.commit().map_err(storage)?;
            return Ok(current);
        }
        if current.state != expected {
            return Err(BrokerError::Conflict(format!(
                "attempt transition expected {} but found {}",
                expected.as_str(),
                current.state.as_str()
            )));
        }
        validate_existing_evidence(&current, evidence)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE broker_attempts
                SET state = ?1,
                    revocation_set_digest = COALESCE(?2, revocation_set_digest),
                    budget_commit_index = COALESCE(?3, budget_commit_index),
                    revocation_commit_index = COALESCE(?4, revocation_commit_index),
                    authority_commit_index = COALESCE(?5, authority_commit_index),
                    leader_epoch = COALESCE(?6, leader_epoch),
                    response_digest = COALESCE(?7, response_digest),
                    updated_at = ?8
                WHERE attempt_id = ?9 AND state = ?10
                "#,
                params![
                    next.as_str(),
                    evidence.revocation_set_digest,
                    evidence
                        .budget_commit_index
                        .map(|value| sqlite_u64(value, "budget index"))
                        .transpose()?,
                    evidence
                        .revocation_commit_index
                        .map(|value| sqlite_u64(value, "revocation index"))
                        .transpose()?,
                    evidence
                        .authority_commit_index
                        .map(|value| sqlite_u64(value, "authority index"))
                        .transpose()?,
                    evidence
                        .leader_epoch
                        .map(|value| sqlite_u64(value, "leader epoch"))
                        .transpose()?,
                    evidence.response_digest,
                    sqlite_u64(now_unix_seconds, "attempt update time")?,
                    attempt_id,
                    expected.as_str(),
                ],
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(BrokerError::Conflict(
                "attempt transition lost its compare-and-swap".to_string(),
            ));
        }
        let updated = load_attempt_in_transaction(&transaction, attempt_id)?
            .ok_or_else(|| BrokerError::Invariant("updated attempt disappeared".to_string()))?;
        transaction.commit().map_err(storage)?;
        Ok(updated)
    }

    fn recoverable_attempts(&self, limit: usize) -> Result<Vec<AttemptRecord>> {
        if limit == 0 || limit > 1_000 {
            return Err(BrokerError::InvalidRequest(
                "recovery batch limit is invalid".to_string(),
            ));
        }
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                r#"
                SELECT attempt_id
                FROM broker_attempts
                WHERE state IN ('prepared', 'held', 'captured', 'dispatch_committed', 'unknown_outcome')
                ORDER BY updated_at, attempt_id
                LIMIT ?1
                "#,
            )
            .map_err(storage)?;
        let attempt_ids = statement
            .query_map(
                [i64::try_from(limit).map_err(|_| {
                    BrokerError::InvalidRequest("recovery limit exceeds SQLite range".to_string())
                })?],
                |row| row.get::<_, String>(0),
            )
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?;
        let mut records = Vec::with_capacity(attempt_ids.len());
        for attempt_id in attempt_ids {
            records.push(
                load_attempt_from_connection(&connection, &attempt_id)?.ok_or_else(|| {
                    BrokerError::Invariant("recovery attempt disappeared".to_string())
                })?,
            );
        }
        Ok(records)
    }
}

fn load_attempt_in_transaction(
    transaction: &Transaction<'_>,
    attempt_id: &str,
) -> Result<Option<AttemptRecord>> {
    load_attempt_row(transaction, attempt_id)
}

fn load_attempt_from_connection(
    connection: &Connection,
    attempt_id: &str,
) -> Result<Option<AttemptRecord>> {
    load_attempt_row(connection, attempt_id)
}

fn load_attempt_row(connection: &Connection, attempt_id: &str) -> Result<Option<AttemptRecord>> {
    let row = connection
        .query_row(
            r#"
            SELECT attempt_id, operation_id, invocation_id, parent_capability_id,
                   broker_capability_id, request_digest, proof_digest, proof_key_id,
                   proof_nonce, nonce_expires_at, hold_id, authorize_event_id,
                   reverse_event_id, capture_event_id, quotas_json,
                   authority_metadata_digest, state, revocation_set_digest,
                   budget_commit_index, revocation_commit_index, authority_commit_index,
                   leader_epoch, response_digest, updated_at
            FROM broker_attempts
            WHERE attempt_id = ?1
            "#,
            [attempt_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                    row.get::<_, String>(15)?,
                    row.get::<_, String>(16)?,
                    row.get::<_, Option<String>>(17)?,
                    row.get::<_, Option<i64>>(18)?,
                    row.get::<_, Option<i64>>(19)?,
                    row.get::<_, Option<i64>>(20)?,
                    row.get::<_, Option<i64>>(21)?,
                    row.get::<_, Option<String>>(22)?,
                    row.get::<_, i64>(23)?,
                ))
            },
        )
        .optional()
        .map_err(storage)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let quotas: Vec<ExecutionQuota> = serde_json::from_slice(&row.14)
        .map_err(|error| BrokerError::Invariant(format!("stored quota set is invalid: {error}")))?;
    let record = AttemptRecord {
        registration: AttemptRegistration {
            ids: AttemptIds {
                attempt_id: row.0,
                operation_id: row.1,
                hold_id: row.10,
                authorize_event_id: row.11,
                reverse_event_id: row.12,
                capture_event_id: row.13,
            },
            invocation_id: row.2,
            parent_capability_id: row.3,
            broker_capability_id: row.4,
            request_digest: row.5,
            proof_digest: row.6,
            proof_key_id: row.7,
            proof_nonce: row.8,
            nonce_expires_at_unix_seconds: nonnegative_u64(row.9, "nonce expiry")?,
            quotas,
            authority_metadata_digest: row.15,
        },
        state: AttemptState::parse(&row.16)?,
        revocation_set_digest: row.17,
        budget_commit_index: optional_u64(row.18, "budget commit index")?,
        revocation_commit_index: optional_u64(row.19, "revocation commit index")?,
        authority_commit_index: optional_u64(row.20, "authority commit index")?,
        leader_epoch: optional_u64(row.21, "leader epoch")?,
        response_digest: row.22,
        updated_at_unix_seconds: nonnegative_u64(row.23, "attempt update time")?,
    };
    record.registration.validate()?;
    validate_record_evidence(&record)?;
    Ok(Some(record))
}

fn validate_repeated_evidence(
    current: &AttemptRecord,
    evidence: &AttemptTransitionEvidence,
) -> Result<()> {
    validate_existing_evidence(current, evidence)?;
    for (incoming, stored, label) in [
        (
            evidence.revocation_set_digest.as_ref(),
            current.revocation_set_digest.as_ref(),
            "revocation-set digest",
        ),
        (
            evidence.response_digest.as_ref(),
            current.response_digest.as_ref(),
            "response digest",
        ),
    ] {
        if incoming.is_some() && incoming != stored {
            return Err(BrokerError::Conflict(format!(
                "repeated transition changed {label}"
            )));
        }
    }
    Ok(())
}

fn validate_existing_evidence(
    current: &AttemptRecord,
    evidence: &AttemptTransitionEvidence,
) -> Result<()> {
    for (incoming, stored, label) in [
        (
            evidence.revocation_set_digest.as_ref(),
            current.revocation_set_digest.as_ref(),
            "revocation-set digest",
        ),
        (
            evidence.response_digest.as_ref(),
            current.response_digest.as_ref(),
            "response digest",
        ),
    ] {
        if stored.is_some() && incoming.is_some() && incoming != stored {
            return Err(BrokerError::Conflict(format!(
                "attempt transition changed {label}"
            )));
        }
    }
    for (incoming, stored, label) in [
        (
            evidence.budget_commit_index,
            current.budget_commit_index,
            "budget commit index",
        ),
        (
            evidence.revocation_commit_index,
            current.revocation_commit_index,
            "revocation commit index",
        ),
        (
            evidence.authority_commit_index,
            current.authority_commit_index,
            "authority commit index",
        ),
        (evidence.leader_epoch, current.leader_epoch, "leader epoch"),
    ] {
        if stored.is_some() && incoming.is_some() && incoming != stored {
            return Err(BrokerError::Conflict(format!(
                "attempt transition changed {label}"
            )));
        }
    }
    Ok(())
}

fn validate_transition_evidence(
    next: AttemptState,
    evidence: &AttemptTransitionEvidence,
) -> Result<()> {
    if let Some(digest) = &evidence.revocation_set_digest {
        validate_digest(digest, "transition revocation-set digest")?;
    }
    if let Some(digest) = &evidence.response_digest {
        validate_digest(digest, "transition response digest")?;
    }
    if matches!(
        next,
        AttemptState::Captured | AttemptState::DispatchCommitted | AttemptState::Completed
    ) && (evidence.revocation_set_digest.is_none()
        || evidence.budget_commit_index.is_none()
        || evidence.revocation_commit_index.is_none()
        || evidence.authority_commit_index.is_none()
        || evidence.leader_epoch.is_none())
    {
        return Err(BrokerError::Invariant(
            "captured transition lacks atomic authority evidence".to_string(),
        ));
    }
    if next == AttemptState::Completed && evidence.response_digest.is_none() {
        return Err(BrokerError::Invariant(
            "completed transition lacks a response digest".to_string(),
        ));
    }
    Ok(())
}

fn validate_record_evidence(record: &AttemptRecord) -> Result<()> {
    let evidence = AttemptTransitionEvidence {
        revocation_set_digest: record.revocation_set_digest.clone(),
        budget_commit_index: record.budget_commit_index,
        revocation_commit_index: record.revocation_commit_index,
        authority_commit_index: record.authority_commit_index,
        leader_epoch: record.leader_epoch,
        response_digest: record.response_digest.clone(),
    };
    validate_transition_evidence(record.state, &evidence)
}

fn storage(error: rusqlite::Error) -> BrokerError {
    BrokerError::Storage(format!("broker SQLite operation failed: {error}"))
}

fn sqlite_u64(value: u64, label: &str) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| BrokerError::InvalidRequest(format!("{label} exceeds SQLite range")))
}

fn nonnegative_u64(value: i64, label: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| BrokerError::Invariant(format!("stored {label} is negative")))
}

fn optional_u64(value: Option<i64>, label: &str) -> Result<Option<u64>> {
    value.map(|inner| nonnegative_u64(inner, label)).transpose()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::store::derive_attempt_ids;

    fn registration(nonce: &str) -> AttemptRegistration {
        let request_digest = "a".repeat(64);
        AttemptRegistration {
            ids: derive_attempt_ids("broker-cap", "invocation", nonce, &request_digest)
                .expect("ids"),
            invocation_id: "invocation".to_string(),
            parent_capability_id: "parent-cap".to_string(),
            broker_capability_id: "broker-cap".to_string(),
            request_digest,
            proof_digest: "b".repeat(64),
            proof_key_id: "proof-key".to_string(),
            proof_nonce: nonce.to_string(),
            nonce_expires_at_unix_seconds: 100,
            quotas: vec![ExecutionQuota {
                key_id: "broker-quota".to_string(),
                maximum_executions: 1,
            }],
            authority_metadata_digest: "c".repeat(64),
        }
    }

    #[test]
    fn nonce_and_prepared_intent_commit_atomically_and_retry_exactly() {
        let store = SqliteAttemptStore::open_in_memory().expect("store");
        let registration = registration("nonce-abcdefghijkl");
        assert!(matches!(
            store.register_attempt(&registration, 10).expect("insert"),
            RegisterAttemptOutcome::Inserted(_)
        ));
        assert!(matches!(
            store.register_attempt(&registration, 11).expect("retry"),
            RegisterAttemptOutcome::ExactRetry(_)
        ));
    }

    #[test]
    fn concurrent_replay_has_one_insert_and_exact_retries_only() {
        let path = tempfile::NamedTempFile::new().expect("tempfile");
        let path = path.path().to_path_buf();
        drop(path.clone());
        let store = Arc::new(SqliteAttemptStore::open(&path).expect("store"));
        let barrier = Arc::new(Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                store.register_attempt(&registration("nonce-abcdefghijkl"), 10)
            }));
        }
        let mut inserted = 0;
        for worker in workers {
            match worker.join().expect("join").expect("register") {
                RegisterAttemptOutcome::Inserted(_) => inserted += 1,
                RegisterAttemptOutcome::ExactRetry(_) => {}
            }
        }
        assert_eq!(inserted, 1);
    }

    #[test]
    fn state_machine_refuses_dispatch_without_capture() {
        let store = SqliteAttemptStore::open_in_memory().expect("store");
        let registration = registration("nonce-abcdefghijkl");
        store.register_attempt(&registration, 10).expect("insert");
        assert!(store
            .transition(
                &registration.ids.attempt_id,
                AttemptState::Prepared,
                AttemptState::DispatchCommitted,
                &AttemptTransitionEvidence::default(),
                11,
            )
            .is_err());
    }

    #[test]
    fn deterministic_attempt_reuse_with_changed_input_is_a_conflict() {
        let store = SqliteAttemptStore::open_in_memory().expect("store");
        let registration = registration("nonce-abcdefghijkl");
        store.register_attempt(&registration, 10).expect("insert");

        let mut changed = registration;
        changed.proof_digest = "d".repeat(64);
        assert!(matches!(
            store.register_attempt(&changed, 11),
            Err(BrokerError::Conflict(_))
        ));
    }

    #[test]
    fn nonce_insert_failure_rolls_back_the_prepared_intent() {
        let store = SqliteAttemptStore::open_in_memory().expect("store");
        store
            .connection()
            .expect("connection")
            .execute("DROP TABLE broker_nonces", [])
            .expect("drop nonce table");

        assert!(matches!(
            store.register_attempt(&registration("nonce-abcdefghijkl"), 10),
            Err(BrokerError::Storage(_))
        ));
        let attempt_count: i64 = store
            .connection()
            .expect("connection")
            .query_row("SELECT COUNT(*) FROM broker_attempts", [], |row| row.get(0))
            .expect("attempt count");
        assert_eq!(attempt_count, 0);
    }
}
