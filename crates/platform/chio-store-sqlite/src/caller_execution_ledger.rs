//! Executor-owned at-most-once dispatch and durable report publication.
//!
//! Provisioning is explicit and opening never creates or repairs a ledger.
//! An uncertain claim or effect is never retried. All processes serving the
//! same executor must share this physical ledger. Privileged filesystem
//! rollback and independent ledgers are outside this local custody boundary.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::{Keypair, PublicKey};
use chio_kernel::admission_operation::AdmissionIdentifier;
use chio_kernel::caller_delivery::{
    CallerDeliveryError, CallerDeliveryReportBodyV1, CallerExecutorIdentityV1,
    CallerInvocationBindingV1, SignedCallerDeliveryReportV1, SignedCallerDispatchAuthorizationV1,
    CALLER_DELIVERY_REPORT_SCHEMA,
};
use chio_kernel::{CallerExecutionReport, KernelError};
use chio_sqlite_file_identity::{main_database_file_identity, SqliteFileIdentity};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};

const SCHEMA: &str = include_str!("caller_execution_ledger.sql");
const APPLICATION_ID: i64 = 0x43484345;
const SCHEMA_VERSION: i64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum CallerExecutionLedgerError {
    #[error(transparent)]
    Authentication(#[from] CallerDeliveryError),
    #[error("caller executor ledger failed closed: {0}")]
    Storage(String),
    #[error("caller executor has an unresolved original attempt; redelivery cannot execute it")]
    OutcomeUnknown,
    #[error("caller executor ledger is full; retained claims cannot be evicted")]
    Capacity,
}

type Result<T> = std::result::Result<T, CallerExecutionLedgerError>;

/// Persistent local executor custody. It has no authority to issue a kernel
/// start authorization and cannot turn a reservation nonce into one.
pub struct SqliteCallerExecutionLedger {
    connection: Mutex<Connection>,
    path: PathBuf,
    file_identity: SqliteFileIdentity,
    executor: CallerExecutorIdentityV1,
    max_operations: u32,
}

impl SqliteCallerExecutionLedger {
    /// Create a new private ledger. Never call this automatically on restart or
    /// when an existing ledger is unavailable. No populated store is migrated.
    /// At most 64 operations are retained (about 66 MiB of bounded payloads).
    pub fn provision(
        path: &Path,
        executor: CallerExecutorIdentityV1,
        max_operations: u32,
    ) -> Result<Self> {
        if !(1..=64).contains(&max_operations) {
            return Err(invalid("invalid executor capacity"));
        }
        validate_executor(&executor)?;
        let path = private_path(path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(&path).map_err(storage)?;
        file.sync_all().map_err(storage)?;
        // On a failed initialization retain the file for inspection. Open
        // refuses the incomplete catalog; no empty-history retry is invented.
        let mut connection = connect(&path)?;
        connection
            .execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(storage)?;
        let identity = file_identity(&connection, &path)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute_batch(SCHEMA).map_err(storage)?;
        tx.pragma_update(None, "application_id", APPLICATION_ID)
            .map_err(storage)?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)
            .map_err(storage)?;
        let encoded = chio_core::canonical_json_bytes(&executor).map_err(storage)?;
        tx.execute(
            "INSERT INTO caller_executor_configuration VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                encoded,
                identity.device.to_string(),
                identity.inode.to_string(),
                max_operations
            ],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO caller_executor_clock VALUES (1, ?1)",
            [now_ms()?],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        drop(connection);
        fs::File::open(
            path.parent()
                .ok_or_else(|| invalid("executor parent missing"))?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(storage)?;
        Self::open(&path, executor)
    }

    /// Open only an already provisioned exact executor/key epoch. Rotation
    /// needs an explicit history-preserving migration, never a fresh ledger.
    pub fn open(path: &Path, executor: CallerExecutorIdentityV1) -> Result<Self> {
        validate_executor(&executor)?;
        let path = private_path(path)?;
        if !fs::symlink_metadata(&path).map_err(storage)?.is_file() {
            return Err(invalid("executor ledger must already be a regular file"));
        }
        let mut connection = connect(&path)?;
        let identity = file_identity(&connection, &path)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(storage)?;
        validate_schema(&tx)?;
        let (encoded, device, inode, capacity): (Vec<u8>, String, String, u32) = tx.query_row(
            "SELECT
                CASE WHEN typeof(identity) = 'blob' AND length(identity) BETWEEN 1 AND 4096 THEN identity END,
                CASE WHEN typeof(device) = 'text' AND length(CAST(device AS BLOB)) BETWEEN 1 AND 20 THEN device END,
                CASE WHEN typeof(inode) = 'text' AND length(CAST(inode AS BLOB)) BETWEEN 1 AND 20 THEN inode END,
                max_operations
             FROM caller_executor_configuration WHERE singleton = 1",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).map_err(storage)?;
        if encoded != chio_core::canonical_json_bytes(&executor).map_err(storage)?
            || device != identity.device.to_string()
            || inode != identity.inode.to_string()
            || !(1..=64).contains(&capacity)
        {
            return Err(invalid(
                "executor identity or physical ledger was substituted",
            ));
        }
        let claims: u32 = tx
            .query_row("SELECT count(*) FROM caller_executor_claims", [], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        if claims > capacity {
            return Err(invalid("executor claim inventory exceeds capacity"));
        }
        read_clock(&tx)?;
        let foreign_keys: Option<String> = tx
            .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
            .optional()
            .map_err(storage)?;
        if foreign_keys.is_some() {
            return Err(invalid("executor report has no original claim"));
        }
        tx.commit().map_err(storage)?;
        Ok(Self {
            connection: Mutex::new(connection),
            path,
            file_identity: identity,
            executor,
            max_operations: capacity,
        })
    }

    /// Authenticate and durably claim before calling `effect`. Exact duplicate
    /// delivery returns the persisted signed report or OutcomeUnknown, never a
    /// second callback. An error or panic after claim leaves permanent custody.
    /// The configured key signs executor observations, not provider attestation.
    pub fn execute_once(
        &self,
        authorization: &SignedCallerDispatchAuthorizationV1,
        trusted_kernel: &PublicKey,
        expected_invocation: &CallerInvocationBindingV1,
        executor_key: &Keypair,
        effect: impl FnOnce() -> std::result::Result<CallerExecutionReport, KernelError>,
    ) -> Result<SignedCallerDeliveryReportV1> {
        if executor_key.public_key() != self.executor.public_key {
            return Err(invalid(
                "executor signing key differs from its configured identity",
            ));
        }
        let digest =
            authorization.verify_historical(trusted_kernel, &self.executor, expected_invocation)?;
        let encoded = authorization.canonical_bytes()?;
        let kernel_key = trusted_kernel.to_hex();
        let operation_id = expected_invocation.operation_id.as_str();
        let claim_id = uuid::Uuid::new_v4().to_string();
        let claimed_at;
        {
            let mut connection = self
                .connection
                .lock()
                .map_err(|_| invalid("executor connection lock poisoned"))?;
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(storage)?;
            self.validate_live(&tx)?;
            let now = advance_clock(&tx)?;
            let existing: Option<(Vec<u8>, String)> = tx.query_row(
                "SELECT
                    CASE WHEN typeof(authorization) = 'blob' AND length(authorization) BETWEEN 1 AND 32768 THEN authorization END,
                    CASE WHEN typeof(claim_id) = 'text' AND length(CAST(claim_id AS BLOB)) = 36 THEN claim_id END
                 FROM caller_executor_claims WHERE operation_id = ?1",
                params![operation_id], |row| Ok((row.get(0)?, row.get(1)?)),
            ).optional().map_err(storage)?;
            if let Some((original, original_claim)) = existing {
                if original != encoded {
                    return Err(invalid("redelivery changed the original authorization"));
                }
                let report: Option<Vec<u8>> = tx.query_row(
                    "SELECT CASE WHEN typeof(report) = 'blob' AND length(report) BETWEEN 1 AND 1048576 THEN report END FROM caller_executor_reports WHERE kernel_key = ?1 AND operation_id = ?2",
                    params![kernel_key, operation_id], |row| row.get(0),
                ).optional().map_err(storage)?;
                let report = report.ok_or(CallerExecutionLedgerError::OutcomeUnknown)?;
                let report = SignedCallerDeliveryReportV1::from_canonical_bytes(&report)?;
                report.verify(
                    authorization,
                    trusted_kernel,
                    &self.executor,
                    expected_invocation,
                )?;
                if report.report.claim_id.as_str() != original_claim {
                    return Err(invalid("report changed its original executor claim"));
                }
                tx.commit().map_err(storage)?;
                return Ok(report);
            }
            let verified = authorization.verify_for_claim(
                trusted_kernel,
                &self.executor,
                expected_invocation,
                u64::try_from(now).map_err(storage)?,
            )?;
            claimed_at = u64::try_from(now).map_err(storage)?;
            let count: u32 = tx
                .query_row("SELECT count(*) FROM caller_executor_claims", [], |row| {
                    row.get(0)
                })
                .map_err(storage)?;
            if count >= self.max_operations {
                return Err(CallerExecutionLedgerError::Capacity);
            }
            tx.execute(
                "INSERT INTO caller_executor_claims VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    kernel_key,
                    operation_id,
                    digest.as_str(),
                    encoded,
                    claim_id,
                    now
                ],
            )
            .map_err(storage)?;
            verified.require_live_at(u64::try_from(now_ms()?).map_err(storage)?)?;
            tx.commit().map_err(storage)?;
            // Commit failure is unresolved, never permission to invoke. Exact
            // readback confirms the particular claim that this call created.
            let retained: (Vec<u8>, String) = connection.query_row(
                "SELECT authorization, claim_id FROM caller_executor_claims WHERE kernel_key = ?1 AND operation_id = ?2",
                params![kernel_key, operation_id], |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(storage)?;
            if retained != (encoded, claim_id.clone()) {
                return Err(invalid("executor claim acknowledgement changed"));
            }
        }
        let started = u64::try_from(now_ms()?).map_err(storage)?;
        if started < claimed_at {
            return Err(invalid("executor clock regressed after claim"));
        }
        authorization.verify_for_claim(
            trusted_kernel,
            &self.executor,
            expected_invocation,
            started,
        )?;
        // No database lock or transaction spans the external callback.
        let observed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(effect))
            .map_err(|_| CallerExecutionLedgerError::OutcomeUnknown)?
            .map_err(|_| CallerExecutionLedgerError::OutcomeUnknown)?;
        let completed = u64::try_from(now_ms()?).map_err(storage)?;
        let report = SignedCallerDeliveryReportV1::sign(
            CallerDeliveryReportBodyV1 {
                schema: CALLER_DELIVERY_REPORT_SCHEMA.into(),
                authorization_digest: digest,
                executor: self.executor.clone(),
                claim_id: AdmissionIdentifier::try_new("executor_claim", claim_id)
                    .map_err(storage)?,
                execution_started_at_unix_ms: started,
                completed_at_unix_ms: completed,
                output: observed.output,
                realized_cost: observed.realized_cost.map(|cost| {
                    chio_core::capability::scope::MonetaryAmount {
                        units: cost.units,
                        currency: cost.currency,
                    }
                }),
            },
            executor_key,
        )?;
        report.verify(
            authorization,
            trusted_kernel,
            &self.executor,
            expected_invocation,
        )?;
        let bytes = report.canonical_bytes()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| invalid("executor connection lock poisoned"))?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        self.validate_live(&tx)?;
        advance_clock(&tx)?;
        tx.execute(
            "INSERT INTO caller_executor_reports VALUES (?1, ?2, ?3)",
            params![kernel_key, operation_id, bytes],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        let retained: Vec<u8> = connection.query_row("SELECT report FROM caller_executor_reports WHERE kernel_key = ?1 AND operation_id = ?2", params![kernel_key, operation_id], |row| row.get(0)).map_err(storage)?;
        if retained != bytes {
            return Err(invalid("executor report acknowledgement changed"));
        }
        Ok(report)
    }

    fn validate_live(&self, connection: &Connection) -> Result<()> {
        validate_schema(connection)?;
        if file_identity(connection, &self.path)? != self.file_identity {
            return Err(invalid("executor ledger path identity changed"));
        }
        Ok(())
    }
}

fn connect(path: &Path) -> Result<Connection> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(storage)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(storage)?;
    connection
        .execute_batch("PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")
        .map_err(storage)?;
    Ok(connection)
}

fn validate_schema(connection: &Connection) -> Result<()> {
    let application: i64 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(storage)?;
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(storage)?;
    let journal: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .map_err(storage)?;
    let synchronous: i64 = connection
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .map_err(storage)?;
    let foreign_keys: i64 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(storage)?;
    if application != APPLICATION_ID
        || version != SCHEMA_VERSION
        || journal != "wal"
        || synchronous != 2
        || foreign_keys != 1
    {
        return Err(invalid(
            "executor schema or durability profile is unsupported",
        ));
    }
    let model = Connection::open_in_memory().map_err(storage)?;
    model.execute_batch(SCHEMA).map_err(storage)?;
    if catalog(connection)? != catalog(&model)? {
        return Err(invalid("executor catalog changed"));
    }
    Ok(())
}

fn catalog(connection: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut statement = connection
        .prepare(
            "SELECT
            CASE WHEN length(CAST(type AS BLOB)) BETWEEN 1 AND 16 THEN type END,
            CASE WHEN length(CAST(name AS BLOB)) BETWEEN 1 AND 128 THEN name END,
            CASE WHEN length(CAST(sql AS BLOB)) BETWEEN 1 AND 8192 THEN sql END
         FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name LIMIT 32",
        )
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(storage)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage)
}

fn private_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() || path.to_string_lossy().starts_with("file:") {
        return Err(invalid(
            "executor ledger requires an absolute filesystem path",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("executor parent missing"))?;
    let metadata = fs::symlink_metadata(parent).map_err(storage)?;
    if !metadata.is_dir() {
        return Err(invalid("executor parent is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("executor parent must be private"));
        }
    }
    Ok(fs::canonicalize(parent).map_err(storage)?.join(
        path.file_name()
            .ok_or_else(|| invalid("executor filename missing"))?,
    ))
}

fn file_identity(connection: &Connection, path: &Path) -> Result<SqliteFileIdentity> {
    let identity = main_database_file_identity(connection).map_err(storage)?;
    let metadata = fs::symlink_metadata(path).map_err(storage)?;
    if !metadata.is_file() || identity.link_count != 1 {
        return Err(invalid(
            "executor ledger must be a regular single-link file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.dev() != identity.device
            || metadata.ino() != identity.inode
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(invalid("executor ledger identity or permissions changed"));
        }
    }
    Ok(identity)
}

fn validate_executor(executor: &CallerExecutorIdentityV1) -> Result<()> {
    if executor.key_epoch == 0
        || executor.key_epoch >= (1_u64 << 53)
        || executor.public_key.is_weak_ed25519()
    {
        return Err(invalid("executor key selection is invalid"));
    }
    Ok(())
}

fn advance_clock(connection: &Connection) -> Result<i64> {
    let now = now_ms()?;
    let previous = read_clock(connection)?;
    if now < previous {
        return Err(invalid("executor authority clock regressed"));
    }
    if connection
        .execute(
            "UPDATE caller_executor_clock SET high_water_unix_ms=?1 WHERE singleton=1",
            [now],
        )
        .map_err(storage)?
        != 1
    {
        return Err(invalid("executor clock disappeared"));
    }
    Ok(now)
}

fn read_clock(connection: &Connection) -> Result<i64> {
    connection
        .query_row(
            "SELECT CASE WHEN typeof(high_water_unix_ms) = 'integer'
                AND high_water_unix_ms BETWEEN 1 AND 9007199254740991
                THEN high_water_unix_ms END
             FROM caller_executor_clock WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(storage)
}

fn now_ms() -> Result<i64> {
    let value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(storage)?
        .as_millis();
    if value == 0 || value >= (1_u128 << 53) {
        return Err(invalid("executor clock is outside I-JSON range"));
    }
    i64::try_from(value).map_err(storage)
}

fn storage(error: impl std::fmt::Display) -> CallerExecutionLedgerError {
    invalid(error.to_string())
}
fn invalid(message: impl Into<String>) -> CallerExecutionLedgerError {
    CallerExecutionLedgerError::Storage(message.into())
}
