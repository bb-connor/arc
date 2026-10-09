//! Existing-only inspection of authority storage for unauthenticated readers.
//!
//! Inspection never creates a directory or database, never migrates, stamps or
//! changes the journal mode of the schema, never bootstraps signing material and
//! never advances the persisted clock floor. Every read runs in one deferred
//! transaction on a read-only connection, so it never takes the authority write
//! lock that issuance, rotation and anchoring serialize on.

use super::*;
use crate::store_clock::StoreClock;
use chio_security_types::clock::{Clock, UnixMillis};
use std::sync::Arc;
use std::time::Duration;

/// Readers wait on transient WAL index locks exactly as authority writers do.
const AUTHORITY_READ_BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

/// Refusal from existing-only authority inspection.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityInspectionError {
    /// No database exists at the path, or its owner never bootstrapped one.
    #[error("authority storage is not initialized")]
    Uninitialized,
    #[error(transparent)]
    Store(#[from] AuthorityStoreError),
}

impl From<rusqlite::Error> for AuthorityInspectionError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

impl From<chio_security_types::clock::ClockError> for AuthorityInspectionError {
    fn from(error: chio_security_types::clock::ClockError) -> Self {
        Self::Store(error.into())
    }
}

/// Read-only view of an authority database that its writable owner provisioned.
pub struct SqliteAuthorityInspection {
    clock: StoreClock,
    custody: custody::AuthorityCustody,
}

impl SqliteAuthorityInspection {
    /// Open existing authority storage, validating custody, the schema stamp,
    /// the bootstrapped head and the persisted clock floor.
    pub fn open_existing_with_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AuthorityInspectionError> {
        let custody = custody::AuthorityCustody::inspect_existing(path.as_ref())?
            .ok_or(AuthorityInspectionError::Uninitialized)?;
        let inspection = Self {
            clock: StoreClock::new(clock),
            custody,
        };
        inspection.read(|_, _| Ok(()))?;
        Ok(inspection)
    }

    /// The current head, lifecycle state and live issuer keys at this clock.
    pub fn status(&self) -> Result<AuthorityStatus, AuthorityInspectionError> {
        self.read(|connection, now| {
            let snapshot = replication::read_snapshot(connection)?;
            let mut status = SqliteCapabilityAuthority::read_status_from_connection(connection)?;
            status.trusted_public_keys = lifecycle::live_public_keys(&snapshot, now.as_secs())?;
            Ok(status)
        })
    }

    /// The locally held signing seed. A follower holds its own seed while the
    /// replicated head may name another custodian.
    pub fn local_keypair(&self) -> Result<Keypair, AuthorityInspectionError> {
        self.read(|connection, _| {
            SqliteCapabilityAuthority::read_keypair_from_connection(connection)
        })
    }

    fn read<T>(
        &self,
        inspect: impl FnOnce(&Connection, UnixMillis) -> Result<T, AuthorityStoreError>,
    ) -> Result<T, AuthorityInspectionError> {
        let mut connection = self.custody.open_read_only_connection()?;
        connection.busy_timeout(AUTHORITY_READ_BUSY_TIMEOUT)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        validate_existing_schema(&transaction)?;
        let now = self.clock.unix_millis()?;
        lifecycle::validate_time_floor(&transaction, now)?;
        let head = SqliteCapabilityAuthority::read_status_from_connection(&transaction)?;
        if !head.trusted_public_keys.contains(&head.public_key) {
            return Err(AuthorityStoreError::Schema(
                "authority head is absent from persisted issuer history; restore an authenticated backup before reopening".into(),
            )
            .into());
        }
        let value = inspect(&transaction, now)?;
        self.custody.validate(&transaction)?;
        transaction.commit()?;
        Ok(value)
    }
}

/// Accept only storage the writable owner fully provisioned at this binary's
/// schema revision. Anything older needs the owner to migrate it first.
fn validate_existing_schema(connection: &Connection) -> Result<(), AuthorityInspectionError> {
    let user_tables: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if user_tables == 0 {
        return Err(AuthorityInspectionError::Uninitialized);
    }
    let application_id: i32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id == 0 {
        return Err(AuthorityStoreError::Schema(
            "authority storage predates schema stamping; the authority owner must migrate it"
                .into(),
        )
        .into());
    }
    let version = crate::check_schema_version(
        connection,
        AUTHORITY_STORE_SCHEMA_KEY,
        AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION,
        AUTHORITY_STORE_LEGACY_ANCHOR_TABLES,
    )
    .map_err(|error| AuthorityStoreError::Schema(error.to_string()))?;
    if version != AUTHORITY_STORE_SUPPORTED_SCHEMA_VERSION {
        return Err(AuthorityStoreError::Schema(format!(
            "authority storage schema version {version} needs migration by the authority owner"
        ))
        .into());
    }
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(AuthorityStoreError::Schema(format!(
            "authority storage uses journal mode `{journal_mode}`; readers require WAL"
        ))
        .into());
    }
    let bootstrapped: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_state WHERE singleton_id = 1)",
        [],
        |row| row.get(0),
    )?;
    if !bootstrapped {
        return Err(AuthorityInspectionError::Uninitialized);
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
#[path = "read_only_tests.rs"]
mod tests;
