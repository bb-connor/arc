//! A migration handle cannot serve legacy replay reservations. Opening it
//! preserves the source's retained rows, clocks, capacity and schema exactly.

use std::path::Path;
use std::time::Duration;

use rusqlite::OpenFlags;

use super::super::{
    configure_pooled_connection, now_secs, StableReplayClock, MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64,
};
use super::*;

/// Migration-only source I/O. This deliberately does not implement the legacy
/// `GovernedApprovalReplayStore` trait or expose its underlying store handle.
pub struct SqliteGovernedApprovalReplaySource {
    pub(super) store: SqliteGovernedApprovalReplayStore,
}

impl SqliteGovernedApprovalReplaySource {
    /// Open an existing, canonical source without migration, pruning, clock
    /// advancement, capacity changes or file creation. This is required when
    /// resuming a pinned but not yet sealed source after process loss.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let filesystem_path = path
            .to_str()
            .map(crate::sqlite_filesystem_path)
            .unwrap_or_else(|| path.to_path_buf());
        if !std::fs::symlink_metadata(&filesystem_path)?
            .file_type()
            .is_file()
        {
            return Err(invalid("migration source must be an existing regular file"));
        }
        let manager = r2d2_sqlite::SqliteConnectionManager::file(path)
            .with_flags(
                OpenFlags::SQLITE_OPEN_READ_WRITE
                    | OpenFlags::SQLITE_OPEN_URI
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .with_init(configure_pooled_connection);
        let pool = r2d2::Pool::builder()
            .max_size(1)
            .connection_timeout(Duration::from_secs(5))
            .build(manager)?;
        let mut store = SqliteGovernedApprovalReplayStore {
            pool,
            path: Some(filesystem_path),
            capacity: 1,
            clock: StableReplayClock::new(now_secs(), MAX_GOVERNED_APPROVAL_CLOCK_SKEW_I64),
        };
        let mut connection = store.pool.get()?;
        require_durability(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        schema::verify_metadata(&tx)?;
        if store.load_replay_source_seal_tx(&tx)?.is_none() {
            schema::verify(&tx, false)?;
        }
        store.replay_source_file_identity(&tx)?;
        let inventory = inventory::read(&tx)?;
        inventory.validate()?;
        let capacity = inventory
            .capacity
            .parse::<usize>()
            .map_err(|_| invalid("source capacity cannot be represented on this platform"))?;
        tx.commit()?;
        drop(connection);
        store.capacity = capacity;
        Ok(Self { store })
    }
}
