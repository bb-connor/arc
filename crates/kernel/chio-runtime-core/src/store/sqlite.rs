use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::Connection;

use crate::ChioRuntimeError;

mod admission_replay;
mod evidence_artifacts;
mod health_summaries;
mod leases_scheduler;
mod replay_source;
mod runs_steps;
mod schema_migrations;
mod swarm_authority_bundles;
mod treaty_artifacts;
mod trust_floors;

pub struct SqliteRuntimeOrchestrationStore {
    pub(super) path: PathBuf,
    pub(super) connection: Mutex<Connection>,
    clock: std::sync::Arc<dyn chio_security_types::clock::Clock>,
}

impl SqliteRuntimeOrchestrationStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ChioRuntimeError> {
        Self::open_with_clock(
            path,
            std::sync::Arc::new(chio_security_types::clock::SystemClock),
        )
    }

    pub fn open_with_clock(
        path: impl AsRef<Path>,
        clock: std::sync::Arc<dyn chio_security_types::clock::Clock>,
    ) -> Result<Self, ChioRuntimeError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(ChioRuntimeError::Io)?;
            }
        }
        let connection = Connection::open(&path).map_err(sqlite_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(sqlite_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(sqlite_error)?;
        connection
            .busy_timeout(std::time::Duration::from_millis(5_000))
            .map_err(sqlite_error)?;
        let store = Self {
            path,
            clock,
            connection: Mutex::new(connection),
        };
        // A sealed source must be verified before legacy schema initialization
        // can recreate a missing replay table and erase evidence of corruption.
        store.verify_replay_source_before_init()?;
        store.init_schema()?;
        Ok(store)
    }

    pub(super) fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>, ChioRuntimeError> {
        self.connection.lock().map_err(|_| {
            ChioRuntimeError::Store("runtime orchestration sqlite store is poisoned".to_string())
        })
    }
}

pub(super) fn sqlite_error(error: rusqlite::Error) -> ChioRuntimeError {
    ChioRuntimeError::Sqlite(error)
}

pub(super) fn sqlite_i64(value: u64, field: &str) -> Result<i64, ChioRuntimeError> {
    i64::try_from(value).map_err(|_| ChioRuntimeError::Rejected {
        code: "runtime_sqlite_integer_out_of_range",
        detail: format!("{field} does not fit sqlite i64"),
    })
}

pub(super) fn sqlite_u64(value: i64, field: &str) -> Result<u64, ChioRuntimeError> {
    u64::try_from(value).map_err(|_| ChioRuntimeError::Rejected {
        code: "runtime_sqlite_integer_negative",
        detail: format!("{field} is negative"),
    })
}

pub(super) fn query_count(connection: &Connection, table: &str) -> Result<u64, ChioRuntimeError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = connection
        .query_row(&sql, [], |row| row.get(0))
        .map_err(sqlite_error)?;
    sqlite_u64(count, table)
}
