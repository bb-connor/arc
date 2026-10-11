//! Serialize current lease authority, owned time and protected mutations.
use rusqlite::{params, Transaction, TransactionBehavior};

use super::{sqlite_error, sqlite_i64, SqliteRuntimeOrchestrationStore};
use crate::{validation::validate_runtime_run_lease, ChioRuntimeError, RuntimeRunLease};

pub(super) fn rejected() -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code: "runtime_run_write_lease_rejected",
        detail: "run write requires current, active lease ownership and nonregressing time".into(),
    }
}

impl SqliteRuntimeOrchestrationStore {
    pub(super) fn with_run_write<T>(
        &self,
        lease: &RuntimeRunLease,
        write: impl FnOnce(&Transaction<'_>, i64) -> Result<T, ChioRuntimeError>,
    ) -> Result<T, ChioRuntimeError> {
        validate_runtime_run_lease(lease)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        // Observe time after taking the write lock. A timestamp captured before
        // blocking cannot extend the authority of an expired owner.
        let now = sqlite_i64(
            self.clock.unix_millis()?.get(),
            "runtime run write timestamp",
        )?;
        let changed = transaction
            .execute(
                "UPDATE runtime_run_leases SET heartbeat_at_unix_ms = ?1
             WHERE run_id = ?2 AND lease_id = ?3 AND owner_id = ?4 AND fencing_token = ?5
               AND acquired_at_unix_ms = ?6 AND state = 'active' AND fencing_token > 0
               AND typeof(fencing_token) = 'integer'
               AND typeof(acquired_at_unix_ms) = 'integer'
               AND typeof(heartbeat_at_unix_ms) = 'integer'
               AND typeof(expires_at_unix_ms) = 'integer'
               AND acquired_at_unix_ms >= 0
               AND heartbeat_at_unix_ms >= acquired_at_unix_ms
               AND heartbeat_at_unix_ms <= ?1 AND expires_at_unix_ms > ?1
               AND EXISTS (
                   SELECT 1 FROM runtime_runs WHERE run_id = ?2
                     AND typeof(started_at_unix_ms) = 'integer'
                     AND typeof(updated_at_unix_ms) = 'integer'
                     AND started_at_unix_ms >= 0
                     AND updated_at_unix_ms >= started_at_unix_ms
                     AND updated_at_unix_ms <= ?1
               )",
                params![
                    now,
                    lease.run_id,
                    lease.lease_id,
                    lease.owner_id,
                    sqlite_i64(lease.fencing_token, "runtime run fencing token")?,
                    sqlite_i64(
                        lease.acquired_at_unix_ms,
                        "runtime run acquisition timestamp"
                    )?,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(rejected());
        }
        let result = write(&transaction, now)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(result)
    }
}
