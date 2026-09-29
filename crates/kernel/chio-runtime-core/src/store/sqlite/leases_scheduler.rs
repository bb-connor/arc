#![cfg_attr(not(test), deny(clippy::arithmetic_side_effects))]
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use super::{sqlite_error, sqlite_i64, sqlite_u64, SqliteRuntimeOrchestrationStore};
use crate::schema::{CHIO_RUNTIME_RUN_LEASE_SCHEMA, CHIO_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA};
use crate::types::{RuntimeRunLease, RuntimeSchedulerTickReport, RuntimeSupervisorProfile};
use crate::validation::{
    validate_non_empty, validate_runtime_run_lease, validate_runtime_scheduler_tick_report,
    validate_runtime_supervisor_profile,
};
use crate::ChioRuntimeError;

fn rejected(code: &'static str, detail: &str) -> ChioRuntimeError {
    ChioRuntimeError::Rejected {
        code,
        detail: detail.to_owned(),
    }
}

fn lease_expiry(now: u64, ttl: u64) -> Result<u64, ChioRuntimeError> {
    if ttl == 0 {
        return Err(rejected(
            "runtime_run_lease_invalid_ttl",
            "run lease ttl must be positive",
        ));
    }
    now.checked_add(ttl)
        .filter(|expiry| i64::try_from(*expiry).is_ok())
        .ok_or_else(|| {
            rejected(
                "runtime_run_lease_expiry_overflow",
                "run lease expiry exceeds the SQLite clock range",
            )
        })
}

fn next_fencing_token(previous: i64) -> Result<u64, ChioRuntimeError> {
    if previous <= 0 {
        return Err(rejected(
            "runtime_run_lease_invalid_fencing_token",
            "persisted fencing token must be positive",
        ));
    }
    previous
        .checked_add(1)
        .and_then(|next| u64::try_from(next).ok())
        .ok_or_else(|| {
            rejected(
                "runtime_run_lease_fencing_exhausted",
                "run lease fencing token is exhausted",
            )
        })
}

fn stale_cutoff(now: u64, after: u64) -> Result<Option<i64>, ChioRuntimeError> {
    // A timeout longer than the entire elapsed epoch cannot make heartbeat zero stale.
    now.checked_sub(after)
        .map(|cutoff| sqlite_i64(cutoff, "runtime stale heartbeat timestamp"))
        .transpose()
}

fn scheduler_count(count: usize) -> Result<u64, ChioRuntimeError> {
    u64::try_from(count).map_err(|_| {
        rejected(
            "runtime_scheduler_count_overflow",
            "scheduler count exceeds u64",
        )
    })
}

fn acquire_run_lease_tx(
    tx: &Transaction<'_>,
    run_id: &str,
    owner_id: &str,
    now_unix_ms: u64,
    ttl_ms: u64,
) -> Result<RuntimeRunLease, ChioRuntimeError> {
    validate_non_empty(run_id, "runtime_run_empty_id")?;
    validate_non_empty(owner_id, "runtime_run_lease_empty_owner")?;
    let now = sqlite_i64(now_unix_ms, "runtime run lease timestamp")?;
    let expiry = lease_expiry(now_unix_ms, ttl_ms)?;
    let expires_at = sqlite_i64(expiry, "runtime run lease expiry")?;
    let existing: Option<(String, i64, i64, String)> = tx
            .query_row(
                "SELECT owner_id, expires_at_unix_ms, fencing_token, state FROM runtime_run_leases WHERE run_id = ?1",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(sqlite_error)?;
    let fencing_token =
        if let Some((_existing_owner, existing_expires, existing_token, state)) = existing {
            sqlite_u64(existing_expires, "runtime run lease expiry")?;
            if state == "active" && existing_expires > now {
                return Err(ChioRuntimeError::Rejected {
                    code: "runtime_run_lease_conflict",
                    detail: format!("runtime run {run_id} already has an active lease"),
                });
            }
            next_fencing_token(existing_token)?
        } else {
            1
        };
    let lease = RuntimeRunLease {
        schema: CHIO_RUNTIME_RUN_LEASE_SCHEMA.to_string(),
        run_id: run_id.to_string(),
        lease_id: format!("{run_id}:{owner_id}:{fencing_token}"),
        owner_id: owner_id.to_string(),
        acquired_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: expiry,
        heartbeat_at_unix_ms: now_unix_ms,
        fencing_token,
        state: "active".to_string(),
        reason_code: None,
    };
    validate_runtime_run_lease(&lease)?;
    tx.execute(
        r#"
            INSERT INTO runtime_run_leases (
                run_id, lease_id, owner_id, acquired_at_unix_ms, expires_at_unix_ms,
                heartbeat_at_unix_ms, fencing_token, state, reason_code
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(run_id) DO UPDATE SET
                lease_id = excluded.lease_id,
                owner_id = excluded.owner_id,
                acquired_at_unix_ms = excluded.acquired_at_unix_ms,
                expires_at_unix_ms = excluded.expires_at_unix_ms,
                heartbeat_at_unix_ms = excluded.heartbeat_at_unix_ms,
                fencing_token = excluded.fencing_token,
                state = excluded.state,
                reason_code = excluded.reason_code
            "#,
        params![
            lease.run_id,
            lease.lease_id,
            lease.owner_id,
            now,
            expires_at,
            now,
            sqlite_i64(lease.fencing_token, "runtime run lease fencing token")?,
            lease.state,
            lease.reason_code
        ],
    )
    .map_err(sqlite_error)?;
    Ok(lease)
}

impl SqliteRuntimeOrchestrationStore {
    pub fn acquire_run_lease(
        &self,
        run_id: &str,
        owner_id: &str,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<RuntimeRunLease, ChioRuntimeError> {
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let lease = acquire_run_lease_tx(&tx, run_id, owner_id, now_unix_ms, ttl_ms)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(lease)
    }

    pub fn heartbeat_run_lease(
        &self,
        run_id: &str,
        owner_id: &str,
        fencing_token: u64,
        now_unix_ms: u64,
        ttl_ms: u64,
    ) -> Result<RuntimeRunLease, ChioRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        validate_non_empty(owner_id, "runtime_run_lease_empty_owner")?;
        let now = sqlite_i64(now_unix_ms, "runtime run lease heartbeat timestamp")?;
        let expiry = lease_expiry(now_unix_ms, ttl_ms)?;
        let expires_at = sqlite_i64(expiry, "runtime run lease heartbeat expiry")?;
        let mut connection = self.lock_connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let row: Option<(String, String, i64, i64, i64, String, i64)> = tx
            .query_row(
                r#"
                SELECT lease_id, owner_id, acquired_at_unix_ms, expires_at_unix_ms,
                       fencing_token, state, heartbeat_at_unix_ms
                FROM runtime_run_leases
                WHERE run_id = ?1
                "#,
                params![run_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((
            lease_id,
            existing_owner,
            acquired_at,
            existing_expires,
            existing_token,
            state,
            previous_heartbeat,
        )) = row
        else {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_run_lease_missing",
                detail: format!("runtime run {run_id} has no lease"),
            });
        };
        if existing_token <= 0 {
            return Err(rejected(
                "runtime_run_lease_invalid_fencing_token",
                "persisted fencing token must be positive",
            ));
        }
        if existing_owner != owner_id
            || sqlite_u64(existing_token, "runtime run lease fencing token")? != fencing_token
            || state != "active"
        {
            return Err(ChioRuntimeError::Rejected {
                code: "runtime_run_stale_fencing_token",
                detail: format!("runtime run {run_id} heartbeat used stale fencing token"),
            });
        }
        sqlite_u64(existing_expires, "runtime run lease expiry")?;
        let previous_heartbeat =
            sqlite_u64(previous_heartbeat, "runtime run lease heartbeat timestamp")?;
        if now_unix_ms < previous_heartbeat {
            return Err(rejected(
                "runtime_run_lease_clock_regressed",
                "lease heartbeat clock moved backwards",
            ));
        }
        if existing_expires <= now {
            return Err(rejected(
                "runtime_run_lease_expired",
                "run lease expired before heartbeat",
            ));
        }
        let lease = RuntimeRunLease {
            schema: CHIO_RUNTIME_RUN_LEASE_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            lease_id,
            owner_id: owner_id.to_string(),
            acquired_at_unix_ms: sqlite_u64(acquired_at, "runtime run lease acquired timestamp")?,
            expires_at_unix_ms: expiry,
            heartbeat_at_unix_ms: now_unix_ms,
            fencing_token,
            state,
            reason_code: None,
        };
        validate_runtime_run_lease(&lease)?;
        let changed = tx.execute(
            "UPDATE runtime_run_leases SET heartbeat_at_unix_ms = ?1, expires_at_unix_ms = ?2
             WHERE run_id = ?3 AND owner_id = ?4 AND fencing_token = ?5 AND state = 'active' AND expires_at_unix_ms > ?1",
            params![now, expires_at, run_id, owner_id, sqlite_i64(fencing_token, "runtime run lease fencing token")?],
        ).map_err(sqlite_error)?;
        if changed != 1 {
            return Err(rejected(
                "runtime_run_stale_fencing_token",
                "lease ownership changed during heartbeat",
            ));
        }
        tx.commit().map_err(sqlite_error)?;
        Ok(lease)
    }

    pub fn scheduler_tick_report(
        &self,
        profile: &RuntimeSupervisorProfile,
        owner_id: &str,
        now_unix_ms: u64,
        max_runs: u64,
    ) -> Result<RuntimeSchedulerTickReport, ChioRuntimeError> {
        validate_runtime_supervisor_profile(profile)?;
        validate_non_empty(owner_id, "runtime_scheduler_empty_owner")?;
        let now = sqlite_i64(now_unix_ms, "runtime scheduler tick timestamp")?;
        let mut connection = self.lock_connection()?;
        // Capacity, expiration, claims and their report share one write snapshot.
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let mut claimed_run_ids = Vec::new();
        let mut expired_run_ids = Vec::new();
        let mut skipped_run_count = 0;
        let accepted =
            now_unix_ms >= profile.issued_at_unix_ms && now_unix_ms < profile.expires_at_unix_ms;
        if accepted {
            lease_expiry(now_unix_ms, profile.run_lease_ttl_ms)?;
            let stale_before = stale_cutoff(now_unix_ms, profile.stale_run_after_ms)?;
            {
                let mut statement = tx.prepare(
                    "SELECT run_id FROM runtime_run_leases WHERE state = 'active' AND
                     (expires_at_unix_ms <= ?1 OR (?2 IS NOT NULL AND heartbeat_at_unix_ms <= ?2)) ORDER BY run_id",
                ).map_err(sqlite_error)?;
                for row in statement
                    .query_map(params![now, stale_before], |row| row.get::<_, String>(0))
                    .map_err(sqlite_error)?
                {
                    expired_run_ids.push(row.map_err(sqlite_error)?);
                }
            }
            tx.execute(
                "UPDATE runtime_run_leases SET state = 'expired', reason_code = 'runtime_run_lease_expired' WHERE state = 'active' AND
                 (expires_at_unix_ms <= ?1 OR (?2 IS NOT NULL AND heartbeat_at_unix_ms <= ?2))",
                params![now, stale_before],
            ).map_err(sqlite_error)?;
            let active = active_nonterminal_lease_count(&tx)?;
            // Existing work above a lowered capacity leaves zero new admission slots.
            let claim_limit = max_runs
                .min(profile.max_concurrent_runs)
                .saturating_sub(active);
            let pending_runs = pending_run_ids(&tx)?;
            let pending_count = scheduler_count(pending_runs.len())?;
            let take = usize::try_from(claim_limit.min(pending_count)).map_err(|_| {
                rejected(
                    "runtime_scheduler_count_overflow",
                    "claim limit exceeds usize",
                )
            })?;
            for run_id in pending_runs.into_iter().take(take) {
                match acquire_run_lease_tx(
                    &tx,
                    &run_id,
                    owner_id,
                    now_unix_ms,
                    profile.run_lease_ttl_ms,
                ) {
                    Ok(_) => claimed_run_ids.push(run_id),
                    Err(ChioRuntimeError::Rejected {
                        code: "runtime_run_lease_conflict",
                        ..
                    }) => {}
                    Err(error) => return Err(error),
                }
            }
            skipped_run_count = pending_count
                .checked_sub(scheduler_count(claimed_run_ids.len())?)
                .ok_or_else(|| {
                    rejected(
                        "runtime_scheduler_count_overflow",
                        "claimed count exceeds pending count",
                    )
                })?;
        }
        let report = RuntimeSchedulerTickReport {
            schema: CHIO_RUNTIME_SCHEDULER_TICK_REPORT_SCHEMA.to_string(),
            accepted,
            failure_code: (!accepted).then(|| "runtime_scheduler_profile_stale".to_owned()),
            tick_id: format!("{owner_id}:{now_unix_ms}"),
            owner_id: owner_id.to_string(),
            generated_at_unix_ms: now_unix_ms,
            max_runs,
            claimed_run_ids,
            expired_run_ids,
            blocked_run_ids: Vec::new(),
            skipped_run_count,
            checks: vec!["runtime_ops.scheduler_tick".to_string()],
        };
        validate_runtime_scheduler_tick_report(&report)?;
        tx.execute(
            "INSERT OR REPLACE INTO runtime_scheduler_ticks (tick_id, owner_id, generated_at_unix_ms, claimed_count, blocked_count) VALUES (?1, ?2, ?3, ?4, 0)",
            params![report.tick_id, owner_id, now, sqlite_i64(scheduler_count(report.claimed_run_ids.len())?, "runtime scheduler claimed count")?],
        ).map_err(sqlite_error)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(report)
    }
}

pub(super) fn lease_count_by_state(
    connection: &Connection,
    state: &str,
) -> Result<u64, ChioRuntimeError> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_run_leases WHERE state = ?1",
            params![state],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime lease count")
}

fn active_nonterminal_lease_count(connection: &Connection) -> Result<u64, ChioRuntimeError> {
    let count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM runtime_run_leases leases
            LEFT JOIN runtime_runs runs ON runs.run_id = leases.run_id
            WHERE leases.state = 'active'
              AND (
                runs.status IS NULL
                OR runs.status NOT IN ('proof_accepted', 'terminal_failure', 'completed')
              )
            "#,
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime active nonterminal lease count")
}

pub(super) fn stale_lease_count(
    connection: &Connection,
    now_unix_ms: u64,
    stale_run_after_ms: u64,
) -> Result<u64, ChioRuntimeError> {
    let stale_before = stale_cutoff(now_unix_ms, stale_run_after_ms)?;
    let count: i64 = connection
        .query_row(
            r#"
            SELECT COUNT(*)
            FROM runtime_run_leases leases
            LEFT JOIN runtime_runs runs ON runs.run_id = leases.run_id
            WHERE leases.state = 'active'
              AND (leases.expires_at_unix_ms <= ?1 OR (?2 IS NOT NULL AND leases.heartbeat_at_unix_ms <= ?2))
              AND (
                runs.status IS NULL
                OR runs.status NOT IN ('proof_accepted', 'terminal_failure', 'completed')
              )
            "#,
            params![
                sqlite_i64(now_unix_ms, "runtime stale lease timestamp")?,
                stale_before
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    sqlite_u64(count, "runtime stale lease count")
}

fn pending_run_ids(connection: &Connection) -> Result<Vec<String>, ChioRuntimeError> {
    let mut statement = connection
        .prepare(
            r#"
                SELECT runs.run_id
                FROM runtime_runs runs
                WHERE runs.status IN ('pending', 'planned', 'proof_pending')
                  AND NOT EXISTS (
                    SELECT 1
                    FROM runtime_run_leases leases
                    WHERE leases.run_id = runs.run_id
                      AND leases.state = 'active'
                  )
                ORDER BY runs.updated_at_unix_ms, runs.run_id
                "#,
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?;
    let mut run_ids = Vec::new();
    for row in rows {
        run_ids.push(row.map_err(sqlite_error)?);
    }
    Ok(run_ids)
}
