use rusqlite::{params, Transaction, TransactionBehavior};

use super::{sqlite_error, sqlite_i64, SqliteRuntimeOrchestrationStore};
use crate::types::{RuntimeEvidenceManifestEntry, RuntimeOrchestrationStepState, RuntimeRunLease};
use crate::validation::{
    validate_non_empty, validate_runtime_orchestration_step_state, validate_state_label,
};
use crate::ChioRuntimeError;

impl SqliteRuntimeOrchestrationStore {
    /// Register pending work once. Registration never grants write ownership
    /// and cannot reset an existing run or any of its protected step evidence.
    pub fn register_run(&self, run_id: &str) -> Result<bool, ChioRuntimeError> {
        validate_non_empty(run_id, "runtime_run_empty_id")?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        let now = sqlite_i64(
            self.clock.unix_millis()?.get(),
            "runtime registration timestamp",
        )?;
        let inserted = transaction.execute(
            "INSERT INTO runtime_runs (run_id, status, started_at_unix_ms, updated_at_unix_ms, failure_code)
             VALUES (?1, 'pending', ?2, ?2, NULL) ON CONFLICT(run_id) DO NOTHING",
            params![run_id, now],
        ).map_err(sqlite_error)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(inserted == 1)
    }

    pub fn record_run_state(
        &self,
        lease: &RuntimeRunLease,
        status: &str,
        failure_code: Option<&str>,
    ) -> Result<(), ChioRuntimeError> {
        validate_state_label(status, "runtime_run_invalid_status")?;
        self.with_run_write(lease, |transaction, now| {
            write_run(transaction, &lease.run_id, status, failure_code, now)
        })
    }

    /// The shorthand carries the same explicit run authority as the long form.
    /// There is no implicit, unfenced `default` run.
    pub fn record_step_state(
        &self,
        lease: &RuntimeRunLease,
        state: RuntimeOrchestrationStepState,
    ) -> Result<(), ChioRuntimeError> {
        self.record_run_step_state(lease, state)
    }

    pub fn record_run_step_state(
        &self,
        lease: &RuntimeRunLease,
        state: RuntimeOrchestrationStepState,
    ) -> Result<(), ChioRuntimeError> {
        validate_runtime_orchestration_step_state(&state)?;
        self.with_run_write(lease, |transaction, _| {
            write_step(transaction, &lease.run_id, &state)
        })
    }

    /// Commit one writer's complete run/step snapshot and release its lease
    /// atomically. A late step failure retains neither partial progress nor a
    /// released lease. Later work must acquire its own, incremented fence.
    pub fn complete_run_write(
        &self,
        lease: &RuntimeRunLease,
        status: &str,
        failure_code: Option<&str>,
        steps: &[RuntimeOrchestrationStepState],
        artifacts: &[RuntimeEvidenceManifestEntry],
    ) -> Result<(), ChioRuntimeError> {
        validate_state_label(status, "runtime_run_invalid_status")?;
        let mut indices = std::collections::BTreeSet::new();
        for step in steps {
            validate_runtime_orchestration_step_state(step)?;
            if !indices.insert(step.step_index) {
                return Err(ChioRuntimeError::Rejected {
                    code: "runtime_run_duplicate_step_index",
                    detail: "one run write cannot contain duplicate step indices".into(),
                });
            }
        }
        for artifact in artifacts {
            super::evidence_artifacts::validate_entry(artifact)?;
        }
        self.with_run_write(lease, |transaction, now| {
            write_run(transaction, &lease.run_id, status, failure_code, now)?;
            for step in steps {
                write_step(transaction, &lease.run_id, step)?;
            }
            for artifact in artifacts {
                super::evidence_artifacts::write_entry(transaction, &lease.run_id, artifact, now)?;
            }
            let released = transaction.execute(
                "UPDATE runtime_run_leases SET state = 'released', reason_code = 'runtime_run_write_complete'
                 WHERE run_id = ?1 AND lease_id = ?2 AND owner_id = ?3 AND fencing_token = ?4 AND state = 'active'",
                params![lease.run_id, lease.lease_id, lease.owner_id,
                    sqlite_i64(lease.fencing_token, "runtime run fencing token")?],
            ).map_err(sqlite_error)?;
            if released != 1 {
                return Err(super::run_write_fence::rejected());
            }
            Ok(())
        })
    }

    pub fn recorded_run_ids(&self) -> Result<Vec<String>, ChioRuntimeError> {
        let connection = self.lock_connection()?;
        let mut statement = connection
            .prepare("SELECT run_id FROM runtime_runs ORDER BY run_id")
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
}

fn write_run(
    transaction: &Transaction<'_>,
    run_id: &str,
    status: &str,
    failure_code: Option<&str>,
    now: i64,
) -> Result<(), ChioRuntimeError> {
    let changed = transaction.execute(
        "UPDATE runtime_runs SET status = ?2, updated_at_unix_ms = ?3, failure_code = ?4 WHERE run_id = ?1",
        params![run_id, status, now, failure_code],
    ).map_err(sqlite_error)?;
    if changed != 1 {
        return Err(super::run_write_fence::rejected());
    }
    Ok(())
}

fn write_step(
    transaction: &Transaction<'_>,
    run_id: &str,
    state: &RuntimeOrchestrationStepState,
) -> Result<(), ChioRuntimeError> {
    transaction
        .execute(
            r#"
                INSERT INTO runtime_step_states (
                    run_id, step_index, admission_id, state, destructive,
                    admission_report_sha256, tool_receipt_sha256, lease_id
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(run_id, step_index) DO UPDATE SET
                    admission_id = excluded.admission_id,
                    state = excluded.state,
                    destructive = excluded.destructive,
                    admission_report_sha256 = excluded.admission_report_sha256,
                    tool_receipt_sha256 = excluded.tool_receipt_sha256,
                    lease_id = excluded.lease_id
                "#,
            params![
                run_id,
                sqlite_i64(state.step_index, "runtime step index")?,
                state.admission_id,
                state.state,
                if state.destructive { 1_i64 } else { 0_i64 },
                state.admission_report_sha256,
                state.tool_receipt_sha256,
                state.lease_id
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}
