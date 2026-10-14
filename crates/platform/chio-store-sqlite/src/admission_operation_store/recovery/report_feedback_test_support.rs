//! A rollback-only source-loss probe on an actual first terminal Report.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Damage only the authenticated first Report projection inside a savepoint.
    /// Retained events and global commits remain intact, and every change rolls back.
    pub fn verify_recovery_report_retained_source_for_test(
        &self,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<usize, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(&self.serving_owner.fence))?;
        let physical = workflow_tx(&tx, scope, workflow)?;
        historical_holds::require_unheld(&tx, &physical)?;
        if physical.reported_decision.is_some()
            || auxiliary_captured_terminal(&tx, &physical)?.is_none()
        {
            return Err(invariant(
                "Report source fixture requires auxiliary completion",
            ));
        }
        let feedback = reported_feedback(&tx, &physical)?
            .ok_or_else(|| invariant("Report source fixture has no original feedback"))?;
        let before_workflow = encode(&physical)?;
        let before_view = encode(&historical_holds::view(&tx, physical.clone())?)?;
        let quota_key = format!("workflow-quota:{}:{}", scope_key(scope)?, workflow.as_str());
        let before_quota = raw_checked(&tx, &quota_key)?
            .ok_or_else(|| invariant("Report source fixture quota disappeared"))?;
        let intent = physical
            .admission
            .as_ref()
            .ok_or_else(|| invariant("Report source fixture intent absent"))?;
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
        let before_native = encode(
            &load_by_operation_id_tx(&tx, binding.operation_id())?
                .ok_or_else(|| invariant("Report source fixture native absent"))?
                .operation
                .to_persisted(),
        )?;
        let keys = {
            let mut query = tx
                .prepare(
                    "SELECT record_key FROM admission_operation_recovery_records
                 WHERE scope_key=?1 AND kind='command' AND record_key GLOB 'command:*'
                   AND json_extract(CAST(payload AS TEXT),'$.reported_decision.workflow_id')=?2
                 LIMIT 2",
                )
                .map_err(sqlite_error)?;
            let rows = query
                .query_map(params![scope_key(scope)?, workflow.as_str()], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(sqlite_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sqlite_error)?;
            rows
        };
        if keys.len() != 1 {
            return Err(invariant("Report source fixture original is ambiguous"));
        }
        let key = &keys[0];
        let before_report = raw_checked(&tx, key)?
            .ok_or_else(|| invariant("Report source fixture original absent"))?;
        let report_source = source_reference(&tx, key)?;
        let before_history = history_census(&tx)?;
        let trigger: String = tx
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger'
             AND name='admission_operation_recovery_no_delete'",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let deferred: i64 = tx
            .query_row("PRAGMA defer_foreign_keys", [], |row| row.get(0))
            .map_err(sqlite_error)?;
        tx.execute_batch("SAVEPOINT recovery_report_source_probe")
            .map_err(sqlite_error)?;
        let probe = (|| {
            tx.execute_batch(
                "PRAGMA defer_foreign_keys=ON;
                DROP TRIGGER admission_operation_recovery_no_delete",
            )
            .map_err(sqlite_error)?;
            if tx
                .execute(
                    "DELETE FROM admission_operation_recovery_records WHERE record_key=?1",
                    [key],
                )
                .map_err(sqlite_error)?
                != 1
            {
                return Err(invariant(
                    "Report source fixture did not remove its selected row",
                ));
            }
            if history_census(&tx)? != before_history {
                return Err(invariant("Report source probe changed retained history"));
            }
            Ok(matches!(
                historical_holds::view(&tx, physical.clone()),
                Err(AdmissionOperationStoreError::Invariant(_))
            ))
        })();
        tx.execute_batch(
            "ROLLBACK TO recovery_report_source_probe;
            RELEASE recovery_report_source_probe",
        )
        .map_err(sqlite_error)?;
        tx.pragma_update(None, "defer_foreign_keys", deferred)
            .map_err(sqlite_error)?;
        let refused = probe?;
        let restored_report = raw_checked(&tx, key)?
            .ok_or_else(|| invariant("Report source fixture did not restore original"))?;
        let restored_quota = raw_checked(&tx, &quota_key)?
            .ok_or_else(|| invariant("Report source fixture did not restore quota"))?;
        verify_source_reference(&tx, &report_source)?;
        let restored_trigger: String = tx
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type='trigger'
             AND name='admission_operation_recovery_no_delete'",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if restored_report.version != before_report.version
            || restored_report.payload != before_report.payload
            || restored_quota.version != before_quota.version
            || restored_quota.payload != before_quota.payload
            || encode(&workflow_tx(&tx, scope, workflow)?)? != before_workflow
            || encode(&historical_holds::view(&tx, physical.clone())?)? != before_view
            || reported_feedback(&tx, &physical)? != Some(feedback)
            || encode(
                &load_by_operation_id_tx(&tx, binding.operation_id())?
                    .ok_or_else(|| invariant("Report source fixture native disappeared"))?
                    .operation
                    .to_persisted(),
            )? != before_native
            || history_census(&tx)? != before_history
            || restored_trigger != trigger
        {
            return Err(invariant("Report source fixture changed original custody"));
        }
        tx.rollback().map_err(sqlite_error)?;
        if !refused {
            return Err(invariant(
                "missing original Report source became pristine feedback absence",
            ));
        }
        Ok(1)
    }
}

fn history_census(tx: &Connection) -> Result<(i64, i64), AdmissionOperationStoreError> {
    tx.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_events),
                (SELECT count(*) FROM authority_global_commits)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .map_err(sqlite_error)
}
