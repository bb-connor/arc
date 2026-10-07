//! A fixed rollback-only probe against actual captured auxiliary-held custody.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Reconstruct only the authentic quota immediately before its one hold.
    /// Deliberate projection damage exists only inside a rolled-back savepoint.
    pub fn verify_recovery_quota_retained_head_for_test(
        &self,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<usize, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(&self.serving_owner.fence))?;
        let physical = workflow_tx(&tx, scope, workflow)?;
        let before_workflow = encode(&physical)?;
        let key = quota_key(scope, workflow)?;
        let row =
            raw_checked(&tx, &key)?.ok_or_else(|| invariant("quota head fixture is absent"))?;
        source_reference(&tx, &key)?;
        let current = workflow_quota(&tx, scope, workflow)?;
        let hold = current
            .native_hold
            .as_ref()
            .ok_or_else(|| invariant("quota head fixture requires an auxiliary hold"))?;
        hold.verify(&tx, scope, workflow)?;
        if !physical.captured || physical.historical_hold.is_some() || row.version < 2 {
            return Err(invariant(
                "quota head fixture requires unchanged captured custody",
            ));
        }
        if auxiliary_historical_hold(&tx, &physical)?.is_none() {
            return Err(invariant(
                "current quota head lost its genuine auxiliary hold",
            ));
        }
        let mut prior = current.clone();
        prior.native_hold = None;
        let prior_version = row.version - 1;
        let prior_payload = encode(&prior)?;
        let (prior_digest, _) = historical_record_reference(&tx, &key, prior_version)?;
        if record_digest(
            &key,
            &row.scope,
            &row.kind,
            prior_version,
            &prior_payload,
            None,
            None,
        )? != prior_digest
        {
            return Err(invariant(
                "quota head fixture did not retain the exact pre-hold projection",
            ));
        }
        prior.validate(
            &tx,
            scope,
            workflow,
            physical.revision.get(),
            prior
                .baseline_commands
                .get()
                .checked_add(prior.command_units()?)
                .ok_or_else(|| invariant("quota head fixture command count exhausted"))?,
            prior_version,
        )?;
        let triggers_before: (String, String) = tx.query_row(
            "SELECT
                (SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='admission_operation_recovery_identity'),
                (SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='admission_operation_recovery_hold_immutable')",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(sqlite_error)?;
        tx.execute_batch("SAVEPOINT workflow_quota_head_probe")
            .map_err(sqlite_error)?;
        let probe = (|| {
            tx.execute_batch(
                "DROP TRIGGER admission_operation_recovery_identity;
                 DROP TRIGGER admission_operation_recovery_hold_immutable",
            )
            .map_err(sqlite_error)?;
            tx.execute(
                "UPDATE admission_operation_recovery_records SET version=?2,payload=?3 WHERE record_key=?1",
                params![&key,i64::try_from(prior_version)
                    .map_err(|_| invariant("quota head fixture version exhausted"))?,&prior_payload],
            ).map_err(sqlite_error)?;
            let old = raw_checked(&tx, &key)?.ok_or_else(|| {
                invariant("quota head fixture lost its authentic prior projection")
            })?;
            if old.version != prior_version || old.payload != prior_payload {
                return Err(invariant(
                    "quota head fixture did not restore its authentic prior projection",
                ));
            }
            Ok(matches!(
                auxiliary_historical_hold(&tx, &physical),
                Err(AdmissionOperationStoreError::Invariant(_))
            ))
        })();
        tx.execute_batch(
            "ROLLBACK TO workflow_quota_head_probe; RELEASE workflow_quota_head_probe",
        )
        .map_err(sqlite_error)?;
        let refused = probe?;
        let restored = raw_checked(&tx, &key)?
            .ok_or_else(|| invariant("quota head fixture did not restore current custody"))?;
        let triggers_after: (String, String) = tx.query_row(
            "SELECT
                (SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='admission_operation_recovery_identity'),
                (SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='admission_operation_recovery_hold_immutable')",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(sqlite_error)?;
        if triggers_after != triggers_before
            || restored.version != row.version
            || restored.payload != row.payload
            || encode(&workflow_tx(&tx, scope, workflow)?)? != before_workflow
            || auxiliary_historical_hold(&tx, &physical)?.is_none()
        {
            return Err(invariant("quota head fixture changed retained custody"));
        }
        tx.rollback().map_err(sqlite_error)?;
        if !refused {
            return Err(invariant(
                "authentic pre-hold quota hid the current auxiliary hold",
            ));
        }
        Ok(1)
    }
}
