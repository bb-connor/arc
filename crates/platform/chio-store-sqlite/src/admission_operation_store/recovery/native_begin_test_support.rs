//! Model an initial native begin whose legacy workflow link was not published.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Seed only an actual valid Prepared begin for this exact finalized owner.
    /// This uses the normal core writer and anchor, never rewrites old custody.
    pub fn retain_recovery_begin_without_link_for_test(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        if operation.binding().participant_requirements().channel {
            return Err(invariant("missing-link fixture requires a tool begin"));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let permit = prepare_begin_tx(&tx, operation, now)?
            .ok_or_else(|| invariant("missing-link fixture owner absent"))?;
        if permit.record.native_link.is_some()
            || permit.record.captured
            || permit.record.admission_closed
        {
            return Err(invariant(
                "missing-link fixture requires untouched native ownership",
            ));
        }
        let encoded = match begin_prepared_operation_tx(&tx, operation, fence, now)? {
            PreparedAdmissionBeginTxResult::Created { encoded } => encoded,
            _ => {
                return Err(invariant(
                    "missing-link fixture native begin already exists",
                ))
            }
        };
        append_operation_commit_with_participant(
            &tx,
            operation,
            &encoded,
            None,
            "begin",
            None,
            &self.serving_owner,
            now,
        )?;
        // Omit only publication. The initial core operation is real and anchored.
        drop(permit);
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
}
