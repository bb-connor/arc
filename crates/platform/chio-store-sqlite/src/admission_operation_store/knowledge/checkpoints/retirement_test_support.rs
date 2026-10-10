//! Connection-local fault injection for atomic checkpoint retirement.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Fail only the real checkpoint owner retirement write on this connection.
    /// A TEMP trigger changes no durable schema, authority or protected source.
    pub fn inject_checkpoint_retirement_owner_failure_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?.execute_batch(
            "CREATE TEMP TRIGGER fail_checkpoint_owner_retirement BEFORE UPDATE ON main.admission_operation_recovery_records
             WHEN NEW.record_key GLOB 'knowledge-reference-owner:*'
               AND json_extract(NEW.payload,'$.owner.owner')='checkpoint_revision'
               AND json_extract(NEW.payload,'$.state')='retired'
             BEGIN SELECT RAISE(ABORT,'injected checkpoint owner retirement failure'); END;",
        ).map_err(sqlite_error)
    }

    pub fn clear_checkpoint_retirement_owner_failure_for_test(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.connection()?
            .execute_batch("DROP TRIGGER temp.fail_checkpoint_owner_retirement")
            .map_err(sqlite_error)
    }
}
