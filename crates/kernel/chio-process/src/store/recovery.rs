use super::{read_process, require_running};
use crate::recovery::RecoveryCallReservation;
use crate::{digest, ProcessError};
use chio_kernel::ToolCallRequest;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

impl super::Store {
    pub(crate) fn verify_recovery_reservation(
        &mut self,
        reservation: &RecoveryCallReservation,
    ) -> Result<(), ProcessError> {
        self.require_open_recovery_reservation(
            &reservation.process_id,
            &reservation.operation_key,
        )?;
        let process = read_process(&self.connection, &reservation.process_id)?
            .ok_or_else(|| ProcessError::NotFound(reservation.process_id.clone()))?;
        if reservation.capability_digest != digest(&process.capability)? {
            return Err(ProcessError::Conflict);
        }
        let current: Option<Vec<u8>> = self.connection.query_row(
            "SELECT reservation FROM process_recovery_calls WHERE process_id=?1 AND operation_key=?2 AND continuation_id=?3",
            params![reservation.process_id, reservation.operation_key, reservation.continuation_id.as_str()],
            |row| row.get(0)).optional()?;
        if current.as_deref()
            != Some(chio_core_types::canonical_json_bytes(reservation)?.as_slice())
        {
            return Err(ProcessError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn reserve_recovery(
        &mut self,
        reservation: &RecoveryCallReservation,
    ) -> Result<(), ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::unused_recovery_reservation::require_open_recovery_reservation(
            &tx,
            &reservation.process_id,
            &reservation.operation_key,
        )?;
        let process = read_process(&tx, &reservation.process_id)?
            .ok_or_else(|| ProcessError::NotFound(reservation.process_id.clone()))?;
        require_running(&process)?;
        if reservation.runtime_id != self.namespace
            || reservation.capability_digest != digest(&process.capability)?
        {
            return Err(ProcessError::Conflict);
        }
        let encoded = chio_core_types::canonical_json_bytes(reservation)?;
        let existing: Option<Vec<u8>> = tx.query_row(
            "SELECT reservation FROM process_recovery_calls WHERE process_id=?1 AND (operation_key=?2 OR continuation_id=?3)",
            params![reservation.process_id,reservation.operation_key,reservation.continuation_id.as_str()], |row| row.get(0),
        ).optional()?;
        if let Some(existing) = existing {
            if existing != encoded {
                return Err(ProcessError::Conflict);
            }
        } else {
            let occupied: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM process_calls WHERE process_id=?1 AND operation_key=?2)",
                params![reservation.process_id,reservation.operation_key],|row|row.get(0))?;
            if occupied {
                return Err(ProcessError::Conflict);
            }
            let changed = tx.execute(
                "UPDATE processes SET tree_calls=tree_calls+1 WHERE id=?1 AND tree_calls<?2",
                params![process.root_id, process.limits.max_calls],
            )?;
            if changed != 1 {
                return Err(ProcessError::Limit("logical tool calls"));
            }
            tx.execute("INSERT INTO process_recovery_calls(process_id,operation_key,continuation_id,reservation) VALUES (?1,?2,?3,?4)",
                params![reservation.process_id,reservation.operation_key,reservation.continuation_id.as_str(),encoded])?;
            tx.execute(
                "UPDATE process_runtime SET version=2 WHERE singleton=1 AND version=1",
                [],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn finalize_recovery(
        &mut self,
        reservation: &RecoveryCallReservation,
        request: &ToolCallRequest,
        binding: &str,
    ) -> Result<(), ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::unused_recovery_reservation::require_open_recovery_reservation(
            &tx,
            &reservation.process_id,
            &reservation.operation_key,
        )?;
        let process = read_process(&tx, &reservation.process_id)?
            .ok_or_else(|| ProcessError::NotFound(reservation.process_id.clone()))?;
        require_running(&process)?;
        if reservation.capability_digest != digest(&process.capability)?
            || reservation.capability_digest != digest(&request.capability)?
            || request.agent_id != process.capability.subject.to_hex()
        {
            return Err(ProcessError::Conflict);
        }
        let encoded = chio_core_types::canonical_json_bytes(reservation)?;
        let current: Option<(Vec<u8>,Option<String>)>=tx.query_row("SELECT reservation,final_binding FROM process_recovery_calls WHERE process_id=?1 AND operation_key=?2 AND continuation_id=?3",
            params![reservation.process_id,reservation.operation_key,reservation.continuation_id.as_str()], |row|Ok((row.get(0)?,row.get(1)?))).optional()?;
        match current {
            Some((retained, Some(final_binding)))
                if retained == encoded && final_binding == binding =>
            {
                let call: Option<String>=tx.query_row("SELECT request_hash FROM process_calls WHERE process_id=?1 AND operation_key=?2",params![reservation.process_id,reservation.operation_key],|row|row.get(0)).optional()?;
                if call.as_deref() != Some(binding) {
                    return Err(ProcessError::Conflict);
                }
            }
            Some((retained, None)) if retained == encoded => {
                tx.execute("INSERT INTO process_calls(process_id,operation_key,request_hash) VALUES (?1,?2,?3)",params![reservation.process_id,reservation.operation_key,binding])?;
                let changed=tx.execute("UPDATE process_recovery_calls SET final_binding=?1 WHERE process_id=?2 AND operation_key=?3 AND final_binding IS NULL",params![binding,reservation.process_id,reservation.operation_key])?;
                if changed != 1 {
                    return Err(ProcessError::Conflict);
                }
            }
            _ => return Err(ProcessError::Conflict),
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{store::Store, ProcessLimits};
    use chio_security_types::recovery::{ContinuationId, IntentDigest};

    #[test]
    fn recovery_populated_legacy_journal_preserves_bytes_and_refuses_downgrade(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let path = super::super::private_file(&directory.path().join("process.db"))?;
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../spec/vectors/recovery/v1/legacy-process-binding.json"
        ))?;
        let request: ToolCallRequest = serde_json::from_value(fixture["request"].clone())?;
        let capability = serde_json::to_string(&request.capability)?;
        let limits = serde_json::to_string(&ProcessLimits {
            max_processes: 8,
            max_depth: 4,
            max_calls: 3,
            state: Default::default(),
        })?;
        let binding = fixture["cases"][0]["binding_hash"]
            .as_str()
            .ok_or("legacy binding")?;
        let db = rusqlite::Connection::open(&path)?;
        // Exact predecessor SQL, retained independently of current DDL.
        db.execute_batch(include_str!("../../tests/fixtures/legacy-process-v1.sql"))?;
        db.execute(
            "INSERT INTO process_runtime VALUES(1,1,'original-namespace','authority','key')",
            [],
        )?;
        db.execute("INSERT INTO processes(id,root_id,depth,capability,limits,tree_calls) VALUES('root','root',0,?1,?2,1)", params![capability, limits])?;
        db.execute("INSERT INTO process_calls(process_id,operation_key,request_hash) VALUES('root','original-call',?1)", [binding])?;
        drop(db);

        // DDL must roll back when the caller cannot open the retained authority.
        assert!(Store::open(&path, "foreign-authority", "key").is_err());
        let db = rusqlite::Connection::open(&path)?;
        assert!(!db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='process_recovery_calls')",
            [],
            |row| row.get::<_, bool>(0)
        )?);
        drop(db);

        let mut store = Store::open(&path, "authority", "key")?;
        assert_eq!(store.namespace, "original-namespace");
        let legacy: (String, String, String, i64) = store.connection.query_row(
            "SELECT p.capability,p.limits,c.request_hash,p.tree_calls FROM processes p JOIN process_calls c ON c.process_id=p.id WHERE c.operation_key='original-call'", [],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        assert_eq!(legacy, (capability, limits, binding.to_owned(), 1));
        assert_eq!(
            store
                .connection
                .query_row("SELECT version FROM process_runtime", [], |row| row
                    .get::<_, i64>(0))?,
            1
        );
        let reservation = RecoveryCallReservation {
            runtime_id: store.namespace.clone(),
            process_id: "root".into(),
            continuation_id: ContinuationId::new("original-continuation")?,
            operation_key: "recovery-call".into(),
            request_id: "original-request".into(),
            capability_digest: digest(&request.capability)?,
            unsigned_intent: IntentDigest::from_bytes([7; 32]),
            server_id: request.server_id,
            host_binding: "original-host-binding".into(),
        };
        store.reserve_recovery(&reservation)?;
        store.reserve_recovery(&reservation)?;
        assert_eq!(store.process("root")?.tree_calls, 2);
        assert_eq!(
            store
                .connection
                .query_row("SELECT version FROM process_runtime", [], |row| row
                    .get::<_, i64>(0))?,
            2
        );
        assert!(store
            .connection
            .execute("UPDATE process_runtime SET version=1", [])
            .is_err());
        assert!(store
            .connection
            .execute("DELETE FROM process_recovery_calls", [])
            .is_err());
        drop(store);
        let mut reopened = Store::open(&path, "authority", "key")?;
        reopened.verify_recovery_reservation(&reservation)?;
        assert_eq!(reopened.namespace, "original-namespace");
        assert_eq!(reopened.process("root")?.tree_calls, 2);
        Ok(())
    }
}
