use super::{read_process, require_running};
use crate::recovery::RecoveryCallReservation;
use crate::{digest, ProcessError};
use chio_kernel::ToolCallRequest;
use rusqlite::{params, OptionalExtension};

impl super::Store {
    pub(crate) fn verify_recovery_reservation(
        &mut self,
        reservation: &RecoveryCallReservation,
    ) -> Result<(), ProcessError> {
        self.require_open_recovery_reservation(
            &reservation.data.process_id,
            &reservation.data.operation_key,
        )?;
        let process = read_process(&self.connection, &reservation.data.process_id)?
            .ok_or_else(|| ProcessError::NotFound(reservation.data.process_id.clone()))?;
        if reservation.data.capability_digest != digest(&process.capability)? {
            return Err(ProcessError::Conflict);
        }
        let current: Option<Vec<u8>> = self.connection.query_row(
            "SELECT reservation FROM process_recovery_calls WHERE process_id=?1 AND operation_key=?2 AND continuation_id=?3",
            params![reservation.data.process_id, reservation.data.operation_key, reservation.data.continuation_id.as_str()],
            |row| row.get(0)).optional()?;
        if current.as_deref()
            != Some(chio_core_types::canonical_json_bytes(reservation)?.as_slice())
        {
            return Err(ProcessError::Conflict);
        }
        Ok(())
    }

    /// Read-only probe: whether this exact reservation is already retained,
    /// so replay needs no write. A different retained reservation or a
    /// permanently closed one refuses. Nothing is written here.
    pub(crate) fn recovery_reservation_replayed(
        &self,
        reservation: &RecoveryCallReservation,
    ) -> Result<bool, ProcessError> {
        super::unused_recovery_reservation::require_open_recovery_reservation(
            &self.connection,
            &reservation.data.process_id,
            &reservation.data.operation_key,
        )?;
        let encoded = chio_core_types::canonical_json_bytes(reservation)?;
        let existing: Option<Vec<u8>> = self.connection.query_row(
            "SELECT reservation FROM process_recovery_calls WHERE process_id=?1 AND (operation_key=?2 OR continuation_id=?3)",
            params![reservation.data.process_id,reservation.data.operation_key,reservation.data.continuation_id.as_str()], |row| row.get(0),
        ).optional()?;
        match existing {
            Some(existing) if existing == encoded => Ok(true),
            Some(_) => Err(ProcessError::Conflict),
            None => Ok(false),
        }
    }

    /// Test fixtures drive the actual reservation body directly; production
    /// reservation always runs through the routed current writer.
    #[cfg(any(test, feature = "admission-test-support"))]
    pub(crate) fn reserve_recovery(
        &mut self,
        reservation: &RecoveryCallReservation,
    ) -> Result<(), ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        reserve_recovery_call(&tx, &self.namespace, reservation)?;
        tx.commit()?;
        Ok(())
    }

    /// Test fixtures drive the actual finalization body directly; production
    /// finalization always runs through the routed current writer.
    #[cfg(any(test, feature = "admission-test-support"))]
    pub(crate) fn finalize_recovery(
        &mut self,
        reservation: &RecoveryCallReservation,
        request: &ToolCallRequest,
        binding: &str,
    ) -> Result<(), ProcessError> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        finalize_recovery_call(&tx, reservation, request, binding)?;
        tx.commit()?;
        Ok(())
    }
}

/// The complete reservation body inside one writer transaction: the open
/// guard, running identity, immutable-content replay, the one-time logical
/// call debit, the reservation row and the version transition. Executed by
/// the bank-proven routed writer.
pub(crate) fn reserve_recovery_call(
    tx: &rusqlite::Transaction<'_>,
    namespace: &str,
    reservation: &RecoveryCallReservation,
) -> Result<(), ProcessError> {
    super::unused_recovery_reservation::require_open_recovery_reservation(
        tx,
        &reservation.data.process_id,
        &reservation.data.operation_key,
    )?;
    let process = read_process(tx, &reservation.data.process_id)?
        .ok_or_else(|| ProcessError::NotFound(reservation.data.process_id.clone()))?;
    require_running(&process)?;
    if reservation.data.runtime_id != namespace
        || reservation.data.capability_digest != digest(&process.capability)?
    {
        return Err(ProcessError::Conflict);
    }
    let encoded = chio_core_types::canonical_json_bytes(reservation)?;
    let existing: Option<Vec<u8>> = tx.query_row(
        "SELECT reservation FROM process_recovery_calls WHERE process_id=?1 AND (operation_key=?2 OR continuation_id=?3)",
        params![reservation.data.process_id,reservation.data.operation_key,reservation.data.continuation_id.as_str()], |row| row.get(0),
    ).optional()?;
    if let Some(existing) = existing {
        if existing != encoded {
            return Err(ProcessError::Conflict);
        }
    } else {
        let occupied: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM process_calls WHERE process_id=?1 AND operation_key=?2)",
            params![reservation.data.process_id, reservation.data.operation_key],
            |row| row.get(0),
        )?;
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
            params![reservation.data.process_id,reservation.data.operation_key,reservation.data.continuation_id.as_str(),encoded])?;
        tx.execute(
            "UPDATE process_runtime SET version=2 WHERE singleton=1 AND version=1",
            [],
        )?;
    }
    Ok(())
}

/// The complete finalization body inside one writer transaction: the open
/// guard, running identity and capability binding, and the exactly-once
/// call row with its final binding. Executed by the bank-proven routed
/// writer.
pub(crate) fn finalize_recovery_call(
    tx: &rusqlite::Transaction<'_>,
    reservation: &RecoveryCallReservation,
    request: &ToolCallRequest,
    binding: &str,
) -> Result<(), ProcessError> {
    super::unused_recovery_reservation::require_open_recovery_reservation(
        tx,
        &reservation.data.process_id,
        &reservation.data.operation_key,
    )?;
    let process = read_process(tx, &reservation.data.process_id)?
        .ok_or_else(|| ProcessError::NotFound(reservation.data.process_id.clone()))?;
    require_running(&process)?;
    if reservation.data.capability_digest != digest(&process.capability)?
        || reservation.data.capability_digest != digest(&request.capability)?
        || request.agent_id != process.capability.subject.to_hex()
    {
        return Err(ProcessError::Conflict);
    }
    let encoded = chio_core_types::canonical_json_bytes(reservation)?;
    let current: Option<(Vec<u8>,Option<String>)>=tx.query_row("SELECT reservation,final_binding FROM process_recovery_calls WHERE process_id=?1 AND operation_key=?2 AND continuation_id=?3",
        params![reservation.data.process_id,reservation.data.operation_key,reservation.data.continuation_id.as_str()], |row|Ok((row.get(0)?,row.get(1)?))).optional()?;
    match current {
        Some((retained, Some(final_binding)))
            if retained == encoded && final_binding == binding =>
        {
            let call: Option<String>=tx.query_row("SELECT request_hash FROM process_calls WHERE process_id=?1 AND operation_key=?2",params![reservation.data.process_id,reservation.data.operation_key],|row|row.get(0)).optional()?;
            if call.as_deref() != Some(binding) {
                return Err(ProcessError::Conflict);
            }
        }
        Some((retained, None)) if retained == encoded => {
            tx.execute("INSERT INTO process_calls(process_id,operation_key,request_hash) VALUES (?1,?2,?3)",params![reservation.data.process_id,reservation.data.operation_key,binding])?;
            let changed=tx.execute("UPDATE process_recovery_calls SET final_binding=?1 WHERE process_id=?2 AND operation_key=?3 AND final_binding IS NULL",params![binding,reservation.data.process_id,reservation.data.operation_key])?;
            if changed != 1 {
                return Err(ProcessError::Conflict);
            }
        }
        _ => return Err(ProcessError::Conflict),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Store;
    use chio_security_types::recovery::{ContinuationId, IntentDigest};

    #[test]
    fn foreign_authority_refuses_a_historical_journal_without_ddl(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let path = super::super::private_file(&directory.path().join("process.db"))?;
        let authority = uuid::Uuid::new_v4().to_string();
        let db = rusqlite::Connection::open(&path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        // Exact predecessor SQL, retained independently of current DDL.
        db.execute_batch(include_str!("../../tests/fixtures/legacy-process-v1.sql"))?;
        db.execute(
            "INSERT INTO process_runtime VALUES(1,1,?1,?2,'key')",
            params![uuid::Uuid::new_v4().to_string(), authority],
        )?;
        drop(db);

        // No DDL happens when the caller cannot open the retained authority.
        assert!(Store::open(&path, "foreign-authority", "key").is_err());
        assert!(Store::open(&path, &authority, "foreign-key").is_err());
        let db = rusqlite::Connection::open(&path)?;
        assert!(!db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='process_recovery_calls')",
            [],
            |row| row.get::<_, bool>(0)
        )?);
        Ok(())
    }

    #[test]
    fn recovery_reservation_identity_keeps_the_persisted_unwrapped_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../spec/vectors/recovery/v1/legacy-process-binding.json"
        ))?;
        let request: ToolCallRequest = serde_json::from_value(fixture["request"].clone())?;
        let reservation = RecoveryCallReservation {
            data: chio_kernel::recovery::RecoveryProcessReservationV1 {
                runtime_id: uuid::Uuid::new_v4().to_string(),
                process_id: "root".into(),
                continuation_id: ContinuationId::new("original-continuation")?,
                operation_key: "recovery-call".into(),
                request_id: "original-request".into(),
                capability_digest: digest(&request.capability)?,
                unsigned_intent: IntentDigest::from_bytes([7; 32]),
                server_id: request.server_id,
                host_binding: "original-host-binding".into(),
            },
        };
        // The shared DTO must preserve the persisted unwrapped identity shape.
        let bytes = chio_core_types::canonical_json_bytes(&reservation)?;
        assert_eq!(
            bytes,
            chio_core_types::canonical_json_bytes(reservation.identity())?
        );
        let decoded: RecoveryCallReservation = serde_json::from_slice(&bytes)?;
        assert_eq!(decoded, reservation);
        let mut unknown = serde_json::to_value(&reservation)?;
        unknown
            .as_object_mut()
            .ok_or("reservation object")?
            .insert("untrusted_authority".into(), true.into());
        assert!(serde_json::from_value::<RecoveryCallReservation>(unknown).is_err());
        Ok(())
    }
}
