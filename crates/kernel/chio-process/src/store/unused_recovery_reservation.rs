//! Permanent closure preserves the charged original and forbids every participant.
use super::*;
use crate::recovery::{RecoveryCallReservation, UnusedRecoveryReservationClosureData};
pub(crate) mod catalog;
mod history;

impl Store {
    /// Authenticate the actual path and enforced level before the routed
    /// closure. Nothing is written here.
    pub(crate) fn authorize_unused_recovery_closure(
        &self,
        writer: (&str, &str),
    ) -> Result<(), ProcessError> {
        self.require_enforced_knowledge()?;
        self.original_snapshot(writer.0, writer.1).verify_path()
    }

    /// The actual path is still the original journal after the closure
    /// committed.
    pub(crate) fn confirm_unused_recovery_closure(
        &self,
        writer: (&str, &str),
    ) -> Result<(), ProcessError> {
        self.original_snapshot(writer.0, writer.1).verify_path()
    }

    pub(crate) fn verify_unused_recovery_reservation_closure(
        &self,
        expected: &UnusedRecoveryReservationClosureData,
    ) -> Result<(), ProcessError> {
        self.original_snapshot(expected.authority_domain(), expected.kernel_key())
            .verify_path()?;
        catalog::verify(&self.connection)?;
        let actual = history::load(&self.connection, expected.reservation())?
            .ok_or(ProcessError::Conflict)?;
        if actual != *expected {
            return Err(ProcessError::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_open_recovery_reservation(
        &self,
        process: &str,
        operation: &str,
    ) -> Result<(), ProcessError> {
        require_open_recovery_reservation(&self.connection, process, operation)
    }
}

/// The complete closure body inside one writer transaction: the retained
/// cohorts, the exact unused history and the permanent closure row with its
/// feature activation. Executed only by the bank-proven routed writer.
pub(crate) fn close_unused_recovery_reservation_call(
    tx: &rusqlite::Transaction<'_>,
    namespace_expected: &str,
    writer: (&str, &str),
    reservation: &RecoveryCallReservation,
) -> Result<UnusedRecoveryReservationClosureData, ProcessError> {
    super::knowledge::require_enforced_level(tx)?;
    verify_before_open(tx)?;
    let (version, namespace, authority, key) = history::metadata(tx)?;
    if !matches!(version, 5..=7)
        || namespace != namespace_expected
        || authority != writer.0
        || key != writer.1
    {
        return Err(ProcessError::Conflict);
    }
    catalog::verify(tx)?;
    history::unused(tx, reservation)?;
    if let Some(existing) = history::load(tx, reservation)? {
        return Ok(existing);
    }
    let (root, lineage) = history::lineage(tx, &reservation.data.process_id)?;
    let value = UnusedRecoveryReservationClosureData::from_actual_journal(
        reservation.clone(),
        authority,
        key,
        root,
        lineage,
    );
    let bytes = chio_core_types::canonical_json_bytes(&value)?;
    if bytes.len() > 16384 {
        return Err(ProcessError::Limit("unused recovery closure"));
    }
    tx.execute(
        "INSERT INTO process_unused_recovery_reservations(process_id,operation_key,continuation_id,closure) VALUES(?1,?2,?3,?4)",
        params![reservation.data.process_id,reservation.data.operation_key,reservation.data.continuation_id.as_str(),bytes],
    )?;
    if version == 5 {
        super::raise_feature_level(tx, 5, 6)?;
    }
    verify_cohort(tx)?;
    Ok(value)
}

/// The participant writer uses this check inside its actual Immediate cut.
pub(super) fn require_open_recovery_reservation(
    connection: &Connection,
    process: &str,
    operation: &str,
) -> Result<(), ProcessError> {
    let level = super::feature_level(connection)?;
    if !matches!(level, 1..=7) {
        return Err(ProcessError::Configuration(
            "unsupported recovery participant journal version",
        ));
    }
    verify_before_open(connection)?;
    if !catalog::family_present(connection)? {
        return Ok(());
    }
    let closed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM process_unused_recovery_reservations WHERE process_id=?1 AND operation_key=?2)",
        params![process,operation], |row| row.get(0),
    )?;
    if closed {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

pub(super) fn verify_cohort(connection: &Connection) -> Result<(), ProcessError> {
    catalog::verify(connection)?;
    let version = history::metadata(connection)?.0;
    if !matches!(version, 6 | 7) {
        return Err(ProcessError::Configuration(
            "unused recovery closure version changed",
        ));
    }
    if version == 7 {
        super::confined_delivery::verify_cohort(connection)?;
    }
    let mut query = connection.prepare(
        "SELECT process_id,operation_key,continuation_id,
         CASE WHEN typeof(closure)='blob' AND length(closure) BETWEEN 1 AND 16384 THEN closure END
         FROM process_unused_recovery_reservations ORDER BY process_id,operation_key",
    )?;
    let mut rows = query.query([])?;
    let mut found = false;
    while let Some(row) = rows.next()? {
        found = true;
        let process: String = row.get(0)?;
        let operation: String = row.get(1)?;
        let continuation: String = row.get(2)?;
        let bytes: Option<Vec<u8>> = row.get(3)?;
        let bytes = bytes.ok_or(ProcessError::Conflict)?;
        let value: UnusedRecoveryReservationClosureData = serde_json::from_slice(&bytes)?;
        if value.reservation().data.process_id != process
            || value.reservation().data.operation_key != operation
            || value.reservation().data.continuation_id.as_str() != continuation
            || chio_core_types::canonical_json_bytes(&value)? != bytes
        {
            return Err(ProcessError::Conflict);
        }
        history::verify(connection, &value)?;
    }
    if !found && version == 6 {
        return Err(ProcessError::Configuration(
            "unused recovery journal lacks actual closed custody",
        ));
    }
    Ok(())
}

/// Existing retained closure metadata is verified before base DDL can repair it.
pub(super) fn verify_before_open(connection: &Connection) -> Result<(), ProcessError> {
    let runtime_present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='process_runtime')",
        [],
        |row| row.get(0),
    )?;
    if !runtime_present {
        if catalog::family_present(connection)? {
            return Err(ProcessError::Conflict);
        }
        return Ok(());
    }
    let version: Option<u32> = connection
        .query_row(
            "SELECT version FROM process_runtime WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let level = version
        .map(|version| super::level_for_version(connection, version))
        .transpose()?;
    if matches!(level, Some(6 | 7)) {
        return verify_cohort(connection);
    }
    if catalog::family_present(connection)? {
        catalog::verify(connection)?;
        let populated: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM process_unused_recovery_reservations)",
            [],
            |row| row.get(0),
        )?;
        if populated {
            return Err(ProcessError::Configuration(
                "closed recovery custody cannot be a predecessor",
            ));
        }
    }
    Ok(())
}

pub(super) fn install_or_verify(connection: &Connection, version: u32) -> Result<(), ProcessError> {
    if !catalog::family_present(connection)? {
        if matches!(version, 6 | 7) {
            return Err(ProcessError::Configuration(
                "closed recovery catalog disappeared",
            ));
        }
        connection.execute_batch(catalog::SQL)?;
    }
    if matches!(version, 6 | 7) {
        verify_cohort(connection)
    } else {
        verify_before_open(connection)
    }
}

/// Only the exact retained predecessor guard may precede the known open upgrade.
pub(super) fn verify_retained_version_guard(connection: &Connection) -> Result<(), ProcessError> {
    catalog::verify_retained_version_guard(connection)
}
