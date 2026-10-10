//! Typed original reservation history and immutable Process lineage custody.
use super::*;
use crate::recovery::UnusedRecoveryReservationClosureData;

pub(super) fn metadata(
    connection: &Connection,
) -> Result<(u32, String, String, String), ProcessError> {
    let (version, namespace, authority, key): (
        u32,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = connection.query_row(
        "SELECT version,
         CASE WHEN typeof(namespace)='text' AND length(CAST(namespace AS BLOB)) BETWEEN 1 AND 256 THEN namespace END,
         CASE WHEN typeof(authority)='text' AND length(CAST(authority AS BLOB)) BETWEEN 1 AND 256 THEN authority END,
         CASE WHEN typeof(kernel_key)='text' AND length(CAST(kernel_key AS BLOB)) BETWEEN 1 AND 32768 THEN kernel_key END
         FROM process_runtime WHERE singleton=1",
        [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    )?;
    Ok((
        version,
        namespace.ok_or(ProcessError::Conflict)?,
        authority.ok_or(ProcessError::Conflict)?,
        key.ok_or(ProcessError::Conflict)?,
    ))
}

pub(super) fn lineage(
    connection: &Connection,
    process_id: &str,
) -> Result<(String, String), ProcessError> {
    let original = read_process(connection, process_id)?
        .ok_or_else(|| ProcessError::NotFound(process_id.to_owned()))?;
    let mut current = original.clone();
    let mut identities = Vec::new();
    loop {
        crate::verify_capability(&current.capability)?;
        identities.push((
            current.id.clone(),
            current.parent_id.clone(),
            current.root_id.clone(),
            current.depth,
            digest(&current.capability)?,
        ));
        if identities.len() > 65 || current.root_id != original.root_id {
            return Err(ProcessError::Conflict);
        }
        let Some(parent_id) = &current.parent_id else {
            if current.id != original.root_id || current.depth != 0 {
                return Err(ProcessError::Conflict);
            }
            break;
        };
        let parent = read_process(connection, parent_id)?
            .ok_or_else(|| ProcessError::NotFound(parent_id.clone()))?;
        if parent.depth.checked_add(1) != Some(current.depth) {
            return Err(ProcessError::Conflict);
        }
        crate::validate_child(&parent.capability, &current.capability)?;
        current = parent;
    }
    Ok((original.root_id, digest(&identities)?))
}

pub(super) fn unused(
    connection: &Connection,
    reservation: &RecoveryCallReservation,
) -> Result<(), ProcessError> {
    let (_, namespace, _, _) = metadata(connection)?;
    let process = read_process(connection, &reservation.process_id)?
        .ok_or_else(|| ProcessError::NotFound(reservation.process_id.clone()))?;
    if reservation.runtime_id != namespace
        || reservation.capability_digest != digest(&process.capability)?
        || reservation.operation_key != format!("recovery:{}", reservation.continuation_id.as_str())
        || reservation.request_id
            != format!(
                "process:{}",
                digest(&(
                    &namespace,
                    &reservation.process_id,
                    &reservation.operation_key
                ))?
            )
        || process.tree_calls == 0
    {
        return Err(ProcessError::Conflict);
    }
    let retained: Option<(String, Option<Vec<u8>>, Option<String>)> = connection.query_row(
        "SELECT continuation_id,
         CASE WHEN typeof(reservation)='blob' AND length(reservation) BETWEEN 1 AND 4096 THEN reservation END,
         final_binding FROM process_recovery_calls WHERE process_id=?1 AND operation_key=?2",
        params![reservation.process_id,reservation.operation_key],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).optional()?;
    let Some((continuation, bytes, final_binding)) = retained else {
        return Err(ProcessError::Conflict);
    };
    if continuation != reservation.continuation_id.as_str()
        || bytes.as_deref() != Some(chio_core_types::canonical_json_bytes(reservation)?.as_slice())
        || final_binding.is_some()
    {
        return Err(ProcessError::Conflict);
    }
    let participated: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM process_calls WHERE process_id=?1 AND operation_key=?2)
         OR EXISTS(SELECT 1 FROM process_call_nonces WHERE process_id=?1 AND operation_key=?2)",
        params![reservation.process_id, reservation.operation_key],
        |row| row.get(0),
    )?;
    if participated {
        return Err(ProcessError::Conflict);
    }
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    reservation: &RecoveryCallReservation,
) -> Result<Option<UnusedRecoveryReservationClosureData>, ProcessError> {
    let row: Option<(String, Option<Vec<u8>>)> = connection.query_row(
        "SELECT continuation_id,CASE WHEN typeof(closure)='blob' AND length(closure) BETWEEN 1 AND 16384 THEN closure END
         FROM process_unused_recovery_reservations WHERE process_id=?1 AND operation_key=?2",
        params![reservation.process_id,reservation.operation_key], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional()?;
    let Some((continuation, bytes)) = row else {
        return Ok(None);
    };
    let bytes = bytes.ok_or(ProcessError::Conflict)?;
    let value: UnusedRecoveryReservationClosureData = serde_json::from_slice(&bytes)?;
    if continuation != reservation.continuation_id.as_str()
        || value.reservation() != reservation
        || chio_core_types::canonical_json_bytes(&value)? != bytes
    {
        return Err(ProcessError::Conflict);
    }
    verify(connection, &value)?;
    Ok(Some(value))
}

pub(super) fn verify(
    connection: &Connection,
    value: &UnusedRecoveryReservationClosureData,
) -> Result<(), ProcessError> {
    let (version, namespace, authority, key) = metadata(connection)?;
    let (root, lineage) = lineage(connection, value.reservation().process_id())?;
    if !matches!(version, 6 | 7)
        || value.reservation().runtime_id != namespace
        || value.authority_domain() != authority
        || value.kernel_key() != key
        || value.root_process() != root
        || value.lineage_digest() != lineage
    {
        return Err(ProcessError::Conflict);
    }
    if version == 7 {
        super::super::confined_delivery::verify_cohort(connection)?;
    }
    unused(connection, value.reservation())
}
