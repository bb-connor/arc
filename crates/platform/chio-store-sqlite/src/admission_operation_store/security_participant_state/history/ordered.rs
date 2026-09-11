//! Fold separate native journal families in their anchored global order.
//! Each family retains its own sequence and hash chain, including join-v1 bytes.
use super::super::egress;
use super::super::output;
use super::*;
use std::collections::BTreeSet;

pub(in crate::admission_operation_store::security_participant_state) enum Event {
    Join(Box<Record>),
    Egress(Box<egress::Record>),
    Output(Box<output::Record>),
}

impl Event {
    pub(in crate::admission_operation_store::security_participant_state) fn changes(
        &self,
    ) -> &[NativeRowChange] {
        match self {
            Self::Join(record) => record.changes.as_slice(),
            Self::Egress(record) => record.changes.as_slice(),
            Self::Output(record) => record.changes.as_slice(),
        }
    }
    pub(in crate::admission_operation_store::security_participant_state) fn totals(
        &self,
    ) -> (u64, u64) {
        match self {
            Self::Join(record) => (record.current_rows, record.current_bytes),
            Self::Egress(record) => (record.current_rows, record.current_bytes),
            Self::Output(record) => (record.current_rows, record.current_bytes),
        }
    }
}

pub(in crate::admission_operation_store::security_participant_state) fn validate_history_bounds(
    connection: &Connection,
    authority: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let (mut count, mut bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_record)),0) FROM security_participant_state_mutations WHERE security_authority_id = ?1", [authority], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
    if egress::exists(connection)? {
        let (extra_count,extra_bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_record)),0) FROM security_participant_egress_events WHERE security_authority_id = ?1", [authority], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
        count = count
            .checked_add(extra_count)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        bytes = bytes
            .checked_add(extra_bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
    }
    if output::exists(connection)? {
        let (extra_count,extra_bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_record)),0) FROM security_participant_output_events WHERE security_authority_id = ?1", [authority], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
        count = count
            .checked_add(extra_count)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        bytes = bytes
            .checked_add(extra_bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
    }
    if !(0..=65_536).contains(&count) || !(0..=67_108_864).contains(&bytes) {
        return Err(invalid("combined native journal exceeds bounds"));
    }
    Ok(())
}

pub(in crate::admission_operation_store::security_participant_state) fn latest_totals(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<(u64, u64), AdmissionOperationStoreError> {
    let authority = initialization.authority.as_str();
    let last: Option<(String,i64)> = connection.query_row("SELECT projection_kind, projection_sequence FROM authority_global_commits
        WHERE projection_key = ?1 AND ((projection_kind = 'security_participant_state' AND projection_sequence > 1)
           OR projection_kind IN ('security_participant_egress','security_participant_output')) ORDER BY commit_sequence DESC LIMIT 1", [authority], |row| Ok((row.get(0)?,row.get(1)?))).optional().map_err(sqlite_error)?;
    let Some((kind, sequence)) = last else {
        let (rows,bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_row)),0) FROM security_participant_migration_rows WHERE security_authority_id = ?1", [authority], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
        return Ok((
            u64::try_from(rows).map_err(invalid)?,
            u64::try_from(bytes).map_err(invalid)?,
        ));
    };
    let sequence = u64::try_from(sequence).map_err(invalid)?;
    match kind.as_str() {
        "security_participant_state" => {
            let record = super::load(connection, authority, sequence)?
                .ok_or_else(|| invalid("latest native join is absent"))?;
            Ok((record.current_rows, record.current_bytes))
        }
        "security_participant_egress" => {
            let record = egress::load(connection, authority, sequence)?
                .ok_or_else(|| invalid("latest native egress is absent"))?;
            Ok((record.current_rows, record.current_bytes))
        }
        "security_participant_output" => {
            let record = output::load(connection, authority, sequence)?
                .ok_or_else(|| invalid("latest native output is absent"))?;
            Ok((record.current_rows, record.current_bytes))
        }
        _ => Err(invalid("unknown native journal family")),
    }
}

pub(in crate::admission_operation_store::security_participant_state) fn visit(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
    mut apply: impl FnMut(&Event) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    let authority = initialization.authority.as_str();
    validate_history_bounds(connection, authority)?;
    let join_head = super::head(connection, authority)?;
    let egress_head = if egress::exists(connection)? {
        egress::head(connection, authority)?
    } else {
        0
    };
    let mut join_sequence = 1;
    let output_head = if output::exists(connection)? {
        output::head(connection, authority)?
    } else {
        0
    };
    let mut output_sequence = 0;
    let mut output_previous = initialization.digest.clone();
    let mut egress_sequence = 0;
    let mut join_previous = initialization.digest.clone();
    let mut egress_previous = initialization.digest.clone();
    let mut observed_at = initialization.initialized_at;
    let mut initialized = false;
    let mut joined = BTreeSet::new();
    let mut statement = connection.prepare("SELECT projection_kind, projection_sequence FROM authority_global_commits WHERE projection_key = ?1
        AND projection_kind IN ('security_participant_state','security_participant_egress','security_participant_output') ORDER BY commit_sequence").map_err(sqlite_error)?;
    let mut rows = statement.query([authority]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let kind: String = row.get(0).map_err(sqlite_error)?;
        let sequence =
            u64::try_from(row.get::<_, i64>(1).map_err(sqlite_error)?).map_err(invalid)?;
        if kind == "security_participant_state" && sequence == 1 {
            if initialized || join_sequence != 1 || egress_sequence != 0 || output_sequence != 0 {
                return Err(invalid(
                    "native initialization is not the first global event",
                ));
            }
            initialized = true;
            continue;
        }
        if !initialized {
            return Err(invalid("native event precedes global initialization"));
        }
        let event = match kind.as_str() {
            "security_participant_state" => {
                let record = super::load(connection, authority, sequence)?
                    .ok_or_else(|| invalid("native global join is absent"))?;
                if sequence != join_sequence + 1
                    || record.initialization != initialization.digest
                    || record.previous != join_previous
                    || record.lease.fence.store_uuid != initialization.fence.store_uuid
                    || record.observed_at < observed_at
                {
                    return Err(invalid("native join family is out of global order"));
                }
                join_sequence = sequence;
                join_previous = record.digest()?;
                observed_at = record.observed_at;
                joined.insert(
                    AdmissionOperationV1::from_persisted(record.operation.clone())?
                        .binding()
                        .operation_id()
                        .clone(),
                );
                Event::Join(Box::new(record))
            }
            "security_participant_egress" => {
                let record = egress::load(connection, authority, sequence)?
                    .ok_or_else(|| invalid("native global egress is absent"))?;
                let operation = AdmissionOperationV1::from_persisted(record.operation.clone())?;
                if sequence != egress_sequence + 1
                    || record.initialization != initialization.digest
                    || record.previous != egress_previous
                    || record.lease.fence.store_uuid != initialization.fence.store_uuid
                    || record.observed_at < observed_at
                    || !joined.contains(operation.binding().operation_id())
                {
                    return Err(invalid(
                        "native egress family is out of global order or precedes its join",
                    ));
                }
                egress_sequence = sequence;
                egress_previous = record.digest()?;
                observed_at = record.observed_at;
                Event::Egress(Box::new(record))
            }
            "security_participant_output" => {
                let record = output::load(connection, authority, sequence)?
                    .ok_or_else(|| invalid("native global output is absent"))?;
                if sequence != output_sequence + 1
                    || record.initialization != initialization.digest
                    || record.previous != output_previous
                    || record.lease.fence.store_uuid != initialization.fence.store_uuid
                    || record.observed_at < observed_at
                    || !joined.contains(record.intent.operation_id())
                {
                    return Err(invalid(
                        "native output family is out of global order or precedes its input join",
                    ));
                }
                output_sequence = sequence;
                output_previous = record.digest()?;
                observed_at = record.observed_at;
                Event::Output(Box::new(record))
            }
            _ => return Err(invalid("unknown native journal family")),
        };
        apply(&event)?;
    }
    if !initialized
        || join_sequence != join_head
        || egress_sequence != egress_head
        || output_sequence != output_head
    {
        return Err(invalid(
            "native journal events lack complete global coverage",
        ));
    }
    Ok(())
}
