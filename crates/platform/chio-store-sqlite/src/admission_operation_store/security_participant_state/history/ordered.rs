//! Fold separate native journal families in their anchored global order.
//! Each family retains its own sequence and hash chain, including join-v1 bytes.
use super::super::nonce_preflight;
use super::super::output;
use super::super::{egress, knowledge};
use super::*;

pub(in crate::admission_operation_store::security_participant_state) enum Event {
    Join(Box<Record>),
    Egress(Box<egress::Record>),
    Output(Box<output::Record>),
    NoncePreflight(Box<nonce_preflight::Record>),
    Knowledge(Box<knowledge::Record>),
}

impl Event {
    pub(in crate::admission_operation_store::security_participant_state) fn changes(
        &self,
    ) -> &[NativeRowChange] {
        match self {
            Self::Join(record) => record.changes.as_slice(),
            Self::Egress(record) => record.changes.as_slice(),
            Self::Output(record) => record.changes.as_slice(),
            Self::NoncePreflight(record) => record.changes.as_slice(),
            Self::Knowledge(record) => record.changes.as_slice(),
        }
    }
    pub(in crate::admission_operation_store::security_participant_state) fn totals(
        &self,
    ) -> (u64, u64) {
        match self {
            Self::Join(record) => (record.current_rows, record.current_bytes),
            Self::Egress(record) => (record.current_rows, record.current_bytes),
            Self::Output(record) => (record.current_rows, record.current_bytes),
            Self::NoncePreflight(record) => (record.current_rows, record.current_bytes),
            Self::Knowledge(record) => (record.current_rows, record.current_bytes),
        }
    }
}

pub(in crate::admission_operation_store::security_participant_state) fn validate_history_bounds(
    connection: &Connection,
    authority: &str,
) -> Result<(), AdmissionOperationStoreError> {
    journal_totals(connection, authority).map(|_| ())
}

/// Actual retained native bytes and journal slots of the live segment, above
/// the latest seal. Each compact knowledge root counts with its journal-owned
/// chunks. These totals are data and cannot discharge a pending source
/// purpose or create an allocation.
pub(in crate::admission_operation_store::security_participant_state) fn journal_totals(
    connection: &Connection,
    authority: &str,
) -> Result<(u64, u64), AdmissionOperationStoreError> {
    super::segments::live_totals(connection, authority)
}

/// Whether the operation's dispatch join was committed before `commit`.
fn joined_before(
    connection: &Connection,
    authority: &str,
    operation: &str,
    commit: i64,
) -> Result<bool, AdmissionOperationStoreError> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_state_mutations AS mutation
             JOIN authority_global_commits AS global
               ON global.projection_kind = 'security_participant_state'
              AND global.projection_key = mutation.security_authority_id
              AND global.projection_sequence = mutation.sequence
             WHERE mutation.security_authority_id = ?1 AND mutation.operation_id = ?2
               AND global.commit_sequence < ?3)",
            params![authority, operation, commit],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

/// Current native rows and bytes after the writer's latest journal entry, read
/// from its segment snapshot's family heads; the imported source before any.
pub(in crate::admission_operation_store::security_participant_state) fn latest_totals(
    connection: &Connection,
    segment: &super::segments::SegmentSnapshot,
) -> Result<(u64, u64), AdmissionOperationStoreError> {
    let authority = segment.authority();
    let Some((family, sequence)) = segment.latest(connection)? else {
        let (rows,bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_row)),0) FROM security_participant_migration_rows WHERE security_authority_id = ?1", [authority], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
        return Ok((
            u64::try_from(rows).map_err(invalid)?,
            u64::try_from(bytes).map_err(invalid)?,
        ));
    };
    match family {
        Some(super::segments::Family::Mutations) => {
            let record = super::load(connection, authority, sequence)?
                .ok_or_else(|| invalid("latest native join is absent"))?;
            Ok((record.current_rows, record.current_bytes))
        }
        Some(super::segments::Family::Egress) => {
            let record = egress::load(connection, authority, sequence)?
                .ok_or_else(|| invalid("latest native egress is absent"))?;
            Ok((record.current_rows, record.current_bytes))
        }
        Some(super::segments::Family::Output) => {
            let record = output::load(connection, authority, sequence)?
                .ok_or_else(|| invalid("latest native output is absent"))?;
            Ok((record.current_rows, record.current_bytes))
        }
        Some(super::segments::Family::NoncePreflight) => {
            let record = nonce_preflight::load(connection, authority, sequence)?
                .ok_or_else(|| invalid("latest native nonce_preflight is absent"))?;
            Ok((record.current_rows, record.current_bytes))
        }
        None => {
            let record = knowledge::load(connection, authority, sequence)?;
            Ok((record.current_rows, record.current_bytes))
        }
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
    let knowledge_head = knowledge::head(connection, authority)?;
    let mut knowledge_sequence = 0;
    let mut knowledge_previous = initialization.digest.clone();
    let mut join_sequence = 1;
    let output_head = if output::exists(connection)? {
        output::head(connection, authority)?
    } else {
        0
    };
    let nonce_preflight_head = if nonce_preflight::exists(connection)? {
        nonce_preflight::head(connection, authority)?
    } else {
        0
    };
    let mut nonce_preflight_sequence = 0;
    let mut nonce_preflight_previous = initialization.digest.clone();
    let mut output_sequence = 0;
    let mut output_previous = initialization.digest.clone();
    let mut egress_sequence = 0;
    let mut join_previous = initialization.digest.clone();
    let mut egress_previous = initialization.digest.clone();
    let mut observed_at = initialization.initialized_at;
    let mut initialized = false;
    let mut statement = connection.prepare("SELECT projection_kind, projection_key, projection_sequence, commit_sequence FROM authority_global_commits WHERE (projection_key = ?1
        AND projection_kind IN ('security_participant_state','security_participant_egress','security_participant_output','security_participant_nonce_preflight')) OR (projection_kind='recovery' AND projection_key GLOB ?2) ORDER BY commit_sequence").map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            authority,
            format!("{}*", knowledge::prefix(authority))
        ])
        .map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let kind: String = row.get(0).map_err(sqlite_error)?;
        let key: String = row.get(1).map_err(sqlite_error)?;
        let sequence =
            u64::try_from(row.get::<_, i64>(2).map_err(sqlite_error)?).map_err(invalid)?;
        let commit: i64 = row.get(3).map_err(sqlite_error)?;
        if kind == "security_participant_state" && sequence == 1 {
            if initialized
                || join_sequence != 1
                || egress_sequence != 0
                || output_sequence != 0
                || nonce_preflight_sequence != 0
                || knowledge_sequence != 0
            {
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
                    || !joined_before(
                        connection,
                        authority,
                        operation.binding().operation_id().as_str(),
                        commit,
                    )?
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
                    || !joined_before(
                        connection,
                        authority,
                        record.intent.operation_id().as_str(),
                        commit,
                    )?
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
            "security_participant_nonce_preflight" => {
                let record = nonce_preflight::load(connection, authority, sequence)?
                    .ok_or_else(|| invalid("native global nonce_preflight is absent"))?;
                if sequence != nonce_preflight_sequence + 1
                    || record.initialization != initialization.digest
                    || record.previous != nonce_preflight_previous
                    || record.lease.fence.store_uuid != initialization.fence.store_uuid
                    || record.observed_at < observed_at
                    || joined_before(
                        connection,
                        authority,
                        record.intent.operation_id().as_str(),
                        commit,
                    )?
                {
                    return Err(invalid(
                        "native nonce preflight family is out of global order or follows a dispatch join",
                    ));
                }
                nonce_preflight_sequence = sequence;
                nonce_preflight_previous = record.digest()?;
                observed_at = record.observed_at;
                Event::NoncePreflight(Box::new(record))
            }
            "recovery" => {
                knowledge_sequence += 1;
                let (record, digest) =
                    knowledge::load_with_digest(connection, authority, knowledge_sequence)?;
                let expected_key =
                    format!("{}{knowledge_sequence:016}", knowledge::prefix(authority));
                if sequence != 1
                    || key != expected_key
                    || record.initialization != initialization.digest
                    || record.previous != knowledge_previous
                    || record.observed_at < observed_at
                {
                    return Err(invalid("knowledge join family is out of global order"));
                }
                knowledge_previous = digest;
                observed_at = record.observed_at;
                Event::Knowledge(Box::new(record))
            }
            _ => return Err(invalid("unknown native journal family")),
        };
        apply(&event)?;
    }
    if !initialized
        || join_sequence != join_head
        || egress_sequence != egress_head
        || output_sequence != output_head
        || nonce_preflight_sequence != nonce_preflight_head
        || knowledge_sequence != knowledge_head
    {
        return Err(invalid(
            "native journal events lack complete global coverage",
        ));
    }
    Ok(())
}
