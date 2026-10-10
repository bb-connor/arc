//! Fold separate native journal families in their anchored global order.
//! Each family retains its own sequence and hash chain, including join-v1 bytes.
use super::super::checkpoint;
use super::super::egress;
use super::super::nonce_preflight;
use super::super::output;
use super::*;

const MAX_JOURNAL_EVENTS: i64 = 65_536;
const MAX_JOURNAL_BYTES: i64 = 67_108_864;

#[cfg(test)]
thread_local! {
    static TEST_JOURNAL_BOUNDS: std::cell::Cell<(i64, i64)> =
        const { std::cell::Cell::new((MAX_JOURNAL_EVENTS, MAX_JOURNAL_BYTES)) };
}

#[cfg(test)]
pub(in crate::admission_operation_store) fn with_test_bounds<T>(
    events: i64,
    bytes: i64,
    run: impl FnOnce() -> T,
) -> T {
    assert!((1..=MAX_JOURNAL_EVENTS).contains(&events));
    assert!((1..=MAX_JOURNAL_BYTES).contains(&bytes));
    struct Reset((i64, i64));
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_JOURNAL_BOUNDS.set(self.0);
        }
    }
    let _reset = Reset(TEST_JOURNAL_BOUNDS.replace((events, bytes)));
    run()
}

fn journal_bounds() -> (i64, i64) {
    #[cfg(test)]
    return TEST_JOURNAL_BOUNDS.get();
    #[cfg(not(test))]
    (MAX_JOURNAL_EVENTS, MAX_JOURNAL_BYTES)
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Observe every ordered native journal walk on this authority connection,
    /// whichever thread runs it. The observer receives zero when a walk starts,
    /// then the walk's running event count after each anchored event. It cannot
    /// change a verification result and is absent from production builds.
    pub fn observe_native_history_visits_for_test(
        &self,
        observer: impl Fn(u64) + Send + std::panic::UnwindSafe + 'static,
    ) -> Result<(), AdmissionOperationStoreError> {
        use rusqlite::functions::FunctionFlags;
        let connection = self.connection()?;
        connection
            .create_scalar_function(
                "native_history_visit_probe",
                1,
                FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DIRECTONLY,
                move |context| {
                    let visited = u64::try_from(context.get::<i64>(0)?)
                        .map_err(|error| rusqlite::Error::UserFunctionError(Box::new(error)))?;
                    observer(visited);
                    Ok(0_i32)
                },
            )
            .map_err(sqlite_error)?;
        connection
            .execute_batch("CREATE TEMP TABLE IF NOT EXISTS native_history_visit_probe_installed (singleton INTEGER PRIMARY KEY CHECK(singleton = 1))")
            .map_err(sqlite_error)
    }
}

#[cfg(feature = "admission-test-support")]
struct VisitProbe {
    installed: bool,
    visited: u64,
}

#[cfg(feature = "admission-test-support")]
impl VisitProbe {
    fn start(connection: &Connection) -> Result<Self, AdmissionOperationStoreError> {
        let installed = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_temp_schema WHERE type = 'table' AND name = 'native_history_visit_probe_installed')",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let probe = Self {
            installed,
            visited: 0,
        };
        probe.report(connection)?;
        Ok(probe)
    }

    fn advance(&mut self, connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
        self.visited = self
            .visited
            .checked_add(1)
            .ok_or_else(|| invalid("native history visit count overflow"))?;
        self.report(connection)
    }

    fn report(&self, connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
        if self.installed {
            let _: i32 = connection
                .query_row(
                    "SELECT native_history_visit_probe(?1)",
                    [i64::try_from(self.visited).map_err(invalid)?],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
        }
        Ok(())
    }
}

pub(in crate::admission_operation_store::security_participant_state) enum Event {
    Join(Box<Record>),
    Egress(Box<egress::Record>),
    Output(Box<output::Record>),
    NoncePreflight(Box<nonce_preflight::Record>),
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
        }
    }
}

pub(in crate::admission_operation_store::security_participant_state) fn validate_history_bounds(
    connection: &Connection,
    authority: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let (count, bytes) = segment_totals(connection, authority)?;
    let (max_events, max_bytes) = journal_bounds();
    if !(0..=max_events).contains(&count) || !(0..=max_bytes).contains(&bytes) {
        return Err(invalid("combined native journal exceeds bounds"));
    }
    Ok(())
}

pub(in crate::admission_operation_store::security_participant_state) fn segment_totals(
    connection: &Connection,
    authority: &str,
) -> Result<(i64, i64), AdmissionOperationStoreError> {
    let floors = checkpoint::floors(connection, authority)?;
    let (mut count, mut bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_record)),0) FROM security_participant_state_mutations WHERE security_authority_id = ?1 AND sequence > ?2", params![authority,i64::try_from(floors[0]).map_err(invalid)?], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
    if egress::exists(connection)? {
        let (extra_count,extra_bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_record)),0) FROM security_participant_egress_events WHERE security_authority_id = ?1 AND sequence > ?2", params![authority,i64::try_from(floors[1]).map_err(invalid)?], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
        count = count
            .checked_add(extra_count)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        bytes = bytes
            .checked_add(extra_bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
    }
    if output::exists(connection)? {
        let (extra_count,extra_bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_record)),0) FROM security_participant_output_events WHERE security_authority_id = ?1 AND sequence > ?2", params![authority,i64::try_from(floors[2]).map_err(invalid)?], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
        count = count
            .checked_add(extra_count)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        bytes = bytes
            .checked_add(extra_bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
    }
    if nonce_preflight::exists(connection)? {
        let (extra_count,extra_bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_record)),0) FROM security_participant_nonce_preflight_events WHERE security_authority_id = ?1 AND sequence > ?2", params![authority,i64::try_from(floors[3]).map_err(invalid)?], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
        count = count
            .checked_add(extra_count)
            .ok_or_else(|| invalid("native journal count overflow"))?;
        bytes = bytes
            .checked_add(extra_bytes)
            .ok_or_else(|| invalid("native journal byte overflow"))?;
    }
    Ok((count, bytes))
}

pub(in crate::admission_operation_store::security_participant_state) fn family_head(
    connection: &Connection,
    authority: &str,
    table: &str,
    family: usize,
) -> Result<u64, AdmissionOperationStoreError> {
    let floor = checkpoint::floors(connection, authority)?
        .get(family)
        .copied()
        .ok_or_else(|| invalid("native journal family is out of range"))?;
    let floor_i64 = i64::try_from(floor).map_err(invalid)?;
    let (count,first,last,bytes): (i64,i64,i64,i64) = connection.query_row(&format!(
        "SELECT COUNT(*),COALESCE(MIN(sequence),?2),COALESCE(MAX(sequence),?2),COALESCE(SUM(length(canonical_record)),0)
         FROM {table} WHERE security_authority_id = ?1 AND sequence > ?2"
    ),params![authority,floor_i64],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).map_err(sqlite_error)?;
    if !(0..=MAX_JOURNAL_EVENTS).contains(&count)
        || !(0..=MAX_JOURNAL_BYTES).contains(&bytes)
        || last
            != floor_i64
                .checked_add(count)
                .ok_or_else(|| invalid("native suffix sequence overflow"))?
        || (count > 0 && first != floor_i64 + 1)
    {
        return Err(invalid("native journal suffix exceeds bounds or has gaps"));
    }
    u64::try_from(last).map_err(invalid)
}

pub(in crate::admission_operation_store::security_participant_state) fn latest_totals(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
) -> Result<(u64, u64), AdmissionOperationStoreError> {
    let authority = initialization.authority.as_str();
    let checkpoint = checkpoint::latest(connection, authority)?;
    let mut last = checkpoint
        .as_ref()
        .map(|record| (record.global_sequence + 1, String::new(), 0_u64));
    let candidates = [
        (
            "security_participant_state",
            super::head(connection, authority)?,
        ),
        (
            "security_participant_egress",
            if egress::exists(connection)? {
                egress::head(connection, authority)?
            } else {
                0
            },
        ),
        (
            "security_participant_output",
            if output::exists(connection)? {
                output::head(connection, authority)?
            } else {
                0
            },
        ),
        (
            "security_participant_nonce_preflight",
            if nonce_preflight::exists(connection)? {
                nonce_preflight::head(connection, authority)?
            } else {
                0
            },
        ),
    ];
    for (kind, sequence) in candidates {
        if sequence == 0 || (kind == "security_participant_state" && sequence == 1) {
            continue;
        }
        let commit: i64 = connection.query_row(
            "SELECT commit_sequence FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2 AND projection_sequence = ?3",
            params![kind,authority,i64::try_from(sequence).map_err(invalid)?],|row|row.get(0),
        ).map_err(sqlite_error)?;
        let commit = u64::try_from(commit).map_err(invalid)?;
        if last.as_ref().is_none_or(|previous| commit > previous.0) {
            last = Some((commit, kind.into(), sequence));
        }
    }
    let last = last.map(|(_, kind, sequence)| (kind, sequence));
    let Some((kind, sequence)) = last else {
        let (rows,bytes): (i64,i64) = connection.query_row("SELECT COUNT(*), COALESCE(SUM(length(canonical_row)),0) FROM security_participant_migration_rows WHERE security_authority_id = ?1", [authority], |row| Ok((row.get(0)?,row.get(1)?))).map_err(sqlite_error)?;
        return Ok((
            u64::try_from(rows).map_err(invalid)?,
            u64::try_from(bytes).map_err(invalid)?,
        ));
    };
    match kind.as_str() {
        "" => checkpoint
            .map(|record| (record.current_rows, record.current_bytes))
            .ok_or_else(|| invalid("native checkpoint totals are absent")),
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
        "security_participant_nonce_preflight" => {
            let record = nonce_preflight::load(connection, authority, sequence)?
                .ok_or_else(|| invalid("latest native nonce_preflight is absent"))?;
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
    // Recheck the initialization once for this history traversal. No verification
    // result survives this call or crosses a transaction/mutation boundary.
    if super::super::records::load_metadata(connection, authority)?.as_ref() != Some(initialization)
    {
        return Err(invalid("native history initialization changed"));
    }
    validate_history_bounds(connection, authority)?;
    let checkpoint = checkpoint::latest(connection, authority)?;
    let join_head = super::head(connection, authority)?;
    let egress_head = if egress::exists(connection)? {
        egress::head(connection, authority)?
    } else {
        0
    };
    let floors = checkpoint.as_ref().map_or([1, 0, 0, 0], |record| {
        record.heads.each_ref().map(|head| head.sequence)
    });
    let mut join_sequence = floors[0];
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
    let [mut join_previous, mut egress_previous, mut output_previous, mut nonce_preflight_previous] =
        checkpoint.as_ref().map_or_else(
            || std::array::from_fn(|_| initialization.digest.clone()),
            |record| record.heads.each_ref().map(|head| head.digest.clone()),
        );
    let mut nonce_preflight_sequence = floors[3];
    let mut output_sequence = floors[2];
    let mut egress_sequence = floors[1];
    let mut observed_at = checkpoint
        .as_ref()
        .map_or(initialization.initialized_at, |record| record.observed_at);
    let mut initialized = checkpoint.is_some();
    let join_floor = if checkpoint.is_some() { floors[0] } else { 0 };
    let mut statement = connection.prepare("SELECT projection_kind, projection_sequence, mutation_kind, projection_reference_digest, store_uuid, store_lease_id, store_owner_epoch,commit_sequence FROM authority_global_commits WHERE projection_key = ?1
        AND ((projection_kind = 'security_participant_state' AND projection_sequence > ?2)
          OR (projection_kind = 'security_participant_egress' AND projection_sequence > ?3)
          OR (projection_kind = 'security_participant_output' AND projection_sequence > ?4)
          OR (projection_kind = 'security_participant_nonce_preflight' AND projection_sequence > ?5)) ORDER BY commit_sequence").map_err(sqlite_error)?;
    let mut rows = statement
        .query(params![
            authority,
            i64::try_from(join_floor).map_err(invalid)?,
            i64::try_from(floors[1]).map_err(invalid)?,
            i64::try_from(floors[2]).map_err(invalid)?,
            i64::try_from(floors[3]).map_err(invalid)?
        ])
        .map_err(sqlite_error)?;
    #[cfg(feature = "admission-test-support")]
    let mut probe = VisitProbe::start(connection)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        #[cfg(feature = "admission-test-support")]
        probe.advance(connection)?;
        let kind: String = row.get(0).map_err(sqlite_error)?;
        let sequence =
            u64::try_from(row.get::<_, i64>(1).map_err(sqlite_error)?).map_err(invalid)?;
        let global_sequence =
            u64::try_from(row.get::<_, i64>(7).map_err(sqlite_error)?).map_err(invalid)?;
        if kind == "security_participant_state" && sequence == 1 {
            if initialized
                || join_sequence != 1
                || egress_sequence != 0
                || output_sequence != 0
                || nonce_preflight_sequence != 0
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
                let record = egress::load_initialized(connection, initialization, sequence)?
                    .ok_or_else(|| invalid("native global egress is absent"))?;
                let operation = AdmissionOperationV1::from_persisted(record.operation.clone())?;
                if sequence != egress_sequence + 1
                    || record.initialization != initialization.digest
                    || record.previous != egress_previous
                    || record.lease.fence.store_uuid != initialization.fence.store_uuid
                    || record.observed_at < observed_at
                    || !join_precedes(
                        connection,
                        initialization,
                        operation.binding().operation_id(),
                        global_sequence,
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
                let record = output::load_initialized(connection, initialization, sequence)?
                    .ok_or_else(|| invalid("native global output is absent"))?;
                if sequence != output_sequence + 1
                    || record.initialization != initialization.digest
                    || record.previous != output_previous
                    || record.lease.fence.store_uuid != initialization.fence.store_uuid
                    || record.observed_at < observed_at
                    || !join_precedes(
                        connection,
                        initialization,
                        record.intent.operation_id(),
                        global_sequence,
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
                let record =
                    nonce_preflight::load_initialized(connection, initialization, sequence)?
                        .ok_or_else(|| invalid("native global nonce_preflight is absent"))?;
                if sequence != nonce_preflight_sequence + 1
                    || record.initialization != initialization.digest
                    || record.previous != nonce_preflight_previous
                    || record.lease.fence.store_uuid != initialization.fence.store_uuid
                    || record.observed_at < observed_at
                    || join_precedes(
                        connection,
                        initialization,
                        record.intent.operation_id(),
                        global_sequence,
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
            _ => return Err(invalid("unknown native journal family")),
        };
        let (mutation, digest, fence) = match &event {
            Event::Join(record) => (super::MUTATION, record.digest()?, &record.lease.fence),
            Event::Egress(record) => (record.mutation(), record.digest()?, &record.lease.fence),
            Event::Output(record) => (output::MUTATION, record.digest()?, &record.lease.fence),
            Event::NoncePreflight(record) => (
                nonce_preflight::MUTATION,
                record.digest()?,
                &record.lease.fence,
            ),
        };
        if row.get::<_, String>(2).map_err(sqlite_error)? != mutation
            || row.get::<_, String>(3).map_err(sqlite_error)? != digest
            || row.get::<_, String>(4).map_err(sqlite_error)? != fence.store_uuid
            || row
                .get::<_, Option<String>>(5)
                .map_err(sqlite_error)?
                .as_deref()
                != Some(fence.lease_id.as_str())
            || row.get::<_, i64>(6).map_err(sqlite_error)?
                != i64::try_from(fence.owner_epoch).map_err(invalid)?
        {
            return Err(invalid("native event differs from its exact global commit"));
        }
        apply(&event)?;
    }
    if !initialized
        || join_sequence != join_head
        || egress_sequence != egress_head
        || output_sequence != output_head
        || nonce_preflight_sequence != nonce_preflight_head
    {
        return Err(invalid(
            "native journal events lack complete global coverage",
        ));
    }
    Ok(())
}

fn join_precedes(
    connection: &Connection,
    initialization: &SecurityParticipantStateInitialization,
    operation: &AdmissionOperationId,
    global_sequence: u64,
) -> Result<bool, AdmissionOperationStoreError> {
    let Some(record) = super::load_for_operation(connection, operation)? else {
        return Ok(false);
    };
    if record.authority != initialization.authority
        || record.initialization != initialization.digest
    {
        return Err(invalid("native predecessor join changed initialization"));
    }
    let (count,commit): (i64,Option<i64>) = connection.query_row(
        "SELECT COUNT(*),MIN(commit_sequence) FROM authority_global_commits WHERE projection_kind = 'security_participant_state'
         AND projection_key = ?1 AND projection_sequence = ?2 AND mutation_kind = ?3 AND projection_reference_digest = ?4
         AND store_uuid = ?5 AND store_lease_id = ?6 AND store_owner_epoch = ?7",
        params![record.authority.as_str(),i64::try_from(record.sequence).map_err(invalid)?,super::MUTATION,record.digest()?,
            record.lease.fence.store_uuid,record.lease.fence.lease_id,i64::try_from(record.lease.fence.owner_epoch).map_err(invalid)?],
        |row|Ok((row.get(0)?,row.get(1)?)),
    ).map_err(sqlite_error)?;
    if count != 1 {
        return Err(invalid(
            "native predecessor join lacks exact global custody",
        ));
    }
    Ok(
        u64::try_from(commit.ok_or_else(|| invalid("native predecessor join commit absent"))?)
            .map_err(invalid)?
            < global_sequence,
    )
}
