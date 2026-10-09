//! Retained snapshots authorized by exact global references and current custody.
use super::*;

mod cadence;
mod compaction;
mod record;
mod rows;
mod schema;
#[cfg(test)]
pub(in crate::admission_operation_store) use compaction::with_test_pinning_operations;
pub(crate) use compaction::NativeCompactionAuthority;
pub(super) use record::{FamilyHead, Record};
pub(in crate::admission_operation_store) use schema::{require_absent, sql, verify_catalog};

const PROJECTION: &str = "security_participant_checkpoint";
const MUTATION: &str = "checkpoint_security_participant_history";

pub(super) fn latest(
    connection: &Connection,
    authority: &str,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    record::latest(connection, authority)
}

pub(super) fn floors(
    connection: &Connection,
    authority: &str,
) -> Result<[u64; 4], AdmissionOperationStoreError> {
    Ok(
        latest(connection, authority)?.map_or([1, 0, 0, 0], |record| {
            record.heads.map(|head| head.sequence)
        }),
    )
}

pub(super) fn visit_rows(
    connection: &Connection,
    record: &Record,
    apply: impl FnMut(&str, &[u8]) -> Result<(), AdmissionOperationStoreError>,
) -> Result<(), AdmissionOperationStoreError> {
    rows::visit(connection, record, apply)
}

fn heads(
    connection: &Connection,
    initialized: &SecurityParticipantStateInitialization,
) -> Result<[FamilyHead; 4], AdmissionOperationStoreError> {
    let authority = initialized.authority.as_str();
    let join = history::head(connection, authority)?;
    let egress = egress::head(connection, authority)?;
    let output = output::head(connection, authority)?;
    let nonce = nonce_preflight::head(connection, authority)?;
    Ok([
        FamilyHead {
            sequence: join,
            digest: if join == 1 {
                initialized.digest.clone()
            } else {
                let record = history::load(connection, authority, join)?
                    .ok_or_else(|| invalid("checkpoint join head absent"))?;
                super::integrity::verify_event_reference(
                    connection,
                    super::PROJECTION_KIND,
                    authority,
                    join,
                    history::MUTATION,
                    &record.digest()?,
                    &record.lease.fence,
                )?;
                record.digest()?
            },
        },
        FamilyHead {
            sequence: egress,
            digest: if egress == 0 {
                initialized.digest.clone()
            } else {
                let record = egress::load(connection, authority, egress)?
                    .ok_or_else(|| invalid("checkpoint egress head absent"))?;
                super::integrity::verify_event_reference(
                    connection,
                    "security_participant_egress",
                    authority,
                    egress,
                    record.mutation(),
                    &record.digest()?,
                    &record.lease.fence,
                )?;
                record.digest()?
            },
        },
        FamilyHead {
            sequence: output,
            digest: if output == 0 {
                initialized.digest.clone()
            } else {
                let record = output::load(connection, authority, output)?
                    .ok_or_else(|| invalid("checkpoint output head absent"))?;
                super::integrity::verify_event_reference(
                    connection,
                    "security_participant_output",
                    authority,
                    output,
                    output::MUTATION,
                    &record.digest()?,
                    &record.lease.fence,
                )?;
                record.digest()?
            },
        },
        FamilyHead {
            sequence: nonce,
            digest: if nonce == 0 {
                initialized.digest.clone()
            } else {
                let record = nonce_preflight::load(connection, authority, nonce)?
                    .ok_or_else(|| invalid("checkpoint nonce head absent"))?;
                super::integrity::verify_event_reference(
                    connection,
                    "security_participant_nonce_preflight",
                    authority,
                    nonce,
                    nonce_preflight::MUTATION,
                    &record.digest()?,
                    &record.lease.fence,
                )?;
                record.digest()?
            },
        },
    ])
}

impl SqliteAdmissionOperationStore {
    /// Seal the exact current native rows and journal prefix under current
    /// serving ownership. The unchanged 65,536-event / 64-MiB cap then applies
    /// to the suffix. Call this explicit operator maintenance method before
    /// capacity exhaustion, or after a denied append has rolled back, then retry
    /// the same operation. It retains all old events and claims, keeps the same
    /// initialization and labels, and creates no invocation or dispatch permit.
    /// Finished transition and egress-fence rows leave the current state; their
    /// identities stay in the immutable journals.
    ///
    /// Use the initialized authority selected by the trusted host and the
    /// current serving fence. Caller time is only checked for skew; the owner
    /// clock supplies checkpoint time. Repeating without new events or newly
    /// dead rows returns the prior anchored digest. Commit/anchor uncertainty
    /// requires reopen.
    pub fn checkpoint_security_participant_history(
        &self,
        initialized: &SecurityParticipantStateInitialization,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
        self.checkpoint_history(
            cadence::Selection::Initialization(initialized),
            fence,
            trusted_now_unix_ms,
            false,
        )?
        .ok_or_else(|| invalid("explicit native checkpoint was not retained"))
    }

    pub(in crate::admission_operation_store) fn checkpoint_selected_native_history_if_due(
        &self,
        binding: &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<AdmissionDigest>, AdmissionOperationStoreError> {
        self.checkpoint_history(
            cadence::Selection::Binding(binding),
            fence,
            trusted_now_unix_ms,
            true,
        )
    }

    fn checkpoint_history(
        &self,
        selected: cadence::Selection<'_>,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
        automatic: bool,
    ) -> Result<Option<AdmissionDigest>, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        if !schema::present(&tx)? {
            return Err(invalid("native checkpoint requires admission schema v36"));
        }
        let observed_at = observed_time(&tx, trusted_now_unix_ms, &self.serving_owner)?;
        let actual = super::records::load(&tx, selected.authority())?
            .ok_or_else(|| invalid("native checkpoint initialization is absent"))?;
        if !selected.matches(&actual)? || fence.store_uuid != actual.fence.store_uuid {
            return Err(invalid("native checkpoint selected initialization differs"));
        }
        let heads = heads(&tx, &actual)?;
        let previous = latest(&tx, actual.authority.as_str())?;
        let unchanged = previous
            .as_ref()
            .is_some_and(|previous| previous.heads == heads);
        let (events, bytes) = history::ordered::segment_totals(&tx, actual.authority.as_str())?;
        history::ordered::validate_history_bounds(&tx, actual.authority.as_str())?;
        let due = cadence::due(events)?;
        // A pending fence can expire without any new event. Explicit
        // maintenance, and automatic maintenance within one event of the
        // current-row budget, therefore always look for dead rows.
        let sweep = !automatic || super::storage::within_event_of_budget(&tx)?;
        // Current rows were authenticated above in this transaction. Only rows
        // that no later native command can read leave the sealed snapshot.
        let dead = if due || sweep {
            compaction::plan(&tx, actual.authority.as_str(), observed_at)?
        } else {
            Vec::new()
        };
        let seal = if automatic {
            due || !dead.is_empty()
        } else {
            !unchanged || !dead.is_empty()
        };
        if !seal {
            return match (&previous, automatic) {
                (Some(previous), false) => {
                    AdmissionDigest::try_new("native_checkpoint", previous.digest()?)
                        .map(Some)
                        .map_err(Into::into)
                }
                _ => Ok(None),
            };
        }
        let sequence = previous.as_ref().map_or(Ok(1), |record| {
            record
                .sequence
                .checked_add(1)
                .ok_or_else(|| invalid("native checkpoint sequence overflow"))
        })?;
        let (global_sequence,global_digest): (i64,String) = tx.query_row(
            "SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).map_err(sqlite_error)?;
        let tx = compaction::compact(tx, actual.authority.as_str(), observed_at, dead)?;
        let (tables, current_rows, current_bytes) =
            rows::copy(&tx, actual.authority.as_str(), sequence)?;
        super::cutpoint(70)?;
        let record = Record {
            schema: Record::format(),
            authority: actual.authority.clone(),
            sequence,
            initialization: actual.digest.clone(),
            previous: previous
                .as_ref()
                .map_or(Ok(actual.digest.clone()), Record::digest)?,
            global_sequence: u64::try_from(global_sequence).map_err(invalid)?,
            global_digest,
            fence: fence.clone(),
            observed_at,
            heads,
            tables,
            current_rows,
            current_bytes,
            segment_events: u64::try_from(events).map_err(invalid)?,
            segment_bytes: u64::try_from(bytes).map_err(invalid)?,
        };
        record.insert(&tx)?;
        rows::visit(&tx, &record, |_, _| Ok(()))?;
        super::cutpoint(71)?;
        self.serving_owner
            .append_global_commit(
                &tx,
                MUTATION,
                PROJECTION,
                actual.authority.as_str(),
                sequence,
            )
            .map_err(map_owner_error)?;
        super::cutpoint(72)?;
        let digest = AdmissionDigest::try_new("native_checkpoint", record.digest()?)?;
        self.commit_write(tx)?;
        if let Err(error) = super::cutpoint(73) {
            return Err(map_owner_error(
                self.serving_owner.outcome_unknown(error.to_string()),
            ));
        }
        self.sync_after_write(&connection)?;
        super::cutpoint(74)?;
        Ok(Some(digest))
    }
}

pub(crate) fn projection_reference(
    connection: &Connection,
    key: &str,
    sequence: u64,
) -> Result<String, SqliteServingOwnerError> {
    let record = record::load_local(connection, key, sequence)
        .map_err(map_integrity)?
        .ok_or_else(|| map_integrity("native checkpoint reference is absent"))?;
    rows::visit(connection, &record, |_, _| Ok(())).map_err(map_integrity)?;
    record.digest().map_err(map_integrity)
}

pub(in crate::admission_operation_store) fn verify_coverage(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    if !schema::present(connection).map_err(map_integrity)? {
        let global: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = ?1)",
                [PROJECTION],
                |row| row.get(0),
            )
            .map_err(map_integrity)?;
        return if !global {
            Ok(())
        } else {
            Err(map_integrity("native checkpoint references lack catalog"))
        };
    }
    // A current owner already authenticated archived events at open. Ordinary
    // readbacks compare indexed heads for at most sixteen initialized roots;
    // they do not rescan retained snapshot archives.
    let mut statement = connection.prepare("SELECT security_authority_id FROM security_participant_state_initializations ORDER BY security_authority_id LIMIT 17")
        .map_err(map_integrity)?;
    let mut roots = statement.query([]).map_err(map_integrity)?;
    let mut count = 0;
    while let Some(root) = roots.next().map_err(map_integrity)? {
        count += 1;
        if count > 16 {
            return Err(map_integrity("native checkpoint roots exceed bounds"));
        }
        let authority: String = root.get(0).map_err(map_integrity)?;
        let local = latest(connection, &authority)
            .map_err(map_integrity)?
            .map_or(0, |record| record.sequence);
        let global: i64 = connection.query_row(
            "SELECT COALESCE(MAX(projection_sequence),0) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2",
            params![PROJECTION,authority],|row|row.get(0),
        ).map_err(map_integrity)?;
        if local != u64::try_from(global).map_err(map_integrity)? {
            return Err(map_integrity("native checkpoint global head differs"));
        }
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn verify_all(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    if !schema::present(connection)? {
        return Ok(());
    }
    let global_exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits')",[],|row|row.get(0)).map_err(sqlite_error)?;
    if !global_exists {
        let occupied: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM security_participant_checkpoint_events) OR EXISTS(SELECT 1 FROM security_participant_checkpoint_rows)",[],|row|row.get(0)).map_err(sqlite_error)?;
        return if !occupied {
            Ok(())
        } else {
            Err(invalid(
                "native checkpoint history lacks the global catalog",
            ))
        };
    }
    verify_coverage(connection).map_err(invalid)?;
    let global: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1",
            [PROJECTION],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let local: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM security_participant_checkpoint_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let orphan: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM security_participant_checkpoint_rows AS snapshot
         WHERE NOT EXISTS(SELECT 1 FROM security_participant_checkpoint_events AS event
             WHERE event.security_authority_id = snapshot.security_authority_id AND event.sequence = snapshot.checkpoint_sequence))
         OR EXISTS(SELECT 1 FROM security_participant_checkpoint_events AS event
         WHERE NOT EXISTS(SELECT 1 FROM security_participant_state_initializations AS initialized
             WHERE initialized.security_authority_id = event.security_authority_id))",
        [],|row|row.get(0),
    ).map_err(sqlite_error)?;
    if local != global || orphan {
        return Err(invalid("native checkpoint global coverage differs"));
    }
    let mut statement = connection.prepare("SELECT security_authority_id,sequence FROM security_participant_checkpoint_events ORDER BY security_authority_id,sequence")
        .map_err(sqlite_error)?;
    let mut events = statement.query([]).map_err(sqlite_error)?;
    while let Some(event) = events.next().map_err(sqlite_error)? {
        let authority: String = event.get(0).map_err(sqlite_error)?;
        let sequence =
            u64::try_from(event.get::<_, i64>(1).map_err(sqlite_error)?).map_err(invalid)?;
        let record = record::load_local(connection, &authority, sequence)?
            .ok_or_else(|| invalid("native checkpoint archive event absent"))?;
        record::verify_reference(connection, &record)?;
        rows::visit(connection, &record, |_, _| Ok(()))?;
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn verify_pristine(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    let global_exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'authority_global_commits')",[],|row|row.get(0)).map_err(map_integrity)?;
    if global_exists {
        let occupied: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind = ?1)",
                [PROJECTION],
                |row| row.get(0),
            )
            .map_err(map_integrity)?;
        if occupied {
            return Err(map_integrity(
                "pristine native state has checkpoint references",
            ));
        }
    }
    if schema::present(connection).map_err(map_integrity)? {
        let occupied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_checkpoint_events) OR EXISTS(SELECT 1 FROM security_participant_checkpoint_rows)",
            [],|row|row.get(0),
        ).map_err(map_integrity)?;
        if occupied {
            return Err(map_integrity("native checkpoint state is not pristine"));
        }
    }
    Ok(())
}

fn map_integrity(detail: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(format!("native checkpoint integrity: {detail}"))
}
