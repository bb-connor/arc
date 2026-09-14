//! Local, non-recursive verification of bounded migration records.
use super::*;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct MigrationEvent {
    pub(super) sequence: u64,
    pub(super) mutation_kind: String,
    pub(super) event_digest: String,
    pub(super) observed_at_unix_ms: u64,
    pub(super) fence: StoreMutationFence,
}

fn hash(domain: &[u8], value: &impl Serialize) -> Result<String, AdmissionOperationStoreError> {
    let mut bytes = domain.to_vec();
    bytes.extend(canonical_json_bytes(value).map_err(invalid)?);
    Ok(sha256_hex(&bytes))
}

pub(super) fn new_expectation(
    snapshot: SecurityParticipantSourceSnapshot,
) -> Result<SecurityParticipantMigrationRecord, AdmissionOperationStoreError> {
    let fingerprint_digest = snapshot.digest().map_err(invalid)?;
    let expectation_id = hash(
        b"chio.security-participant-expectation-id.v1\0",
        &(
            snapshot.binding().destination_store_uuid().as_str(),
            snapshot.binding().security_authority_id().as_str(),
            snapshot.binding().source_id().as_str(),
            &fingerprint_digest,
        ),
    )?;
    Ok(SecurityParticipantMigrationRecord {
        snapshot,
        expectation_id: AdmissionIdentifier::try_new("expectation_id", expectation_id)?,
        fingerprint_digest,
        events: Vec::new(),
    })
}

fn event_digest(
    record: &SecurityParticipantMigrationRecord,
    event: &MigrationEvent,
    previous: &str,
) -> Result<String, AdmissionOperationStoreError> {
    hash(
        b"chio.security-participant-migration-event.v1\0",
        &(
            record.authority(),
            record.expectation_id.as_str(),
            &record.fingerprint_digest,
            event.sequence,
            &event.mutation_kind,
            previous,
            event.observed_at_unix_ms,
            &event.fence,
        ),
    )
}

pub(super) fn insert_expectation(
    tx: &Transaction<'_>,
    record: &SecurityParticipantMigrationRecord,
) -> Result<(), AdmissionOperationStoreError> {
    let identity = record.snapshot.file_identity().map_err(invalid)?;
    tx.execute("INSERT INTO security_participant_migration_expectations
        (security_authority_id, source_id, expectation_id, destination_store_uuid, source_device,
         source_inode, canonical_source, fingerprint_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![record.authority(), record.snapshot.binding().source_id().as_str(), record.expectation_id.as_str(),
            record.snapshot.binding().destination_store_uuid().as_str(), identity.device.to_string(), identity.inode.to_string(),
            record.snapshot.canonical_bytes().map_err(invalid)?, record.fingerprint_digest],
    ).map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn insert_event(
    tx: &Transaction<'_>,
    record: &SecurityParticipantMigrationRecord,
    sequence: u64,
    observed: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if sequence != u64::try_from(record.events.len()).map_err(invalid)? + 1
        || record
            .events
            .last()
            .is_some_and(|event| observed < event.observed_at_unix_ms)
    {
        return Err(invalid("migration event transition or time invalid"));
    }
    let mut event = MigrationEvent {
        sequence,
        mutation_kind: mutation(sequence)?.to_owned(),
        event_digest: String::new(),
        observed_at_unix_ms: observed,
        fence: fence.clone(),
    };
    let previous = record
        .events
        .last()
        .map_or(GENESIS_CHAIN_DIGEST, |event| event.event_digest.as_str());
    event.event_digest = event_digest(record, &event, previous)?;
    tx.execute("INSERT INTO security_participant_migration_events
        (security_authority_id, sequence, mutation_kind, event_digest, observed_at_unix_ms, store_uuid,
         store_lease_id, store_owner_epoch) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![record.authority(), i64::try_from(sequence).map_err(invalid)?, event.mutation_kind,
            event.event_digest, i64::try_from(observed).map_err(invalid)?, fence.store_uuid,
            fence.lease_id, i64::try_from(fence.owner_epoch).map_err(invalid)?],
    ).map_err(sqlite_error)?;
    Ok(())
}

pub(in crate::admission_operation_store) fn verify_all(
    connection: &Connection,
) -> Result<Vec<SecurityParticipantMigrationRecord>, AdmissionOperationStoreError> {
    if !storage::validate_bounds(connection)? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT security_authority_id FROM security_participant_migration_expectations
        ORDER BY security_authority_id",
        )
        .map_err(sqlite_error)?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    let records = keys
        .into_iter()
        .map(|key| load_bounded(connection, &key))
        .collect::<Result<Vec<_>, _>>()?;
    // Reserve the complete source inventory at pin time, before source retirement.
    verify_capacity(
        records
            .iter()
            .flat_map(|record| record.snapshot.tables())
            .map(|table| (table.row_count, table.encoded_bytes)),
    )?;
    Ok(records)
}

fn verify_capacity(
    mut inventories: impl Iterator<Item = (u64, u64)>,
) -> Result<(), AdmissionOperationStoreError> {
    let (rows, bytes) =
        inventories.try_fold((0_u64, 0_u64), |(rows, bytes), (next_rows, next_bytes)| {
            Ok::<_, AdmissionOperationStoreError>((
                rows.checked_add(next_rows)
                    .ok_or_else(|| invalid("pinned row count overflow"))?,
                bytes
                    .checked_add(next_bytes)
                    .ok_or_else(|| invalid("pinned byte count overflow"))?,
            ))
        })?;
    if rows > MAX_TOTAL_ROWS || bytes > MAX_TOTAL_BYTES {
        return Err(invalid(
            "complete pinned inventories exceed destination capacity",
        ));
    }
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    authority: &str,
) -> Result<Option<SecurityParticipantMigrationRecord>, AdmissionOperationStoreError> {
    if !storage::validate_bounds(connection)? {
        return Ok(None);
    }
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM security_participant_migration_expectations
        WHERE security_authority_id = ?1)",
            [authority],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    // Resolve just this source's verified bytes. The global coverage callback
    // separately verifies all records and reserved capacity once per snapshot.
    // Rehashing every source for each event reference would be quadratic.
    exists
        .then(|| load_bounded(connection, authority))
        .transpose()
}

fn load_bounded(
    connection: &Connection,
    authority: &str,
) -> Result<SecurityParticipantMigrationRecord, AdmissionOperationStoreError> {
    type Stored = (String, String, String, String, String, Vec<u8>, String);
    let (source, expectation_id, destination, device, inode, canonical, digest): Stored = connection.query_row(
        "SELECT source_id, expectation_id, destination_store_uuid, source_device, source_inode,
         canonical_source, fingerprint_digest FROM security_participant_migration_expectations WHERE security_authority_id = ?1",
        [authority], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
    ).map_err(sqlite_error)?;
    let snapshot =
        SecurityParticipantSourceSnapshot::from_canonical_bytes(&canonical).map_err(invalid)?;
    let identity = snapshot.file_identity().map_err(invalid)?;
    let mut record = new_expectation(snapshot)?;
    if record.authority() != authority
        || record.snapshot.binding().source_id().as_str() != source
        || record.snapshot.binding().destination_store_uuid().as_str() != destination
        || record.expectation_id.as_str() != expectation_id
        || record.fingerprint_digest != digest
        || identity.device.to_string() != device
        || identity.inode.to_string() != inode
    {
        return Err(invalid("stored source expectation binding mismatch"));
    }
    let mut statement = connection
        .prepare(
            "SELECT sequence, mutation_kind, event_digest, observed_at_unix_ms,
        store_uuid, store_lease_id, store_owner_epoch FROM security_participant_migration_events
        WHERE security_authority_id = ?1 ORDER BY sequence",
        )
        .map_err(sqlite_error)?;
    let events = statement
        .query_map([authority], |row| {
            Ok(MigrationEvent {
                sequence: row_u64(row, 0)?,
                mutation_kind: row.get(1)?,
                event_digest: row.get(2)?,
                observed_at_unix_ms: row_u64(row, 3)?,
                fence: StoreMutationFence {
                    store_uuid: row.get(4)?,
                    lease_id: row.get(5)?,
                    owner_epoch: row_u64(row, 6)?,
                },
            })
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if events.is_empty() || events.len() > 2 {
        return Err(invalid("migration lacks its exact expectation event"));
    }
    let mut previous = GENESIS_CHAIN_DIGEST;
    let mut observed = 0;
    for (index, event) in events.iter().enumerate() {
        let sequence = u64::try_from(index).map_err(invalid)? + 1;
        if event.sequence != sequence
            || event.mutation_kind != mutation(sequence)?
            || event.fence.store_uuid != destination
            || event.observed_at_unix_ms < observed
            || event_digest(&record, event, previous)? != event.event_digest
        {
            return Err(invalid(
                "migration event binding, digest, order or time mismatch",
            ));
        }
        let matches: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM chio_serving_leases
            WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3)",
                params![
                    event.fence.store_uuid,
                    i64::try_from(event.fence.owner_epoch).map_err(invalid)?,
                    event.fence.lease_id
                ],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if !matches {
            return Err(invalid("migration historical owner mismatch"));
        }
        previous = &event.event_digest;
        observed = event.observed_at_unix_ms;
    }
    record.events = events;
    storage::verify_rows(connection, &record)?;
    Ok(record)
}

fn row_u64(row: &Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(column)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_inventory_capacity_accepts_exact_limits_and_rejects_either_excess() {
        assert!(
            verify_capacity([(1, 1), (MAX_TOTAL_ROWS - 1, MAX_TOTAL_BYTES - 1)].into_iter())
                .is_ok()
        );
        for inventories in [
            [(MAX_TOTAL_ROWS, 0), (1, 0)],
            [(0, MAX_TOTAL_BYTES), (0, 1)],
        ] {
            assert!(verify_capacity(inventories.into_iter()).is_err());
        }
    }

    #[test]
    fn complete_inventory_capacity_cannot_wrap_row_or_byte_counts() {
        for inventories in [[(u64::MAX, 0), (1, 0)], [(0, u64::MAX), (0, 1)]] {
            assert!(verify_capacity(inventories.into_iter()).is_err());
        }
    }
}
