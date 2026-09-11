use super::*;

type IntegrityResult<T> = Result<T, String>;

const TABLES: [&str; 3] = [
    "runtime_replay_migration_expectations",
    "runtime_replay_migration_events",
    "runtime_replay_legacy_tombstones",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MigrationEvent {
    pub(super) sequence: u64,
    pub(super) mutation_kind: String,
    pub(super) expectation_digest: String,
    pub(super) inventory_sha256: String,
    pub(super) event_digest: String,
    pub(super) observed_at_unix_ms: u64,
    pub(super) fence: StoreMutationFence,
}

fn hash(domain: &[u8], value: &impl Serialize) -> IntegrityResult<String> {
    let encoded = canonical_json_bytes(value).map_err(|error| error.to_string())?;
    let mut bytes = Vec::with_capacity(domain.len() + encoded.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&encoded);
    Ok(sha256_hex(&bytes))
}

pub(super) fn new_expectation(
    snapshot: RuntimeReplaySourceSnapshotV1,
) -> Result<RuntimeReplayMigrationRecordV1, AdmissionOperationStoreError> {
    // The destination derives generation identity from the full pinned source,
    // not from a mutable owner lease or an identifier supplied by the source.
    let expectation_id = hash(
        b"chio.runtime-replay-expectation-id.v1\0",
        &(
            snapshot.destination_authority_id(),
            snapshot.runtime_authority_id(),
            snapshot.source_id(),
            snapshot.inventory_sha256(),
        ),
    )
    .map_err(integrity_error)?;
    let expectation_digest = hash(
        b"chio.runtime-replay-expectation.v1\0",
        &(
            &expectation_id,
            snapshot.destination_authority_id(),
            snapshot.runtime_authority_id(),
            snapshot.source_id(),
            snapshot.inventory_sha256(),
        ),
    )
    .map_err(integrity_error)?;
    Ok(RuntimeReplayMigrationRecordV1 {
        snapshot,
        expectation_id: AdmissionIdentifier::try_new("expectation_id", expectation_id)?,
        expectation_digest,
        events: Vec::new(),
    })
}

fn event_digest(
    record: &RuntimeReplayMigrationRecordV1,
    event: &MigrationEvent,
    previous: &str,
) -> IntegrityResult<String> {
    hash(
        b"chio.runtime-replay-migration-event.v1\0",
        &(
            record.snapshot.runtime_authority_id(),
            record.expectation_id.as_str(),
            event.sequence,
            &event.mutation_kind,
            &event.expectation_digest,
            &event.inventory_sha256,
            previous,
            event.observed_at_unix_ms,
            &event.fence,
        ),
    )
}

pub(super) fn insert_expectation(
    transaction: &Transaction<'_>,
    record: &RuntimeReplayMigrationRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    transaction
        .execute(
            "INSERT INTO runtime_replay_migration_expectations
         (runtime_authority_id, source_id, expectation_id, destination_store_uuid,
          canonical_source, inventory_sha256, expectation_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                record.snapshot.runtime_authority_id(),
                record.snapshot.source_id(),
                record.expectation_id.as_str(),
                record.snapshot.destination_authority_id(),
                record.snapshot.canonical_bytes(),
                record.snapshot.inventory_sha256(),
                record.expectation_digest,
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn insert_event(
    transaction: &Transaction<'_>,
    record: &RuntimeReplayMigrationRecordV1,
    sequence: u64,
    observed: u64,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    if sequence != record.events.len() as u64 + 1 || !(1..=3).contains(&sequence) {
        return Err(integrity_error("invalid migration event transition"));
    }
    if record
        .events
        .last()
        .is_some_and(|previous| observed < previous.observed_at_unix_ms)
    {
        return Err(integrity_error("migration authority time regressed"));
    }
    let previous = record
        .events
        .last()
        .map_or(GENESIS_CHAIN_DIGEST, |event| event.event_digest.as_str());
    let mut event = MigrationEvent {
        sequence,
        mutation_kind: migration_mutation(sequence)?.into(),
        expectation_digest: record.expectation_digest.clone(),
        inventory_sha256: record.snapshot.inventory_sha256().into(),
        event_digest: String::new(),
        observed_at_unix_ms: observed,
        fence: fence.clone(),
    };
    event.event_digest = event_digest(record, &event, previous).map_err(integrity_error)?;
    transaction
        .execute(
            "INSERT INTO runtime_replay_migration_events
         (runtime_authority_id, sequence, mutation_kind, expectation_digest,
          inventory_sha256, event_digest, observed_at_unix_ms, store_uuid,
          store_lease_id, store_owner_epoch) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                record.snapshot.runtime_authority_id(),
                i64::try_from(event.sequence).map_err(integrity_error)?,
                event.mutation_kind,
                event.expectation_digest,
                event.inventory_sha256,
                event.event_digest,
                i64::try_from(event.observed_at_unix_ms).map_err(integrity_error)?,
                fence.store_uuid,
                fence.lease_id,
                i64::try_from(fence.owner_epoch).map_err(integrity_error)?,
            ],
        )
        .map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn insert_tombstones(
    transaction: &Transaction<'_>,
    record: &RuntimeReplayMigrationRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = transaction
        .prepare(
            "INSERT INTO runtime_replay_legacy_tombstones
         (runtime_authority_id, participant_kind, resource_id, source_id,
          expectation_id, historical_admission_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .map_err(sqlite_error)?;
    for marker in record.snapshot.markers() {
        statement
            .execute(params![
                record.snapshot.runtime_authority_id(),
                marker.kind().as_str(),
                marker.resource_id(),
                record.snapshot.source_id(),
                record.expectation_id.as_str(),
                marker.historical_admission_id(),
            ])
            .map_err(sqlite_error)?;
    }
    Ok(())
}

fn text_bound(column: &str, maximum: usize) -> String {
    format!(
        "typeof({column}) <> 'text' OR length(CAST({column} AS BLOB)) NOT BETWEEN 1 AND {maximum}"
    )
}

fn invalid_row_exists(
    connection: &Connection,
    table: &str,
    predicate: &str,
) -> IntegrityResult<bool> {
    connection
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE {predicate})"),
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())
}

/// Check storage type/count/byte bounds before reading attacker-controlled
/// strings or blobs. Empty historical fixtures may predate all three tables.
fn validate_storage_bounds(connection: &Connection) -> IntegrityResult<bool> {
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name IN
         ('runtime_replay_migration_expectations', 'runtime_replay_migration_events',
          'runtime_replay_legacy_tombstones')",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if count == 0 {
        return Ok(false);
    }
    if count != 3 {
        return Err("partial runtime migration schema".into());
    }
    let (expectations, bytes): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(canonical_source AS BLOB))), 0)
         FROM runtime_replay_migration_expectations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|error| error.to_string())?;
    if !(0..=MAX_MIGRATIONS as i64).contains(&expectations)
        || !(0..=MAX_TOTAL_SOURCE_BYTES as i64).contains(&bytes)
    {
        return Err("migration expectation aggregate limit exceeded".into());
    }
    for (table, columns, extra, maximum_rows) in [
        (TABLES[0], vec![
            ("runtime_authority_id", 512), ("source_id", 512), ("expectation_id", 512),
            ("destination_store_uuid", 512), ("inventory_sha256", 64), ("expectation_digest", 64),
        ], "typeof(canonical_source) <> 'blob' OR length(canonical_source) NOT BETWEEN 1 AND 8388608",
        MAX_MIGRATIONS),
        (TABLES[1], vec![
            ("runtime_authority_id", 512), ("mutation_kind", 64), ("expectation_digest", 64),
            ("inventory_sha256", 64), ("event_digest", 64), ("store_uuid", 512), ("store_lease_id", 512),
        ], "typeof(sequence) <> 'integer' OR sequence NOT BETWEEN 1 AND 3
            OR typeof(observed_at_unix_ms) <> 'integer' OR observed_at_unix_ms NOT BETWEEN 0 AND 9007199254740991
            OR typeof(store_owner_epoch) <> 'integer' OR store_owner_epoch < 1",
        MAX_MIGRATIONS * 3),
        (TABLES[2], vec![
            ("runtime_authority_id", 512), ("participant_kind", 64), ("resource_id", 512),
            ("source_id", 512), ("expectation_id", 512), ("historical_admission_id", 512),
        ], "participant_kind NOT IN ('destructive_lease', 'treaty_continuation', 'swarm_continuation')",
        MAX_TOTAL_MARKERS),
    ] {
        let rows: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM {table}"), [], |row| row.get(0),
        ).map_err(|error| error.to_string())?;
        if !(0..=maximum_rows as i64).contains(&rows) {
            return Err(format!("{table} row limit exceeded"));
        }
        let predicate = columns.into_iter()
            .map(|(column, maximum)| text_bound(column, maximum))
            .chain([extra.into()])
            .collect::<Vec<_>>().join(" OR ");
        if invalid_row_exists(connection, table, &predicate)? {
            return Err(format!("{table} has invalid storage types or sizes"));
        }
    }
    Ok(true)
}

pub(in crate::admission_operation_store) fn verify_all_records(
    connection: &Connection,
) -> IntegrityResult<Vec<RuntimeReplayMigrationRecordV1>> {
    if !validate_storage_bounds(connection)? {
        return Ok(Vec::new());
    }
    for table in [TABLES[1], TABLES[2]] {
        if invalid_row_exists(connection, table, &format!(
            "NOT EXISTS(SELECT 1 FROM {} AS expectation WHERE expectation.runtime_authority_id = {table}.runtime_authority_id)",
            TABLES[0],
        ))? {
            return Err(format!("{table} has an orphan record"));
        }
    }
    let mut statement = connection.prepare(
        "SELECT runtime_authority_id FROM runtime_replay_migration_expectations ORDER BY runtime_authority_id",
    ).map_err(|error| error.to_string())?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    let records: Vec<RuntimeReplayMigrationRecordV1> = keys
        .into_iter()
        .map(|key| {
            load_bounded_record(connection, &key)?
                .ok_or_else(|| "migration disappeared within its snapshot".into())
        })
        .collect::<IntegrityResult<_>>()?;
    // Reserve migration capacity when pinning, before the source is frozen.
    // Pending expectations consume the same complete-inventory budget as imports.
    let total = records.iter().try_fold(0_usize, |total, record| {
        total
            .checked_add(record.snapshot.markers().len())
            .ok_or_else(|| "migration marker capacity overflow".to_owned())
    })?;
    if total > MAX_TOTAL_MARKERS {
        return Err("migration complete-inventory capacity exceeded".into());
    }
    Ok(records)
}

pub(super) fn load_record(
    connection: &Connection,
    runtime_authority_id: &str,
) -> IntegrityResult<Option<RuntimeReplayMigrationRecordV1>> {
    if !validate_storage_bounds(connection)? {
        return Ok(None);
    }
    load_bounded_record(connection, runtime_authority_id)
}

fn load_bounded_record(
    connection: &Connection,
    runtime_authority_id: &str,
) -> IntegrityResult<Option<RuntimeReplayMigrationRecordV1>> {
    type StoredExpectation = (String, String, String, Vec<u8>, String, String);
    let stored: Option<StoredExpectation> = connection
        .query_row(
            "SELECT source_id, expectation_id, destination_store_uuid, canonical_source,
         inventory_sha256, expectation_digest FROM runtime_replay_migration_expectations
         WHERE runtime_authority_id = ?1",
            [runtime_authority_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some((
        source_id,
        expectation_id,
        destination,
        canonical,
        inventory_digest,
        expectation_digest,
    )) = stored
    else {
        return Ok(None);
    };
    let snapshot = RuntimeReplaySourceSnapshotV1::from_canonical_bytes(&canonical)
        .map_err(|error| error.to_string())?;
    if snapshot.source_id() != source_id
        || snapshot.runtime_authority_id() != runtime_authority_id
        || snapshot.destination_authority_id() != destination
        || snapshot.inventory_sha256() != inventory_digest
    {
        return Err("stored expectation source binding mismatch".into());
    }
    let mut record = new_expectation(snapshot).map_err(|error| error.to_string())?;
    if record.expectation_id.as_str() != expectation_id
        || record.expectation_digest != expectation_digest
    {
        return Err("stored expectation identity or digest mismatch".into());
    }
    let mut statement = connection
        .prepare(
            "SELECT sequence, mutation_kind, expectation_digest, inventory_sha256, event_digest,
         observed_at_unix_ms, store_uuid, store_lease_id, store_owner_epoch
         FROM runtime_replay_migration_events WHERE runtime_authority_id = ?1 ORDER BY sequence",
        )
        .map_err(|error| error.to_string())?;
    let events = statement
        .query_map([runtime_authority_id], |row| {
            Ok(MigrationEvent {
                sequence: row_u64(row, 0)?,
                mutation_kind: row.get(1)?,
                expectation_digest: row.get(2)?,
                inventory_sha256: row.get(3)?,
                event_digest: row.get(4)?,
                observed_at_unix_ms: row_u64(row, 5)?,
                fence: StoreMutationFence {
                    store_uuid: row.get(6)?,
                    lease_id: row.get(7)?,
                    owner_epoch: row_u64(row, 8)?,
                },
            })
        })
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    if events.is_empty() || events.len() > 3 {
        return Err("migration must retain its expectation event".into());
    }
    let mut previous = GENESIS_CHAIN_DIGEST;
    let mut observed = 0;
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 + 1
            || event.mutation_kind
                != migration_mutation(index as u64 + 1).map_err(|error| error.to_string())?
            || event.expectation_digest != record.expectation_digest
            || event.inventory_sha256 != record.snapshot.inventory_sha256()
            || event.fence.store_uuid != record.snapshot.destination_authority_id()
            || event.observed_at_unix_ms < observed
            || event_digest(&record, event, previous)? != event.event_digest
        {
            return Err("migration event binding, digest, order or time mismatch".into());
        }
        let lease_matches: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM chio_serving_leases
             WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3)",
                params![
                    event.fence.store_uuid,
                    i64::try_from(event.fence.owner_epoch).map_err(|error| error.to_string())?,
                    event.fence.lease_id
                ],
                |row| row.get(0),
            )
            .map_err(|error| error.to_string())?;
        if !lease_matches {
            return Err("migration event historical owner lease mismatch".into());
        }
        previous = &event.event_digest;
        observed = event.observed_at_unix_ms;
    }
    record.events = events;
    verify_tombstones(connection, &record)?;
    Ok(Some(record))
}

fn row_u64(row: &Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(column)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}

fn verify_tombstones(
    connection: &Connection,
    record: &RuntimeReplayMigrationRecordV1,
) -> IntegrityResult<()> {
    let mut statement = connection.prepare(
        "SELECT participant_kind, resource_id, source_id, expectation_id, historical_admission_id
         FROM runtime_replay_legacy_tombstones WHERE runtime_authority_id = ?1
         ORDER BY CASE participant_kind WHEN 'destructive_lease' THEN 0
             WHEN 'treaty_continuation' THEN 1 WHEN 'swarm_continuation' THEN 2 ELSE 3 END,
             resource_id COLLATE BINARY",
    ).map_err(|error| error.to_string())?;
    let mut rows = statement
        .query([record.snapshot.runtime_authority_id()])
        .map_err(|error| error.to_string())?;
    let expected = if record.is_imported() {
        record.snapshot.markers()
    } else {
        &[]
    };
    for marker in expected {
        let row = rows
            .next()
            .map_err(|error| error.to_string())?
            .ok_or("missing unresolved legacy tombstone")?;
        let actual: (String, String, String, String, String) = (
            row.get(0).map_err(|error| error.to_string())?,
            row.get(1).map_err(|error| error.to_string())?,
            row.get(2).map_err(|error| error.to_string())?,
            row.get(3).map_err(|error| error.to_string())?,
            row.get(4).map_err(|error| error.to_string())?,
        );
        if actual.0 != marker.kind().as_str()
            || actual.1 != marker.resource_id()
            || actual.2 != record.snapshot.source_id()
            || actual.3 != record.expectation_id.as_str()
            || actual.4 != marker.historical_admission_id()
        {
            return Err("unresolved legacy tombstone does not match pinned source".into());
        }
    }
    if rows.next().map_err(|error| error.to_string())?.is_some() {
        return Err("extra or premature unresolved legacy tombstone".into());
    }
    Ok(())
}
