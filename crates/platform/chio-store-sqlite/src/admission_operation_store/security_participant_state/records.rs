//! Bounded local verification. Never recursively calls the global verifier.
use super::*;

fn digest(
    record: &SecurityParticipantStateInitialization,
) -> Result<String, AdmissionOperationStoreError> {
    let mut bytes = b"chio.security-participant-state.initialization.v1\0".to_vec();
    bytes.extend(
        canonical_json_bytes(&(
            record.authority.as_str(),
            record.expectation.as_str(),
            &record.fingerprint,
            &record.schema,
            record.initialized_at,
            &record.fence,
        ))
        .map_err(invalid)?,
    );
    Ok(sha256_hex(&bytes))
}

pub(super) fn new(
    source: &SecurityParticipantMigrationRecord,
    initialized_at: u64,
    fence: &StoreMutationFence,
) -> Result<SecurityParticipantStateInitialization, AdmissionOperationStoreError> {
    new_with_catalog(source, initialized_at, fence, schema::digest()?)
}

pub(super) fn new_with_catalog(
    source: &SecurityParticipantMigrationRecord,
    initialized_at: u64,
    fence: &StoreMutationFence,
    catalog_digest: String,
) -> Result<SecurityParticipantStateInitialization, AdmissionOperationStoreError> {
    super::super::schema::validate_trusted_time(initialized_at, "native initialization time")?;
    let mut record = SecurityParticipantStateInitialization {
        authority: AdmissionIdentifier::try_new(
            "security_authority_id",
            source.snapshot().binding().security_authority_id().as_str(),
        )?,
        expectation: source.expectation_id().clone(),
        fingerprint: source.snapshot().digest().map_err(invalid)?,
        schema: catalog_digest,
        initialized_at,
        fence: fence.clone(),
        digest: String::new(),
    };
    record.digest = digest(&record)?;
    Ok(record)
}

pub(super) fn insert(
    tx: &Transaction<'_>,
    record: &SecurityParticipantStateInitialization,
) -> Result<(), AdmissionOperationStoreError> {
    tx.execute(
        "INSERT INTO security_participant_state_initializations
        (security_authority_id, expectation_id, fingerprint_digest, schema_digest, initialized_at,
         store_uuid, store_lease_id, store_owner_epoch, initialization_digest)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            record.authority.as_str(),
            record.expectation.as_str(),
            record.fingerprint,
            record.schema,
            i64::try_from(record.initialized_at).map_err(invalid)?,
            record.fence.store_uuid,
            record.fence.lease_id,
            i64::try_from(record.fence.owner_epoch).map_err(invalid)?,
            record.digest
        ],
    )
    .map_err(sqlite_error)?;
    Ok(())
}

fn validate_bounds(
    connection: &Connection,
    version: i32,
) -> Result<bool, AdmissionOperationStoreError> {
    if !schema::verify_version(connection, version)? {
        return Ok(false);
    }
    let (count, malformed): (i64, bool) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MAX(
        length(CAST(security_authority_id AS BLOB)) NOT BETWEEN 1 AND 512
        OR length(CAST(expectation_id AS BLOB)) != 64
        OR length(CAST(fingerprint_digest AS BLOB)) != 64
        OR length(CAST(schema_digest AS BLOB)) != 64
        OR length(CAST(initialization_digest AS BLOB)) != 64
        OR length(CAST(store_uuid AS BLOB)) NOT BETWEEN 1 AND 512
        OR length(CAST(store_lease_id AS BLOB)) NOT BETWEEN 1 AND 512
        OR initialized_at NOT BETWEEN 1 AND 9007199254740991 OR store_owner_epoch < 1
    ), 0) FROM security_participant_state_initializations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if !(0..=16).contains(&count) || malformed {
        return Err(invalid("native initialization metadata exceeds bounds"));
    }
    Ok(true)
}

pub(super) fn load(
    connection: &Connection,
    authority: &str,
) -> Result<Option<SecurityParticipantStateInitialization>, AdmissionOperationStoreError> {
    let record = load_metadata(connection, authority)?;
    if let Some(record) = &record {
        let source = security_participant_migration::load_imported_source(connection, authority)?;
        super::history::verify_rows(connection, &source, record)?;
    }
    Ok(record)
}

pub(super) fn load_metadata(
    connection: &Connection,
    authority: &str,
) -> Result<Option<SecurityParticipantStateInitialization>, AdmissionOperationStoreError> {
    if !validate_bounds(connection, schema::recorded_version(connection)?)? {
        return Ok(None);
    }
    load_bounded(connection, authority)
}

fn load_bounded(
    connection: &Connection,
    authority: &str,
) -> Result<Option<SecurityParticipantStateInitialization>, AdmissionOperationStoreError> {
    type Stored = (String, String, String, i64, String, String, i64, String);
    let stored: Option<Stored> = connection.query_row("SELECT expectation_id, fingerprint_digest,
        schema_digest, initialized_at, store_uuid, store_lease_id, store_owner_epoch, initialization_digest
        FROM security_participant_state_initializations WHERE security_authority_id = ?1", [authority],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
    ).optional().map_err(sqlite_error)?;
    let Some((
        expectation,
        fingerprint,
        schema,
        initialized_at,
        store_uuid,
        lease_id,
        owner_epoch,
        stored_digest,
    )) = stored
    else {
        return Ok(None);
    };
    let source = security_participant_migration::load_imported_source(connection, authority)?;
    let mut record = new(
        &source,
        u64::try_from(initialized_at).map_err(invalid)?,
        &StoreMutationFence {
            store_uuid,
            lease_id,
            owner_epoch: u64::try_from(owner_epoch).map_err(invalid)?,
        },
    )?;
    // The initialization catalog is historical evidence, not the current
    // schema. A v29 migration must not rewrite a v28 initialization digest.
    if schema != schema::digest_version(28)? && schema != schema::digest_version(29)? {
        return Err(invalid("native initialization catalog digest is unknown"));
    }
    record.schema.clone_from(&schema);
    record.digest = digest(&record)?;
    if record.expectation.as_str() != expectation
        || record.fingerprint != fingerprint
        || record.schema != schema
        || record.digest != stored_digest
        || record.fence.store_uuid
            != source
                .snapshot()
                .binding()
                .destination_store_uuid()
                .as_str()
    {
        return Err(invalid("native initialization binding or digest mismatch"));
    }
    let historical: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_serving_leases
        WHERE store_uuid = ?1 AND owner_epoch = ?2 AND lease_id = ?3)",
            params![record.fence.store_uuid, owner_epoch, record.fence.lease_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let imported_at: i64 = connection
        .query_row(
            "SELECT observed_at_unix_ms FROM security_participant_migration_events
        WHERE security_authority_id = ?1 AND sequence = 2",
            [authority],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !historical || initialized_at < imported_at {
        return Err(invalid("native initialization owner or time mismatch"));
    }
    Ok(Some(record))
}

pub(in crate::admission_operation_store) fn verify_all(
    connection: &Connection,
) -> Result<Vec<SecurityParticipantStateInitialization>, AdmissionOperationStoreError> {
    verify_all_version(connection, 29)
}

pub(super) fn verify_all_version(
    connection: &Connection,
    version: i32,
) -> Result<Vec<SecurityParticipantStateInitialization>, AdmissionOperationStoreError> {
    if !validate_bounds(connection, version)? {
        return Ok(Vec::new());
    }
    storage::verify_no_orphans(connection)?;
    let mut statement = connection.prepare("SELECT security_authority_id FROM security_participant_state_initializations ORDER BY security_authority_id").map_err(sqlite_error)?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    keys.into_iter()
        .map(|key| {
            let record = load_bounded(connection, &key)?
                .ok_or_else(|| invalid("native initialization disappeared"))?;
            let source = security_participant_migration::load_imported_source(connection, &key)?;
            if version == 28 {
                if record.schema != schema::digest_version(28)? {
                    return Err(invalid("v28 initialization has a future schema digest"));
                }
                storage::verify_rows(connection, &source)?;
            } else {
                super::history::verify_rows(connection, &source, &record)?;
            }
            Ok(record)
        })
        .collect()
}
