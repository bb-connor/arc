use super::*;

type IntegrityResult<T> = Result<T, String>;

fn digest(
    qualification: &RuntimeSourceQualificationV1,
    observed: u64,
    fence: &StoreMutationFence,
) -> IntegrityResult<String> {
    let bytes = canonical_json_bytes(&(
        "chio.runtime-source-record.v1",
        qualification.qualification_sha256(),
        observed,
        fence,
    ))
    .map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

pub(super) fn new_record(
    qualification: RuntimeSourceQualificationV1,
    observed_at_unix_ms: u64,
    fence: StoreMutationFence,
) -> Result<RuntimeSourceRecordV1, AdmissionOperationStoreError> {
    Ok(RuntimeSourceRecordV1 {
        qualification_id: AdmissionIdentifier::try_new(
            "qualification_id",
            qualification.qualification_sha256(),
        )?,
        record_digest: digest(&qualification, observed_at_unix_ms, &fence)
            .map_err(integrity_error)?,
        qualification,
        observed_at_unix_ms,
        fence,
    })
}

pub(super) fn insert(
    transaction: &Transaction<'_>,
    record: &RuntimeSourceRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    transaction.execute(
        "INSERT INTO runtime_source_qualifications
         (runtime_authority_id, source_id, qualification_id, destination_store_uuid, canonical_source,
          observed_at_unix_ms, store_lease_id, store_owner_epoch, record_digest)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![record.qualification.runtime_authority_id(), record.qualification.source_id(),
            record.qualification_id.as_str(), record.fence.store_uuid, record.qualification.canonical_bytes(),
            i64::try_from(record.observed_at_unix_ms).map_err(integrity_error)?, record.fence.lease_id,
            i64::try_from(record.fence.owner_epoch).map_err(integrity_error)?, record.record_digest],
    ).map_err(sqlite_error)?;
    Ok(())
}

pub(super) fn source_table_exists(connection: &Connection) -> IntegrityResult<bool> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'runtime_source_qualifications')",
        [], |row| row.get(0),
    ).map_err(|error| error.to_string())
}

pub(in crate::admission_operation_store) fn verify_all_records(
    connection: &Connection,
) -> IntegrityResult<Vec<RuntimeSourceRecordV1>> {
    if !source_table_exists(connection)? {
        return Err("runtime source qualification table is absent".into());
    }
    let count: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_source_qualifications",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if count > MAX_QUALIFICATION_HISTORY {
        return Err("runtime source qualification history capacity exceeded".into());
    }
    supersession::verify_counts(connection, count)?;
    let invalid: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_source_qualifications
         WHERE typeof(canonical_source) <> 'blob' OR length(canonical_source) NOT BETWEEN 1 AND 4096
            OR typeof(runtime_authority_id) <> 'text' OR octet_length(runtime_authority_id) NOT BETWEEN 1 AND 2048
            OR typeof(source_id) <> 'text' OR octet_length(source_id) NOT BETWEEN 1 AND 2048
            OR typeof(qualification_id) <> 'text' OR octet_length(qualification_id) <> 64
            OR typeof(destination_store_uuid) <> 'text' OR octet_length(destination_store_uuid) NOT BETWEEN 1 AND 512
            OR typeof(store_lease_id) <> 'text' OR octet_length(store_lease_id) NOT BETWEEN 1 AND 512
            OR typeof(record_digest) <> 'text' OR octet_length(record_digest) <> 64
            OR typeof(observed_at_unix_ms) <> 'integer' OR observed_at_unix_ms NOT BETWEEN 0 AND 9007199254740991
            OR typeof(store_owner_epoch) <> 'integer' OR store_owner_epoch <= 0)",
        [], |row| row.get(0),
    ).map_err(|error| error.to_string())?;
    if invalid {
        return Err("runtime source row violates storage bounds".into());
    }
    let mut statement = connection.prepare(
        "SELECT runtime_authority_id, source_id, qualification_id, destination_store_uuid, canonical_source,
         observed_at_unix_ms, store_lease_id, store_owner_epoch, record_digest
         FROM runtime_source_qualifications ORDER BY runtime_authority_id",
    ).map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, String>(8)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut records = Vec::new();
    for row in rows {
        let (runtime, source, id, destination, bytes, observed, lease, epoch, stored_digest) =
            row.map_err(|error| error.to_string())?;
        let qualification = RuntimeSourceQualificationV1::from_canonical_bytes(&bytes)
            .map_err(|error| error.to_string())?;
        if qualification.runtime_authority_id() != runtime
            || qualification.source_id() != source
            || qualification.destination_authority_id() != destination
            || qualification.qualification_sha256() != id
        {
            return Err("runtime source row differs from its canonical qualification".into());
        }
        let fence = StoreMutationFence {
            store_uuid: destination,
            lease_id: lease,
            owner_epoch: u64::try_from(epoch).map_err(|error| error.to_string())?,
        };
        let record = new_record(
            qualification,
            u64::try_from(observed).map_err(|error| error.to_string())?,
            fence,
        )
        .map_err(|error| error.to_string())?;
        if record.record_digest != stored_digest {
            return Err("runtime source record digest mismatch".into());
        }
        records.push(record);
    }
    if super::supersession::active_count(connection, &records)? > MAX_SOURCES {
        return Err("runtime source capacity exceeded".into());
    }
    Ok(records)
}

pub(super) fn load_record(
    connection: &Connection,
    runtime: &str,
) -> IntegrityResult<Option<RuntimeSourceRecordV1>> {
    Ok(verify_all_records(connection)?
        .into_iter()
        .find(|record| record.qualification.runtime_authority_id() == runtime))
}
