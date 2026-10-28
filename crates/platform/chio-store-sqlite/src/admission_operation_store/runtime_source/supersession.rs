use super::*;

pub(super) const MUTATION: &str = "supersede_runtime_source";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Supersession {
    schema: String,
    pub prior_runtime: String,
    prior_qualification: String,
    prior_digest: String,
    pub replacement_runtime: String,
    replacement_qualification: String,
    replacement_digest: String,
    pub observed_at_unix_ms: u64,
    pub fence: StoreMutationFence,
}

impl Supersession {
    pub fn new(prior: &RuntimeSourceRecordV1, replacement: &RuntimeSourceRecordV1) -> Self {
        Self {
            schema: "chio.runtime-source-supersession.v1".into(),
            prior_runtime: prior.qualification.runtime_authority_id().into(),
            prior_qualification: prior.qualification_id.as_str().into(),
            prior_digest: prior.record_digest.clone(),
            replacement_runtime: replacement.qualification.runtime_authority_id().into(),
            replacement_qualification: replacement.qualification_id.as_str().into(),
            replacement_digest: replacement.record_digest.clone(),
            observed_at_unix_ms: replacement.observed_at_unix_ms,
            fence: replacement.fence.clone(),
        }
    }

    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        canonical_json_bytes(self).map_err(|error| error.to_string())
    }

    pub fn digest(&self) -> Result<String, String> {
        Ok(sha256_hex(&self.bytes()?))
    }

    pub fn insert(&self, tx: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
        tx.execute(
            "INSERT INTO runtime_source_supersessions
             (prior_runtime_authority_id, replacement_runtime_authority_id, canonical_supersession, record_digest)
             VALUES (?1, ?2, ?3, ?4)",
            params![self.prior_runtime, self.replacement_runtime,
                self.bytes().map_err(integrity_error)?, self.digest().map_err(integrity_error)?],
        ).map_err(sqlite_error)?;
        Ok(())
    }
}

pub(super) fn verify_counts(
    connection: &Connection,
    qualification_count: usize,
) -> Result<(), String> {
    let count: usize = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_source_supersessions",
            [],
            |row| row.get(0),
        )
        .map_err(|error| error.to_string())?;
    if count > MAX_SUPERSEDED {
        return Err("runtime source supersession history capacity exceeded".into());
    }
    if count > qualification_count {
        return Err("runtime source supersession count exceeds source count".into());
    }
    Ok(())
}

pub(super) fn load_all(
    connection: &Connection,
    records: &[RuntimeSourceRecordV1],
) -> Result<Vec<Supersession>, String> {
    verify_counts(connection, records.len())?;
    let mut statement = connection.prepare(
        "SELECT
         CASE WHEN typeof(prior_runtime_authority_id) = 'text'
                   AND octet_length(prior_runtime_authority_id) BETWEEN 1 AND 2048
                   AND instr(prior_runtime_authority_id, char(0)) = 0
              THEN prior_runtime_authority_id ELSE NULL END,
         CASE WHEN typeof(replacement_runtime_authority_id) = 'text'
                   AND octet_length(replacement_runtime_authority_id) BETWEEN 1 AND 2048
                   AND instr(replacement_runtime_authority_id, char(0)) = 0
              THEN replacement_runtime_authority_id ELSE NULL END,
         CASE WHEN typeof(canonical_supersession) = 'blob' AND length(canonical_supersession) BETWEEN 1 AND 8192
              THEN canonical_supersession ELSE NULL END,
         CASE WHEN typeof(record_digest) = 'text' AND length(record_digest) = 64
                   AND octet_length(record_digest) <= 128 AND instr(record_digest, char(0)) = 0
                   AND record_digest NOT GLOB '*[^0-9a-f]*'
              THEN record_digest ELSE NULL END
         FROM runtime_source_supersessions ORDER BY prior_runtime_authority_id",
    ).map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|error| error.to_string())?;
    let mut result = Vec::new();
    for row in rows {
        let (prior_id, replacement_id, bytes, digest) = row.map_err(|error| error.to_string())?;
        let (Some(prior_id), Some(replacement_id), Some(bytes), Some(digest)) =
            (prior_id, replacement_id, bytes, digest)
        else {
            return Err("runtime source supersession violates storage bounds".into());
        };
        let record: Supersession = chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 8192)
            .and_then(|input| input.decode_canonical())
            .map_err(|error| error.to_string())?;
        let prior = records
            .iter()
            .find(|r| r.qualification.runtime_authority_id() == prior_id)
            .ok_or("supersession names an absent prior source")?;
        let replacement = records
            .iter()
            .find(|r| r.qualification.runtime_authority_id() == replacement_id)
            .ok_or("supersession names an absent replacement source")?;
        if prior_id == replacement_id
            || prior.qualification.source_id() == replacement.qualification.source_id()
            || prior.observed_at_unix_ms > replacement.observed_at_unix_ms
            || prior.fence.store_uuid != replacement.fence.store_uuid
            || record != Supersession::new(prior, replacement)
            || record.bytes()? != bytes
            || record.digest()? != digest
        {
            return Err("runtime source supersession binding mismatch".into());
        }
        result.push(record);
    }
    Ok(result)
}

pub(super) fn active_count(
    connection: &Connection,
    records: &[RuntimeSourceRecordV1],
) -> Result<usize, String> {
    records
        .len()
        .checked_sub(load_all(connection, records)?.len())
        .ok_or_else(|| "runtime source supersession count exceeds source count".into())
}

pub(super) fn require_active(
    connection: &Connection,
    runtime: &str,
) -> Result<(), AdmissionOperationStoreError> {
    let superseded: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM runtime_source_supersessions WHERE prior_runtime_authority_id = ?1)",
        [runtime], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if superseded {
        return Err(invariant(
            "runtime source qualification has been superseded",
        ));
    }
    Ok(())
}
