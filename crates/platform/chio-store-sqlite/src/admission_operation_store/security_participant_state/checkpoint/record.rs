use super::*;

const FORMAT: &str = "chio.native-security-checkpoint.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store::security_participant_state) struct FamilyHead {
    pub sequence: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store::security_participant_state) struct Record {
    pub schema: String,
    pub authority: AdmissionIdentifier,
    pub sequence: u64,
    pub initialization: String,
    pub previous: String,
    pub global_sequence: u64,
    pub global_digest: String,
    pub fence: StoreMutationFence,
    pub observed_at: u64,
    pub heads: [FamilyHead; 4],
    pub tables: Vec<rows::Fingerprint>,
    pub current_rows: u64,
    pub current_bytes: u64,
    pub segment_events: u64,
    pub segment_bytes: u64,
}

impl Record {
    pub(super) fn format() -> String {
        FORMAT.into()
    }

    pub(super) fn bytes(&self) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        let bytes = canonical_json_bytes(self).map_err(invalid)?;
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(invalid("native checkpoint record exceeds bounds"));
        }
        Ok(bytes)
    }

    pub(super) fn digest(&self) -> Result<String, AdmissionOperationStoreError> {
        let mut bytes = b"chio.native-security-checkpoint.commit.v1\0".to_vec();
        bytes.extend(self.bytes()?);
        Ok(sha256_hex(&bytes))
    }

    fn validate(&self, connection: &Connection) -> Result<(), AdmissionOperationStoreError> {
        let initialized =
            super::super::records::load_metadata(connection, self.authority.as_str())?
                .ok_or_else(|| invalid("native checkpoint initialization is absent"))?;
        if self.schema != FORMAT
            || self.initialization != initialized.digest
            || self.fence.store_uuid != initialized.fence.store_uuid
            || !(1..=9_007_199_254_740_991).contains(&self.sequence)
            || self.global_sequence == 0
            || self.global_sequence >= 9_007_199_254_740_991
            || self.observed_at < initialized.initialized_at
            || self.current_rows > 65_536
            || self.current_bytes > 67_108_864
            || self.segment_events > 65_536
            || self.segment_bytes > 67_108_864
            || self.heads[0].sequence < 1
            || self
                .heads
                .iter()
                .any(|head| head.sequence > 9_007_199_254_740_991)
            || self.tables.len() != super::super::schema::TABLES.len()
        {
            return Err(invalid("native checkpoint metadata is malformed"));
        }
        super::super::super::schema::validate_trusted_time(
            self.observed_at,
            "native checkpoint time",
        )?;
        for digest in [&self.initialization, &self.previous, &self.global_digest]
            .into_iter()
            .chain(self.heads.iter().map(|head| &head.digest))
        {
            AdmissionDigest::try_new("native_checkpoint_digest", digest)?;
        }
        let mut total_rows = 0_u64;
        let mut total_bytes = 0_u64;
        for (fingerprint, table) in self.tables.iter().zip(super::super::schema::TABLES) {
            if fingerprint.table != table.source
                || fingerprint.row_count > 65_536
                || fingerprint.encoded_bytes > 67_108_864
            {
                return Err(invalid("native checkpoint table inventory is malformed"));
            }
            AdmissionDigest::try_new("native_checkpoint_table", &fingerprint.digest)?;
            total_rows = total_rows
                .checked_add(fingerprint.row_count)
                .ok_or_else(|| invalid("native checkpoint row count overflow"))?;
            total_bytes = total_bytes
                .checked_add(fingerprint.encoded_bytes)
                .ok_or_else(|| invalid("native checkpoint byte count overflow"))?;
        }
        if (total_rows, total_bytes) != (self.current_rows, self.current_bytes) {
            return Err(invalid("native checkpoint snapshot totals differ"));
        }
        let previous = if self.sequence == 1 {
            initialized.digest
        } else {
            connection.query_row(
                "SELECT CASE WHEN length(CAST(checkpoint_digest AS BLOB)) = 64 THEN checkpoint_digest END
                 FROM security_participant_checkpoint_events WHERE security_authority_id = ?1 AND sequence = ?2",
                params![self.authority.as_str(), i64::try_from(self.sequence - 1).map_err(invalid)?],
                |row| row.get::<_, Option<String>>(0),
            ).optional().map_err(sqlite_error)?.flatten()
                .ok_or_else(|| invalid("native checkpoint predecessor is absent"))?
        };
        let exact: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE commit_sequence = ?1 AND chain_digest = ?2)
             AND EXISTS(SELECT 1 FROM chio_serving_leases WHERE store_uuid = ?3 AND owner_epoch = ?4 AND lease_id = ?5)",
            params![i64::try_from(self.global_sequence).map_err(invalid)?, self.global_digest,
                self.fence.store_uuid, i64::try_from(self.fence.owner_epoch).map_err(invalid)?, self.fence.lease_id],
            |row| row.get(0),
        ).map_err(sqlite_error)?;
        if self.previous != previous || !exact {
            return Err(invalid(
                "native checkpoint predecessor or ownership differs",
            ));
        }
        Ok(())
    }

    pub(super) fn insert(&self, tx: &Transaction<'_>) -> Result<(), AdmissionOperationStoreError> {
        self.validate(tx)?;
        tx.execute(
            "INSERT INTO security_participant_checkpoint_events
             (security_authority_id,sequence,canonical_record,checkpoint_digest,observed_at) VALUES (?1,?2,?3,?4,?5)",
            params![self.authority.as_str(), i64::try_from(self.sequence).map_err(invalid)?,
                self.bytes()?, self.digest()?, i64::try_from(self.observed_at).map_err(invalid)?],
        ).map_err(sqlite_error)?;
        Ok(())
    }
}

pub(super) fn load_local(
    connection: &Connection,
    authority: &str,
    sequence: u64,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    let bytes: Option<Option<Vec<u8>>> = connection.query_row(
        "SELECT CASE WHEN typeof(canonical_record) = 'blob' AND length(canonical_record) BETWEEN 1 AND 65536
         THEN canonical_record END FROM security_participant_checkpoint_events
         WHERE security_authority_id = ?1 AND sequence = ?2",
        params![authority,i64::try_from(sequence).map_err(invalid)?], |row| row.get(0),
    ).optional().map_err(sqlite_error)?;
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let bytes = bytes.ok_or_else(|| invalid("native checkpoint bytes exceed bounds"))?;
    let record: Record = chio_core::canonical::UntrustedJsonText::from_wire(&bytes, 65_536)
        .and_then(|input| input.decode_signed())?;
    if record.bytes()? != bytes
        || record.authority.as_str() != authority
        || record.sequence != sequence
    {
        return Err(invalid(
            "native checkpoint index differs from canonical history",
        ));
    }
    record.validate(connection)?;
    let exact: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM security_participant_checkpoint_events WHERE security_authority_id = ?1
         AND sequence = ?2 AND checkpoint_digest = ?3 AND observed_at = ?4)",
        params![authority,i64::try_from(sequence).map_err(invalid)?,record.digest()?,i64::try_from(record.observed_at).map_err(invalid)?],
        |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !exact {
        return Err(invalid("native checkpoint projection differs"));
    }
    Ok(Some(record))
}

pub(super) fn verify_reference(
    connection: &Connection,
    record: &Record,
) -> Result<(), AdmissionOperationStoreError> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind = ?1 AND projection_key = ?2
         AND projection_sequence = ?3 AND mutation_kind = ?4 AND projection_reference_digest = ?5
         AND store_uuid = ?6 AND store_lease_id = ?7 AND store_owner_epoch = ?8
         AND commit_sequence = ?9 AND previous_chain_digest = ?10",
        params![PROJECTION,record.authority.as_str(),i64::try_from(record.sequence).map_err(invalid)?,MUTATION,
            record.digest()?,record.fence.store_uuid,record.fence.lease_id,i64::try_from(record.fence.owner_epoch).map_err(invalid)?,
            i64::try_from(record.global_sequence + 1).map_err(invalid)?,record.global_digest],
        |row| row.get(0),
    ).map_err(sqlite_error)?;
    if count != 1 {
        return Err(invalid("native checkpoint lacks its exact global commit"));
    }
    Ok(())
}

pub(super) fn latest(
    connection: &Connection,
    authority: &str,
) -> Result<Option<Record>, AdmissionOperationStoreError> {
    if !schema::present(connection)? {
        return Ok(None);
    }
    let sequence: Option<i64> = connection.query_row(
        "SELECT MAX(sequence) FROM security_participant_checkpoint_events WHERE security_authority_id = ?1",
        [authority], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let Some(sequence) = sequence else {
        return Ok(None);
    };
    let record = load_local(
        connection,
        authority,
        u64::try_from(sequence).map_err(invalid)?,
    )?
    .ok_or_else(|| invalid("native checkpoint head is absent"))?;
    // The enclosing serving-owner transaction pins the independent rollback
    // anchor. This exact global reference, not the local self hash, authorizes
    // using the checkpoint as a fold boundary.
    verify_reference(connection, &record)?;
    Ok(Some(record))
}

#[cfg(test)]
#[path = "record_wire_tests.rs"]
mod wire_tests;
