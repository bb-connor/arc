//! A source reference is an authenticated latest head, never execution authority.
use super::*;

pub(in crate::admission_operation_store) struct ProtectedSourceReference {
    record_key: String,
    scope_key: String,
    kind: String,
    version: u64,
    record_digest: ProjectionDigest,
    event_sequence: u64,
    global_commit_sequence: u64,
}

/// Immutable source identity retained inside an owning journal. Decoding this
/// data cannot reconstruct a fresh source reference or a native write owner.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct HistoricalProtectedSourceData {
    record_key: String,
    scope_key: String,
    kind: String,
    version: chio_security_types::recovery::SafeInteger,
    record_digest: ProjectionDigest,
    event_sequence: chio_security_types::recovery::SafeInteger,
    global_commit_sequence: chio_security_types::recovery::SafeInteger,
}

impl HistoricalProtectedSourceData {
    pub(in crate::admission_operation_store) fn record_key(&self) -> &str {
        &self.record_key
    }

    pub(in crate::admission_operation_store) fn global_commit_sequence(&self) -> u64 {
        self.global_commit_sequence.get()
    }
}

impl ProtectedSourceReference {
    pub(in crate::admission_operation_store) fn record_key(&self) -> &str {
        &self.record_key
    }
    pub(in crate::admission_operation_store) fn scope_key(&self) -> &str {
        &self.scope_key
    }
    pub(in crate::admission_operation_store) fn kind(&self) -> &str {
        &self.kind
    }
    pub(in crate::admission_operation_store) fn version(&self) -> u64 {
        self.version
    }
    pub(in crate::admission_operation_store) fn digest(&self) -> &ProjectionDigest {
        &self.record_digest
    }
    pub(in crate::admission_operation_store) fn event_sequence(&self) -> u64 {
        self.event_sequence
    }
    pub(in crate::admission_operation_store) fn global_commit_sequence(&self) -> u64 {
        self.global_commit_sequence
    }

    pub(in crate::admission_operation_store) fn historical_data(
        &self,
    ) -> Result<HistoricalProtectedSourceData, AdmissionOperationStoreError> {
        use chio_security_types::recovery::SafeInteger;
        Ok(HistoricalProtectedSourceData {
            record_key: self.record_key.clone(),
            scope_key: self.scope_key.clone(),
            kind: self.kind.clone(),
            version: SafeInteger::new(self.version)
                .map_err(|_| invariant("historical source version exhausted"))?,
            record_digest: self.record_digest,
            event_sequence: SafeInteger::new(self.event_sequence)
                .map_err(|_| invariant("historical source event exhausted"))?,
            global_commit_sequence: SafeInteger::new(self.global_commit_sequence)
                .map_err(|_| invariant("historical source global reference exhausted"))?,
        })
    }
}

/// Compare historical data at the original source cut. The caller separately
/// authenticates the owning journal and global prefix. This never returns a
/// current source reference, mutation owner or permission to append.
pub(in crate::admission_operation_store) fn matches_historical_source_payload_at_cut(
    tx: &Connection,
    data: &HistoricalProtectedSourceData,
    expected_key: &str,
    expected_scope: &str,
    expected_kind: &str,
    canonical_payload: &[u8],
    source_cut: u64,
) -> Result<bool, AdmissionOperationStoreError> {
    if expected_key.is_empty()
        || expected_key.len() > 512
        || expected_scope.len() != 64
        || !matches!(expected_kind, "command" | "deployment")
        || data.record_key != expected_key
        || data.scope_key != expected_scope
        || data.kind != expected_kind
        || data.version.get() == 0
        || data.event_sequence.get() == 0
        || data.global_commit_sequence.get() == 0
        || data.global_commit_sequence.get() > source_cut
    {
        return Ok(false);
    }
    let _: serde_json::Value = decode(canonical_payload)?;
    let (digest, commit) = historical_record_reference(tx, expected_key, data.version.get())?;
    let (sequence, retained_digest): (i64, String) = tx
        .query_row(
            "SELECT sequence,record_digest FROM main.admission_operation_recovery_events
             WHERE record_key=?1 AND record_version=?2",
            params![
                expected_key,
                i64::try_from(data.version.get())
                    .map_err(|_| invariant("historical source version exhausted"))?
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    let latest: Option<i64> = tx
        .query_row(
            "SELECT projection_sequence FROM main.authority_global_commits
             WHERE projection_kind='recovery' AND projection_key=?1
               AND commit_sequence<=?2
             ORDER BY commit_sequence DESC LIMIT 1",
            params![
                expected_key,
                i64::try_from(source_cut)
                    .map_err(|_| invariant("historical source cut exhausted"))?
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    Ok(latest
        .map(|version| stored_u64(version, "historical selected source version"))
        .transpose()?
        == Some(data.version.get())
        && stored_u64(sequence, "historical selected source event")? == data.event_sequence.get()
        && commit == data.global_commit_sequence.get()
        && retained_digest == digest
        && digest == hex::encode(data.record_digest.as_bytes())
        && digest
            == record_digest(
                expected_key,
                expected_scope,
                expected_kind,
                data.version.get(),
                canonical_payload,
                None,
                None,
            )?)
}

pub(in crate::admission_operation_store) fn source_reference(
    tx: &Connection,
    key: &str,
) -> Result<ProtectedSourceReference, AdmissionOperationStoreError> {
    let row = raw_checked(tx, key)?.ok_or(AdmissionOperationStoreError::NotFound)?;
    let (digest, commit) = historical_record_reference(tx, key, row.version)?;
    let (event_version, event_sequence): (i64, i64) = tx
        .query_row(
            "SELECT record_version,sequence FROM main.admission_operation_recovery_events
             WHERE record_key=?1 ORDER BY record_version DESC LIMIT 1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    let (global_version, global_commit): (i64, i64) = tx
        .query_row(
            "SELECT projection_sequence,commit_sequence FROM main.authority_global_commits
             WHERE projection_kind='recovery' AND projection_key=?1
             ORDER BY projection_sequence DESC,commit_sequence DESC LIMIT 1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(sqlite_error)?;
    if stored_u64(event_version, "protected source latest event version")? != row.version
        || stored_u64(global_version, "protected source latest global version")? != row.version
        || stored_u64(global_commit, "protected source latest global commit")? != commit
    {
        return Err(invariant(
            "protected source projection is not its latest head",
        ));
    }
    // raw() has already recomputed the full record digest, including namespace
    // and request, and matched it to this event. The historical helper verifies
    // the event framing and unique corresponding immutable global reference.
    let digest = digest_bytes(&digest)?;
    Ok(ProtectedSourceReference {
        record_key: key.to_owned(),
        scope_key: row.scope,
        kind: row.kind,
        version: row.version,
        record_digest: ProjectionDigest::from_bytes(digest),
        event_sequence: stored_u64(event_sequence, "protected source event sequence")?,
        global_commit_sequence: commit,
    })
}

pub(in crate::admission_operation_store) fn verify_source_reference(
    tx: &Connection,
    expected: &ProtectedSourceReference,
) -> Result<(), AdmissionOperationStoreError> {
    let current = source_reference(tx, &expected.record_key)?;
    if current.record_key != expected.record_key
        || current.scope_key != expected.scope_key
        || current.kind != expected.kind
        || current.version != expected.version
        || current.record_digest != expected.record_digest
        || current.event_sequence != expected.event_sequence
        || current.global_commit_sequence != expected.global_commit_sequence
    {
        return Err(invariant("protected source reference changed"));
    }
    Ok(())
}

fn digest_bytes(text: &str) -> Result<[u8; 32], AdmissionOperationStoreError> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invariant("protected source digest is invalid"));
    }
    let mut digest = [0; 32];
    for (target, bytes) in digest.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(bytes)
            .map_err(|_| invariant("protected source digest is invalid"))?;
        *target = u8::from_str_radix(pair, 16)
            .map_err(|_| invariant("protected source digest is invalid"))?;
    }
    Ok(digest)
}

#[cfg(test)]
#[path = "protected_source_reference_tests.rs"]
mod protected_source_reference_tests;
