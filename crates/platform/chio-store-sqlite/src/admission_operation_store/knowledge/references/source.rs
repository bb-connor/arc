//! Immutable source anchors are evidence, never fresh mutation authority.
use super::*;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct SourceAnchor {
    record_key: String,
    scope_key: String,
    kind: String,
    version: u64,
    digest: ProjectionDigest,
    event_sequence: u64,
    global_commit_sequence: u64,
}

impl SourceAnchor {
    pub(in crate::admission_operation_store) fn validate_ordinary(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.validate()?;
        if self.record_key.len() > 512
            || self.kind != "command"
            || self.scope_key.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(refused("ordinary reference source exceeds its envelope"));
        }
        SafeInteger::new(self.version).map_err(refused)?;
        SafeInteger::new(self.event_sequence).map_err(refused)?;
        SafeInteger::new(self.global_commit_sequence).map_err(refused)?;
        Ok(())
    }

    pub(in crate::admission_operation_store) fn capture(
        source: &protected::ProtectedSourceReference,
    ) -> Self {
        Self {
            record_key: source.record_key().to_owned(),
            scope_key: source.scope_key().to_owned(),
            kind: source.kind().to_owned(),
            version: source.version(),
            digest: *source.digest(),
            event_sequence: source.event_sequence(),
            global_commit_sequence: source.global_commit_sequence(),
        }
    }

    pub(in crate::admission_operation_store) fn record_key(&self) -> &str {
        &self.record_key
    }

    pub(in crate::admission_operation_store) fn scope_key(&self) -> &str {
        &self.scope_key
    }

    pub(in crate::admission_operation_store) fn version(&self) -> u64 {
        self.version
    }

    /// Authenticate a complete historical command envelope. This returns
    /// immutable source data and conveys no fresh writer or terminal authority.
    pub(in crate::admission_operation_store) fn historical_command(
        connection: &Connection,
        current: &protected::ProtectedSourceReference,
        version: u64,
        canonical_envelope: &[u8],
    ) -> Result<Option<Self>, AdmissionOperationStoreError> {
        if !protected::matches_historical_source_command_payload(
            connection,
            current,
            version,
            canonical_envelope,
        )? {
            return Ok(None);
        }
        let (sequence, digest): (i64, String) = connection.query_row(
            "SELECT sequence,record_digest FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
            params![current.record_key(), i64::try_from(version).map_err(refused)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(sqlite_error)?;
        let digest: [u8; 32] = hex::decode(digest)
            .map_err(refused)?
            .try_into()
            .map_err(|_| refused("publication historical digest"))?;
        let anchor = Self {
            record_key: current.record_key().to_owned(),
            scope_key: current.scope_key().to_owned(),
            kind: current.kind().to_owned(),
            version,
            digest: ProjectionDigest::from_bytes(digest),
            event_sequence: stored_u64(sequence, "publication historical event")?,
            global_commit_sequence: protected::historical_record_commit(
                connection,
                current.record_key(),
                version,
            )?,
        };
        anchor.verify_historical_identity(connection)?;
        Ok(Some(anchor))
    }

    pub(in crate::admission_operation_store) fn global_commit_sequence(&self) -> u64 {
        self.global_commit_sequence
    }

    pub(super) fn same_logical_source(&self, other: &Self) -> bool {
        self.record_key == other.record_key
            && self.scope_key == other.scope_key
            && self.kind == other.kind
    }

    pub(in crate::admission_operation_store) fn not_after(&self, other: &Self) -> bool {
        if self.version == other.version {
            return self == other;
        }
        self.same_logical_source(other)
            && self.version < other.version
            && self.event_sequence < other.event_sequence
            && self.global_commit_sequence < other.global_commit_sequence
    }

    /// Authenticate the original immutable event without requiring a mutable
    /// owning source to remain at its first version.
    pub(in crate::admission_operation_store) fn verify_historical_identity(
        &self,
        connection: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.validate()?;
        let current = protected::source_reference(connection, &self.record_key)?;
        if !self.not_after(&Self::capture(&current)) {
            return Err(refused("reference original source is not retained"));
        }
        let commit =
            protected::historical_record_commit(connection, &self.record_key, self.version)?;
        let version = i64::try_from(self.version)
            .map_err(|_| refused("reference original version exhausted"))?;
        let (sequence, digest): (i64, String) = connection
            .query_row(
                "SELECT sequence,record_digest FROM admission_operation_recovery_events
                 WHERE record_key=?1 AND record_version=?2",
                params![self.record_key, version],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sqlite_error)?;
        if stored_u64(sequence, "reference original event sequence")? != self.event_sequence
            || digest != hex::encode(self.digest.as_bytes())
            || commit != self.global_commit_sequence
        {
            return Err(refused("reference original source identity changed"));
        }
        Ok(())
    }

    /// The caller supplies the complete canonical owning envelope. A content
    /// digest or decoded checkpoint body cannot replace protected framing.
    pub(in crate::admission_operation_store) fn matches_historical_command_payload(
        &self,
        connection: &Connection,
        canonical_envelope: &[u8],
    ) -> Result<bool, AdmissionOperationStoreError> {
        self.verify_historical_identity(connection)?;
        protected::matches_historical_command_payload(
            connection,
            &self.record_key,
            &self.scope_key,
            self.version,
            canonical_envelope,
        )
    }

    pub(super) fn validate(&self) -> Result<(), AdmissionOperationStoreError> {
        if self.record_key.is_empty()
            || self.scope_key.len() != 64
            || !self.scope_key.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self.kind.is_empty()
            || self.version == 0
            || self.event_sequence == 0
            || self.global_commit_sequence == 0
        {
            return Err(refused("reference original source anchor"));
        }
        Ok(())
    }
}

impl std::fmt::Debug for SourceAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SourceAnchor([redacted])")
    }
}
