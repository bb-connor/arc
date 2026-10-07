//! Exact immutable framing of a closed typed knowledge atom body.
use super::labels::MAX_LOGICAL_LABEL_BYTES;
use crate::admission_operation_store::recovery::storage as protected;
use crate::admission_operation_store::{invariant, sha256_hex, AdmissionOperationStoreError};
use chio_security_types::recovery::*;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(in crate::admission_operation_store) const MAX_PRIVATE_ROW_BYTES: usize = 262_144;
pub(in crate::admission_operation_store) const MAX_CHUNK_DATA_BYTES: usize = 65_536;
const MAX_LABELS: usize = 16;
const MAX_POLICIES: usize = MAX_LABELS * 64;
const MAX_ATOM_INDEX_BYTES: usize = MAX_POLICIES * (256 * 8 + 128) + MAX_LABELS * 64 * 8;
const MAX_CHANGE_ROWS: usize = 4096;
const MAX_ROW_CELLS: usize = 64;
const MAX_IMAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CELL_ENVELOPE_BYTES: usize = 128;
const MAX_NON_LABEL_FIELDS_BYTES: usize = 16 * MAX_PRIVATE_ROW_BYTES;
const MAX_CHUNK_HEADER_BYTES: usize = 16 * 1024;

/// A protocol-derived ceiling, independent of how much sharing a particular
/// label happens to have. It includes every exact native before/after image and
/// the compiled cell wrapper overhead. It is not a per-row ceiling increase.
pub(in crate::admission_operation_store) const MAX_ATOM_BODY_BYTES: usize = MAX_LABELS
    * MAX_LOGICAL_LABEL_BYTES
    + MAX_ATOM_INDEX_BYTES
    + 2 * MAX_IMAGE_BYTES
    + MAX_CHANGE_ROWS * MAX_ROW_CELLS * MAX_CELL_ENVELOPE_BYTES
    + MAX_NON_LABEL_FIELDS_BYTES;
pub(in crate::admission_operation_store) const MAX_CHUNK_COUNT: usize =
    MAX_ATOM_BODY_BYTES.div_ceil(MAX_CHUNK_DATA_BYTES);
pub(in crate::admission_operation_store) const MAX_ENCODED_SET_BYTES: usize =
    2 * MAX_ATOM_BODY_BYTES + MAX_CHUNK_COUNT * MAX_CHUNK_HEADER_BYTES + MAX_PRIVATE_ROW_BYTES;

/// Evidence data. Only an opaque native Journal or checkpoint Restore source
/// can select an owner when constructing the affine write proof.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::admission_operation_store) enum EncodingOwner {
    Journal {
        scope: RecoveryScopeV1,
        authority: String,
        sequence: u64,
        release: ReleaseId,
    },
    Restore {
        scope: RecoveryScopeV1,
        record_key: String,
        release: ReleaseId,
    },
}

impl EncodingOwner {
    pub(in crate::admission_operation_store) fn scope(&self) -> &RecoveryScopeV1 {
        match self {
            Self::Journal { scope, .. } | Self::Restore { scope, .. } => scope,
        }
    }
    pub(in crate::admission_operation_store) fn root_key(
        &self,
    ) -> Result<String, AdmissionOperationStoreError> {
        match self {
            Self::Journal {
                authority,
                sequence,
                ..
            } => {
                if authority.is_empty() || authority.len() > 512 || *sequence == 0 {
                    return Err(invalid());
                }
                Ok(format!(
                    "knowledge-join:{}:{sequence:016}",
                    sha256_hex(authority.as_bytes())
                ))
            }
            Self::Restore {
                scope, record_key, ..
            } => {
                let scope = protected::scope_key(scope)?;
                if record_key.len() > 512
                    || !(record_key.starts_with(&format!("knowledge-restore:{scope}:"))
                        || record_key.starts_with(&format!("knowledge-restore:v2:{scope}:")))
                {
                    return Err(invalid());
                }
                Ok(record_key.clone())
            }
        }
    }
    fn identity(&self) -> Result<String, AdmissionOperationStoreError> {
        self.root_key()?;
        Ok(sha256_hex(&protected::encode(self)?))
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChunkEncoding {
    LabelAtomsV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct ChunkedBody {
    knowledge_chunk_encoding: ChunkEncoding,
    owner: EncodingOwner,
    body_digest: String,
    body_bytes: u64,
    chunk_count: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkRecord {
    knowledge_chunk_encoding: ChunkEncoding,
    owner: EncodingOwner,
    body_digest: String,
    body_bytes: u64,
    chunk_count: u32,
    ordinal: u32,
    data: String,
}

pub(in crate::admission_operation_store) struct StagedKnowledgeEncodingChunk {
    key: String,
    scope: String,
    payload: Vec<u8>,
}
impl StagedKnowledgeEncodingChunk {
    pub(in crate::admission_operation_store) fn key(&self) -> &str {
        &self.key
    }
    pub(in crate::admission_operation_store) fn scope(&self) -> &str {
        &self.scope
    }
    pub(in crate::admission_operation_store) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl ChunkedBody {
    /// Pure framing, not a write grant. The private owning write proof checks
    /// its actual source, exact typed body and complete inventory separately.
    pub(in crate::admission_operation_store) fn capture(
        owner: EncodingOwner,
        body: &[u8],
    ) -> Result<(Self, Vec<StagedKnowledgeEncodingChunk>), AdmissionOperationStoreError> {
        if body.len() <= MAX_PRIVATE_ROW_BYTES || body.len() > MAX_ATOM_BODY_BYTES {
            return Err(invalid());
        }
        let scope = protected::scope_key(owner.scope())?;
        let root = Self {
            knowledge_chunk_encoding: ChunkEncoding::LabelAtomsV1,
            owner,
            body_digest: sha256_hex(body),
            body_bytes: u64::try_from(body.len()).map_err(|_| invalid())?,
            chunk_count: u32::try_from(body.len().div_ceil(MAX_CHUNK_DATA_BYTES))
                .map_err(|_| invalid())?,
        };
        root.validate()?;
        let mut staged =
            Vec::with_capacity(usize::try_from(root.chunk_count).map_err(|_| invalid())?);
        for (ordinal, bytes) in body.chunks(MAX_CHUNK_DATA_BYTES).enumerate() {
            let ordinal = u32::try_from(ordinal).map_err(|_| invalid())?;
            let record = ChunkRecord {
                knowledge_chunk_encoding: ChunkEncoding::LabelAtomsV1,
                owner: root.owner.clone(),
                body_digest: root.body_digest.clone(),
                body_bytes: root.body_bytes,
                chunk_count: root.chunk_count,
                ordinal,
                data: hex::encode(bytes),
            };
            let payload = protected::encode(&record)?;
            if payload.len() > 2 * MAX_CHUNK_DATA_BYTES + MAX_CHUNK_HEADER_BYTES {
                return Err(invalid());
            }
            staged.push(StagedKnowledgeEncodingChunk {
                key: root.chunk_key(ordinal)?,
                scope: scope.clone(),
                payload,
            });
        }
        Ok((root, staged))
    }

    pub(in crate::admission_operation_store) fn validate(
        &self,
    ) -> Result<(), AdmissionOperationStoreError> {
        let length = usize::try_from(self.body_bytes).map_err(|_| invalid())?;
        let count = usize::try_from(self.chunk_count).map_err(|_| invalid())?;
        if length <= MAX_PRIVATE_ROW_BYTES
            || length > MAX_ATOM_BODY_BYTES
            || count == 0
            || count > MAX_CHUNK_COUNT
            || count != length.div_ceil(MAX_CHUNK_DATA_BYTES)
            || self.body_digest.len() != 64
            || !self
                .body_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid());
        }
        self.owner.root_key()?;
        Ok(())
    }
    pub(in crate::admission_operation_store) fn owner(&self) -> &EncodingOwner {
        &self.owner
    }
    pub(in crate::admission_operation_store) fn chunk_prefix(
        &self,
    ) -> Result<String, AdmissionOperationStoreError> {
        Ok(format!(
            "knowledge-encoding-chunk:{}:{}:",
            self.owner.identity()?,
            self.body_digest
        ))
    }

    /// Any retained physical member of this exact owner and body prevents a
    /// new immutable set. Planned-key absence alone cannot prove its complete
    /// prefix pristine, including event-only or global-only retained members.
    pub(in crate::admission_operation_store) fn verify_pristine_prefix(
        &self,
        tx: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.validate()?;
        let retained: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB ?1)
                     OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB ?1)
                     OR EXISTS(SELECT 1 FROM authority_global_commits
                               WHERE projection_kind='recovery' AND projection_key GLOB ?1)",
                [format!("{}*", self.chunk_prefix()?)],
                |row| row.get(0),
            )
            .map_err(|_| invalid())?;
        if retained {
            return Err(invalid());
        }
        Ok(())
    }
    fn chunk_key(&self, ordinal: u32) -> Result<String, AdmissionOperationStoreError> {
        if ordinal >= self.chunk_count {
            return Err(invalid());
        }
        Ok(format!("{}{ordinal:04}", self.chunk_prefix()?))
    }

    #[cfg(feature = "admission-test-support")]
    pub(in crate::admission_operation_store) fn verify_fixture_body(
        &self,
        owner: &EncodingOwner,
        body: &[u8],
    ) -> Result<(), AdmissionOperationStoreError> {
        self.validate()?;
        if &self.owner != owner
            || self.body_digest != sha256_hex(body)
            || self.body_bytes != u64::try_from(body.len()).map_err(|_| invalid())?
            || usize::try_from(self.chunk_count).map_err(|_| invalid())?
                != body.len().div_ceil(MAX_CHUNK_DATA_BYTES)
        {
            return Err(invalid());
        }
        Ok(())
    }

    /// This test-only frame deliberately declares a different valid set size.
    /// It uses the actual owner's original body digest and first extra ordinal.
    #[cfg(feature = "admission-test-support")]
    pub(in crate::admission_operation_store) fn extra_ordinal_fixture(
        &self,
    ) -> Result<StagedKnowledgeEncodingChunk, AdmissionOperationStoreError> {
        self.validate()?;
        let count = self.chunk_count.checked_add(1).ok_or_else(invalid)?;
        let bytes = usize::try_from(self.chunk_count)
            .map_err(|_| invalid())?
            .checked_mul(MAX_CHUNK_DATA_BYTES)
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or_else(invalid)?;
        if count as usize > MAX_CHUNK_COUNT || bytes > MAX_ATOM_BODY_BYTES {
            return Err(invalid());
        }
        let record = ChunkRecord {
            knowledge_chunk_encoding: ChunkEncoding::LabelAtomsV1,
            owner: self.owner.clone(),
            body_digest: self.body_digest.clone(),
            body_bytes: u64::try_from(bytes).map_err(|_| invalid())?,
            chunk_count: count,
            ordinal: self.chunk_count,
            data: "00".to_owned(),
        };
        let payload = protected::encode(&record)?;
        if payload.len() > MAX_PRIVATE_ROW_BYTES {
            return Err(invalid());
        }
        Ok(StagedKnowledgeEncodingChunk {
            key: format!("{}{:04}", self.chunk_prefix()?, self.chunk_count),
            scope: protected::scope_key(self.owner.scope())?,
            payload,
        })
    }

    #[cfg(feature = "admission-test-support")]
    pub(in crate::admission_operation_store) fn fixture_body_counts(&self) -> (u64, u32) {
        (self.body_bytes, self.chunk_count)
    }

    /// The surrounding typed decoder authenticates the exact current or
    /// historical root payload and supplies its actual protected global ordinal.
    /// This method reconstructs data and supplies no release authority.
    pub(in crate::admission_operation_store) fn load(
        &self,
        tx: &Connection,
        root: &AuthenticatedKnowledgeEncodingRoot<'_>,
    ) -> Result<Vec<u8>, AdmissionOperationStoreError> {
        self.validate()?;
        root.verify(tx)?;
        if root.owner != self.owner {
            return Err(invalid());
        }
        let scope = protected::scope_key(self.owner.scope())?;
        let expected_length = usize::try_from(self.body_bytes).map_err(|_| invalid())?;
        let count = usize::try_from(self.chunk_count).map_err(|_| invalid())?;
        let mut sources = Vec::with_capacity(count);
        let mut complete_digest = Sha256::new();
        for ordinal in 0..self.chunk_count {
            let key = self.chunk_key(ordinal)?;
            let row = protected::raw_checked(tx, &key)?.ok_or_else(invalid)?;
            let source = protected::source_reference(tx, &key)?;
            let local: bool = tx.query_row(
                "SELECT native_namespace IS NULL AND native_request IS NULL FROM admission_operation_recovery_records WHERE record_key=?1",
                [&key], |row| row.get(0),
            ).map_err(|_| invalid())?;
            if !local
                || row.version != 1
                || row.kind != "command"
                || row.scope != scope
                || source.version() != 1
                || source.kind() != "command"
                || source.scope_key() != scope
                || source.global_commit_sequence() >= root.global_sequence
            {
                return Err(invalid());
            }
            let chunk: ChunkRecord = protected::decode(&row.payload)?;
            let start = usize::try_from(ordinal)
                .map_err(|_| invalid())?
                .checked_mul(MAX_CHUNK_DATA_BYTES)
                .ok_or_else(invalid)?;
            let expected = expected_length
                .checked_sub(start)
                .ok_or_else(invalid)?
                .min(MAX_CHUNK_DATA_BYTES);
            if chunk.owner != self.owner
                || chunk.body_digest != self.body_digest
                || chunk.body_bytes != self.body_bytes
                || chunk.chunk_count != self.chunk_count
                || chunk.ordinal != ordinal
                || chunk.data.len() != expected.checked_mul(2).ok_or_else(invalid)?
                || !chunk
                    .data
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid());
            }
            let bytes = hex::decode(&chunk.data).map_err(|_| invalid())?;
            complete_digest.update(&bytes);
            sources.push(source);
        }
        let actual: i64 = tx.query_row(
            "SELECT count(*) FROM (
                SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB ?1
                UNION SELECT record_key FROM admission_operation_recovery_events WHERE record_key GLOB ?1
                UNION SELECT projection_key FROM authority_global_commits
                WHERE projection_kind='recovery' AND projection_key GLOB ?1
             )", [format!("{}*", self.chunk_prefix()?)], |row| row.get(0),
        ).map_err(|_| invalid())?;
        if usize::try_from(actual).map_err(|_| invalid())? != count
            || hex::encode(complete_digest.finalize()) != self.body_digest
        {
            return Err(invalid());
        }
        // Authenticate the complete bounded inventory and digest before the
        // one full-body allocation. Recheck each exact current source when
        // reading the same immutable chunk a second time in the anchored Tx.
        let mut body = Vec::with_capacity(expected_length);
        for source in sources {
            protected::verify_source_reference(tx, &source)?;
            let row = protected::raw_checked(tx, source.record_key())?.ok_or_else(invalid)?;
            let chunk: ChunkRecord = protected::decode(&row.payload)?;
            let bytes = hex::decode(&chunk.data).map_err(|_| invalid())?;
            body.extend_from_slice(&bytes);
        }
        if body.len() != expected_length || sha256_hex(&body) != self.body_digest {
            return Err(invalid());
        }
        root.verify(tx)?;
        Ok(body)
    }
}

/// Historical root payloads remain valid after a lawful Restore state advance.
/// Exact command framing authenticates their own version/global ordinal rather
/// than incorrectly requiring equality with the latest root bytes.
pub(in crate::admission_operation_store) struct AuthenticatedKnowledgeEncodingRoot<'read> {
    connection: &'read Connection,
    owner: EncodingOwner,
    version: u64,
    payload: Vec<u8>,
    current: protected::ProtectedSourceReference,
    global_sequence: u64,
}

impl<'read> AuthenticatedKnowledgeEncodingRoot<'read> {
    /// Both current and retained historical decoders have an exact physical
    /// key/version from their authenticated owning row. No global ordinal is
    /// accepted from a caller or serialized chunk descriptor.
    pub(in crate::admission_operation_store) fn authenticate(
        tx: &'read Connection,
        key: &str,
        version: u64,
        canonical_root: &[u8],
        owner: &EncodingOwner,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let current = protected::source_reference(tx, key)?;
        if owner.root_key()? != key
            || current.kind() != "command"
            || current.scope_key() != protected::scope_key(owner.scope())?
            || version == 0
            || version > current.version()
            || canonical_root.is_empty()
            || canonical_root.len() > MAX_PRIVATE_ROW_BYTES
        {
            return Err(invalid());
        }
        let local: bool = tx.query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL FROM admission_operation_recovery_records WHERE record_key=?1",
            [key], |row| row.get(0),
        ).map_err(|_| invalid())?;
        if !local
            || !protected::matches_historical_source_command_payload(
                tx,
                &current,
                version,
                canonical_root,
            )?
        {
            return Err(invalid());
        }
        let global_sequence = protected::historical_record_commit(tx, key, version)?;
        let root = Self {
            connection: tx,
            owner: owner.clone(),
            version,
            payload: canonical_root.to_vec(),
            current,
            global_sequence,
        };
        root.verify(tx)?;
        Ok(root)
    }
    fn verify(&self, tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq(self.connection, tx) {
            return Err(invalid());
        }
        protected::verify_source_reference(tx, &self.current)?;
        if !protected::matches_historical_source_command_payload(
            tx,
            &self.current,
            self.version,
            &self.payload,
        )? || protected::historical_record_commit(tx, self.current.record_key(), self.version)?
            != self.global_sequence
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> AdmissionOperationStoreError {
    invariant("knowledge atom chunk framing is invalid")
}
