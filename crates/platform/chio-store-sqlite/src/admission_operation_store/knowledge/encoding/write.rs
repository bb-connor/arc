//! An actual native source owns the complete priced encoding append.
use super::chunks::{
    ChunkedBody, EncodingOwner, StagedKnowledgeEncodingChunk, MAX_ATOM_BODY_BYTES, MAX_CHUNK_COUNT,
    MAX_ENCODED_SET_BYTES, MAX_PRIVATE_ROW_BYTES,
};
use crate::admission_operation_store::knowledge::AuthenticatedCheckpointRestoreEncodingSource;
use crate::admission_operation_store::recovery::storage as protected;
use crate::admission_operation_store::security_participant_state::knowledge::encoding::source::AuthenticatedNativeKnowledgeEncodingSource;
use crate::admission_operation_store::{invariant, AdmissionOperationStoreError};
use chio_security_types::recovery::ReleaseId;
use rusqlite::{Connection, Transaction};
use serde::Serialize;
use std::collections::BTreeSet;
use std::ops::Deref;

enum Source<'tx, 'conn> {
    Journal(AuthenticatedNativeKnowledgeEncodingSource<'tx, 'conn>),
    Restore(AuthenticatedCheckpointRestoreEncodingSource<'tx, 'conn>),
}

impl<'tx, 'conn> Source<'tx, 'conn> {
    fn transaction(&self) -> &'tx Transaction<'conn> {
        match self {
            Self::Journal(source) => source.transaction(),
            Self::Restore(source) => source.transaction(),
        }
    }
    fn owner(&self) -> EncodingOwner {
        match self {
            Self::Journal(source) => source.owner(),
            Self::Restore(source) => source.owner(),
        }
    }
    fn expected_root(&self) -> Option<&protected::ProtectedSourceReference> {
        match self {
            Self::Journal(source) => source.expected_root(),
            Self::Restore(source) => source.expected_root(),
        }
    }
    fn verify(&self, tx: &Transaction<'conn>) -> Result<(), AdmissionOperationStoreError> {
        match self {
            Self::Journal(source) => source.verify(tx),
            Self::Restore(source) => source.verify(tx),
        }
    }
    fn verify_stored_body(&self, body: &[u8]) -> Result<(), AdmissionOperationStoreError> {
        match self {
            Self::Journal(source) => source.verify_stored_body(body),
            Self::Restore(source) => source.verify_stored_body(body),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum JournalMarker {
    ChunkedLabelAtomsV1,
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum RestoreMarker {
    ChunkedLabelAtomsV1,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIdentity {
    release: ReleaseId,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct JournalRoot<'a> {
    knowledge_join_encoding: JournalMarker,
    authority: String,
    sequence: u64,
    scope: chio_security_types::recovery::RecoveryScopeV1,
    release: ReleaseIdentity,
    body: &'a ChunkedBody,
}
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RestoreRoot<'a> {
    checkpoint_restore_encoding: RestoreMarker,
    scope: chio_security_types::recovery::RecoveryScopeV1,
    intent: ReleaseIdentity,
    body: &'a ChunkedBody,
}

/// No Clone, Deserialize or constructor from caller-selected family/key/bytes.
/// The fixed source variants can be minted only by the actual journal and
/// checkpoint Restore owners after their original authority and state checks.
pub(in crate::admission_operation_store) struct VerifiedKnowledgeEncodingWrite<'tx, 'conn> {
    source: Source<'tx, 'conn>,
    owner: EncodingOwner,
    root_key: String,
    scope_key: String,
    root_payload: Vec<u8>,
    chunks: Vec<StagedKnowledgeEncodingChunk>,
    chunked_body: Option<ChunkedBody>,
    body: Vec<u8>,
    captured_head: (i64, String),
    encoded_bytes: u64,
}

impl<'tx, 'conn> VerifiedKnowledgeEncodingWrite<'tx, 'conn> {
    pub(in crate::admission_operation_store) fn journal(
        source: AuthenticatedNativeKnowledgeEncodingSource<'tx, 'conn>,
        stored_body: Vec<u8>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Self::prepare(Source::Journal(source), stored_body)
    }
    pub(in crate::admission_operation_store) fn restore(
        source: AuthenticatedCheckpointRestoreEncodingSource<'tx, 'conn>,
        stored_body: Vec<u8>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Self::prepare(Source::Restore(source), stored_body)
    }

    fn prepare(
        source: Source<'tx, 'conn>,
        body: Vec<u8>,
    ) -> Result<Self, AdmissionOperationStoreError> {
        let tx = source.transaction();
        source.verify(tx)?;
        source.verify_stored_body(&body)?;
        if body.is_empty() || body.len() > MAX_ATOM_BODY_BYTES {
            return Err(invalid());
        }
        let owner = source.owner();
        let root_key = owner.root_key()?;
        let scope_key = protected::scope_key(owner.scope())?;
        let (root_payload, chunks, chunked_body) = if body.len() <= MAX_PRIVATE_ROW_BYTES {
            (body.clone(), Vec::new(), None)
        } else {
            let (root, chunks) = ChunkedBody::capture(owner.clone(), &body)?;
            #[cfg(feature = "admission-test-support")]
            if let Source::Restore(actual) = &source {
                super::prefix_fault::retain_extra_prefix_fixture(actual, &root)?;
            }
            root.verify_pristine_prefix(tx)?;
            let payload = match &owner {
                EncodingOwner::Journal {
                    authority,
                    sequence,
                    scope,
                    release,
                } => protected::encode(&JournalRoot {
                    knowledge_join_encoding: JournalMarker::ChunkedLabelAtomsV1,
                    authority: authority.clone(),
                    sequence: *sequence,
                    scope: scope.clone(),
                    release: ReleaseIdentity {
                        release: release.clone(),
                    },
                    body: &root,
                })?,
                EncodingOwner::Restore { scope, release, .. } => protected::encode(&RestoreRoot {
                    checkpoint_restore_encoding: RestoreMarker::ChunkedLabelAtomsV1,
                    scope: scope.clone(),
                    intent: ReleaseIdentity {
                        release: release.clone(),
                    },
                    body: &root,
                })?,
            };
            (payload, chunks, Some(root))
        };
        let encoded_bytes = chunks.iter().try_fold(
            u64::try_from(root_payload.len()).map_err(|_| invalid())?,
            |total, chunk| {
                total
                    .checked_add(u64::try_from(chunk.payload().len()).map_err(|_| invalid())?)
                    .ok_or_else(invalid)
            },
        )?;
        let captured_head = global_head(tx)?;
        let proof = Self {
            source,
            owner,
            root_key,
            scope_key,
            root_payload,
            chunks,
            chunked_body,
            body,
            captured_head,
            encoded_bytes,
        };
        proof.verify(tx)?;
        Ok(proof)
    }

    pub(in crate::admission_operation_store) fn transaction(&self) -> &'tx Transaction<'conn> {
        self.source.transaction()
    }
    pub(in crate::admission_operation_store) fn root_key(&self) -> &str {
        &self.root_key
    }
    pub(in crate::admission_operation_store) fn scope_key(&self) -> &str {
        &self.scope_key
    }
    pub(in crate::admission_operation_store) fn expected_root(
        &self,
    ) -> Option<&protected::ProtectedSourceReference> {
        self.source.expected_root()
    }
    pub(in crate::admission_operation_store) fn root_payload(&self) -> &[u8] {
        &self.root_payload
    }
    pub(in crate::admission_operation_store) fn staged_chunks(
        &self,
    ) -> &[StagedKnowledgeEncodingChunk] {
        &self.chunks
    }
    pub(in crate::admission_operation_store) fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }

    /// Recheck the complete actual owner/body prefix in the original writer
    /// immediately before any immutable member or root append.
    pub(in crate::admission_operation_store) fn verify_pristine_prefix(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction()), Deref::deref(tx)) {
            return Err(invalid());
        }
        match &self.chunked_body {
            Some(body) if body.owner() == &self.owner => body.verify_pristine_prefix(tx),
            None if self.chunks.is_empty() && self.body.len() <= MAX_PRIVATE_ROW_BYTES => Ok(()),
            _ => Err(invalid()),
        }
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'conn>,
    ) -> Result<(), AdmissionOperationStoreError> {
        if !std::ptr::eq::<Connection>(Deref::deref(self.transaction()), Deref::deref(tx))
            || self.owner != self.source.owner()
            || self.root_key != self.owner.root_key()?
            || self.scope_key != protected::scope_key(self.owner.scope())?
            || global_head(tx)? != self.captured_head
            || self.root_payload.is_empty()
            || self.root_payload.len() > MAX_PRIVATE_ROW_BYTES
            || self.chunks.len() > MAX_CHUNK_COUNT
            || usize::try_from(self.encoded_bytes).map_err(|_| invalid())? > MAX_ENCODED_SET_BYTES
        {
            return Err(invalid());
        }
        self.source.verify(tx)?;
        self.source.verify_stored_body(&self.body)?;
        self.verify_pristine_prefix(tx)?;
        match self.expected_root() {
            Some(expected) => {
                protected::verify_source_reference(tx, expected)?;
                if expected.record_key() != self.root_key
                    || expected.scope_key() != self.scope_key
                    || expected.kind() != "command"
                {
                    return Err(invalid());
                }
            }
            None => {
                if protected::raw_checked(tx, &self.root_key)?.is_some() {
                    return Err(invalid());
                }
            }
        }
        let mut keys = BTreeSet::new();
        let mut bytes = u64::try_from(self.root_payload.len()).map_err(|_| invalid())?;
        for chunk in &self.chunks {
            if !keys.insert(chunk.key())
                || chunk.key() == self.root_key
                || chunk.scope() != self.scope_key
                || chunk.payload().is_empty()
                || chunk.payload().len() > MAX_PRIVATE_ROW_BYTES
                || protected::raw_checked(tx, chunk.key())?.is_some()
            {
                return Err(invalid());
            }
            bytes = bytes
                .checked_add(u64::try_from(chunk.payload().len()).map_err(|_| invalid())?)
                .ok_or_else(invalid)?;
        }
        if bytes != self.encoded_bytes {
            return Err(invalid());
        }
        Ok(())
    }
}

fn global_head(tx: &Connection) -> Result<(i64, String), AdmissionOperationStoreError> {
    tx.query_row("SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton=1", [], |row| Ok((row.get(0)?,row.get(1)?)))
        .map_err(|_| invalid())
}
fn invalid() -> AdmissionOperationStoreError {
    invariant("knowledge encoding source or priced append changed")
}

impl std::fmt::Debug for VerifiedKnowledgeEncodingWrite<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedKnowledgeEncodingWrite([redacted])")
    }
}
