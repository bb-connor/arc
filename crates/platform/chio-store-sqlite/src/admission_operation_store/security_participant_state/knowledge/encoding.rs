//! Native journal decoding retains old wire bytes and exact atom/chunk custody.
use super::Record;
use crate::admission_operation_store::knowledge::encoding::chunks::{
    AuthenticatedKnowledgeEncodingRoot, ChunkedBody, EncodingOwner,
};
use crate::admission_operation_store::knowledge::encoding::write::VerifiedKnowledgeEncodingWrite;
use crate::admission_operation_store::recovery::storage as protected;
use crate::admission_operation_store::{invariant, AdmissionOperationStoreError};
use chio_security_types::recovery::{RecoveryScopeV1, ReleaseId};
use rusqlite::{Connection, Transaction};
use serde::{Deserialize, Serialize};

mod atoms;
mod legacy;
pub(in crate::admission_operation_store) mod source;

#[derive(Deserialize)]
struct EncodingProbe {
    knowledge_join_encoding: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalChunkMarker {
    ChunkedLabelAtomsV1,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseIdentity {
    release: ReleaseId,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRoot {
    knowledge_join_encoding: JournalChunkMarker,
    authority: String,
    sequence: u64,
    scope: RecoveryScopeV1,
    release: ReleaseIdentity,
    body: ChunkedBody,
}

pub(super) fn prepare<'tx, 'conn>(
    tx: &'tx Transaction<'conn>,
    record: &'tx Record,
) -> Result<VerifiedKnowledgeEncodingWrite<'tx, 'conn>, AdmissionOperationStoreError> {
    require_atom_format(tx)?;
    let source = source::AuthenticatedNativeKnowledgeEncodingSource::after_native_join(tx, record)?;
    let body = atoms::logical_body(record)?;
    VerifiedKnowledgeEncodingWrite::journal(source, body)
}

pub(super) fn decode(
    tx: &Connection,
    key: &str,
    version: u64,
    bytes: &[u8],
) -> Result<Record, AdmissionOperationStoreError> {
    if bytes.is_empty() || bytes.len() > 262_144 {
        return Err(invalid());
    }
    let probe: EncodingProbe = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    match probe.knowledge_join_encoding.as_deref() {
        None | Some("interned_labels_v1") => legacy::decode(tx, bytes),
        Some("interned_label_atoms_v1") => {
            require_atom_format(tx)?;
            atoms::decode_body(bytes)
        }
        Some("chunked_label_atoms_v1") => {
            require_atom_format(tx)?;
            let root: JournalRoot = protected::decode(bytes)?;
            let owner = EncodingOwner::Journal {
                scope: root.scope.clone(),
                authority: root.authority.clone(),
                sequence: root.sequence,
                release: root.release.release.clone(),
            };
            if root.body.owner() != &owner || owner.root_key()? != key || version != 1 {
                return Err(invalid());
            }
            let custody =
                AuthenticatedKnowledgeEncodingRoot::authenticate(tx, key, version, bytes, &owner)?;
            let body = root.body.load(tx, &custody)?;
            let record = atoms::decode_body(&body)?;
            if record.authority != root.authority
                || record.sequence != root.sequence
                || record.scope != root.scope
                || record.release.release != root.release.release
                || atoms::logical_body(&record)? != body
            {
                return Err(invalid());
            }
            Ok(record)
        }
        Some(_) => Err(invalid()),
    }
}

fn require_atom_format(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    use crate::admission_operation_store::{
        ADMISSION_OPERATION_SCHEMA_ANCHORS, ADMISSION_OPERATION_SCHEMA_KEY,
    };
    let version = crate::check_schema_version(
        tx,
        ADMISSION_OPERATION_SCHEMA_KEY,
        40,
        ADMISSION_OPERATION_SCHEMA_ANCHORS,
    )
    .map_err(|_| invalid())?;
    if version != 40 {
        return Err(invalid());
    }
    Ok(())
}

/// Exact pure framing for a proposed native journal. This creates no encoding
/// write source and does not authorize inserting its root or immutable chunks.
pub(super) fn preview_rows(
    record: &Record,
) -> Result<Vec<(String, String, Vec<u8>)>, AdmissionOperationStoreError> {
    let body = atoms::logical_body(record)?;
    let owner = EncodingOwner::Journal {
        scope: record.scope.clone(),
        authority: record.authority.clone(),
        sequence: record.sequence,
        release: record.release.release.clone(),
    };
    let key = owner.root_key()?;
    let scope = protected::scope_key(&record.scope)?;
    if body.len() <= 262_144 {
        return Ok(vec![(key, scope, body)]);
    }
    let (root, chunks) = ChunkedBody::capture(owner, &body)?;
    let payload = protected::encode(&JournalRoot {
        knowledge_join_encoding: JournalChunkMarker::ChunkedLabelAtomsV1,
        authority: record.authority.clone(),
        sequence: record.sequence,
        scope: record.scope.clone(),
        release: ReleaseIdentity {
            release: record.release.release.clone(),
        },
        body: root,
    })?;
    let mut rows = Vec::with_capacity(chunks.len() + 1);
    rows.push((key, scope, payload));
    rows.extend(chunks.into_iter().map(|chunk| {
        (
            chunk.key().into(),
            chunk.scope().into(),
            chunk.payload().to_vec(),
        )
    }));
    Ok(rows)
}
fn invalid() -> AdmissionOperationStoreError {
    invariant("knowledge journal atom source is invalid")
}
