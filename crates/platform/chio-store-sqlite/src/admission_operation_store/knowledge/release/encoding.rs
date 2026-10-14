//! A release outcome row is either the exact inline record or a bounded root
//! over the complete canonical record in immutable encoding chunks.
use super::*;
use crate::admission_operation_store::knowledge::encoding::chunks::{
    AuthenticatedKnowledgeEncodingRoot, ChunkedBody, EncodingOwner,
};

/// Disjoint strict forms: a chunked root never decodes as an inline record.
#[derive(Deserialize)]
#[serde(untagged)]
enum StoredReleaseRecord {
    Chunked(Box<ChunkedReleaseRecord>),
    Inline(Box<ReleaseRecord>),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChunkedReleaseEncoding {
    ChunkedReleaseRecordV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkedReleaseIdentity {
    release: ReleaseId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkedReleaseRecord {
    knowledge_release_encoding: ChunkedReleaseEncoding,
    scope: RecoveryScopeV1,
    release: ChunkedReleaseIdentity,
    original_version: SafeInteger,
    body: ChunkedBody,
}

/// Borrowed serializer of the same chunked root, used only by the one encoded
/// writer. Reads require the stored root to equal its canonical form above.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ChunkedReleaseRoot<'a> {
    knowledge_release_encoding: ChunkedReleaseEncoding,
    scope: &'a RecoveryScopeV1,
    release: ChunkedReleaseIdentity,
    original_version: SafeInteger,
    body: &'a ChunkedBody,
}

/// The bounded root row over a chunked release body.
pub(in crate::admission_operation_store) fn chunked_release_root(
    owner: &EncodingOwner,
    original_version: u64,
    body: &ChunkedBody,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    let EncodingOwner::Release { scope, release, .. } = owner else {
        return Err(refused("release root selected another encoding owner"));
    };
    if body.owner() != owner || original_version != ORIGINAL_RELEASE_VERSION {
        return Err(refused("release root changed its exact owner"));
    }
    protected::encode(&ChunkedReleaseRoot {
        knowledge_release_encoding: ChunkedReleaseEncoding::ChunkedReleaseRecordV1,
        scope,
        release: ChunkedReleaseIdentity {
            release: release.clone(),
        },
        original_version: SafeInteger::new(original_version).map_err(refused)?,
        body,
    })
}

/// The original admission is always the first version of its release key.
pub(super) const ORIGINAL_RELEASE_VERSION: u64 = 1;

/// Decode one authenticated release row at its exact version. A chunked root
/// is authenticated against its own historical framing, its owner must be this
/// exact release key, and the complete body must be canonical record bytes.
pub(super) fn decode_release(
    tx: &Connection,
    key: &str,
    version: u64,
    payload: &[u8],
) -> Result<ReleaseRecord, AdmissionOperationStoreError> {
    let stored: StoredReleaseRecord =
        serde_json::from_slice(payload).map_err(|_| refused("release row is corrupt"))?;
    let record = match stored {
        StoredReleaseRecord::Inline(record) => {
            if canonical(&*record)? != payload {
                return Err(refused("release row is not exact canonical data"));
            }
            *record
        }
        StoredReleaseRecord::Chunked(chunked) => {
            if canonical(&*chunked)? != payload
                || chunked.original_version.get() != ORIGINAL_RELEASE_VERSION
            {
                return Err(refused("release root is not exact canonical data"));
            }
            let EncodingOwner::Release {
                scope,
                record_key,
                release,
            } = chunked.body.owner()
            else {
                return Err(refused("release root selected another encoding owner"));
            };
            if record_key != key || *scope != chunked.scope || *release != chunked.release.release {
                return Err(refused("release root changed its exact owner"));
            }
            let root = AuthenticatedKnowledgeEncodingRoot::authenticate(
                tx,
                key,
                version,
                payload,
                chunked.body.owner(),
            )?;
            let body = chunked.body.load(tx, &root)?;
            let record: ReleaseRecord =
                serde_json::from_slice(&body).map_err(|_| refused("release body is corrupt"))?;
            if canonical(&record)? != body
                || record.intent.release != chunked.release.release
                || record.intent.artifact.scope != chunked.scope
            {
                return Err(refused("release body changed its exact record"));
            }
            record
        }
    };
    Ok(record)
}

/// Canonical bytes without the single-row ceiling; callers bound each form.
pub(super) fn canonical(value: &impl Serialize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    chio_core::canonical_json_bytes(value).map_err(|_| refused("release encoding refused"))
}
