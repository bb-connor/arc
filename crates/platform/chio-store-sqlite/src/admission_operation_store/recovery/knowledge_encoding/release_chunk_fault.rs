//! One armed actual release outcome write can withhold or alter its last
//! immutable chunk. This child and its store controls exist only with
//! admission-test-support enabled; production triggers stay unchanged.
use super::*;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

const MAX_FIXTURES: usize = 16;

#[derive(Clone, Copy)]
enum ReleaseChunkFault {
    Missing,
    Corrupt,
}

static FIXTURES: OnceLock<Mutex<BTreeMap<String, ReleaseChunkFault>>> = OnceLock::new();

/// Disarms its one release chunk fault when dropped.
pub struct KnowledgeReleaseChunkFaultGuard {
    record_key: String,
}

impl Drop for KnowledgeReleaseChunkFaultGuard {
    fn drop(&mut self) {
        if let Some(fixtures) = FIXTURES.get() {
            if let Ok(mut fixtures) = fixtures.lock() {
                fixtures.remove(&self.record_key);
            }
        }
    }
}

impl SqliteAdmissionOperationStore {
    /// The next encoded outcome of this exact release key persists its root and
    /// every chunk except the last.
    pub fn inject_missing_release_chunk_fixture(
        &self,
        scope: &RecoveryScopeV1,
        record_key: &str,
    ) -> Result<KnowledgeReleaseChunkFaultGuard, AdmissionOperationStoreError> {
        self.arm_release_chunk_fault(scope, record_key, ReleaseChunkFault::Missing)
    }

    /// The next encoded outcome of this exact release key persists its last
    /// chunk with one changed data nibble, still canonical and guard-valid.
    pub fn inject_corrupt_release_chunk_fixture(
        &self,
        scope: &RecoveryScopeV1,
        record_key: &str,
    ) -> Result<KnowledgeReleaseChunkFaultGuard, AdmissionOperationStoreError> {
        self.arm_release_chunk_fault(scope, record_key, ReleaseChunkFault::Corrupt)
    }

    fn arm_release_chunk_fault(
        &self,
        scope: &RecoveryScopeV1,
        record_key: &str,
        fault: ReleaseChunkFault,
    ) -> Result<KnowledgeReleaseChunkFaultGuard, AdmissionOperationStoreError> {
        if scope.authority_domain.as_str() != self.serving_owner.fence.store_uuid
            || record_key.len() > 512
            || !record_key.starts_with(&format!("knowledge-release:v2:{}:", scope_key(scope)?))
        {
            return Err(invariant("release chunk fault binding"));
        }
        let mut fixtures = FIXTURES
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .map_err(|_| invariant("release chunk fault poisoned"))?;
        if fixtures.len() >= MAX_FIXTURES || fixtures.contains_key(record_key) {
            return Err(invariant("release chunk fault already occupied"));
        }
        fixtures.insert(record_key.to_owned(), fault);
        Ok(KnowledgeReleaseChunkFaultGuard {
            record_key: record_key.to_owned(),
        })
    }
}

/// Called by the one encoded writer after every source, CAS, bound, band and
/// pristine-prefix check. Unarmed keys and non-release roots write nothing
/// here and return None.
pub(super) fn persist_armed_release_outcome<'tx, 'conn>(
    tx: &Transaction<'conn>,
    owner: &SqliteServingOwner,
    proof: &VerifiedKnowledgeEncodingWrite<'tx, 'conn>,
    next_version: u64,
) -> Result<Option<(ProtectedSourceReference, ProtectedMutationDelta)>, AdmissionOperationStoreError>
{
    if !proof.root_key().starts_with("knowledge-release:") || proof.staged_chunks().is_empty() {
        return Ok(None);
    }
    let Some(fixtures) = FIXTURES.get() else {
        return Ok(None);
    };
    let fault = {
        let mut fixtures = fixtures
            .lock()
            .map_err(|_| invariant("release chunk fault poisoned"))?;
        match fixtures.remove(proof.root_key()) {
            Some(fault) => fault,
            None => return Ok(None),
        }
    };
    let last = proof.staged_chunks().len() - 1;
    let mut mutations = 1_u64;
    let mut bytes = u64::try_from(proof.root_payload().len())
        .map_err(|_| invariant("release chunk fault byte count"))?;
    for (ordinal, chunk) in proof.staged_chunks().iter().enumerate() {
        let payload = match (ordinal == last, fault) {
            (true, ReleaseChunkFault::Missing) => continue,
            (true, ReleaseChunkFault::Corrupt) => corrupt(chunk.payload())?,
            (false, _) => chunk.payload().to_vec(),
        };
        persist_record(
            tx,
            owner,
            chunk.key(),
            chunk.scope(),
            "command",
            &payload,
            None,
        )?;
        let row = raw_checked(tx, chunk.key())?
            .ok_or_else(|| invariant("release chunk fault lost its retained chunk"))?;
        if row.payload != payload {
            return Err(invariant("release chunk fault changed its retained bytes"));
        }
        mutations = mutations
            .checked_add(1)
            .ok_or_else(|| invariant("release chunk fault write count"))?;
        bytes = bytes
            .checked_add(
                u64::try_from(payload.len())
                    .map_err(|_| invariant("release chunk fault byte count"))?,
            )
            .ok_or_else(|| invariant("release chunk fault byte count"))?;
    }
    persist_record(
        tx,
        owner,
        proof.root_key(),
        proof.scope_key(),
        "command",
        proof.root_payload(),
        None,
    )?;
    let source = source_reference(tx, proof.root_key())?;
    if source.version() != next_version || source.scope_key() != proof.scope_key() {
        return Err(invariant("release chunk fault changed its root frame"));
    }
    require_encoding_header(tx, proof.root_key())?;
    Ok(Some((
        source,
        ProtectedMutationDelta {
            mutations,
            encoded_bytes: bytes,
        },
    )))
}

/// The same canonical chunk with its first data nibble changed.
fn corrupt(payload: &[u8]) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    let mut chunk: serde_json::Value = decode(payload)?;
    let data = chunk
        .get("data")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invariant("release chunk fault lost its data"))?
        .to_owned();
    let mut altered = data.into_bytes();
    let first = altered
        .first_mut()
        .ok_or_else(|| invariant("release chunk fault lost its data"))?;
    *first = if *first == b'0' { b'1' } else { b'0' };
    chunk["data"] = serde_json::Value::String(
        String::from_utf8(altered).map_err(|_| invariant("release chunk fault data"))?,
    );
    encode(&chunk)
}
