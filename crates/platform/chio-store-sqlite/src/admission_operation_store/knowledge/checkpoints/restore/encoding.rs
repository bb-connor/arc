//! Closed private restore encoding preserves every original logical field.
//! Exact atom bodies reconstruct through authenticated immutable chunk roots.
use super::{validate_restore_identity, RestoreActorBinding, RestoreRecord};
use crate::admission_operation_store::knowledge::encoding::chunks::{
    AuthenticatedKnowledgeEncodingRoot, ChunkedBody, EncodingOwner,
};
use crate::admission_operation_store::knowledge::encoding::labels::{
    LabelIndex, LabelTable, LabelTableBuilder, StoredRecipient, StoredRelease,
    MAX_LOGICAL_LABEL_BYTES,
};
use crate::admission_operation_store::recovery::storage as protected;
use crate::admission_operation_store::{invariant, AdmissionOperationStoreError};
use chio_security_types::knowledge::*;
use chio_security_types::recovery::*;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

// This is the existing protected row ceiling, not a new allowance. A restore
// expands five precise fields from its one protocol-bounded label table.
const MAX_PRIVATE_ROW_BYTES: usize = 262_144;
const RESTORE_LABEL_REFERENCES: usize = 5;
const MAX_RESTORE_ATOM_BODY_BYTES: usize =
    MAX_PRIVATE_ROW_BYTES + MAX_LOGICAL_LABEL_BYTES * RESTORE_LABEL_REFERENCES;
const MAX_EXPANDED_RESTORE_BYTES: usize =
    MAX_RESTORE_ATOM_BODY_BYTES + MAX_LOGICAL_LABEL_BYTES * RESTORE_LABEL_REFERENCES;
const MAX_CHECKPOINT_ENVELOPE_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StoredRestoreRecord {
    Chunked(Box<ChunkedRestoreRecord>),
    Compact(Box<CompactRestoreRecord>),
    Legacy(Box<RestoreRecord>),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestoreEncoding {
    InternedLabelAtomsV1,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChunkedRestoreEncoding {
    ChunkedLabelAtomsV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkedRestoreIntent {
    release: ReleaseId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkedRestoreRecord {
    checkpoint_restore_encoding: ChunkedRestoreEncoding,
    scope: RecoveryScopeV1,
    intent: ChunkedRestoreIntent,
    body: ChunkedBody,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCheckpoint {
    domain_version: VersionV1,
    checkpoint: CheckpointId,
    revision: SafeInteger,
    scope: RecoveryScopeV1,
    runtime: ProtectedText<128>,
    artifacts: NonEmptyBoundedList<ArtifactVersionRefV1, 8>,
    model_contexts: BoundedList<ModelContextV1, 8>,
    label: LabelIndex,
    influence: ArtifactInfluenceV1,
    lineage: IsolationLineageId,
    isolation_epoch: ProtectedText<128>,
    native_evidence_sequence: SafeInteger,
    policy: PolicyDigest,
}

impl StoredCheckpoint {
    fn capture(
        checkpoint: &LabeledCheckpointV1,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        checkpoint.validate().map_err(|_| invalid())?;
        if protected::encode(checkpoint)?.len() > MAX_CHECKPOINT_ENVELOPE_BYTES {
            return Err(invalid());
        }
        Ok(Self {
            domain_version: checkpoint.domain_version,
            checkpoint: checkpoint.checkpoint.clone(),
            revision: checkpoint.revision,
            scope: checkpoint.scope.clone(),
            runtime: checkpoint.runtime.clone(),
            artifacts: checkpoint.artifacts.clone(),
            model_contexts: checkpoint.model_contexts.clone(),
            label: labels.insert(&checkpoint.label)?,
            influence: checkpoint.influence.clone(),
            lineage: checkpoint.lineage.clone(),
            isolation_epoch: checkpoint.isolation_epoch.clone(),
            native_evidence_sequence: checkpoint.native_evidence_sequence,
            policy: checkpoint.policy,
        })
    }

    fn expand(
        &self,
        labels: &LabelTable,
    ) -> Result<LabeledCheckpointV1, AdmissionOperationStoreError> {
        let checkpoint = LabeledCheckpointV1 {
            domain_version: self.domain_version,
            checkpoint: self.checkpoint.clone(),
            revision: self.revision,
            scope: self.scope.clone(),
            runtime: self.runtime.clone(),
            artifacts: self.artifacts.clone(),
            model_contexts: self.model_contexts.clone(),
            label: labels.label(self.label)?.clone(),
            influence: self.influence.clone(),
            lineage: self.lineage.clone(),
            isolation_epoch: self.isolation_epoch.clone(),
            native_evidence_sequence: self.native_evidence_sequence,
            policy: self.policy,
        };
        checkpoint.validate().map_err(|_| invalid())?;
        if protected::encode(&checkpoint)?.len() > MAX_CHECKPOINT_ENVELOPE_BYTES {
            return Err(invalid());
        }
        Ok(checkpoint)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompactRestoreRecord {
    checkpoint_restore_encoding: RestoreEncoding,
    checkpoint: StoredCheckpoint,
    recipient: StoredRecipient,
    intent: StoredRelease,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_binding: Option<RestoreActorBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installation_generation: Option<SafeInteger>,
    labels: LabelTable,
}

impl CompactRestoreRecord {
    fn capture(record: &RestoreRecord) -> Result<Self, AdmissionOperationStoreError> {
        validate_record(record)?;
        let mut labels = LabelTableBuilder::new();
        // The first occurrence order is fixed by the actual logical restore.
        let checkpoint = StoredCheckpoint::capture(&record.checkpoint, &mut labels)?;
        let recipient = StoredRecipient::capture(&record.recipient, &mut labels)?;
        let intent = StoredRelease::capture(&record.intent, &mut labels)?;
        let stored = Self {
            checkpoint_restore_encoding: RestoreEncoding::InternedLabelAtomsV1,
            checkpoint,
            recipient,
            intent,
            actor_binding: record.actor_binding.clone(),
            installation_generation: record.installation_generation,
            labels: labels.finish()?,
        };
        // A full typed body may span immutable rows. It stays bounded by
        // the fixed Restore schema; each persisted row retains its ceiling.
        if canonical(&stored)?.len() > MAX_RESTORE_ATOM_BODY_BYTES {
            return Err(invalid());
        }
        let reconstructed = stored.expand_unchecked()?;
        if canonical(&reconstructed)? != canonical(record)? {
            return Err(invalid());
        }
        Ok(stored)
    }

    fn preflight_expansion(&self) -> Result<(), AdmissionOperationStoreError> {
        let release = self.intent.label_references();
        let references = [
            self.checkpoint.label,
            self.recipient.label_reference(),
            release[0],
            release[1],
            release[2],
        ];
        // Every palette value must occur in the exact capture order. This
        // check precedes any expanded owner map, including unused values.
        self.labels.validate_references(&references)?;
        let wire_bytes = canonical(self)?.len();
        if wire_bytes > MAX_RESTORE_ATOM_BODY_BYTES {
            return Err(invalid());
        }
        let expanded_bound = self
            .labels
            .expansion_budget(RESTORE_LABEL_REFERENCES, wire_bytes)?;
        if expanded_bound > MAX_EXPANDED_RESTORE_BYTES {
            return Err(invalid());
        }
        Ok(())
    }

    fn expand_unchecked(&self) -> Result<RestoreRecord, AdmissionOperationStoreError> {
        // Bounds are checked before cloning any referenced labels. The
        // maximum is derived from five closed references and a capped wire.
        self.preflight_expansion()?;
        let record = RestoreRecord {
            checkpoint: self.checkpoint.expand(&self.labels)?,
            recipient: self.recipient.expand(&self.labels)?,
            intent: self.intent.expand(&self.labels)?,
            actor_binding: self.actor_binding.clone(),
            installation_generation: self.installation_generation,
        };
        validate_record(&record)?;
        if canonical(&record)?.len() > MAX_EXPANDED_RESTORE_BYTES {
            return Err(invalid());
        }
        Ok(record)
    }

    fn expand(&self) -> Result<RestoreRecord, AdmissionOperationStoreError> {
        let record = self.expand_unchecked()?;
        // A compact record is admissible only when the unchanged legacy wire
        // cannot fit. Delivery outcomes cannot shrink an admitted restore.
        if canonical(&record)?.len() <= MAX_PRIVATE_ROW_BYTES {
            return Err(invalid());
        }
        let repeated = Self::capture(&record)?;
        // Exact canonical recapture rejects unused/reordered palette values
        // and out-of-range indices; no second private representation is
        // accepted for the same authenticated logical restore.
        if canonical(&repeated)? != canonical(self)? {
            return Err(invalid());
        }
        Ok(record)
    }
}

/// Source-private write verification uses this exact body. The shared affine
/// plan frames it into bounded immutable rows only when it cannot fit inline.
/// Small Legacy records retain their original canonical byte preimages.
pub(super) fn logical_body(
    record: &RestoreRecord,
) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    validate_record(record)?;
    let original = canonical(record)?;
    if original.len() <= MAX_PRIVATE_ROW_BYTES {
        return Ok(original);
    }
    canonical(&CompactRestoreRecord::capture(record)?)
}

/// Exact protected framing supplies key/version/custody. Chunk resolution
/// authenticates that same owner and original root ordinal before expansion.
/// No data decoder grants delivery or replaces current native authority.
pub(super) fn decode(
    connection: &rusqlite::Connection,
    key: &str,
    version: u64,
    bytes: &[u8],
) -> Result<RestoreRecord, AdmissionOperationStoreError> {
    let stored: StoredRestoreRecord = protected::decode(bytes)?;
    match stored {
        StoredRestoreRecord::Legacy(record) => {
            validate_record(&record)?;
            Ok(*record)
        }
        StoredRestoreRecord::Compact(record) => {
            require_restore_format(connection)?;
            record.expand()
        }
        StoredRestoreRecord::Chunked(chunked) => {
            require_restore_format(connection)?;
            let owner = chunked.body.owner();
            let EncodingOwner::Restore {
                scope,
                record_key,
                release,
            } = owner
            else {
                return Err(invalid());
            };
            if record_key != key || chunked.scope != *scope || chunked.intent.release != *release {
                return Err(invalid());
            }
            let root = AuthenticatedKnowledgeEncodingRoot::authenticate(
                connection, key, version, bytes, owner,
            )?;
            let body = chunked.body.load(connection, &root)?;
            if body.len() <= MAX_PRIVATE_ROW_BYTES || body.len() > MAX_RESTORE_ATOM_BODY_BYTES {
                return Err(invalid());
            }
            let compact: CompactRestoreRecord =
                serde_json::from_slice(&body).map_err(|_| invalid())?;
            if canonical(&compact)? != body {
                return Err(invalid());
            }
            let record = compact.expand()?;
            if record.checkpoint.scope != *scope || record.intent.release != *release {
                return Err(invalid());
            }
            Ok(record)
        }
    }
}

pub(super) fn require_restore_format(
    connection: &rusqlite::Connection,
) -> Result<(), AdmissionOperationStoreError> {
    use crate::admission_operation_store::{
        ADMISSION_OPERATION_SCHEMA_ANCHORS, ADMISSION_OPERATION_SCHEMA_KEY,
    };
    let observed = crate::check_schema_version(
        connection,
        ADMISSION_OPERATION_SCHEMA_KEY,
        40,
        ADMISSION_OPERATION_SCHEMA_ANCHORS,
    )
    .map_err(|_| invalid())?;
    if observed != 40 {
        return Err(invalid());
    }
    Ok(())
}

fn validate_record(record: &RestoreRecord) -> Result<(), AdmissionOperationStoreError> {
    let ArtifactReleaseKindV1::IndependentlyAdmitted { request } = &record.intent.kind else {
        return Err(invalid());
    };
    validate_restore_identity(record, &record.checkpoint.scope, request)
}

pub(super) fn canonical(value: &impl Serialize) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    chio_core::canonical_json_bytes(value).map_err(|_| invalid())
}

fn invalid() -> AdmissionOperationStoreError {
    invariant("checkpoint restore encoding is invalid")
}
