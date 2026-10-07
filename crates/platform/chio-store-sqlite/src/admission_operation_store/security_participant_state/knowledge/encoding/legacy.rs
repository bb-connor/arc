//! Private journal wire representation preserves typed native join semantics.
use super::super::Record;
use crate::admission_operation_store::knowledge::encoding::legacy_labels::{
    LabelIndex, LabelTable, LabelTableBuilder, StoredRelease,
};
use crate::admission_operation_store::{invariant, AdmissionOperationStoreError};
use chio_security_types::ports::{
    BoundedVec, FlowJoinRequest, FlowStateKey, FlowStateSnapshot, RecordId,
};
use chio_security_types::recovery::RecoveryScopeV1;
use serde::{Deserialize, Serialize};

const MAX_PRIVATE_ROW_BYTES: usize = 262_144;
const EXPLICIT_LABEL_REFERENCES: usize = 9;
const MAX_EXPANDED_IMAGE_BYTES: usize = 8 * 1024 * 1024;

#[path = "legacy_rows.rs"]
mod rows;
use rows::{ExpansionBudget, StoredRowChange};

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StoredRecord {
    Compact(Box<CompactRecord>),
    Legacy(Box<Record>),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalEncoding {
    InternedLabelsV1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRequest {
    key: FlowStateKey,
    principal_join: LabelIndex,
    lineage_join: LabelIndex,
    session_join: LabelIndex,
    transition_id: RecordId,
}

impl StoredRequest {
    fn capture(
        value: &FlowJoinRequest,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            key: value.key.clone(),
            principal_join: labels.insert(&value.principal_join)?,
            lineage_join: labels.insert(&value.lineage_join)?,
            session_join: labels.insert(&value.session_join)?,
            transition_id: value.transition_id.clone(),
        })
    }

    fn expand(&self, labels: &LabelTable) -> Result<FlowJoinRequest, AdmissionOperationStoreError> {
        Ok(FlowJoinRequest {
            key: self.key.clone(),
            principal_join: labels.label(self.principal_join)?.clone(),
            lineage_join: labels.label(self.lineage_join)?.clone(),
            session_join: labels.label(self.session_join)?.clone(),
            transition_id: self.transition_id.clone(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSnapshot {
    key: FlowStateKey,
    principal_label: LabelIndex,
    lineage_label: LabelIndex,
    session_label: LabelIndex,
    context_generation: u64,
}

impl StoredSnapshot {
    fn capture(
        value: &FlowStateSnapshot,
        labels: &mut LabelTableBuilder,
    ) -> Result<Self, AdmissionOperationStoreError> {
        Ok(Self {
            key: value.key.clone(),
            principal_label: labels.insert(&value.principal_label)?,
            lineage_label: labels.insert(&value.lineage_label)?,
            session_label: labels.insert(&value.session_label)?,
            context_generation: value.context_generation,
        })
    }

    fn expand(
        &self,
        labels: &LabelTable,
    ) -> Result<FlowStateSnapshot, AdmissionOperationStoreError> {
        Ok(FlowStateSnapshot {
            key: self.key.clone(),
            principal_label: labels.label(self.principal_label)?.clone(),
            lineage_label: labels.label(self.lineage_label)?.clone(),
            session_label: labels.label(self.session_label)?.clone(),
            context_generation: self.context_generation,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompactRecord {
    knowledge_join_encoding: JournalEncoding,
    authority: String,
    initialization: String,
    sequence: u64,
    previous: String,
    observed_at: u64,
    scope: RecoveryScopeV1,
    release: StoredRelease,
    request: StoredRequest,
    result: StoredSnapshot,
    changes: BoundedVec<StoredRowChange, 4096>,
    current_rows: u64,
    current_bytes: u64,
    labels: LabelTable,
}

impl CompactRecord {
    fn capture(record: &Record) -> Result<Self, AdmissionOperationStoreError> {
        record.validate()?;
        let mut labels = LabelTableBuilder::new();
        let release = StoredRelease::capture(&record.release, &mut labels)?;
        let request = StoredRequest::capture(&record.request, &mut labels)?;
        let result = StoredSnapshot::capture(&record.result, &mut labels)?;
        let changes = record
            .changes
            .as_slice()
            .iter()
            .map(|change| StoredRowChange::capture(change, &mut labels))
            .collect::<Result<Vec<_>, _>>()?;
        let stored = Self {
            knowledge_join_encoding: JournalEncoding::InternedLabelsV1,
            authority: record.authority.clone(),
            initialization: record.initialization.clone(),
            sequence: record.sequence,
            previous: record.previous.clone(),
            observed_at: record.observed_at,
            scope: record.scope.clone(),
            release,
            request,
            result,
            changes: BoundedVec::new(changes).map_err(|_| invalid())?,
            current_rows: record.current_rows,
            current_bytes: record.current_bytes,
            labels: labels.finish()?,
        };
        // Reconstruct through the compiled row codec before saving. A new
        // encoding never weakens the existing label, row or identity checks.
        let reconstructed = stored.expand_unchecked()?;
        if chio_core::canonical_json_bytes(&reconstructed).map_err(|_| invalid())?
            != chio_core::canonical_json_bytes(record).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        Ok(stored)
    }

    fn expand_unchecked(&self) -> Result<Record, AdmissionOperationStoreError> {
        self.labels.validate()?;
        // Inspect original palette bytes before cloning any repeated label.
        // Row expansion separately enforces the native eight-MiB capture bound.
        let largest = self.labels.maximum_label_bytes()?;
        let maximum = largest
            .checked_mul(EXPLICIT_LABEL_REFERENCES)
            .and_then(|bytes| bytes.checked_add(MAX_EXPANDED_IMAGE_BYTES))
            .ok_or_else(invalid)?;
        if maximum > MAX_PRIVATE_ROW_BYTES * EXPLICIT_LABEL_REFERENCES + MAX_EXPANDED_IMAGE_BYTES {
            return Err(invalid());
        }
        let mut budget = ExpansionBudget::default();
        let changes = self
            .changes
            .as_slice()
            .iter()
            .map(|change| change.expand(&self.labels, &mut budget))
            .collect::<Result<Vec<_>, _>>()?;
        let record = Record {
            authority: self.authority.clone(),
            initialization: self.initialization.clone(),
            sequence: self.sequence,
            previous: self.previous.clone(),
            observed_at: self.observed_at,
            scope: self.scope.clone(),
            release: self.release.expand(&self.labels)?,
            request: self.request.expand(&self.labels)?,
            result: self.result.expand(&self.labels)?,
            changes: BoundedVec::new(changes).map_err(|_| invalid())?,
            current_rows: self.current_rows,
            current_bytes: self.current_bytes,
        };
        record.validate()?;
        Ok(record)
    }

    fn expand(&self) -> Result<Record, AdmissionOperationStoreError> {
        let record = self.expand_unchecked()?;
        if chio_core::canonical_json_bytes(&record)
            .map_err(|_| invalid())?
            .len()
            <= MAX_PRIVATE_ROW_BYTES
        {
            // The owning encoder selects the exact legacy body whenever it
            // fits. Accept only that one lawful representation for small rows.
            return Err(invalid());
        }
        // The first-occurrence palette order is canonical. Reject unused,
        // reordered or aliased label entries rather than accepting several
        // authenticated wire meanings for the same logical native record.
        let repeated = Self::capture(&record)?;
        if chio_core::canonical_json_bytes(&repeated).map_err(|_| invalid())?
            != chio_core::canonical_json_bytes(self).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        Ok(record)
    }
}

/// This function reconstructs data. The owning loader must additionally verify
/// the protected row's scope/kind/version, native authority and sequence before
/// exposing either this record or the digest of its exact immutable payload.
pub(super) fn decode(
    tx: &rusqlite::Connection,
    bytes: &[u8],
) -> Result<Record, AdmissionOperationStoreError> {
    use crate::admission_operation_store::recovery::storage;
    let stored: StoredRecord = storage::decode(bytes)?;
    match stored {
        StoredRecord::Legacy(record) => {
            record.validate()?;
            Ok(*record)
        }
        StoredRecord::Compact(record) => {
            require_compact_format(tx)?;
            record.expand()
        }
    }
}

fn require_compact_format(tx: &rusqlite::Connection) -> Result<(), AdmissionOperationStoreError> {
    use crate::admission_operation_store::{
        ADMISSION_OPERATION_SCHEMA_ANCHORS, ADMISSION_OPERATION_SCHEMA_KEY,
    };
    let observed = crate::check_schema_version(
        tx,
        ADMISSION_OPERATION_SCHEMA_KEY,
        40,
        ADMISSION_OPERATION_SCHEMA_ANCHORS,
    )
    .map_err(|_| invalid())?;
    if observed != 39 && observed != 40 {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> AdmissionOperationStoreError {
    invariant("knowledge journal encoding is invalid")
}
