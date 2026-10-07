//! Private journal wire representation preserves typed native join semantics.
use super::super::Record;
use crate::admission_operation_store::knowledge::encoding::labels::{
    LabelIndex, LabelTable, LabelTableBuilder, StoredRelease, MAX_LOGICAL_LABEL_BYTES,
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

#[path = "atom_rows.rs"]
mod rows;
use rows::{ExpansionBudget, StoredRowChange};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalEncoding {
    InternedLabelAtomsV1,
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
pub(super) struct AtomRecord {
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

impl AtomRecord {
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
            knowledge_join_encoding: JournalEncoding::InternedLabelAtomsV1,
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
        let release = self.release.label_references();
        let mut references = vec![
            release[0],
            release[1],
            release[2],
            self.request.principal_join,
            self.request.lineage_join,
            self.request.session_join,
            self.result.principal_label,
            self.result.lineage_label,
            self.result.session_label,
        ];
        let mut preflight = ExpansionBudget::default();
        for change in self.changes.as_slice() {
            change.preflight_labels(&self.labels, &mut references, &mut preflight)?;
        }
        self.labels.validate_references(&references)?;
        let maximum = self.labels.expansion_budget(
            EXPLICIT_LABEL_REFERENCES,
            MAX_EXPANDED_IMAGE_BYTES + 16 * MAX_PRIVATE_ROW_BYTES,
        )?;
        if maximum
            > MAX_LOGICAL_LABEL_BYTES * EXPLICIT_LABEL_REFERENCES
                + MAX_EXPANDED_IMAGE_BYTES
                + 16 * MAX_PRIVATE_ROW_BYTES
        {
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

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StoredBody {
    Atoms(Box<AtomRecord>),
    Legacy(Box<Record>),
}

pub(super) fn logical_body(record: &Record) -> Result<Vec<u8>, AdmissionOperationStoreError> {
    record.validate()?;
    let plain = chio_core::canonical_json_bytes(record).map_err(|_| invalid())?;
    if plain.len() <= MAX_PRIVATE_ROW_BYTES {
        return Ok(plain);
    }
    let atoms = AtomRecord::capture(record)?;
    let bytes = chio_core::canonical_json_bytes(&atoms).map_err(|_| invalid())?;
    if bytes.len()
        > crate::admission_operation_store::knowledge::encoding::chunks::MAX_ATOM_BODY_BYTES
    {
        return Err(invalid());
    }
    Ok(bytes)
}

pub(super) fn decode_body(bytes: &[u8]) -> Result<Record, AdmissionOperationStoreError> {
    if bytes.is_empty()
        || bytes.len()
            > crate::admission_operation_store::knowledge::encoding::chunks::MAX_ATOM_BODY_BYTES
    {
        return Err(invalid());
    }
    let body: StoredBody = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if chio_core::canonical_json_bytes(&body).map_err(|_| invalid())? != bytes {
        return Err(invalid());
    }
    match body {
        StoredBody::Atoms(atoms) => atoms.expand(),
        StoredBody::Legacy(record) => {
            if bytes.len() > MAX_PRIVATE_ROW_BYTES {
                return Err(invalid());
            }
            record.validate()?;
            Ok(*record)
        }
    }
}

fn invalid() -> AdmissionOperationStoreError {
    invariant("knowledge atom journal encoding is invalid")
}
