use serde::{Deserialize, Serialize};

use super::BranchError;

pub const BRANCH_RECORD_SCHEMA: &str = "chio.computer.branch-record.v1";
pub const PUBLICATION_RECORD_SCHEMA: &str = "chio.computer.publication-record.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchState {
    /// Writers holding the current generation may stage.
    Open,
    /// Writers are fenced and the output tree is bound.
    Frozen,
    /// The output tree and its producer reference are retained.
    Sealed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PublicationState {
    /// Recorded before the project ref moves.
    Intent,
    /// The project ref moved to the output tree.
    Published,
    /// The project ref no longer equaled the expected base.
    Conflict { actual: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BranchRecord {
    pub schema: String,
    pub branch_id: String,
    pub project_id: String,
    pub base_tree: String,
    pub generation: u64,
    pub state: BranchState,
    pub output_tree: Option<String>,
    pub producer: Option<String>,
}

impl BranchRecord {
    pub(super) fn open(branch_id: &str, project_id: &str, base_tree: &str) -> Self {
        Self {
            schema: BRANCH_RECORD_SCHEMA.to_owned(),
            branch_id: branch_id.to_owned(),
            project_id: project_id.to_owned(),
            base_tree: base_tree.to_owned(),
            generation: 0,
            state: BranchState::Open,
            output_tree: None,
            producer: None,
        }
    }

    pub(super) fn frozen(&self, output_tree: &str) -> Result<Self, BranchError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(BranchError::BoundExceeded("generation"))?;
        Ok(Self {
            generation,
            state: BranchState::Frozen,
            output_tree: Some(output_tree.to_owned()),
            ..self.clone()
        })
    }

    pub(super) fn sealed(&self, producer: &str) -> Self {
        Self {
            state: BranchState::Sealed,
            producer: Some(producer.to_owned()),
            ..self.clone()
        }
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, BranchError> {
        chio_core_types::canonical::canonical_json_bytes(self)
            .map_err(|_| BranchError::CorruptRecord(self.branch_id.clone()))
    }

    pub(super) fn decode(bytes: &[u8], branch_id: &str) -> Result<Self, BranchError> {
        let corrupt = || BranchError::CorruptRecord(branch_id.to_owned());
        let record: Self = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
        let canonical =
            chio_core_types::canonical::canonical_json_bytes(&record).map_err(|_| corrupt())?;
        if canonical != bytes {
            return Err(corrupt());
        }
        let consistent = record.schema == BRANCH_RECORD_SCHEMA
            && record.branch_id == branch_id
            && match record.state {
                BranchState::Open => record.output_tree.is_none() && record.producer.is_none(),
                BranchState::Frozen => record.output_tree.is_some() && record.producer.is_none(),
                BranchState::Sealed => record.output_tree.is_some() && record.producer.is_some(),
            };
        if consistent {
            Ok(record)
        } else {
            Err(corrupt())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PublicationRecord {
    pub schema: String,
    pub publication_id: String,
    pub branch_id: String,
    pub project_id: String,
    pub expected_base: String,
    pub output_tree: String,
    pub state: PublicationState,
}

impl PublicationRecord {
    pub(super) fn intent(
        publication_id: &str,
        branch_id: &str,
        project_id: &str,
        expected_base: &str,
        output_tree: &str,
    ) -> Self {
        Self {
            schema: PUBLICATION_RECORD_SCHEMA.to_owned(),
            publication_id: publication_id.to_owned(),
            branch_id: branch_id.to_owned(),
            project_id: project_id.to_owned(),
            expected_base: expected_base.to_owned(),
            output_tree: output_tree.to_owned(),
            state: PublicationState::Intent,
        }
    }

    pub(super) fn published(&self) -> Self {
        Self {
            state: PublicationState::Published,
            ..self.clone()
        }
    }

    pub(super) fn conflict(&self, actual: &str) -> Self {
        Self {
            state: PublicationState::Conflict {
                actual: actual.to_owned(),
            },
            ..self.clone()
        }
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, BranchError> {
        chio_core_types::canonical::canonical_json_bytes(self)
            .map_err(|_| BranchError::CorruptRecord(self.publication_id.clone()))
    }

    pub(super) fn decode(bytes: &[u8], branch_id: &str) -> Result<Self, BranchError> {
        let corrupt = || BranchError::CorruptRecord(branch_id.to_owned());
        let record: Self = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
        let canonical =
            chio_core_types::canonical::canonical_json_bytes(&record).map_err(|_| corrupt())?;
        if canonical != bytes {
            return Err(corrupt());
        }
        if record.schema != PUBLICATION_RECORD_SCHEMA || record.branch_id != branch_id {
            return Err(corrupt());
        }
        Ok(record)
    }
}
