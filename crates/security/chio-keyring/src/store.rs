use chio_core_types::Hash;
use serde::{Deserialize, Serialize};

use crate::{EventId, KeyId, SignedKeyLogCheckpoint};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningTopology {
    LocalSingleWriter,
    MultiWorker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStage {
    Pending,
    Witnessed,
    Activated,
}

impl CheckpointStage {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Witnessed => "witnessed",
            Self::Activated => "activated",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "witnessed" => Some(Self::Witnessed),
            "activated" => Some(Self::Activated),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCheckpoint {
    pub checkpoint: SignedKeyLogCheckpoint,
    pub stage: CheckpointStage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLogHead {
    pub active_key_id: KeyId,
    pub pending_key_id: Option<KeyId>,
    pub pending_event_id: Option<EventId>,
    pub signing_epoch: u64,
    pub last_sequence: u64,
    pub last_event_hash: Hash,
    pub tree_size: u64,
    pub root_hash: Hash,
}
