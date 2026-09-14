use chio_core_types::capability::token::CapabilityToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("worker authentication failed")]
    Unauthenticated,
    #[error("process runtime configuration: {0}")]
    Configuration(&'static str),
    #[error("invalid process operation: {0}")]
    Invalid(&'static str),
    #[error("process not found: {0}")]
    NotFound(String),
    #[error("process is cancelled: {0}")]
    Cancelled(String),
    #[error("process identity or operation binding conflicts with persisted state")]
    Conflict,
    #[error("process tree limit reached: {0}")]
    Limit(&'static str),
    #[error("checkpoint revision conflict")]
    CheckpointConflict,
    #[error("process state blob is not available to this process")]
    BlobMissing,
    #[error("process state blob integrity check failed")]
    BlobCorrupt,
    #[error("process store mutex is poisoned")]
    StorePoisoned,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Core(#[from] chio_core_types::Error),
    #[error(transparent)]
    Kernel(#[from] chio_kernel::KernelError),
}

/// Host-imposed ceilings shared across the entire root process tree.
/// A logical call consumes one slot even if denied or its outcome is unknown.
/// Kernel monetary and capability budgets remain independently enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessLimits {
    pub max_processes: u32,
    pub max_depth: u32,
    pub max_calls: u32,
    #[serde(default, skip_serializing_if = "ProcessStateLimits::is_default")]
    pub state: ProcessStateLimits,
}

impl ProcessLimits {
    pub(crate) fn validate(self) -> Result<(), ProcessError> {
        if self.max_processes == 0 || self.max_depth > 64 || self.max_calls == 0 {
            return Err(ProcessError::Invalid(
                "process and call ceilings must be positive; max depth must be at most 64",
            ));
        }
        self.state.validate()
    }
}

/// Immutable state belongs to a process and consumes its root tree's quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessStateLimits {
    pub max_bytes: u32,
    pub max_blobs: u32,
}

impl Default for ProcessStateLimits {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_blobs: 4096,
        }
    }
}

impl ProcessStateLimits {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    fn validate(self) -> Result<(), ProcessError> {
        if self.max_bytes == 0
            || self.max_bytes > 1024 * 1024 * 1024
            || self.max_blobs == 0
            || self.max_blobs > 16_384
        {
            return Err(ProcessError::Invalid(
                "state ceilings must be positive and at most 1 GiB and 16384 blobs",
            ));
        }
        Ok(())
    }
}

pub const MAX_STATE_BLOB_BYTES: usize = 1024 * 1024;
pub const STATE_BLOB_PROTOCOL: &str = "chio.process.blobs.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateBlobRef {
    pub sha256: String,
    pub bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStorage {
    pub protocol: String,
    pub max_blob_bytes: u32,
    pub limits: ProcessStateLimits,
    pub process_bytes: u64,
    pub process_blobs: u64,
    pub tree_bytes: u64,
    pub tree_blobs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    Running,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub revision: u64,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct ProcessSnapshot {
    pub id: String,
    pub parent_id: Option<String>,
    pub root_id: String,
    pub depth: u32,
    pub capability: CapabilityToken,
    pub state: ProcessState,
    pub limits: ProcessLimits,
    pub checkpoint: Checkpoint,
    pub tree_calls: u32,
}
