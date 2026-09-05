use chio_core_types::capability::token::CapabilityToken;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
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
}

impl ProcessLimits {
    pub(crate) fn validate(self) -> Result<(), ProcessError> {
        if self.max_processes == 0 || self.max_depth > 64 || self.max_calls == 0 {
            return Err(ProcessError::Invalid(
                "process and call ceilings must be positive; max depth must be at most 64",
            ));
        }
        Ok(())
    }
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
