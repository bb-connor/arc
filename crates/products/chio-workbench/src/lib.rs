//! Local application layer for kernel-mediated delegated coding tasks.
#![forbid(unsafe_code)]
#![cfg(unix)]

mod engine;
mod kernel;
mod model;
pub mod provider;
mod store;
mod tools;
pub mod web;

pub use engine::{Workbench, WorkbenchConfig};
pub use model::{Action, Role, Run, RunStatus, TaskStatus};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("another task is already running")]
    Busy,
    #[error("run not found")]
    NotFound,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Kernel(#[from] chio_kernel::KernelError),
    #[error("state lock unavailable")]
    Lock,
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
