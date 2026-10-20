//! Capability lineage index for Chio kernel.
//!
//! This module provides persistence and query functions for capability snapshots.
//! Snapshots are recorded at issuance time and co-located with the receipt database
//! for efficient JOINs. The delegation chain can be walked via WITH RECURSIVE CTE.

use serde::{Deserialize, Serialize};

use chio_core::receipt::evidence::{CapabilitySnapshot, CapabilitySnapshotError};

use crate::receipt_store::ReceiptStoreError;

impl From<CapabilitySnapshotError> for ReceiptStoreError {
    fn from(error: CapabilitySnapshotError) -> Self {
        match error {
            CapabilitySnapshotError::Conflict(reason) => Self::Conflict(reason),
            CapabilitySnapshotError::UntrustedInput(error) => Self::from(error),
            CapabilitySnapshotError::Json(error) => Self::Json(error),
        }
    }
}

/// A capability snapshot with the source database sequence used for cluster sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCapabilitySnapshot {
    pub seq: u64,
    pub snapshot: CapabilitySnapshot,
}

/// Errors from capability lineage operations.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityLineageError {
    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
