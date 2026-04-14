use arc_core::capability::CapabilityToken;
use arc_core::credit::CreditBondRow;
use arc_core::receipt::{ArcReceipt, ChildRequestReceipt};

use crate::capability_lineage::CapabilitySnapshot;
use crate::checkpoint::KernelCheckpoint;

/// Configuration for receipt retention and archival.
///
/// When set on `KernelConfig`, the kernel can archive aged-out or oversized
/// receipt databases to a separate read-only SQLite file while keeping archived
/// receipts verifiable against their Merkle checkpoint roots.
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// Number of days to retain receipts in the live database. Default: 90.
    pub retention_days: u64,
    /// Maximum size in bytes before the live database is rotated. Default: 10 GB.
    pub max_size_bytes: u64,
    /// Path for the archive SQLite file. Must be writable on first rotation.
    pub archive_path: String,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            retention_days: 90,
            max_size_bytes: 10_737_418_240,
            archive_path: "receipts-archive.sqlite3".to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReceiptStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("sqlite pool error: {0}")]
    Pool(String),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("failed to prepare receipt store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto decode error: {0}")]
    CryptoDecode(String),

    #[error("canonical json error: {0}")]
    Canonical(String),

    #[error("invalid outcome filter: {0}")]
    InvalidOutcome(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("not found: {0}")]
    NotFound(String),
}

pub trait ReceiptStore: Send {
    fn append_arc_receipt(&mut self, receipt: &ArcReceipt) -> Result<(), ReceiptStoreError>;
    fn append_arc_receipt_returning_seq(
        &mut self,
        receipt: &ArcReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        self.append_arc_receipt(receipt)?;
        Ok(None)
    }
    fn append_child_receipt(
        &mut self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError>;

    fn receipts_canonical_bytes_range(
        &self,
        _start_seq: u64,
        _end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        Ok(Vec::new())
    }

    fn store_checkpoint(
        &mut self,
        _checkpoint: &KernelCheckpoint,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        false
    }

    fn record_capability_snapshot(
        &mut self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn resolve_credit_bond(
        &self,
        _bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        Ok(None)
    }

    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct StoredToolReceipt {
    pub seq: u64,
    pub receipt: ArcReceipt,
}

#[derive(Debug, Clone)]
pub struct StoredChildReceipt {
    pub seq: u64,
    pub receipt: ChildRequestReceipt,
}

#[derive(Debug, Clone)]
pub struct FederatedEvidenceShareImport {
    pub share_id: String,
    pub manifest_hash: String,
    pub exported_at: u64,
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: String,
    pub require_proofs: bool,
    pub query_json: String,
    pub tool_receipts: Vec<StoredToolReceipt>,
    pub capability_lineage: Vec<CapabilitySnapshot>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FederatedEvidenceShareSummary {
    pub share_id: String,
    pub manifest_hash: String,
    pub imported_at: u64,
    pub exported_at: u64,
    pub issuer: String,
    pub partner: String,
    pub signer_public_key: String,
    pub require_proofs: bool,
    pub tool_receipts: u64,
    pub capability_lineage: u64,
}
