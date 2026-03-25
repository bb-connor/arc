use pact_core::receipt::{ChildRequestReceipt, PactReceipt};
use serde::{Deserialize, Serialize};

use crate::capability_lineage::{CapabilityLineageError, CapabilitySnapshot};
use crate::checkpoint::{CheckpointError, KernelCheckpoint, ReceiptInclusionProof};
use crate::receipt_query::ReceiptQuery;
use crate::receipt_store::ReceiptStoreError;

/// Full-export query used for offline evidence packaging.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

/// Truthful coverage mode for child receipts in an export bundle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceChildReceiptScope {
    /// All child receipts matching the query window are included.
    FullQueryWindow,
    /// Child receipts are included only as time-window context because there is
    /// no capability/agent join path for them yet.
    TimeWindowContextOnly,
    /// Child receipts are omitted because the export was capability/agent scoped
    /// without a truthful join path or time-window fallback.
    OmittedNoJoinPath,
}

/// Tool receipt plus its stable store sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceToolReceiptRecord {
    pub seq: u64,
    pub receipt: PactReceipt,
}

/// Child receipt plus its stable store sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceChildReceiptRecord {
    pub seq: u64,
    pub receipt: ChildRequestReceipt,
}

/// Receipt that was exported but does not currently have checkpoint coverage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceUncheckpointedReceipt {
    pub seq: u64,
    pub receipt_id: String,
}

/// Live-database retention state captured at export time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRetentionMetadata {
    pub live_db_size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_live_receipt_timestamp: Option<u64>,
}

/// Complete evidence bundle assembled from a local SQLite store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceExportBundle {
    pub query: EvidenceExportQuery,
    pub tool_receipts: Vec<EvidenceToolReceiptRecord>,
    pub child_receipts: Vec<EvidenceChildReceiptRecord>,
    pub child_receipt_scope: EvidenceChildReceiptScope,
    pub checkpoints: Vec<KernelCheckpoint>,
    pub capability_lineage: Vec<CapabilitySnapshot>,
    pub inclusion_proofs: Vec<ReceiptInclusionProof>,
    pub uncheckpointed_receipts: Vec<EvidenceUncheckpointedReceipt>,
    pub retention: EvidenceRetentionMetadata,
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceExportError {
    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),

    #[error("capability lineage error: {0}")]
    CapabilityLineage(#[from] CapabilityLineageError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),

    #[error("core error: {0}")]
    Core(#[from] pact_core::Error),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl EvidenceExportQuery {
    pub fn as_receipt_query(&self, cursor: Option<u64>) -> ReceiptQuery {
        ReceiptQuery {
            capability_id: self.capability_id.clone(),
            tool_server: None,
            tool_name: None,
            outcome: None,
            since: self.since,
            until: self.until,
            min_cost: None,
            max_cost: None,
            cursor,
            limit: crate::MAX_QUERY_LIMIT,
            agent_subject: self.agent_subject.clone(),
        }
    }

    fn has_subject_or_capability_scope(&self) -> bool {
        self.capability_id.is_some() || self.agent_subject.is_some()
    }

    fn has_time_window(&self) -> bool {
        self.since.is_some() || self.until.is_some()
    }

    #[must_use]
    pub fn child_receipt_scope(&self) -> EvidenceChildReceiptScope {
        if self.has_subject_or_capability_scope() {
            if self.has_time_window() {
                EvidenceChildReceiptScope::TimeWindowContextOnly
            } else {
                EvidenceChildReceiptScope::OmittedNoJoinPath
            }
        } else {
            EvidenceChildReceiptScope::FullQueryWindow
        }
    }
}
