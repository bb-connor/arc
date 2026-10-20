//! Store-side errors and receipt queries for evidence export.
//!
//! The bundle model lives in `chio_core::receipt::evidence`; this module
//! binds it to the hosted receipt store.

use chio_core::receipt::evidence::{
    EvidenceExportQuery, EvidenceReadBoundaryError, ReceiptReadBoundary,
};
use chio_kernel_core::evidence_verify::CheckpointError;

use crate::capability_lineage::CapabilityLineageError;
use crate::receipt_query::{ReceiptQuery, ReceiptReadContext};
use crate::receipt_store::ReceiptStoreError;

#[derive(Debug, thiserror::Error)]
pub enum EvidenceExportError {
    #[error(transparent)]
    UntrustedInput(#[from] chio_core::canonical::UntrustedJsonError),
    #[error("receipt store error: {0}")]
    ReceiptStore(#[from] ReceiptStoreError),

    #[error("capability lineage error: {0}")]
    CapabilityLineage(#[from] CapabilityLineageError),

    #[error("checkpoint error: {0}")]
    Checkpoint(#[from] CheckpointError),

    #[error("core error: {0}")]
    Core(#[from] chio_core::Error),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("receipt read boundary error: {0}")]
    ReadBoundary(String),
}

impl From<EvidenceReadBoundaryError> for EvidenceExportError {
    fn from(error: EvidenceReadBoundaryError) -> Self {
        Self::ReadBoundary(error.0)
    }
}

/// The receipt-store page query an evidence export reads through.
pub trait EvidenceExportReceiptQuery {
    fn as_receipt_query(&self, cursor: Option<u64>) -> ReceiptQuery;
}

impl EvidenceExportReceiptQuery for EvidenceExportQuery {
    fn as_receipt_query(&self, cursor: Option<u64>) -> ReceiptQuery {
        let read_context = match &self.read_boundary {
            Some(ReceiptReadBoundary::AdminAll) => Some(ReceiptReadContext::admin_service()),
            Some(ReceiptReadBoundary::TenantScoped { tenant }) => {
                Some(ReceiptReadContext::authenticated_tenant(tenant.clone()))
            }
            None => None,
        };
        ReceiptQuery {
            capability_id: self.capability_id.clone(),
            tool_server: None,
            tool_name: None,
            outcome: None,
            since: self.since,
            until: self.until,
            min_cost: None,
            max_cost: None,
            cost_currency: None,
            cursor,
            limit: crate::MAX_QUERY_LIMIT,
            agent_subject: self.agent_subject.clone(),
            tenant_filter: self.effective_tenant_filter(),
            read_context,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "Test fixtures deliberately fail on violated setup invariants."
)]
mod tests {
    use super::*;

    #[test]
    fn admin_all_evidence_export_uses_remote_safe_read_context() {
        let receipt_query = EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..EvidenceExportQuery::default()
        }
        .as_receipt_query(None);

        assert_eq!(receipt_query.tenant_filter.as_deref(), Some("tenant-a"));
        assert_eq!(
            receipt_query.read_context,
            Some(ReceiptReadContext::admin_service())
        );
    }

    #[test]
    fn read_boundary_errors_keep_their_message() {
        let error = EvidenceExportError::from(
            EvidenceExportQuery::default()
                .validate_read_boundary()
                .expect_err("missing read boundary must fail closed"),
        );
        assert!(matches!(error, EvidenceExportError::ReadBoundary(message)
            if message == "evidence export requires an explicit receipt read boundary"));
    }
}
