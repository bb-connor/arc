//! SIEM event wrapper around ChioReceipt with extracted financial metadata.

use chio_core::receipt::{ChioReceipt, FinancialReceiptMetadata};
use serde::{Deserialize, Serialize};

/// A SIEM event wrapping a ChioReceipt with optionally extracted financial metadata.
///
/// The `receipt` field contains the full receipt (including raw metadata) for
/// forwarding to SIEM backends. The `financial` field is extracted for
/// structured filtering without requiring JSON path traversal on the export side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    /// The full ChioReceipt as stored in the kernel receipt database.
    pub receipt: ChioReceipt,
    /// Financial metadata extracted from `receipt.metadata["financial"]`, if present.
    pub financial: Option<FinancialReceiptMetadata>,
    /// Semantic receipt kind. Legacy receipts default to mediated decisions
    /// unless their trust level marks them advisory.
    pub receipt_kind: String,
    /// Runtime boundary class used by downstream authorization mapping.
    pub boundary_class: String,
    /// Human-facing result label. Only mediated/prevent/allow is authorized.
    pub result: String,
}

impl SiemEvent {
    /// Construct a SiemEvent from a ChioReceipt.
    ///
    /// Attempts to extract `FinancialReceiptMetadata` from
    /// `receipt.metadata["financial"]`. Returns `None` for the `financial` field
    /// if the metadata key is absent or fails to deserialize.
    pub fn from_receipt(receipt: ChioReceipt) -> Self {
        let financial = receipt
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("financial"))
            .and_then(|val| serde_json::from_value::<FinancialReceiptMetadata>(val.clone()).ok());

        let view = receipt.semantic_view();
        Self {
            receipt,
            financial,
            receipt_kind: view.receipt_kind.as_str().to_string(),
            boundary_class: view.boundary_class.as_str().to_string(),
            result: view.result.as_str().to_string(),
        }
    }
}
