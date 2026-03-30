//! SIEM event wrapper around ArcReceipt with extracted financial metadata.

use arc_core::receipt::{ArcReceipt, FinancialReceiptMetadata};
use serde::{Deserialize, Serialize};

/// A SIEM event wrapping a ArcReceipt with optionally extracted financial metadata.
///
/// The `receipt` field contains the full receipt (including raw metadata) for
/// forwarding to SIEM backends. The `financial` field is extracted for
/// structured filtering without requiring JSON path traversal on the export side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemEvent {
    /// The full ArcReceipt as stored in the kernel receipt database.
    pub receipt: ArcReceipt,
    /// Financial metadata extracted from `receipt.metadata["financial"]`, if present.
    pub financial: Option<FinancialReceiptMetadata>,
}

impl SiemEvent {
    /// Construct a SiemEvent from a ArcReceipt.
    ///
    /// Attempts to extract `FinancialReceiptMetadata` from
    /// `receipt.metadata["financial"]`. Returns `None` for the `financial` field
    /// if the metadata key is absent or fails to deserialize.
    pub fn from_receipt(receipt: ArcReceipt) -> Self {
        let financial = receipt
            .metadata
            .as_ref()
            .and_then(|meta| meta.get("financial"))
            .and_then(|val| serde_json::from_value::<FinancialReceiptMetadata>(val.clone()).ok());

        Self { receipt, financial }
    }
}
