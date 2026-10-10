//! Typed receipt rejection causes with redacted public formatting.

/// The authorization field that could not be linked to an audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptBinding {
    Capability,
    Receipt,
    Request,
    Session,
    ToolCall,
    Correlation,
    Operation,
    Resource,
    ParameterHash,
    OperationPayload,
    Tool,
    Signer,
}

/// A semantic failure linking the live authorization receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("urn:chio:error:attest:receipt-signing-failed")]
pub enum ReceiptAuthorizationError {
    Missing(ReceiptBinding),
    Mismatch(ReceiptBinding),
    InvalidSignature,
    NotAuthorizing,
    InvalidTenant,
    MalformedToolCall,
}

/// Errors from signing, durable receipt append and checkpoint preparation.
#[derive(thiserror::Error)]
pub enum ReceiptSignError {
    #[error("{0}")]
    Audit(#[from] crate::AcpAuditError),
    #[error("{0}")]
    Authorization(#[from] ReceiptAuthorizationError),
    #[error("urn:chio:error:attest:receipt-signing-failed")]
    Canonical(#[from] chio_core::error::Error),
    #[error("urn:chio:error:attest:receipt-signing-failed")]
    Store(#[from] chio_kernel::receipt_store::ReceiptStoreError),
    #[error("urn:chio:error:attest:receipt-signing-failed")]
    PoisonedStore,
    #[error("urn:chio:error:attest:receipt-signing-failed")]
    SignerUnavailable,
    #[error("urn:chio:error:transaction:receipt-uncheckpointed")]
    CheckpointUnavailable,
}
impl std::fmt::Debug for ReceiptSignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
