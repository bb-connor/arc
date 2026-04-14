//! Error types for the ARC tower middleware.

use std::fmt;

/// Error type for ARC tower middleware operations.
#[derive(Debug)]
pub enum ArcTowerError {
    /// Failed to evaluate the request.
    Evaluation(String),
    /// Failed to sign a receipt.
    ReceiptSign(String),
    /// Failed to extract caller identity.
    IdentityExtraction(String),
    /// Inner service error.
    Inner(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for ArcTowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evaluation(msg) => write!(f, "ARC evaluation error: {msg}"),
            Self::ReceiptSign(msg) => write!(f, "ARC receipt signing error: {msg}"),
            Self::IdentityExtraction(msg) => write!(f, "ARC identity extraction error: {msg}"),
            Self::Inner(err) => write!(f, "inner service error: {err}"),
        }
    }
}

impl std::error::Error for ArcTowerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(err) => Some(err.as_ref()),
            _ => None,
        }
    }
}
