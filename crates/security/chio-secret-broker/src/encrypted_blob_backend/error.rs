//! Closed credential refusal/storage categories retain native store failures.
use chio_store_sqlite::BlobStoreError;
use std::{error::Error, fmt};

/// Native credential storage error available only through explicit cause inspection.
pub struct CredentialStoreError {
    source: BlobStoreError,
}

impl CredentialStoreError {
    pub(super) fn new(source: BlobStoreError) -> Self {
        Self { source }
    }
}

impl fmt::Debug for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialStoreError(redacted)")
    }
}

impl fmt::Display for CredentialStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential store cause retained")
    }
}

impl Error for CredentialStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
