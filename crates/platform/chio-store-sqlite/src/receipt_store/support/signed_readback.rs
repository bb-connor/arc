use chio_core::receipt::lineage::{ReceiptLineageStatement, SignedExportEnvelope};
use serde::{de::DeserializeOwned, Serialize};

use super::*;

/// Decode native signed formats without losing duplicate keys or numeric precision.
/// Signature verification and row binding remain the caller's responsibility.
fn decode_signed_json<T: DeserializeOwned>(raw: &str) -> Result<T, ReceiptStoreError> {
    chio_core::canonical::UntrustedJsonText::new(raw)
        .decode_signed()
        .map_err(ReceiptStoreError::from)
}

/// Recheck persisted economy artifacts before reports or workflow comparisons
/// consume them. A valid embedded signer proves integrity, not authorization.
pub(crate) fn decode_verified_signed_export<T>(
    raw: &str,
) -> Result<SignedExportEnvelope<T>, ReceiptStoreError>
where
    T: DeserializeOwned + Serialize + Clone,
{
    let envelope: SignedExportEnvelope<T> = decode_signed_json(raw)?;
    if !envelope
        .verify_signature()
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
    {
        return Err(ReceiptStoreError::Conflict(
            "persisted signed export signature verification failed".to_owned(),
        ));
    }
    Ok(envelope)
}

pub(crate) fn decode_verified_lineage_statement(
    raw: &str,
    receipt_id: &str,
) -> Result<ReceiptLineageStatement, ReceiptStoreError> {
    let statement: ReceiptLineageStatement = decode_signed_json(raw)?;
    if statement.child_receipt_id != receipt_id {
        return Err(ReceiptStoreError::Conflict(
            "persisted lineage statement does not match the requested child receipt".to_owned(),
        ));
    }
    if !statement
        .verify_signature()
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?
    {
        return Err(ReceiptStoreError::Conflict(
            "persisted lineage statement signature verification failed".to_owned(),
        ));
    }
    Ok(statement)
}
