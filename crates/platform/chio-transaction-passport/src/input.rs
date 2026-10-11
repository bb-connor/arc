//! Bounded original evidence decoding. Authentication remains with the verifier.

use chio_core_types::canonical::UntrustedJsonText;
use serde::de::DeserializeOwned;

use crate::TransactionPassportError;

/// Maximum original document size, including whitespace and ignored fields.
pub const MAX_EVIDENCE_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum total evidence retained by one verification invocation.
pub const MAX_EVIDENCE_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum number of independently supplied artifacts in a verification bundle.
pub const MAX_EVIDENCE_ARTIFACTS: usize = 4096;

/// Reject ambiguous or lossy original JSON before typed projection. This does
/// not verify a signature, trusted issuer, replay state, or an authority claim.
pub fn decode_evidence_json<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, TransactionPassportError> {
    UntrustedJsonText::from_wire(bytes, MAX_EVIDENCE_DOCUMENT_BYTES)
        .and_then(|input| input.decode_signed())
        .map_err(|error| TransactionPassportError::Input(error.into()))
}

/// Bound verification work before hashing, decoding, or traversing a collection.
/// Callers include the graph and policy documents as well as artifact bodies.
pub fn validate_evidence_budget<'a>(
    documents: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(), TransactionPassportError> {
    let mut remaining = MAX_EVIDENCE_BUNDLE_BYTES;
    for (index, document) in documents.into_iter().enumerate() {
        if index >= MAX_EVIDENCE_ARTIFACTS || document.len() > MAX_EVIDENCE_DOCUMENT_BYTES {
            return Err(TransactionPassportError::EvidenceLimit);
        }
        remaining = remaining
            .checked_sub(document.len())
            .ok_or(TransactionPassportError::EvidenceLimit)?;
    }
    Ok(())
}

pub(crate) fn project<T: DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, TransactionPassportError> {
    serde_json::from_value(value).map_err(|error| {
        TransactionPassportError::Input(
            chio_core_types::canonical::UntrustedJsonError::Decode(error).into(),
        )
    })
}

/// Bound graph traversal independently from the original document byte budget.
pub fn validate_evidence_graph_size(
    nodes: usize,
    edges: usize,
) -> Result<(), TransactionPassportError> {
    if nodes > MAX_EVIDENCE_ARTIFACTS || edges > 4 * MAX_EVIDENCE_ARTIFACTS {
        return Err(TransactionPassportError::EvidenceLimit);
    }
    Ok(())
}
