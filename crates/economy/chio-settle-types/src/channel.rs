use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, PublicKey};
use serde::Serialize;

const CHANNEL_RECEIPT_AUTHORITY_DIGEST_DOMAIN: &[u8] =
    b"chio.channel.receipt-authority.digest.v1\0";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ChannelReceiptAuthorityDigestError {
    #[error("channel canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Domain-separated SHA-256 over the canonical JSON of the kernel key that
/// signs channel receipts.
pub fn derive_channel_receipt_authority_digest(
    kernel_key: &PublicKey,
) -> Result<String, ChannelReceiptAuthorityDigestError> {
    domain_digest(CHANNEL_RECEIPT_AUTHORITY_DIGEST_DOMAIN, kernel_key)
}

fn domain_digest<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<String, ChannelReceiptAuthorityDigestError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ChannelReceiptAuthorityDigestError::Canonicalization(error.to_string()))?;
    let mut bytes = Vec::with_capacity(domain.len() + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}
