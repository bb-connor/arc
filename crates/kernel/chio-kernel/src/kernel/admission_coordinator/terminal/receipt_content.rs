use super::*;

/// Produce the receipt-visible content binding for a delivery verdict.
///
/// A mismatch keeps the actual output and digest only in the durable outcome
/// store for privileged challenge handling. The public Deny receipt binds a
/// domain-separated redaction preimage keyed by the committed expected digest,
/// so neither its content hash, delivery-contract block, nor stream metadata
/// becomes a payload confirmation oracle. Replaying the same mismatch
/// reconstructs identical receipt bytes without requiring new randomness.
pub(super) fn receipt_visible_delivery_content(
    actual: &ReceiptContent,
    digest_mismatched: bool,
    expected_digest: Option<&str>,
) -> ReceiptContent {
    if digest_mismatched {
        let mut canonical_content = Vec::with_capacity(
            DELIVERY_MISMATCH_REDACTION_DOMAIN.len() + expected_digest.map_or(0, str::len),
        );
        canonical_content.extend_from_slice(DELIVERY_MISMATCH_REDACTION_DOMAIN);
        if let Some(expected_digest) = expected_digest {
            canonical_content.extend_from_slice(expected_digest.as_bytes());
        }
        return ReceiptContent {
            content_hash: sha256_hex(&canonical_content),
            metadata: None,
            canonical_content,
        };
    }
    ReceiptContent {
        content_hash: actual.content_hash.clone(),
        metadata: actual.metadata.clone(),
        canonical_content: actual.canonical_content.clone(),
    }
}
