//! Checked storage accounting for seller artifact capacity.

use super::FindingOperatorBundleStoreError;
use rusqlite::OptionalExtension;

pub(super) fn seller_database_bytes(
    conn: &rusqlite::Connection,
) -> Result<i64, FindingOperatorBundleStoreError> {
    let page_count: i64 = conn
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
    let page_size: i64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
    if page_count < 0 || page_size <= 0 {
        return Err(FindingOperatorBundleStoreError::DigestMismatch);
    }
    page_count
        .checked_mul(page_size)
        .ok_or(FindingOperatorBundleStoreError::SellerArtifactCapacity)
}

pub(super) fn seller_finding_artifact_bytes(
    conn: &rusqlite::Connection,
    finding_id: &str,
) -> Result<Option<i64>, FindingOperatorBundleStoreError> {
    let payload_bytes: Option<i64> = conn
        .query_row(
            "SELECT length(ciphertext) FROM chio_finding_payloads WHERE finding_id = ?1",
            [finding_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
    let bundle_bytes: Option<i64> = conn
        .query_row(
            "SELECT length(bundle_json) FROM chio_finding_operator_bundles WHERE finding_id = ?1",
            [finding_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
    let proof_bytes: Option<i64> = conn
        .query_row(
            "SELECT length(proof_json) FROM chio_finding_operator_proofs WHERE finding_id = ?1",
            [finding_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
    let (Some(payload_bytes), Some(bundle_bytes), Some(proof_bytes)) =
        (payload_bytes, bundle_bytes, proof_bytes)
    else {
        return Ok(None);
    };
    if payload_bytes < 0 || bundle_bytes < 0 || proof_bytes < 0 {
        return Err(FindingOperatorBundleStoreError::DigestMismatch);
    }
    payload_bytes
        .checked_add(bundle_bytes)
        .and_then(|value| value.checked_add(proof_bytes))
        .map(Some)
        .ok_or(FindingOperatorBundleStoreError::SellerArtifactCapacity)
}
