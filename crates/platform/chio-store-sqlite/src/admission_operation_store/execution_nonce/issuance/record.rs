//! Bounded, canonical issuance evidence tied to the exact operation commit.

use super::*;

pub(in crate::admission_operation_store) fn verify(
    connection: &Connection,
    operation: &AdmissionOperationV1,
) -> Result<Option<AdmissionExecutionNonceReservationV1>, AdmissionOperationStoreError> {
    let row = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(nonce_id AS BLOB)) BETWEEN 1 AND 512 THEN nonce_id END,
                CASE WHEN length(issuer) = 64 THEN issuer END,
                CASE WHEN length(issuance_json) BETWEEN 1 AND 16384 THEN issuance_json END,
                CASE WHEN length(operation_json) BETWEEN 1 AND 262144 THEN operation_json END,
                issued_at_unix_ms
         FROM admission_execution_nonce_issuances WHERE operation_id = ?1",
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((nonce_id, issuer, artifact, snapshot, at)) = row else {
        if operation.execution_nonce_issuance_digest().is_some() {
            return Err(invariant(
                "operation nonce issuance attachment has no durable artifact",
            ));
        }
        return Ok(None);
    };
    let (Some(nonce_id), Some(issuer), Some(artifact), Some(snapshot)) =
        (nonce_id, issuer, artifact, snapshot)
    else {
        return Err(invariant(
            "durable nonce issuance exceeds its storage bound",
        ));
    };
    let digest = sha256_hex(&artifact);
    if operation
        .execution_nonce_issuance_digest()
        .map(AdmissionDigest::as_str)
        != Some(&digest)
    {
        return Err(invariant(
            "durable nonce issuance and operation attachment disagree",
        ));
    }
    let issued = AdmissionOperationV1::from_persisted(
        serde_json::from_slice::<PersistedAdmissionOperationV1>(&snapshot)
            .map_err(|error| invariant(error.to_string()))?,
    )?;
    if issued.binding() != operation.binding()
        || issued.state() != AdmissionOperationState::Prepared
        || issued.attachments().iter().any(|attachment| {
            !matches!(
                attachment,
                AdmissionAttachment::ExecutionNonceIssuanceDigest(_)
                    | AdmissionAttachment::ExecutionNoncePreflightDigest(_)
            )
        })
        || issued.execution_nonce_issuance_digest() != operation.execution_nonce_issuance_digest()
        || !history::preserves_attachments(&issued, operation)
        || issued.version() > operation.version()
        || encode_operation(&issued)? != snapshot
    {
        return Err(invariant(
            "nonce issuance snapshot does not match its operation",
        ));
    }
    let at = stored_u64(at, "nonce issued_at_unix_ms")?;
    let committed: bool = connection
        .query_row(
            "SELECT COUNT(*) = 1 FROM admission_operation_commits
         WHERE operation_id = ?1 AND operation_version = ?2
           AND mutation_kind = 'compare_and_swap' AND participant_digest = ?3
           AND operation_digest = ?4 AND recorded_at_unix_ms = ?5",
            params![
                operation.binding().operation_id().as_str(),
                sqlite_i64(issued.version(), "issued_operation_version")?,
                commit_digest(&artifact, &snapshot, at)?,
                sha256_hex(&snapshot),
                sqlite_i64(at, "nonce issued_at_unix_ms")?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !committed {
        return Err(invariant("nonce issuance lost its exact admission commit"));
    }
    super::super::super::nonce_preflight::verify_issued_cleanup(
        connection,
        &issued,
        Some(issued.version()),
    )?;
    let original = retained_request::load_retained_request_tx(connection, operation)?
        .ok_or_else(|| invariant("nonce issuance lost its retained original request"))?;
    let issuer = PublicKey::from_hex(&issuer).map_err(|error| invariant(error.to_string()))?;
    let checked = AdmissionExecutionNonceReservationV1::from_canonical_bytes(
        &artifact, &issued, &original, &issuer, at,
    )?;
    checked.require_operation_bound_profile()?;
    if checked.nonce_id().as_str() != nonce_id {
        return Err(invariant("nonce issuance identifier was substituted"));
    }
    Ok(Some(checked))
}

pub(in crate::admission_operation_store) fn verify_ownership(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let orphan: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_execution_nonce_issuances AS nonce
         WHERE NOT EXISTS(SELECT 1 FROM admission_operations AS operation
                          WHERE operation.operation_id = nonce.operation_id))",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if orphan {
        return Err(invariant(
            "execution nonce issuance has no owning operation",
        ));
    }
    Ok(())
}

pub(super) fn commit_digest(
    issuance: &[u8],
    operation: &[u8],
    issued_at_unix_ms: u64,
) -> Result<String, AdmissionOperationStoreError> {
    canonical_json_bytes(&serde_json::json!({
        "schema": "chio.admission-execution-nonce-issuance-commit.v1",
        "issuance_digest": sha256_hex(issuance),
        "operation_digest": sha256_hex(operation),
        "issued_at_unix_ms": issued_at_unix_ms,
    }))
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|error| invariant(error.to_string()))
}
