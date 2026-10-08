//! Deterministic admission operation and cleanup action identifiers.
use super::*;

pub fn derive_operation_id(
    kind: AdmissionOperationKind,
    coordinator_authority_id: &str,
    request_id: &str,
    capability_id: &str,
    authorization_capability_hash: &str,
    request_binding_hash: &str,
) -> Result<String, AdmissionOperationError> {
    validate_identifier(coordinator_authority_id, "coordinator_authority_id")?;
    validate_identifier(request_id, "request_id")?;
    validate_identifier(capability_id, "capability_id")?;
    validate_digest(
        authorization_capability_hash,
        "authorization_capability_hash",
    )?;
    validate_digest(request_binding_hash, "request_binding_hash")?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationIdentity<'a> {
        kind: AdmissionOperationKind,
        coordinator_authority_id: &'a str,
        request_id: &'a str,
        capability_id: &'a str,
        authorization_capability_hash: &'a str,
        request_binding_hash: &'a str,
    }
    let canonical = canonical_json_bytes(&OperationIdentity {
        kind,
        coordinator_authority_id,
        request_id,
        capability_id,
        authorization_capability_hash,
        request_binding_hash,
    })
    .map_err(|error| {
        AdmissionOperationError::Invalid(format!(
            "failed to canonicalize admission operation identity: {error}"
        ))
    })?;
    let mut bytes = Vec::with_capacity(ADMISSION_OPERATION_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(ADMISSION_OPERATION_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

pub fn derive_cleanup_action_id(
    operation_id: &str,
    request_binding_hash: &str,
    kind: AdmissionCleanupActionKind,
    payload_hash: &str,
) -> Result<String, AdmissionOperationError> {
    validate_digest(operation_id, "cleanup operation_id")?;
    validate_digest(request_binding_hash, "cleanup request_binding_hash")?;
    validate_digest(payload_hash, "cleanup payload_hash")?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CleanupIdentity<'a> {
        operation_id: &'a str,
        request_binding_hash: &'a str,
        kind: AdmissionCleanupActionKind,
        payload_hash: &'a str,
    }
    let canonical = canonical_json_bytes(&CleanupIdentity {
        operation_id,
        request_binding_hash,
        kind,
        payload_hash,
    })
    .map_err(|error| {
        AdmissionOperationError::Invalid(format!(
            "failed to canonicalize admission cleanup identity: {error}"
        ))
    })?;
    let mut bytes = Vec::with_capacity(ADMISSION_CLEANUP_ACTION_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(ADMISSION_CLEANUP_ACTION_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}
