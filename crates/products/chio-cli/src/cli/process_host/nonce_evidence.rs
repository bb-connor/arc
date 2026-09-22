//! Original nonce custody, authenticated by the call and signed store readback.

use chio_core::{
    capability::token::CapabilityToken,
    crypto::{canonical_json_bytes, sha256_hex},
    receipt::body::ChioReceipt,
    PublicKey,
};
use chio_kernel::admission_operation::{
    verify_operation_execution_nonce_at, AdmissionOperationId, AdmissionOperationV1,
    AdmissionReceiptMetadataV1,
};
use chio_kernel::execution_nonce::NonceBinding;
use serde_json::{json, Value};

use super::state::error;
use crate::CliError;
pub(super) use chio_store_sqlite::admission_operation_store::ExecutionNonceEvidenceV1 as Evidence;

fn operation_id(receipt: &ChioReceipt) -> Result<Option<AdmissionOperationId>, CliError> {
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| error("missing call metadata"))?;
    if let Some(projection) = metadata.get("admission_operation") {
        let projection: AdmissionReceiptMetadataV1 =
            serde_json::from_value(projection.clone()).map_err(error)?;
        return Ok(Some(projection.operation_id));
    }
    let reference = &metadata["chio_runtime"]["operation_owned_replay"]["reference"];
    if reference.is_null() {
        return Ok(None);
    }
    let reference: chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimReferenceV1 =
        serde_json::from_value(reference.clone()).map_err(error)?;
    Ok(Some(reference.operation_id().clone()))
}

pub(super) fn verify(
    evidence: Option<&Evidence>,
    receipt: &ChioReceipt,
    response: &Value,
    cap: &CapabilityToken,
    key: &PublicKey,
    observed_at: u64,
) -> Result<Option<String>, CliError> {
    let nonce = crate::process_response_verify::response_nonce(response)?;
    let id = operation_id(receipt)?;
    let Some(evidence) = evidence else {
        let projection = receipt
            .metadata
            .as_ref()
            .and_then(|m| m.get("admission_operation"));
        if nonce.is_some()
            || receipt.decision == Some(chio_core::receipt::decision::Decision::Allow)
            || projection.is_some_and(|p| !p["retained_dispatch_commit"].is_null())
        {
            return Err(error("missing original execution nonce custody"));
        }
        return Ok(None);
    };
    let operation =
        AdmissionOperationV1::from_persisted(evidence.operation.clone()).map_err(error)?;
    let binding = operation.binding();
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| error("missing call metadata"))?;
    let expected = NonceBinding {
        subject_id: cap.subject.to_hex(),
        request_id: response["request_id"]
            .as_str()
            .ok_or_else(|| error("missing request ID"))?
            .into(),
        capability_id: cap.id.clone(),
        tool_server: receipt.tool_server.clone(),
        tool_name: receipt.tool_name.clone(),
        parameter_hash: receipt.action.parameter_hash.clone(),
    };
    if nonce.as_ref() != Some(&evidence.signed_nonce)
        || id.as_ref() != Some(binding.operation_id())
        || binding.request_id().as_str() != expected.request_id
        || binding.capability_id().as_str() != cap.id
        || evidence
            .operation
            .binding
            .authorization_capability_hash
            .as_str()
            != sha256_hex(&canonical_json_bytes(cap).map_err(error)?)
        || binding.action_parameter_hash().as_str() != receipt.action.parameter_hash
        || binding.policy_hash().as_str() != receipt.policy_hash
        || !binding.participant_requirements().execution_nonce
        || evidence.verified_at_unix_ms > observed_at
        || evidence
            .reserved_at_unix_ms
            .is_some_and(|time| time > observed_at || time < evidence.verified_at_unix_ms)
        || (evidence.reserved_at_unix_ms.is_some() != operation.execution_nonce_id().is_some())
        || operation
            .execution_nonce_id()
            .is_some_and(|id| id.as_str() != evidence.signed_nonce.nonce.nonce_id)
        || (operation.dispatch_commit().is_some() && evidence.reserved_at_unix_ms.is_none())
    {
        return Err(error(
            "execution nonce differs from original operation custody",
        ));
    }
    if let Some(projection) = metadata.get("admission_operation") {
        let projection: AdmissionReceiptMetadataV1 =
            serde_json::from_value(projection.clone()).map_err(error)?;
        if projection.projected_state != operation.state()
            || projection.projected_operation_version != operation.version()
            || projection.retained_dispatch_commit.as_ref() != operation.dispatch_commit()
        {
            return Err(error(
                "execution nonce operation differs from signed admission",
            ));
        }
    }
    verify_operation_execution_nonce_at(
        &evidence.signed_nonce,
        binding.operation_id(),
        key,
        &expected,
        i64::try_from(evidence.verified_at_unix_ms / 1000).map_err(error)?,
    )
    .map_err(error)?;
    let reservation = json!({
        "schema": "chio.admission-execution-nonce-reservation.v1",
        "operation_id": binding.operation_id(), "issuer": key,
        "signed_nonce": evidence.signed_nonce,
    });
    let digest = sha256_hex(&canonical_json_bytes(&reservation).map_err(error)?);
    if operation
        .execution_nonce_issuance_digest()
        .map(|value| value.as_str())
        != Some(digest.as_str())
    {
        return Err(error(
            "execution nonce differs from original issuance commitment",
        ));
    }
    Ok(Some(evidence.signed_nonce.nonce.nonce_id.clone()))
}

#[cfg(target_os = "linux")]
pub(super) fn export(
    host: &super::state::Host,
    receipt: &ChioReceipt,
    now: u64,
) -> Result<Option<Evidence>, CliError> {
    let Some(id) = operation_id(receipt)? else {
        return Ok(None);
    };
    let (store, fence) = host
        .authority
        .local_runtime_participant()
        .ok_or_else(|| error("missing original nonce authority"))?;
    store
        .load_execution_nonce_evidence(&id, &fence, now)
        .map_err(error)
}
