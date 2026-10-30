//! Sandbox attestation, tool-server acknowledgement, and trusted-time proof validation.

use super::*;

fn verify_sandbox_attestation_signature(
    sandbox: &RuntimeSandboxAttestation,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&sandbox.attester, "sandbox attester")?;
    let signature = Signature::from_hex(&sandbox.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecuritySignatureInvalid(format!(
            "sandbox attestation signature invalid: {error}"
        ))
    })?;
    let verified = verify_wrapped(
        &public_key,
        RUNTIME_SANDBOX_ATTESTATION_SIGNATURE_SCHEMA,
        &sandbox_attestation_signature_body(sandbox),
        &signature,
    )
    .is_ok();
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecuritySignatureInvalid(
            "sandbox attestation signature invalid".to_string(),
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RuntimeSandboxAttestationSignatureBody<'a> {
    schema: &'static str,
    attestation_id: &'a str,
    tool_server_id: &'a str,
    tool_instance_id: &'a str,
    tool_manifest_digest: &'a str,
    sandbox_profile_digest: &'a str,
    egress_policy_digest: &'a str,
    started_at: &'a str,
    expires_at: &'a str,
    attester: &'a str,
}

pub(super) fn sandbox_attestation_signature_body(
    sandbox: &RuntimeSandboxAttestation,
) -> RuntimeSandboxAttestationSignatureBody<'_> {
    RuntimeSandboxAttestationSignatureBody {
        schema: RUNTIME_SANDBOX_ATTESTATION_SIGNATURE_SCHEMA,
        attestation_id: &sandbox.attestation_id,
        tool_server_id: &sandbox.tool_server_id,
        tool_instance_id: &sandbox.tool_instance_id,
        tool_manifest_digest: &sandbox.tool_manifest_digest,
        sandbox_profile_digest: &sandbox.sandbox_profile_digest,
        egress_policy_digest: &sandbox.egress_policy_digest,
        started_at: &sandbox.started_at,
        expires_at: &sandbox.expires_at,
        attester: &sandbox.attester,
    }
}

pub(in crate::runtime_security) fn validate_sandbox_attestation(
    lease: &RuntimeExecutionLease,
    sandbox: &RuntimeSandboxAttestation,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if sandbox.attestation_id != lease.sandbox_attestation_ref {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox attestation mismatch".to_string(),
        ));
    }
    if sandbox.tool_server_id != lease.tool_server_id
        || sandbox.tool_instance_id != lease.tool_instance_id
        || sandbox.tool_manifest_digest != lease.tool_manifest_digest
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox tool binding mismatch".to_string(),
        ));
    }
    require_non_empty(&sandbox.schema, "sandbox attestation schema")?;
    for (field, value) in [
        ("sandbox_profile_digest", &sandbox.sandbox_profile_digest),
        ("egress_policy_digest", &sandbox.egress_policy_digest),
    ] {
        validate_digest_field(field, value)?;
    }
    for (field, value) in [
        ("started_at", &sandbox.started_at),
        ("expires_at", &sandbox.expires_at),
        ("attester", &sandbox.attester),
        ("signature", &sandbox.signature),
    ] {
        require_non_empty(value, field)?;
    }
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let lease_expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    let sandbox_started_at = parse_rfc3339_utc(&sandbox.started_at, "sandbox started_at")?;
    let sandbox_expires_at = parse_rfc3339_utc(&sandbox.expires_at, "sandbox expires_at")?;
    if sandbox_expires_at <= sandbox_started_at
        || sandbox_started_at > lease_issued_at
        || sandbox_expires_at < lease_expires_at
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox attestation not valid for execution lease".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "sandbox attester",
        &sandbox.attester,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_sandbox_attestation_signature(sandbox)?;
    Ok(())
}

pub(in crate::runtime_security) fn validate_tool_server_ack(
    lease: &RuntimeExecutionLease,
    sandbox: &RuntimeSandboxAttestation,
    ack: &RuntimeToolServerAck,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if ack.lease_id != lease.lease_id
        || ack.tool_server_id != lease.tool_server_id
        || ack.tool_instance_id != lease.tool_instance_id
        || ack.sandbox_attestation_ref != sandbox.attestation_id
        || ack.nonce != lease.nonce
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "tool-server acknowledgement mismatch".to_string(),
        ));
    }
    if ack.terminal_status != "allowed_executed" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "tool-server acknowledgement did not execute".to_string(),
        ));
    }
    require_non_empty(&ack.schema, "tool-server acknowledgement schema")?;
    require_non_empty(&ack.ack_id, "ack_id")?;
    require_non_empty(&ack.issued_at, "issued_at")?;
    require_non_empty(&ack.signature, "signature")?;
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let lease_expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    let ack_issued_at = parse_rfc3339_utc(&ack.issued_at, "tool-server acknowledgement issued_at")?;
    if ack_issued_at < lease_issued_at || ack_issued_at > lease_expires_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "acknowledgement outside execution lease".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "tool-server",
        &ack.tool_server_id,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_tool_server_ack_signature(ack)?;
    Ok(())
}

pub(in crate::runtime_security) fn validate_trusted_time_proof(
    lease: &RuntimeExecutionLease,
    ack: &RuntimeToolServerAck,
    proof: &RuntimeTrustedTimeProof,
    trusted_roots: &[&RuntimeTrustRoot],
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if proof.schema != RUNTIME_TRUSTED_TIME_PROOF_SCHEMA_ID {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof schema mismatch".to_string(),
        ));
    }
    for (field, value) in [
        ("proof_id", &proof.proof_id),
        ("lease_id", &proof.lease_id),
        ("ack_id", &proof.ack_id),
        ("observed_at", &proof.observed_at),
        ("time_source_id", &proof.time_source_id),
        ("issuer", &proof.issuer),
        ("signature", &proof.signature),
    ] {
        require_non_empty(value, field)?;
    }
    if proof.lease_id != lease.lease_id || proof.ack_id != ack.ack_id {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof acknowledgement mismatch".to_string(),
        ));
    }
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let lease_expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    let observed_at = parse_rfc3339_utc(&proof.observed_at, "trusted time observed_at")?;
    if proof.max_clock_skew_ms > 30_000 {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof clock skew bound too wide".to_string(),
        ));
    }
    if observed_at < lease_issued_at || observed_at > lease_expires_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "trusted time proof outside execution lease".to_string(),
        ));
    }
    ensure_runtime_identity_is_trusted(
        "trusted time issuer",
        &proof.issuer,
        trusted_roots,
        trusted_root_signer_keys,
    )?;
    verify_trusted_time_proof_signature(proof)?;
    Ok(())
}

fn verify_tool_server_ack_signature(
    ack: &RuntimeToolServerAck,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&ack.tool_server_id, "tool-server id")?;
    let signature = Signature::from_hex(&ack.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecuritySignatureInvalid(format!(
            "tool-server acknowledgement signature invalid: {error}"
        ))
    })?;
    let verified = verify_wrapped(
        &public_key,
        RUNTIME_TOOL_SERVER_ACK_SIGNATURE_SCHEMA,
        &tool_server_ack_signature_body(ack),
        &signature,
    )
    .is_ok();
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecuritySignatureInvalid(
            "tool-server acknowledgement signature invalid".to_string(),
        ))
    }
}

fn verify_trusted_time_proof_signature(
    proof: &RuntimeTrustedTimeProof,
) -> Result<(), TransactionPassportError> {
    let public_key = self_certifying_public_key(&proof.issuer, "trusted time issuer")?;
    let signature = Signature::from_hex(&proof.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecuritySignatureInvalid(format!(
            "trusted time proof signature invalid: {error}"
        ))
    })?;
    let verified = verify_wrapped(
        &public_key,
        RUNTIME_TRUSTED_TIME_PROOF_SIGNATURE_SCHEMA,
        &trusted_time_proof_signature_body(proof),
        &signature,
    )
    .is_ok();
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecuritySignatureInvalid(
            "trusted time proof signature invalid".to_string(),
        ))
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RuntimeToolServerAckSignatureBody<'a> {
    schema: &'static str,
    ack_id: &'a str,
    lease_id: &'a str,
    tool_server_id: &'a str,
    tool_instance_id: &'a str,
    sandbox_attestation_ref: &'a str,
    nonce: &'a str,
    terminal_status: &'a str,
    issued_at: &'a str,
}

pub(super) fn tool_server_ack_signature_body(
    ack: &RuntimeToolServerAck,
) -> RuntimeToolServerAckSignatureBody<'_> {
    RuntimeToolServerAckSignatureBody {
        schema: RUNTIME_TOOL_SERVER_ACK_SIGNATURE_SCHEMA,
        ack_id: &ack.ack_id,
        lease_id: &ack.lease_id,
        tool_server_id: &ack.tool_server_id,
        tool_instance_id: &ack.tool_instance_id,
        sandbox_attestation_ref: &ack.sandbox_attestation_ref,
        nonce: &ack.nonce,
        terminal_status: &ack.terminal_status,
        issued_at: &ack.issued_at,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RuntimeTrustedTimeProofSignatureBody<'a> {
    schema: &'static str,
    proof_id: &'a str,
    lease_id: &'a str,
    ack_id: &'a str,
    observed_at: &'a str,
    max_clock_skew_ms: u64,
    time_source_id: &'a str,
    issuer: &'a str,
}

pub(super) fn trusted_time_proof_signature_body(
    proof: &RuntimeTrustedTimeProof,
) -> RuntimeTrustedTimeProofSignatureBody<'_> {
    RuntimeTrustedTimeProofSignatureBody {
        schema: RUNTIME_TRUSTED_TIME_PROOF_SIGNATURE_SCHEMA,
        proof_id: &proof.proof_id,
        lease_id: &proof.lease_id,
        ack_id: &proof.ack_id,
        observed_at: &proof.observed_at,
        max_clock_skew_ms: proof.max_clock_skew_ms,
        time_source_id: &proof.time_source_id,
        issuer: &proof.issuer,
    }
}
