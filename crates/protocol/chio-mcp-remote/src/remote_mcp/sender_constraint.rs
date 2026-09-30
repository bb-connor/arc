//! Runtime sender binding and original DPoP proof verification.
use super::*;

pub(super) fn decode_sender_dpop_proof(raw: &str) -> Result<DpopProof, SenderConstraintError> {
    let encoded = raw;
    if encoded.len() > MAX_AUTH_JSON_BYTES {
        return Err(chio_core::canonical::UntrustedJsonError::TooLarge {
            bytes: encoded.len(),
            bound: MAX_AUTH_JSON_BYTES,
        }
        .into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
    Ok(decode_json(&bytes, MAX_AUTH_JSON_BYTES)?)
}

pub(super) struct SenderConstraintVerifier<'a> {
    clock: &'a RemoteClock,
    nonce_store: &'a DpopNonceStore,
    config: &'a DpopConfig,
}

impl<'a> SenderConstraintVerifier<'a> {
    pub(super) fn new(
        clock: &'a RemoteClock,
        nonce_store: &'a DpopNonceStore,
        config: &'a DpopConfig,
    ) -> Self {
        Self {
            clock,
            nonce_store,
            config,
        }
    }

    pub(super) fn verify_proof(
        &self,
        proof: &DpopProof,
        expected_binding_id: &str,
        expected_target: &str,
        expected_method: &str,
        expected_agent_key: &PublicKey,
    ) -> Result<(), SenderConstraintError> {
        let now = self.clock.seconds()?;
        let expires_at = proof
            .body
            .issued_at
            .checked_add(self.config.proof_ttl_secs)
            .ok_or(ClockError::Overflow)?;
        let latest = now
            .checked_add(self.config.max_clock_skew_secs)
            .ok_or(ClockError::Overflow)?;
        chio_kernel::dpop::validate_dpop_replay_identity(
            &proof.body.nonce,
            &proof.body.capability_id,
        )?;
        if !is_supported_dpop_schema(&proof.body.schema) || proof.body.replay_authority.is_some() {
            return Err(SenderConstraintError::UnsupportedSchema);
        }
        if proof.body.agent_key != *expected_agent_key {
            return Err(SenderConstraintError::SenderKeyMismatch);
        }
        let expected_action_hash = sha256_hex(HTTP_DPOP_ACTION_HASH_EMPTY);
        if proof.body.capability_id != expected_binding_id
            || proof.body.tool_server != expected_target
            || proof.body.tool_name != expected_method
            || proof.body.action_hash != expected_action_hash
        {
            return Err(SenderConstraintError::TargetMismatch);
        }
        if proof.body.nonce.trim().is_empty() {
            return Err(SenderConstraintError::EmptyNonce);
        }
        if proof.body.issued_at > latest {
            return Err(ClockError::NotYetValid.into());
        }
        if now >= expires_at {
            return Err(ClockError::Expired.into());
        }
        let message = canonical_json_bytes(&proof.body)?;
        if !proof.body.agent_key.verify(&message, &proof.signature) {
            return Err(SenderConstraintError::InvalidSignature);
        }
        match self.nonce_store.check_and_insert_through(
            &proof.body.nonce,
            expected_binding_id,
            expires_at,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(SenderConstraintError::NonceReused),
            Err(error) => Err(error.into()),
        }
    }

    pub(super) fn validate(
        &self,
        sender_constraint: Option<&ChioSenderConstraintClaims>,
        headers: &HeaderMap,
        expected_binding_id: Option<&str>,
        expected_target: &str,
        expected_method: &str,
    ) -> Result<(), SenderConstraintError> {
        let Some(sender_constraint) = sender_constraint else {
            return Ok(());
        };

        if let Some(expected_thumbprint) = sender_constraint.mtls_thumbprint_sha256.as_deref() {
            let actual_thumbprint = headers
                .get(CHIO_MTLS_THUMBPRINT_HEADER)
                .map(|value| value.to_str())
                .transpose()?
                .ok_or(SenderConstraintError::MtlsBinding)?;
            if actual_thumbprint != expected_thumbprint {
                return Err(SenderConstraintError::MtlsBinding);
            }
        }
        if let Some(expected_attestation) = sender_constraint.chio_attestation_sha256.as_deref() {
            let actual_attestation = headers
                .get(CHIO_RUNTIME_ATTESTATION_HEADER)
                .map(|value| value.to_str())
                .transpose()?
                .ok_or(SenderConstraintError::AttestationBinding)?;
            if actual_attestation != expected_attestation {
                return Err(SenderConstraintError::AttestationBinding);
            }
        }
        if let Some(sender_key) = sender_constraint.chio_sender_key.as_deref() {
            let binding_id = expected_binding_id.ok_or(SenderConstraintError::MissingBinding)?;
            let proof = headers
                .get(DPOP_HEADER)
                .map(|value| value.to_str())
                .transpose()?
                .ok_or(SenderConstraintError::MissingProof)?;
            let proof = decode_sender_dpop_proof(proof)?;
            let sender_key = PublicKey::from_hex(sender_key)?;
            self.verify_proof(
                &proof,
                binding_id,
                expected_target,
                expected_method,
                &sender_key,
            )?;
        }
        Ok(())
    }
}
