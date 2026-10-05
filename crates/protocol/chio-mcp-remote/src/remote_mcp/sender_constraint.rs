//! Runtime sender binding and original DPoP proof verification.
use super::*;

/// Sender keys identify a signing authority, so decoding must reject keys
/// whose small-order group admits signatures without a private key.
pub(super) fn decode_sender_key(raw: &str) -> Result<PublicKey, chio_core::error::Error> {
    let key = PublicKey::from_hex(raw)?;
    if key.is_weak_ed25519() {
        return Err(chio_core::error::Error::InvalidPublicKey(
            "weak Ed25519 sender key".into(),
        ));
    }
    Ok(key)
}

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
        if !proof
            .body
            .agent_key
            .verify_strict(&message, &proof.signature)
        {
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

    pub(super) fn validate<'b>(
        &self,
        sender_constraint: Option<&ChioSenderConstraintClaims>,
        headers: impl Into<SenderRequest<'b>>,
        expected_binding_id: Option<&str>,
        expected_target: &str,
        expected_method: &str,
    ) -> Result<(), SenderConstraintError> {
        let headers = headers.into();
        let Some(sender_constraint) = sender_constraint else {
            return Ok(());
        };

        validate_profile(sender_constraint)
            .map_err(|_| SenderConstraintError::UnsupportedSchema)?;

        if let Some(expected_thumbprint) = sender_constraint.mtls_thumbprint_sha256.as_deref() {
            let actual_thumbprint = headers
                .transport()
                .and_then(TransportIdentity::mtls)
                .ok_or(SenderConstraintError::MtlsBinding)?;
            if actual_thumbprint != expected_thumbprint {
                return Err(SenderConstraintError::MtlsBinding);
            }
        }
        if let Some(expected_attestation) = sender_constraint.chio_attestation_sha256.as_deref() {
            let actual_attestation = headers
                .transport()
                .and_then(TransportIdentity::attestation)
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
            let sender_key = decode_sender_key(sender_key)?;
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

/// Closed confirmation profile. Missing fields differ from explicit null values.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfirmationWire {
    #[serde(default, rename = "chioSenderKey", deserialize_with = "nonempty_field")]
    sender: Option<String>,
    #[serde(default, rename = "x5t#S256", deserialize_with = "nonempty_field")]
    mtls: Option<String>,
    #[serde(
        default,
        rename = "chioAttestationSha256",
        deserialize_with = "nonempty_field"
    )]
    attestation: Option<String>,
}
fn nonempty_field<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = <String as serde::Deserialize>::deserialize(deserializer)?;
    if value.is_empty() || value.len() > 256 || !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(serde::de::Error::custom(
            "invalid sender confirmation field",
        ));
    }
    Ok(Some(value))
}
impl TryFrom<ConfirmationWire> for ChioSenderConstraintClaims {
    type Error = &'static str;
    fn try_from(wire: ConfirmationWire) -> Result<Self, Self::Error> {
        let claims = Self {
            chio_sender_key: wire.sender,
            mtls_thumbprint_sha256: wire.mtls,
            chio_attestation_sha256: wire.attestation,
        };
        validate_profile(&claims)?;
        Ok(claims)
    }
}
fn validate_profile(claims: &ChioSenderConstraintClaims) -> Result<(), &'static str> {
    if claims.is_empty() {
        return Err("empty sender confirmation");
    }
    if claims.chio_attestation_sha256.is_some()
        && claims.chio_sender_key.is_none()
        && claims.mtls_thumbprint_sha256.is_none()
    {
        return Err("attestation requires sender key or TLS binding");
    }
    for field in [
        &claims.chio_sender_key,
        &claims.mtls_thumbprint_sha256,
        &claims.chio_attestation_sha256,
    ]
    .into_iter()
    .flatten()
    {
        if field.is_empty()
            || field.len() > 256
            || !field.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("invalid sender confirmation field");
        }
    }
    if let Some(key) = &claims.chio_sender_key {
        decode_sender_key(key).map_err(|_| "invalid sender key")?;
    }
    Ok(())
}
pub(super) fn deserialize_confirmation<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ChioSenderConstraintClaims>, D::Error> {
    <ChioSenderConstraintClaims as serde::Deserialize>::deserialize(deserializer).map(Some)
}

pub(super) fn validate_attestation_context(
    claims: &JwtClaims,
) -> Result<(), SenderConstraintError> {
    if let Some(expected) = claims
        .cnf
        .as_ref()
        .and_then(|cnf| cnf.chio_attestation_sha256.as_deref())
    {
        let actual = claims
            .chio_transaction_context
            .as_ref()
            .and_then(|context| context.get("runtimeAssuranceEvidenceSha256"))
            .and_then(Value::as_str);
        if actual != Some(expected) {
            return Err(SenderConstraintError::AttestationBinding);
        }
    }
    Ok(())
}
