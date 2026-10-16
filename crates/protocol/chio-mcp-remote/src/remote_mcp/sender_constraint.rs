//! Runtime sender binding verification.
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

/// Validate transport sender bindings. A Chio sender-key confirmation or a
/// presented DPoP proof is refused: this transport holds no durable replay
/// custody for authentication proofs, so neither may degrade to a bearer.
pub(super) fn validate_sender_constraint<'b>(
    sender_constraint: Option<&ChioSenderConstraintClaims>,
    headers: impl Into<SenderRequest<'b>>,
) -> Result<(), SenderConstraintError> {
    let headers = headers.into();
    if headers.get(DPOP_HEADER).is_some() {
        return Err(SenderConstraintError::DpopUnavailable);
    }
    let Some(sender_constraint) = sender_constraint else {
        return Ok(());
    };

    validate_profile(sender_constraint).map_err(|_| SenderConstraintError::UnsupportedSchema)?;
    if sender_constraint.chio_sender_key.is_some() {
        return Err(SenderConstraintError::DpopUnavailable);
    }
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
    Ok(())
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
