use base64::Engine as _;
use chio_core::Signature;
use serde_json::Value;

use crate::CredentialError;

pub(super) const MAX_JSON_BYTES: usize = 1024 * 1024;
pub(super) const MAX_ENCODED_JSON_BYTES: usize = MAX_JSON_BYTES.div_ceil(3) * 4;

pub(super) fn decode_compact_jwt_without_signature<F>(
    compact: &str,
    label: &str,
    error_mapper: F,
) -> Result<(Value, Value, String, Signature), CredentialError>
where
    F: Fn(String) -> CredentialError,
{
    // Bound each segment before base64 decoding or copying the signed preimage.
    let parts = compact.split('.').take(4).collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(error_mapper(format!(
            "{label} JWT must contain exactly three compact segments"
        )));
    }
    for (part, name, max_encoded) in [
        (parts[0], "header", MAX_ENCODED_JSON_BYTES),
        (parts[1], "payload", MAX_ENCODED_JSON_BYTES),
        (parts[2], "signature", 86),
    ] {
        if part.len() > max_encoded {
            return Err(error_mapper(format!(
                "{label} JWT {name} exceeds size limit"
            )));
        }
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|error| {
            error_mapper(format!(
                "{label} JWT header is not valid base64url: {error}"
            ))
        })?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|error| {
            error_mapper(format!(
                "{label} JWT payload is not valid base64url: {error}"
            ))
        })?;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|error| {
            error_mapper(format!(
                "{label} JWT signature is not valid base64url: {error}"
            ))
        })?;
    if signature_bytes.len() != 64 {
        return Err(error_mapper(format!(
            "{label} JWT signature must decode to 64 bytes, got {}",
            signature_bytes.len()
        )));
    }
    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);
    let header = chio_core::canonical::UntrustedJsonText::from_wire(&header_bytes, MAX_JSON_BYTES)
        .and_then(|input| input.decode_signed())
        .map_err(|error| error_mapper(format!("{label} JWT header is not valid JSON: {error}")))?;
    let payload =
        chio_core::canonical::UntrustedJsonText::from_wire(&payload_bytes, MAX_JSON_BYTES)
            .and_then(|input| input.decode_signed())
            .map_err(|error| {
                error_mapper(format!("{label} JWT payload is not valid JSON: {error}"))
            })?;
    Ok((
        header,
        payload,
        signing_input,
        Signature::from_bytes(&signature_array),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_jwt_bounds_segments_before_base64_allocation() {
        let key = crate::Keypair::from_seed(&[37; 32]);
        let compact = crate::sign_jwt_value("JWT", &serde_json::json!({"sub": "a"}), &key)
            .expect("sign valid JWT");
        let decode = |value: &str| {
            decode_compact_jwt_without_signature(
                value,
                "test",
                CredentialError::InvalidOid4vpResponse,
            )
        };
        let (_, payload, signing_input, signature) = decode(&compact).expect("valid JWT");
        assert_eq!(payload["sub"], "a");
        assert!(key
            .public_key()
            .verify(signing_input.as_bytes(), &signature));

        let original: Vec<_> = compact.split('.').collect();
        for (index, name, max) in [
            (0, "header", MAX_ENCODED_JSON_BYTES),
            (1, "payload", MAX_ENCODED_JSON_BYTES),
            (2, "signature", 86),
        ] {
            let oversized = "!".repeat(max + 1);
            let mut parts = original.clone();
            parts[index] = &oversized;
            let error = decode(&parts.join(".")).expect_err("oversized segment");
            assert!(error
                .to_string()
                .contains(&format!("{name} exceeds size limit")));
        }
    }
}
