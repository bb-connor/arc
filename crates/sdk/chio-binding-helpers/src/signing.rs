use serde::{Deserialize, Serialize};

use crate::Result;

/// Wrapped signature over caller JSON under a registered schema id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedJsonSignature {
    pub schema_id: String,
    pub canonical_json: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

fn normalize_hex(value: &str) -> &str {
    value.strip_prefix("0x").unwrap_or(value)
}

#[must_use]
pub fn public_key_hex_matches(left: &str, right: &str) -> bool {
    normalize_hex(left).eq_ignore_ascii_case(normalize_hex(right))
}

#[must_use]
pub fn is_valid_public_key_hex(value: &str) -> bool {
    chio_core::PublicKey::from_hex(value).is_ok()
}

#[must_use]
pub fn is_valid_signature_hex(value: &str) -> bool {
    chio_core::Signature::from_hex(value).is_ok()
}

/// Public key of the Ed25519 seed.
pub fn public_key_from_seed_ed25519(seed_hex: &str) -> Result<String> {
    Ok(chio_core::Keypair::from_seed_hex(seed_hex)?
        .public_key()
        .to_hex())
}

fn json_document(input: &str) -> Result<serde_json::Value> {
    chio_core::canonical::UntrustedJsonText::from_wire(
        input.as_bytes(),
        crate::MAX_JSON_INPUT_BYTES,
    )
    .and_then(|text| text.decode_document())
    .map_err(|error| chio_core::Error::UntrustedInput(error.into()).into())
}

/// Sign the signing wrapper of the canonical form of `input_json` under
/// `schema_id`; an id outside the signed-artifact registry is refused.
pub fn sign_wrapped_json_ed25519(
    schema_id: &str,
    input_json: &str,
    seed_hex: &str,
) -> Result<WrappedJsonSignature> {
    let canonical =
        chio_core::canonical::CanonicalBytes::from_value(&json_document(input_json)?)?;
    let keypair = chio_core::Keypair::from_seed_hex(seed_hex)?;
    let signature = keypair.sign_wrapped(schema_id, &canonical)?;
    let canonical_json = String::from_utf8(canonical.into_vec())
        .map_err(|error| chio_core::Error::CanonicalJson(error.to_string()))?;
    Ok(WrappedJsonSignature {
        schema_id: schema_id.to_owned(),
        canonical_json,
        public_key_hex: keypair.public_key().to_hex(),
        signature_hex: signature.to_hex(),
    })
}

/// Verify a signature over the signing wrapper of the canonical form of
/// `input_json` under `schema_id`.
pub fn verify_wrapped_json(
    schema_id: &str,
    input_json: &str,
    public_key_hex: &str,
    signature_hex: &str,
) -> Result<()> {
    let value = json_document(input_json)?;
    let public_key = chio_core::PublicKey::from_hex(public_key_hex)?;
    let signature = chio_core::Signature::from_hex(signature_hex)?;
    chio_core::crypto::verify_wrapped(&public_key, schema_id, &value, &signature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        public_key_from_seed_ed25519, public_key_hex_matches, sign_wrapped_json_ed25519,
        verify_wrapped_json,
    };
    use crate::Error;

    #[test]
    fn sign_and_verify_wrapped_json() -> crate::Result<()> {
        let seed = "09".repeat(32);
        let signed = sign_wrapped_json_ed25519("chio.receipt.v1", "{\"z\":1,\"a\":2}", &seed)?;
        assert_eq!(signed.canonical_json, "{\"a\":2,\"z\":1}");
        assert_eq!(signed.public_key_hex, public_key_from_seed_ed25519(&seed)?);
        verify_wrapped_json(
            "chio.receipt.v1",
            "{\"z\":1,\"a\":2}",
            &signed.public_key_hex,
            &signed.signature_hex,
        )?;
        assert!(matches!(
            verify_wrapped_json(
                "chio.receipt.v1",
                "{\"z\":2,\"a\":2}",
                &signed.public_key_hex,
                &signed.signature_hex,
            ),
            Err(Error::Core(chio_core::Error::SignatureRejected))
        ));
        assert!(matches!(
            verify_wrapped_json(
                "chio.capability.v1",
                "{\"z\":1,\"a\":2}",
                &signed.public_key_hex,
                &signed.signature_hex,
            ),
            Err(Error::Core(chio_core::Error::SignatureRejected))
        ));
        Ok(())
    }

    #[test]
    fn unregistered_schema_id_refuses() {
        assert!(matches!(
            sign_wrapped_json_ed25519("chio.unregistered-fixture.v1", "{}", &"09".repeat(32)),
            Err(Error::Core(chio_core::Error::UnregisteredSchemaId(ref id)))
                if id == "chio.unregistered-fixture.v1"
        ));
    }

    #[test]
    fn public_key_matching_ignores_case_and_prefix() {
        assert!(public_key_hex_matches("0xABCD", "abcd"));
    }
}
