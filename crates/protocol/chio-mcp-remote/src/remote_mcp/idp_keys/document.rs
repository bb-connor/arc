//! JWKS document admission.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chio_core::canonical::UntrustedJsonText;
use chio_core::root_authority::{Jwk, JwkCurve, JwkKeyType, JwsAlgorithm};
use serde::Deserialize;
use serde_json::Value;

use super::{MAX_ADMITTED_KEYS, MAX_JWKS_DOCUMENT_BYTES, MIN_RSA_MODULUS_BITS};
use crate::root_exchange::jws::VerifyingKey;

/// Why a JWKS document is refused as a whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum JwksDocumentError {
    #[error("JWKS document has {bytes} bytes, above {MAX_JWKS_DOCUMENT_BYTES}")]
    TooLarge { bytes: usize },
    #[error("JWKS document is not a JSON object with a `keys` array")]
    Malformed,
    #[error("JWKS document has no admissible signing key")]
    NoUsableKeys,
    #[error("JWKS document admits {count} keys, above {MAX_ADMITTED_KEYS}")]
    TooManyKeys { count: usize },
}

/// Members other than `keys` are not read.
#[derive(Deserialize)]
struct JwksDocument {
    keys: Vec<Value>,
}

/// Decode a fetched JWKS document into its admitted keys, ordered by `kid`.
///
/// A key is dropped when it does not decode as a public [`Jwk`], declares a
/// `use` other than `sig`, declares an `alg` its key type cannot carry, is
/// an RSA key with a modulus below [`MIN_RSA_MODULUS_BITS`], or has no
/// verification material the exchange can use ([`VerifyingKey::from_jwk`]:
/// off-curve points, unsupported curves such as P-521). Every key sharing a
/// `kid` with another key is dropped.
pub fn admit_jwks_document(bytes: &[u8]) -> Result<Vec<Jwk>, JwksDocumentError> {
    if bytes.len() > MAX_JWKS_DOCUMENT_BYTES {
        return Err(JwksDocumentError::TooLarge { bytes: bytes.len() });
    }
    let document: JwksDocument = UntrustedJsonText::from_wire(bytes, MAX_JWKS_DOCUMENT_BYTES)
        .map_err(|_| JwksDocumentError::Malformed)?
        .decode_external()
        .map_err(|_| JwksDocumentError::Malformed)?;
    admit_keys(
        document
            .keys
            .iter()
            .filter_map(|value| <Jwk as Deserialize>::deserialize(value).ok())
            .collect(),
    )
}

/// Apply the per-key checks and the set bounds to decoded keys.
pub(super) fn admit_keys(candidates: Vec<Jwk>) -> Result<Vec<Jwk>, JwksDocumentError> {
    let mut by_kid: BTreeMap<String, Option<Jwk>> = BTreeMap::new();
    for key in candidates.into_iter().filter(key_is_admissible) {
        by_kid
            .entry(key.kid.as_str().to_owned())
            .and_modify(|slot| *slot = None)
            .or_insert(Some(key));
    }
    let keys: Vec<Jwk> = by_kid.into_values().flatten().collect();
    if keys.is_empty() {
        return Err(JwksDocumentError::NoUsableKeys);
    }
    if keys.len() > MAX_ADMITTED_KEYS {
        return Err(JwksDocumentError::TooManyKeys { count: keys.len() });
    }
    Ok(keys)
}

fn key_is_admissible(key: &Jwk) -> bool {
    if key.alg.is_some_and(|alg| !key_supports(key, alg)) || VerifyingKey::from_jwk(key).is_none() {
        return false;
    }
    match key.kty {
        JwkKeyType::Rsa => key
            .n
            .as_ref()
            .and_then(|modulus| rsa_modulus_bits(modulus.as_str()))
            .is_some_and(|bits| bits >= MIN_RSA_MODULUS_BITS),
        JwkKeyType::Ec | JwkKeyType::Okp => true,
    }
}

/// Whether `key` has the type and curve that `alg` signs with.
pub(super) fn key_supports(key: &Jwk, alg: JwsAlgorithm) -> bool {
    match alg {
        JwsAlgorithm::RS256
        | JwsAlgorithm::RS384
        | JwsAlgorithm::RS512
        | JwsAlgorithm::PS256
        | JwsAlgorithm::PS384
        | JwsAlgorithm::PS512 => key.kty == JwkKeyType::Rsa,
        JwsAlgorithm::ES256 => key.kty == JwkKeyType::Ec && key.crv == Some(JwkCurve::P256),
        JwsAlgorithm::ES384 => key.kty == JwkKeyType::Ec && key.crv == Some(JwkCurve::P384),
        JwsAlgorithm::ES512 => key.kty == JwkKeyType::Ec && key.crv == Some(JwkCurve::P521),
        JwsAlgorithm::EdDSA => key.kty == JwkKeyType::Okp && key.crv == Some(JwkCurve::Ed25519),
    }
}

/// Significant bits of a base64url big-endian modulus.
fn rsa_modulus_bits(encoded: &str) -> Option<usize> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let start = bytes.iter().position(|byte| *byte != 0)?;
    let leading = bytes.get(start)?.leading_zeros() as usize;
    Some((bytes.len() - start) * 8 - leading)
}
