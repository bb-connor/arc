//! Pinned Play Integrity verifier key material.
//!
//! The Play Integrity verifier pins its trust anchor here rather than
//! trusting a caller-supplied JWKS. [`play_integrity_pinned_jwks_json`]
//! returns the JWKS the production verification path uses; the signing key
//! and the caller-supplied-JWKS test helpers below are compiled only under
//! `cfg(test)` or the `dev-fixtures` feature so a shipped binary cannot mint
//! its own Play Integrity tokens or swap in a different verification key.

use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};

use jsonwebtoken::DecodingKey;
#[cfg(any(test, feature = "dev-fixtures"))]
use jsonwebtoken::EncodingKey;

/// Private key for the synthetic Play Integrity signer. Test/dev only:
/// it is the counterpart to the pinned public coordinates so deterministic
/// tests can mint tokens that the pinned verifier accepts. Never compiled
/// into a production binary.
#[cfg(any(test, feature = "dev-fixtures"))]
const PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWTFfCGljY6aw3Hrt
kHmPRiazukxPLb6ilpRAewjW8nihRANCAATDskChT+Altkm9X7MI69T3IUmrQU0L
950IxEzvw/x5BMEINRMrXLBJhqzO9Bm+d6JbqA21YQmd1Kt4RzLJR1W+
-----END PRIVATE KEY-----"#;

/// Pinned Play Integrity verification key (P-256) affine coordinates. The
/// verifier trusts only this key material; in production the caller does
/// not get to supply its own JWKS.
const PLAY_INTEGRITY_PINNED_X_B64: &str = "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ";
const PLAY_INTEGRITY_PINNED_Y_B64: &str = "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4";

pub const GOOGLE_PLAY_INTEGRITY_ROOT_KID: &str = "chio-play-integrity-fixture-root";
pub const GOOGLE_PLAY_INTEGRITY_ISSUER: &str = "https://playintegrity.googleapis.com";

/// Decoding key derived from the pinned Play Integrity public coordinates.
///
/// # Errors
///
/// Returns an error if the embedded pinned coordinates are malformed.
pub fn play_integrity_decoding_key() -> Result<DecodingKey, String> {
    DecodingKey::from_ec_components(PLAY_INTEGRITY_PINNED_X_B64, PLAY_INTEGRITY_PINNED_Y_B64)
        .map_err(|error| format!("invalid pinned Play Integrity P-256 public key: {error}"))
}

/// Encoding key for the synthetic Play Integrity signer. Test/dev only.
///
/// # Errors
///
/// Returns an error if the embedded fixture private key is malformed.
#[cfg(any(test, feature = "dev-fixtures"))]
pub fn play_integrity_encoding_key() -> Result<EncodingKey, String> {
    EncodingKey::from_ec_pem(PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM)
        .map_err(|error| format!("invalid Play Integrity P-256 fixture key: {error}"))
}

/// The pinned Play Integrity JWKS used by the production verification path.
#[must_use]
pub fn play_integrity_pinned_jwks_json() -> String {
    serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "kid": GOOGLE_PLAY_INTEGRITY_ROOT_KID,
                "use": "sig",
                "x": PLAY_INTEGRITY_PINNED_X_B64,
                "y": PLAY_INTEGRITY_PINNED_Y_B64
            }
        ]
    })
    .to_string()
}

/// Backwards-compatible alias used by deterministic tests that need the
/// JWKS the pinned verifier trusts.
#[cfg(any(test, feature = "dev-fixtures"))]
#[must_use]
pub fn play_integrity_jwks_json() -> String {
    play_integrity_pinned_jwks_json()
}

/// SHA-256 fingerprint (hex) of the pinned Play Integrity public point.
///
/// # Errors
///
/// Returns an error if the embedded pinned coordinates are malformed.
pub fn play_integrity_root_sha256_hex() -> Result<String, String> {
    let mut point = Base64UrlUnpadded::decode_vec(PLAY_INTEGRITY_PINNED_X_B64)
        .map_err(|error| format!("invalid pinned Play Integrity x coordinate: {error}"))?;
    let y = Base64UrlUnpadded::decode_vec(PLAY_INTEGRITY_PINNED_Y_B64)
        .map_err(|error| format!("invalid pinned Play Integrity y coordinate: {error}"))?;
    point.extend_from_slice(&y);
    Ok(hex::encode(Sha256::digest(point)))
}
