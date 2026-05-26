//! Pinned Play Integrity verifier key material for deterministic tests.

use base64ct::{Base64UrlUnpadded, Encoding};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sha2::{Digest, Sha256};

const PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgQD37xT23owvinT84
+ExxKy0xQO+5tuDc2Shtda1E68ChRANCAASpOFAhlQgJTPRG/t2cR1ARHHtFQV+e
jEBKw8D82kom7V/wbhjyQdzz8qe9AIH2t6EI6Lr/GOKWstG2k62Vpp0W
-----END PRIVATE KEY-----"#;

const PLAY_INTEGRITY_FIXTURE_X_B64: &str = "qThQIZUICUz0Rv7dnEdQERx7RUFfnoxASsPA_NpKJu0";
const PLAY_INTEGRITY_FIXTURE_Y_B64: &str = "X_BuGPJB3PPyp70Agfa3oQjouv8Y4pay0baTrZWmnRY";

pub const GOOGLE_PLAY_INTEGRITY_ROOT_KID: &str = "chio-play-integrity-fixture-root";
pub const GOOGLE_PLAY_INTEGRITY_ISSUER: &str = "https://playintegrity.googleapis.com";

pub fn play_integrity_decoding_key() -> DecodingKey {
    match DecodingKey::from_ec_components(
        PLAY_INTEGRITY_FIXTURE_X_B64,
        PLAY_INTEGRITY_FIXTURE_Y_B64,
    ) {
        Ok(key) => key,
        Err(error) => panic!("invalid Play Integrity ES256 fixture public key: {error}"),
    }
}

pub fn play_integrity_encoding_key() -> EncodingKey {
    match EncodingKey::from_ec_pem(PLAY_INTEGRITY_FIXTURE_PRIVATE_KEY_PEM) {
        Ok(key) => key,
        Err(error) => panic!("invalid Play Integrity ES256 fixture key: {error}"),
    }
}

#[must_use]
pub fn play_integrity_jwks_json() -> String {
    serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "alg": "ES256",
                "crv": "P-256",
                "kid": GOOGLE_PLAY_INTEGRITY_ROOT_KID,
                "use": "sig",
                "x": PLAY_INTEGRITY_FIXTURE_X_B64,
                "y": PLAY_INTEGRITY_FIXTURE_Y_B64
            }
        ]
    })
    .to_string()
}

#[must_use]
pub fn play_integrity_root_sha256_hex() -> String {
    let mut public_key = match Base64UrlUnpadded::decode_vec(PLAY_INTEGRITY_FIXTURE_X_B64) {
        Ok(bytes) => bytes,
        Err(error) => panic!("invalid Play Integrity ES256 fixture x coordinate: {error}"),
    };
    let y = match Base64UrlUnpadded::decode_vec(PLAY_INTEGRITY_FIXTURE_Y_B64) {
        Ok(bytes) => bytes,
        Err(error) => panic!("invalid Play Integrity ES256 fixture y coordinate: {error}"),
    };
    public_key.extend_from_slice(&y);
    hex::encode(Sha256::digest(public_key))
}
