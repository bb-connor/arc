//! Thin wrappers around ed25519-dalek for signing and verifying canonical JSON.
//!
//! Mirrors the `hush-core` signing API but is self-contained within arc-core
//! so that downstream crates do not need a direct hush-core dependency.

use ed25519_dalek::{
    Signature as DalekSignature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Ed25519 keypair for signing.
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from raw seed bytes (32 bytes).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Create from hex-encoded seed bytes (with optional `0x` prefix).
    pub fn from_seed_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|e| Error::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(Error::InvalidSignature(format!(
                "expected 32-byte seed, got {} bytes",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_seed(&arr))
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature { inner: sig }
    }

    /// Sign a serializable value by converting it to canonical JSON first.
    ///
    /// Returns the signature and the canonical bytes that were signed, so the
    /// caller can store or transmit them alongside the signature.
    pub fn sign_canonical<T: Serialize>(&self, value: &T) -> Result<(Signature, Vec<u8>)> {
        let bytes = canonical_json_bytes(value)?;
        let sig = self.sign(&bytes);
        Ok((sig, bytes))
    }

    #[must_use]
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    #[must_use]
    pub fn seed_hex(&self) -> String {
        hex::encode(self.seed_bytes())
    }
}

// ed25519-dalek's SigningKey implements ZeroizeOnDrop, so private key material
// is automatically zeroed when this struct is dropped.

/// Ed25519 public key for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    verifying_key: VerifyingKey,
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

impl PublicKey {
    /// Create from raw bytes (32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key =
            VerifyingKey::from_bytes(bytes).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// Create from hex-encoded bytes (with optional `0x` prefix).
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|e| Error::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(Error::InvalidPublicKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Verify a signature against a message.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(message, &signature.inner).is_ok()
    }

    /// Verify a signature over the canonical JSON form of a serializable value.
    pub fn verify_canonical<T: Serialize>(&self, value: &T, signature: &Signature) -> Result<bool> {
        let bytes = canonical_json_bytes(value)?;
        Ok(self.verify(&bytes, signature))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }
}

/// Ed25519 signature (64 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    inner: DalekSignature,
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

impl Signature {
    /// Create from raw bytes (64 bytes).
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            inner: DalekSignature::from_bytes(bytes),
        }
    }

    /// Create from hex-encoded bytes (with optional `0x` prefix).
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|e| Error::InvalidHex(e.to_string()))?;
        if bytes.len() != 64 {
            return Err(Error::InvalidSignature(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&arr))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.inner.to_bytes())
    }

    #[must_use]
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }
}

/// Compute SHA-256 of the given bytes, returning the hash as lowercase hex.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Serialize a value to canonical JSON bytes (RFC 8785 / JCS).
///
/// Uses the full RFC 8785 implementation from `crate::canonical`. Object keys
/// are sorted by UTF-16 code unit comparison, numbers follow ECMAScript
/// `JSON.stringify()` rules, and strings use minimal escaping.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    crate::canonical::canonical_json_bytes(value)
}

/// Serialize a value to a canonical JSON string (RFC 8785 / JCS).
pub fn canonical_json_string<T: Serialize>(value: &T) -> Result<String> {
    crate::canonical::canonical_json_string(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let kp = Keypair::generate();
        let msg = b"hello arc";
        let sig = kp.sign(msg);
        assert!(kp.public_key().verify(msg, &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"hello arc");
        assert!(!kp.public_key().verify(b"wrong", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let sig = kp1.sign(b"hello arc");
        assert!(!kp2.public_key().verify(b"hello arc", &sig));
    }

    #[test]
    fn deterministic_from_seed() {
        let seed = [42u8; 32];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);
        assert_eq!(kp1.public_key().to_hex(), kp2.public_key().to_hex());
    }

    #[test]
    fn keypair_seed_hex_roundtrip() {
        let kp = Keypair::generate();
        let restored = Keypair::from_seed_hex(&kp.seed_hex()).unwrap();
        assert_eq!(kp.public_key().to_hex(), restored.public_key().to_hex());
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let kp = Keypair::generate();
        let hex = kp.public_key().to_hex();
        let restored = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(kp.public_key(), restored);
    }

    #[test]
    fn pubkey_hex_with_0x_prefix() {
        let kp = Keypair::generate();
        let hex = format!("0x{}", kp.public_key().to_hex());
        let restored = PublicKey::from_hex(&hex).unwrap();
        assert_eq!(kp.public_key(), restored);
    }

    #[test]
    fn signature_hex_roundtrip() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"test");
        let hex = sig.to_hex();
        let restored = Signature::from_hex(&hex).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn pubkey_serde_roundtrip() {
        let kp = Keypair::generate();
        let pk = kp.public_key();
        let json = serde_json::to_string(&pk).unwrap();
        let restored: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, restored);
    }

    #[test]
    fn signature_serde_roundtrip() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"test");
        let json = serde_json::to_string(&sig).unwrap();
        let restored: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn sign_canonical_roundtrip() {
        let kp = Keypair::generate();
        let value = serde_json::json!({"b": 2, "a": 1});
        let (sig, _bytes) = kp.sign_canonical(&value).unwrap();
        let valid = kp.public_key().verify_canonical(&value, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn canonical_json_key_order() {
        let value = serde_json::json!({"z": 1, "a": 2, "m": 3});
        let s = canonical_json_string(&value).unwrap();
        let a_pos = s.find("\"a\"").unwrap();
        let m_pos = s.find("\"m\"").unwrap();
        let z_pos = s.find("\"z\"").unwrap();
        assert!(a_pos < m_pos);
        assert!(m_pos < z_pos);
    }

    #[test]
    fn sha256_hex_known_value() {
        // SHA-256("hello") is well-known
        assert_eq!(
            sha256_hex(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
