//! Public keys accepted as signature verifiers.

use alloc::string::{String, ToString};

use serde::{Deserialize, Serialize};

use super::{PublicKey, SharedCanonicalBytes, Signature, SigningAlgorithm};
use crate::canonical::{CanonicalBytes, CanonicalJsonWitness};
use crate::error::{Error, Result};

/// A public key accepted as a signature verifier.
///
/// Construction rejects weak (small-order) Ed25519 material, including the
/// classical half of a hybrid key, with [`Error::InvalidPublicKey`]. A key
/// that identifies a trust anchor, pinned signer or artifact issuer is held
/// as this type so the rejection happens once, when the key is accepted,
/// rather than at each verifier. Verification applies the strict rules of
/// [`PublicKey::verify`]. Serialization is identical to [`PublicKey`];
/// deserialization rejects weak keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPublicKey {
    key: PublicKey,
}

impl TrustedPublicKey {
    /// Accept `key` as a verifier.
    ///
    /// Fails with [`Error::InvalidPublicKey`] when the key carries weak
    /// Ed25519 material.
    pub fn new(key: PublicKey) -> Result<Self> {
        if key.is_weak_ed25519() {
            return Err(Error::InvalidPublicKey(
                "weak (small-order) Ed25519 public key".to_string(),
            ));
        }
        Ok(Self { key })
    }

    /// Accept `key` as a verifier that must be an Ed25519 key.
    ///
    /// Fails with [`Error::InvalidPublicKey`] for any other algorithm or a
    /// weak key.
    pub fn new_ed25519(key: PublicKey) -> Result<Self> {
        if key.algorithm() != SigningAlgorithm::Ed25519 {
            return Err(Error::InvalidPublicKey(
                "Ed25519 public key required".to_string(),
            ));
        }
        Self::new(key)
    }

    /// Parse a hex-encoded public key and accept it as a verifier.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        Self::new(PublicKey::from_hex(hex_str)?)
    }

    /// The accepted public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// Unwrap the accepted public key.
    #[must_use]
    pub fn into_public_key(self) -> PublicKey {
        self.key
    }

    /// Which algorithm this public key belongs to.
    #[must_use]
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.key.algorithm()
    }

    /// Hex encoding, identical to [`PublicKey::to_hex`].
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.key.to_hex()
    }

    /// Verify a signature against a message with [`PublicKey::verify`].
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.key.verify(message, signature)
    }

    /// Verify a signature over the canonical JSON form of `value`.
    pub fn verify_canonical<T: Serialize>(&self, value: &T, signature: &Signature) -> Result<bool> {
        self.key.verify_canonical(value, signature)
    }

    /// Verify a signature over shared canonical JSON bytes.
    #[must_use]
    pub fn verify_shared_canonical(
        &self,
        canonical: &SharedCanonicalBytes,
        signature: &Signature,
    ) -> bool {
        self.key.verify_shared_canonical(canonical, signature)
    }

    /// Verify a signature over canonical JSON bytes without reserializing.
    #[must_use]
    pub fn verify_canonical_bytes(
        &self,
        canonical: &CanonicalBytes<CanonicalJsonWitness>,
        signature: &Signature,
    ) -> bool {
        self.key.verify_canonical_bytes(canonical, signature)
    }
}

impl TryFrom<PublicKey> for TrustedPublicKey {
    type Error = Error;

    fn try_from(key: PublicKey) -> Result<Self> {
        Self::new(key)
    }
}

impl From<TrustedPublicKey> for PublicKey {
    fn from(key: TrustedPublicKey) -> Self {
        key.key
    }
}

impl AsRef<PublicKey> for TrustedPublicKey {
    fn as_ref(&self) -> &PublicKey {
        &self.key
    }
}

impl Serialize for TrustedPublicKey {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.key.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrustedPublicKey {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let key = PublicKey::deserialize(deserializer)?;
        Self::new(key).map_err(serde::de::Error::custom)
    }
}
