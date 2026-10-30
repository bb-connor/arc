//! `chio.idp-key-snapshot.v1`: the key set the exchange observed for one provider record.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{PublicKey, Signature};

use super::jwk::Jwk;
use super::wire::{
    canonical_public_key, canonical_signature, check_items, check_schema, validated_type, HttpsUrl,
    Sha256Digest, Uri,
};
use super::RootAuthorityShapeError;

pub const CHIO_IDP_KEY_SNAPSHOT_SCHEMA: &str = "chio.idp-key-snapshot.v1";

/// Domain prefix of a key snapshot digest.
pub const IDP_KEY_SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"chio.idp-key-snapshot.v1\0";

const REGISTRY_SOURCE_PREFIX: &str = "registry:";

/// Where the key set came from: the record's `jwks_url`, or
/// `registry:<provider_id>` for a record with an inline `jwks`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeySnapshotSource {
    JwksUrl(HttpsUrl),
    Registry(String),
}

impl KeySnapshotSource {
    pub fn parse(value: &str) -> core::result::Result<Self, RootAuthorityShapeError> {
        if let Some(provider_id) = value.strip_prefix(REGISTRY_SOURCE_PREFIX) {
            let length = provider_id.chars().count();
            if length == 0
                || length > 128
                || provider_id.chars().any(|character| {
                    character == '\0' || character.is_whitespace() || character == '\u{feff}'
                })
            {
                return Err(RootAuthorityShapeError::Pattern {
                    field: "source",
                    expected: "registry:<1 to 128 characters without NUL or whitespace>",
                });
            }
            return Ok(Self::Registry(provider_id.into()));
        }
        HttpsUrl::new(value)
            .map(Self::JwksUrl)
            .map_err(|_| RootAuthorityShapeError::Pattern {
                field: "source",
                expected: "an https:// JWKS URL or registry:<provider_id>",
            })
    }
}

impl Serialize for KeySnapshotSource {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        match self {
            Self::JwksUrl(url) => url.serialize(serializer),
            Self::Registry(provider_id) => {
                let mut text = String::from(REGISTRY_SOURCE_PREFIX);
                text.push_str(provider_id);
                serializer.serialize_str(&text)
            }
        }
    }
}

impl<'de> Deserialize<'de> for KeySnapshotSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// The members of [`IdpKeySnapshot`]; [`IdpKeySnapshot::new`] validates them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdpKeySnapshotFields {
    pub schema: String,
    pub issuer: Uri,
    pub source: KeySnapshotSource,
    pub keys: Vec<Jwk>,
    pub observed_at: u64,
    #[serde(deserialize_with = "canonical_public_key")]
    pub exchange_key: PublicKey,
    #[serde(deserialize_with = "canonical_signature")]
    pub signature: Signature,
}

validated_type!(
    /// The provider's signed statement of the keys an identity provider published.
    #[derive(Debug, Clone, PartialEq, Eq)]
    IdpKeySnapshot(IdpKeySnapshotFields)
);

/// Every snapshot member except `signature`.
#[derive(Serialize)]
pub struct IdpKeySnapshotSigningBody<'a> {
    pub schema: &'a str,
    pub issuer: &'a Uri,
    pub source: &'a KeySnapshotSource,
    pub keys: &'a [Jwk],
    pub observed_at: u64,
    pub exchange_key: &'a PublicKey,
}

impl IdpKeySnapshotFields {
    pub fn validate(&self) -> core::result::Result<(), RootAuthorityShapeError> {
        check_schema(&self.schema, CHIO_IDP_KEY_SNAPSHOT_SCHEMA)?;
        check_items("keys", self.keys.len(), 0, 64)
    }
}

impl IdpKeySnapshot {
    #[must_use]
    pub fn signing_body(&self) -> IdpKeySnapshotSigningBody<'_> {
        IdpKeySnapshotSigningBody {
            schema: &self.schema,
            issuer: &self.issuer,
            source: &self.source,
            keys: &self.keys,
            observed_at: self.observed_at,
            exchange_key: &self.exchange_key,
        }
    }

    /// `SHA-256("chio.idp-key-snapshot.v1\0" || canonical_json(snapshot))`, signature
    /// included; the `key_snapshot_digest` a delegation context names.
    pub fn digest(&self) -> crate::error::Result<Sha256Digest> {
        let canonical = crate::canonical::canonical_json_bytes(self)?;
        Ok(Sha256Digest::of_domain(
            IDP_KEY_SNAPSHOT_DIGEST_DOMAIN,
            &canonical,
        ))
    }

    /// Verify `signature` over the signing body under `pinned_exchange_key`,
    /// which `exchange_key` must equal.
    pub fn verify_signature(
        &self,
        pinned_exchange_key: &PublicKey,
    ) -> core::result::Result<(), IdpKeySnapshotSignatureError> {
        if &self.exchange_key != pinned_exchange_key {
            return Err(IdpKeySnapshotSignatureError::ExchangeKeyNotPinned);
        }
        match crate::crypto::verify_wrapped(
            pinned_exchange_key,
            super::CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
            &self.signing_body(),
            &self.signature,
        ) {
            Ok(()) => Ok(()),
            Err(crate::error::Error::SignatureRejected) => {
                Err(IdpKeySnapshotSignatureError::InvalidSignature)
            }
            Err(error) => Err(IdpKeySnapshotSignatureError::Canonicalization(
                error.to_string(),
            )),
        }
    }
}

/// Why a key snapshot signature is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdpKeySnapshotSignatureError {
    /// `exchange_key` is not the pinned exchange key.
    ExchangeKeyNotPinned,
    /// The signature does not verify under the pinned exchange key.
    InvalidSignature,
    Canonicalization(String),
}

impl core::fmt::Display for IdpKeySnapshotSignatureError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ExchangeKeyNotPinned => {
                formatter.write_str("key snapshot exchange_key is not the pinned exchange key")
            }
            Self::InvalidSignature => formatter.write_str("key snapshot signature is invalid"),
            Self::Canonicalization(error) => {
                write!(formatter, "key snapshot canonicalization failed: {error}")
            }
        }
    }
}

impl core::error::Error for IdpKeySnapshotSignatureError {}
