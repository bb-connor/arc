//! `chio.root-exchange-sign-request.v1` and its response: what an edge asks
//! trust-control to sign, and the checks that authorize it. The request is a
//! closed union of artifact kinds, so no message or byte string can reach a
//! signing key.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKey, Signature};

use super::idp_key_snapshot::{
    IdpKeySnapshot, IdpKeySnapshotFields, IdpKeySnapshotSigningBody, KeySnapshotSource,
    CHIO_IDP_KEY_SNAPSHOT_SCHEMA,
};
use super::jwk::Jwk;
use super::provider_identity::EnterpriseProviderIdentity;
use super::wire::{
    canonical_public_key, check_items, check_schema, validated_type, Identifier, Sha256Digest, Uri,
};
use super::RootAuthorityShapeError;

pub const CHIO_ROOT_EXCHANGE_SIGN_REQUEST_SCHEMA: &str = "chio.root-exchange-sign-request.v1";
pub const CHIO_ROOT_EXCHANGE_SIGN_RESPONSE_SCHEMA: &str = "chio.root-exchange-sign-response.v1";

/// How far `observed_at` may be from the signer's clock.
pub const MAX_SIGN_CLOCK_SKEW_SECS: u64 = 60;

/// The members of [`IdpKeySnapshotBody`]; [`IdpKeySnapshotBody::new`] validates them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdpKeySnapshotBodyFields {
    pub schema: String,
    pub issuer: Uri,
    pub source: KeySnapshotSource,
    pub keys: Vec<Jwk>,
    pub observed_at: u64,
    #[serde(deserialize_with = "canonical_public_key")]
    pub exchange_key: PublicKey,
}

validated_type!(
    /// An unsigned [`IdpKeySnapshot`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    IdpKeySnapshotBody(IdpKeySnapshotBodyFields)
);

impl IdpKeySnapshotBodyFields {
    pub fn validate(&self) -> core::result::Result<(), RootAuthorityShapeError> {
        check_schema(&self.schema, CHIO_IDP_KEY_SNAPSHOT_SCHEMA)?;
        check_items("keys", self.keys.len(), 0, 64)
    }
}

impl IdpKeySnapshotBody {
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

    /// The snapshot members with `signature` attached.
    #[must_use]
    pub fn signed(&self, signature: Signature) -> IdpKeySnapshotFields {
        IdpKeySnapshotFields {
            schema: self.schema.clone(),
            issuer: self.issuer.clone(),
            source: self.source.clone(),
            keys: self.keys.clone(),
            observed_at: self.observed_at,
            exchange_key: self.exchange_key.clone(),
            signature,
        }
    }
}

/// What an edge asks trust-control to sign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RootExchangeSignRequest {
    IdpKeySnapshot {
        provider_record_id: Identifier,
        provider_identity_digest: Sha256Digest,
        body: IdpKeySnapshotBody,
    },
}

/// The signed artifact, under the signing id its kind fixes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RootExchangeSignResponse {
    IdpKeySnapshot {
        schema: String,
        artifact: IdpKeySnapshot,
    },
}

impl RootExchangeSignResponse {
    #[must_use]
    pub fn idp_key_snapshot(artifact: IdpKeySnapshot) -> Self {
        Self::IdpKeySnapshot {
            schema: CHIO_IDP_KEY_SNAPSHOT_SCHEMA.to_string(),
            artifact,
        }
    }
}

/// Why trust-control refuses to sign. Every refusal precedes the signing call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootExchangeSignRefusal {
    ProviderRecordUnknown,
    ProviderRecordDisabled,
    ProviderIdentityMismatch,
    IssuerMismatch,
    SourceMismatch,
    InlineKeysMismatch,
    ForeignExchangeKey,
    ObservedAtOutsideSkew { observed_at: u64, now: u64 },
    Canonicalization(String),
}

impl fmt::Display for RootExchangeSignRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderRecordUnknown => formatter.write_str("provider record is unknown"),
            Self::ProviderRecordDisabled => formatter.write_str("provider record is disabled"),
            Self::ProviderIdentityMismatch => {
                formatter.write_str("provider identity digest differs from the record")
            }
            Self::IssuerMismatch => formatter.write_str("snapshot issuer differs from the record"),
            Self::SourceMismatch => {
                formatter.write_str("snapshot source differs from the record's trust material")
            }
            Self::InlineKeysMismatch => {
                formatter.write_str("snapshot keys differ from the record's inline keys")
            }
            Self::ForeignExchangeKey => {
                formatter.write_str("snapshot exchange_key is not the current exchange key")
            }
            Self::ObservedAtOutsideSkew { observed_at, now } => write!(
                formatter,
                "snapshot observed_at {observed_at} is outside the allowed skew of {now}"
            ),
            Self::Canonicalization(error) => {
                write!(formatter, "sign request canonicalization failed: {error}")
            }
        }
    }
}

impl core::error::Error for RootExchangeSignRefusal {}

/// Authorize signing `body` for the enabled record whose projection is
/// `identity`. `edge_identity_digest` is the digest the edge pinned;
/// `exchange_key` is the signer's current key.
pub fn check_snapshot_sign(
    body: &IdpKeySnapshotBody,
    identity: &EnterpriseProviderIdentity,
    edge_identity_digest: &Sha256Digest,
    exchange_key: &PublicKey,
    now: u64,
) -> core::result::Result<(), RootExchangeSignRefusal> {
    let digest = identity
        .digest()
        .map_err(|error| RootExchangeSignRefusal::Canonicalization(error.to_string()))?;
    if &digest != edge_identity_digest {
        return Err(RootExchangeSignRefusal::ProviderIdentityMismatch);
    }
    if body.issuer != identity.issuer {
        return Err(RootExchangeSignRefusal::IssuerMismatch);
    }
    match (&identity.jwks_url, &identity.jwks, &body.source) {
        (Some(record_url), None, KeySnapshotSource::JwksUrl(url)) if url == record_url => {}
        (None, Some(jwks), KeySnapshotSource::Registry(provider_id))
            if provider_id == identity.provider_id.as_str() =>
        {
            if body.keys != jwks.keys {
                return Err(RootExchangeSignRefusal::InlineKeysMismatch);
            }
        }
        _ => return Err(RootExchangeSignRefusal::SourceMismatch),
    }
    if &body.exchange_key != exchange_key {
        return Err(RootExchangeSignRefusal::ForeignExchangeKey);
    }
    if body.observed_at.abs_diff(now) > MAX_SIGN_CLOCK_SKEW_SECS {
        return Err(RootExchangeSignRefusal::ObservedAtOutsideSkew {
            observed_at: body.observed_at,
            now,
        });
    }
    Ok(())
}
