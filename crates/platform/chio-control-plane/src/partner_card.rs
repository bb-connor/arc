//! Pinned federation partner cards.
//!
//! A partner card pins a federation partner's trust-control URL and
//! trust-control authority key, and carries the federation policy this
//! operator applies to that partner. The registry is operator-local trust
//! input: it is validated whole when it loads, and one invalid card refuses
//! the registry.

use std::collections::BTreeMap;
use std::path::Path;

use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use url::Url;

pub const PARTNER_CARD_REGISTRY_SCHEMA: &str = "chio.partner-card-registry.v1";

/// Ceiling on a partner's revocation freshness TTL.
pub const MAX_REVOCATION_FRESHNESS_TTL_SECONDS: u64 = 300;

/// Longest accepted partner id, in bytes.
pub const MAX_PARTNER_ID_BYTES: usize = 64;

const MAX_PARTNER_CARD_REGISTRY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PartnerCardError {
    #[error("partner card registry is unreadable: {0}")]
    Unreadable(String),
    #[error("partner card registry is malformed: {0}")]
    Malformed(String),
    #[error("unsupported partner card registry schema `{0}`")]
    UnsupportedSchema(String),
    #[error("partner card key `{key}` does not match its partnerId `{partner_id}`")]
    KeyMismatch { key: String, partner_id: String },
    #[error(
        "partner id `{0}` must be 1 to 64 bytes of lowercase ASCII letters, digits, `-` or `_`"
    )]
    InvalidPartnerId(String),
    #[error("partner `{partner_id}` trustControlUrl is invalid: {reason}")]
    InvalidTrustControlUrl { partner_id: String, reason: String },
    #[error("partners `{first}` and `{second}` share one trustControlUrl")]
    DuplicateTrustControlUrl { first: String, second: String },
    #[error("partner `{0}` federationPolicy has no revocationFreshnessTtlSeconds")]
    MissingRevocationFreshnessTtl(String),
    #[error(
        "partner `{partner_id}` revocationFreshnessTtlSeconds must be between 1 and {MAX_REVOCATION_FRESHNESS_TTL_SECONDS}, got {ttl}"
    )]
    InvalidRevocationFreshnessTtl { partner_id: String, ttl: u64 },
}

/// The federation policy this operator applies to one partner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartnerFederationPolicy {
    /// Longest age of the partner's signed revocation root this operator
    /// accepts at its door. Required: a card without it is refused at load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_freshness_ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartnerCard {
    pub partner_id: String,
    /// The partner's trust-control base URL, without a trailing slash.
    pub trust_control_url: String,
    /// The partner's trust-control authority key, which signs its published
    /// revocation roots.
    pub authority_public_key: PublicKey,
    pub federation_policy: PartnerFederationPolicy,
}

impl PartnerCard {
    /// The revocation freshness TTL in milliseconds. A card without a TTL
    /// never loads; one built in memory without it accepts no root age.
    #[must_use]
    pub fn revocation_freshness_ttl_ms(&self) -> u64 {
        self.federation_policy
            .revocation_freshness_ttl_seconds
            .unwrap_or(0)
            .saturating_mul(1_000)
    }

    fn validate(&self) -> Result<(), PartnerCardError> {
        validate_partner_id(&self.partner_id)?;
        validate_trust_control_url(&self.partner_id, &self.trust_control_url)?;
        let ttl = self
            .federation_policy
            .revocation_freshness_ttl_seconds
            .ok_or_else(|| {
                PartnerCardError::MissingRevocationFreshnessTtl(self.partner_id.clone())
            })?;
        if ttl == 0 || ttl > MAX_REVOCATION_FRESHNESS_TTL_SECONDS {
            return Err(PartnerCardError::InvalidRevocationFreshnessTtl {
                partner_id: self.partner_id.clone(),
                ttl,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PartnerCardRegistry {
    pub schema: String,
    pub partners: BTreeMap<String, PartnerCard>,
}

impl PartnerCardRegistry {
    /// Loads and validates the registry at `path`. A missing file is refused.
    pub fn load(path: &Path) -> Result<Self, PartnerCardError> {
        let bytes = read_bounded(path)?;
        Self::from_json(&bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, PartnerCardError> {
        let registry: Self = chio_core::canonical::UntrustedJsonText::from_wire(
            bytes,
            MAX_PARTNER_CARD_REGISTRY_BYTES,
        )
        .and_then(|input| input.decode_signed())
        .map_err(|error| PartnerCardError::Malformed(error.to_string()))?;
        registry.validate()?;
        Ok(registry)
    }

    fn validate(&self) -> Result<(), PartnerCardError> {
        if self.schema != PARTNER_CARD_REGISTRY_SCHEMA {
            return Err(PartnerCardError::UnsupportedSchema(self.schema.clone()));
        }
        let mut urls = BTreeMap::new();
        for (key, card) in &self.partners {
            if key != &card.partner_id {
                return Err(PartnerCardError::KeyMismatch {
                    key: key.clone(),
                    partner_id: card.partner_id.clone(),
                });
            }
            card.validate()?;
            if let Some(first) = urls.insert(card.trust_control_url.as_str(), key.as_str()) {
                return Err(PartnerCardError::DuplicateTrustControlUrl {
                    first: first.to_owned(),
                    second: key.clone(),
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, partner_id: &str) -> Option<&PartnerCard> {
        self.partners.get(partner_id)
    }

    /// The card whose trust-control URL is exactly `url`.
    #[must_use]
    pub fn by_trust_control_url(&self, url: &str) -> Option<&PartnerCard> {
        self.partners
            .values()
            .find(|card| card.trust_control_url == url)
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, PartnerCardError> {
    use std::io::Read as _;
    let unreadable = |error: std::io::Error| PartnerCardError::Unreadable(error.to_string());
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut bytes = Vec::new();
    file.take(crate::integer::count(MAX_PARTNER_CARD_REGISTRY_BYTES).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > MAX_PARTNER_CARD_REGISTRY_BYTES {
        return Err(PartnerCardError::Unreadable(format!(
            "registry exceeds {MAX_PARTNER_CARD_REGISTRY_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn validate_partner_id(partner_id: &str) -> Result<(), PartnerCardError> {
    let valid = !partner_id.is_empty()
        && partner_id.len() <= MAX_PARTNER_ID_BYTES
        && partner_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    if valid {
        Ok(())
    } else {
        Err(PartnerCardError::InvalidPartnerId(partner_id.to_owned()))
    }
}

fn validate_trust_control_url(partner_id: &str, url: &str) -> Result<(), PartnerCardError> {
    let invalid = |reason: &str| PartnerCardError::InvalidTrustControlUrl {
        partner_id: partner_id.to_owned(),
        reason: reason.to_owned(),
    };
    let parsed = Url::parse(url).map_err(|error| invalid(&error.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(invalid("scheme must be https"));
    }
    if parsed.host_str().is_none() {
        return Err(invalid("a host is required"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid("userinfo is not allowed"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid("a query or fragment is not allowed"));
    }
    if url.ends_with('/') {
        return Err(invalid("a trailing slash is not allowed"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "partner_card_tests.rs"]
mod tests;
