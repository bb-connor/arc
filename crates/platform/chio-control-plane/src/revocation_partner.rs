//! The federation revocation partner registry.
//!
//! Each entry names a federation partner whose passport revocations this
//! operator mirrors: the partner's credential issuer URL, the trust-control
//! authority key that signs its revocation roots, and the freshness TTL this
//! operator applies to those roots. The registry is operator-local trust input,
//! read per use under a size bound and validated whole: one invalid entry
//! refuses the registry.

use std::collections::BTreeMap;
use std::path::Path;

use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use url::Url;

pub const REVOCATION_PARTNER_REGISTRY_SCHEMA: &str = "chio.revocation-partner-registry.v1";

/// Ceiling on a partner's revocation freshness TTL.
pub const MAX_REVOCATION_FRESHNESS_TTL_SECONDS: u64 = 300;

/// Longest accepted partner id, in bytes.
pub const MAX_PARTNER_ID_BYTES: usize = 64;

const MAX_REVOCATION_PARTNER_REGISTRY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevocationPartnerError {
    #[error("revocation partner registry is unreadable: {0}")]
    Unreadable(String),
    #[error("revocation partner registry is malformed: {0}")]
    Malformed(String),
    #[error("unsupported revocation partner registry schema `{0}`")]
    UnsupportedSchema(String),
    #[error("registry key `{key}` does not match its partnerId `{partner_id}`")]
    KeyMismatch { key: String, partner_id: String },
    #[error(
        "partner id `{0}` must be 1 to 64 bytes of lowercase ASCII letters, digits, `-` or `_`"
    )]
    InvalidPartnerId(String),
    #[error("partner `{partner_id}` issuer is invalid: {reason}")]
    InvalidIssuer { partner_id: String, reason: String },
    #[error("partners `{first}` and `{second}` share one issuer")]
    DuplicateIssuer { first: String, second: String },
    #[error("partner `{0}` has no revocationFreshnessTtlSeconds")]
    MissingRevocationFreshnessTtl(String),
    #[error(
        "partner `{partner_id}` revocationFreshnessTtlSeconds must be between 1 and {MAX_REVOCATION_FRESHNESS_TTL_SECONDS}, got {ttl}"
    )]
    InvalidRevocationFreshnessTtl { partner_id: String, ttl: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationPartner {
    pub partner_id: String,
    /// The partner's credential issuer URL, without a trailing slash: the
    /// signed `iss` of the passports it issues and the base of its
    /// revocation feed.
    pub issuer: String,
    /// The partner's trust-control authority key, which signs its published
    /// revocation roots.
    pub authority_public_key: PublicKey,
    /// Longest age of the partner's signed revocation root this operator
    /// accepts at its door. Required: an entry without it is refused at load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_freshness_ttl_seconds: Option<u64>,
}

impl RevocationPartner {
    /// The revocation freshness TTL in milliseconds. A partner without a TTL
    /// never loads; one built in memory without it accepts no root age.
    #[must_use]
    pub fn revocation_freshness_ttl_ms(&self) -> u64 {
        self.revocation_freshness_ttl_seconds
            .unwrap_or(0)
            .saturating_mul(1_000)
    }

    fn validate(&self) -> Result<(), RevocationPartnerError> {
        validate_partner_id(&self.partner_id)?;
        validate_issuer(&self.partner_id, &self.issuer)?;
        let ttl = self.revocation_freshness_ttl_seconds.ok_or_else(|| {
            RevocationPartnerError::MissingRevocationFreshnessTtl(self.partner_id.clone())
        })?;
        if ttl == 0 || ttl > MAX_REVOCATION_FRESHNESS_TTL_SECONDS {
            return Err(RevocationPartnerError::InvalidRevocationFreshnessTtl {
                partner_id: self.partner_id.clone(),
                ttl,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationPartnerRegistry {
    pub schema: String,
    pub partners: BTreeMap<String, RevocationPartner>,
}

impl RevocationPartnerRegistry {
    /// Loads and validates the registry at `path`. A missing file is refused.
    pub fn load(path: &Path) -> Result<Self, RevocationPartnerError> {
        let bytes = read_bounded(path)?;
        Self::from_json(&bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, RevocationPartnerError> {
        let registry: Self = chio_core::canonical::UntrustedJsonText::from_wire(
            bytes,
            MAX_REVOCATION_PARTNER_REGISTRY_BYTES,
        )
        .and_then(|input| input.decode_signed())
        .map_err(|error| RevocationPartnerError::Malformed(error.to_string()))?;
        registry.validate()?;
        Ok(registry)
    }

    fn validate(&self) -> Result<(), RevocationPartnerError> {
        if self.schema != REVOCATION_PARTNER_REGISTRY_SCHEMA {
            return Err(RevocationPartnerError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        let mut urls = BTreeMap::new();
        for (key, partner) in &self.partners {
            if key != &partner.partner_id {
                return Err(RevocationPartnerError::KeyMismatch {
                    key: key.clone(),
                    partner_id: partner.partner_id.clone(),
                });
            }
            partner.validate()?;
            if let Some(first) = urls.insert(partner.issuer.as_str(), key.as_str()) {
                return Err(RevocationPartnerError::DuplicateIssuer {
                    first: first.to_owned(),
                    second: key.clone(),
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, partner_id: &str) -> Option<&RevocationPartner> {
        self.partners.get(partner_id)
    }

    /// The partner whose trust-control URL is exactly `url`.
    #[must_use]
    pub fn by_issuer(&self, url: &str) -> Option<&RevocationPartner> {
        self.partners.values().find(|partner| partner.issuer == url)
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, RevocationPartnerError> {
    use std::io::Read as _;
    let unreadable = |error: std::io::Error| RevocationPartnerError::Unreadable(error.to_string());
    let file = std::fs::File::open(path).map_err(unreadable)?;
    let mut bytes = Vec::new();
    file.take(crate::integer::count(MAX_REVOCATION_PARTNER_REGISTRY_BYTES).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(unreadable)?;
    if bytes.len() > MAX_REVOCATION_PARTNER_REGISTRY_BYTES {
        return Err(RevocationPartnerError::Unreadable(format!(
            "registry exceeds {MAX_REVOCATION_PARTNER_REGISTRY_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

fn validate_partner_id(partner_id: &str) -> Result<(), RevocationPartnerError> {
    let valid = !partner_id.is_empty()
        && partner_id.len() <= MAX_PARTNER_ID_BYTES
        && partner_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        });
    if valid {
        Ok(())
    } else {
        Err(RevocationPartnerError::InvalidPartnerId(
            partner_id.to_owned(),
        ))
    }
}

fn validate_issuer(partner_id: &str, url: &str) -> Result<(), RevocationPartnerError> {
    let invalid = |reason: &str| RevocationPartnerError::InvalidIssuer {
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
#[path = "revocation_partner_tests.rs"]
mod tests;
