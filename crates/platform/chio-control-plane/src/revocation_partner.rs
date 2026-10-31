//! The federation revocation partner registry.
//!
//! Each entry names a federation partner whose passport revocations this
//! operator mirrors: the partner's credential issuer URL, the trust-control
//! authority key that signs its revocation roots, every key the partner has
//! issued passport credentials under, and the freshness TTL this operator
//! applies to those roots. The registry is operator-local trust input, read per
//! use under a size bound and validated whole: one invalid entry refuses the
//! registry.

use std::collections::BTreeMap;
use std::path::Path;

use chio_core::crypto::PublicKey;
use chio_did::DidChio;
use serde::{Deserialize, Serialize};
use url::Url;

pub const REVOCATION_PARTNER_REGISTRY_SCHEMA: &str = "chio.revocation-partner-registry.v1";

/// Ceiling on a partner's revocation freshness TTL.
pub const MAX_REVOCATION_FRESHNESS_TTL_SECONDS: u64 = 300;

/// Longest accepted partner id, in bytes.
pub const MAX_PARTNER_ID_BYTES: usize = 64;

/// Most credential issuer keys one partner lists.
pub const MAX_PARTNER_ISSUER_KEYS: usize = 8;

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
    #[error("presented issuer `{issuer}` is malformed: {reason}")]
    MalformedPresentedIssuer { issuer: String, reason: String },
    #[error("partners `{first}` and `{second}` share one issuer")]
    DuplicateIssuer { first: String, second: String },
    #[error("partner `{0}` lists a key that is not an Ed25519 key")]
    UnsupportedKey(String),
    #[error(
        "partner `{partner_id}` must list 1 to {MAX_PARTNER_ISSUER_KEYS} issuerPublicKeys, got {count}"
    )]
    IssuerKeyCount { partner_id: String, count: usize },
    #[error("partner `{0}` issuerPublicKeys must include its authorityPublicKey")]
    AuthorityKeyNotAnIssuerKey(String),
    #[error("partner `{0}` lists one issuer key twice")]
    RepeatedIssuerKey(String),
    #[error("partners `{first}` and `{second}` share one key")]
    DuplicateIssuerKey { first: String, second: String },
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
    /// Every key the partner signs native passport credentials under,
    /// including retired keys whose credentials are still presented. Lists
    /// the authority key.
    pub issuer_public_keys: Vec<PublicKey>,
    /// Longest age of the partner's signed revocation root this operator
    /// accepts at its door.
    pub revocation_freshness_ttl_seconds: u64,
}

impl RevocationPartner {
    #[must_use]
    pub fn revocation_freshness_ttl_ms(&self) -> u64 {
        self.revocation_freshness_ttl_seconds.saturating_mul(1_000)
    }

    /// The `did:chio` of every issuer key: the issuer DIDs of the native
    /// passport credentials this partner signs.
    pub fn issuer_dids(&self) -> Result<Vec<String>, RevocationPartnerError> {
        self.issuer_public_keys
            .iter()
            .map(|key| {
                DidChio::from_public_key(key.clone())
                    .map(|did| did.to_string())
                    .map_err(|_| RevocationPartnerError::UnsupportedKey(self.partner_id.clone()))
            })
            .collect()
    }

    /// Every distinct key the entry names, as hex.
    fn keys(&self) -> Vec<String> {
        let mut keys = self
            .issuer_public_keys
            .iter()
            .map(PublicKey::to_hex)
            .collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        keys
    }

    fn validate(&self) -> Result<(), RevocationPartnerError> {
        validate_partner_id(&self.partner_id)?;
        validate_issuer(&self.partner_id, &self.issuer)?;
        DidChio::from_public_key(self.authority_public_key.clone())
            .map_err(|_| RevocationPartnerError::UnsupportedKey(self.partner_id.clone()))?;
        let count = self.issuer_public_keys.len();
        if count == 0 || count > MAX_PARTNER_ISSUER_KEYS {
            return Err(RevocationPartnerError::IssuerKeyCount {
                partner_id: self.partner_id.clone(),
                count,
            });
        }
        if !self.issuer_public_keys.contains(&self.authority_public_key) {
            return Err(RevocationPartnerError::AuthorityKeyNotAnIssuerKey(
                self.partner_id.clone(),
            ));
        }
        if self.keys().len() != count {
            return Err(RevocationPartnerError::RepeatedIssuerKey(
                self.partner_id.clone(),
            ));
        }
        self.issuer_dids()?;
        let ttl = self.revocation_freshness_ttl_seconds;
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
    /// Loads and validates the registry at `path` through the shared bounded
    /// registry reader. A missing, oversized or invalid file is refused.
    pub fn load(path: &Path) -> Result<Self, RevocationPartnerError> {
        let bytes =
            crate::signed_input::read_bounded(path).map_err(
                |error| match crate::CliError::from(error) {
                    crate::CliError::File(error) => {
                        RevocationPartnerError::Unreadable(error.to_string())
                    }
                    error => RevocationPartnerError::Malformed(error.to_string()),
                },
            )?;
        Self::from_json(&bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, RevocationPartnerError> {
        let registry: Self = crate::signed_input::decode(bytes)
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
        let mut issuers = BTreeMap::new();
        let mut keys = BTreeMap::new();
        for (key, partner) in &self.partners {
            if key != &partner.partner_id {
                return Err(RevocationPartnerError::KeyMismatch {
                    key: key.clone(),
                    partner_id: partner.partner_id.clone(),
                });
            }
            partner.validate()?;
            let canonical = canonical_issuer(&partner.issuer).map_err(|reason| {
                RevocationPartnerError::InvalidIssuer {
                    partner_id: partner.partner_id.clone(),
                    reason: reason.to_owned(),
                }
            })?;
            if let Some(first) = issuers.insert(canonical, key.as_str()) {
                return Err(RevocationPartnerError::DuplicateIssuer {
                    first: first.to_owned(),
                    second: key.clone(),
                });
            }
            for public_key in partner.keys() {
                if let Some(first) = keys.insert(public_key, key.as_str()) {
                    return Err(RevocationPartnerError::DuplicateIssuerKey {
                        first: first.to_owned(),
                        second: key.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn get(&self, partner_id: &str) -> Option<&RevocationPartner> {
        self.partners.get(partner_id)
    }

    /// The partner whose issuer equals the presented issuer `url` under the
    /// RFC 3986 equivalences: case-insensitive scheme and host, default port
    /// elision and trailing slashes on the path. A presented issuer that does
    /// not parse, or carries userinfo, a query or a fragment, is refused.
    pub fn by_issuer(
        &self,
        url: &str,
    ) -> Result<Option<&RevocationPartner>, RevocationPartnerError> {
        let wanted = canonical_issuer(url).map_err(|reason| {
            RevocationPartnerError::MalformedPresentedIssuer {
                issuer: url.to_owned(),
                reason: reason.to_owned(),
            }
        })?;
        Ok(self.partners.values().find(|partner| {
            canonical_issuer(&partner.issuer).is_ok_and(|canonical| canonical == wanted)
        }))
    }

    /// Every partner one of whose issuer keys has a DID in `dids`.
    #[must_use]
    pub fn by_issuer_dids(&self, dids: &[String]) -> Vec<&RevocationPartner> {
        self.partners
            .values()
            .filter(|partner| {
                partner
                    .issuer_dids()
                    .is_ok_and(|own| own.iter().any(|did| dids.contains(did)))
            })
            .collect()
    }
}

/// The canonical form two issuer URLs are compared in.
fn canonical_issuer(url: &str) -> Result<String, &'static str> {
    let parsed = Url::parse(url).map_err(|_| "not a URL")?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("userinfo is not allowed");
    }
    if parsed.query().is_some() {
        return Err("a query is not allowed");
    }
    if parsed.fragment().is_some() {
        return Err("a fragment is not allowed");
    }
    let host = parsed.host_str().ok_or("a host is required")?;
    let port = parsed
        .port_or_known_default()
        .ok_or("the scheme has no default port")?;
    Ok(format!(
        "{}://{}:{}{}",
        parsed.scheme(),
        host,
        port,
        parsed.path().trim_end_matches('/')
    ))
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
