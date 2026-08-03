//! Canonical revocation binding used by the agent-economy admission protocol.
//!
//! The security admission protocol uses a different signed domain and stricter
//! lineage-aware constructor. Keeping this type distinct prevents a value from
//! one protocol from being accepted by the other merely because both carry a
//! sorted identifier list and a SHA-256 digest.

use crate::{canonical_json_bytes, sha256_hex};

pub const MAX_AGENT_ECONOMY_ADMISSION_REVOCATION_IDS: usize = 256;
const MAX_AGENT_ECONOMY_REVOCATION_ID_BYTES: usize = 512;
const AGENT_ECONOMY_ADMISSION_REVOCATION_SET_DOMAIN: &str = "chio.admission-revocation-set.v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AgentEconomyRevocationSetError {
    #[error("agent-economy admission revocation set is empty")]
    Empty,
    #[error("agent-economy admission revocation set exceeds its member limit")]
    TooManyMembers,
    #[error("agent-economy admission revocation identifier is empty or oversized")]
    InvalidIdentifier,
    #[error("agent-economy admission revocation set contains duplicate identifier `{0}`")]
    DuplicateIdentifier(String),
    #[error("agent-economy admission revocation identifiers are not canonical")]
    NonCanonicalIdentifiers,
    #[error("agent-economy admission revocation digest is not lowercase SHA-256 hex")]
    InvalidDigest,
    #[error("agent-economy admission revocation digest does not match its members")]
    DigestMismatch,
    #[error("agent-economy admission revocation presentation does not match the bound set")]
    SetMismatch,
    #[error("agent-economy admission revocation canonicalization failed: {0}")]
    Canonicalization(String),
}

/// Sorted revocation identifiers bound under the agent-economy admission domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEconomyCanonicalRevocationSet {
    ids: Vec<String>,
    digest: String,
}

impl AgentEconomyCanonicalRevocationSet {
    pub fn canonicalize(mut ids: Vec<String>) -> Result<Self, AgentEconomyRevocationSetError> {
        validate_member_bounds(&ids)?;
        ids.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        validate_canonical_ids(&ids)?;
        let digest = revocation_set_digest(&ids)?;
        Ok(Self { ids, digest })
    }

    pub fn from_canonical_parts(
        ids: Vec<String>,
        digest: String,
    ) -> Result<Self, AgentEconomyRevocationSetError> {
        validate_member_bounds(&ids)?;
        validate_canonical_ids(&ids)?;
        if !is_sha256_hex(&digest) {
            return Err(AgentEconomyRevocationSetError::InvalidDigest);
        }
        if revocation_set_digest(&ids)? != digest {
            return Err(AgentEconomyRevocationSetError::DigestMismatch);
        }
        Ok(Self { ids, digest })
    }

    #[must_use]
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn verify_exact(
        &self,
        presented_ids: &[String],
        presented_digest: &str,
    ) -> Result<(), AgentEconomyRevocationSetError> {
        validate_member_bounds(presented_ids)?;
        validate_canonical_ids(presented_ids)?;
        if !is_sha256_hex(presented_digest) {
            return Err(AgentEconomyRevocationSetError::InvalidDigest);
        }
        if revocation_set_digest(presented_ids)? != presented_digest {
            return Err(AgentEconomyRevocationSetError::DigestMismatch);
        }
        if presented_ids != self.ids || presented_digest != self.digest {
            return Err(AgentEconomyRevocationSetError::SetMismatch);
        }
        Ok(())
    }
}

fn validate_member_bounds(ids: &[String]) -> Result<(), AgentEconomyRevocationSetError> {
    if ids.is_empty() {
        return Err(AgentEconomyRevocationSetError::Empty);
    }
    if ids.len() > MAX_AGENT_ECONOMY_ADMISSION_REVOCATION_IDS {
        return Err(AgentEconomyRevocationSetError::TooManyMembers);
    }
    if ids
        .iter()
        .any(|id| id.is_empty() || id.len() > MAX_AGENT_ECONOMY_REVOCATION_ID_BYTES)
    {
        return Err(AgentEconomyRevocationSetError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_canonical_ids(ids: &[String]) -> Result<(), AgentEconomyRevocationSetError> {
    for pair in ids.windows(2) {
        if pair[0] == pair[1] {
            return Err(AgentEconomyRevocationSetError::DuplicateIdentifier(
                pair[0].clone(),
            ));
        }
        if pair[0].as_bytes() > pair[1].as_bytes() {
            return Err(AgentEconomyRevocationSetError::NonCanonicalIdentifiers);
        }
    }
    Ok(())
}

fn revocation_set_digest(value: &[String]) -> Result<String, AgentEconomyRevocationSetError> {
    let canonical = canonical_json_bytes(&value)
        .map_err(|error| AgentEconomyRevocationSetError::Canonicalization(error.to_string()))?;
    let mut message = Vec::with_capacity(
        AGENT_ECONOMY_ADMISSION_REVOCATION_SET_DOMAIN.len() + 1 + canonical.len(),
    );
    message.extend_from_slice(AGENT_ECONOMY_ADMISSION_REVOCATION_SET_DOMAIN.as_bytes());
    message.push(0);
    message.extend_from_slice(&canonical);
    Ok(sha256_hex(&message))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_domain_is_distinct_from_security_admission_domain() {
        let set = AgentEconomyCanonicalRevocationSet::canonicalize(vec!["cap-1".to_string()])
            .expect("canonical agent-economy revocation set");
        let security = crate::supplemental_quota::CanonicalRevocationSet::new("cap-1", &[], &[])
            .expect("canonical security revocation set");
        assert_ne!(set.digest(), security.digest());
    }

    #[test]
    fn reconstruction_rejects_wrong_domain_digest() {
        let security = crate::supplemental_quota::CanonicalRevocationSet::new("cap-1", &[], &[])
            .expect("canonical security revocation set");
        assert_eq!(
            AgentEconomyCanonicalRevocationSet::from_canonical_parts(
                security.ids().to_vec(),
                security.digest().to_string(),
            ),
            Err(AgentEconomyRevocationSetError::DigestMismatch)
        );
    }
}
