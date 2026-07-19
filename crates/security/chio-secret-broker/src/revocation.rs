use chio_core_types::{canonical_json_bytes, PublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{validate_digest, validate_identifier, BrokerError, Result};

// This is the protocol-owned revocation-set domain shared with the kernel's
// CanonicalRevocationSet. Broker capture must carry the exact same digest that
// the combined authority authorized.
const REVOCATION_SET_DOMAIN: &[u8] = b"chio.revocation-set.v1\0";
const MAX_REVOCATION_MEMBERS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityLivenessRequest {
    pub parent_capability_id: String,
    pub expected_subject: PublicKey,
    pub expected_audience: String,
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LiveParentCapability {
    pub capability_id: String,
    pub subject: PublicKey,
    pub audience: String,
    pub delegation_ancestor_ids: Vec<String>,
    pub expires_at_unix_seconds: u64,
    pub verified_at_unix_seconds: u64,
    pub authority_snapshot_digest: String,
}

pub trait CapabilityLiveness: Send + Sync {
    fn verify_live_parent(
        &self,
        request: &CapabilityLivenessRequest,
    ) -> Result<LiveParentCapability>;

    /// Return the exact signed authority exchange used for audit evidence.
    /// Implementations without a signed authority transport fail closed.
    fn verify_live_parent_with_audit_evidence(
        &self,
        _request: &CapabilityLivenessRequest,
    ) -> Result<crate::authority_ipc::VerifiedAuthorityExchange> {
        Err(BrokerError::AuthorityUnavailable(
            "liveness authority does not expose signed audit evidence".to_string(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerRevocationRequest {
    pub broker_capability_id: String,
    pub revocation_id: String,
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrokerRevocationSnapshot {
    pub revoked: bool,
    pub observed_at_unix_seconds: u64,
    pub commit_index: u64,
    pub authority_domain: String,
}

pub trait BrokerRevocations: Send + Sync {
    fn check_broker_revocation(
        &self,
        request: &BrokerRevocationRequest,
    ) -> Result<BrokerRevocationSnapshot>;

    /// Return the exact signed authority exchange used for audit evidence.
    /// Implementations without a signed authority transport fail closed.
    fn check_broker_revocation_with_audit_evidence(
        &self,
        _request: &BrokerRevocationRequest,
    ) -> Result<crate::authority_ipc::VerifiedAuthorityExchange> {
        Err(BrokerError::AuthorityUnavailable(
            "revocation authority does not expose signed audit evidence".to_string(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBrokerRevocationSet {
    ids: Vec<String>,
    digest: String,
}

impl CanonicalBrokerRevocationSet {
    pub fn new(
        parent_capability_id: &str,
        delegation_ancestor_ids: &[String],
        broker_capability_id: &str,
        broker_revocation_id: &str,
    ) -> Result<Self> {
        let mut ids = Vec::with_capacity(
            delegation_ancestor_ids
                .len()
                .checked_add(3)
                .ok_or_else(|| {
                    BrokerError::InvalidRequest("revocation set overflow".to_string())
                })?,
        );
        ids.push(parent_capability_id.to_string());
        ids.extend_from_slice(delegation_ancestor_ids);
        ids.push(broker_capability_id.to_string());
        ids.push(broker_revocation_id.to_string());
        if ids.len() > MAX_REVOCATION_MEMBERS {
            return Err(BrokerError::InvalidRequest(
                "revocation set exceeds broker limit".to_string(),
            ));
        }
        for id in &ids {
            validate_identifier(id, "revocation id", 512)?;
        }
        ids.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(BrokerError::InvalidRequest(
                "revocation set contains duplicate identities".to_string(),
            ));
        }
        let digest = digest_canonical_revocation_ids(&ids)?;
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
}

pub(crate) fn digest_canonical_revocation_ids(ids: &[String]) -> Result<String> {
    if ids.is_empty() || ids.len() > MAX_REVOCATION_MEMBERS {
        return Err(BrokerError::InvalidRequest(
            "revocation set is empty or oversized".to_string(),
        ));
    }
    for id in ids {
        validate_identifier(id, "revocation id", 512)?;
    }
    if ids
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(BrokerError::InvalidRequest(
            "revocation set must be strictly sorted and unique".to_string(),
        ));
    }
    let canonical = canonical_json_bytes(&ids).map_err(|error| {
        BrokerError::Invariant(format!("revocation-set canonicalization failed: {error}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(REVOCATION_SET_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub fn validate_parent_liveness(
    request: &CapabilityLivenessRequest,
    parent: &LiveParentCapability,
    maximum_snapshot_age_seconds: u64,
) -> Result<()> {
    validate_digest(
        &parent.authority_snapshot_digest,
        "parent authority snapshot digest",
    )?;
    validate_identifier(&parent.capability_id, "parent capability id", 512)?;
    for ancestor in &parent.delegation_ancestor_ids {
        validate_identifier(ancestor, "delegation ancestor id", 512)?;
    }
    if parent
        .delegation_ancestor_ids
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(BrokerError::AuthorizationDenied(
            "delegation ancestors are not strictly sorted and unique".to_string(),
        ));
    }
    let latest_snapshot = parent
        .verified_at_unix_seconds
        .checked_add(maximum_snapshot_age_seconds)
        .ok_or_else(|| BrokerError::AuthorityUnavailable("liveness time overflow".to_string()))?;
    if parent.capability_id != request.parent_capability_id
        || parent.subject != request.expected_subject
        || parent.audience != request.expected_audience
        || request.now_unix_seconds >= parent.expires_at_unix_seconds
        || parent.verified_at_unix_seconds > request.now_unix_seconds
        || request.now_unix_seconds > latest_snapshot
    {
        return Err(BrokerError::AuthorizationDenied(
            "parent capability is not live for this broker request".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_revocation_snapshot(
    snapshot: &BrokerRevocationSnapshot,
    now_unix_seconds: u64,
    maximum_snapshot_age_seconds: u64,
    expected_authority_domain: &str,
) -> Result<()> {
    validate_identifier(
        &snapshot.authority_domain,
        "revocation authority domain",
        512,
    )?;
    let latest_snapshot = snapshot
        .observed_at_unix_seconds
        .checked_add(maximum_snapshot_age_seconds)
        .ok_or_else(|| BrokerError::AuthorityUnavailable("revocation time overflow".to_string()))?;
    if snapshot.revoked {
        return Err(BrokerError::AuthorizationDenied(
            "broker capability is revoked".to_string(),
        ));
    }
    if snapshot.observed_at_unix_seconds > now_unix_seconds
        || now_unix_seconds > latest_snapshot
        || snapshot.authority_domain != expected_authority_domain
    {
        return Err(BrokerError::AuthorityUnavailable(
            "broker revocation state is stale or from a separate authority domain".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chio_core_types::Keypair;
    use chio_test_support::prelude::*;

    use super::*;

    #[test]
    fn stale_wrong_subject_wrong_audience_and_expired_parent_fail_closed() {
        let subject = Keypair::from_seed(&[1; 32]).public_key();
        let request = CapabilityLivenessRequest {
            parent_capability_id: "parent".to_string(),
            expected_subject: subject.clone(),
            expected_audience: "broker-parent".to_string(),
            now_unix_seconds: 20,
        };
        let valid = LiveParentCapability {
            capability_id: "parent".to_string(),
            subject,
            audience: "broker-parent".to_string(),
            delegation_ancestor_ids: Vec::new(),
            expires_at_unix_seconds: 30,
            verified_at_unix_seconds: 20,
            authority_snapshot_digest: "a".repeat(64),
        };
        validate_parent_liveness(&request, &valid, 1).test_expect("valid parent");
        let mut changed = valid.clone();
        changed.verified_at_unix_seconds = 18;
        assert!(validate_parent_liveness(&request, &changed, 1).is_err());
        let mut changed = valid.clone();
        changed.audience = "other".to_string();
        assert!(validate_parent_liveness(&request, &changed, 1).is_err());
        let mut changed = valid;
        changed.expires_at_unix_seconds = 20;
        assert!(validate_parent_liveness(&request, &changed, 1).is_err());
    }

    #[test]
    fn revoked_stale_or_separate_revocation_authority_fails_closed() {
        let valid = BrokerRevocationSnapshot {
            revoked: false,
            observed_at_unix_seconds: 20,
            commit_index: 1,
            authority_domain: "combined".to_string(),
        };
        validate_revocation_snapshot(&valid, 20, 1, "combined").test_expect("valid snapshot");
        let mut changed = valid.clone();
        changed.revoked = true;
        assert!(validate_revocation_snapshot(&changed, 20, 1, "combined").is_err());
        let mut changed = valid.clone();
        changed.observed_at_unix_seconds = 18;
        assert!(validate_revocation_snapshot(&changed, 20, 1, "combined").is_err());
        assert!(validate_revocation_snapshot(&valid, 20, 1, "separate").is_err());
    }
}
