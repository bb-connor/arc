use serde::{Deserialize, Serialize};

use crate::revocation::digest_canonical_revocation_ids;
use crate::{validate_digest, validate_identifier, BrokerError, Result};

const MAX_QUOTA_KEYS: usize = 8;
const MAX_IDENTIFIER_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAuthorityProfile {
    AuthoritativeHoldEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionAuthorityCapabilities {
    pub profile: ExecutionAuthorityProfile,
    pub atomic_multi_key_holds: bool,
    pub combined_capture_and_revocation: bool,
    pub query_by_id: bool,
    pub shared_revocation_write_domain: bool,
}

impl ExecutionAuthorityCapabilities {
    pub fn require_production(self) -> Result<()> {
        if self.profile != ExecutionAuthorityProfile::AuthoritativeHoldEvent
            || !self.atomic_multi_key_holds
            || !self.combined_capture_and_revocation
            || !self.query_by_id
            || !self.shared_revocation_write_domain
        {
            return Err(BrokerError::AuthorityUnavailable(
                "execution authority lacks atomic hold, query, or combined revocation capture"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionQuota {
    pub key_id: String,
    pub maximum_executions: u32,
}

impl ExecutionQuota {
    pub fn validate(&self) -> Result<()> {
        validate_identifier(&self.key_id, "quota key", MAX_IDENTIFIER_BYTES)?;
        if self.maximum_executions == 0 {
            return Err(BrokerError::InvalidRequest(
                "quota maximum must be positive".to_string(),
            ));
        }
        Ok(())
    }
}

pub fn canonicalize_quotas(mut quotas: Vec<ExecutionQuota>) -> Result<Vec<ExecutionQuota>> {
    if quotas.is_empty() || quotas.len() > MAX_QUOTA_KEYS {
        return Err(BrokerError::InvalidRequest(
            "execution quota set is empty or oversized".to_string(),
        ));
    }
    for quota in &quotas {
        quota.validate()?;
    }
    quotas.sort_unstable_by(|left, right| left.key_id.cmp(&right.key_id));
    let mut deduplicated: Vec<ExecutionQuota> = Vec::with_capacity(quotas.len());
    for quota in quotas {
        if let Some(previous) = deduplicated.last() {
            if previous.key_id == quota.key_id {
                if previous.maximum_executions != quota.maximum_executions {
                    return Err(BrokerError::Invariant(
                        "identical quota key has conflicting maximum".to_string(),
                    ));
                }
                continue;
            }
        }
        deduplicated.push(quota);
    }
    Ok(deduplicated)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizeExecutionHoldRequest {
    pub operation_id: String,
    pub invocation_id: String,
    pub parent_capability_id: String,
    pub broker_capability_id: String,
    pub hold_id: String,
    pub authorize_event_id: String,
    pub quotas: Vec<ExecutionQuota>,
    pub authority_metadata_digest: String,
}

impl AuthorizeExecutionHoldRequest {
    pub fn validate(&self) -> Result<()> {
        validate_execution_ids(
            &self.operation_id,
            &self.invocation_id,
            &self.parent_capability_id,
            &self.broker_capability_id,
            &self.hold_id,
            &self.authorize_event_id,
        )?;
        validate_digest(&self.authority_metadata_digest, "authority metadata digest")?;
        if canonicalize_quotas(self.quotas.clone())? != self.quotas {
            return Err(BrokerError::InvalidRequest(
                "quota set is not in canonical comparison form".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryExecutionHoldRequest {
    pub operation_id: String,
    pub invocation_id: String,
    pub parent_capability_id: String,
    pub broker_capability_id: String,
    pub hold_id: String,
    pub authorize_event_id: String,
    pub reverse_event_id: String,
    pub capture_event_id: String,
}

impl QueryExecutionHoldRequest {
    pub fn validate(&self) -> Result<()> {
        for event_id in [
            &self.authorize_event_id,
            &self.reverse_event_id,
            &self.capture_event_id,
        ] {
            validate_execution_ids(
                &self.operation_id,
                &self.invocation_id,
                &self.parent_capability_id,
                &self.broker_capability_id,
                &self.hold_id,
                event_id,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReverseExecutionHoldRequest {
    pub operation_id: String,
    pub invocation_id: String,
    pub parent_capability_id: String,
    pub broker_capability_id: String,
    pub hold_id: String,
    pub reverse_event_id: String,
    pub proof_dispatch_did_not_begin: bool,
}

impl ReverseExecutionHoldRequest {
    pub fn validate(&self) -> Result<()> {
        validate_execution_ids(
            &self.operation_id,
            &self.invocation_id,
            &self.parent_capability_id,
            &self.broker_capability_id,
            &self.hold_id,
            &self.reverse_event_id,
        )?;
        if !self.proof_dispatch_did_not_begin {
            return Err(BrokerError::AuthorizationDenied(
                "hold reversal lacks proof that dispatch did not begin".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureExecutionHoldRequest {
    pub operation_id: String,
    pub invocation_id: String,
    pub parent_capability_id: String,
    pub broker_capability_id: String,
    pub hold_id: String,
    pub capture_event_id: String,
    pub revocation_ids: Vec<String>,
    pub revocation_set_digest: String,
    pub authorization_artifact_digest: String,
    pub authority_metadata_digest: String,
}

impl CaptureExecutionHoldRequest {
    pub fn validate(&self) -> Result<()> {
        validate_execution_ids(
            &self.operation_id,
            &self.invocation_id,
            &self.parent_capability_id,
            &self.broker_capability_id,
            &self.hold_id,
            &self.capture_event_id,
        )?;
        validate_digest(&self.revocation_set_digest, "revocation-set digest")?;
        validate_digest(
            &self.authorization_artifact_digest,
            "authorization artifact digest",
        )?;
        validate_digest(&self.authority_metadata_digest, "authority metadata digest")?;
        if self.revocation_ids.is_empty()
            || self
                .revocation_ids
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(BrokerError::InvalidRequest(
                "revocation set must be strictly sorted and nonempty".to_string(),
            ));
        }
        if !self
            .revocation_ids
            .iter()
            .any(|id| id == &self.parent_capability_id)
            || !self
                .revocation_ids
                .iter()
                .any(|id| id == &self.broker_capability_id)
        {
            return Err(BrokerError::InvalidRequest(
                "revocation set omits parent or broker capability".to_string(),
            ));
        }
        if digest_canonical_revocation_ids(&self.revocation_ids)? != self.revocation_set_digest {
            return Err(BrokerError::InvalidRequest(
                "revocation-set digest does not match its canonical members".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CombinedCaptureCommit {
    pub checked_revocation_set_digest: String,
    pub budget_commit_index: u64,
    pub revocation_commit_index: u64,
    pub authority_commit_index: u64,
    pub leader_epoch: u64,
}

impl CombinedCaptureCommit {
    pub fn validate_for(&self, request: &CaptureExecutionHoldRequest) -> Result<()> {
        if self.checked_revocation_set_digest != request.revocation_set_digest {
            return Err(BrokerError::Invariant(
                "authority checked a different revocation set".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionHoldState {
    Unknown,
    Denied,
    Held,
    Reversed,
    Captured(CombinedCaptureCommit),
}

pub trait BrokerExecutionBudget: Send + Sync {
    fn capabilities(&self) -> ExecutionAuthorityCapabilities;

    fn query_execution_hold(
        &self,
        request: &QueryExecutionHoldRequest,
    ) -> Result<ExecutionHoldState>;

    fn authorize_execution_hold(
        &self,
        request: &AuthorizeExecutionHoldRequest,
    ) -> Result<ExecutionHoldState>;

    fn reverse_execution_hold(
        &self,
        request: &ReverseExecutionHoldRequest,
    ) -> Result<ExecutionHoldState>;

    fn capture_execution_hold(
        &self,
        request: &CaptureExecutionHoldRequest,
    ) -> Result<ExecutionHoldState>;
}

fn validate_execution_ids(
    operation_id: &str,
    invocation_id: &str,
    parent_capability_id: &str,
    broker_capability_id: &str,
    hold_id: &str,
    event_id: &str,
) -> Result<()> {
    for (value, label) in [
        (operation_id, "operation id"),
        (invocation_id, "invocation id"),
        (parent_capability_id, "parent capability id"),
        (broker_capability_id, "broker capability id"),
        (hold_id, "hold id"),
        (event_id, "event id"),
    ] {
        validate_identifier(value, label, MAX_IDENTIFIER_BYTES)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::CanonicalBrokerRevocationSet;

    #[test]
    fn quota_deduplication_preserves_distinct_parent_and_broker_ceilings() {
        let quotas = canonicalize_quotas(vec![
            ExecutionQuota {
                key_id: "parent".to_string(),
                maximum_executions: 10,
            },
            ExecutionQuota {
                key_id: "broker".to_string(),
                maximum_executions: 2,
            },
            ExecutionQuota {
                key_id: "parent".to_string(),
                maximum_executions: 10,
            },
        ])
        .expect("canonical quotas");
        assert_eq!(quotas.len(), 2);
        assert_eq!(quotas[0].key_id, "broker");
        assert_eq!(quotas[1].key_id, "parent");
    }

    #[test]
    fn sequential_or_unqueryable_authority_is_not_production_capable() {
        for capabilities in [
            ExecutionAuthorityCapabilities {
                profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                atomic_multi_key_holds: false,
                combined_capture_and_revocation: true,
                query_by_id: true,
                shared_revocation_write_domain: true,
            },
            ExecutionAuthorityCapabilities {
                profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                atomic_multi_key_holds: true,
                combined_capture_and_revocation: false,
                query_by_id: true,
                shared_revocation_write_domain: true,
            },
            ExecutionAuthorityCapabilities {
                profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                atomic_multi_key_holds: true,
                combined_capture_and_revocation: true,
                query_by_id: false,
                shared_revocation_write_domain: true,
            },
            ExecutionAuthorityCapabilities {
                profile: ExecutionAuthorityProfile::AuthoritativeHoldEvent,
                atomic_multi_key_holds: true,
                combined_capture_and_revocation: true,
                query_by_id: true,
                shared_revocation_write_domain: false,
            },
        ] {
            assert!(capabilities.require_production().is_err());
        }
    }

    #[test]
    fn capture_rejects_omitted_reordered_or_misbound_revocation_members() {
        let canonical = CanonicalBrokerRevocationSet::new(
            "parent",
            &["ancestor".to_string()],
            "broker",
            "broker-revocation",
        )
        .expect("canonical revocations");
        let valid = CaptureExecutionHoldRequest {
            operation_id: "operation".to_string(),
            invocation_id: "invocation".to_string(),
            parent_capability_id: "parent".to_string(),
            broker_capability_id: "broker".to_string(),
            hold_id: "hold".to_string(),
            capture_event_id: "capture".to_string(),
            revocation_ids: canonical.ids().to_vec(),
            revocation_set_digest: canonical.digest().to_string(),
            authorization_artifact_digest: "a".repeat(64),
            authority_metadata_digest: "b".repeat(64),
        };
        valid.validate().expect("valid capture");

        let mut changed = valid.clone();
        changed.revocation_ids.retain(|id| id != "broker");
        assert!(changed.validate().is_err());

        let mut changed = valid.clone();
        changed.revocation_ids.reverse();
        assert!(changed.validate().is_err());

        let mut changed = valid;
        changed.revocation_set_digest = "c".repeat(64);
        assert!(changed.validate().is_err());
    }
}
