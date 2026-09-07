use chio_core_types::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::budget::{canonicalize_quotas, ExecutionQuota};
use crate::{validate_digest, validate_identifier, BrokerError, Result};

const ID_DOMAIN: &[u8] = b"chio.broker-attempt-identifiers.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptState {
    Registered,
    Prepared,
    Held,
    Captured,
    DispatchCommitted,
    Reversed,
    UnknownOutcome,
    Completed,
    Failed,
}

impl AttemptState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Prepared => "prepared",
            Self::Held => "held",
            Self::Captured => "captured",
            Self::DispatchCommitted => "dispatch_committed",
            Self::Reversed => "reversed",
            Self::UnknownOutcome => "unknown_outcome",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "registered" => Ok(Self::Registered),
            "prepared" => Ok(Self::Prepared),
            "held" => Ok(Self::Held),
            "captured" => Ok(Self::Captured),
            "dispatch_committed" => Ok(Self::DispatchCommitted),
            "reversed" => Ok(Self::Reversed),
            "unknown_outcome" => Ok(Self::UnknownOutcome),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(BrokerError::Invariant(
                "stored broker attempt state is unknown".to_string(),
            )),
        }
    }

    #[must_use]
    pub fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Registered, Self::Prepared | Self::Failed)
                | (
                    Self::Prepared,
                    Self::Held | Self::Captured | Self::Reversed | Self::Failed,
                )
                | (Self::Prepared | Self::Held, Self::UnknownOutcome)
                | (Self::Held, Self::Captured | Self::Reversed | Self::Failed)
                | (
                    Self::Captured,
                    Self::DispatchCommitted | Self::UnknownOutcome | Self::Failed
                )
                | (
                    Self::DispatchCommitted,
                    Self::Completed | Self::Failed | Self::UnknownOutcome
                )
                | (
                    Self::UnknownOutcome,
                    Self::Reversed | Self::Completed | Self::Failed
                )
        ) || self == next
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptIds {
    pub operation_id: String,
    pub attempt_id: String,
    pub hold_id: String,
    pub authorize_event_id: String,
    pub reverse_event_id: String,
    pub capture_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptRegistration {
    pub ids: AttemptIds,
    pub invocation_id: String,
    pub parent_capability_id: String,
    pub broker_capability_id: String,
    pub request_digest: String,
    pub request_canonical_digest: String,
    pub proof_digest: String,
    pub proof_key_id: String,
    pub proof_nonce: String,
    pub nonce_expires_at_unix_seconds: u64,
    pub quotas: Vec<ExecutionQuota>,
    pub authority_metadata_digest: String,
    pub revocation_authority_domain: String,
}

impl AttemptRegistration {
    pub fn validate(&self) -> Result<()> {
        for (value, label) in [
            (&self.ids.operation_id, "operation id"),
            (&self.ids.attempt_id, "attempt id"),
            (&self.ids.hold_id, "hold id"),
            (&self.ids.authorize_event_id, "authorize event id"),
            (&self.ids.reverse_event_id, "reverse event id"),
            (&self.ids.capture_event_id, "capture event id"),
            (&self.invocation_id, "invocation id"),
            (&self.parent_capability_id, "parent capability id"),
            (&self.broker_capability_id, "broker capability id"),
            (&self.proof_key_id, "proof key id"),
        ] {
            validate_identifier(value, label, 512)?;
        }
        validate_digest(&self.request_digest, "request digest")?;
        validate_digest(
            &self.request_canonical_digest,
            "canonical broker execute request digest",
        )?;
        validate_digest(&self.proof_digest, "proof digest")?;
        validate_digest(&self.authority_metadata_digest, "authority metadata digest")?;
        validate_identifier(
            &self.revocation_authority_domain,
            "revocation authority domain",
            512,
        )?;
        if self.proof_nonce.len() < 16
            || self.proof_nonce.len() > 128
            || !self
                .proof_nonce
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || self.nonce_expires_at_unix_seconds == 0
        {
            return Err(BrokerError::InvalidRequest(
                "attempt proof nonce or expiry is invalid".to_string(),
            ));
        }
        if canonicalize_quotas(self.quotas.clone())? != self.quotas {
            return Err(BrokerError::InvalidRequest(
                "attempt quota set is not canonical".to_string(),
            ));
        }
        let mut expected = derive_attempt_ids(
            &self.broker_capability_id,
            &self.invocation_id,
            &self.proof_nonce,
            &self.request_digest,
        )?;
        // The kernel admission operation is created after the broker-specific
        // attempt, hold, and event identifiers are derived. Its authoritative
        // saga ID replaces only the provisional operation reference.
        expected.operation_id.clone_from(&self.ids.operation_id);
        if expected != self.ids {
            return Err(BrokerError::InvalidRequest(
                "attempt identifiers do not match the canonical derivation".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptRecord {
    pub registration: AttemptRegistration,
    pub state: AttemptState,
    pub dispatch_claim_id: Option<String>,
    pub revocation_set_digest: Option<String>,
    pub budget_commit_index: Option<u64>,
    pub revocation_commit_index: Option<u64>,
    pub authority_commit_index: Option<u64>,
    pub leader_epoch: Option<u64>,
    pub response_digest: Option<String>,
    pub updated_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterAttemptOutcome {
    Inserted(AttemptRecord),
    ExactRetry(AttemptRecord),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttemptTransitionEvidence {
    pub revocation_set_digest: Option<String>,
    pub budget_commit_index: Option<u64>,
    pub revocation_commit_index: Option<u64>,
    pub authority_commit_index: Option<u64>,
    pub leader_epoch: Option<u64>,
    pub response_digest: Option<String>,
}

pub trait AttemptStore: Send + Sync {
    /// Persist and fsync a registration intent before any budget mutation.
    fn register_intent(
        &self,
        registration: &AttemptRegistration,
        now_unix_seconds: u64,
    ) -> Result<RegisterAttemptOutcome>;

    /// Atomically claim a registered intent for the one execution path that
    /// may materialize credentials. Returns false when another caller won.
    fn claim_registered_attempt(&self, attempt_id: &str, now_unix_seconds: u64) -> Result<bool>;

    fn register_attempt(
        &self,
        registration: &AttemptRegistration,
        now_unix_seconds: u64,
    ) -> Result<RegisterAttemptOutcome>;

    fn load_attempt(&self, attempt_id: &str) -> Result<Option<AttemptRecord>>;

    fn transition(
        &self,
        attempt_id: &str,
        expected: AttemptState,
        next: AttemptState,
        evidence: &AttemptTransitionEvidence,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord>;

    /// Claim the one pre-dispatch execution path allowed to advance a captured
    /// attempt. A false result means another live caller owns the claim.
    fn claim_captured_attempt(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        now_unix_seconds: u64,
    ) -> Result<bool>;

    fn release_captured_attempt_claim(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        now_unix_seconds: u64,
    ) -> Result<bool>;

    fn commit_captured_attempt_dispatch(
        &self,
        attempt_id: &str,
        dispatch_claim_id: &str,
        evidence: &AttemptTransitionEvidence,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord>;

    /// Clear a claim left by a dead process during explicit startup recovery.
    fn clear_stale_captured_attempt_claim(
        &self,
        attempt_id: &str,
        now_unix_seconds: u64,
    ) -> Result<AttemptRecord>;

    fn recoverable_attempts(
        &self,
        after_attempt_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AttemptRecord>>;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeterministicIdBody<'a> {
    broker_capability_id: &'a str,
    invocation_id: &'a str,
    proof_nonce: &'a str,
    request_digest: &'a str,
}

pub fn derive_attempt_ids(
    broker_capability_id: &str,
    invocation_id: &str,
    proof_nonce: &str,
    request_digest: &str,
) -> Result<AttemptIds> {
    let canonical = canonical_json_bytes(&DeterministicIdBody {
        broker_capability_id,
        invocation_id,
        proof_nonce,
        request_digest,
    })
    .map_err(|error| BrokerError::Invariant(format!("attempt ID derivation failed: {error}")))?;
    Ok(AttemptIds {
        operation_id: derive_id("operation", &canonical),
        attempt_id: derive_id("attempt", &canonical),
        hold_id: derive_id("hold", &canonical),
        authorize_event_id: derive_id("authorize", &canonical),
        reverse_event_id: derive_id("reverse", &canonical),
        capture_event_id: derive_id("capture", &canonical),
    })
}

pub fn derive_attempt_ids_for_operation(
    broker_capability_id: &str,
    invocation_id: &str,
    proof_nonce: &str,
    request_digest: &str,
    admission_operation_id: &str,
) -> Result<AttemptIds> {
    validate_identifier(admission_operation_id, "admission operation id", 512)?;
    let mut ids = derive_attempt_ids(
        broker_capability_id,
        invocation_id,
        proof_nonce,
        request_digest,
    )?;
    ids.operation_id = admission_operation_id.to_string();
    Ok(ids)
}

fn derive_id(label: &str, canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ID_DOMAIN);
    hasher.update(label.as_bytes());
    hasher.update([0]);
    hasher.update(canonical);
    format!("broker-{label}-{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn deterministic_ids_bind_nonce_invocation_capability_and_request() {
        let first = derive_attempt_ids("cap", "invocation", "nonce-abcdefghijkl", &"a".repeat(64))
            .test_expect("ids");
        let same = derive_attempt_ids("cap", "invocation", "nonce-abcdefghijkl", &"a".repeat(64))
            .test_expect("ids");
        let changed =
            derive_attempt_ids("cap", "invocation", "nonce-abcdefghijkm", &"a".repeat(64))
                .test_expect("ids");
        assert_eq!(first, same);
        assert_ne!(first.attempt_id, changed.attempt_id);
    }

    #[test]
    fn kernel_operation_id_replaces_only_the_provisional_reference() {
        let provisional =
            derive_attempt_ids("cap", "invocation", "nonce-abcdefghijkl", &"a".repeat(64))
                .test_expect("provisional ids");
        let bound = derive_attempt_ids_for_operation(
            "cap",
            "invocation",
            "nonce-abcdefghijkl",
            &"a".repeat(64),
            "kernel-admission-operation",
        )
        .test_expect("operation-bound ids");
        assert_eq!(bound.operation_id, "kernel-admission-operation");
        assert_eq!(bound.attempt_id, provisional.attempt_id);
        assert_eq!(bound.hold_id, provisional.hold_id);
        assert_eq!(bound.authorize_event_id, provisional.authorize_event_id);
        assert_eq!(bound.reverse_event_id, provisional.reverse_event_id);
        assert_eq!(bound.capture_event_id, provisional.capture_event_id);
    }
}
