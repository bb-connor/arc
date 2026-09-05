use chio_core::canonical_json_bytes;
use chio_core::capability::governance::VerifiedApprovalSetBody;
use chio_core::capability::governance::{GovernedApprovalDecision, GovernedApprovalToken};
pub use chio_core::capability::governance::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody,
};
pub use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequest, ThresholdApprovalRequirement,
};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{sha256_hex, PublicKey, SigningAlgorithm};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use crate::approval::{ApprovalReservationMember, ApprovalSetReservationInput, ApprovalStoreError};

mod collector_validation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApproverIdentity {
    pub identifier: String,
    pub public_key: PublicKey,
    pub directory_version: String,
}

pub trait ApproverDirectory: Send + Sync {
    fn resolve_approver(&self, identifier: &str) -> Result<ResolvedApproverIdentity, String>;
}

pub trait ThresholdApprovalRequirementResolver: Send + Sync {
    fn resolve_requirement(
        &self,
        policy_hash: &str,
        server_id: &str,
        tool_name: &str,
    ) -> Result<Option<ThresholdApprovalRequirement>, String>;
}

impl<F> ThresholdApprovalRequirementResolver for F
where
    F: Fn(&str, &str, &str) -> Result<Option<ThresholdApprovalRequirement>, String> + Send + Sync,
{
    fn resolve_requirement(
        &self,
        policy_hash: &str,
        server_id: &str,
        tool_name: &str,
    ) -> Result<Option<ThresholdApprovalRequirement>, String> {
        self(policy_hash, server_id, tool_name)
    }
}

/// Pure threshold verification inputs assembled after ordinary capability admission.
pub struct ThresholdApprovalVerificationInput<'a> {
    pub request_id: &'a str,
    pub server_id: &'a str,
    pub tool_name: &'a str,
    pub governed_intent_hash: &'a str,
    pub subject: &'a PublicKey,
    pub authorization_capability_hash: &'a str,
    pub authorizing_capability_expires_at: u64,
    pub governed_operation_expires_at: u64,
    pub policy_hash: &'a str,
    pub proposal: &'a ThresholdApprovalProposal,
    pub approval_tokens: &'a [GovernedApprovalToken],
    pub trusted_policy_authorities: &'a [PublicKey],
    pub allowed_token_algorithms: &'a [SigningAlgorithm],
    pub now: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ThresholdApprovalVerificationError {
    #[error("threshold approval requirement resolution failed: {0}")]
    Requirement(String),
    #[error("threshold approval verification denied: {0}")]
    Denied(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedThresholdApprovalSet {
    body: VerifiedApprovalSetBody,
    members: Vec<ApprovalReservationMember>,
}

impl VerifiedThresholdApprovalSet {
    #[must_use]
    pub fn body(&self) -> &VerifiedApprovalSetBody {
        &self.body
    }

    #[must_use]
    pub fn members(&self) -> &[ApprovalReservationMember] {
        &self.members
    }

    pub fn approval_set_hash(&self) -> Result<String, ThresholdApprovalVerificationError> {
        self.body.approval_set_hash().map_err(|error| {
            threshold_denied(&format!("verified approval set hash failed: {error}"))
        })
    }

    pub fn reservation_input(&self) -> Result<ApprovalSetReservationInput, ApprovalStoreError> {
        ApprovalSetReservationInput::new(
            self.body
                .approval_set_hash()
                .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?,
            self.members.clone(),
            self.body.proposal_deadline,
        )
    }
}

impl core::ops::Deref for VerifiedThresholdApprovalSet {
    type Target = VerifiedApprovalSetBody;

    fn deref(&self) -> &Self::Target {
        &self.body
    }
}

pub fn authorization_capability_hash(
    capability: &CapabilityToken,
) -> Result<String, ThresholdApprovalVerificationError> {
    let canonical = canonical_json_bytes(capability).map_err(|error| {
        ThresholdApprovalVerificationError::Denied(format!(
            "authorizing capability canonicalization failed: {error}"
        ))
    })?;
    Ok(sha256_hex(&canonical))
}

/// Verify a complete threshold token set without mutating replay state.
pub fn verify_threshold_approval_set(
    input: &ThresholdApprovalVerificationInput<'_>,
    resolver: &dyn ThresholdApprovalRequirementResolver,
) -> Result<VerifiedThresholdApprovalSet, ThresholdApprovalVerificationError> {
    let token_count = input.approval_tokens.len();
    if token_count > chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS {
        return Err(threshold_denied(
            "approval token set exceeds the protocol ceiling",
        ));
    }
    let requirement = resolver
        .resolve_requirement(input.policy_hash, input.server_id, input.tool_name)
        .map_err(ThresholdApprovalVerificationError::Requirement)?
        .ok_or_else(|| threshold_denied("threshold approval requirement is unavailable"))?;
    requirement
        .validate()
        .map_err(|error| threshold_denied(&error))?;
    if requirement.policy_hash != input.policy_hash
        || token_count > requirement.eligible_approvers.len()
        || token_count < usize::try_from(requirement.threshold).unwrap_or(usize::MAX)
    {
        return Err(threshold_denied(
            "approval token set does not satisfy policy",
        ));
    }

    let proposal = input.proposal;
    let body = &proposal.body;
    if !input
        .trusted_policy_authorities
        .contains(&body.policy_authority)
        || !proposal.verify_signature().map_err(|error| {
            threshold_denied(&format!("threshold proposal signature failed: {error}"))
        })?
    {
        return Err(threshold_denied("threshold proposal signer is not trusted"));
    }
    if body.request_id != input.request_id
        || body.governed_intent_hash != input.governed_intent_hash
        || &body.subject != input.subject
        || body.authorizing_capability_digest != input.authorization_capability_hash
        || body.policy_hash != input.policy_hash
        || body.threshold != requirement.threshold
        || body.eligible_set_digest != requirement.eligible_set_digest
    {
        return Err(threshold_denied(
            "threshold proposal binding does not match policy",
        ));
    }
    let expected_deadline = body
        .proposal_created_at
        .checked_add(requirement.timeout_seconds)
        .ok_or_else(|| threshold_denied("threshold proposal deadline overflowed"))?
        .min(input.authorizing_capability_expires_at)
        .min(input.governed_operation_expires_at);
    if body.proposal_deadline != expected_deadline
        || input.now < body.proposal_created_at
        || input.now >= body.proposal_deadline
    {
        return Err(threshold_denied("threshold proposal window is invalid"));
    }

    let proposal_hash = proposal
        .artifact_digest()
        .map_err(|error| threshold_denied(&format!("threshold proposal hash failed: {error}")))?;
    let eligible = requirement
        .eligible_approvers
        .iter()
        .map(|approver| approver.public_key.to_hex())
        .collect::<BTreeSet<_>>();
    let mut token_ids = BTreeSet::new();
    let mut token_digests = BTreeSet::new();
    let mut signers = BTreeSet::new();
    let mut members = Vec::with_capacity(token_count);
    for token in input.approval_tokens {
        if token.threshold_proposal_hash.as_deref() != Some(proposal_hash.as_str())
            || token.request_id != input.request_id
            || token.governed_intent_hash != input.governed_intent_hash
            || &token.subject != input.subject
            || token.decision != GovernedApprovalDecision::Approved
            || token.id.is_empty()
            || token.id.trim() != token.id
            || token.issued_at < body.proposal_created_at
            || token.issued_at >= body.proposal_deadline
            || input.now < token.issued_at
            || token.expires_at <= token.issued_at
            || token.expires_at > body.proposal_deadline
            || input.now >= token.expires_at
        {
            return Err(threshold_denied(
                "approval token binding or validity is invalid",
            ));
        }
        let algorithm = token.algorithm.unwrap_or_default();
        if !input.allowed_token_algorithms.contains(&algorithm)
            || token.approver.algorithm() != algorithm
            || token.signature.algorithm() != algorithm
            || !eligible.contains(&token.approver.to_hex())
            || !token.verify_signature().map_err(|error| {
                threshold_denied(&format!("approval token signature failed: {error}"))
            })?
        {
            return Err(threshold_denied("approval token signer is not valid"));
        }
        let digest = token
            .token_digest()
            .map_err(|error| threshold_denied(&format!("approval token digest failed: {error}")))?;
        if !token_ids.insert(token.id.clone())
            || !token_digests.insert(digest.clone())
            || !signers.insert(token.approver.to_hex())
        {
            return Err(threshold_denied("approval token set contains a duplicate"));
        }
        members.push(
            ApprovalReservationMember::new(token.id.clone(), digest).map_err(|error| {
                threshold_denied(&format!("approval replay member is invalid: {error}"))
            })?,
        );
    }
    members.sort_unstable_by(|left, right| {
        left.token_digest()
            .cmp(right.token_digest())
            .then_with(|| left.token_id().cmp(right.token_id()))
    });
    let body = VerifiedApprovalSetBody::new(token_digests.into_iter().collect(), proposal)
        .map_err(|error| threshold_denied(&format!("verified approval set failed: {error}")))?;
    Ok(VerifiedThresholdApprovalSet { body, members })
}

fn threshold_denied(reason: &str) -> ThresholdApprovalVerificationError {
    ThresholdApprovalVerificationError::Denied(reason.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdApprovalCollectorState {
    Collecting,
    Ready,
    Delivered,
    Cancelled,
}

impl ThresholdApprovalCollectorState {
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Delivered | Self::Cancelled)
    }
}

/// Serializable collector state. Deserialization does not authenticate this record;
/// use [`ThresholdApprovalCollector`] to validate it against current authority.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ThresholdApprovalCollectorProposal {
    pub proposal: ThresholdApprovalProposal,
    pub requirement: ThresholdApprovalRequirement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitter: Option<PublicKey>,
    #[serde(default)]
    pub require_submitter_separation: bool,
    pub state: ThresholdApprovalCollectorState,
    pub tokens: Vec<GovernedApprovalToken>,
    pub version: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollectedThresholdApprovalSet {
    pub proposal: ThresholdApprovalProposal,
    pub tokens: Vec<GovernedApprovalToken>,
}

#[derive(Debug, thiserror::Error)]
pub enum ThresholdApprovalCollectorStoreError {
    #[error("threshold approval proposal not found: {0}")]
    NotFound(String),
    #[error("threshold approval collector conflict: {0}")]
    Conflict(String),
    #[error("threshold approval collector backend error: {0}")]
    Backend(String),
    #[error("threshold approval collector serialization error: {0}")]
    Serialization(String),
}

/// Persistence and compare-and-swap port, not an authorization interface.
/// Implementations must atomically compare versions and persist complete records.
/// Signature, policy, and approver checks belong to [`ThresholdApprovalCollector`].
pub trait ThresholdApprovalCollectorStore: Send + Sync {
    fn create(
        &self,
        proposal: &ThresholdApprovalCollectorProposal,
    ) -> Result<(), ThresholdApprovalCollectorStoreError>;

    fn get(
        &self,
        proposal_id: &str,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>;

    fn append_token(
        &self,
        proposal_id: &str,
        expected_version: u64,
        token: &GovernedApprovalToken,
        replaced_token_id: Option<&str>,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError>;

    fn transition(
        &self,
        proposal_id: &str,
        expected_version: u64,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError>;
}

#[derive(Clone)]
pub struct ThresholdApprovalCollector {
    store: Arc<dyn ThresholdApprovalCollectorStore>,
    active_policy_hash: String,
    trusted_policy_authorities: Vec<PublicKey>,
}

impl std::fmt::Debug for ThresholdApprovalCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdApprovalCollector")
            .field("active_policy_hash", &self.active_policy_hash)
            .field(
                "trusted_policy_authority_count",
                &self.trusted_policy_authorities.len(),
            )
            .finish_non_exhaustive()
    }
}

impl ThresholdApprovalCollector {
    #[must_use]
    pub fn new(
        store: Arc<dyn ThresholdApprovalCollectorStore>,
        active_policy_hash: String,
        trusted_policy_authorities: Vec<PublicKey>,
    ) -> Self {
        Self {
            store,
            active_policy_hash,
            trusted_policy_authorities,
        }
    }

    pub fn create_proposal(
        &self,
        proposal: ThresholdApprovalProposal,
        requirement: ThresholdApprovalRequirement,
        submitter: Option<PublicKey>,
        require_submitter_separation: bool,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        let record = ThresholdApprovalCollectorProposal {
            proposal,
            requirement,
            submitter,
            require_submitter_separation,
            state: ThresholdApprovalCollectorState::Collecting,
            tokens: Vec::new(),
            version: 0,
            updated_at: now,
        };
        record.validate_restored(
            &record.proposal.body.proposal_id,
            &self.active_policy_hash,
            &self.trusted_policy_authorities,
        )?;
        self.store.create(&record)?;
        Ok(record)
    }

    /// Authenticate a historical snapshot against the collector's current trust
    /// configuration. Expiry is checked separately when submitting or delivering.
    pub fn get_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>
    {
        let record = self.store.get(proposal_id)?;
        if let Some(record) = &record {
            record.validate_restored(
                proposal_id,
                &self.active_policy_hash,
                &self.trusted_policy_authorities,
            )?;
        }
        Ok(record)
    }

    pub fn submit_token(
        &self,
        proposal_id: &str,
        token: GovernedApprovalToken,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let record = self
            .get_proposal(proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal no longer accepts updates".to_string(),
            ));
        }
        record.validate_update_time(now)?;
        record
            .proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        record.validate_new_token(&token, now)?;
        let digest = token
            .artifact_digest()
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        let mut replaced_token_id = None;
        for existing in &record.tokens {
            let existing_digest = existing.artifact_digest().map_err(|error| {
                ThresholdApprovalCollectorStoreError::Serialization(error.to_string())
            })?;
            if existing.id == token.id || existing_digest == digest {
                return Err(ThresholdApprovalCollectorStoreError::Conflict(
                    "threshold approval token id, digest, and signer must be unique".to_string(),
                ));
            }
            if existing.approver == token.approver {
                if existing.validate_time(now).is_ok() {
                    return Err(ThresholdApprovalCollectorStoreError::Conflict(
                        "threshold approval token id, digest, and signer must be unique"
                            .to_string(),
                    ));
                }
                replaced_token_id = Some(existing.id.as_str());
            }
        }
        let active_count = record
            .tokens
            .iter()
            .filter(|existing| {
                Some(existing.id.as_str()) != replaced_token_id
                    && existing.validate_time(now).is_ok()
            })
            .count()
            .checked_add(1)
            .ok_or_else(|| {
                ThresholdApprovalCollectorStoreError::Conflict(
                    "threshold approval token count overflowed".to_string(),
                )
            })?;
        let threshold = usize::try_from(record.requirement.threshold).map_err(|_| {
            ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval quorum does not fit this platform".to_string(),
            )
        })?;
        let next_state = if active_count >= threshold {
            ThresholdApprovalCollectorState::Ready
        } else {
            ThresholdApprovalCollectorState::Collecting
        };
        self.store.append_token(
            proposal_id,
            record.version,
            &token,
            replaced_token_id,
            next_state,
            now,
        )
    }

    pub fn deliver(
        &self,
        proposal_id: &str,
        now: u64,
    ) -> Result<CollectedThresholdApprovalSet, ThresholdApprovalCollectorStoreError> {
        let record = self
            .get_proposal(proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.state != ThresholdApprovalCollectorState::Ready {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal is not ready for delivery".to_string(),
            ));
        }
        record
            .proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        record.validate_update_time(now)?;
        // A token may expire well before the proposal deadline. Ignore superseded
        // or expired history and deliver only the currently valid set.
        let valid_tokens = record
            .tokens
            .iter()
            .filter(|token| token.validate_time(now).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        let threshold = usize::try_from(record.requirement.threshold).map_err(|_| {
            ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval quorum does not fit this platform".to_string(),
            )
        })?;
        if valid_tokens.len() < threshold {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval quorum is no longer satisfied".to_string(),
            ));
        }
        let delivered = self.store.transition(
            proposal_id,
            record.version,
            ThresholdApprovalCollectorState::Delivered,
            now,
        )?;
        Ok(CollectedThresholdApprovalSet {
            proposal: delivered.proposal,
            tokens: valid_tokens,
        })
    }

    pub fn cancel(
        &self,
        proposal_id: &str,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let record = self
            .get_proposal(proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal is already terminal".to_string(),
            ));
        }
        record.validate_update_time(now)?;
        self.store.transition(
            proposal_id,
            record.version,
            ThresholdApprovalCollectorState::Cancelled,
            now,
        )
    }
}

#[derive(Default)]
pub struct InMemoryThresholdApprovalCollectorStore {
    proposals: RwLock<HashMap<String, ThresholdApprovalCollectorProposal>>,
}

impl InMemoryThresholdApprovalCollectorStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ThresholdApprovalCollectorStore for InMemoryThresholdApprovalCollectorStore {
    fn create(
        &self,
        proposal: &ThresholdApprovalCollectorProposal,
    ) -> Result<(), ThresholdApprovalCollectorStoreError> {
        let mut proposals = self.proposals.write().map_err(|_| {
            ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
        })?;
        let id = &proposal.proposal.body.proposal_id;
        match proposals.get(id) {
            Some(existing) if existing == proposal => Ok(()),
            Some(_) => Err(ThresholdApprovalCollectorStoreError::Conflict(
                "proposal id already exists with different content".to_string(),
            )),
            None => {
                proposals.insert(id.clone(), proposal.clone());
                Ok(())
            }
        }
    }

    fn get(
        &self,
        proposal_id: &str,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>
    {
        self.proposals
            .read()
            .map_err(|_| {
                ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
            })
            .map(|proposals| proposals.get(proposal_id).cloned())
    }

    fn append_token(
        &self,
        proposal_id: &str,
        expected_version: u64,
        token: &GovernedApprovalToken,
        replaced_token_id: Option<&str>,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut proposals = self.proposals.write().map_err(|_| {
            ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
        })?;
        let record = proposals.get_mut(proposal_id).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::NotFound(proposal_id.to_string())
        })?;
        if record.version != expected_version || record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        let next_version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        if let Some(replaced_token_id) = replaced_token_id {
            let existing = record
                .tokens
                .iter_mut()
                .find(|existing| existing.id == replaced_token_id)
                .ok_or_else(|| {
                    ThresholdApprovalCollectorStoreError::Conflict(
                        "threshold approval replacement token disappeared".to_string(),
                    )
                })?;
            *existing = token.clone();
        } else {
            record.tokens.push(token.clone());
        }
        record.state = next_state;
        record.version = next_version;
        record.updated_at = updated_at;
        Ok(record.clone())
    }

    fn transition(
        &self,
        proposal_id: &str,
        expected_version: u64,
        next_state: ThresholdApprovalCollectorState,
        updated_at: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut proposals = self.proposals.write().map_err(|_| {
            ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
        })?;
        let record = proposals.get_mut(proposal_id).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::NotFound(proposal_id.to_string())
        })?;
        if record.version != expected_version || record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal changed concurrently".to_string(),
            ));
        }
        let next_version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.state = next_state;
        record.version = next_version;
        record.updated_at = updated_at;
        Ok(record.clone())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{
        GovernedApprovalTokenBody, ThresholdApprovalProposalBody,
    };
    use chio_core::capability::threshold_approval::ThresholdApproverIdentity;
    use chio_core::crypto::{sha256_hex, Keypair};

    struct Fixture {
        collector: ThresholdApprovalCollector,
        authority: Keypair,
        submitter: Keypair,
        alice: Keypair,
        bob: Keypair,
        subject: Keypair,
        requirement: ThresholdApprovalRequirement,
    }

    fn fixture() -> Fixture {
        let authority = Keypair::generate();
        let submitter = Keypair::generate();
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let subject = Keypair::generate();
        let policy_hash = sha256_hex(b"active-policy");
        let requirement = ThresholdApprovalRequirement::new(
            policy_hash.clone(),
            2,
            vec![
                ThresholdApproverIdentity {
                    identifier: "alice".to_string(),
                    public_key: alice.public_key(),
                },
                ThresholdApproverIdentity {
                    identifier: "bob".to_string(),
                    public_key: bob.public_key(),
                },
                ThresholdApproverIdentity {
                    identifier: "submitter".to_string(),
                    public_key: submitter.public_key(),
                },
            ],
            "directory-v1".to_string(),
            100,
        )
        .unwrap();
        let collector = ThresholdApprovalCollector::new(
            Arc::new(InMemoryThresholdApprovalCollectorStore::new()),
            policy_hash,
            vec![authority.public_key()],
        );
        Fixture {
            collector,
            authority,
            submitter,
            alice,
            bob,
            subject,
            requirement,
        }
    }

    fn proposal(fixture: &Fixture, proposal_id: &str) -> ThresholdApprovalProposal {
        ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: chio_core::capability::governance::THRESHOLD_APPROVAL_PROPOSAL_SCHEMA
                    .to_string(),
                proposal_id: proposal_id.to_string(),
                request_id: "request-1".to_string(),
                governed_intent_hash: sha256_hex(b"intent"),
                subject: fixture.subject.public_key(),
                authorizing_capability_digest: sha256_hex(b"capability"),
                policy_hash: fixture.requirement.policy_hash.clone(),
                threshold: fixture.requirement.threshold,
                eligible_set_digest: fixture.requirement.eligible_set_digest.clone(),
                proposal_created_at: 100,
                proposal_deadline: 200,
                policy_authority: fixture.authority.public_key(),
            },
            &fixture.authority,
        )
        .unwrap()
    }

    fn token(
        proposal: &ThresholdApprovalProposal,
        approver: &Keypair,
        token_id: &str,
    ) -> GovernedApprovalToken {
        token_expiring_at(proposal, approver, token_id, 199)
    }

    fn token_expiring_at(
        proposal: &ThresholdApprovalProposal,
        approver: &Keypair,
        token_id: &str,
        expires_at: u64,
    ) -> GovernedApprovalToken {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: token_id.to_string(),
                approver: approver.public_key(),
                subject: proposal.body.subject.clone(),
                governed_intent_hash: proposal.body.governed_intent_hash.clone(),
                request_id: proposal.body.request_id.clone(),
                threshold_proposal_hash: Some(proposal.artifact_digest().unwrap()),
                issued_at: 101,
                expires_at,
                decision: GovernedApprovalDecision::Approved,
            },
            approver,
        )
        .unwrap()
    }

    #[test]
    fn collector_persists_quorum_before_returning_original_tokens() {
        let fixture = fixture();
        let proposal = proposal(&fixture, "proposal-1");
        fixture
            .collector
            .create_proposal(
                proposal.clone(),
                fixture.requirement.clone(),
                Some(fixture.submitter.public_key()),
                true,
                100,
            )
            .unwrap();

        let separated = fixture
            .collector
            .submit_token(
                "proposal-1",
                token(&proposal, &fixture.submitter, "token-submitter"),
                110,
            )
            .unwrap_err();
        assert!(separated.to_string().contains("cannot approve"));

        let collecting = fixture
            .collector
            .submit_token(
                "proposal-1",
                token(&proposal, &fixture.alice, "token-alice"),
                110,
            )
            .unwrap();
        assert_eq!(
            collecting.state,
            ThresholdApprovalCollectorState::Collecting
        );
        let duplicate = fixture
            .collector
            .submit_token(
                "proposal-1",
                token(&proposal, &fixture.alice, "token-alice-2"),
                111,
            )
            .unwrap_err();
        assert!(duplicate.to_string().contains("must be unique"));

        let ready = fixture
            .collector
            .submit_token(
                "proposal-1",
                token(&proposal, &fixture.bob, "token-bob"),
                112,
            )
            .unwrap();
        assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);
        assert_eq!(ready.tokens.len(), 2);

        let delivered = fixture.collector.deliver("proposal-1", 113).unwrap();
        assert_eq!(delivered.proposal, proposal);
        assert_eq!(
            delivered
                .tokens
                .iter()
                .map(|value| value.id.as_str())
                .collect::<Vec<_>>(),
            vec!["token-alice", "token-bob"]
        );
        let stored = fixture
            .collector
            .get_proposal("proposal-1")
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, ThresholdApprovalCollectorState::Delivered);
        assert!(fixture.collector.deliver("proposal-1", 114).is_err());
    }

    #[test]
    fn collector_rejects_stale_policy_changed_intent_and_terminal_updates() {
        let fixture = fixture();
        let mut stale_requirement = fixture.requirement.clone();
        stale_requirement.policy_hash = sha256_hex(b"stale-policy");
        assert!(fixture
            .collector
            .create_proposal(
                proposal(&fixture, "stale"),
                stale_requirement,
                None,
                false,
                100,
            )
            .is_err());

        let proposal = proposal(&fixture, "changed-intent");
        fixture
            .collector
            .create_proposal(
                proposal.clone(),
                fixture.requirement.clone(),
                None,
                false,
                100,
            )
            .unwrap();
        let mut changed = token(&proposal, &fixture.alice, "changed-token");
        changed.governed_intent_hash = sha256_hex(b"different-intent");
        assert!(fixture
            .collector
            .submit_token("changed-intent", changed, 110)
            .is_err());
        fixture.collector.cancel("changed-intent", 111).unwrap();
        assert!(fixture
            .collector
            .submit_token(
                "changed-intent",
                token(&proposal, &fixture.alice, "late-token"),
                112,
            )
            .is_err());
    }

    // Token expiry is bounded above by the proposal deadline but not below, so a
    // set that was quorate at submission can hold expired tokens by delivery time
    // while the proposal itself is still valid.
    #[test]
    fn ready_proposal_accepts_replacement_for_an_expired_token() {
        let fixture = fixture();
        let proposal = proposal(&fixture, "expiring");
        fixture
            .collector
            .create_proposal(
                proposal.clone(),
                fixture.requirement.clone(),
                None,
                false,
                100,
            )
            .unwrap();

        fixture
            .collector
            .submit_token(
                "expiring",
                token_expiring_at(&proposal, &fixture.alice, "token-alice", 120),
                110,
            )
            .unwrap();
        let ready = fixture
            .collector
            .submit_token(
                "expiring",
                token_expiring_at(&proposal, &fixture.bob, "token-bob", 199),
                110,
            )
            .unwrap();
        assert_eq!(ready.state, ThresholdApprovalCollectorState::Ready);

        // The proposal deadline is 200, so only the tokens have lapsed here.
        let expired = fixture.collector.deliver("expiring", 150).unwrap_err();
        assert!(
            expired
                .to_string()
                .contains("quorum is no longer satisfied"),
            "delivery must reject lapsed tokens; got: {expired}"
        );
        let stored = fixture.collector.get_proposal("expiring").unwrap().unwrap();
        assert_eq!(stored.state, ThresholdApprovalCollectorState::Ready);

        let refreshed = fixture
            .collector
            .submit_token(
                "expiring",
                token_expiring_at(&proposal, &fixture.alice, "token-alice-fresh", 199),
                150,
            )
            .unwrap();
        assert_eq!(refreshed.state, ThresholdApprovalCollectorState::Ready);
        assert_eq!(refreshed.tokens.len(), 2);
        assert!(refreshed
            .tokens
            .iter()
            .any(|token| token.id == "token-alice-fresh"));
        assert!(!refreshed
            .tokens
            .iter()
            .any(|token| token.id == "token-alice"));

        let delivered = fixture.collector.deliver("expiring", 151).unwrap();
        assert_eq!(delivered.tokens.len(), 2);
        assert!(delivered
            .tokens
            .iter()
            .any(|token| token.id == "token-alice-fresh"));
    }
}
