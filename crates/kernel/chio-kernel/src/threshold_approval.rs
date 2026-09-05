use chio_core::capability::governance::{GovernedApprovalDecision, GovernedApprovalToken};
pub use chio_core::capability::governance::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody,
};
pub use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequest, ThresholdApprovalRequirement,
};
use chio_core::crypto::PublicKey;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::approval::ApprovalStoreError;
use crate::approval::{
    ThresholdApprovalProposalCreationContext, ThresholdApprovalProposalRegistration,
};

mod collector_validation;
mod verification;

pub use verification::{
    authorization_capability_hash, verify_threshold_approval_set,
    ThresholdApprovalVerificationError, ThresholdApprovalVerificationInput,
    VerifiedThresholdApprovalSet,
};
pub(crate) use verification::{
    verify_threshold_approval_proposal, verify_threshold_approval_set_with_requirement,
    ThresholdApprovalProposalVerificationInput,
};

/// Resolve current authority from an authenticated request source, never from
/// collector HTTP fields or a proposal body. Implementations must recheck policy,
/// capability authority, route, intent and submitter for each call. Collection
/// does not replace the kernel's independent execution-time admission checks.
pub trait ThresholdApprovalContextResolver: Send + Sync {
    fn resolve_context(
        &self,
        request_id: &str,
        now: u64,
    ) -> Result<ThresholdApprovalProposalCreationContext, ApprovalStoreError>;
}

impl<F> ThresholdApprovalContextResolver for F
where
    F: Fn(&str, u64) -> Result<ThresholdApprovalProposalCreationContext, ApprovalStoreError>
        + Send
        + Sync,
{
    fn resolve_context(
        &self,
        request_id: &str,
        now: u64,
    ) -> Result<ThresholdApprovalProposalCreationContext, ApprovalStoreError> {
        self(request_id, now)
    }
}

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
    /// None identifies a pre-context-binding record, which cannot authorize new
    /// collection or delivery until explicitly migrated using trusted context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_route: Option<ThresholdApprovalRequest>,
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
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError>;

    /// Bind a retained pre-context record once, preserving votes and the last
    /// state-transition timestamp (which also fixes the delivered token set).
    fn bind_request_route(
        &self,
        proposal_id: &str,
        expected_version: u64,
        route: &ThresholdApprovalRequest,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError>;

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
    context_resolver: Arc<dyn ThresholdApprovalContextResolver>,
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
        context_resolver: Arc<dyn ThresholdApprovalContextResolver>,
    ) -> Self {
        Self {
            store,
            active_policy_hash,
            trusted_policy_authorities,
            context_resolver,
        }
    }

    pub fn create_proposal(
        &self,
        proposal: ThresholdApprovalProposal,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        let context = self.resolve_context(&proposal.body.request_id, now)?;
        ThresholdApprovalProposalRegistration::new(
            proposal.clone(),
            &context,
            &self.trusted_policy_authorities,
            now,
        )
        .map_err(collector_validation::context_error)?;
        let record = ThresholdApprovalCollectorProposal {
            proposal,
            request_route: Some(context.matched_request().clone()),
            requirement: context.requirement().clone(),
            submitter: context.submitter().cloned(),
            require_submitter_separation: context.separation_of_duties(),
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
        let persisted = self.store.create(&record)?;
        if !persisted.registration_matches(&record)? {
            return Err(ThresholdApprovalCollectorStoreError::Serialization(
                "threshold proposal store returned different registration material".into(),
            ));
        }
        persisted.validate_restored(
            &record.proposal.body.proposal_id,
            &self.active_policy_hash,
            &self.trusted_policy_authorities,
        )?;
        persisted.validate_update_time(now)?;
        persisted.validate_current_context(&context, &self.trusted_policy_authorities)?;
        Ok(persisted)
    }

    /// Authenticate a historical snapshot against the collector's current trust
    /// configuration. Expiry is checked separately when submitting or delivering.
    pub fn get_proposal(
        &self,
        proposal_id: &str,
        now: u64,
    ) -> Result<Option<ThresholdApprovalCollectorProposal>, ThresholdApprovalCollectorStoreError>
    {
        let record = self.store.get(proposal_id)?;
        if let Some(record) = &record {
            record.validate_restored(
                proposal_id,
                &self.active_policy_hash,
                &self.trusted_policy_authorities,
            )?;
            record.validate_update_time(now)?;
            let context = self.resolve_context(&record.proposal.body.request_id, now)?;
            record.validate_current_context(&context, &self.trusted_policy_authorities)?;
        }
        Ok(record)
    }

    fn resolve_context(
        &self,
        request_id: &str,
        now: u64,
    ) -> Result<ThresholdApprovalProposalCreationContext, ThresholdApprovalCollectorStoreError>
    {
        let context = self
            .context_resolver
            .resolve_context(request_id, now)
            .map_err(collector_validation::context_error)?;
        if context.matched_request().request_id() != request_id {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval context resolved a different request".to_string(),
            ));
        }
        Ok(context)
    }

    /// Explicit operator migration for a retained unbound proposal. The trusted
    /// resolver must recover the original authenticated request, not infer it from
    /// these records. No policy, token, or delivery timestamp is rewritten.
    pub fn bind_existing_proposal(
        &self,
        proposal_id: &str,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut record = self
            .store
            .get(proposal_id)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        record.validate_restored(
            proposal_id,
            &self.active_policy_hash,
            &self.trusted_policy_authorities,
        )?;
        record.validate_update_time(now)?;
        let context = self.resolve_context(&record.proposal.body.request_id, now)?;
        if record.request_route.is_some() {
            record.validate_current_context(&context, &self.trusted_policy_authorities)?;
            return Ok(record);
        }
        record.request_route = Some(context.matched_request().clone());
        record.validate_current_context(&context, &self.trusted_policy_authorities)?;
        let persisted = self.store.bind_request_route(
            proposal_id,
            record.version,
            context.matched_request(),
        )?;
        if !persisted.registration_matches(&record)?
            || persisted.updated_at != record.updated_at
            || persisted.state != record.state
            || persisted.tokens != record.tokens
        {
            return Err(ThresholdApprovalCollectorStoreError::Serialization(
                "threshold proposal migration changed retained history".into(),
            ));
        }
        Ok(persisted)
    }

    pub fn submit_token(
        &self,
        proposal_id: &str,
        token: GovernedApprovalToken,
        now: u64,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let record = self
            .get_proposal(proposal_id, now)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        record.validate_update_time(now)?;
        record
            .proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        let digest = token
            .artifact_digest()
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        for existing in &record.tokens {
            let existing_digest = existing.artifact_digest().map_err(|error| {
                ThresholdApprovalCollectorStoreError::Serialization(error.to_string())
            })?;
            if existing_digest == digest {
                // An acknowledgement retry returns the original stored state
                // without adding a vote or extending token validity.
                return Ok(record);
            }
        }
        if record.state.is_terminal() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal no longer accepts updates".to_string(),
            ));
        }
        record.validate_new_token(&token, now)?;
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
            .get_proposal(proposal_id, now)?
            .ok_or_else(|| ThresholdApprovalCollectorStoreError::NotFound(proposal_id.into()))?;
        if !matches!(
            record.state,
            ThresholdApprovalCollectorState::Ready | ThresholdApprovalCollectorState::Delivered
        ) {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval proposal is not ready for delivery".to_string(),
            ));
        }
        record
            .proposal
            .validate_at(now)
            .map_err(|error| ThresholdApprovalCollectorStoreError::Conflict(error.to_string()))?;
        record.validate_update_time(now)?;
        // A delivered record is terminal. Its timestamp and retained tokens fix
        // the original response set, including after an acknowledgement is lost.
        let selected_at = if record.state == ThresholdApprovalCollectorState::Delivered {
            record.updated_at
        } else {
            now
        };
        let valid_tokens = record
            .tokens
            .iter()
            .filter(|token| token.is_valid_at(selected_at))
            .cloned()
            .collect::<Vec<_>>();
        let threshold = usize::try_from(record.requirement.threshold).map_err(|_| {
            ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval quorum does not fit this platform".to_string(),
            )
        })?;
        if valid_tokens.len() < threshold
            || valid_tokens.iter().any(|token| !token.is_valid_at(now))
        {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold approval quorum is no longer satisfied".to_string(),
            ));
        }
        if record.state == ThresholdApprovalCollectorState::Delivered {
            return Ok(CollectedThresholdApprovalSet {
                proposal: record.proposal,
                tokens: valid_tokens,
            });
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
            .get_proposal(proposal_id, now)?
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
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut proposals = self.proposals.write().map_err(|_| {
            ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
        })?;
        let id = &proposal.proposal.body.proposal_id;
        match proposals.get(id) {
            Some(existing) => {
                if existing.registration_matches(proposal)? {
                    Ok(existing.clone())
                } else {
                    Err(ThresholdApprovalCollectorStoreError::Conflict(
                        "proposal id already exists with different content".to_string(),
                    ))
                }
            }
            None => {
                proposals.insert(id.clone(), proposal.clone());
                Ok(proposal.clone())
            }
        }
    }

    fn bind_request_route(
        &self,
        proposal_id: &str,
        expected_version: u64,
        route: &ThresholdApprovalRequest,
    ) -> Result<ThresholdApprovalCollectorProposal, ThresholdApprovalCollectorStoreError> {
        let mut proposals = self.proposals.write().map_err(|_| {
            ThresholdApprovalCollectorStoreError::Backend("proposal map poisoned".to_string())
        })?;
        let record = proposals.get_mut(proposal_id).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::NotFound(proposal_id.to_string())
        })?;
        if record.version != expected_version || record.request_route.is_some() {
            return Err(ThresholdApprovalCollectorStoreError::Conflict(
                "threshold proposal changed or already has an authenticated route".to_string(),
            ));
        }
        let next_version = record.version.checked_add(1).ok_or_else(|| {
            ThresholdApprovalCollectorStoreError::Conflict("proposal version overflowed".into())
        })?;
        record.request_route = Some(route.clone());
        record.version = next_version;
        Ok(record.clone())
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
    use crate::approval::ThresholdApprovalProposalCreationParameters;
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
        let context = ThresholdApprovalProposalCreationContext::new(
            ThresholdApprovalProposalCreationParameters {
                matched_request: ThresholdApprovalRequest::new("request-1", "server", "tool")
                    .unwrap(),
                requirement: requirement.clone(),
                subject: subject.public_key(),
                governed_intent_hash: sha256_hex(b"intent"),
                authorization_capability_hash: sha256_hex(b"capability"),
                authorizing_capability_expires_at: 200,
                governed_operation_expires_at: 200,
                submitter: Some(submitter.public_key()),
                separation_of_duties: true,
            },
        )
        .unwrap();
        let collector = ThresholdApprovalCollector::new(
            Arc::new(InMemoryThresholdApprovalCollectorStore::new()),
            policy_hash,
            vec![authority.public_key()],
            Arc::new(move |_: &str, _: u64| Ok(context.clone())),
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
            .create_proposal(proposal.clone(), 100)
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
            .get_proposal("proposal-1", 120)
            .unwrap()
            .unwrap();
        assert_eq!(stored.state, ThresholdApprovalCollectorState::Delivered);
        assert_eq!(
            fixture.collector.deliver("proposal-1", 114).unwrap(),
            delivered
        );
    }

    #[test]
    fn collector_rejects_stale_policy_changed_intent_and_terminal_updates() {
        let fixture = fixture();
        let mut stale_body = proposal(&fixture, "stale").body;
        stale_body.policy_hash = sha256_hex(b"stale-policy");
        let stale_proposal =
            ThresholdApprovalProposal::sign(stale_body, &fixture.authority).unwrap();
        assert!(fixture
            .collector
            .create_proposal(stale_proposal, 100)
            .is_err());

        let proposal = proposal(&fixture, "changed-intent");
        fixture
            .collector
            .create_proposal(proposal.clone(), 100)
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
            .create_proposal(proposal.clone(), 100)
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
        let stored = fixture
            .collector
            .get_proposal("expiring", 120)
            .unwrap()
            .unwrap();
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
