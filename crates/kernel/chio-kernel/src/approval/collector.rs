//! Durable threshold proposal registration, vote collection, and replay projection.

use std::collections::{BTreeMap, HashSet};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::{
    governance::{
        GovernedApprovalDecision, GovernedApprovalToken, ThresholdApprovalProposal,
        VerifiedApprovalSetBody,
    },
    threshold_approval::{
        ThresholdApprovalRequest, ThresholdApprovalRequirement, MAX_THRESHOLD_APPROVAL_TOKENS,
    },
};
use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};

use super::{
    validate_reservation_digest, ApprovalReservationMember, ApprovalSetReservationInput,
    ApprovalStoreError, MAX_RESERVATION_IDENTIFIER_BYTES,
};

const MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES: usize = 262_144;

fn threshold_eligible_map(
    requirement: &ThresholdApprovalRequirement,
) -> Result<BTreeMap<String, PublicKey>, ApprovalStoreError> {
    let mut eligible = BTreeMap::new();
    for approver in &requirement.eligible_approvers {
        if eligible
            .insert(approver.identifier.clone(), approver.public_key.clone())
            .is_some()
        {
            return Err(ApprovalStoreError::Invalid(
                "threshold approval requirement contains a duplicate identifier".to_string(),
            ));
        }
    }
    Ok(eligible)
}

/// Durable state of one policy-authority-signed threshold proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdApprovalCollectorStatus {
    Collecting,
    Satisfied,
    Delivered,
    Expired,
}

impl ThresholdApprovalCollectorStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Satisfied => "satisfied",
            Self::Delivered => "delivered",
            Self::Expired => "expired",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "collecting" => Some(Self::Collecting),
            "satisfied" => Some(Self::Satisfied),
            "delivered" => Some(Self::Delivered),
            "expired" => Some(Self::Expired),
            _ => None,
        }
    }
}

/// Authenticated current request bindings required to create a durable proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdApprovalProposalCreationContext {
    matched_request: ThresholdApprovalRequest,
    requirement: ThresholdApprovalRequirement,
    subject: PublicKey,
    governed_intent_hash: String,
    authorization_capability_hash: String,
    authorizing_capability_expires_at: u64,
    governed_operation_expires_at: u64,
    submitter: Option<PublicKey>,
    separation_of_duties: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdApprovalProposalCreationParameters {
    pub matched_request: ThresholdApprovalRequest,
    pub requirement: ThresholdApprovalRequirement,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub authorization_capability_hash: String,
    pub authorizing_capability_expires_at: u64,
    pub governed_operation_expires_at: u64,
    pub submitter: Option<PublicKey>,
    pub separation_of_duties: bool,
}

impl ThresholdApprovalProposalCreationContext {
    pub fn new(
        parameters: ThresholdApprovalProposalCreationParameters,
    ) -> Result<Self, ApprovalStoreError> {
        let ThresholdApprovalProposalCreationParameters {
            matched_request,
            requirement,
            subject,
            governed_intent_hash,
            authorization_capability_hash,
            authorizing_capability_expires_at,
            governed_operation_expires_at,
            submitter,
            separation_of_duties,
        } = parameters;
        ThresholdApprovalRequest::new(
            matched_request.request_id(),
            matched_request.server_id(),
            matched_request.tool_name(),
        )
        .map_err(ApprovalStoreError::Invalid)?;
        requirement
            .validate()
            .map_err(ApprovalStoreError::Invalid)?;
        validate_reservation_digest(&governed_intent_hash, "governed_intent_hash")?;
        validate_reservation_digest(
            &authorization_capability_hash,
            "authorization_capability_hash",
        )?;
        if authorizing_capability_expires_at == 0 || governed_operation_expires_at == 0 {
            return Err(ApprovalStoreError::Invalid(
                "threshold proposal authority expiries must be nonzero".to_string(),
            ));
        }
        if separation_of_duties && submitter.is_none() {
            return Err(ApprovalStoreError::Invalid(
                "separation of duties requires an authenticated submitter".to_string(),
            ));
        }
        Ok(Self {
            matched_request,
            requirement,
            subject,
            governed_intent_hash,
            authorization_capability_hash,
            authorizing_capability_expires_at,
            governed_operation_expires_at,
            submitter,
            separation_of_duties,
        })
    }

    #[must_use]
    pub fn matched_request(&self) -> &ThresholdApprovalRequest {
        &self.matched_request
    }

    #[must_use]
    pub fn requirement(&self) -> &ThresholdApprovalRequirement {
        &self.requirement
    }

    #[must_use]
    pub fn subject(&self) -> &PublicKey {
        &self.subject
    }

    #[must_use]
    pub fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    #[must_use]
    pub fn authorization_capability_hash(&self) -> &str {
        &self.authorization_capability_hash
    }

    #[must_use]
    pub fn authorizing_capability_expires_at(&self) -> u64 {
        self.authorizing_capability_expires_at
    }

    #[must_use]
    pub fn governed_operation_expires_at(&self) -> u64 {
        self.governed_operation_expires_at
    }

    #[must_use]
    pub fn submitter(&self) -> Option<&PublicKey> {
        self.submitter.as_ref()
    }

    #[must_use]
    pub fn separation_of_duties(&self) -> bool {
        self.separation_of_duties
    }
}

/// Validated immutable registration material for one threshold proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThresholdApprovalProposalRegistration {
    proposal: ThresholdApprovalProposal,
    server_id: String,
    tool_name: String,
    eligible_approvers: BTreeMap<String, PublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    submitter_fingerprint: Option<String>,
    separation_of_duties: bool,
}

impl ThresholdApprovalProposalRegistration {
    pub fn new(
        proposal: ThresholdApprovalProposal,
        context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<Self, ApprovalStoreError> {
        let registration = Self {
            proposal,
            server_id: context.matched_request.server_id().to_string(),
            tool_name: context.matched_request.tool_name().to_string(),
            eligible_approvers: threshold_eligible_map(&context.requirement)?,
            submitter_fingerprint: context.submitter.as_ref().map(PublicKey::to_hex),
            separation_of_duties: context.separation_of_duties,
        };
        registration.validate_for_creation(context, trusted_policy_authorities, now)?;
        Ok(registration)
    }

    pub fn from_persisted_parts(
        proposal: ThresholdApprovalProposal,
        server_id: String,
        tool_name: String,
        eligible_approvers: BTreeMap<String, PublicKey>,
        submitter_fingerprint: Option<String>,
        separation_of_duties: bool,
    ) -> Result<Self, ApprovalStoreError> {
        let registration = Self {
            proposal,
            server_id,
            tool_name,
            eligible_approvers,
            submitter_fingerprint,
            separation_of_duties,
        };
        registration.validate(true)?;
        Ok(registration)
    }

    fn validate(&self, persisted: bool) -> Result<(), ApprovalStoreError> {
        let invalid = |message: String| collector_validation_error(persisted, message);
        let proposal_bytes = canonical_json_bytes(&self.proposal).map_err(|error| {
            invalid(format!(
                "threshold proposal canonicalization failed: {error}"
            ))
        })?;
        if proposal_bytes.len() > MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES {
            return Err(invalid(
                "threshold proposal exceeds the collector storage limit".to_string(),
            ));
        }
        let algorithm = self.proposal.algorithm.unwrap_or_default();
        if self.proposal.policy_authority().algorithm() != algorithm
            || self.proposal.signature.algorithm() != algorithm
            || !self
                .proposal
                .verify_signature()
                .map_err(|error| invalid(format!("threshold proposal signature failed: {error}")))?
        {
            return Err(invalid(
                "threshold proposal signature did not verify".to_string(),
            ));
        }
        let eligible_bytes = canonical_json_bytes(&self.eligible_approvers).map_err(|error| {
            invalid(format!(
                "threshold eligible approvers canonicalization failed: {error}"
            ))
        })?;
        if eligible_bytes.len() > MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES {
            return Err(invalid(
                "threshold eligible approvers exceed the collector storage limit".to_string(),
            ));
        }
        let body = self.proposal.body();
        validate_collector_identifier(&self.server_id, "server_id", persisted)?;
        validate_collector_identifier(&self.tool_name, "tool_name", persisted)?;
        let lifetime = body
            .proposal_deadline
            .checked_sub(body.proposal_created_at())
            .ok_or_else(|| invalid("threshold proposal deadline precedes creation".to_string()))?;
        let requirement = ThresholdApprovalRequirement::new(
            body.policy_hash().to_string(),
            body.required(),
            self.eligible_approvers
                .iter()
                .map(|(identifier, public_key)| {
                    chio_core::capability::threshold_approval::ThresholdApproverIdentity {
                        identifier: identifier.clone(),
                        public_key: public_key.clone(),
                    }
                })
                .collect(),
            "durable-collector".to_string(),
            lifetime,
        )
        .map_err(|error| invalid(format!("threshold eligible set is invalid: {error}")))?;
        if requirement.eligible_set_digest != body.eligible_set_digest() {
            return Err(invalid(
                "threshold proposal eligible-set digest does not match its approvers".to_string(),
            ));
        }
        if self.separation_of_duties && self.submitter_fingerprint.is_none() {
            return Err(invalid(
                "separation of duties requires a submitter fingerprint".to_string(),
            ));
        }
        if let Some(fingerprint) = self.submitter_fingerprint.as_deref() {
            // This is the full algorithm-aware public-key encoding, not a
            // replay identifier. Current authority validation compares it with
            // the authenticated typed submitter; hybrid keys exceed 512 bytes.
            validate_collector_text(
                fingerprint,
                "submitter_fingerprint",
                MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES,
                persisted,
            )?;
        }
        Ok(())
    }

    pub fn validate_current_authority(
        &self,
        current_policy_hash: &str,
        trusted_policy_authorities: &[PublicKey],
    ) -> Result<(), ApprovalStoreError> {
        validate_reservation_digest(current_policy_hash, "current_policy_hash")?;
        if self.proposal.body().policy_hash() != current_policy_hash {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal carries a stale policy hash".to_string(),
            ));
        }
        if !trusted_policy_authorities.contains(self.proposal.policy_authority()) {
            return Err(ApprovalStoreError::Invalid(
                "threshold proposal signer is not a trusted policy authority".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_creation(
        &self,
        context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<(), ApprovalStoreError> {
        self.validate_current_context(context, trusted_policy_authorities)?;
        let body = self.proposal.body();
        if now < body.proposal_created_at() {
            return Err(ApprovalStoreError::Invalid(
                "threshold proposal is not yet valid".to_string(),
            ));
        }
        if now >= body.proposal_deadline {
            return Err(ApprovalStoreError::AlreadyResolved(
                "threshold proposal has expired".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_current_context(
        &self,
        context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
    ) -> Result<(), ApprovalStoreError> {
        self.validate(false)?;
        let requirement = &context.requirement;
        self.validate_current_authority(&requirement.policy_hash, trusted_policy_authorities)?;
        let body = self.proposal.body();
        if body.request_id() != context.matched_request.request_id()
            || self.server_id != context.matched_request.server_id()
            || self.tool_name != context.matched_request.tool_name()
        {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal does not match the authenticated request route".to_string(),
            ));
        }
        if body.required() != requirement.threshold
            || body.eligible_set_digest() != requirement.eligible_set_digest
            || self.eligible_approvers != threshold_eligible_map(requirement)?
        {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal does not match the current approval requirement".to_string(),
            ));
        }
        if self.separation_of_duties != context.separation_of_duties {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal separation-of-duties policy changed".to_string(),
            ));
        }
        let current_submitter = context.submitter.as_ref().map(PublicKey::to_hex);
        if self.submitter_fingerprint != current_submitter {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal authenticated submitter changed".to_string(),
            ));
        }
        if body.subject() != &context.subject
            || body.governed_intent_hash() != context.governed_intent_hash
            || body.authorization_capability_hash() != context.authorization_capability_hash
        {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal does not match the authenticated request bindings".to_string(),
            ));
        }
        let exact_deadline = body
            .proposal_created_at()
            .checked_add(requirement.timeout_seconds)
            .ok_or_else(|| {
                ApprovalStoreError::Invalid(
                    "threshold proposal deadline arithmetic overflowed".to_string(),
                )
            })?
            .min(context.authorizing_capability_expires_at)
            .min(context.governed_operation_expires_at);
        if body.proposal_deadline != exact_deadline {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal deadline does not match authenticated authority bounds"
                    .to_string(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn proposal(&self) -> &ThresholdApprovalProposal {
        &self.proposal
    }

    #[must_use]
    pub fn eligible_approvers(&self) -> &BTreeMap<String, PublicKey> {
        &self.eligible_approvers
    }

    #[must_use]
    pub fn server_id(&self) -> &str {
        &self.server_id
    }

    #[must_use]
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    #[must_use]
    pub fn submitter_fingerprint(&self) -> Option<&str> {
        self.submitter_fingerprint.as_deref()
    }

    #[must_use]
    pub fn separation_of_duties(&self) -> bool {
        self.separation_of_duties
    }
}

/// One original signed approval token and its durable collector metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdApprovalVoteRecord {
    token: GovernedApprovalToken,
    token_digest: String,
    approver_fingerprint: String,
    received_at: u64,
}

impl ThresholdApprovalVoteRecord {
    pub fn validate_new(
        registration: &ThresholdApprovalProposalRegistration,
        token: GovernedApprovalToken,
        received_at: u64,
        persisted: bool,
    ) -> Result<Self, ApprovalStoreError> {
        let invalid = |message: String| collector_validation_error(persisted, message);
        let body = registration.proposal.body();
        if received_at < body.proposal_created_at() || received_at >= body.proposal_deadline {
            return Err(invalid(
                "threshold vote was received outside the proposal window".to_string(),
            ));
        }
        let proposal_hash = registration
            .proposal
            .proposal_hash()
            .map_err(|error| invalid(format!("threshold proposal hash failed: {error}")))?;
        if token.threshold_proposal_hash.as_deref() != Some(proposal_hash.as_str()) {
            return Err(invalid(
                "approval token proposal binding does not match".to_string(),
            ));
        }
        if token.request_id != body.request_id() {
            return Err(invalid(
                "approval token request binding does not match".to_string(),
            ));
        }
        if token.governed_intent_hash != body.governed_intent_hash() {
            return Err(invalid(
                "approval token intent binding does not match".to_string(),
            ));
        }
        if &token.subject != body.subject() {
            return Err(invalid(
                "approval token subject binding does not match".to_string(),
            ));
        }
        if token.decision != GovernedApprovalDecision::Approved {
            return Err(invalid(
                "threshold collector accepts only approved tokens".to_string(),
            ));
        }
        validate_collector_identifier(&token.id, "approval_token_id", persisted)?;
        if token.issued_at < body.proposal_created_at()
            || token.issued_at >= body.proposal_deadline
            || received_at < token.issued_at
        {
            return Err(invalid(
                "approval token issuance is outside the proposal window".to_string(),
            ));
        }
        if token.expires_at <= token.issued_at
            || token.expires_at > body.proposal_deadline
            || received_at >= token.expires_at
        {
            return Err(invalid(
                "approval token expiry is outside the proposal window".to_string(),
            ));
        }
        let expected_algorithm = token.algorithm.unwrap_or_default();
        if token.approver.algorithm() != expected_algorithm
            || token.signature.algorithm() != expected_algorithm
        {
            return Err(invalid(
                "approval token signing algorithm is inconsistent".to_string(),
            ));
        }
        if !token
            .verify_signature()
            .map_err(|error| invalid(format!("approval token signature failed: {error}")))?
        {
            return Err(invalid(
                "approval token signature did not verify".to_string(),
            ));
        }
        let approver_fingerprint = token.approver.to_hex();
        if !registration
            .eligible_approvers
            .values()
            .any(|eligible| eligible == &token.approver)
        {
            return Err(invalid(
                "approval token signer is not policy-eligible".to_string(),
            ));
        }
        if registration.separation_of_duties
            && registration.submitter_fingerprint.as_deref() == Some(approver_fingerprint.as_str())
        {
            return Err(invalid(
                "proposal submitter cannot approve when separation of duties is required"
                    .to_string(),
            ));
        }
        let canonical = canonical_json_bytes(&token)
            .map_err(|error| invalid(format!("approval token canonicalization failed: {error}")))?;
        if canonical.len() > MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES {
            return Err(invalid(
                "approval token exceeds the collector storage limit".to_string(),
            ));
        }
        let token_digest = token
            .token_digest()
            .map_err(|error| invalid(format!("approval token digest failed: {error}")))?;
        Ok(Self {
            token,
            token_digest,
            approver_fingerprint,
            received_at,
        })
    }

    pub fn from_persisted_parts(
        registration: &ThresholdApprovalProposalRegistration,
        token: GovernedApprovalToken,
        token_digest: String,
        approver_fingerprint: String,
        received_at: u64,
    ) -> Result<Self, ApprovalStoreError> {
        let validated = Self::validate_new(registration, token, received_at, true)?;
        if validated.token_digest != token_digest
            || validated.approver_fingerprint != approver_fingerprint
        {
            return Err(ApprovalStoreError::Serialization(
                "persisted threshold vote metadata does not match its signed token".to_string(),
            ));
        }
        Ok(validated)
    }

    #[must_use]
    pub fn token(&self) -> &GovernedApprovalToken {
        &self.token
    }

    #[must_use]
    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }

    #[must_use]
    pub fn approver_fingerprint(&self) -> &str {
        &self.approver_fingerprint
    }

    #[must_use]
    pub fn received_at(&self) -> u64 {
        self.received_at
    }
}

/// Pure validated projection of a threshold approval set and its history.
/// This type is not a persistence owner or proof of current authorization.
/// Use `ThresholdApprovalCollector` for collection and current-context checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdApprovalProposalRecord {
    registration: ThresholdApprovalProposalRegistration,
    status: ThresholdApprovalCollectorStatus,
    votes: Vec<ThresholdApprovalVoteRecord>,
    satisfied_at: Option<u64>,
    delivered_at: Option<u64>,
}

impl ThresholdApprovalProposalRecord {
    pub fn from_persisted_parts(
        registration: ThresholdApprovalProposalRegistration,
        status: ThresholdApprovalCollectorStatus,
        votes: Vec<ThresholdApprovalVoteRecord>,
        satisfied_at: Option<u64>,
        delivered_at: Option<u64>,
    ) -> Result<Self, ApprovalStoreError> {
        registration.validate(true)?;
        let record = Self {
            registration,
            status,
            votes,
            satisfied_at,
            delivered_at,
        };
        record.validate_persisted_state()?;
        Ok(record)
    }

    fn validate_persisted_state(&self) -> Result<(), ApprovalStoreError> {
        if self.votes.len() > MAX_THRESHOLD_APPROVAL_TOKENS {
            return Err(ApprovalStoreError::Serialization(
                "persisted threshold vote count exceeds the protocol ceiling".to_string(),
            ));
        }
        let mut token_ids = HashSet::new();
        let mut token_digests = HashSet::new();
        let mut approvers = HashSet::new();
        for vote in &self.votes {
            let validated = ThresholdApprovalVoteRecord::from_persisted_parts(
                &self.registration,
                vote.token.clone(),
                vote.token_digest.clone(),
                vote.approver_fingerprint.clone(),
                vote.received_at,
            )?;
            if !token_ids.insert(validated.token.id.clone())
                || !token_digests.insert(validated.token_digest)
                || !approvers.insert(validated.approver_fingerprint)
            {
                return Err(ApprovalStoreError::Serialization(
                    "persisted threshold votes contain duplicate identities".to_string(),
                ));
            }
        }
        let required =
            usize::try_from(self.registration.proposal.body().required()).map_err(|_| {
                ApprovalStoreError::Serialization(
                    "persisted threshold requirement does not fit this platform".to_string(),
                )
            })?;
        let threshold_met = self.votes.len() >= required;
        match self.status {
            ThresholdApprovalCollectorStatus::Collecting => {
                if threshold_met || self.satisfied_at.is_some() || self.delivered_at.is_some() {
                    return Err(ApprovalStoreError::Serialization(
                        "collecting threshold proposal has terminal state metadata".to_string(),
                    ));
                }
            }
            ThresholdApprovalCollectorStatus::Satisfied => {
                if !threshold_met || self.satisfied_at.is_none() || self.delivered_at.is_some() {
                    return Err(ApprovalStoreError::Serialization(
                        "satisfied threshold proposal has inconsistent state metadata".to_string(),
                    ));
                }
            }
            ThresholdApprovalCollectorStatus::Delivered => {
                if !threshold_met || self.satisfied_at.is_none() || self.delivered_at.is_none() {
                    return Err(ApprovalStoreError::Serialization(
                        "delivered threshold proposal has inconsistent state metadata".to_string(),
                    ));
                }
            }
            ThresholdApprovalCollectorStatus::Expired => {
                if self.delivered_at.is_some() || threshold_met != self.satisfied_at.is_some() {
                    return Err(ApprovalStoreError::Serialization(
                        "expired threshold proposal has inconsistent state metadata".to_string(),
                    ));
                }
            }
        }
        // All votes above have valid signatures and distinct signers. A stored
        // satisfaction time must also be causally supported by a received quorum,
        // not merely fall inside the proposal's signed validity window. Later
        // surplus votes do not move the time at which the quorum was first met.
        if self.satisfied_at.is_some_and(|satisfied_at| {
            self.votes
                .iter()
                .filter(|vote| vote.received_at <= satisfied_at)
                .count()
                < required
        }) {
            return Err(ApprovalStoreError::Serialization(
                "persisted threshold satisfaction precedes receipt of a quorum".to_string(),
            ));
        }
        let created_at = self.registration.proposal.body().proposal_created_at();
        let deadline = self.registration.proposal.body().proposal_deadline;
        if self
            .satisfied_at
            .is_some_and(|timestamp| timestamp < created_at || timestamp >= deadline)
            || self.delivered_at.is_some_and(|timestamp| {
                timestamp < self.satisfied_at.unwrap_or(created_at) || timestamp >= deadline
            })
        {
            return Err(ApprovalStoreError::Serialization(
                "threshold proposal transition timestamp is outside its signed window".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_current_bindings(
        &self,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
    ) -> Result<(), ApprovalStoreError> {
        self.registration
            .validate_current_context(current_context, trusted_policy_authorities)
    }

    pub fn existing_vote_for(
        &self,
        token: &GovernedApprovalToken,
    ) -> Result<Option<&ThresholdApprovalVoteRecord>, ApprovalStoreError> {
        let digest = token
            .token_digest()
            .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?;
        let fingerprint = token.approver.to_hex();
        for vote in &self.votes {
            if vote.token.id == token.id
                || vote.token_digest == digest
                || vote.approver_fingerprint == fingerprint
            {
                if vote.token == *token
                    && vote.token_digest == digest
                    && vote.approver_fingerprint == fingerprint
                {
                    return Ok(Some(vote));
                }
                return Err(ApprovalStoreError::Replay(
                    "threshold vote reuses a token ID, digest, or approver".to_string(),
                ));
            }
        }
        Ok(None)
    }

    #[must_use]
    pub fn registration(&self) -> &ThresholdApprovalProposalRegistration {
        &self.registration
    }

    #[must_use]
    pub fn proposal(&self) -> &ThresholdApprovalProposal {
        self.registration.proposal()
    }

    #[must_use]
    pub fn status(&self) -> ThresholdApprovalCollectorStatus {
        self.status
    }

    #[must_use]
    pub fn votes(&self) -> &[ThresholdApprovalVoteRecord] {
        &self.votes
    }

    #[must_use]
    pub fn approval_tokens(&self) -> Vec<GovernedApprovalToken> {
        self.votes.iter().map(|vote| vote.token.clone()).collect()
    }

    #[must_use]
    pub fn satisfied_at(&self) -> Option<u64> {
        self.satisfied_at
    }

    #[must_use]
    pub fn delivered_at(&self) -> Option<u64> {
        self.delivered_at
    }

    pub fn reservation_input(&self) -> Result<ApprovalSetReservationInput, ApprovalStoreError> {
        if !matches!(
            self.status,
            ThresholdApprovalCollectorStatus::Satisfied
                | ThresholdApprovalCollectorStatus::Delivered
        ) {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal is not ready for replay reservation".to_string(),
            ));
        }
        let body = VerifiedApprovalSetBody::new(
            self.votes
                .iter()
                .map(|vote| vote.token_digest.clone())
                .collect(),
            self.proposal(),
        )
        .map_err(|error| {
            ApprovalStoreError::Invalid(format!(
                "threshold collector set projection failed: {error}"
            ))
        })?;
        ApprovalSetReservationInput::new(
            body.approval_set_hash().map_err(|error| {
                ApprovalStoreError::Invalid(format!("threshold collector set hash failed: {error}"))
            })?,
            self.votes
                .iter()
                .map(|vote| {
                    ApprovalReservationMember::new(vote.token.id.clone(), vote.token_digest.clone())
                })
                .collect::<Result<Vec<_>, _>>()?,
            self.proposal().body().proposal_deadline,
        )
    }
}

fn validate_collector_identifier(
    value: &str,
    label: &'static str,
    persisted: bool,
) -> Result<(), ApprovalStoreError> {
    validate_collector_text(value, label, MAX_RESERVATION_IDENTIFIER_BYTES, persisted)
}

fn validate_collector_text(
    value: &str,
    label: &'static str,
    max_bytes: usize,
    persisted: bool,
) -> Result<(), ApprovalStoreError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(collector_validation_error(
            persisted,
            format!("{label} is empty, oversized, or not normalized"),
        ));
    }
    Ok(())
}

fn collector_validation_error(persisted: bool, message: String) -> ApprovalStoreError {
    if persisted {
        ApprovalStoreError::Serialization(message)
    } else {
        ApprovalStoreError::Invalid(message)
    }
}
