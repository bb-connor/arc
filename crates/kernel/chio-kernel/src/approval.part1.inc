use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Mutex, RwLock};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::{
    governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedAutonomyTier,
        GovernedTransactionIntent,
    },
    scope::{Constraint, MonetaryAmount},
    threshold_approval::{
        ThresholdApprovalProposal, ThresholdApprovalRequest, ThresholdApprovalRequirement,
        VerifiedApprovalSetBody, MAX_THRESHOLD_APPROVAL_TOKENS,
    },
};
use chio_core::crypto::{sha256_hex, PublicKey};
use chio_log_redact::redacted;
use serde::{Deserialize, Serialize};

use crate::admission_operation::ReplayReservationState;
use crate::runtime::{ToolCallRequest, Verdict};
use crate::{AgentId, KernelError, ServerId};

/// Maximum lifetime (in seconds) permitted on a single approval token.
/// Mirrors the `MAX_APPROVAL_TTL_SECS` documented in the HITL protocol
/// section 15: the single-use replay registry's TTL is pinned to this
/// value so no token can outlive its replay entry.
pub const MAX_APPROVAL_TTL_SECS: u64 = 3600;
const MAX_RESERVATION_IDENTIFIER_BYTES: usize = 512;
const MAX_THRESHOLD_COLLECTOR_ARTIFACT_BYTES: usize = 262_144;

/// A request for human approval, produced when the approval guard
/// returns `Verdict::PendingApproval`. Designed to be serialized into
/// the approval store and the webhook payload without further wrapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovalRequest {
    /// Unique request identifier. Caller-stable so the approval store
    /// can be keyed on this value. Callers should supply a UUIDv7.
    pub approval_id: String,

    /// The policy / grant identifier that triggered the approval.
    pub policy_id: String,

    /// The calling agent's identifier.
    pub subject_id: AgentId,

    /// Capability token ID bound to this request.
    pub capability_id: String,

    /// Public key of the capability subject this approval is bound to.
    /// A presented approval token must carry the same subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_public_key: Option<PublicKey>,

    /// Server hosting the target tool.
    pub tool_server: ServerId,

    /// Tool being invoked.
    pub tool_name: String,

    /// Short action verb for human summaries (e.g. `invoke`, `charge`).
    pub action: String,

    /// SHA-256 hex digest of the canonical JSON of the tool arguments
    /// / governed intent. Used to bind an approval token to this exact
    /// parameter set; a mutated argument payload will not satisfy the
    /// same approval.
    pub parameter_hash: String,

    /// Unix seconds after which the request auto-denies (or escalates,
    /// per `timeout_action` in the grant).
    pub expires_at: u64,

    /// Hint for channels about where the human can respond (e.g. the
    /// URL of the dashboard or a Slack permalink). `None` means
    /// "dispatcher will fill this in after sending".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_hint: Option<String>,

    /// Unix seconds when the request was created.
    pub created_at: u64,

    /// Short human-readable summary for dashboards.
    pub summary: String,

    /// Original governed intent, when one is bound. Required for
    /// threshold-based approvals so the approver sees the financial
    /// envelope they are signing off on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent: Option<GovernedTransactionIntent>,

    /// Public keys allowed to approve this request. The kernel fails
    /// closed when the set is empty or when the presented approver is
    /// not in the set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_approvers: Vec<PublicKey>,

    /// Guards that triggered the approval requirement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggered_by: Vec<String>,
}

/// Minimal approval decision recorded after a human responds.
///
/// Callers construct this from the HTTP `POST /approvals/{id}/respond`
/// payload. It is an in-process marker; the cryptographic artifact is
/// the `GovernedApprovalToken` that rides alongside it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    Approved,
    Denied,
}

/// Decision packet delivered by an approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    /// Approval request this decision answers.
    pub approval_id: String,
    /// Outcome (approved / denied).
    pub outcome: ApprovalOutcome,
    /// Optional free-form reason supplied by the approver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Public key of the approver. Used to validate the token signature
    /// and for non-repudiation in the receipt.
    pub approver: PublicKey,
    /// Signed approval token produced by the approver.
    pub token: GovernedApprovalToken,
    /// Unix seconds when the kernel received this decision.
    pub received_at: u64,
}

/// Lightweight "approval token" representation used inside the kernel.
/// For HITL v1 this wraps the existing `GovernedApprovalToken` together
/// with the approval request it satisfies, so consumers do not have to
/// re-plumb the full governance type through every surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub approval_id: String,
    pub governed_token: GovernedApprovalToken,
    pub approver: PublicKey,
}

impl ApprovalToken {
    /// Build an `ApprovalToken` from a decision packet.
    #[must_use]
    pub fn from_decision(decision: &ApprovalDecision) -> Self {
        Self {
            approval_id: decision.approval_id.clone(),
            governed_token: decision.token.clone(),
            approver: decision.approver.clone(),
        }
    }

    /// Verify the token's cryptographic signature and binding against
    /// the original approval request. Returns `Err(KernelError::ApprovalRejected)`
    /// when any check fails.
    pub fn verify_against(
        &self,
        request: &ApprovalRequest,
        now: u64,
    ) -> Result<GovernedApprovalDecision, KernelError> {
        // Binding checks: request_id, intent hash, approver identity.
        if self.governed_token.request_id != request.approval_id {
            return Err(KernelError::ApprovalRejected(
                "approval token bound to a different request".into(),
            ));
        }
        if self.governed_token.governed_intent_hash != request.parameter_hash {
            return Err(KernelError::ApprovalRejected(
                "approval token bound to a different parameter set".into(),
            ));
        }
        if self.governed_token.approver != self.approver {
            return Err(KernelError::ApprovalRejected(
                "approval token approver mismatch".into(),
            ));
        }
        if request.trusted_approvers.is_empty() {
            return Err(KernelError::ApprovalRejected(
                "approval request does not declare any trusted approvers".into(),
            ));
        }
        if !request.trusted_approvers.contains(&self.approver) {
            return Err(KernelError::ApprovalRejected(
                "approval token approver is not trusted for this request".into(),
            ));
        }
        match request.subject_public_key.as_ref() {
            Some(expected_subject) if &self.governed_token.subject != expected_subject => {
                return Err(KernelError::ApprovalRejected(
                    "approval token subject does not match the request subject".into(),
                ));
            }
            Some(_) => {}
            None if self.governed_token.subject.to_hex() != request.subject_id => {
                return Err(KernelError::ApprovalRejected(
                    "approval request is missing a subject binding".into(),
                ));
            }
            None => {}
        }

        // Time bounds.
        if now >= self.governed_token.expires_at {
            return Err(KernelError::ApprovalRejected(
                "approval token has expired".into(),
            ));
        }
        if now < self.governed_token.issued_at {
            return Err(KernelError::ApprovalRejected(
                "approval token not yet valid".into(),
            ));
        }

        // Lifetime cap: a token whose lifetime exceeds MAX_APPROVAL_TTL_SECS
        // cannot be safely tracked in the single-use replay registry.
        let lifetime = self
            .governed_token
            .expires_at
            .saturating_sub(self.governed_token.issued_at);
        if lifetime > MAX_APPROVAL_TTL_SECS {
            return Err(KernelError::ApprovalRejected(format!(
                "approval token lifetime {lifetime}s exceeds cap {MAX_APPROVAL_TTL_SECS}s"
            )));
        }

        let ok = self.governed_token.verify_signature().map_err(|e| {
            KernelError::ApprovalRejected(format!(
                "approval token signature verification failed: {e}"
            ))
        })?;
        if !ok {
            return Err(KernelError::ApprovalRejected(
                "approval token signature did not verify".into(),
            ));
        }

        Ok(self.governed_token.decision)
    }
}

/// Errors emitted by approval stores.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalStoreError {
    #[error("invalid approval reservation: {0}")]
    Invalid(String),
    #[error("approval request not found: {0}")]
    NotFound(String),
    #[error("approval already resolved: {0}")]
    AlreadyResolved(String),
    #[error("approval state conflict: {0}")]
    Conflict(String),
    #[error("approval token already consumed (replay detected): {0}")]
    Replay(String),
    #[error("storage backend error: {0}")]
    Backend(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Durability and coordination guarantees provided by an approval replay authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalStoreProfile {
    EphemeralLocal,
    SingleNodeDurable,
    SharedLinearizable,
}

impl ApprovalStoreProfile {
    #[must_use]
    pub fn supports_dispatch_workers(self, dispatch_worker_count: usize) -> bool {
        match self {
            Self::EphemeralLocal => false,
            Self::SingleNodeDurable => dispatch_worker_count == 1,
            Self::SharedLinearizable => dispatch_worker_count > 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReservationMember {
    token_id: String,
    token_digest: String,
}

impl ApprovalReservationMember {
    pub fn new(token_id: String, token_digest: String) -> Result<Self, ApprovalStoreError> {
        validate_reservation_identifier(&token_id, "token_id")?;
        validate_reservation_digest(&token_digest, "token_digest")?;
        Ok(Self {
            token_id,
            token_digest,
        })
    }

    pub fn token_id(&self) -> &str {
        &self.token_id
    }

    pub fn token_digest(&self) -> &str {
        &self.token_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalSetReservationInput {
    approval_set_hash: String,
    members: Vec<ApprovalReservationMember>,
    proposal_deadline: u64,
}

impl ApprovalSetReservationInput {
    pub fn new(
        approval_set_hash: String,
        members: Vec<ApprovalReservationMember>,
        proposal_deadline: u64,
    ) -> Result<Self, ApprovalStoreError> {
        validate_reservation_digest(&approval_set_hash, "approval_set_hash")?;
        if proposal_deadline == 0 || proposal_deadline > i64::MAX as u64 {
            return Err(ApprovalStoreError::Invalid(
                "proposal_deadline is outside the durable timestamp range".to_string(),
            ));
        }
        let members = normalize_approval_reservation_members(members)?;
        Ok(Self {
            approval_set_hash,
            members,
            proposal_deadline,
        })
    }

    pub fn from_persisted_parts(
        approval_set_hash: String,
        members: Vec<ApprovalReservationMember>,
        proposal_deadline: u64,
    ) -> Result<Self, ApprovalStoreError> {
        let normalized = Self::new(
            approval_set_hash.clone(),
            members.clone(),
            proposal_deadline,
        )
        .map_err(persisted_approval_reservation_error)?;
        if normalized.members != members {
            return Err(ApprovalStoreError::Serialization(
                "persisted approval members are not normalized".to_string(),
            ));
        }
        Ok(normalized)
    }

    pub fn approval_set_hash(&self) -> &str {
        &self.approval_set_hash
    }

    pub fn members(&self) -> &[ApprovalReservationMember] {
        &self.members
    }

    pub fn proposal_deadline(&self) -> u64 {
        self.proposal_deadline
    }
}

/// Immutable operation ownership for one normalized verified approval set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReservation {
    operation_id: String,
    approval_set: ApprovalSetReservationInput,
    state: ReplayReservationState,
}

impl ApprovalReservation {
    pub fn new(
        operation_id: String,
        approval_set: ApprovalSetReservationInput,
    ) -> Result<Self, ApprovalStoreError> {
        validate_reservation_digest(&operation_id, "operation_id")?;
        let approval_set = ApprovalSetReservationInput::new(
            approval_set.approval_set_hash,
            approval_set.members,
            approval_set.proposal_deadline,
        )?;
        Ok(Self {
            operation_id,
            approval_set,
            state: ReplayReservationState::Reserved,
        })
    }

    pub fn from_persisted_parts(
        operation_id: String,
        approval_set: ApprovalSetReservationInput,
        state: ReplayReservationState,
    ) -> Result<Self, ApprovalStoreError> {
        let approval_set = ApprovalSetReservationInput::from_persisted_parts(
            approval_set.approval_set_hash,
            approval_set.members,
            approval_set.proposal_deadline,
        )?;
        let mut reservation =
            Self::new(operation_id, approval_set).map_err(persisted_approval_reservation_error)?;
        reservation.state = state;
        Ok(reservation)
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn approval_set(&self) -> &ApprovalSetReservationInput {
        &self.approval_set
    }

    pub fn state(&self) -> ReplayReservationState {
        self.state
    }
}

fn validate_reservation_identifier(
    value: &str,
    label: &'static str,
) -> Result<(), ApprovalStoreError> {
    if value.is_empty()
        || value.len() > MAX_RESERVATION_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte == 0)
    {
        return Err(ApprovalStoreError::Invalid(format!(
            "{label} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

fn validate_reservation_digest(value: &str, label: &'static str) -> Result<(), ApprovalStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ApprovalStoreError::Invalid(format!(
            "{label} must be lowercase SHA-256 hex"
        )));
    }
    Ok(())
}

fn normalize_approval_reservation_members(
    mut members: Vec<ApprovalReservationMember>,
) -> Result<Vec<ApprovalReservationMember>, ApprovalStoreError> {
    if members.is_empty()
        || members.len() > crate::admission_operation::MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION
    {
        return Err(ApprovalStoreError::Invalid(format!(
            "approval member count must be between 1 and {}",
            crate::admission_operation::MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION
        )));
    }
    for member in &members {
        validate_reservation_identifier(&member.token_id, "token_id")?;
        validate_reservation_digest(&member.token_digest, "token_digest")?;
    }
    members.sort_unstable_by(|left, right| {
        left.token_digest
            .cmp(&right.token_digest)
            .then_with(|| left.token_id.cmp(&right.token_id))
    });
    if members
        .windows(2)
        .any(|pair| pair[0].token_digest == pair[1].token_digest)
    {
        return Err(ApprovalStoreError::Invalid(
            "approval-token digests contain a duplicate".to_string(),
        ));
    }
    let mut token_ids = members
        .iter()
        .map(|member| member.token_id.as_str())
        .collect::<Vec<_>>();
    token_ids.sort_unstable();
    if token_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ApprovalStoreError::Invalid(
            "approval token IDs contain a duplicate".to_string(),
        ));
    }
    Ok(members)
}

fn persisted_approval_reservation_error(error: ApprovalStoreError) -> ApprovalStoreError {
    match error {
        ApprovalStoreError::Invalid(message) => ApprovalStoreError::Serialization(message),
        other => other,
    }
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
            eligible_approvers: context.requirement.eligible().clone(),
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
        if !self
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
            .proposal_deadline()
            .checked_sub(body.proposal_created_at())
            .ok_or_else(|| invalid("threshold proposal deadline precedes creation".to_string()))?;
        let requirement = ThresholdApprovalRequirement::new(
            body.required(),
            self.eligible_approvers.clone(),
            lifetime,
            body.policy_hash(),
            1,
        )
        .map_err(|error| invalid(format!("threshold eligible set is invalid: {error}")))?;
        if requirement.eligible_set_digest() != body.eligible_set_digest() {
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
            validate_collector_identifier(fingerprint, "submitter_fingerprint", persisted)?;
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
        if now >= body.proposal_deadline() {
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
        self.validate_current_authority(requirement.policy_hash(), trusted_policy_authorities)?;
        let body = self.proposal.body();
        if body.request_id() != context.matched_request.request_id()
            || self.server_id != context.matched_request.server_id()
            || self.tool_name != context.matched_request.tool_name()
        {
            return Err(ApprovalStoreError::Conflict(
                "threshold proposal does not match the authenticated request route".to_string(),
            ));
        }
        if body.required() != requirement.required()
            || body.eligible_set_digest() != requirement.eligible_set_digest()
            || self.eligible_approvers != *requirement.eligible()
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
            .checked_add(requirement.proposal_timeout_seconds())
            .ok_or_else(|| {
                ApprovalStoreError::Invalid(
                    "threshold proposal deadline arithmetic overflowed".to_string(),
                )
            })?
            .min(context.authorizing_capability_expires_at)
            .min(context.governed_operation_expires_at);
        if body.proposal_deadline() != exact_deadline {
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
        if received_at < body.proposal_created_at() || received_at >= body.proposal_deadline() {
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
            || token.issued_at >= body.proposal_deadline()
            || received_at < token.issued_at
        {
            return Err(invalid(
                "approval token issuance is outside the proposal window".to_string(),
            ));
        }
        if token.expires_at <= token.issued_at
            || token.expires_at > body.proposal_deadline()
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

/// Complete durable collector projection returned by storage and HTTP surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdApprovalProposalRecord {
    registration: ThresholdApprovalProposalRegistration,
    status: ThresholdApprovalCollectorStatus,
    votes: Vec<ThresholdApprovalVoteRecord>,
    satisfied_at: Option<u64>,
    delivered_at: Option<u64>,
}

impl ThresholdApprovalProposalRecord {
    fn new(registration: ThresholdApprovalProposalRegistration) -> Self {
        Self {
            registration,
            status: ThresholdApprovalCollectorStatus::Collecting,
            votes: Vec::new(),
            satisfied_at: None,
            delivered_at: None,
        }
    }

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
        let created_at = self.registration.proposal.body().proposal_created_at();
        let deadline = self.registration.proposal.body().proposal_deadline();
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

    fn expire_if_due(&mut self, now: u64) -> bool {
        if self.status != ThresholdApprovalCollectorStatus::Delivered
            && self.status != ThresholdApprovalCollectorStatus::Expired
            && now >= self.registration.proposal.body().proposal_deadline()
        {
            self.status = ThresholdApprovalCollectorStatus::Expired;
            return true;
        }
        false
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
            self.proposal().body().proposal_deadline(),
        )
    }
}

fn validate_collector_identifier(
    value: &str,
    label: &'static str,
    persisted: bool,
) -> Result<(), ApprovalStoreError> {
    if value.is_empty()
        || value.len() > MAX_RESERVATION_IDENTIFIER_BYTES
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

/// Filter for `list_pending`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    /// Only include requests whose `expires_at` is greater than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_expired_at: Option<u64>,
    /// Maximum number of rows to return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// Resolved-approval row retained for audit and replay protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedApproval {
    pub approval_id: String,
    pub outcome: ApprovalOutcome,
    pub resolved_at: u64,
    pub approver_hex: String,
    pub token_id: String,
}
