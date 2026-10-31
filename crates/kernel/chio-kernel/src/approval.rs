//! Human-in-the-loop (HITL) primitives.
//!
//! This module houses the approval-request data model, the persistent
//! approval-store contract, and the resume entry points used by the HTTP
//! surface after a human responds. The design follows
//! `docs/protocols/HUMAN-IN-THE-LOOP-PROTOCOL.md`.

mod collector;
mod tool_context;

pub use tool_context::ToolApprovalContext;

pub use collector::{
    ThresholdApprovalCollectorStatus, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalCreationParameters, ThresholdApprovalProposalRecord,
    ThresholdApprovalProposalRegistration, ThresholdApprovalVoteRecord,
};

use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedTransactionIntent,
};
use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};

use crate::security_admission_operation::ReplayReservationState;
use crate::{AgentId, KernelError, ServerId};

/// Maximum lifetime (in seconds) permitted on a single approval token.
/// Mirrors the `MAX_APPROVAL_TTL_SECS` documented in the HITL protocol
/// section 15: the single-use replay registry's TTL is pinned to this
/// value so no token can outlive its replay entry.
pub const MAX_APPROVAL_TTL_SECS: u64 = 3600;
pub(crate) const MAX_RESERVATION_IDENTIFIER_BYTES: usize = 512;

/// A request for human approval. Designed to be serialized into the
/// approval store and the approval API responses without further wrapping.
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
        if now >= request.expires_at || self.governed_token.expires_at > request.expires_at {
            return Err(KernelError::ApprovalRejected(
                "approval request expired or token exceeds its deadline".into(),
            ));
        }
        // Binding checks: request_id, intent hash, approver identity.
        if self.approval_id != request.approval_id
            || self.governed_token.request_id != request.approval_id
        {
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

        // Lifetime cap: a token whose lifetime exceeds MAX_APPROVAL_TTL_SECS
        // cannot be safely tracked in the single-use replay registry.
        let lifetime = self
            .governed_token
            .expires_at
            .checked_sub(self.governed_token.issued_at)
            .ok_or_else(|| {
                KernelError::ApprovalRejected("approval token validity window is inverted".into())
            })?;

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

        if lifetime > MAX_APPROVAL_TTL_SECS {
            return Err(KernelError::ApprovalRejected(format!(
                "approval token lifetime {lifetime}s exceeds cap {MAX_APPROVAL_TTL_SECS}s"
            )));
        }

        let ok = self
            .governed_token
            .verify_integrity_embedded_key()
            .map_err(|e| {
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
    #[error(transparent)]
    Schema(#[from] chio_security_types::schema::SchemaRefusal),
    #[error(transparent)]
    Clock(#[from] chio_security_types::clock::ClockError),
    #[error(transparent)]
    UntrustedInput(#[from] chio_core::canonical::UntrustedJsonError),
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
        if proposal_deadline == 0 || i64::try_from(proposal_deadline).is_err() {
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
        || members.len()
            > crate::security_admission_operation::MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION
    {
        return Err(ApprovalStoreError::Invalid(format!(
            "approval member count must be between 1 and {}",
            crate::security_admission_operation::MAX_APPROVAL_TOKEN_DIGESTS_PER_OPERATION
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
        .array_windows::<2>()
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
    if token_ids
        .array_windows::<2>()
        .any(|pair| pair[0] == pair[1])
    {
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
    pub request: ApprovalRequest,
    pub token: GovernedApprovalToken,
}

/// Persistent store for pending and resolved HITL approvals. The trait
/// is intentionally synchronous because every concrete implementation
/// in the kernel hot path today (in-memory, SQLite via `rusqlite`) is
/// synchronous, and the kernel itself does not run on an async
/// executor.
pub trait ApprovalStore: Send + Sync {
    fn authority_profile(&self) -> ApprovalStoreProfile {
        ApprovalStoreProfile::EphemeralLocal
    }

    /// Persist a new pending request. Idempotent on `approval_id`: a
    /// second call with the same id returns without error as long as
    /// the stored payload matches.
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError>;

    /// Fetch a single pending approval by id.
    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError>;

    /// List all pending approvals matching the filter.
    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError>;

    /// Mark a pending approval as resolved. Returns
    /// `ApprovalStoreError::AlreadyResolved` if the request has already
    /// been resolved (double-resolve protection) and
    /// `ApprovalStoreError::Replay` if the bound token has already been
    /// consumed on a different request.
    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError>;

    /// Count approved calls for a given subject / grant pair. Used by
    /// `Constraint::RequireApprovalAbove` threshold accounting.
    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError>;

    /// Returns `true` if the token has already been consumed.
    fn is_consumed(&self, token_id: &str, parameter_hash: &str)
        -> Result<bool, ApprovalStoreError>;

    /// Fetch the resolution record for a previously resolved approval.
    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError>;
    /// Atomically bind a normalized approval-token digest set to an operation.
    /// The default fails closed so operation-owned callers never fall back to
    /// the pending-request resolution ledger.
    fn reserve_approval_set(
        &self,
        _operation_id: &str,
        _approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "operation-owned approval reservations are unavailable".to_string(),
        ))
    }

    fn commit_approval_reservation(
        &self,
        _operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "operation-owned approval reservations are unavailable".to_string(),
        ))
    }

    fn cancel_approval_reservation(
        &self,
        _operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "operation-owned approval reservations are unavailable".to_string(),
        ))
    }

    fn get_approval_reservation(
        &self,
        _operation_id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "operation-owned approval reservations are unavailable".to_string(),
        ))
    }
}

/// Apply a resolved approval decision: verify the token, mark it
/// consumed, persist the resolution, and return the final verdict that
/// the kernel should treat as the outcome.
pub fn resume_with_decision(
    store: &dyn ApprovalStore,
    decision: &ApprovalDecision,
    now: u64,
) -> Result<ApprovalOutcome, KernelError> {
    let pending = match store
        .get_pending(&decision.approval_id)
        .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?
    {
        Some(p) => p,
        None => {
            if let Some(resolution) = store
                .get_resolution(&decision.approval_id)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?
            {
                return Err(KernelError::ApprovalRejected(format!(
                    "already resolved: {} ({:?})",
                    resolution.approval_id, resolution.outcome
                )));
            }
            return Err(KernelError::ApprovalRejected(format!(
                "unknown approval id: {}",
                decision.approval_id
            )));
        }
    };

    // Single-use replay check: reject immediately if the token has
    // already been consumed by a prior resolution.
    let already = store
        .is_consumed(&decision.token.id, &pending.parameter_hash)
        .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;
    if already {
        return Err(KernelError::ApprovalRejected(
            "approval token already consumed (replay)".into(),
        ));
    }

    // Verify the token cryptographically.
    let approval_token = ApprovalToken {
        approval_id: pending.approval_id.clone(),
        governed_token: decision.token.clone(),
        approver: decision.approver.clone(),
    };
    let token_decision = approval_token.verify_against(&pending, now)?;

    // Validate that the HTTP envelope's outcome matches the signed-token
    // decision BEFORE touching the store. Otherwise a mismatched pair
    // (token says Denied, body says Approved) would already have flipped
    // the pending request to `resolved=true` and bumped any approval
    // counters before we bail out, corrupting approval-threshold state
    // and replay-protection bookkeeping while still returning an error.
    let outcome = match (token_decision, &decision.outcome) {
        (GovernedApprovalDecision::Approved, ApprovalOutcome::Approved) => {
            ApprovalOutcome::Approved
        }
        (GovernedApprovalDecision::Denied, ApprovalOutcome::Denied) => ApprovalOutcome::Denied,
        _ => {
            return Err(KernelError::ApprovalRejected(
                "HTTP outcome disagrees with signed token decision".into(),
            ));
        }
    };

    // Record consumption inside the same store call so it survives a
    // restart: `resolve` is expected to atomically mark the request
    // resolved AND record the consumed token id. We only reach this
    // point once the envelope/token consistency check has passed.
    store
        .resolve(&decision.approval_id, decision)
        .map_err(|e| match e {
            ApprovalStoreError::AlreadyResolved(m) => {
                KernelError::ApprovalRejected(format!("already resolved: {m}"))
            }
            ApprovalStoreError::Replay(m) => {
                KernelError::ApprovalRejected(format!("replay detected: {m}"))
            }
            other => KernelError::Internal(format!("approval store: {other}")),
        })?;

    Ok(outcome)
}

// ---------------------------------------------------------------------
// In-memory reference implementations.
// ---------------------------------------------------------------------

/// Thread-safe in-memory `ApprovalStore`. Useful for tests and for
/// ephemeral deployments where operators explicitly accept data loss
/// on restart (ephemeral: data is lost on restart; use the SQLite-backed
/// store for production durability).
#[derive(Default)]
pub struct InMemoryApprovalStore {
    pending: RwLock<HashMap<String, ApprovalRequest>>,
    resolved: RwLock<HashMap<String, ResolvedApproval>>,
    consumed: Mutex<HashMap<String, u64>>, // key: token_id ":" parameter_hash
    approved_counts: Mutex<HashMap<String, u64>>, // key: subject_id + ":" + policy_id
}

impl InMemoryApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn consumed_key(token_id: &str, parameter_hash: &str) -> String {
        format!("{token_id}:{parameter_hash}")
    }
}

impl ApprovalStore for InMemoryApprovalStore {
    fn store_pending(&self, request: &ApprovalRequest) -> Result<(), ApprovalStoreError> {
        let mut guard = self
            .pending
            .write()
            .map_err(|_| ApprovalStoreError::Backend("pending map poisoned".into()))?;
        match guard.get(&request.approval_id) {
            Some(existing) if existing == request => return Ok(()),
            Some(_) => {
                return Err(ApprovalStoreError::Backend(format!(
                    "approval_id {} already exists with different payload",
                    request.approval_id
                )))
            }
            None => {}
        }
        guard.insert(request.approval_id.clone(), request.clone());
        Ok(())
    }

    fn get_pending(&self, id: &str) -> Result<Option<ApprovalRequest>, ApprovalStoreError> {
        let guard = self
            .pending
            .read()
            .map_err(|_| ApprovalStoreError::Backend("pending map poisoned".into()))?;
        Ok(guard.get(id).cloned())
    }

    fn list_pending(
        &self,
        filter: &ApprovalFilter,
    ) -> Result<Vec<ApprovalRequest>, ApprovalStoreError> {
        let guard = self
            .pending
            .read()
            .map_err(|_| ApprovalStoreError::Backend("pending map poisoned".into()))?;
        let mut out: Vec<_> = guard
            .values()
            .filter(|req| {
                filter
                    .subject_id
                    .as_deref()
                    .is_none_or(|s| req.subject_id == s)
                    && filter
                        .tool_server
                        .as_deref()
                        .is_none_or(|s| req.tool_server == s)
                    && filter
                        .tool_name
                        .as_deref()
                        .is_none_or(|s| req.tool_name == s)
                    && filter.not_expired_at.is_none_or(|t| req.expires_at > t)
            })
            .cloned()
            .collect();
        out.sort_by_key(|approval| approval.created_at);
        if let Some(limit) = filter.limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    fn resolve(&self, id: &str, decision: &ApprovalDecision) -> Result<(), ApprovalStoreError> {
        let mut pending_guard = self
            .pending
            .write()
            .map_err(|_| ApprovalStoreError::Backend("pending map poisoned".into()))?;
        let Some(pending) = pending_guard.get(id).cloned() else {
            return Err(ApprovalStoreError::NotFound(id.to_string()));
        };

        let verified = ApprovalToken::from_decision(decision)
            .verify_against(&pending, decision.received_at)
            .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?;
        if matches!(verified, GovernedApprovalDecision::Approved)
            != (decision.outcome == ApprovalOutcome::Approved)
        {
            return Err(ApprovalStoreError::Invalid(
                "signed decision disagrees with resolution".into(),
            ));
        }
        pending_guard.remove(id);

        {
            let mut consumed = self
                .consumed
                .lock()
                .map_err(|_| ApprovalStoreError::Backend("consumed map poisoned".into()))?;
            let key = Self::consumed_key(&decision.token.id, &pending.parameter_hash);
            if consumed.contains_key(&key) {
                // Put the pending row back so the caller can retry the
                // lookup on subsequent requests.
                pending_guard.insert(id.to_string(), pending);
                return Err(ApprovalStoreError::Replay(id.to_string()));
            }
            consumed.insert(key, decision.received_at);
        }

        let mut resolved = self
            .resolved
            .write()
            .map_err(|_| ApprovalStoreError::Backend("resolved map poisoned".into()))?;
        if resolved.contains_key(id) {
            return Err(ApprovalStoreError::AlreadyResolved(id.to_string()));
        }
        resolved.insert(
            id.to_string(),
            ResolvedApproval {
                approval_id: id.to_string(),
                outcome: decision.outcome.clone(),
                resolved_at: decision.received_at,
                approver_hex: decision.approver.to_hex(),
                token_id: decision.token.id.clone(),
                request: pending.clone(),
                token: decision.token.clone(),
            },
        );

        if decision.outcome == ApprovalOutcome::Approved {
            let mut counts = self
                .approved_counts
                .lock()
                .map_err(|_| ApprovalStoreError::Backend("counts map poisoned".into()))?;
            let key = format!("{}:{}", pending.subject_id, pending.policy_id);
            *counts.entry(key).or_default() += 1;
        }

        Ok(())
    }

    fn count_approved(&self, subject_id: &str, policy_id: &str) -> Result<u64, ApprovalStoreError> {
        let counts = self
            .approved_counts
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("counts map poisoned".into()))?;
        Ok(counts
            .get(&format!("{subject_id}:{policy_id}"))
            .copied()
            .unwrap_or(0))
    }

    fn is_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        let consumed = self
            .consumed
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("consumed map poisoned".into()))?;
        Ok(consumed.contains_key(&Self::consumed_key(token_id, parameter_hash)))
    }

    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        let guard = self
            .resolved
            .read()
            .map_err(|_| ApprovalStoreError::Backend("resolved map poisoned".into()))?;
        Ok(guard.get(id).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{GovernedApprovalDecision, GovernedApprovalTokenBody};
    use chio_core::crypto::Keypair;

    fn make_request(approval_id: &str, parameter_hash: &str) -> ApprovalRequest {
        let subject = Keypair::generate();
        let approver = Keypair::generate();
        ApprovalRequest {
            approval_id: approval_id.to_string(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: parameter_hash.to_string(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        }
    }

    fn make_token(
        approver: &Keypair,
        subject: &Keypair,
        approval_id: &str,
        parameter_hash: &str,
        decision: GovernedApprovalDecision,
    ) -> GovernedApprovalToken {
        let body = GovernedApprovalTokenBody {
            id: format!("tok-{approval_id}"),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: parameter_hash.to_string(),
            request_id: approval_id.to_string(),
            threshold_proposal_hash: None,
            issued_at: 10,
            expires_at: 100,
            decision,
        };
        GovernedApprovalToken::sign(body, approver).unwrap()
    }

    #[test]
    fn resume_flow_approved() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-1", "h-1");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-1".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        let outcome = resume_with_decision(&store, &decision, 50).unwrap();
        assert_eq!(outcome, ApprovalOutcome::Approved);
        assert_eq!(store.count_approved("agent-1", "policy-1").unwrap(), 1);
    }

    #[test]
    fn resume_flow_replay_rejected() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-2", "h-2");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-2",
            "h-2",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-2".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        // First resolution succeeds.
        resume_with_decision(&store, &decision, 50).unwrap();
        // Second resolution must fail (replay).
        let err = resume_with_decision(&store, &decision, 51).unwrap_err();
        match err {
            KernelError::ApprovalRejected(_) => {}
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn resume_flow_duplicate_resolution_reports_already_resolved() {
        let store = InMemoryApprovalStore::new();
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let mut req = make_request("a-2b", "h-2b");
        req.subject_public_key = Some(subject.public_key());
        req.trusted_approvers = vec![approver.public_key()];
        store.store_pending(&req).unwrap();

        let token = make_token(
            &approver,
            &subject,
            "a-2b",
            "h-2b",
            GovernedApprovalDecision::Approved,
        );
        let decision = ApprovalDecision {
            approval_id: "a-2b".into(),
            outcome: ApprovalOutcome::Approved,
            reason: None,
            approver: approver.public_key(),
            token,
            received_at: 50,
        };

        resume_with_decision(&store, &decision, 50).unwrap();
        let err = resume_with_decision(&store, &decision, 51).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("already resolved"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_wrong_request_id() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_token(
            &approver,
            &subject,
            "a-X",
            "h-X",
            GovernedApprovalDecision::Approved,
        );
        let req = make_request("a-other", "h-X");
        let approval_token = ApprovalToken {
            approval_id: "a-X".into(),
            governed_token: token,
            approver: approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(_) => {}
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_untrusted_approver() {
        let trusted_approver = Keypair::generate();
        let rogue_approver = Keypair::generate();
        let subject = Keypair::generate();
        let token = make_token(
            &rogue_approver,
            &subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let req = ApprovalRequest {
            approval_id: "a-1".into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: "h-1".into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![trusted_approver.public_key()],
            triggered_by: vec![],
        };
        let approval_token = ApprovalToken {
            approval_id: "a-1".into(),
            governed_token: token,
            approver: rogue_approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("not trusted"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn verify_against_rejects_subject_mismatch() {
        let approver = Keypair::generate();
        let expected_subject = Keypair::generate();
        let rogue_subject = Keypair::generate();
        let token = make_token(
            &approver,
            &rogue_subject,
            "a-1",
            "h-1",
            GovernedApprovalDecision::Approved,
        );
        let req = ApprovalRequest {
            approval_id: "a-1".into(),
            policy_id: "policy-1".into(),
            subject_id: "agent-1".into(),
            capability_id: "cap-1".into(),
            subject_public_key: Some(expected_subject.public_key()),
            tool_server: "srv".into(),
            tool_name: "invoke".into(),
            action: "invoke".into(),
            parameter_hash: "h-1".into(),
            expires_at: 1_000_000,
            callback_hint: None,
            created_at: 0,
            summary: String::new(),
            governed_intent: None,
            trusted_approvers: vec![approver.public_key()],
            triggered_by: vec![],
        };
        let approval_token = ApprovalToken {
            approval_id: "a-1".into(),
            governed_token: token,
            approver: approver.public_key(),
        };
        let err = approval_token.verify_against(&req, 50).unwrap_err();
        match err {
            KernelError::ApprovalRejected(reason) => {
                assert!(reason.contains("subject"), "{reason}");
            }
            other => panic!("expected ApprovalRejected, got {other:?}"),
        }
    }

    #[test]
    fn resolution_without_request_or_token_is_refused_at_decode() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let resolution = ResolvedApproval {
            approval_id: "a-decode".into(),
            outcome: ApprovalOutcome::Approved,
            resolved_at: 50,
            approver_hex: approver.public_key().to_hex(),
            token_id: "tok-a-decode".into(),
            request: make_request("a-decode", "h-decode"),
            token: make_token(
                &approver,
                &subject,
                "a-decode",
                "h-decode",
                GovernedApprovalDecision::Approved,
            ),
        };
        let encoded = serde_json::to_value(&resolution).unwrap();
        for field in ["request", "token"] {
            let mut missing = encoded.clone();
            missing.as_object_mut().unwrap().remove(field);
            let error = serde_json::from_value::<ResolvedApproval>(missing).unwrap_err();
            assert_eq!(error.to_string(), format!("missing field `{field}`"));
        }
    }
}
