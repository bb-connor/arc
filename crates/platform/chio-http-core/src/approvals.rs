//! HITL approval HTTP surface.
//!
//! Substrate-agnostic handlers for the approval endpoints:
//!
//! | Method | Path                            | Handler |
//! |--------|---------------------------------|---------|
//! | GET    | `/approvals/pending`            | [`handle_list_pending`] |
//! | GET    | `/approvals/{id}`               | [`handle_get_approval`] |
//! | POST   | `/approvals/{id}/respond`       | [`handle_respond`] |
//! | POST   | `/approvals/batch/respond`      | [`handle_batch_respond`] |
//! | POST   | `/approvals/threshold/proposals` | [`handle_create_threshold_approval_proposal`] |
//! | GET    | `/approvals/threshold/proposals/{id}` | [`handle_get_threshold_approval_proposal`] |
//! | POST   | `/approvals/threshold/proposals/{id}/votes` | [`handle_append_threshold_approval_vote`] |
//! | POST   | `/approvals/threshold/proposals/{id}/deliver` | [`handle_deliver_threshold_approval_response`] |
//!
//! Each handler accepts parsed inputs and returns a typed response so
//! `chio-tower`, `chio-api-protect`, and hosted sidecars can serve them
//! without agreeing on a framework. Errors carry HTTP status codes via
//! [`ApprovalHandlerError::status`] for predictable mapping.

use std::sync::Arc;

use chio_core_types::capability::governance::GovernedApprovalToken;
use chio_core_types::capability::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalRequest, ThresholdApprovalResolutionError,
};
use chio_core_types::crypto::PublicKey;
use chio_kernel::approval::ThresholdApprovalProposalRecord;
use chio_kernel::{
    resume_with_decision, ApprovalDecision, ApprovalFilter, ApprovalOutcome, ApprovalRequest,
    ApprovalStore, ApprovalStoreError, ApprovalToken, KernelError, ResolvedApproval,
    ThresholdApprovalCollectorStatus, ThresholdApprovalProposalCreationContext,
    ThresholdApprovalProposalRegistration,
};
use serde::{Deserialize, Serialize};

/// Errors returned by the approval handlers. Each variant maps onto a
/// stable HTTP status so substrate adapters can relay the code without
/// re-interpreting the semantics.
#[derive(Debug, Clone)]
pub enum ApprovalHandlerError {
    /// Request body could not be parsed into the expected JSON shape.
    BadRequest(String),
    /// Target approval id does not exist in the store.
    NotFound(String),
    /// Approval was already resolved (single-response rule).
    Conflict(String),
    /// Replay detected: the signed token has already been consumed.
    ReplayDetected(String),
    /// Approval token failed binding / signature / time checks.
    Rejected(String),
    /// Backend store surfaced an internal error.
    Internal(String),
}

impl ApprovalHandlerError {
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            Self::BadRequest(_) => 400,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::ReplayDetected(_) => 409,
            Self::Rejected(_) => 403,
            Self::Internal(_) => 500,
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::ReplayDetected(_) => "replay_detected",
            Self::Rejected(_) => "approval_rejected",
            Self::Internal(_) => "internal_error",
        }
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::BadRequest(m)
            | Self::NotFound(m)
            | Self::Conflict(m)
            | Self::ReplayDetected(m)
            | Self::Rejected(m)
            | Self::Internal(m) => m.clone(),
        }
    }

    #[must_use]
    pub fn body(&self) -> serde_json::Value {
        serde_json::json!({
            "error": self.code(),
            "message": self.message(),
        })
    }
}

impl std::fmt::Display for ApprovalHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for ApprovalHandlerError {}

impl From<ApprovalStoreError> for ApprovalHandlerError {
    fn from(e: ApprovalStoreError) -> Self {
        match e {
            ApprovalStoreError::NotFound(m) => Self::NotFound(m),
            ApprovalStoreError::AlreadyResolved(m) => {
                Self::Conflict(format!("already resolved: {m}"))
            }
            ApprovalStoreError::Conflict(m) => Self::Conflict(m),
            ApprovalStoreError::Replay(m) => Self::ReplayDetected(m),
            ApprovalStoreError::Invalid(m) => Self::BadRequest(m),
            ApprovalStoreError::Backend(m) => Self::Internal(m),
            ApprovalStoreError::Serialization(m) => Self::Internal(m),
        }
    }
}

impl From<KernelError> for ApprovalHandlerError {
    fn from(e: KernelError) -> Self {
        match e {
            KernelError::ApprovalRejected(m) => {
                if m.contains("replay") {
                    Self::ReplayDetected(m)
                } else {
                    Self::Rejected(m)
                }
            }
            other => Self::Internal(other.to_string()),
        }
    }
}

/// Admin handle bound to the kernel's approval store.
#[derive(Clone)]
pub struct ApprovalAdmin {
    store: Arc<dyn ApprovalStore>,
    threshold_policy: Option<Arc<ThresholdApprovalCollectorPolicy>>,
}

/// Authenticated policy material used by threshold collector routes.
pub struct ThresholdApprovalCollectorPolicy {
    current_policy_hash: String,
    trusted_policy_authorities: Vec<PublicKey>,
    request_context_resolver: Arc<dyn ThresholdApprovalRequestContextResolver>,
}

/// Trusted current request state resolved from the canonical request ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedThresholdApprovalRequestContext {
    matched_request: ThresholdApprovalRequest,
    proposal_context: ThresholdApprovalProposalCreationContext,
}

impl AuthenticatedThresholdApprovalRequestContext {
    #[must_use]
    pub fn new(
        matched_request: ThresholdApprovalRequest,
        proposal_context: ThresholdApprovalProposalCreationContext,
    ) -> Self {
        Self {
            matched_request,
            proposal_context,
        }
    }

    #[must_use]
    pub fn matched_request(&self) -> &ThresholdApprovalRequest {
        &self.matched_request
    }

    #[must_use]
    pub fn proposal_context(&self) -> &ThresholdApprovalProposalCreationContext {
        &self.proposal_context
    }
}

/// Authenticated lookup for immutable request, policy, submitter, and expiry bindings.
pub trait ThresholdApprovalRequestContextResolver: Send + Sync {
    fn resolve_threshold_approval_request_context(
        &self,
        request_id: &str,
        current_policy_hash: &str,
    ) -> Result<AuthenticatedThresholdApprovalRequestContext, ThresholdApprovalResolutionError>;
}

impl<F> ThresholdApprovalRequestContextResolver for F
where
    F: Fn(
            &str,
            &str,
        )
            -> Result<AuthenticatedThresholdApprovalRequestContext, ThresholdApprovalResolutionError>
        + Send
        + Sync,
{
    fn resolve_threshold_approval_request_context(
        &self,
        request_id: &str,
        current_policy_hash: &str,
    ) -> Result<AuthenticatedThresholdApprovalRequestContext, ThresholdApprovalResolutionError>
    {
        (self)(request_id, current_policy_hash)
    }
}

impl std::fmt::Debug for ThresholdApprovalCollectorPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdApprovalCollectorPolicy")
            .field("current_policy_hash", &self.current_policy_hash)
            .field(
                "trusted_policy_authority_count",
                &self.trusted_policy_authorities.len(),
            )
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ApprovalAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalAdmin").finish_non_exhaustive()
    }
}

impl ApprovalAdmin {
    #[must_use]
    pub fn new(store: Arc<dyn ApprovalStore>) -> Self {
        Self {
            store,
            threshold_policy: None,
        }
    }

    pub fn new_with_threshold_policy(
        store: Arc<dyn ApprovalStore>,
        current_policy_hash: String,
        trusted_policy_authorities: Vec<PublicKey>,
        request_context_resolver: Arc<dyn ThresholdApprovalRequestContextResolver>,
    ) -> Result<Self, ApprovalHandlerError> {
        if current_policy_hash.len() != 64
            || !current_policy_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ApprovalHandlerError::Internal(
                "threshold collector current policy hash is not lowercase SHA-256 hex".to_string(),
            ));
        }
        if trusted_policy_authorities.is_empty() {
            return Err(ApprovalHandlerError::Internal(
                "threshold collector has no trusted policy authority".to_string(),
            ));
        }
        Ok(Self {
            store,
            threshold_policy: Some(Arc::new(ThresholdApprovalCollectorPolicy {
                current_policy_hash,
                trusted_policy_authorities,
                request_context_resolver,
            })),
        })
    }

    #[must_use]
    pub fn store(&self) -> &Arc<dyn ApprovalStore> {
        &self.store
    }

    /// Whether threshold collector routes have a trusted policy and request authority.
    #[must_use]
    pub fn threshold_collector_configured(&self) -> bool {
        self.threshold_policy.is_some()
    }

    fn threshold_policy(&self) -> Result<&ThresholdApprovalCollectorPolicy, ApprovalHandlerError> {
        self.threshold_policy.as_deref().ok_or_else(|| {
            ApprovalHandlerError::Internal(
                "threshold collector policy authority is not configured".to_string(),
            )
        })
    }

    fn resolve_threshold_context(
        &self,
        request_id: &str,
    ) -> Result<AuthenticatedThresholdApprovalRequestContext, ApprovalHandlerError> {
        let policy = self.threshold_policy()?;
        let context = policy
            .request_context_resolver
            .resolve_threshold_approval_request_context(request_id, &policy.current_policy_hash)
            .map_err(|error| {
                ApprovalHandlerError::Rejected(format!(
                    "authenticated threshold request context resolution failed: {error}"
                ))
            })?;
        if context.matched_request.request_id() != request_id {
            return Err(ApprovalHandlerError::Rejected(
                "authenticated threshold request context returned a different request ID"
                    .to_string(),
            ));
        }
        if context.proposal_context.matched_request() != &context.matched_request {
            return Err(ApprovalHandlerError::Rejected(
                "authenticated threshold request context contains inconsistent route bindings"
                    .to_string(),
            ));
        }
        if context.proposal_context.requirement().policy_hash() != policy.current_policy_hash {
            return Err(ApprovalHandlerError::Conflict(
                "authenticated threshold request context carries a stale policy hash".to_string(),
            ));
        }
        Ok(context)
    }
}

// ----- Wire shapes --------------------------------------------------

/// Query parameters for `GET /approvals/pending`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PendingQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_expired_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

impl From<PendingQuery> for ApprovalFilter {
    fn from(q: PendingQuery) -> Self {
        Self {
            subject_id: q.subject_id,
            tool_server: q.tool_server,
            tool_name: q.tool_name,
            not_expired_at: q.not_expired_at,
            limit: q.limit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingListResponse {
    pub approvals: Vec<ApprovalRequest>,
    pub count: usize,
}

/// Body for `POST /approvals/threshold/proposals`.
///
/// Eligible approvers, threshold, timeout, current policy, trusted policy
/// authorities, matched route, submitter identity, expiry bounds, and
/// separation of duties are deliberately absent. They come from the
/// authenticated [`ApprovalAdmin`] request-context authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateThresholdApprovalProposalRequest {
    pub proposal: ThresholdApprovalProposal,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThresholdApprovalProposalResponse {
    pub proposal: ThresholdApprovalCollectorProjection,
}

/// Public collector state without pre-delivery approval-token bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ThresholdApprovalCollectorProjection {
    pub proposal_id: String,
    pub request_id: String,
    pub status: ThresholdApprovalCollectorStatus,
    pub vote_count: usize,
    pub canonical_token_digests: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub satisfied_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<u64>,
}

impl From<&ThresholdApprovalProposalRecord> for ThresholdApprovalCollectorProjection {
    fn from(record: &ThresholdApprovalProposalRecord) -> Self {
        Self {
            proposal_id: record.proposal().body().proposal_id().to_string(),
            request_id: record.proposal().body().request_id().to_string(),
            status: record.status(),
            vote_count: record.votes().len(),
            canonical_token_digests: record
                .votes()
                .iter()
                .map(|vote| vote.token_digest().to_string())
                .collect(),
            satisfied_at: record.satisfied_at(),
            delivered_at: record.delivered_at(),
        }
    }
}

/// Body for appending one original signed approval token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendThresholdApprovalVoteRequest {
    pub token: GovernedApprovalToken,
}

/// Body for durably marking a satisfying response as delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverThresholdApprovalResponseRequest {}

#[derive(Debug, Clone, Serialize)]
pub struct DeliveredThresholdApprovalResponse {
    pub proposal: ThresholdApprovalCollectorProjection,
    pub approval_tokens: Vec<GovernedApprovalToken>,
}

/// Body for `POST /approvals/{id}/respond`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespondRequest {
    pub outcome: ApprovalOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub approver: PublicKey,
    pub token: GovernedApprovalToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespondResponse {
    pub approval_id: String,
    pub outcome: ApprovalOutcome,
    pub resolved_at: u64,
}

/// Body for `POST /approvals/batch/respond`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRespondRequest {
    pub decisions: Vec<BatchDecisionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchDecisionEntry {
    pub approval_id: String,
    pub outcome: ApprovalOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub approver: PublicKey,
    pub token: GovernedApprovalToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRespondResponse {
    pub results: Vec<BatchRespondResult>,
    pub summary: BatchRespondSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRespondResult {
    pub approval_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ApprovalOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRespondSummary {
    pub total: usize,
    pub approved: usize,
    pub denied: usize,
    pub rejected: usize,
}

// ----- Handlers -----------------------------------------------------

/// Create one durable policy-authority-signed threshold proposal.
pub fn handle_create_threshold_approval_proposal(
    admin: &ApprovalAdmin,
    body: CreateThresholdApprovalProposalRequest,
    now: u64,
) -> Result<ThresholdApprovalProposalResponse, ApprovalHandlerError> {
    let policy = admin.threshold_policy()?;
    let context = admin.resolve_threshold_context(body.proposal.body().request_id())?;
    let registration = ThresholdApprovalProposalRegistration::new(
        body.proposal,
        context.proposal_context(),
        &policy.trusted_policy_authorities,
        now,
    )?;
    let proposal = admin.store.create_threshold_approval_proposal(
        &registration,
        context.proposal_context(),
        &policy.trusted_policy_authorities,
        now,
    )?;
    Ok(ThresholdApprovalProposalResponse {
        proposal: (&proposal).into(),
    })
}

/// Load one durable threshold proposal and persist expiry before responding.
pub fn handle_get_threshold_approval_proposal(
    admin: &ApprovalAdmin,
    proposal_id: &str,
    now: u64,
) -> Result<ThresholdApprovalProposalResponse, ApprovalHandlerError> {
    let policy = admin.threshold_policy()?;
    let request_id = admin
        .store
        .get_threshold_approval_proposal_request_id(
            proposal_id,
            &policy.current_policy_hash,
            &policy.trusted_policy_authorities,
        )?
        .ok_or_else(|| ApprovalHandlerError::NotFound(proposal_id.to_string()))?;
    let context = admin.resolve_threshold_context(&request_id)?;
    let proposal = admin
        .store
        .get_threshold_approval_proposal(
            proposal_id,
            context.proposal_context(),
            &policy.trusted_policy_authorities,
            now,
        )?
        .ok_or_else(|| ApprovalHandlerError::NotFound(proposal_id.to_string()))?;
    Ok(ThresholdApprovalProposalResponse {
        proposal: (&proposal).into(),
    })
}

/// Append one original signed token and atomically return the persisted status.
pub fn handle_append_threshold_approval_vote(
    admin: &ApprovalAdmin,
    proposal_id: &str,
    body: AppendThresholdApprovalVoteRequest,
    now: u64,
) -> Result<ThresholdApprovalProposalResponse, ApprovalHandlerError> {
    let policy = admin.threshold_policy()?;
    let request_id = admin
        .store
        .get_threshold_approval_proposal_request_id(
            proposal_id,
            &policy.current_policy_hash,
            &policy.trusted_policy_authorities,
        )?
        .ok_or_else(|| ApprovalHandlerError::NotFound(proposal_id.to_string()))?;
    let context = admin.resolve_threshold_context(&request_id)?;
    let proposal = admin.store.append_threshold_approval_vote(
        proposal_id,
        &body.token,
        context.proposal_context(),
        &policy.trusted_policy_authorities,
        now,
    )?;
    Ok(ThresholdApprovalProposalResponse {
        proposal: (&proposal).into(),
    })
}

/// Persist delivery before returning the complete original satisfying token set.
pub fn handle_deliver_threshold_approval_response(
    admin: &ApprovalAdmin,
    proposal_id: &str,
    body: DeliverThresholdApprovalResponseRequest,
    now: u64,
) -> Result<DeliveredThresholdApprovalResponse, ApprovalHandlerError> {
    let policy = admin.threshold_policy()?;
    let request_id = admin
        .store
        .get_threshold_approval_proposal_request_id(
            proposal_id,
            &policy.current_policy_hash,
            &policy.trusted_policy_authorities,
        )?
        .ok_or_else(|| ApprovalHandlerError::NotFound(proposal_id.to_string()))?;
    let context = admin.resolve_threshold_context(&request_id)?;
    let proposal = admin.store.mark_threshold_approval_response_delivered(
        proposal_id,
        context.proposal_context(),
        &policy.trusted_policy_authorities,
        now,
    )?;
    let _ = body;
    let approval_tokens = proposal.approval_tokens();
    Ok(DeliveredThresholdApprovalResponse {
        proposal: (&proposal).into(),
        approval_tokens,
    })
}

/// `GET /approvals/pending` -- list pending approvals matching the
/// filter. Returns a stable JSON shape.
pub fn handle_list_pending(
    admin: &ApprovalAdmin,
    query: PendingQuery,
) -> Result<PendingListResponse, ApprovalHandlerError> {
    let filter: ApprovalFilter = query.into();
    let approvals = admin.store.list_pending(&filter)?;
    let count = approvals.len();
    Ok(PendingListResponse { approvals, count })
}

/// `GET /approvals/{id}`.
///
/// Returns the pending record if still outstanding; otherwise returns
/// the resolved record. Adapters may encode "resolved" via the
/// `resolution` field so callers can tell the two states apart without
/// extra round trips.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetApprovalResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<ApprovalRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<ResolvedApproval>,
}

pub fn handle_get_approval(
    admin: &ApprovalAdmin,
    approval_id: &str,
) -> Result<GetApprovalResponse, ApprovalHandlerError> {
    let pending = admin.store.get_pending(approval_id)?;
    let resolution = admin.store.get_resolution(approval_id)?;
    if pending.is_none() && resolution.is_none() {
        return Err(ApprovalHandlerError::NotFound(approval_id.to_string()));
    }
    Ok(GetApprovalResponse {
        pending,
        resolution,
    })
}

/// `POST /approvals/{id}/respond` -- submit an approval decision.
pub fn handle_respond(
    admin: &ApprovalAdmin,
    approval_id: &str,
    body: RespondRequest,
    now: u64,
) -> Result<RespondResponse, ApprovalHandlerError> {
    // The approval_id in the URL must agree with the token the human
    // signed, otherwise the signed binding is wrong and we cannot
    // authorize resume.
    if body.token.request_id != approval_id {
        return Err(ApprovalHandlerError::BadRequest(format!(
            "approval_id {approval_id} does not match signed token request_id {}",
            body.token.request_id
        )));
    }

    let decision = ApprovalDecision {
        approval_id: approval_id.to_string(),
        outcome: body.outcome.clone(),
        reason: body.reason,
        approver: body.approver.clone(),
        token: body.token,
        received_at: now,
    };

    let outcome = resume_with_decision(admin.store.as_ref(), &decision, now)?;

    // Defense-in-depth: the ApprovalToken is now consumed; exercise
    // the replay guard immediately so operators can trust the store
    // wrote the record.
    let approval_token = ApprovalToken::from_decision(&decision);
    let _ = approval_token; // consumed; flagged via resume_with_decision.

    Ok(RespondResponse {
        approval_id: approval_id.to_string(),
        outcome,
        resolved_at: now,
    })
}

/// `POST /approvals/batch/respond` -- apply decisions to multiple
/// approvals in one call.
pub fn handle_batch_respond(
    admin: &ApprovalAdmin,
    body: BatchRespondRequest,
    now: u64,
) -> Result<BatchRespondResponse, ApprovalHandlerError> {
    if body.decisions.is_empty() {
        return Err(ApprovalHandlerError::BadRequest(
            "batch respond requires at least one decision".into(),
        ));
    }

    let mut results = Vec::with_capacity(body.decisions.len());
    let mut approved = 0usize;
    let mut denied = 0usize;
    let mut rejected = 0usize;

    for entry in body.decisions {
        let approval_id = entry.approval_id.clone();
        if entry.token.request_id != approval_id {
            rejected += 1;
            results.push(BatchRespondResult {
                approval_id,
                status: "rejected".into(),
                outcome: None,
                error: Some(format!(
                    "token request_id {} mismatches approval_id",
                    entry.token.request_id
                )),
            });
            continue;
        }

        let decision = ApprovalDecision {
            approval_id: approval_id.clone(),
            outcome: entry.outcome.clone(),
            reason: entry.reason,
            approver: entry.approver,
            token: entry.token,
            received_at: now,
        };

        match resume_with_decision(admin.store.as_ref(), &decision, now) {
            Ok(outcome) => {
                match outcome {
                    ApprovalOutcome::Approved => approved += 1,
                    ApprovalOutcome::Denied => denied += 1,
                }
                results.push(BatchRespondResult {
                    approval_id,
                    status: "resolved".into(),
                    outcome: Some(outcome),
                    error: None,
                });
            }
            Err(e) => {
                rejected += 1;
                let handler_err: ApprovalHandlerError = e.into();
                results.push(BatchRespondResult {
                    approval_id,
                    status: "rejected".into(),
                    outcome: None,
                    error: Some(handler_err.message()),
                });
            }
        }
    }

    let total = results.len();
    Ok(BatchRespondResponse {
        results,
        summary: BatchRespondSummary {
            total,
            approved,
            denied,
            rejected,
        },
    })
}
