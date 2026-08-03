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

    /// Record that a token (by `token_id` and `parameter_hash`) has
    /// been consumed. Used to reject replays of the same approval
    /// token across a restart. Implementations may also call this from
    /// [`resolve`]; exposing it on the trait lets the kernel do the
    /// replay check before persisting the resolution, which matters
    /// when the store is backed by SQLite and wants to run the check
    /// inside the transaction.
    fn record_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
        now: u64,
    ) -> Result<(), ApprovalStoreError>;

    /// Returns `true` if the token has already been consumed.
    fn is_consumed(&self, token_id: &str, parameter_hash: &str)
        -> Result<bool, ApprovalStoreError>;

    /// Fetch the resolution record for a previously resolved approval.
    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError>;

    /// Atomically bind a normalized approval-token digest set to an operation.
    /// The default fails closed so operation-owned callers never fall back to
    /// the legacy immediate-consumption registry.
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

    /// Durably create one immutable signed threshold proposal.
    fn create_threshold_approval_proposal(
        &self,
        _registration: &ThresholdApprovalProposalRegistration,
        _current_context: &ThresholdApprovalProposalCreationContext,
        _trusted_policy_authorities: &[PublicKey],
        _now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "durable threshold proposal collection is unavailable".to_string(),
        ))
    }

    /// Resolve the signed canonical request ID before loading trusted context.
    fn get_threshold_approval_proposal_request_id(
        &self,
        _proposal_id: &str,
        _current_policy_hash: &str,
        _trusted_policy_authorities: &[PublicKey],
    ) -> Result<Option<String>, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "durable threshold proposal collection is unavailable".to_string(),
        ))
    }

    /// Load a threshold proposal, persisting expiry before it is returned.
    fn get_threshold_approval_proposal(
        &self,
        _proposal_id: &str,
        _current_context: &ThresholdApprovalProposalCreationContext,
        _trusted_policy_authorities: &[PublicKey],
        _now: u64,
    ) -> Result<Option<ThresholdApprovalProposalRecord>, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "durable threshold proposal collection is unavailable".to_string(),
        ))
    }

    /// Append one original signed token and atomically persist threshold status.
    fn append_threshold_approval_vote(
        &self,
        _proposal_id: &str,
        _token: &GovernedApprovalToken,
        _current_context: &ThresholdApprovalProposalCreationContext,
        _trusted_policy_authorities: &[PublicKey],
        _now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "durable threshold proposal collection is unavailable".to_string(),
        ))
    }

    /// Persist response delivery before returning the original satisfying tokens.
    fn mark_threshold_approval_response_delivered(
        &self,
        _proposal_id: &str,
        _current_context: &ThresholdApprovalProposalCreationContext,
        _trusted_policy_authorities: &[PublicKey],
        _now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        Err(ApprovalStoreError::Backend(
            "durable threshold proposal collection is unavailable".to_string(),
        ))
    }
}

/// Batch approvals let a human pre-approve a class of calls.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BatchApproval {
    pub batch_id: String,
    pub approver_hex: String,
    pub subject_id: AgentId,
    pub server_pattern: String,
    pub tool_pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount_per_call: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_total_amount: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,
    pub not_before: u64,
    pub not_after: u64,
    #[serde(default)]
    pub used_calls: u32,
    #[serde(default)]
    pub used_total_units: u64,
    #[serde(default)]
    pub revoked: bool,
}

/// Store for batch approvals. Counterpart to `ApprovalStore`.
pub trait BatchApprovalStore: Send + Sync {
    fn store(&self, batch: &BatchApproval) -> Result<(), ApprovalStoreError>;

    fn find_matching(
        &self,
        subject_id: &str,
        server_id: &str,
        tool_name: &str,
        amount: Option<&MonetaryAmount>,
        now: u64,
    ) -> Result<Option<BatchApproval>, ApprovalStoreError>;

    fn record_usage(
        &self,
        batch_id: &str,
        amount: Option<&MonetaryAmount>,
    ) -> Result<(), ApprovalStoreError>;

    fn revoke(&self, batch_id: &str) -> Result<(), ApprovalStoreError>;

    fn get(&self, batch_id: &str) -> Result<Option<BatchApproval>, ApprovalStoreError>;
}

/// Contract a channel must satisfy to dispatch an approval request.
///
/// The trait is sync; implementations that need async I/O should use a
/// dedicated thread or a small runtime. `WebhookChannel` uses the
/// blocking `ureq` client already in the crate's dependency tree.
pub trait ApprovalChannel: Send + Sync {
    /// Short channel name (`"webhook"`, `"slack"`, `"dashboard"`...).
    fn name(&self) -> &str;

    /// Deliver an approval request to the configured endpoint. The
    /// channel implementation is responsible for retries; on terminal
    /// failure the call returns `Err` and the kernel leaves the
    /// request in the store (fail-closed).
    fn dispatch(&self, request: &ApprovalRequest) -> Result<ChannelHandle, ChannelError>;
}

/// Handle returned by `dispatch`. Kernel records this alongside the
/// request in the store so `cancel` can be called later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelHandle {
    pub channel: String,
    pub channel_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_url: Option<String>,
}

/// Errors returned by approval channels.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("channel transport error: {0}")]
    Transport(String),
    #[error("channel remote rejected dispatch: {status}: {body}")]
    Remote { status: u16, body: String },
    #[error("channel misconfigured: {0}")]
    Config(String),
}

/// Outcome of running an approval guard against a tool call.
///
/// The pending + approved variants box their inner payloads so the
/// enum stays cheap to pass by value; large variants trip clippy's
/// `large_enum_variant` lint.
#[derive(Debug, Clone)]
pub enum HitlVerdict {
    /// Guard passes -- no approval required.
    Allow,
    /// Guard denies without an approval path (e.g. fail-closed).
    Deny { reason: String },
    /// Approval is required. Kernel should persist the request and
    /// return a 202-style response to the caller.
    Pending {
        request: Box<ApprovalRequest>,
        verdict: Verdict,
    },
    /// Approval was supplied with the request and passed verification.
    Approved { token: Box<ApprovalToken> },
}

/// Compute the parameter hash that binds an `ApprovalRequest` to a
/// specific set of arguments. Input is canonicalized via the existing
/// `sha256_hex(chio_core::canonical::canonical_json_bytes(..))` helper
/// so independent kernels produce identical hashes.
#[must_use]
pub fn compute_parameter_hash(
    tool_server: &str,
    tool_name: &str,
    arguments: &serde_json::Value,
    governed_intent: Option<&GovernedTransactionIntent>,
) -> String {
    let envelope = serde_json::json!({
        "server_id": tool_server,
        "tool_name": tool_name,
        "arguments": arguments,
        "governed_intent": governed_intent,
    });
    match chio_core::canonical::canonical_json_bytes(&envelope) {
        Ok(bytes) => sha256_hex(&bytes),
        // Canonicalization only fails on unserializable inputs -- the
        // tool call arguments are already `serde_json::Value` so this
        // path is unreachable in practice. Fall back to a tagged hash
        // of the display form rather than panicking: we still return
        // a stable string so callers do not have to handle the error.
        Err(_) => sha256_hex(envelope.to_string().as_bytes()),
    }
}

/// The built-in HITL guard. Runs before the generic guard pipeline and
/// decides whether a call passes straight through, requires approval,
/// or was already approved by an accompanying token.
pub struct ApprovalGuard {
    /// Persistent store of pending / resolved approvals.
    store: std::sync::Arc<dyn ApprovalStore>,
    /// Channels fired on new pending requests. Dispatch failures are
    /// logged but do NOT clear the pending record -- the fail-closed
    /// rule from the protocol table is that a webhook delivery failure
    /// keeps the request pending and queryable via the API.
    channels: Vec<std::sync::Arc<dyn ApprovalChannel>>,
    /// Default timeout for newly created requests.
    default_ttl_secs: u64,
}

impl ApprovalGuard {
    pub fn new(store: std::sync::Arc<dyn ApprovalStore>) -> Self {
        Self {
            store,
            channels: Vec::new(),
            default_ttl_secs: 3600,
        }
    }

    #[must_use]
    pub fn with_channel(mut self, channel: std::sync::Arc<dyn ApprovalChannel>) -> Self {
        self.channels.push(channel);
        self
    }

    #[must_use]
    pub fn with_default_ttl(mut self, secs: u64) -> Self {
        self.default_ttl_secs = secs;
        self
    }

    /// Evaluate the grant's constraints against the request. Returns
    /// a `HitlVerdict` describing the next step.
    pub fn evaluate(&self, ctx: ApprovalContext<'_>, now: u64) -> Result<HitlVerdict, KernelError> {
        let mut triggered = Vec::<String>::new();
        let mut threshold_hit = false;
        let mut always_hit = false;
        let mut tier_hit = false;

        for constraint in ctx.constraints {
            match constraint {
                Constraint::RequireApprovalAbove { threshold_units } => {
                    let amount = ctx
                        .request
                        .governed_intent
                        .as_ref()
                        .and_then(|intent| intent.as_tool_invocation())
                        .and_then(|intent| intent.max_amount.as_ref());
                    match amount {
                        Some(amt) if amt.units >= *threshold_units => {
                            threshold_hit = true;
                            triggered.push(format!("require_approval_above:{threshold_units}"));
                        }
                        Some(_) => {
                            // Below threshold -- no approval triggered.
                        }
                        None => {
                            // Fail-closed: constraint present but no
                            // amount to compare. Deny rather than
                            // silently skip.
                            return Ok(HitlVerdict::Deny {
                                reason: format!(
                                    "RequireApprovalAbove requires a governed intent with max_amount (threshold={threshold_units})"
                                ),
                            });
                        }
                    }
                }
                Constraint::MinimumAutonomyTier(GovernedAutonomyTier::Autonomous)
                    if ctx.request.governed_intent.is_some() =>
                {
                    // When paired with the HITL guard, Autonomous tier
                    // is treated as "requires human approval". Direct
                    // / Delegated pass through.
                    tier_hit = true;
                    triggered.push("minimum_autonomy_tier:autonomous".to_string());
                }
                _ => {}
            }
        }

        // An attribute flag on the request (`force_approval`) forces a
        // PendingApproval outcome so host integrations can enter the HITL
        // flow without teaching every constraint variant.
        // Test harnesses use this path too.
        if ctx.force_approval {
            always_hit = true;
            triggered.push("force_approval".to_string());
        }

        let needs_approval = threshold_hit || always_hit || tier_hit;
        if !needs_approval {
            return Ok(HitlVerdict::Allow);
        }
        if ctx.trusted_approvers.is_empty() {
            return Ok(HitlVerdict::Deny {
                reason: "approval required but no trusted approvers are configured".to_string(),
            });
        }

        // If the caller attached an approval token, try to satisfy the
        // request with it before creating a new pending entry.
        if let Some(token) = ctx.presented_token {
            // Reconstruct the request envelope matching the original
            // pending record so we can validate binding.
            let parameter_hash = compute_parameter_hash(
                &ctx.request.server_id,
                &ctx.request.tool_name,
                &ctx.request.arguments,
                ctx.request.governed_intent.as_ref(),
            );

            // Lookup the pending record. If the token refers to an
            // approval id, prefer the stored record; otherwise build
            // a synthetic record to verify against (binding by
            // parameter hash is the cryptographic gate).
            let stored = self
                .store
                .get_pending(&token.approval_id)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;
            let resolved = self
                .store
                .get_resolution(&token.approval_id)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;

            let approval_request = match stored.or_else(|| {
                resolved.map(|res| ApprovalRequest {
                    approval_id: res.approval_id,
                    policy_id: ctx.policy_id.to_string(),
                    subject_id: ctx.request.agent_id.clone(),
                    capability_id: ctx.request.capability.id.clone(),
                    subject_public_key: Some(ctx.request.capability.subject.clone()),
                    tool_server: ctx.request.server_id.clone(),
                    tool_name: ctx.request.tool_name.clone(),
                    action: "invoke".to_string(),
                    parameter_hash: parameter_hash.clone(),
                    expires_at: now + self.default_ttl_secs,
                    callback_hint: None,
                    created_at: now,
                    summary: String::new(),
                    governed_intent: ctx.request.governed_intent.clone(),
                    trusted_approvers: ctx.trusted_approvers.to_vec(),
                    triggered_by: triggered.clone(),
                })
            }) {
                Some(record) => record,
                None => {
                    return Err(KernelError::ApprovalRejected(
                        "approval token does not match any known request".into(),
                    ));
                }
            };

            // Replay check first: before spending cycles on signature
            // verification, fail-closed on a previously consumed token.
            let already_consumed = self
                .store
                .is_consumed(&token.governed_token.id, &approval_request.parameter_hash)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;
            if already_consumed {
                return Err(KernelError::ApprovalRejected(
                    "approval token already consumed (replay)".into(),
                ));
            }

            let decision = token.verify_against(&approval_request, now)?;
            match decision {
                GovernedApprovalDecision::Approved => Ok(HitlVerdict::Approved {
                    token: Box::new(token.clone()),
                }),
                GovernedApprovalDecision::Denied => Ok(HitlVerdict::Deny {
                    reason: "human approver denied the request".into(),
                }),
            }
        } else {
            // No token on the request -- build a new pending entry.
            let parameter_hash = compute_parameter_hash(
                &ctx.request.server_id,
                &ctx.request.tool_name,
                &ctx.request.arguments,
                ctx.request.governed_intent.as_ref(),
            );
            let expires_at = now.saturating_add(self.default_ttl_secs);
            let summary = format!(
                "agent {} requests approval for {}:{}",
                ctx.request.agent_id, ctx.request.server_id, ctx.request.tool_name
            );
            let request = ApprovalRequest {
                approval_id: ctx
                    .approval_id_override
                    .unwrap_or_else(|| uuid::Uuid::now_v7().to_string()),
                policy_id: ctx.policy_id.to_string(),
                subject_id: ctx.request.agent_id.clone(),
                capability_id: ctx.request.capability.id.clone(),
                subject_public_key: Some(ctx.request.capability.subject.clone()),
                tool_server: ctx.request.server_id.clone(),
                tool_name: ctx.request.tool_name.clone(),
                action: "invoke".to_string(),
                parameter_hash,
                expires_at,
                callback_hint: None,
                created_at: now,
                summary,
                governed_intent: ctx.request.governed_intent.clone(),
                trusted_approvers: ctx.trusted_approvers.to_vec(),
                triggered_by: triggered,
            };
            self.store
                .store_pending(&request)
                .map_err(|e| KernelError::Internal(format!("approval store: {e}")))?;

            // Dispatch to channels. Delivery failures are logged but
            // the pending row stays in place: the API can still serve
            // it from `/approvals/pending`.
            for channel in &self.channels {
                if let Err(err) = channel.dispatch(&request) {
                    tracing::warn!(
                        approval_id = %request.approval_id,
                        channel = %channel.name(),
                        error = %redacted!(&err),
                        "approval channel dispatch failed; request remains pending"
                    );
                }
            }

            Ok(HitlVerdict::Pending {
                request: Box::new(request),
                verdict: Verdict::PendingApproval,
            })
        }
    }

    /// Accessor used by the resume flow in the HTTP layer.
    #[must_use]
    pub fn store(&self) -> std::sync::Arc<dyn ApprovalStore> {
        self.store.clone()
    }
}

/// Context passed into [`ApprovalGuard::evaluate`].
pub struct ApprovalContext<'a> {
    pub request: &'a ToolCallRequest,
    pub constraints: &'a [Constraint],
    pub policy_id: &'a str,
    /// Public keys trusted to sign the approval token for this request.
    pub trusted_approvers: &'a [PublicKey],
    /// Approval token presented by the caller, if any.
    pub presented_token: Option<&'a ApprovalToken>,
    /// When `true`, force the guard into the pending path regardless
    /// of constraints. Used by integration tests and by host adapters
    /// that decided out-of-band that the call needs approval.
    pub force_approval: bool,
    /// Optional deterministic id for the generated approval request.
    pub approval_id_override: Option<String>,
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
struct InMemoryApprovalReplayState {
    consumed: HashMap<String, (String, u64)>,
    by_operation: HashMap<String, ApprovalReservation>,
    approval_set_hash_owners: HashMap<String, String>,
    token_id_owners: HashMap<String, String>,
    token_digest_owners: HashMap<String, String>,
}

#[derive(Default)]
pub struct InMemoryApprovalStore {
    pending: RwLock<HashMap<String, ApprovalRequest>>,
    resolved: RwLock<HashMap<String, ResolvedApproval>>,
    approved_counts: Mutex<HashMap<String, u64>>, // key: subject_id + ":" + policy_id
    replay: Mutex<InMemoryApprovalReplayState>,
    threshold_proposals: Mutex<HashMap<String, ThresholdApprovalProposalRecord>>,
}

impl InMemoryApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn transition_approval_reservation(
        &self,
        operation_id: &str,
        target: ReplayReservationState,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        validate_reservation_digest(operation_id, "operation_id")?;
        let mut replay = self.replay.lock().map_err(|_| {
            ApprovalStoreError::Backend("approval replay state poisoned".to_string())
        })?;
        let reservation = replay.by_operation.get_mut(operation_id).ok_or_else(|| {
            ApprovalStoreError::NotFound(format!(
                "approval reservation for operation {operation_id}"
            ))
        })?;
        match (reservation.state, target) {
            (current, requested) if current == requested => Ok(reservation.clone()),
            (
                ReplayReservationState::Reserved,
                ReplayReservationState::Committed | ReplayReservationState::Cancelled,
            ) => {
                reservation.state = target;
                Ok(reservation.clone())
            }
            (current, requested) => Err(ApprovalStoreError::Replay(format!(
                "operation `{operation_id}` approval reservation cannot transition from {} to {}",
                current.as_str(),
                requested.as_str()
            ))),
        }
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
        let Some(pending) = pending_guard.remove(id) else {
            return Err(ApprovalStoreError::NotFound(id.to_string()));
        };

        let token_digest = decision
            .token
            .token_digest()
            .map_err(|error| ApprovalStoreError::Invalid(error.to_string()))?;
        {
            let mut replay = self.replay.lock().map_err(|_| {
                ApprovalStoreError::Backend("approval replay state poisoned".into())
            })?;
            if replay.consumed.contains_key(&decision.token.id)
                || replay.token_id_owners.contains_key(&decision.token.id)
                || replay.token_digest_owners.contains_key(&token_digest)
            {
                // Put the pending row back so the caller can retry the
                // lookup on subsequent requests.
                pending_guard.insert(id.to_string(), pending);
                return Err(ApprovalStoreError::Replay(id.to_string()));
            }
            replay.consumed.insert(
                decision.token.id.clone(),
                (pending.parameter_hash.clone(), decision.received_at),
            );
            replay
                .token_digest_owners
                .insert(token_digest, format!("legacy-approval:{id}"));
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

    fn record_consumed(
        &self,
        token_id: &str,
        parameter_hash: &str,
        now: u64,
    ) -> Result<(), ApprovalStoreError> {
        let mut replay = self
            .replay
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("approval replay state poisoned".into()))?;
        if replay.consumed.contains_key(token_id) || replay.token_id_owners.contains_key(token_id) {
            return Err(ApprovalStoreError::Replay(format!(
                "token {token_id} already consumed"
            )));
        }
        replay
            .consumed
            .insert(token_id.to_string(), (parameter_hash.to_string(), now));
        Ok(())
    }

    fn is_consumed(
        &self,
        token_id: &str,
        _parameter_hash: &str,
    ) -> Result<bool, ApprovalStoreError> {
        let replay = self
            .replay
            .lock()
            .map_err(|_| ApprovalStoreError::Backend("approval replay state poisoned".into()))?;
        Ok(replay.consumed.contains_key(token_id) || replay.token_id_owners.contains_key(token_id))
    }

    fn get_resolution(&self, id: &str) -> Result<Option<ResolvedApproval>, ApprovalStoreError> {
        let guard = self
            .resolved
            .read()
            .map_err(|_| ApprovalStoreError::Backend("resolved map poisoned".into()))?;
        Ok(guard.get(id).cloned())
    }

    fn reserve_approval_set(
        &self,
        operation_id: &str,
        approval_set: &ApprovalSetReservationInput,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        let requested = ApprovalReservation::new(operation_id.to_string(), approval_set.clone())?;
        let proposals = self.threshold_proposals.lock().map_err(|_| {
            ApprovalStoreError::Backend("threshold proposal map poisoned".to_string())
        })?;
        let mut matching_collectors = proposals.values().filter(|record| {
            record.votes.iter().any(|vote| {
                requested.approval_set.members().iter().any(|member| {
                    member.token_id() == vote.token.id || member.token_digest() == vote.token_digest
                })
            })
        });
        let collector = matching_collectors.next();
        if matching_collectors.next().is_some() {
            return Err(ApprovalStoreError::Replay(
                "approval set spans more than one threshold proposal".to_string(),
            ));
        }
        let collector_owner = match collector {
            Some(record) => {
                let expected = record.reservation_input()?;
                if &expected != requested.approval_set() {
                    return Err(ApprovalStoreError::Replay(
                        "approval set does not exactly match its satisfied threshold proposal"
                            .to_string(),
                    ));
                }
                Some(format!(
                    "threshold-proposal:{}",
                    record.proposal().body().proposal_id()
                ))
            }
            None => None,
        };
        let mut replay = self.replay.lock().map_err(|_| {
            ApprovalStoreError::Backend("approval replay state poisoned".to_string())
        })?;
        if let Some(existing) = replay.by_operation.get(operation_id) {
            if existing.approval_set == requested.approval_set {
                return Ok(existing.clone());
            }
            return Err(ApprovalStoreError::Replay(format!(
                "operation `{operation_id}` is already bound to a different approval-token set"
            )));
        }
        if let Some(owner) = replay
            .approval_set_hash_owners
            .get(requested.approval_set.approval_set_hash())
        {
            return Err(ApprovalStoreError::Replay(format!(
                "approval set hash is already owned by operation `{owner}`"
            )));
        }
        for member in requested.approval_set.members() {
            if replay.consumed.contains_key(member.token_id()) {
                return Err(ApprovalStoreError::Replay(format!(
                    "approval token `{}` was already consumed",
                    member.token_id()
                )));
            }
            if let Some(owner) = replay.token_id_owners.get(member.token_id()) {
                if collector_owner.as_deref() != Some(owner.as_str()) {
                    return Err(ApprovalStoreError::Replay(format!(
                        "approval token ID is already owned by `{owner}`"
                    )));
                }
            } else if collector_owner.is_some() {
                return Err(ApprovalStoreError::Serialization(
                    "threshold collector token ID ownership is missing".to_string(),
                ));
            }
            if let Some(owner) = replay.token_digest_owners.get(member.token_digest()) {
                if collector_owner.as_deref() != Some(owner.as_str()) {
                    return Err(ApprovalStoreError::Replay(format!(
                        "approval token digest is already owned by `{owner}`"
                    )));
                }
            } else if collector_owner.is_some() {
                return Err(ApprovalStoreError::Serialization(
                    "threshold collector token digest ownership is missing".to_string(),
                ));
            }
        }
        replay.approval_set_hash_owners.insert(
            requested.approval_set.approval_set_hash().to_string(),
            operation_id.to_string(),
        );
        for member in requested.approval_set.members() {
            replay
                .token_id_owners
                .insert(member.token_id().to_string(), operation_id.to_string());
            replay
                .token_digest_owners
                .insert(member.token_digest().to_string(), operation_id.to_string());
        }
        replay
            .by_operation
            .insert(operation_id.to_string(), requested.clone());
        Ok(requested)
    }

    fn commit_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.transition_approval_reservation(operation_id, ReplayReservationState::Committed)
    }

    fn cancel_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ApprovalReservation, ApprovalStoreError> {
        self.transition_approval_reservation(operation_id, ReplayReservationState::Cancelled)
    }

    fn get_approval_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ApprovalReservation>, ApprovalStoreError> {
        validate_reservation_digest(operation_id, "operation_id")?;
        let replay = self.replay.lock().map_err(|_| {
            ApprovalStoreError::Backend("approval replay state poisoned".to_string())
        })?;
        Ok(replay.by_operation.get(operation_id).cloned())
    }

    fn create_threshold_approval_proposal(
        &self,
        registration: &ThresholdApprovalProposalRegistration,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        registration.validate_for_creation(current_context, trusted_policy_authorities, now)?;
        let proposal_id = registration.proposal.body().proposal_id();
        let mut proposals = self.threshold_proposals.lock().map_err(|_| {
            ApprovalStoreError::Backend("threshold proposal map poisoned".to_string())
        })?;
        if let Some(existing) = proposals.get(proposal_id) {
            if existing.registration == *registration {
                return Ok(existing.clone());
            }
            return Err(ApprovalStoreError::Conflict(format!(
                "proposal_id `{proposal_id}` already has different immutable bindings"
            )));
        }
        if proposals.values().any(|record| {
            record.proposal().body().request_id() == registration.proposal.body().request_id()
        }) {
            return Err(ApprovalStoreError::Conflict(
                "canonical request ID already belongs to another threshold proposal".to_string(),
            ));
        }
        let record = ThresholdApprovalProposalRecord::new(registration.clone());
        proposals.insert(proposal_id.to_string(), record.clone());
        Ok(record)
    }

    fn get_threshold_approval_proposal_request_id(
        &self,
        proposal_id: &str,
        current_policy_hash: &str,
        trusted_policy_authorities: &[PublicKey],
    ) -> Result<Option<String>, ApprovalStoreError> {
        validate_collector_identifier(proposal_id, "proposal_id", false)?;
        let proposals = self.threshold_proposals.lock().map_err(|_| {
            ApprovalStoreError::Backend("threshold proposal map poisoned".to_string())
        })?;
        let Some(record) = proposals.get(proposal_id) else {
            return Ok(None);
        };
        record
            .registration
            .validate_current_authority(current_policy_hash, trusted_policy_authorities)?;
        Ok(Some(record.proposal().body().request_id().to_string()))
    }

    fn get_threshold_approval_proposal(
        &self,
        proposal_id: &str,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<Option<ThresholdApprovalProposalRecord>, ApprovalStoreError> {
        validate_collector_identifier(proposal_id, "proposal_id", false)?;
        let mut proposals = self.threshold_proposals.lock().map_err(|_| {
            ApprovalStoreError::Backend("threshold proposal map poisoned".to_string())
        })?;
        let Some(record) = proposals.get_mut(proposal_id) else {
            return Ok(None);
        };
        record
            .registration
            .validate_current_context(current_context, trusted_policy_authorities)?;
        record.expire_if_due(now);
        Ok(Some(record.clone()))
    }

    fn append_threshold_approval_vote(
        &self,
        proposal_id: &str,
        token: &GovernedApprovalToken,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        validate_collector_identifier(proposal_id, "proposal_id", false)?;
        let mut proposals = self.threshold_proposals.lock().map_err(|_| {
            ApprovalStoreError::Backend("threshold proposal map poisoned".to_string())
        })?;
        let record = proposals
            .get_mut(proposal_id)
            .ok_or_else(|| ApprovalStoreError::NotFound(proposal_id.to_string()))?;
        record.validate_current_bindings(current_context, trusted_policy_authorities)?;
        if record.expire_if_due(now) {
            return Err(ApprovalStoreError::AlreadyResolved(format!(
                "threshold proposal `{proposal_id}` has expired"
            )));
        }
        if record
            .votes()
            .iter()
            .any(|vote| vote.token() == token)
        {
            return Ok(record.clone());
        }
        if record.status != ThresholdApprovalCollectorStatus::Collecting {
            return Err(ApprovalStoreError::AlreadyResolved(format!(
                "threshold proposal `{proposal_id}` is {}",
                record.status.as_str()
            )));
        }
        if record.existing_vote_for(token)?.is_some() {
            return Ok(record.clone());
        }
        let vote = ThresholdApprovalVoteRecord::validate_new(
            &record.registration,
            token.clone(),
            now,
            false,
        )?;
        let required = usize::try_from(record.proposal().body().required()).map_err(|_| {
            ApprovalStoreError::Invalid(
                "threshold requirement does not fit this platform".to_string(),
            )
        })?;
        let mut replay = self.replay.lock().map_err(|_| {
            ApprovalStoreError::Backend("approval replay state poisoned".to_string())
        })?;
        if replay.consumed.contains_key(&token.id) {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token `{}` was already consumed",
                token.id
            )));
        }
        if let Some(owner) = replay.token_id_owners.get(&token.id) {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token ID is already owned by `{owner}`"
            )));
        }
        if let Some(owner) = replay.token_digest_owners.get(vote.token_digest()) {
            return Err(ApprovalStoreError::Replay(format!(
                "approval token digest is already owned by `{owner}`"
            )));
        }
        let owner = format!("threshold-proposal:{proposal_id}");
        replay
            .token_id_owners
            .insert(token.id.clone(), owner.clone());
        replay
            .token_digest_owners
            .insert(vote.token_digest.clone(), owner);
        record.votes.push(vote);
        if record.votes.len() >= required {
            record.status = ThresholdApprovalCollectorStatus::Satisfied;
            record.satisfied_at = Some(now);
        }
        Ok(record.clone())
    }

    fn mark_threshold_approval_response_delivered(
        &self,
        proposal_id: &str,
        current_context: &ThresholdApprovalProposalCreationContext,
        trusted_policy_authorities: &[PublicKey],
        now: u64,
    ) -> Result<ThresholdApprovalProposalRecord, ApprovalStoreError> {
        validate_collector_identifier(proposal_id, "proposal_id", false)?;
        let mut proposals = self.threshold_proposals.lock().map_err(|_| {
            ApprovalStoreError::Backend("threshold proposal map poisoned".to_string())
        })?;
        let record = proposals
            .get_mut(proposal_id)
            .ok_or_else(|| ApprovalStoreError::NotFound(proposal_id.to_string()))?;
        record.validate_current_bindings(current_context, trusted_policy_authorities)?;
        if record.status == ThresholdApprovalCollectorStatus::Delivered {
            return Ok(record.clone());
        }
        if record.expire_if_due(now) {
            return Err(ApprovalStoreError::AlreadyResolved(format!(
                "threshold proposal `{proposal_id}` has expired"
            )));
        }
        if record.status != ThresholdApprovalCollectorStatus::Satisfied {
            return Err(ApprovalStoreError::Conflict(format!(
                "threshold proposal `{proposal_id}` is not satisfied"
            )));
        }
        record.status = ThresholdApprovalCollectorStatus::Delivered;
        record.delivered_at = Some(now);
        Ok(record.clone())
    }
}

/// In-memory `BatchApprovalStore` used in tests. Production backends
/// should persist via `SqliteBatchApprovalStore`.
#[derive(Default)]
pub struct InMemoryBatchApprovalStore {
    batches: RwLock<HashMap<String, BatchApproval>>,
}

impl InMemoryBatchApprovalStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BatchApprovalStore for InMemoryBatchApprovalStore {
    fn store(&self, batch: &BatchApproval) -> Result<(), ApprovalStoreError> {
        let mut guard = self
            .batches
            .write()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        guard.insert(batch.batch_id.clone(), batch.clone());
        Ok(())
    }

    fn find_matching(
        &self,
        subject_id: &str,
        server_id: &str,
        tool_name: &str,
        amount: Option<&MonetaryAmount>,
        now: u64,
    ) -> Result<Option<BatchApproval>, ApprovalStoreError> {
        let guard = self
            .batches
            .read()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        Ok(guard
            .values()
            .find(|b| {
                !b.revoked
                    && b.subject_id == subject_id
                    && pattern_matches(&b.server_pattern, server_id)
                    && pattern_matches(&b.tool_pattern, tool_name)
                    && now >= b.not_before
                    && now < b.not_after
                    && b.max_calls.is_none_or(|c| b.used_calls < c)
                    && amount_fits(b, amount)
            })
            .cloned())
    }

    fn record_usage(
        &self,
        batch_id: &str,
        amount: Option<&MonetaryAmount>,
    ) -> Result<(), ApprovalStoreError> {
        let mut guard = self
            .batches
            .write()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        let Some(batch) = guard.get_mut(batch_id) else {
            return Err(ApprovalStoreError::NotFound(batch_id.to_string()));
        };
        batch.used_calls = batch.used_calls.saturating_add(1);
        if let Some(amt) = amount {
            batch.used_total_units = batch.used_total_units.saturating_add(amt.units);
        }
        Ok(())
    }

    fn revoke(&self, batch_id: &str) -> Result<(), ApprovalStoreError> {
        let mut guard = self
            .batches
            .write()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        let Some(batch) = guard.get_mut(batch_id) else {
            return Err(ApprovalStoreError::NotFound(batch_id.to_string()));
        };
        batch.revoked = true;
        Ok(())
    }

    fn get(&self, batch_id: &str) -> Result<Option<BatchApproval>, ApprovalStoreError> {
        let guard = self
            .batches
            .read()
            .map_err(|_| ApprovalStoreError::Backend("batch map poisoned".into()))?;
        Ok(guard.get(batch_id).cloned())
    }
}

fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    pattern == value
}

fn amount_fits(batch: &BatchApproval, amount: Option<&MonetaryAmount>) -> bool {
    let Some(amt) = amount else {
        // Calls without a monetary intent match only batches that don't
        // constrain per-call amount.
        return batch.max_amount_per_call.is_none() && batch.max_total_amount.is_none();
    };
    if let Some(per_call) = &batch.max_amount_per_call {
        if amt.currency != per_call.currency || amt.units > per_call.units {
            return false;
        }
    }
    if let Some(total) = &batch.max_total_amount {
        if amt.currency != total.currency
            || batch.used_total_units.saturating_add(amt.units) > total.units
        {
            return false;
        }
    }
    true
}
