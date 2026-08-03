/// Validate the exact 1:1 authoritative-finding, action, and reservation shape.
#[cfg(feature = "std")]
pub fn validate_attested_finding_batch_body(body: &AttestedFindingBatchBody) -> PortResult<()> {
    if body.schema_version != ATTESTED_FINDING_BATCH_SCHEMA_VERSION || body.bindings.is_empty() {
        return Err(PortError::invalid_data());
    }
    let ordered_evidence_ids = body
        .bindings
        .as_slice()
        .iter()
        .map(|binding| binding.evidence_id.clone())
        .collect::<Vec<_>>();
    if derive_attested_finding_batch_id(&ordered_evidence_ids)? != body.batch_id {
        return Err(PortError::integrity_failure());
    }
    let mut finding_ids = alloc::collections::BTreeSet::new();
    let mut action_ids = alloc::collections::BTreeSet::new();
    let mut reservation_ids = alloc::collections::BTreeSet::new();
    for (ordinal, binding) in body.bindings.as_slice().iter().enumerate() {
        if binding.tenant_id != body.tenant_id
            || binding.finding_hash == Digest32::new([0_u8; 32])
            || !finding_ids.insert((&binding.tenant_id, &binding.finding_id))
            || !action_ids.insert((&binding.tenant_id, &binding.action_id))
            || !reservation_ids.insert((&binding.tenant_id, &binding.reservation_id))
            || derive_attested_finding_action_id(
                &body.batch_id,
                ordinal,
                &binding.tenant_id,
                &binding.evidence_id,
                &binding.finding_id,
                &binding.finding_hash,
            )? != binding.action_id
            || derive_attested_finding_reservation_id(
                &body.batch_id,
                &binding.action_id,
                &binding.evidence_id,
            )? != binding.reservation_id
        {
            return Err(PortError::integrity_failure());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanRecord {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub generation: u64,
    pub state: RecordId,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub due_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsePlanKey {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
}

/// Durable cursor for the last response evidence receipt whose authoritative
/// store append has been verified.
///
/// Business-state and effect CAS records commit the next receipt's exact body
/// inputs and predecessor before append. Only this separate cursor advances
/// after append succeeds or an append-ack-loss retry reloads and verifies the
/// exact signed receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseReceiptCursor {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub generation: u64,
    pub current_evidence_id: OpaqueReceiptRef,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseReceiptCursorCasRequest {
    pub cursor: ResponseReceiptCursor,
    pub expected_generation: u64,
    pub expected_evidence_id: OpaqueReceiptRef,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseCasRequest {
    pub record: ResponsePlanRecord,
    pub expected_generation: u64,
    pub transition_id: RecordId,
}

/// Atomically commits one scheduler-owned response mutation under one exact
/// live scheduler lease.
///
/// The store compares the complete `current` record, validates the complete
/// `candidate` lifecycle, and requires the candidate to append exactly one
/// mutation whose identifier is `transition_id`. Every field of `work`, both
/// canonical bodies, both body hashes, and both generations are part of the
/// idempotency binding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseScheduledMutationCasRequest {
    pub work: ScheduledWork,
    pub current: ResponsePlanRecord,
    pub candidate: ResponsePlanRecord,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectRecord {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub generation: u64,
    pub scheduler_lease_owner_id: LeaseOwnerId,
    pub scheduler_fencing_token: u64,
    pub state: RecordId,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
    pub encrypted_rollback_ref: Option<RecordId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectKey {
    pub tenant_id: TenantId,
    pub effect_id: EffectId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseEffectCasRequest {
    pub record: ResponseEffectRecord,
    pub expected_generation: u64,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerClaimRequest {
    pub tenant_id: TenantId,
    pub claim_id: RecordId,
    pub lease_owner_id: LeaseOwnerId,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
    pub max_claims: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledWork {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub lease_owner_id: LeaseOwnerId,
    pub lease_expires_at_unix_ms: u64,
    pub fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchKey {
    pub tenant_id: TenantId,
    pub dispatch_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "approval_mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseDispatchApproval {
    Automatic,
    Governed {
        admission_operation_id: RecordId,
        admission_operation_version: u64,
        approval_set_hash: Digest32,
    },
}

/// Canonical immutable authorization for one deterministic response dispatch.
///
/// `response_body_hash` binds the complete `Applying` response record. The
/// governed intent is present for both approval modes because automatic
/// response still executes the exact protocol-owned response intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchAuthorizationBody {
    pub schema_version: u8,
    pub key: ResponseDispatchKey,
    pub action_id: ActionId,
    pub plan_hash: Digest32,
    pub response_body_hash: Digest32,
    pub authorization_capability_hash: Digest32,
    pub governed_intent_hash: Digest32,
    pub policy_decision_hash: Digest32,
    pub executor_authority_id: RecordId,
    pub executor_authority_generation: u64,
    pub approval: ResponseDispatchApproval,
    pub authorized_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchAuthorization {
    pub body: ResponseDispatchAuthorizationBody,
    pub canonical_body: CanonicalBody,
    pub body_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchLease {
    pub lease_owner_id: LeaseOwnerId,
    pub lease_expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchRecoveryRequest {
    pub key: ResponseDispatchKey,
    pub action_id: ActionId,
    pub recovery_id: RecordId,
    pub lease_owner_id: LeaseOwnerId,
    /// Exact fencing token observed before the atomic recovery attempt.
    /// Stores reject `None` so an unfenced legacy request fails closed.
    pub expected_fencing_token: Option<u64>,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "work")]
pub enum ResponseDispatchRecoveryOutcome {
    LiveLease(ScheduledWork),
    Takeover(ScheduledWork),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchCommitRequest {
    pub mode: ResponseDispatchCommitMode,
    pub authorization: ResponseDispatchAuthorization,
    pub response_plan: ResponsePlanRecord,
    pub initial_lease: ResponseDispatchLease,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDispatchCommitMode {
    Fresh,
    GovernedCommittedResume,
    GovernedCommittedExpiredResume,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseDispatchRecord {
    pub authorization: ResponseDispatchAuthorization,
    pub response_plan: ResponsePlanRecord,
    pub initial_work: ScheduledWork,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "record")]
pub enum ResponseDispatchCommitOutcome {
    Committed(ResponseDispatchRecord),
    Existing(ResponseDispatchRecord),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "record")]
pub enum ResponseDispatchLoadOutcome {
    Found(Box<ResponseDispatchRecord>),
    Missing,
}

/// Exact automatic dispatch identity durably closed before executor commit.
///
/// The complete prepared binding is retained so a retry can distinguish the
/// same termination from a conflicting dispatch identity. The response plan is
/// supplied for validation only and is not part of the mutable store state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticResponseDispatchFenceRequest {
    pub response_plan: crate::ResponsePlan,
    pub prepared_dispatch_binding: PreparedActiveResponseDispatchBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AutomaticResponseDispatchFenceRecord {
    pub prepared_dispatch_binding: PreparedActiveResponseDispatchBinding,
    pub binding_hash: Digest32,
    pub fenced_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "record")]
pub enum AutomaticResponseDispatchFenceOutcome {
    Fenced(AutomaticResponseDispatchFenceRecord),
    ExistingFence(AutomaticResponseDispatchFenceRecord),
    Committed(Box<ResponseDispatchRecord>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerWorkKey {
    pub tenant_id: TenantId,
    pub action_id: ActionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRetryState {
    pub key: SchedulerWorkKey,
    pub attempts: u32,
    pub last_error: ErrorCode,
    pub first_failure_at_unix_ms: u64,
    pub not_before_unix_ms: u64,
    pub health_event_id: Option<RecordId>,
    pub health_event_delivered: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerLeaseRenewRequest {
    pub work: ScheduledWork,
    pub now_unix_ms: u64,
    pub lease_expires_at_unix_ms: u64,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRetryRequest {
    pub work: ScheduledWork,
    pub expected_attempts: u32,
    pub error_code: ErrorCode,
    pub first_failure_at_unix_ms: u64,
    pub now_unix_ms: u64,
    pub not_before_unix_ms: u64,
    pub health_event_id: Option<RecordId>,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerHealthAckRequest {
    pub key: SchedulerWorkKey,
    pub event_id: RecordId,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerLeaseReleaseRequest {
    pub work: ScheduledWork,
    pub clear_retry_state: bool,
    pub transition_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayContribution {
    pub effect_id: EffectId,
    pub posture_rank: u32,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentOverlayCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
    pub resulting_snapshot: OverlaySnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayApplyRequest {
    pub target: TenantScopedId,
    pub action_id: ActionId,
    pub contribution: OverlayContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: ContainmentOverlayCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayRemoveRequest {
    pub target: TenantScopedId,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: ContainmentOverlayCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OverlaySnapshot {
    pub target: TenantScopedId,
    pub generation: u64,
    pub effective_posture_rank: u32,
    pub active_contributions: OverlayContributions,
    pub highest_fencing_token: u64,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ContainmentOverlayVersionCommitment<'a> {
    schema_version: u8,
    target: &'a TenantScopedId,
    generation: u64,
    effective_posture_rank: u32,
    active_contributions: &'a OverlayContributions,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ContainmentInstalledContributionCommitment<'a> {
    schema_version: u8,
    target: &'a TenantScopedId,
    effect_id: &'a str,
    posture_rank: u32,
    contribution_hash: Digest32,
    expires_at_unix_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentTargetKind {
    Session,
    Principal,
    Lineage,
    Capability,
}

impl ContainmentTargetKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Principal => "principal",
            Self::Lineage => "lineage",
            Self::Capability => "capability",
        }
    }
}

#[cfg(feature = "std")]
pub fn containment_target(
    tenant_id: &TenantId,
    kind: ContainmentTargetKind,
    authoritative_id: &str,
) -> PortResult<TenantScopedId> {
    use sha2::{Digest as _, Sha256};

    if authoritative_id.is_empty() || authoritative_id.len() > MAX_ID_BYTES {
        return Err(PortError::invalid_data());
    }
    let mut hasher = Sha256::new();
    hasher.update(CONTAINMENT_TARGET_DOMAIN);
    hasher.update(kind.as_str().as_bytes());
    hasher.update([0_u8]);
    hasher.update(authoritative_id.as_bytes());
    let digest = hasher.finalize();
    let mut target_hex = String::with_capacity(digest.len().saturating_mul(2));
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        target_hex.push(char::from(HEX[usize::from(byte >> 4)]));
        target_hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(TenantScopedId {
        tenant_id: tenant_id.clone(),
        id: RecordId::new(format!("{}-{target_hex}", kind.as_str())).map_err(PortError::from)?,
    })
}

#[cfg(feature = "std")]
pub fn containment_session_target(
    tenant_id: &TenantId,
    session_id: &SessionId,
) -> PortResult<TenantScopedId> {
    containment_target(
        tenant_id,
        ContainmentTargetKind::Session,
        session_id.as_str(),
    )
}

#[cfg(feature = "std")]
pub fn validate_containment_overlay_snapshot(
    snapshot: &OverlaySnapshot,
    expected_target: &TenantScopedId,
) -> PortResult<()> {
    if &snapshot.target != expected_target {
        return Err(PortError::integrity_failure());
    }
    let contributions = snapshot.active_contributions.as_slice();
    if contributions
        .windows(2)
        .any(|pair| pair[0].effect_id >= pair[1].effect_id)
    {
        return Err(PortError::integrity_failure());
    }
    let recomputed_posture = contributions
        .iter()
        .map(|entry| entry.posture_rank)
        .max()
        .unwrap_or(0);
    let contribution_count =
        u64::try_from(contributions.len()).map_err(|_| PortError::integrity_failure())?;
    if recomputed_posture != snapshot.effective_posture_rank
        || (snapshot.effective_posture_rank == 0) != contributions.is_empty()
        || snapshot.generation < contribution_count
        || (!contributions.is_empty() && snapshot.highest_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn containment_overlay_version_hash(snapshot: &OverlaySnapshot) -> PortResult<Digest32> {
    validate_containment_overlay_snapshot(snapshot, &snapshot.target)?;
    containment_domain_hash(
        CONTAINMENT_OVERLAY_VERSION_DOMAIN,
        &ContainmentOverlayVersionCommitment {
            schema_version: 1,
            target: &snapshot.target,
            generation: snapshot.generation,
            effective_posture_rank: snapshot.effective_posture_rank,
            active_contributions: &snapshot.active_contributions,
        },
    )
}

#[cfg(feature = "std")]
pub fn containment_installed_version_hash(
    target: &TenantScopedId,
    contribution: &OverlayContribution,
) -> PortResult<Digest32> {
    containment_domain_hash(
        CONTAINMENT_INSTALLED_CONTRIBUTION_DOMAIN,
        &ContainmentInstalledContributionCommitment {
            schema_version: 1,
            target,
            effect_id: contribution.effect_id.as_str(),
            posture_rank: contribution.posture_rank,
            contribution_hash: contribution.contribution_hash,
            expires_at_unix_ms: contribution.expires_at_unix_ms,
        },
    )
}

#[cfg(feature = "std")]
pub fn predict_containment_overlay_apply(
    current: &OverlaySnapshot,
    contribution: &OverlayContribution,
    scheduler_fencing_token: u64,
) -> PortResult<OverlaySnapshot> {
    validate_containment_overlay_snapshot(current, &current.target)?;
    let mut contributions = current.active_contributions.clone().into_vec();
    let generation = if let Some(existing) = contributions
        .iter()
        .find(|entry| entry.effect_id == contribution.effect_id)
    {
        if existing != contribution {
            return Err(PortError::conflict());
        }
        current.generation
    } else {
        contributions.push(contribution.clone());
        contributions.sort_by(|left, right| left.effect_id.cmp(&right.effect_id));
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    };
    let effective_posture_rank = contributions
        .iter()
        .map(|entry| entry.posture_rank)
        .max()
        .unwrap_or(0);
    let snapshot = OverlaySnapshot {
        target: current.target.clone(),
        generation,
        effective_posture_rank,
        active_contributions: OverlayContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: current.highest_fencing_token.max(scheduler_fencing_token),
    };
    validate_containment_overlay_snapshot(&snapshot, &current.target)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn predict_containment_overlay_remove(
    current: &OverlaySnapshot,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<OverlaySnapshot> {
    validate_containment_overlay_snapshot(current, &current.target)?;
    let mut contributions = current.active_contributions.clone().into_vec();
    let before = contributions.len();
    contributions.retain(|entry| &entry.effect_id != effect_id);
    let removed = contributions.len() != before;
    let generation = if removed {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    } else {
        current.generation
    };
    let effective_posture_rank = contributions
        .iter()
        .map(|entry| entry.posture_rank)
        .max()
        .unwrap_or(0);
    let snapshot = OverlaySnapshot {
        target: current.target.clone(),
        generation,
        effective_posture_rank,
        active_contributions: OverlayContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: if removed {
            current.highest_fencing_token.max(scheduler_fencing_token)
        } else {
            current.highest_fencing_token
        },
    };
    validate_containment_overlay_snapshot(&snapshot, &current.target)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
fn containment_domain_hash(domain: &[u8], commitment: &impl Serialize) -> PortResult<Digest32> {
    use sha2::{Digest as _, Sha256};

    let value = serde_json::to_value(commitment).map_err(|_| PortError::integrity_failure())?;
    let canonical = serde_json::to_vec(&value).map_err(|_| PortError::integrity_failure())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}

/// Closed contribution body for a session throttle effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleLimits {
    pub window_ms: u64,
    pub max_invocations: u32,
}

impl SessionThrottleLimits {
    pub fn validate(self) -> PortResult<()> {
        if self.window_ms == 0
            || self.window_ms > SESSION_THROTTLE_MAX_WINDOW_MS
            || self.max_invocations == 0
            || self.max_invocations > SESSION_THROTTLE_MAX_INVOCATIONS
        {
            return Err(PortError::invalid_data());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleKey {
    pub tenant_id: TenantId,
    pub session_id: SessionId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleContribution {
    pub effect_id: EffectId,
    pub limits: SessionThrottleLimits,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleSnapshot {
    pub key: SessionThrottleKey,
    pub generation: u64,
    pub contributions: SessionThrottleContributions,
    pub highest_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
    pub resulting_snapshot: SessionThrottleSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleApplyRequest {
    pub key: SessionThrottleKey,
    pub action_id: ActionId,
    pub contribution: SessionThrottleContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: SessionThrottleCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleRemoveRequest {
    pub key: SessionThrottleKey,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: SessionThrottleCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleConsumeRequest {
    pub key: SessionThrottleKey,
    pub invocation_id: RecordId,
    pub observed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleWindowIdentity {
    pub window_id: RecordId,
    pub window_start_unix_ms: u64,
    pub window_end_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleWindowUsage {
    pub effect_id: EffectId,
    pub identity: SessionThrottleWindowIdentity,
    pub consumed_before: u32,
    pub consumed_after: u32,
    pub max_invocations: u32,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionThrottleDecision {
    pub key: SessionThrottleKey,
    pub allowed: bool,
    pub generation: u64,
    pub current_version_hash: Digest32,
    pub windows: SessionThrottleWindowUsages,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SessionThrottleVersionCommitment<'a> {
    schema_version: u8,
    key: &'a SessionThrottleKey,
    generation: u64,
    contributions: &'a SessionThrottleContributions,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SessionThrottleInstalledCommitment<'a> {
    schema_version: u8,
    key: &'a SessionThrottleKey,
    contribution: &'a SessionThrottleContribution,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SessionThrottleWindowCommitment<'a> {
    schema_version: u8,
    key: &'a SessionThrottleKey,
    effect_id: &'a str,
    window_ms: u64,
    window_start_unix_ms: u64,
}

#[cfg(feature = "std")]
pub fn empty_session_throttle_snapshot(
    key: SessionThrottleKey,
) -> PortResult<SessionThrottleSnapshot> {
    let snapshot = SessionThrottleSnapshot {
        key,
        generation: 0,
        contributions: SessionThrottleContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    };
    validate_session_throttle_snapshot(&snapshot, &snapshot.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn validate_session_throttle_snapshot(
    snapshot: &SessionThrottleSnapshot,
    expected_key: &SessionThrottleKey,
) -> PortResult<()> {
    if &snapshot.key != expected_key
        || snapshot
            .contributions
            .as_slice()
            .windows(2)
            .any(|pair| pair[0].effect_id >= pair[1].effect_id)
    {
        return Err(PortError::integrity_failure());
    }
    for contribution in snapshot.contributions.as_slice() {
        contribution
            .limits
            .validate()
            .map_err(|_| PortError::integrity_failure())?;
        if contribution.expires_at_unix_ms == 0
            || contribution
                .contribution_hash
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(PortError::integrity_failure());
        }
    }
    let count =
        u64::try_from(snapshot.contributions.len()).map_err(|_| PortError::integrity_failure())?;
    if snapshot.generation < count
        || (!snapshot.contributions.is_empty() && snapshot.highest_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn session_throttle_version_hash(snapshot: &SessionThrottleSnapshot) -> PortResult<Digest32> {
    validate_session_throttle_snapshot(snapshot, &snapshot.key)?;
    session_throttle_domain_hash(
        SESSION_THROTTLE_VERSION_DOMAIN,
        &SessionThrottleVersionCommitment {
            schema_version: 1,
            key: &snapshot.key,
            generation: snapshot.generation,
            contributions: &snapshot.contributions,
        },
    )
}

#[cfg(feature = "std")]
pub fn session_throttle_installed_version_hash(
    key: &SessionThrottleKey,
    contribution: &SessionThrottleContribution,
) -> PortResult<Digest32> {
    contribution.limits.validate()?;
    if contribution.expires_at_unix_ms == 0
        || contribution
            .contribution_hash
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PortError::invalid_data());
    }
    session_throttle_domain_hash(
        SESSION_THROTTLE_INSTALLED_CONTRIBUTION_DOMAIN,
        &SessionThrottleInstalledCommitment {
            schema_version: 1,
            key,
            contribution,
        },
    )
}

#[cfg(feature = "std")]
pub fn predict_session_throttle_apply(
    current: &SessionThrottleSnapshot,
    contribution: &SessionThrottleContribution,
    scheduler_fencing_token: u64,
) -> PortResult<SessionThrottleSnapshot> {
    validate_session_throttle_snapshot(current, &current.key)?;
    contribution.limits.validate()?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let generation = if let Some(existing) = contributions
        .iter()
        .find(|entry| entry.effect_id == contribution.effect_id)
    {
        if existing != contribution {
            return Err(PortError::conflict());
        }
        current.generation
    } else {
        contributions.push(contribution.clone());
        contributions.sort_by(|left, right| left.effect_id.cmp(&right.effect_id));
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    };
    let snapshot = SessionThrottleSnapshot {
        key: current.key.clone(),
        generation,
        contributions: SessionThrottleContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: current.highest_fencing_token.max(scheduler_fencing_token),
    };
    validate_session_throttle_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn predict_session_throttle_remove(
    current: &SessionThrottleSnapshot,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<SessionThrottleSnapshot> {
    validate_session_throttle_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let before = contributions.len();
    contributions.retain(|entry| &entry.effect_id != effect_id);
    let removed = before != contributions.len();
    let generation = if removed {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    } else {
        current.generation
    };
    let snapshot = SessionThrottleSnapshot {
        key: current.key.clone(),
        generation,
        contributions: SessionThrottleContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: if removed {
            current.highest_fencing_token.max(scheduler_fencing_token)
        } else {
            current.highest_fencing_token
        },
    };
    validate_session_throttle_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn session_throttle_window_identity(
    key: &SessionThrottleKey,
    effect_id: &EffectId,
    limits: SessionThrottleLimits,
    observed_at_unix_ms: u64,
) -> PortResult<SessionThrottleWindowIdentity> {
    limits.validate()?;
    let window_start_unix_ms = observed_at_unix_ms
        .checked_div(limits.window_ms)
        .and_then(|bucket| bucket.checked_mul(limits.window_ms))
        .ok_or_else(PortError::integrity_failure)?;
    let window_end_unix_ms = window_start_unix_ms
        .checked_add(limits.window_ms)
        .ok_or_else(PortError::integrity_failure)?;
    let digest = session_throttle_domain_hash(
        SESSION_THROTTLE_WINDOW_DOMAIN,
        &SessionThrottleWindowCommitment {
            schema_version: 1,
            key,
            effect_id: effect_id.as_str(),
            window_ms: limits.window_ms,
            window_start_unix_ms,
        },
    )?;
    Ok(SessionThrottleWindowIdentity {
        window_id: RecordId::new(format!(
            "session_throttle_window:{}",
            session_throttle_hex(digest.as_bytes())
        ))
        .map_err(PortError::from)?,
        window_start_unix_ms,
        window_end_unix_ms,
    })
}

#[cfg(feature = "std")]
fn session_throttle_domain_hash(
    domain: &[u8],
    commitment: &impl Serialize,
) -> PortResult<Digest32> {
    use sha2::{Digest as _, Sha256};

    let value = serde_json::to_value(commitment).map_err(|_| PortError::integrity_failure())?;
    let canonical = serde_json::to_vec(&value).map_err(|_| PortError::integrity_failure())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}

#[cfg(feature = "std")]
fn session_throttle_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Closed contribution body for an exact capability-set suspension.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionSpec {
    pub affected_ids: RecordIdSet,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionKey {
    pub tenant_id: TenantId,
    pub affected_set_hash: Digest32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionContribution {
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub affected_ids: RecordIdSet,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionSnapshot {
    pub key: CapabilitySetSuspensionKey,
    pub generation: u64,
    pub contributions: CapabilitySetSuspensionContributions,
    pub highest_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
    pub resulting_snapshot: CapabilitySetSuspensionSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionApplyRequest {
    pub key: CapabilitySetSuspensionKey,
    pub contribution: CapabilitySetSuspensionContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: CapabilitySetSuspensionCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionRemoveRequest {
    pub key: CapabilitySetSuspensionKey,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: CapabilitySetSuspensionCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySuspensionQuery {
    pub tenant_id: TenantId,
    pub capability_id: RecordId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySetSuspensionMatch {
    pub affected_set_hash: Digest32,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilitySuspensionDecision {
    pub tenant_id: TenantId,
    pub capability_id: RecordId,
    pub denied: bool,
    pub active_matches: CapabilitySetSuspensionMatches,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseAffectedSetCommitment<'a> {
    tenant_id: &'a str,
    affected_ids: &'a [RecordId],
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilitySetSuspensionVersionCommitment<'a> {
    schema_version: u8,
    key: &'a CapabilitySetSuspensionKey,
    generation: u64,
    contributions: &'a CapabilitySetSuspensionContributions,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CapabilitySetSuspensionInstalledCommitment<'a> {
    schema_version: u8,
    key: &'a CapabilitySetSuspensionKey,
    contribution: &'a CapabilitySetSuspensionContribution,
}

#[cfg(feature = "std")]
pub fn response_affected_set_hash(
    tenant_id: &TenantId,
    affected_ids: &RecordIdSet,
) -> PortResult<Digest32> {
    if affected_ids.as_slice().is_empty() {
        return Err(PortError::invalid_data());
    }
    capability_set_suspension_domain_hash(
        RESPONSE_AFFECTED_SET_DOMAIN,
        &ResponseAffectedSetCommitment {
            tenant_id: tenant_id.as_str(),
            affected_ids: affected_ids.as_slice(),
        },
    )
}

#[cfg(feature = "std")]
pub fn empty_capability_set_suspension_snapshot(
    key: CapabilitySetSuspensionKey,
) -> PortResult<CapabilitySetSuspensionSnapshot> {
    let snapshot = CapabilitySetSuspensionSnapshot {
        key: key.clone(),
        generation: 0,
        contributions: CapabilitySetSuspensionContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: 0,
    };
    validate_capability_set_suspension_snapshot(&snapshot, &key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn validate_capability_set_suspension_snapshot(
    snapshot: &CapabilitySetSuspensionSnapshot,
    expected_key: &CapabilitySetSuspensionKey,
) -> PortResult<()> {
    if &snapshot.key != expected_key {
        return Err(PortError::integrity_failure());
    }
    let contributions = snapshot.contributions.as_slice();
    if contributions.windows(2).any(|pair| {
        (&pair[0].action_id, &pair[0].effect_id) >= (&pair[1].action_id, &pair[1].effect_id)
    }) {
        return Err(PortError::integrity_failure());
    }
    for contribution in contributions {
        if contribution.expires_at_unix_ms == 0
            || response_affected_set_hash(&snapshot.key.tenant_id, &contribution.affected_ids)?
                != snapshot.key.affected_set_hash
        {
            return Err(PortError::integrity_failure());
        }
    }
    let contribution_count =
        u64::try_from(contributions.len()).map_err(|_| PortError::integrity_failure())?;
    if snapshot.generation < contribution_count
        || (!contributions.is_empty() && snapshot.highest_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn capability_set_suspension_version_hash(
    snapshot: &CapabilitySetSuspensionSnapshot,
) -> PortResult<Digest32> {
    validate_capability_set_suspension_snapshot(snapshot, &snapshot.key)?;
    capability_set_suspension_domain_hash(
        CAPABILITY_SET_SUSPENSION_VERSION_DOMAIN,
        &CapabilitySetSuspensionVersionCommitment {
            schema_version: 1,
            key: &snapshot.key,
            generation: snapshot.generation,
            contributions: &snapshot.contributions,
        },
    )
}

#[cfg(feature = "std")]
pub fn capability_set_suspension_installed_version_hash(
    key: &CapabilitySetSuspensionKey,
    contribution: &CapabilitySetSuspensionContribution,
) -> PortResult<Digest32> {
    if response_affected_set_hash(&key.tenant_id, &contribution.affected_ids)?
        != key.affected_set_hash
    {
        return Err(PortError::invalid_data());
    }
    capability_set_suspension_domain_hash(
        CAPABILITY_SET_SUSPENSION_INSTALLED_CONTRIBUTION_DOMAIN,
        &CapabilitySetSuspensionInstalledCommitment {
            schema_version: 1,
            key,
            contribution,
        },
    )
}

#[cfg(feature = "std")]
pub fn predict_capability_set_suspension_apply(
    current: &CapabilitySetSuspensionSnapshot,
    contribution: &CapabilitySetSuspensionContribution,
    scheduler_fencing_token: u64,
) -> PortResult<CapabilitySetSuspensionSnapshot> {
    validate_capability_set_suspension_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0
        || response_affected_set_hash(&current.key.tenant_id, &contribution.affected_ids)?
            != current.key.affected_set_hash
    {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let generation = if let Some(existing) = contributions.iter().find(|entry| {
        entry.action_id == contribution.action_id && entry.effect_id == contribution.effect_id
    }) {
        if existing != contribution {
            return Err(PortError::conflict());
        }
        current.generation
    } else {
        contributions.push(contribution.clone());
        contributions.sort_by(|left, right| {
            (&left.action_id, &left.effect_id).cmp(&(&right.action_id, &right.effect_id))
        });
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    };
    let snapshot = CapabilitySetSuspensionSnapshot {
        key: current.key.clone(),
        generation,
        contributions: CapabilitySetSuspensionContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: current.highest_fencing_token.max(scheduler_fencing_token),
    };
    validate_capability_set_suspension_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn predict_capability_set_suspension_remove(
    current: &CapabilitySetSuspensionSnapshot,
    action_id: &ActionId,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<CapabilitySetSuspensionSnapshot> {
    validate_capability_set_suspension_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let before = contributions.len();
    contributions.retain(|entry| &entry.action_id != action_id || &entry.effect_id != effect_id);
    let removed = contributions.len() != before;
    let generation = if removed {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    } else {
        current.generation
    };
    let snapshot = CapabilitySetSuspensionSnapshot {
        key: current.key.clone(),
        generation,
        contributions: CapabilitySetSuspensionContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_fencing_token: if removed {
            current.highest_fencing_token.max(scheduler_fencing_token)
        } else {
            current.highest_fencing_token
        },
    };
    validate_capability_set_suspension_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn validate_capability_suspension_decision(
    query: &CapabilitySuspensionQuery,
    decision: &CapabilitySuspensionDecision,
) -> PortResult<()> {
    if decision.tenant_id != query.tenant_id
        || decision.capability_id != query.capability_id
        || decision.denied == decision.active_matches.is_empty()
        || decision.active_matches.as_slice().windows(2).any(|pair| {
            (
                pair[0].action_id.as_str(),
                pair[0].effect_id.as_str(),
                pair[0].affected_set_hash,
            ) >= (
                pair[1].action_id.as_str(),
                pair[1].effect_id.as_str(),
                pair[1].affected_set_hash,
            )
        })
        || decision
            .active_matches
            .as_slice()
            .iter()
            .any(|entry| entry.expires_at_unix_ms == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
fn capability_set_suspension_domain_hash(
    domain: &[u8],
    commitment: &impl Serialize,
) -> PortResult<Digest32> {
    use sha2::{Digest as _, Sha256};

    let value = serde_json::to_value(commitment).map_err(|_| PortError::integrity_failure())?;
    let canonical = serde_json::to_vec(&value).map_err(|_| PortError::integrity_failure())?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Ok(Digest32::new(hasher.finalize().into()))
}

/// Closed contribution body for a commit-indexed issuance freeze.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeSpec {
    pub lineage_id: LineageId,
    pub acquisition: BlastRadiusFenceAcquisition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeKey {
    pub tenant_id: TenantId,
    pub lineage_id: LineageId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeContribution {
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub commit_index: u64,
    pub affected_set_hash: Digest32,
    pub frozen_affected_ids: RecordIdSet,
    pub graph_slice_hash: Digest32,
    /// Rolling external safety lease. Maintenance may extend this beyond the
    /// immutable response-plan expiry while removal is still incomplete.
    pub external_fence: LineageFence,
    pub contribution_hash: Digest32,
    /// Immutable authorization expiry copied from the response plan.
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeSnapshot {
    pub key: IssuanceFreezeKey,
    pub generation: u64,
    pub contributions: IssuanceFreezeContributions,
    pub highest_scheduler_fencing_token: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeCommand {
    pub request: EffectRequest,
    pub result: EffectResult,
    pub resulting_snapshot: IssuanceFreezeSnapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeApplyRequest {
    pub key: IssuanceFreezeKey,
    pub contribution: IssuanceFreezeContribution,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: IssuanceFreezeCommand,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeRemoveRequest {
    pub key: IssuanceFreezeKey,
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub expected_generation: u64,
    pub scheduler_fencing_token: u64,
    pub command: IssuanceFreezeCommand,
}

/// Exact durable removal command whose external fence release has started but
/// whose local contribution cleanup has not yet committed.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezePendingRelease {
    pub request: IssuanceFreezeRemoveRequest,
    pub contribution: IssuanceFreezeContribution,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum IssuanceFreezeOperationStatus {
    NotExecuted,
    ReleasePending {
        contribution: Box<IssuanceFreezeContribution>,
    },
    Completed {
        result: EffectResult,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityIssuanceOperation {
    Issue,
    Delegate,
}

impl CapabilityIssuanceOperation {
    pub fn validate_parent(self, parent_capability_id: Option<&RecordId>) -> PortResult<()> {
        if matches!(
            (self, parent_capability_id),
            (Self::Issue, None) | (Self::Delegate, Some(_))
        ) {
            Ok(())
        } else {
            Err(PortError::invalid_data())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeAdmissionQuery {
    pub tenant_id: TenantId,
    pub lineage_id: LineageId,
    pub operation: CapabilityIssuanceOperation,
    pub parent_capability_id: Option<RecordId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeMatch {
    pub action_id: ActionId,
    pub effect_id: EffectId,
    pub commit_index: u64,
    pub affected_set_hash: Digest32,
    pub contribution_hash: Digest32,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IssuanceFreezeAdmissionDecision {
    pub query: IssuanceFreezeAdmissionQuery,
    pub frozen: bool,
    pub active_matches: IssuanceFreezeMatches,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct IssuanceFreezeVersionCommitment<'a> {
    schema_version: u8,
    key: &'a IssuanceFreezeKey,
    generation: u64,
    contributions: &'a IssuanceFreezeContributions,
}

#[cfg(feature = "std")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct IssuanceFreezeInstalledCommitment<'a> {
    schema_version: u8,
    key: &'a IssuanceFreezeKey,
    action_id: &'a ActionId,
    effect_id: &'a EffectId,
    commit_index: u64,
    affected_set_hash: Digest32,
    frozen_affected_ids: &'a RecordIdSet,
    graph_slice_hash: Digest32,
    contribution_hash: Digest32,
    expires_at_unix_ms: u64,
}

#[cfg(feature = "std")]
pub fn empty_issuance_freeze_snapshot(
    key: IssuanceFreezeKey,
) -> PortResult<IssuanceFreezeSnapshot> {
    let snapshot = IssuanceFreezeSnapshot {
        key: key.clone(),
        generation: 0,
        contributions: IssuanceFreezeContributions::new(Vec::new())
            .map_err(|_| PortError::integrity_failure())?,
        highest_scheduler_fencing_token: 0,
    };
    validate_issuance_freeze_snapshot(&snapshot, &key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn validate_issuance_freeze_contribution(
    key: &IssuanceFreezeKey,
    contribution: &IssuanceFreezeContribution,
) -> PortResult<()> {
    let lineage_root =
        RecordId::new(key.lineage_id.as_str()).map_err(|_| PortError::integrity_failure())?;
    if contribution.commit_index == 0
        || contribution.frozen_affected_ids.as_slice().is_empty()
        || contribution
            .frozen_affected_ids
            .as_slice()
            .binary_search(&lineage_root)
            .is_err()
        || contribution.graph_slice_hash == Digest32::new([0_u8; 32])
        || contribution.expires_at_unix_ms == 0
        || response_affected_set_hash(&key.tenant_id, &contribution.frozen_affected_ids)?
            != contribution.affected_set_hash
        || contribution.external_fence.tenant_id != key.tenant_id
        || contribution.external_fence.action_id != contribution.action_id
        || contribution.external_fence.commit_index != contribution.commit_index
        || contribution.external_fence.affected_set_hash != contribution.affected_set_hash
        || contribution.external_fence.fencing_token == 0
        || contribution.external_fence.scheduler_fencing_token == 0
        || contribution.external_fence.expires_at_unix_ms == 0
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn validate_issuance_freeze_snapshot(
    snapshot: &IssuanceFreezeSnapshot,
    expected_key: &IssuanceFreezeKey,
) -> PortResult<()> {
    if &snapshot.key != expected_key
        || snapshot.contributions.as_slice().windows(2).any(|pair| {
            (&pair[0].action_id, &pair[0].effect_id) >= (&pair[1].action_id, &pair[1].effect_id)
        })
    {
        return Err(PortError::integrity_failure());
    }
    for contribution in snapshot.contributions.as_slice() {
        validate_issuance_freeze_contribution(&snapshot.key, contribution)?;
    }
    let contribution_count =
        u64::try_from(snapshot.contributions.len()).map_err(|_| PortError::integrity_failure())?;
    if snapshot.generation < contribution_count
        || (!snapshot.contributions.is_empty() && snapshot.highest_scheduler_fencing_token == 0)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

#[cfg(feature = "std")]
pub fn issuance_freeze_version_hash(snapshot: &IssuanceFreezeSnapshot) -> PortResult<Digest32> {
    validate_issuance_freeze_snapshot(snapshot, &snapshot.key)?;
    issuance_freeze_domain_hash(
        ISSUANCE_FREEZE_VERSION_DOMAIN,
        &IssuanceFreezeVersionCommitment {
            schema_version: 1,
            key: &snapshot.key,
            generation: snapshot.generation,
            contributions: &snapshot.contributions,
        },
    )
}

#[cfg(feature = "std")]
pub fn issuance_freeze_installed_version_hash(
    key: &IssuanceFreezeKey,
    contribution: &IssuanceFreezeContribution,
) -> PortResult<Digest32> {
    validate_issuance_freeze_contribution(key, contribution)?;
    issuance_freeze_domain_hash(
        ISSUANCE_FREEZE_INSTALLED_CONTRIBUTION_DOMAIN,
        &IssuanceFreezeInstalledCommitment {
            schema_version: 1,
            key,
            action_id: &contribution.action_id,
            effect_id: &contribution.effect_id,
            commit_index: contribution.commit_index,
            affected_set_hash: contribution.affected_set_hash,
            frozen_affected_ids: &contribution.frozen_affected_ids,
            graph_slice_hash: contribution.graph_slice_hash,
            contribution_hash: contribution.contribution_hash,
            expires_at_unix_ms: contribution.expires_at_unix_ms,
        },
    )
}

#[cfg(feature = "std")]
pub fn predict_issuance_freeze_apply(
    current: &IssuanceFreezeSnapshot,
    contribution: &IssuanceFreezeContribution,
    scheduler_fencing_token: u64,
) -> PortResult<IssuanceFreezeSnapshot> {
    validate_issuance_freeze_snapshot(current, &current.key)?;
    validate_issuance_freeze_contribution(&current.key, contribution)?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let generation = if let Some(existing) = contributions.iter().find(|entry| {
        entry.action_id == contribution.action_id && entry.effect_id == contribution.effect_id
    }) {
        if existing != contribution {
            return Err(PortError::conflict());
        }
        current.generation
    } else {
        contributions.push(contribution.clone());
        contributions.sort_by(|left, right| {
            (&left.action_id, &left.effect_id).cmp(&(&right.action_id, &right.effect_id))
        });
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    };
    let snapshot = IssuanceFreezeSnapshot {
        key: current.key.clone(),
        generation,
        contributions: IssuanceFreezeContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_scheduler_fencing_token: current
            .highest_scheduler_fencing_token
            .max(scheduler_fencing_token),
    };
    validate_issuance_freeze_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn predict_issuance_freeze_remove(
    current: &IssuanceFreezeSnapshot,
    action_id: &ActionId,
    effect_id: &EffectId,
    scheduler_fencing_token: u64,
) -> PortResult<IssuanceFreezeSnapshot> {
    validate_issuance_freeze_snapshot(current, &current.key)?;
    if scheduler_fencing_token == 0 {
        return Err(PortError::invalid_data());
    }
    let mut contributions = current.contributions.clone().into_vec();
    let before = contributions.len();
    contributions.retain(|entry| &entry.action_id != action_id || &entry.effect_id != effect_id);
    let removed = contributions.len() != before;
    let generation = if removed {
        current
            .generation
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?
    } else {
        current.generation
    };
    let snapshot = IssuanceFreezeSnapshot {
        key: current.key.clone(),
        generation,
        contributions: IssuanceFreezeContributions::new(contributions)
            .map_err(|_| PortError::integrity_failure())?,
        highest_scheduler_fencing_token: if removed {
            current
                .highest_scheduler_fencing_token
                .max(scheduler_fencing_token)
        } else {
            current.highest_scheduler_fencing_token
        },
    };
    validate_issuance_freeze_snapshot(&snapshot, &current.key)?;
    Ok(snapshot)
}

#[cfg(feature = "std")]
pub fn validate_issuance_freeze_admission_decision(
    query: &IssuanceFreezeAdmissionQuery,
    decision: &IssuanceFreezeAdmissionDecision,
) -> PortResult<()> {
    query
        .operation
        .validate_parent(query.parent_capability_id.as_ref())?;
    if &decision.query != query
        || decision.frozen == decision.active_matches.is_empty()
        || decision.active_matches.as_slice().windows(2).any(|pair| {
            (&pair[0].action_id, &pair[0].effect_id) >= (&pair[1].action_id, &pair[1].effect_id)
        })
        || decision.active_matches.as_slice().iter().any(|entry| {
            entry.commit_index == 0
                || entry.affected_set_hash == Digest32::new([0_u8; 32])
                || entry.contribution_hash == Digest32::new([0_u8; 32])
                || entry.expires_at_unix_ms == 0
        })
    {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}
