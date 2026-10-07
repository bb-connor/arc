use super::{
    decode_response_record, Arc, BTreeMap, BTreeSet, BlastRadiusPort, CanonicalBody,
    CapabilitySetSuspensionBackend, CapabilitySetSuspensionStore, Clock, ContainmentOverlayStore,
    Digest32, EffectExecutionStatus, EffectId, EffectOperation, EffectPort, EffectRequest,
    EffectResult, EffectResultQuery, EgressRestrictionStore, EscalateAlertBackend,
    EscalateAlertStore, IssuanceFreezeBackend, IssuanceFreezeStore, LineageFence,
    LineageFenceMaintenanceOutcome, LineageFenceMaintenanceRequest, MaintainedLineageFence,
    PortError, PortResult, RecordId, ResponseEffectKind, ResponsePlanKey, ResponseSchedulerStore,
    ResponseSnapshot, ResponseTarget, RestrictEgressOverlayBackend,
    SessionSuspensionOverlayBackend, SessionThrottleBackend, SessionThrottleStore,
    SqliteSecurityStateStore, SqliteSiemOutbox, SystemClock, TenantId, EFFECT_COMMAND_ID_PREFIX,
    LINEAGE_FENCE_MAX_LEASE_MS,
};

pub(super) const REQUIRED_EFFECT_KINDS: [ResponseEffectKind; 6] = [
    ResponseEffectKind::EscalateAlert,
    ResponseEffectKind::ThrottleSession,
    ResponseEffectKind::RestrictEgress,
    ResponseEffectKind::SuspendSession,
    ResponseEffectKind::SuspendCapabilitySet,
    ResponseEffectKind::FreezeIssuance,
];

/// One semantically exact external backend for a closed response-effect kind.
///
/// The router owns request validation and replay routing. A backend must expose
/// only the effect kind whose external semantics it actually implements.
pub trait ResponseEffectBackend: Send + Sync {
    fn effect_kind(&self) -> ResponseEffectKind;
    fn ensure_ready(&self) -> PortResult<()>;
    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult>;
    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus>;
    fn maintain_lineage_fence(
        &self,
        _effect: &chio_security_types::PlannedResponseEffect,
        _request: &LineageFenceMaintenanceRequest,
    ) -> PortResult<LineageFenceMaintenanceResult> {
        Err(PortError::unavailable())
    }
}

/// Exact result of maintaining one selected issuance freeze.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageFenceMaintenanceResult {
    Maintained(LineageFence),
    ReleaseCompleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveResponseEffectPortConfigError {
    DuplicateBackend(ResponseEffectKind),
}

impl std::fmt::Display for ActiveResponseEffectPortConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateBackend(kind) => {
                write!(formatter, "duplicate active-response backend for {kind:?}")
            }
        }
    }
}

impl std::error::Error for ActiveResponseEffectPortConfigError {}

/// Fail-closed production router for active-response effects.
///
/// Readiness succeeds only when all six closed protocol effects have distinct,
/// healthy backends and the router holds the durable response-plan authority.
/// With that authority every command and result query is bound to the exact
/// effect of its durable plan before it reaches a backend. The production tree
/// has exact backends for all six closed kinds, including the commit-indexed
/// issuance fence. A partial or unbound router cannot advertise global
/// readiness. Additional backends can be injected without changing the effect
/// request, idempotency key, target, or version commitments.
pub struct ActiveResponseEffectPort {
    backends: BTreeMap<ResponseEffectKind, Arc<dyn ResponseEffectBackend>>,
    plan_authority: Option<Arc<dyn ResponseSchedulerStore>>,
}

impl ActiveResponseEffectPort {
    /// Construct the complete production router from durable native
    /// authorities and preflight all six closed effect kinds, reading time
    /// from the host wall clock.
    pub fn production(
        security_store: Arc<SqliteSecurityStateStore>,
        alert_outbox: Arc<SqliteSiemOutbox>,
        blast_radius: Arc<dyn BlastRadiusPort>,
    ) -> PortResult<Self> {
        Self::production_with_clock(
            security_store,
            alert_outbox,
            blast_radius,
            Arc::new(SystemClock),
        )
    }

    /// Construct the complete production router from durable native
    /// authorities with the host's trusted clock and preflight all six
    /// closed effect kinds. The clock judges issuance fence lease windows and
    /// stamps escalation alerts.
    pub fn production_with_clock(
        security_store: Arc<SqliteSecurityStateStore>,
        alert_outbox: Arc<SqliteSiemOutbox>,
        blast_radius: Arc<dyn BlastRadiusPort>,
        clock: Arc<dyn Clock>,
    ) -> PortResult<Self> {
        let alert_store: Arc<dyn EscalateAlertStore> = alert_outbox.clone();
        let throttle_store: Arc<dyn SessionThrottleStore> = security_store.clone();
        let egress_store: Arc<dyn EgressRestrictionStore> = security_store.clone();
        let session_suspension_store: Arc<dyn ContainmentOverlayStore> = security_store.clone();
        let capability_suspension_store: Arc<dyn CapabilitySetSuspensionStore> =
            security_store.clone();
        let issuance_freeze_store: Arc<dyn IssuanceFreezeStore> = security_store.clone();
        let scheduler_store: Arc<dyn ResponseSchedulerStore> = security_store.clone();
        let backends: Vec<Arc<dyn ResponseEffectBackend>> = vec![
            Arc::new(EscalateAlertBackend::with_clock(
                alert_store,
                Arc::clone(&clock),
            )),
            Arc::new(SessionThrottleBackend::new(throttle_store)),
            Arc::new(RestrictEgressOverlayBackend::new(egress_store)),
            Arc::new(SessionSuspensionOverlayBackend::new(
                session_suspension_store,
            )),
            Arc::new(CapabilitySetSuspensionBackend::new(
                capability_suspension_store,
            )),
            Arc::new(
                IssuanceFreezeBackend::new_with_scheduler(
                    issuance_freeze_store,
                    blast_radius,
                    Arc::clone(&scheduler_store),
                )
                .with_clock(clock),
            ),
        ];
        let router = Self::from_backends(backends)
            .map_err(|_| PortError::invalid_data())?
            .with_plan_authority(scheduler_store);
        router.ensure_effects_ready()?;
        Ok(router)
    }

    pub fn from_backends(
        backends: impl IntoIterator<Item = Arc<dyn ResponseEffectBackend>>,
    ) -> Result<Self, ActiveResponseEffectPortConfigError> {
        let mut configured = BTreeMap::new();
        for backend in backends {
            let kind = backend.effect_kind();
            if configured.insert(kind, backend).is_some() {
                return Err(ActiveResponseEffectPortConfigError::DuplicateBackend(kind));
            }
        }
        Ok(Self {
            backends: configured,
            plan_authority: None,
        })
    }

    /// Bind every command and result query to the durable response plan.
    #[must_use]
    pub fn with_plan_authority(mut self, plan_authority: Arc<dyn ResponseSchedulerStore>) -> Self {
        self.plan_authority = Some(plan_authority);
        self
    }

    #[must_use]
    pub fn session_suspension_only(backend: Arc<SessionSuspensionOverlayBackend>) -> Self {
        let mut backends: BTreeMap<ResponseEffectKind, Arc<dyn ResponseEffectBackend>> =
            BTreeMap::new();
        backends.insert(ResponseEffectKind::SuspendSession, backend);
        Self {
            backends,
            plan_authority: None,
        }
    }

    fn backend(&self, kind: ResponseEffectKind) -> PortResult<&Arc<dyn ResponseEffectBackend>> {
        self.backends.get(&kind).ok_or_else(PortError::unavailable)
    }
}

impl EffectPort for ActiveResponseEffectPort {
    fn ensure_effects_ready(&self) -> PortResult<()> {
        for backend in self.backends.values() {
            backend.ensure_ready()?;
        }
        if REQUIRED_EFFECT_KINDS
            .iter()
            .any(|kind| !self.backends.contains_key(kind))
            || self.plan_authority.is_none()
        {
            return Err(PortError::unavailable());
        }
        Ok(())
    }

    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult> {
        validate_request_binding(
            &request.tenant_id,
            request.effect_kind,
            &request.target,
            request.plan_expires_at_unix_ms,
            request.scheduler_fencing_token,
            &request.idempotency_key,
        )?;
        if let Some(plan_authority) = &self.plan_authority {
            validate_durable_plan_binding(
                plan_authority.as_ref(),
                &DurablePlanBinding::from_request(request),
            )?;
        }
        self.backend(request.effect_kind)?.execute(request)
    }

    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        validate_request_binding(
            &query.tenant_id,
            query.effect_kind,
            &query.target,
            query.plan_expires_at_unix_ms,
            query.scheduler_fencing_token,
            &query.idempotency_key,
        )?;
        if let Some(plan_authority) = &self.plan_authority {
            validate_durable_plan_binding(
                plan_authority.as_ref(),
                &DurablePlanBinding::from_query(query),
            )?;
        }
        self.backend(query.effect_kind)?.load_result(query)
    }

    fn maintain_lineage_fences(
        &self,
        request: &LineageFenceMaintenanceRequest,
    ) -> PortResult<LineageFenceMaintenanceOutcome> {
        if request.plan.tenant_id != request.scheduler_work.tenant_id
            || request.plan.action_id != request.scheduler_work.action_id
            || request.effect_ids.is_empty()
            || request.scheduler_work.fencing_token == 0
            || request.observed_at_unix_ms < request.plan.created_at_unix_ms
            || request.renewed_expires_at_unix_ms <= request.observed_at_unix_ms
            || request
                .renewed_expires_at_unix_ms
                .saturating_sub(request.observed_at_unix_ms)
                > LINEAGE_FENCE_MAX_LEASE_MS
        {
            return Err(PortError::invalid_data());
        }
        let selected = request
            .effect_ids
            .iter()
            .map(EffectId::as_str)
            .collect::<BTreeSet<_>>();
        if selected.len() != request.effect_ids.len() {
            return Err(PortError::invalid_data());
        }
        let mut maintained = Vec::with_capacity(request.effect_ids.len());
        let mut completed_releases = Vec::new();
        for effect_id in &request.effect_ids {
            let effect = request
                .plan
                .effect(effect_id)
                .filter(|effect| effect.kind == ResponseEffectKind::FreezeIssuance)
                .ok_or_else(PortError::invalid_data)?;
            let result = self
                .backend(ResponseEffectKind::FreezeIssuance)?
                .maintain_lineage_fence(effect, request)?;
            match result {
                LineageFenceMaintenanceResult::Maintained(fence) => {
                    maintained.push(MaintainedLineageFence {
                        effect_id: effect.effect_id.clone(),
                        fence,
                    });
                }
                LineageFenceMaintenanceResult::ReleaseCompleted => {
                    completed_releases.push(effect.effect_id.clone());
                }
            }
        }
        Ok(LineageFenceMaintenanceOutcome {
            maintained,
            completed_releases,
        })
    }
}

pub(super) fn validate_request_binding(
    tenant_id: &TenantId,
    effect_kind: ResponseEffectKind,
    target: &ResponseTarget,
    plan_expires_at_unix_ms: u64,
    scheduler_fencing_token: u64,
    idempotency_key: &RecordId,
) -> PortResult<()> {
    if !effect_kind.accepts_target(target)
        || plan_expires_at_unix_ms == 0
        || scheduler_fencing_token == 0
        || !idempotency_key
            .as_str()
            .starts_with(EFFECT_COMMAND_ID_PREFIX)
    {
        return Err(PortError::invalid_data());
    }
    if let ResponseTarget::Tenant {
        tenant_id: target_tenant,
    } = target
    {
        if target_tenant != tenant_id {
            return Err(PortError::invalid_data());
        }
    }
    Ok(())
}

/// The commitments of one effect command or result query that must equal the
/// exact effect of its durable response plan.
pub(super) struct DurablePlanBinding<'a> {
    tenant_id: &'a TenantId,
    action_id: &'a chio_security_types::ports::ActionId,
    plan_hash: Digest32,
    plan_expires_at_unix_ms: u64,
    effect_id: &'a EffectId,
    effect_kind: ResponseEffectKind,
    target: &'a ResponseTarget,
    contribution_hash: Digest32,
    canonical_contribution: Option<&'a CanonicalBody>,
    apply_base_version_hash: Option<Digest32>,
}

impl<'a> DurablePlanBinding<'a> {
    pub(super) fn from_request(request: &'a EffectRequest) -> Self {
        Self {
            tenant_id: &request.tenant_id,
            action_id: &request.action_id,
            plan_hash: request.plan_hash,
            plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
            effect_id: &request.effect_id,
            effect_kind: request.effect_kind,
            target: &request.target,
            contribution_hash: request.contribution_hash,
            canonical_contribution: Some(&request.canonical_contribution),
            apply_base_version_hash: (request.operation == EffectOperation::Apply)
                .then_some(request.expected_version_hash),
        }
    }

    pub(super) fn from_query(query: &'a EffectResultQuery) -> Self {
        Self {
            tenant_id: &query.tenant_id,
            action_id: &query.action_id,
            plan_hash: query.plan_hash,
            plan_expires_at_unix_ms: query.plan_expires_at_unix_ms,
            effect_id: &query.effect_id,
            effect_kind: query.effect_kind,
            target: &query.target,
            contribution_hash: query.contribution_hash,
            canonical_contribution: None,
            apply_base_version_hash: (query.operation == EffectOperation::Apply)
                .then_some(query.expected_version_hash),
        }
    }
}

/// Load the durable response plan and require the bound command to name one
/// of its effects exactly. A missing plan or effect, or any differing
/// commitment, is an integrity failure.
pub(super) fn validate_durable_plan_binding(
    plan_authority: &dyn ResponseSchedulerStore,
    binding: &DurablePlanBinding<'_>,
) -> PortResult<ResponseSnapshot> {
    let record = plan_authority
        .load_plan(&ResponsePlanKey {
            tenant_id: binding.tenant_id.clone(),
            action_id: binding.action_id.clone(),
        })?
        .ok_or_else(PortError::integrity_failure)?;
    let snapshot = decode_response_record(&record).map_err(|_| PortError::integrity_failure())?;
    let planned_effect = snapshot
        .plan
        .effect(binding.effect_id)
        .ok_or_else(PortError::integrity_failure)?;
    if snapshot.plan.tenant_id != *binding.tenant_id
        || snapshot.plan.action_id != *binding.action_id
        || snapshot.plan.plan_hash != binding.plan_hash
        || snapshot.plan.expires_at_unix_ms != binding.plan_expires_at_unix_ms
        || planned_effect.kind != binding.effect_kind
        || planned_effect.target != *binding.target
        || planned_effect.contribution_hash != binding.contribution_hash
        || binding
            .canonical_contribution
            .is_some_and(|body| planned_effect.canonical_contribution != *body)
        || binding
            .apply_base_version_hash
            .is_some_and(|base| planned_effect.observed_base_version_hash != base)
    {
        return Err(PortError::integrity_failure());
    }
    Ok(snapshot)
}
