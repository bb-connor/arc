use super::*;


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
/// healthy backends. The production tree has exact backends for all six closed
/// kinds, including the commit-indexed issuance fence. A partial router cannot
/// advertise global readiness. Additional backends can be injected without
/// changing the effect request, idempotency key, target, or version
/// commitments.
pub struct ActiveResponseEffectPort {
    backends: BTreeMap<ResponseEffectKind, Arc<dyn ResponseEffectBackend>>,
}

impl ActiveResponseEffectPort {
    /// Construct the complete production router from durable native
    /// authorities and preflight all six closed effect kinds.
    pub fn production(
        security_store: Arc<SqliteSecurityStateStore>,
        alert_outbox: Arc<SqliteSiemOutbox>,
        blast_radius: Arc<dyn BlastRadiusPort>,
    ) -> PortResult<Self> {
        let alert_store: Arc<dyn EscalateAlertStore> = alert_outbox.clone();
        let throttle_store: Arc<dyn SessionThrottleStore> = security_store.clone();
        let egress_store: Arc<dyn EgressRestrictionStore> = security_store.clone();
        let session_suspension_store: Arc<dyn ContainmentOverlayStore> = security_store.clone();
        let capability_suspension_store: Arc<dyn CapabilitySetSuspensionStore> = security_store.clone();
        let issuance_freeze_store: Arc<dyn IssuanceFreezeStore> = security_store.clone();
        let scheduler_store: Arc<dyn ResponseSchedulerStore> = security_store.clone();
        let backends: Vec<Arc<dyn ResponseEffectBackend>> = vec![
            Arc::new(EscalateAlertBackend::new(alert_store)),
            Arc::new(SessionThrottleBackend::new(throttle_store)),
            Arc::new(RestrictEgressOverlayBackend::new(egress_store)),
            Arc::new(SessionSuspensionOverlayBackend::new(
                session_suspension_store,
            )),
            Arc::new(CapabilitySetSuspensionBackend::new(
                capability_suspension_store,
            )),
            Arc::new(IssuanceFreezeBackend::new_with_scheduler(
                issuance_freeze_store,
                blast_radius,
                scheduler_store,
            )),
        ];
        let router = Self::from_backends(backends).map_err(|_| PortError::invalid_data())?;
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
        })
    }

    #[must_use]
    pub fn session_suspension_only(backend: Arc<SessionSuspensionOverlayBackend>) -> Self {
        let mut backends: BTreeMap<ResponseEffectKind, Arc<dyn ResponseEffectBackend>> =
            BTreeMap::new();
        backends.insert(ResponseEffectKind::SuspendSession, backend);
        Self { backends }
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
