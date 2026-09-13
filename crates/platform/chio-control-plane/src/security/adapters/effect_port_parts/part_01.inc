use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_quarantine::decode_response_record;
use chio_security_types::ports::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    containment_installed_version_hash, containment_overlay_version_hash,
    containment_session_target, empty_capability_set_suspension_snapshot,
    empty_issuance_freeze_snapshot, empty_session_throttle_snapshot,
    issuance_freeze_installed_version_hash, issuance_freeze_version_hash,
    predict_capability_set_suspension_apply, predict_capability_set_suspension_remove,
    predict_containment_overlay_apply, predict_containment_overlay_remove,
    predict_issuance_freeze_apply, predict_issuance_freeze_remove, predict_session_throttle_apply,
    predict_session_throttle_remove, response_affected_set_hash,
    session_throttle_installed_version_hash, session_throttle_version_hash,
    validate_capability_set_suspension_snapshot, validate_containment_overlay_snapshot,
    validate_issuance_freeze_contribution, validate_issuance_freeze_snapshot,
    validate_session_throttle_snapshot, AlertDeliveryQuery, AlertDeliveryStatus, BlastRadiusPort,
    BlastRadiusResult, CanonicalBody, CapabilitySetSuspensionApplyRequest,
    CapabilitySetSuspensionCommand, CapabilitySetSuspensionContribution,
    CapabilitySetSuspensionKey, CapabilitySetSuspensionRemoveRequest,
    CapabilitySetSuspensionSnapshot, CapabilitySetSuspensionSpec, CapabilitySetSuspensionStore,
    ContainmentOverlayCommand, ContainmentOverlayStore, Digest32, EffectExecutionStatus, EffectId,
    EffectOperation, EffectPort, EffectRequest, EffectResult, EffectResultQuery,
    EgressDeniedDestinations, EgressDestinationSet, EgressRestrictionApplyRequest,
    EgressRestrictionCommand, EgressRestrictionContribution, EgressRestrictionContributions,
    EgressRestrictionRemoveRequest, EgressRestrictionSessionKey, EgressRestrictionSnapshot,
    EgressRestrictionStore, IssuanceFreezeApplyRequest, IssuanceFreezeCommand,
    IssuanceFreezeContribution, IssuanceFreezeFenceMaintenanceRequest, IssuanceFreezeKey,
    IssuanceFreezeOperationStatus, IssuanceFreezePendingRelease, IssuanceFreezeRemoveRequest,
    IssuanceFreezeSnapshot, IssuanceFreezeSpec, IssuanceFreezeStore, LineageFence,
    LineageFenceMaintenanceOutcome, LineageFenceMaintenanceRequest, LineageFenceRelease,
    LineageFenceRenewal, LineageFenceRequest, LineageFenceTakeover, MaintainedLineageFence,
    OverlayApplyRequest, OverlayContribution, OverlayRemoveRequest, OverlaySnapshot, PortError,
    PortResult, RecordId, ResponsePlanKey, ResponseSchedulerStore, ScheduledWork, SecurityAlert,
    SecurityAlertPort, SessionId, SessionThrottleApplyRequest, SessionThrottleCommand,
    SessionThrottleContribution, SessionThrottleKey, SessionThrottleLimits,
    SessionThrottleRemoveRequest, SessionThrottleSnapshot, SessionThrottleStore, TenantId,
    TenantScopedId, LINEAGE_FENCE_MAX_LEASE_MS,
};
use chio_security_types::{
    ResponseEffectKind, ResponseEffectProgress, ResponseSnapshot, ResponseState, ResponseTarget,
};
use chio_store_sqlite::security_state::SqliteSecurityStateStore;
use serde::{Deserialize, Serialize};

use super::native_evidence::SqliteSiemOutbox;

const EGRESS_VERSION_DOMAIN: &[u8] = b"chio.response-effect-egress-state.v1\0";
const INSTALLED_EGRESS_CONTRIBUTION_DOMAIN: &[u8] =
    b"chio.response-effect-egress-contribution.v1\0";
const EFFECT_COMMAND_ID_PREFIX: &str = "response_effect_command:";
const ESCALATE_ALERT_SCHEMA_VERSION: u8 = 1;
const ESCALATE_ALERT_TYPE: &str = "active_response_effect_escalation";
const ESCALATE_ALERT_EVENT_DOMAIN: &[u8] = b"chio.response-effect-alert-event.v1\0";
const ESCALATE_ALERT_COMMAND_DOMAIN: &[u8] = b"chio.response-effect-alert-command.v1\0";
const ESCALATE_ALERT_FINDING_DOMAIN: &[u8] = b"chio.response-effect-alert-finding.v1\0";
const ESCALATE_ALERT_ACTION_DOMAIN: &[u8] = b"chio.response-effect-alert-action.v1\0";
const ESCALATE_ALERT_EVIDENCE_DOMAIN: &[u8] = b"chio.response-effect-alert-evidence.v1\0";
const ESCALATE_ALERT_RESULT_DOMAIN: &[u8] = b"chio.response-effect-alert-result.v1\0";

const REQUIRED_EFFECT_KINDS: [ResponseEffectKind; 6] = [
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
        let alert_store = Arc::clone(&alert_outbox) as Arc<dyn EscalateAlertStore>;
        let throttle_store = Arc::clone(&security_store) as Arc<dyn SessionThrottleStore>;
        let egress_store = Arc::clone(&security_store) as Arc<dyn EgressRestrictionStore>;
        let session_suspension_store =
            Arc::clone(&security_store) as Arc<dyn ContainmentOverlayStore>;
        let capability_suspension_store =
            Arc::clone(&security_store) as Arc<dyn CapabilitySetSuspensionStore>;
        let issuance_freeze_store = Arc::clone(&security_store) as Arc<dyn IssuanceFreezeStore>;
        let scheduler_store = Arc::clone(&security_store) as Arc<dyn ResponseSchedulerStore>;
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

fn validate_request_binding(
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

/// Alert outbox contract needed for exact effect reconciliation after restart.
///
/// `SecurityAlertPort::load_delivery` remains the exact read-after-write query.
/// This extension recovers the canonical first-attempt alert, whose occurrence
/// time is not present in `EffectResultQuery`.
pub trait EscalateAlertStore: SecurityAlertPort {
    fn load_persisted_alert(
        &self,
        tenant_id: &TenantId,
        idempotency_key: &RecordId,
    ) -> PortResult<Option<(SecurityAlert, AlertDeliveryStatus)>>;
}

impl EscalateAlertStore for SqliteSiemOutbox {
    fn load_persisted_alert(
        &self,
        tenant_id: &TenantId,
        idempotency_key: &RecordId,
    ) -> PortResult<Option<(SecurityAlert, AlertDeliveryStatus)>> {
        self.load_persisted_alert_command(tenant_id, idempotency_key)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EscalateAlertCommitment<'a> {
    schema_version: u8,
    tenant_id: &'a str,
    action_id: &'a str,
    plan_hash: Digest32,
    effect_id: &'a str,
    contribution_hash: Digest32,
    scheduler_fencing_token: u64,
}

impl<'a> EscalateAlertCommitment<'a> {
    fn from_request(request: &'a EffectRequest) -> Self {
        Self {
            schema_version: ESCALATE_ALERT_SCHEMA_VERSION,
            tenant_id: request.tenant_id.as_str(),
            action_id: request.action_id.as_str(),
            plan_hash: request.plan_hash,
            effect_id: request.effect_id.as_str(),
            contribution_hash: request.contribution_hash,
            scheduler_fencing_token: request.scheduler_fencing_token,
        }
    }

    fn from_query(query: &'a EffectResultQuery) -> Self {
        Self {
            schema_version: ESCALATE_ALERT_SCHEMA_VERSION,
            tenant_id: query.tenant_id.as_str(),
            action_id: query.action_id.as_str(),
            plan_hash: query.plan_hash,
            effect_id: query.effect_id.as_str(),
            contribution_hash: query.contribution_hash,
            scheduler_fencing_token: query.scheduler_fencing_token,
        }
    }
}

/// Durable exact backend for observational `EscalateAlert` effects.
pub struct EscalateAlertBackend {
    alerts: Arc<dyn EscalateAlertStore>,
}

impl EscalateAlertBackend {
    #[must_use]
    pub fn new(alerts: Arc<dyn EscalateAlertStore>) -> Self {
        Self { alerts }
    }

    fn load_persisted(
        &self,
        commitment: &EscalateAlertCommitment<'_>,
    ) -> PortResult<Option<(SecurityAlert, AlertDeliveryStatus, EffectResult)>> {
        let idempotency_key = escalate_alert_record_id(
            "active_response_alert_command",
            ESCALATE_ALERT_COMMAND_DOMAIN,
            commitment,
        )?;
        let Some((alert, status)) = self.alerts.load_persisted_alert(
            &TenantId::new(commitment.tenant_id).map_err(PortError::from)?,
            &idempotency_key,
        )?
        else {
            return Ok(None);
        };
        validate_escalate_alert(&alert, status, commitment)?;
        let exact = self.alerts.load_delivery(&AlertDeliveryQuery {
            alert: alert.clone(),
        })?;
        if exact != Some(status) {
            return Err(PortError::integrity_failure());
        }
        Ok(Some((alert, status, escalate_alert_result(commitment)?)))
    }

    fn execute_apply(
        &self,
        request: &EffectRequest,
        commitment: &EscalateAlertCommitment<'_>,
    ) -> PortResult<EffectResult> {
        if let Some((_, _, result)) = self.load_persisted(commitment)? {
            return Ok(result);
        }
        let alert = build_escalate_alert(commitment, current_unix_ms()?)?;
        let observed = match self.alerts.page(&alert) {
            Ok(status) => status,
            Err(page_error) => {
                return match self.load_persisted(commitment)? {
                    Some((_, _, result)) => Ok(result),
                    None => Err(page_error),
                };
            }
        };
        validate_alert_delivery_status(observed)?;
        let Some((persisted_alert, persisted_status, result)) = self.load_persisted(commitment)?
        else {
            return Err(PortError::integrity_failure());
        };
        if persisted_alert != alert || persisted_status != observed {
            return Err(PortError::integrity_failure());
        }
        if result.effect_id != request.effect_id {
            return Err(PortError::integrity_failure());
        }
        Ok(result)
    }
}

impl ResponseEffectBackend for EscalateAlertBackend {
    fn effect_kind(&self) -> ResponseEffectKind {
        ResponseEffectKind::EscalateAlert
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.alerts.ensure_alerts_ready()?;
        let readiness_tenant =
            TenantId::new("chio-alert-effect-readiness").map_err(PortError::from)?;
        let readiness_key =
            RecordId::new("active_response_alert_readiness_probe").map_err(PortError::from)?;
        if self
            .alerts
            .load_persisted_alert(&readiness_tenant, &readiness_key)?
            .is_some()
        {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult> {
        validate_escalate_alert_request(request)?;
        verify_canonical_json_contribution(
            &request.canonical_contribution,
            request.contribution_hash,
        )?;
        let commitment = EscalateAlertCommitment::from_request(request);
        self.execute_apply(request, &commitment)
    }

    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        validate_escalate_alert_query(query)?;
        let commitment = EscalateAlertCommitment::from_query(query);
        match self.load_persisted(&commitment)? {
            Some((_, _, result)) => Ok(EffectExecutionStatus::Completed { result }),
            None => Ok(EffectExecutionStatus::NotExecuted),
        }
    }
}

fn validate_escalate_alert_request(request: &EffectRequest) -> PortResult<()> {
    validate_request_binding(
        &request.tenant_id,
        request.effect_kind,
        &request.target,
        request.plan_expires_at_unix_ms,
        request.scheduler_fencing_token,
        &request.idempotency_key,
    )?;
    if request.effect_kind != ResponseEffectKind::EscalateAlert
        || request.operation != EffectOperation::Apply
        || !matches!(
            &request.target,
            ResponseTarget::Tenant { tenant_id } if tenant_id == &request.tenant_id
        )
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn validate_escalate_alert_query(query: &EffectResultQuery) -> PortResult<()> {
    validate_request_binding(
        &query.tenant_id,
        query.effect_kind,
        &query.target,
        query.plan_expires_at_unix_ms,
        query.scheduler_fencing_token,
        &query.idempotency_key,
    )?;
    if query.effect_kind != ResponseEffectKind::EscalateAlert
        || query.operation != EffectOperation::Apply
        || !matches!(
            &query.target,
            ResponseTarget::Tenant { tenant_id } if tenant_id == &query.tenant_id
        )
    {
        return Err(PortError::invalid_data());
    }
    Ok(())
}

fn verify_canonical_json_contribution(body: &CanonicalBody, declared: Digest32) -> PortResult<()> {
    verify_contribution_hash(body, declared)?;
    let value: serde_json::Value =
        serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
    let canonical =
        chio_core::canonical_json_bytes(&value).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn build_escalate_alert(
    commitment: &EscalateAlertCommitment<'_>,
    occurred_at_unix_ms: u64,
) -> PortResult<SecurityAlert> {
    if occurred_at_unix_ms == 0 {
        return Err(PortError::integrity_failure());
    }
    Ok(SecurityAlert {
        tenant_id: TenantId::new(commitment.tenant_id).map_err(PortError::from)?,
        event_id: escalate_alert_record_id(
            "active_response_alert_event",
            ESCALATE_ALERT_EVENT_DOMAIN,
            commitment,
        )?,
        idempotency_key: escalate_alert_record_id(
            "active_response_alert_command",
            ESCALATE_ALERT_COMMAND_DOMAIN,
            commitment,
        )?,
        occurred_at_unix_ms,
        alert_type: RecordId::new(ESCALATE_ALERT_TYPE).map_err(PortError::from)?,
        finding_id_hash: domain_hash(ESCALATE_ALERT_FINDING_DOMAIN, commitment)?,
        action_id_hash: Some(domain_hash(ESCALATE_ALERT_ACTION_DOMAIN, commitment)?),
        evidence_hash: domain_hash(ESCALATE_ALERT_EVIDENCE_DOMAIN, commitment)?,
    })
}

fn validate_escalate_alert(
    alert: &SecurityAlert,
    status: AlertDeliveryStatus,
    commitment: &EscalateAlertCommitment<'_>,
) -> PortResult<()> {
    validate_alert_delivery_status(status)?;
    let expected = build_escalate_alert(commitment, alert.occurred_at_unix_ms)?;
    if alert != &expected {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn validate_alert_delivery_status(status: AlertDeliveryStatus) -> PortResult<()> {
    let valid = match status {
        AlertDeliveryStatus::Pending {
            next_attempt_at_unix_ms,
            ..
        } => next_attempt_at_unix_ms != 0,
        AlertDeliveryStatus::Delivered {
            attempts,
            delivered_at_unix_ms,
        } => attempts != 0 && delivered_at_unix_ms != 0,
    };
    if !valid {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

fn escalate_alert_result(commitment: &EscalateAlertCommitment<'_>) -> PortResult<EffectResult> {
    Ok(EffectResult {
        effect_id: EffectId::new(commitment.effect_id).map_err(PortError::from)?,
        resulting_version_hash: domain_hash(ESCALATE_ALERT_RESULT_DOMAIN, commitment)?,
        applied: true,
    })
}

fn escalate_alert_record_id(
    prefix: &str,
    domain: &[u8],
    commitment: &EscalateAlertCommitment<'_>,
) -> PortResult<RecordId> {
    let digest = domain_hash(domain, commitment)?;
    RecordId::new(format!("{prefix}:{}", hex::encode(digest.as_bytes()))).map_err(PortError::from)
}

fn current_unix_ms() -> PortResult<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PortError::unavailable())?;
    let millis = u64::try_from(elapsed.as_millis()).map_err(|_| PortError::unavailable())?;
    if millis == 0 {
        return Err(PortError::unavailable());
    }
    Ok(millis)
}

/// Exact `ThrottleSession` backend backed by independent durable windows.
///
/// Each effect contributes its own `(window_ms, max_invocations)` constraint.
/// The enforcement store evaluates their conjunction and never rounds multiple
/// contributions into one weaker scalar rate.
pub struct SessionThrottleBackend {
    throttles: Arc<dyn SessionThrottleStore>,
}

impl SessionThrottleBackend {
    #[must_use]
    pub fn new(throttles: Arc<dyn SessionThrottleStore>) -> Self {
        Self { throttles }
    }

    fn key(&self, tenant_id: &TenantId, target: &ResponseTarget) -> PortResult<SessionThrottleKey> {
        let ResponseTarget::Session { session_id } = target else {
            return Err(PortError::invalid_data());
        };
        Ok(SessionThrottleKey {
            tenant_id: tenant_id.clone(),
            session_id: session_id.clone(),
        })
    }

    fn load_snapshot(&self, key: &SessionThrottleKey) -> PortResult<SessionThrottleSnapshot> {
        match self.throttles.load_session_throttles(key)? {
            Some(snapshot) => {
                validate_session_throttle_snapshot(&snapshot, key)?;
                Ok(snapshot)
            }
            None => empty_session_throttle_snapshot(key.clone()),
        }
    }

    fn reconcile_result(&self, request: &EffectRequest) -> PortResult<Option<EffectResult>> {
        match self
            .throttles
            .load_session_throttle_result(&effect_query_from_request(request))?
        {
            EffectExecutionStatus::Completed { result } => {
                if !valid_throttle_effect_result(request.operation, &request.effect_id, &result) {
                    return Err(PortError::integrity_failure());
                }
                Ok(Some(result))
            }
            EffectExecutionStatus::NotExecuted => Ok(None),
            EffectExecutionStatus::Failed { .. } | EffectExecutionStatus::Unknown => {
                Err(PortError::integrity_failure())
            }
        }
    }

    fn verify_committed(
        &self,
        request: &EffectRequest,
        key: &SessionThrottleKey,
        predicted: &SessionThrottleSnapshot,
        result: &EffectResult,
    ) -> PortResult<()> {
        let stored = self
            .throttles
            .load_session_throttles(key)?
            .ok_or_else(PortError::integrity_failure)?;
        validate_session_throttle_snapshot(&stored, key)?;
        if &stored != predicted || self.reconcile_result(request)?.as_ref() != Some(result) {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn execute_apply(
        &self,
        request: &EffectRequest,
        key: SessionThrottleKey,
        limits: SessionThrottleLimits,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let desired = SessionThrottleContribution {
            effect_id: request.effect_id.clone(),
            limits,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        if let Some(existing) = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
        {
            if existing != &desired {
                return Err(PortError::conflict());
            }
        } else if session_throttle_version_hash(&current)? != request.expected_version_hash {
            return Err(PortError::conflict());
        }
        let predicted =
            predict_session_throttle_apply(&current, &desired, request.scheduler_fencing_token)?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: session_throttle_installed_version_hash(&key, &desired)?,
            applied: true,
        };
        let applied = match self
            .throttles
            .apply_session_throttle(&SessionThrottleApplyRequest {
                key: key.clone(),
                action_id: request.action_id.clone(),
                contribution: desired,
                expected_generation: current.generation,
                scheduler_fencing_token: request.scheduler_fencing_token,
                command: SessionThrottleCommand {
                    request: request.clone(),
                    result: result.clone(),
                    resulting_snapshot: predicted.clone(),
                },
            }) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return match self.reconcile_result(request)? {
                    Some(stored) if stored == result => {
                        self.verify_committed(request, &key, &predicted, &stored)?;
                        Ok(stored)
                    }
                    Some(_) => Err(PortError::integrity_failure()),
                    None => Err(error),
                };
            }
        };
        validate_session_throttle_snapshot(&applied, &key)?;
        if applied != predicted {
            return Err(PortError::integrity_failure());
        }
        self.verify_committed(request, &key, &predicted, &result)?;
        Ok(result)
    }

    fn execute_remove(
        &self,
        request: &EffectRequest,
        key: SessionThrottleKey,
        limits: SessionThrottleLimits,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let desired = SessionThrottleContribution {
            effect_id: request.effect_id.clone(),
            limits,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        if session_throttle_installed_version_hash(&key, &desired)? != request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current
            .contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.effect_id)
        {
            if existing != &desired {
                return Err(PortError::conflict());
            }
        }
        let predicted = predict_session_throttle_remove(
            &current,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: session_throttle_version_hash(&predicted)?,
            applied: false,
        };
        let removed = match self
            .throttles
            .remove_session_throttle(&SessionThrottleRemoveRequest {
                key: key.clone(),
                action_id: request.action_id.clone(),
                effect_id: request.effect_id.clone(),
                expected_generation: current.generation,
                scheduler_fencing_token: request.scheduler_fencing_token,
                command: SessionThrottleCommand {
                    request: request.clone(),
                    result: result.clone(),
                    resulting_snapshot: predicted.clone(),
                },
            }) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return match self.reconcile_result(request)? {
                    Some(stored) if stored == result => {
                        self.verify_committed(request, &key, &predicted, &stored)?;
                        Ok(stored)
                    }
                    Some(_) => Err(PortError::integrity_failure()),
                    None => Err(error),
                };
            }
        };
        validate_session_throttle_snapshot(&removed, &key)?;
        if removed != predicted {
            return Err(PortError::integrity_failure());
        }
        self.verify_committed(request, &key, &predicted, &result)?;
        Ok(result)
    }
}

impl ResponseEffectBackend for SessionThrottleBackend {
    fn effect_kind(&self) -> ResponseEffectKind {
        ResponseEffectKind::ThrottleSession
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.throttles.ensure_session_throttles_ready()
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
        if request.effect_kind != ResponseEffectKind::ThrottleSession {
            return Err(PortError::invalid_data());
        }
        verify_contribution_hash(&request.canonical_contribution, request.contribution_hash)?;
        let limits = decode_session_throttle_limits(&request.canonical_contribution)?;
        let key = self.key(&request.tenant_id, &request.target)?;
        if let Some(result) = self.reconcile_result(request)? {
            return Ok(result);
        }
        match request.operation {
            EffectOperation::Apply => self.execute_apply(request, key, limits),
            EffectOperation::Remove => self.execute_remove(request, key, limits),
        }
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
        if query.effect_kind != ResponseEffectKind::ThrottleSession {
            return Err(PortError::invalid_data());
        }
        self.key(&query.tenant_id, &query.target)?;
        let status = self.throttles.load_session_throttle_result(query)?;
        match &status {
            EffectExecutionStatus::Completed { result }
                if !valid_throttle_effect_result(query.operation, &query.effect_id, result) =>
            {
                return Err(PortError::integrity_failure());
            }
            EffectExecutionStatus::Failed { .. } | EffectExecutionStatus::Unknown => {
                return Err(PortError::integrity_failure());
            }
            EffectExecutionStatus::NotExecuted | EffectExecutionStatus::Completed { .. } => {}
        }
        Ok(status)
    }
}

fn decode_session_throttle_limits(body: &CanonicalBody) -> PortResult<SessionThrottleLimits> {
    let limits: SessionThrottleLimits =
        serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
    limits.validate()?;
    let canonical =
        chio_core::canonical_json_bytes(&limits).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(limits)
}

/// Exact `SuspendCapabilitySet` backend backed by immutable affected sets.
///
/// Every contribution carries the complete sorted set committed by the target
/// hash. Overlapping actions compose as a union at enforcement time, while a
/// remove deletes only the matching action and effect contribution.
pub struct CapabilitySetSuspensionBackend {
    suspensions: Arc<dyn CapabilitySetSuspensionStore>,
}

impl CapabilitySetSuspensionBackend {
    #[must_use]
    pub fn new(suspensions: Arc<dyn CapabilitySetSuspensionStore>) -> Self {
        Self { suspensions }
    }

    fn key(
        &self,
        tenant_id: &TenantId,
        target: &ResponseTarget,
    ) -> PortResult<CapabilitySetSuspensionKey> {
        let ResponseTarget::CapabilitySet { affected_set_hash } = target else {
            return Err(PortError::invalid_data());
        };
        Ok(CapabilitySetSuspensionKey {
            tenant_id: tenant_id.clone(),
            affected_set_hash: *affected_set_hash,
        })
    }

    fn load_snapshot(
        &self,
        key: &CapabilitySetSuspensionKey,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        match self.suspensions.load_capability_set_suspensions(key)? {
            Some(snapshot) => {
                validate_capability_set_suspension_snapshot(&snapshot, key)?;
                Ok(snapshot)
            }
            None => empty_capability_set_suspension_snapshot(key.clone()),
        }
    }

    fn reconcile_result(&self, request: &EffectRequest) -> PortResult<Option<EffectResult>> {
        match self
            .suspensions
            .load_capability_set_suspension_result(&effect_query_from_request(request))?
        {
            EffectExecutionStatus::Completed { result } => {
                if !valid_capability_set_suspension_result(
                    request.operation,
                    &request.effect_id,
                    &result,
                ) {
                    return Err(PortError::integrity_failure());
                }
                Ok(Some(result))
            }
            EffectExecutionStatus::NotExecuted => Ok(None),
            EffectExecutionStatus::Failed { .. } | EffectExecutionStatus::Unknown => {
                Err(PortError::integrity_failure())
            }
        }
    }

    fn verify_committed(
        &self,
        request: &EffectRequest,
        key: &CapabilitySetSuspensionKey,
        predicted: &CapabilitySetSuspensionSnapshot,
        result: &EffectResult,
    ) -> PortResult<()> {
        let stored = self
            .suspensions
            .load_capability_set_suspensions(key)?
            .ok_or_else(PortError::integrity_failure)?;
        validate_capability_set_suspension_snapshot(&stored, key)?;
        if &stored != predicted || self.reconcile_result(request)?.as_ref() != Some(result) {
            return Err(PortError::integrity_failure());
        }
        Ok(())
    }

    fn execute_apply(
        &self,
        request: &EffectRequest,
        key: CapabilitySetSuspensionKey,
        spec: CapabilitySetSuspensionSpec,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let contribution = CapabilitySetSuspensionContribution {
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            affected_ids: spec.affected_ids,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        if let Some(existing) = current.contributions.as_slice().iter().find(|entry| {
            entry.action_id == request.action_id && entry.effect_id == request.effect_id
        }) {
            if existing != &contribution {
                return Err(PortError::conflict());
            }
        } else if capability_set_suspension_version_hash(&current)? != request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        let predicted = predict_capability_set_suspension_apply(
            &current,
            &contribution,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: capability_set_suspension_installed_version_hash(
                &key,
                &contribution,
            )?,
            applied: true,
        };
        let applied = match self.suspensions.apply_capability_set_suspension(
            &CapabilitySetSuspensionApplyRequest {
                key: key.clone(),
                contribution,
                expected_generation: current.generation,
                scheduler_fencing_token: request.scheduler_fencing_token,
                command: CapabilitySetSuspensionCommand {
                    request: request.clone(),
                    result: result.clone(),
                    resulting_snapshot: predicted.clone(),
                },
            },
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return match self.reconcile_result(request)? {
                    Some(stored) if stored == result => {
                        self.verify_committed(request, &key, &predicted, &stored)?;
                        Ok(stored)
                    }
                    Some(_) => Err(PortError::integrity_failure()),
                    None => Err(error),
                };
            }
        };
        validate_capability_set_suspension_snapshot(&applied, &key)?;
        if applied != predicted {
            return Err(PortError::integrity_failure());
        }
        self.verify_committed(request, &key, &predicted, &result)?;
        Ok(result)
    }

    fn execute_remove(
        &self,
        request: &EffectRequest,
        key: CapabilitySetSuspensionKey,
        spec: CapabilitySetSuspensionSpec,
    ) -> PortResult<EffectResult> {
        let current = self.load_snapshot(&key)?;
        let contribution = CapabilitySetSuspensionContribution {
            action_id: request.action_id.clone(),
            effect_id: request.effect_id.clone(),
            affected_ids: spec.affected_ids,
            contribution_hash: request.contribution_hash,
            expires_at_unix_ms: request.plan_expires_at_unix_ms,
        };
        if capability_set_suspension_installed_version_hash(&key, &contribution)?
            != request.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        if let Some(existing) = current.contributions.as_slice().iter().find(|entry| {
            entry.action_id == request.action_id && entry.effect_id == request.effect_id
        }) {
            if existing != &contribution {
                return Err(PortError::conflict());
            }
        }
        let predicted = predict_capability_set_suspension_remove(
            &current,
            &request.action_id,
            &request.effect_id,
            request.scheduler_fencing_token,
        )?;
        let result = EffectResult {
            effect_id: request.effect_id.clone(),
            resulting_version_hash: capability_set_suspension_version_hash(&predicted)?,
            applied: false,
        };
        let removed = match self.suspensions.remove_capability_set_suspension(
            &CapabilitySetSuspensionRemoveRequest {
                key: key.clone(),
                action_id: request.action_id.clone(),
                effect_id: request.effect_id.clone(),
                expected_generation: current.generation,
                scheduler_fencing_token: request.scheduler_fencing_token,
                command: CapabilitySetSuspensionCommand {
                    request: request.clone(),
                    result: result.clone(),
                    resulting_snapshot: predicted.clone(),
                },
            },
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return match self.reconcile_result(request)? {
                    Some(stored) if stored == result => {
                        self.verify_committed(request, &key, &predicted, &stored)?;
                        Ok(stored)
                    }
                    Some(_) => Err(PortError::integrity_failure()),
                    None => Err(error),
                };
            }
        };
        validate_capability_set_suspension_snapshot(&removed, &key)?;
        if removed != predicted {
            return Err(PortError::integrity_failure());
        }
        self.verify_committed(request, &key, &predicted, &result)?;
        Ok(result)
    }
}

impl ResponseEffectBackend for CapabilitySetSuspensionBackend {
    fn effect_kind(&self) -> ResponseEffectKind {
        ResponseEffectKind::SuspendCapabilitySet
    }

    fn ensure_ready(&self) -> PortResult<()> {
        self.suspensions.ensure_capability_set_suspensions_ready()
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
        if request.effect_kind != ResponseEffectKind::SuspendCapabilitySet {
            return Err(PortError::invalid_data());
        }
        verify_contribution_hash(&request.canonical_contribution, request.contribution_hash)?;
        let spec = decode_capability_set_suspension_spec(&request.canonical_contribution)?;
        let key = self.key(&request.tenant_id, &request.target)?;
        if response_affected_set_hash(&request.tenant_id, &spec.affected_ids)?
            != key.affected_set_hash
        {
            return Err(PortError::invalid_data());
        }
        if let Some(result) = self.reconcile_result(request)? {
            return Ok(result);
        }
        match request.operation {
            EffectOperation::Apply => self.execute_apply(request, key, spec),
            EffectOperation::Remove => self.execute_remove(request, key, spec),
        }
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
        if query.effect_kind != ResponseEffectKind::SuspendCapabilitySet {
            return Err(PortError::invalid_data());
        }
        let key = self.key(&query.tenant_id, &query.target)?;
        let status = self
            .suspensions
            .load_capability_set_suspension_result(query)?;
        match &status {
            EffectExecutionStatus::Completed { result } => {
                if !valid_capability_set_suspension_result(
                    query.operation,
                    &query.effect_id,
                    result,
                ) {
                    return Err(PortError::integrity_failure());
                }
                if query.operation == EffectOperation::Apply {
                    let snapshot = self
                        .suspensions
                        .load_capability_set_suspensions(&key)?
                        .ok_or_else(PortError::integrity_failure)?;
                    validate_capability_set_suspension_snapshot(&snapshot, &key)?;
                    let contribution = snapshot
                        .contributions
                        .as_slice()
                        .iter()
                        .find(|entry| {
                            entry.action_id == query.action_id && entry.effect_id == query.effect_id
                        })
                        .ok_or_else(PortError::integrity_failure)?;
                    if contribution.contribution_hash != query.contribution_hash
                        || contribution.expires_at_unix_ms != query.plan_expires_at_unix_ms
                        || capability_set_suspension_installed_version_hash(&key, contribution)?
                            != result.resulting_version_hash
                    {
                        return Err(PortError::integrity_failure());
                    }
                }
            }
            EffectExecutionStatus::Failed { .. } | EffectExecutionStatus::Unknown => {
                return Err(PortError::integrity_failure());
            }
            EffectExecutionStatus::NotExecuted => {}
        }
        Ok(status)
    }
}

fn decode_capability_set_suspension_spec(
    body: &CanonicalBody,
) -> PortResult<CapabilitySetSuspensionSpec> {
    let spec: CapabilitySetSuspensionSpec =
        serde_json::from_slice(body.as_bytes()).map_err(|_| PortError::invalid_data())?;
    if spec.affected_ids.as_slice().is_empty() {
        return Err(PortError::invalid_data());
    }
    let canonical =
        chio_core::canonical_json_bytes(&spec).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(spec)
}

/// Exact `FreezeIssuance` backend over a commit-indexed causal fence.
///
/// The external fence blocks descendant issuance and delegation while the
/// local contribution provides the fail-closed admission authority. Removal
/// is journaled before releasing the external fence, then completed by
/// deleting only the matching action and effect contribution.
pub struct IssuanceFreezeBackend {
    freezes: Arc<dyn IssuanceFreezeStore>,
    blast_radius: Arc<dyn BlastRadiusPort>,
    scheduler: Option<Arc<dyn ResponseSchedulerStore>>,
}
