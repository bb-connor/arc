use super::Clock;
use super::SystemClock;
use super::Arc;
use super::AlertDeliveryQuery;
use super::AlertDeliveryStatus;
use super::CanonicalBody;
use super::Digest32;
use super::EffectExecutionStatus;
use super::EffectId;
use super::EffectOperation;
use super::EffectRequest;
use super::EffectResult;
use super::EffectResultQuery;
use super::PortError;
use super::PortResult;
use super::RecordId;
use super::SecurityAlert;
use super::SecurityAlertPort;
use super::TenantId;
use super::ResponseEffectKind;
use super::ResponseTarget;
use super::Serialize;
use super::SqliteSiemOutbox;
use super::ResponseEffectBackend;
use super::validate_request_binding;
use super::verify_contribution_hash;
use super::domain_hash;


pub(super) const ESCALATE_ALERT_SCHEMA_VERSION: u8 = 1;
pub(super) const ESCALATE_ALERT_TYPE: &str = "active_response_effect_escalation";
pub(super) const ESCALATE_ALERT_EVENT_DOMAIN: &[u8] = b"chio.response-effect-alert-event.v1\0";
pub(super) const ESCALATE_ALERT_COMMAND_DOMAIN: &[u8] = b"chio.response-effect-alert-command.v1\0";
pub(super) const ESCALATE_ALERT_FINDING_DOMAIN: &[u8] = b"chio.response-effect-alert-finding.v1\0";
pub(super) const ESCALATE_ALERT_ACTION_DOMAIN: &[u8] = b"chio.response-effect-alert-action.v1\0";
pub(super) const ESCALATE_ALERT_EVIDENCE_DOMAIN: &[u8] = b"chio.response-effect-alert-evidence.v1\0";
pub(super) const ESCALATE_ALERT_RESULT_DOMAIN: &[u8] = b"chio.response-effect-alert-result.v1\0";

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
pub(super) struct EscalateAlertCommitment<'a> {
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
    clock: Arc<dyn Clock>,
}

impl EscalateAlertBackend {
    #[must_use]
    pub fn new(alerts: Arc<dyn EscalateAlertStore>) -> Self {
        Self::with_clock(alerts, Arc::new(SystemClock))
    }

    pub fn with_clock(alerts: Arc<dyn EscalateAlertStore>, clock: Arc<dyn Clock>) -> Self {
        Self { alerts, clock }
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
        let alert = build_escalate_alert(commitment, self.clock.unix_millis()?.get())?;
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

pub(super) fn validate_escalate_alert_request(request: &EffectRequest) -> PortResult<()> {
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

pub(super) fn validate_escalate_alert_query(query: &EffectResultQuery) -> PortResult<()> {
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

pub(super) fn verify_canonical_json_contribution(body: &CanonicalBody, declared: Digest32) -> PortResult<()> {
    verify_contribution_hash(body, declared)?;
    let value: serde_json::Value =
        chio_core::canonical::UntrustedJsonText::from_wire(body.as_bytes(), 64 * 1024 * 1024).and_then(|input| input.decode_signed()).map_err(|error| PortError::with_source(chio_security_types::ports::PortErrorKind::InvalidData, error.code(), error))?;
    let canonical =
        chio_core::canonical_json_bytes(&value).map_err(|_| PortError::invalid_data())?;
    if canonical.as_slice() != body.as_bytes() {
        return Err(PortError::integrity_failure());
    }
    Ok(())
}

pub(super) fn build_escalate_alert(
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

pub(super) fn validate_escalate_alert(
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

pub(super) fn validate_alert_delivery_status(status: AlertDeliveryStatus) -> PortResult<()> {
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

pub(super) fn escalate_alert_result(commitment: &EscalateAlertCommitment<'_>) -> PortResult<EffectResult> {
    Ok(EffectResult {
        effect_id: EffectId::new(commitment.effect_id).map_err(PortError::from)?,
        resulting_version_hash: domain_hash(ESCALATE_ALERT_RESULT_DOMAIN, commitment)?,
        applied: true,
    })
}

pub(super) fn escalate_alert_record_id(
    prefix: &str,
    domain: &[u8],
    commitment: &EscalateAlertCommitment<'_>,
) -> PortResult<RecordId> {
    let digest = domain_hash(domain, commitment)?;
    RecordId::new(format!("{prefix}:{}", hex::encode(digest.as_bytes()))).map_err(PortError::from)
}
