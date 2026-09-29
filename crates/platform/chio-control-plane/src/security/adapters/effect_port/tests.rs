use super::{
    egress_restriction_version_hash, session_containment_target, session_overlay_version_hash,
    ActiveResponseEffectPort, EscalateAlertBackend, EscalateAlertStore, ResponseEffectBackend,
    RestrictEgressOverlayBackend, SessionSuspensionOverlayBackend, SessionThrottleBackend,
};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_kernel::SecurityInvocationContextV1;
use chio_security_kernel::{containment_target, ContainmentTargetKind};
use chio_security_types::ports::{
    containment_installed_version_hash, containment_overlay_version_hash,
    empty_session_throttle_snapshot, session_throttle_version_hash, ActionId, AlertDeliveryQuery,
    AlertDeliveryStatus, CanonicalBody, ContainmentOverlayCommand, ContainmentOverlayStore,
    Digest32, EffectExecutionStatus, EffectId, EffectOperation, EffectPort, EffectRequest,
    EffectResultQuery, EgressRestrictionSessionKey, EgressRestrictionStore, IsolationEpochId,
    LeaseOwnerId, LineageId, OverlayApplyRequest, OverlayContribution, OverlayContributions,
    OverlayRemoveRequest, OverlaySnapshot, PortError, PortErrorKind, PortResult, RecordId,
    ResponsePlanRecord, ResponseStore, SchedulerClaimRequest, SecurityAlert, SecurityAlertPort,
    SessionId, SessionThrottleApplyRequest, SessionThrottleConsumeRequest, SessionThrottleDecision,
    SessionThrottleKey, SessionThrottleRemoveRequest, SessionThrottleSnapshot,
    SessionThrottleStore, TenantId, TenantScopedId,
};
use chio_security_types::{PrincipalId, ResponseEffectKind, ResponseTarget};
use chio_siem::{Alert, AlertBackend, ExportError};
use chio_store_sqlite::SqliteSecurityStateStore;
use serde::Serialize;
use tempfile::tempdir;

use crate::security::adapters::{AlertOutboxConfig, SqliteSiemOutbox};

#[derive(Default)]
struct OverlayState {
    snapshots: Vec<OverlaySnapshot>,
    commands: Vec<ContainmentOverlayCommand>,
    apply_calls: usize,
    remove_calls: usize,
    load_calls: usize,
    unavailable: bool,
}

#[derive(Default)]
struct RecordingOverlayStore {
    state: Mutex<OverlayState>,
}

#[derive(Default)]
struct AlertEffectState {
    entries: Vec<(SecurityAlert, AlertDeliveryStatus)>,
    page_calls: usize,
    exact_load_calls: usize,
    readiness_calls: usize,
    lose_next_page_ack: bool,
    unavailable: bool,
}

#[derive(Default)]
struct RecordingAlertStore {
    state: Mutex<AlertEffectState>,
}

#[derive(Default)]
struct ThrottleEffectState {
    snapshot: Option<SessionThrottleSnapshot>,
    commands: Vec<super::SessionThrottleCommand>,
    apply_calls: usize,
    remove_calls: usize,
    readiness_calls: usize,
    lose_next_apply_ack: bool,
    lose_next_remove_ack: bool,
    unavailable: bool,
}

#[derive(Default)]
struct RecordingThrottleStore {
    state: Mutex<ThrottleEffectState>,
}

impl RecordingThrottleStore {
    fn state(&self) -> std::sync::MutexGuard<'_, ThrottleEffectState> {
        self.state
            .lock()
            .unwrap_or_else(|error| panic!("throttle state poisoned: {error}"))
    }

    fn lose_next_apply_ack(&self) {
        self.state().lose_next_apply_ack = true;
    }

    fn lose_next_remove_ack(&self) {
        self.state().lose_next_remove_ack = true;
    }

    fn fail(&self) {
        self.state().unavailable = true;
    }

    fn counts(&self) -> (usize, usize, usize) {
        let state = self.state();
        (state.apply_calls, state.remove_calls, state.readiness_calls)
    }
}

impl RecordingAlertStore {
    fn state(&self) -> std::sync::MutexGuard<'_, AlertEffectState> {
        self.state
            .lock()
            .unwrap_or_else(|error| panic!("alert state poisoned: {error}"))
    }

    fn lose_next_page_ack(&self) {
        self.state().lose_next_page_ack = true;
    }

    fn fail(&self) {
        self.state().unavailable = true;
    }

    fn mark_delivered(&self, delivered_at_unix_ms: u64) {
        let mut state = self.state();
        let entry = state
            .entries
            .first_mut()
            .unwrap_or_else(|| panic!("alert entry missing"));
        entry.1 = AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms,
        };
    }

    fn tamper_evidence(&self) {
        let mut state = self.state();
        let entry = state
            .entries
            .first_mut()
            .unwrap_or_else(|| panic!("alert entry missing"));
        entry.0.evidence_hash = Digest32::new([99_u8; 32]);
    }

    fn counts(&self) -> (usize, usize, usize) {
        let state = self.state();
        (
            state.page_calls,
            state.exact_load_calls,
            state.readiness_calls,
        )
    }

    fn first_entry(&self) -> (SecurityAlert, AlertDeliveryStatus) {
        self.state()
            .entries
            .first()
            .cloned()
            .unwrap_or_else(|| panic!("alert entry missing"))
    }
}

impl SecurityAlertPort for RecordingAlertStore {
    fn ensure_alerts_ready(&self) -> PortResult<()> {
        let mut state = self.state();
        state.readiness_calls = state.readiness_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        Ok(())
    }

    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
        let mut state = self.state();
        state.page_calls = state.page_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        let status = if let Some((stored, status)) = state
            .entries
            .iter()
            .find(|(stored, _)| stored.idempotency_key == alert.idempotency_key)
        {
            if stored != alert {
                return Err(PortError::conflict());
            }
            *status
        } else {
            let status = AlertDeliveryStatus::Pending {
                attempts: 0,
                next_attempt_at_unix_ms: alert.occurred_at_unix_ms,
            };
            state.entries.push((alert.clone(), status));
            status
        };
        if state.lose_next_page_ack {
            state.lose_next_page_ack = false;
            return Err(PortError::unavailable());
        }
        Ok(status)
    }

    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>> {
        let mut state = self.state();
        state.exact_load_calls = state.exact_load_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        let Some((stored, status)) = state
            .entries
            .iter()
            .find(|(stored, _)| stored.idempotency_key == query.alert.idempotency_key)
        else {
            return Ok(None);
        };
        if stored != &query.alert {
            return Err(PortError::conflict());
        }
        Ok(Some(*status))
    }
}

impl EscalateAlertStore for RecordingAlertStore {
    fn load_persisted_alert(
        &self,
        tenant_id: &TenantId,
        idempotency_key: &RecordId,
    ) -> PortResult<Option<(SecurityAlert, AlertDeliveryStatus)>> {
        let mut state = self.state();
        state.exact_load_calls = state.exact_load_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        let Some((alert, status)) = state
            .entries
            .iter()
            .find(|(alert, _)| &alert.idempotency_key == idempotency_key)
        else {
            return Ok(None);
        };
        if &alert.tenant_id != tenant_id {
            return Err(PortError::integrity_failure());
        }
        Ok(Some((alert.clone(), *status)))
    }
}

impl SessionThrottleStore for RecordingThrottleStore {
    fn ensure_session_throttles_ready(&self) -> PortResult<()> {
        let mut state = self.state();
        state.readiness_calls = state.readiness_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        Ok(())
    }

    fn apply_session_throttle(
        &self,
        request: &SessionThrottleApplyRequest,
    ) -> PortResult<SessionThrottleSnapshot> {
        let mut state = self.state();
        state.apply_calls = state.apply_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        if let Some(existing) = state.commands.iter().find(|command| {
            command.request.idempotency_key == request.command.request.idempotency_key
        }) {
            if existing != &request.command {
                return Err(PortError::conflict());
            }
            return Ok(existing.resulting_snapshot.clone());
        }
        state.snapshot = Some(request.command.resulting_snapshot.clone());
        state.commands.push(request.command.clone());
        if state.lose_next_apply_ack {
            state.lose_next_apply_ack = false;
            return Err(PortError::unavailable());
        }
        Ok(request.command.resulting_snapshot.clone())
    }

    fn remove_session_throttle(
        &self,
        request: &SessionThrottleRemoveRequest,
    ) -> PortResult<SessionThrottleSnapshot> {
        let mut state = self.state();
        state.remove_calls = state.remove_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        if let Some(existing) = state.commands.iter().find(|command| {
            command.request.idempotency_key == request.command.request.idempotency_key
        }) {
            if existing != &request.command {
                return Err(PortError::conflict());
            }
            return Ok(existing.resulting_snapshot.clone());
        }
        state.snapshot = Some(request.command.resulting_snapshot.clone());
        state.commands.push(request.command.clone());
        if state.lose_next_remove_ack {
            state.lose_next_remove_ack = false;
            return Err(PortError::unavailable());
        }
        Ok(request.command.resulting_snapshot.clone())
    }

    fn load_session_throttles(
        &self,
        key: &SessionThrottleKey,
    ) -> PortResult<Option<SessionThrottleSnapshot>> {
        let state = self.state();
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        Ok(state
            .snapshot
            .as_ref()
            .filter(|snapshot| &snapshot.key == key)
            .cloned())
    }

    fn consume_session_invocation(
        &self,
        _request: &SessionThrottleConsumeRequest,
    ) -> PortResult<SessionThrottleDecision> {
        Err(PortError::unavailable())
    }

    fn load_session_throttle_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        let state = self.state();
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        let Some(command) = state.commands.iter().find(|command| {
            command.request.tenant_id == query.tenant_id
                && command.request.idempotency_key == query.idempotency_key
        }) else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        if super::effect_query_from_request(&command.request) != *query {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: command.result.clone(),
        })
    }
}

struct NoopAlertBackend;

impl AlertBackend for NoopAlertBackend {
    fn name(&self) -> &str {
        "effect-port-test-alert-backend"
    }

    fn dispatch<'a>(
        &'a self,
        _alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
    {
        Box::pin(async { Ok(()) })
    }
}

impl RecordingOverlayStore {
    fn require_state(&self) -> std::sync::MutexGuard<'_, OverlayState> {
        self.state
            .lock()
            .unwrap_or_else(|error| panic!("overlay state poisoned: {error}"))
    }

    fn fail_reads(&self) {
        self.require_state().unavailable = true;
    }

    fn counts(&self) -> (usize, usize, usize) {
        let state = self.require_state();
        (state.apply_calls, state.remove_calls, state.load_calls)
    }

    fn snapshot(&self, target: &TenantScopedId) -> Option<OverlaySnapshot> {
        self.require_state()
            .snapshots
            .iter()
            .find(|snapshot| snapshot.target == *target)
            .cloned()
    }
}

impl ContainmentOverlayStore for RecordingOverlayStore {
    fn ensure_containment_overlays_ready(&self) -> PortResult<()> {
        let mut state = self.require_state();
        state.load_calls = state.load_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        Ok(())
    }

    fn apply_contribution(&self, request: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        let mut state = self.require_state();
        state.apply_calls = state.apply_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        if let Some(existing) = state.commands.iter().find(|command| {
            command.request.tenant_id == request.command.request.tenant_id
                && command.request.idempotency_key == request.command.request.idempotency_key
        }) {
            if existing != &request.command {
                return Err(PortError::conflict());
            }
            return Ok(existing.resulting_snapshot.clone());
        }
        let position = state
            .snapshots
            .iter()
            .position(|snapshot| snapshot.target == request.target);
        let mut snapshot = position.map_or_else(
            || empty_snapshot(request.target.clone()),
            |index| state.snapshots[index].clone(),
        );
        if let Some(existing) = snapshot
            .active_contributions
            .as_slice()
            .iter()
            .find(|entry| entry.effect_id == request.contribution.effect_id)
        {
            if existing != &request.contribution {
                return Err(PortError::conflict());
            }
        } else {
            if snapshot.generation != request.expected_generation {
                return Err(PortError::conflict());
            }
            let mut contributions = snapshot.active_contributions.into_vec();
            contributions.push(request.contribution.clone());
            contributions.sort_by(|left, right| left.effect_id.cmp(&right.effect_id));
            snapshot.generation = snapshot.generation.saturating_add(1);
            snapshot.effective_posture_rank = contributions
                .iter()
                .map(|entry| entry.posture_rank)
                .max()
                .unwrap_or(0);
            snapshot.active_contributions = OverlayContributions::new(contributions)
                .unwrap_or_else(|error| panic!("overlay contributions: {error}"));
            snapshot.highest_fencing_token = snapshot
                .highest_fencing_token
                .max(request.scheduler_fencing_token);
        }
        if snapshot != request.command.resulting_snapshot {
            return Err(PortError::integrity_failure());
        }
        match position {
            Some(index) => state.snapshots[index] = snapshot.clone(),
            None => state.snapshots.push(snapshot.clone()),
        }
        state.commands.push(request.command.clone());
        Ok(snapshot)
    }

    fn remove_contribution(&self, request: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot> {
        let mut state = self.require_state();
        state.remove_calls = state.remove_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        if let Some(existing) = state.commands.iter().find(|command| {
            command.request.tenant_id == request.command.request.tenant_id
                && command.request.idempotency_key == request.command.request.idempotency_key
        }) {
            if existing != &request.command {
                return Err(PortError::conflict());
            }
            return Ok(existing.resulting_snapshot.clone());
        }
        let position = state
            .snapshots
            .iter()
            .position(|snapshot| snapshot.target == request.target);
        let mut snapshot = position.map_or_else(
            || empty_snapshot(request.target.clone()),
            |index| state.snapshots[index].clone(),
        );
        if snapshot.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        let mut contributions = snapshot.active_contributions.into_vec();
        let before = contributions.len();
        contributions.retain(|entry| entry.effect_id != request.effect_id);
        if contributions.len() != before {
            snapshot.generation = snapshot.generation.saturating_add(1);
        }
        snapshot.effective_posture_rank = contributions
            .iter()
            .map(|entry| entry.posture_rank)
            .max()
            .unwrap_or(0);
        snapshot.active_contributions = OverlayContributions::new(contributions)
            .unwrap_or_else(|error| panic!("overlay contributions: {error}"));
        snapshot.highest_fencing_token = snapshot
            .highest_fencing_token
            .max(request.scheduler_fencing_token);
        if snapshot != request.command.resulting_snapshot {
            return Err(PortError::integrity_failure());
        }
        match position {
            Some(index) => state.snapshots[index] = snapshot.clone(),
            None => state.snapshots.push(snapshot.clone()),
        }
        state.commands.push(request.command.clone());
        Ok(snapshot)
    }

    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        let mut state = self.require_state();
        state.load_calls = state.load_calls.saturating_add(1);
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        Ok(state
            .snapshots
            .iter()
            .find(|snapshot| snapshot.target == *target)
            .cloned())
    }

    fn load_containment_overlay_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        let state = self.require_state();
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        let Some(command) = state.commands.iter().find(|command| {
            command.request.tenant_id == query.tenant_id
                && command.request.idempotency_key == query.idempotency_key
        }) else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        if !request_matches_query(&command.request, query) {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: command.result.clone(),
        })
    }
}

fn request_matches_query(request: &EffectRequest, query: &EffectResultQuery) -> bool {
    request.tenant_id == query.tenant_id
        && request.action_id == query.action_id
        && request.plan_hash == query.plan_hash
        && request.effect_id == query.effect_id
        && request.effect_kind == query.effect_kind
        && request.target == query.target
        && request.plan_expires_at_unix_ms == query.plan_expires_at_unix_ms
        && request.operation == query.operation
        && request.idempotency_key == query.idempotency_key
        && request.expected_version_hash == query.expected_version_hash
        && request.scheduler_lease_owner_id == query.scheduler_lease_owner_id
        && request.scheduler_fencing_token == query.scheduler_fencing_token
        && request.contribution_hash == query.contribution_hash
}

fn empty_snapshot(target: TenantScopedId) -> OverlaySnapshot {
    OverlaySnapshot {
        target,
        generation: 0,
        effective_posture_rank: 0,
        active_contributions: OverlayContributions::new(Vec::new())
            .unwrap_or_else(|error| panic!("empty overlay: {error}")),
        highest_fencing_token: 0,
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn session() -> SessionId {
    SessionId::new("session-a").unwrap_or_else(|error| panic!("session: {error}"))
}

fn contribution(rank: u32) -> (CanonicalBody, Digest32) {
    let bytes = format!("{{\"posture_rank\":{rank}}}").into_bytes();
    let hash = Digest32::new(*chio_core::sha256(&bytes).as_bytes());
    (
        CanonicalBody::new(bytes).unwrap_or_else(|error| panic!("canonical contribution: {error}")),
        hash,
    )
}

fn request(
    operation: EffectOperation,
    expected_version_hash: Digest32,
    rank: u32,
) -> EffectRequest {
    let (canonical_contribution, contribution_hash) = contribution(rank);
    EffectRequest {
        tenant_id: tenant(),
        action_id: ActionId::new("action-a").unwrap_or_else(|error| panic!("action: {error}")),
        plan_hash: Digest32::new([7; 32]),
        effect_id: EffectId::new("effect-a").unwrap_or_else(|error| panic!("effect: {error}")),
        effect_kind: ResponseEffectKind::SuspendSession,
        target: ResponseTarget::Session {
            session_id: session(),
        },
        plan_expires_at_unix_ms: 80_000,
        operation,
        idempotency_key: RecordId::new("response_effect_command:command-a")
            .unwrap_or_else(|error| panic!("idempotency key: {error}")),
        expected_version_hash,
        scheduler_lease_owner_id: LeaseOwnerId::new("effect-port-worker")
            .unwrap_or_else(|error| panic!("scheduler owner: {error}")),
        scheduler_fencing_token: 9,
        canonical_contribution,
        contribution_hash,
    }
}

fn egress_request(
    operation: EffectOperation,
    expected_version_hash: Digest32,
    destinations: &[&str],
) -> EffectRequest {
    let destination_json = destinations
        .iter()
        .map(|destination| format!("\"{destination}\""))
        .collect::<Vec<_>>()
        .join(",");
    let bytes = format!("{{\"destinations\":[{destination_json}]}}").into_bytes();
    EffectRequest {
        tenant_id: tenant(),
        action_id: ActionId::new("action-a").unwrap_or_else(|error| panic!("action: {error}")),
        plan_hash: Digest32::new([17; 32]),
        effect_id: EffectId::new("effect-egress").unwrap_or_else(|error| panic!("effect: {error}")),
        effect_kind: ResponseEffectKind::RestrictEgress,
        target: ResponseTarget::Session {
            session_id: session(),
        },
        plan_expires_at_unix_ms: 80_000,
        operation,
        idempotency_key: RecordId::new("response_effect_command:egress")
            .unwrap_or_else(|error| panic!("idempotency key: {error}")),
        expected_version_hash,
        scheduler_lease_owner_id: LeaseOwnerId::new("effect-port-worker")
            .unwrap_or_else(|error| panic!("scheduler owner: {error}")),
        scheduler_fencing_token: 9,
        canonical_contribution: CanonicalBody::new(bytes.clone())
            .unwrap_or_else(|error| panic!("egress contribution: {error}")),
        contribution_hash: Digest32::new(*chio_core::sha256(&bytes).as_bytes()),
    }
}

fn alert_request() -> EffectRequest {
    let bytes = br#"{"channel":"security"}"#.to_vec();
    EffectRequest {
        tenant_id: tenant(),
        action_id: ActionId::new("action-alert")
            .unwrap_or_else(|error| panic!("alert action: {error}")),
        plan_hash: Digest32::new([31_u8; 32]),
        effect_id: EffectId::new("effect-alert")
            .unwrap_or_else(|error| panic!("alert effect: {error}")),
        effect_kind: ResponseEffectKind::EscalateAlert,
        target: ResponseTarget::Tenant {
            tenant_id: tenant(),
        },
        plan_expires_at_unix_ms: now_unix_ms().saturating_add(120_000),
        operation: EffectOperation::Apply,
        idempotency_key: RecordId::new("response_effect_command:alert")
            .unwrap_or_else(|error| panic!("alert command: {error}")),
        expected_version_hash: Digest32::new([32_u8; 32]),
        scheduler_lease_owner_id: LeaseOwnerId::new("effect-port-alert-worker")
            .unwrap_or_else(|error| panic!("scheduler owner: {error}")),
        scheduler_fencing_token: 33,
        canonical_contribution: CanonicalBody::new(bytes.clone())
            .unwrap_or_else(|error| panic!("alert contribution: {error}")),
        contribution_hash: Digest32::new(*chio_core::sha256(&bytes).as_bytes()),
    }
}

fn throttle_request(operation: EffectOperation, expected_version_hash: Digest32) -> EffectRequest {
    let limits = super::SessionThrottleLimits {
        window_ms: 5_000,
        max_invocations: 3,
    };
    let bytes = chio_core::canonical_json_bytes(&limits)
        .unwrap_or_else(|error| panic!("throttle limits: {error}"));
    EffectRequest {
        tenant_id: tenant(),
        action_id: ActionId::new("action-throttle")
            .unwrap_or_else(|error| panic!("throttle action: {error}")),
        plan_hash: Digest32::new([35_u8; 32]),
        effect_id: EffectId::new("effect-throttle")
            .unwrap_or_else(|error| panic!("throttle effect: {error}")),
        effect_kind: ResponseEffectKind::ThrottleSession,
        target: ResponseTarget::Session {
            session_id: session(),
        },
        plan_expires_at_unix_ms: now_unix_ms().saturating_add(120_000),
        operation,
        idempotency_key: RecordId::new("response_effect_command:throttle")
            .unwrap_or_else(|error| panic!("throttle command: {error}")),
        expected_version_hash,
        scheduler_lease_owner_id: LeaseOwnerId::new("effect-port-throttle-worker")
            .unwrap_or_else(|error| panic!("scheduler owner: {error}")),
        scheduler_fencing_token: 37,
        canonical_contribution: CanonicalBody::new(bytes.clone())
            .unwrap_or_else(|error| panic!("throttle contribution: {error}")),
        contribution_hash: Digest32::new(*chio_core::sha256(&bytes).as_bytes()),
    }
}

fn query(request: &EffectRequest) -> EffectResultQuery {
    EffectResultQuery {
        tenant_id: request.tenant_id.clone(),
        action_id: request.action_id.clone(),
        plan_hash: request.plan_hash,
        effect_id: request.effect_id.clone(),
        effect_kind: request.effect_kind,
        target: request.target.clone(),
        plan_expires_at_unix_ms: request.plan_expires_at_unix_ms,
        operation: request.operation,
        idempotency_key: request.idempotency_key.clone(),
        expected_version_hash: request.expected_version_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
        contribution_hash: request.contribution_hash,
    }
}

fn port(store: Arc<RecordingOverlayStore>) -> ActiveResponseEffectPort {
    ActiveResponseEffectPort::session_suspension_only(Arc::new(
        SessionSuspensionOverlayBackend::new(store),
    ))
}

fn alert_port(store: Arc<RecordingAlertStore>) -> ActiveResponseEffectPort {
    let alert_store: Arc<dyn EscalateAlertStore> = store;
    let backend: Arc<dyn ResponseEffectBackend> = Arc::new(EscalateAlertBackend::new(alert_store));
    ActiveResponseEffectPort::from_backends(vec![backend])
        .unwrap_or_else(|error| panic!("alert router: {error}"))
}

fn throttle_port(store: Arc<RecordingThrottleStore>) -> ActiveResponseEffectPort {
    let throttle_store: Arc<dyn SessionThrottleStore> = store;
    let backend: Arc<dyn ResponseEffectBackend> =
        Arc::new(SessionThrottleBackend::new(throttle_store));
    ActiveResponseEffectPort::from_backends(vec![backend])
        .unwrap_or_else(|error| panic!("throttle router: {error}"))
}

fn require_error<T: std::fmt::Debug>(result: PortResult<T>) -> PortError {
    match result {
        Ok(value) => panic!("operation unexpectedly succeeded: {value:?}"),
        Err(error) => error,
    }
}

fn now_unix_ms() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("clock before Unix epoch: {error}"));
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}
mod session_target_derivation_matches_the_enforcement_guard;

mod neutral_containment_commitments_match_the_legacy_adapter_domains;

mod suspend_session_apply_and_ack_loss_query_bind_the_exact_contribution;

mod overlapping_session_suspensions_remove_only_their_own_contribution;

mod completed_remove_can_be_retried_without_false_mutation;

mod sqlite_overlay_executes_under_the_real_scheduler_fence;

mod restrict_egress_backend_is_canonical_ack_safe_and_destination_scoped;

mod throttle_backend_recovers_apply_and_remove_ack_loss_across_restart;

mod throttle_backend_rejects_rebinding_noncanonical_limits_and_outage;

mod escalate_alert_recovers_page_ack_loss_retry_and_backend_restart;

mod escalate_alert_exact_query_rejects_wrong_bindings_and_remove;

mod escalate_alert_pending_and_delivered_replay_return_one_stable_result;

mod escalate_alert_distinguishes_tamper_from_outbox_unavailability;

mod sqlite_escalate_alert_survives_restart_and_rejects_rehashed_storage_tamper;

mod alert_and_throttle_are_probed_but_cannot_make_an_incomplete_router_ready;

mod unsupported_effects_fail_closed_before_overlay_mutation;

mod global_readiness_probes_installed_backend_but_rejects_incomplete_matrix;

mod malformed_or_rebound_session_effects_fail_before_mutation;
