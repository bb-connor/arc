#[cfg(test)]
mod tests {
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
        empty_session_throttle_snapshot, session_throttle_version_hash, ActionId,
        AlertDeliveryQuery, AlertDeliveryStatus, CanonicalBody, ContainmentOverlayCommand,
        ContainmentOverlayStore, Digest32, EffectExecutionStatus, EffectId, EffectOperation,
        EffectPort, EffectRequest, EffectResultQuery, EgressRestrictionSessionKey,
        EgressRestrictionStore, IsolationEpochId, LeaseOwnerId, LineageId, OverlayApplyRequest,
        OverlayContribution, OverlayContributions, OverlayRemoveRequest, OverlaySnapshot,
        PortError, PortErrorKind, PortResult, RecordId, ResponsePlanRecord, ResponseStore,
        SchedulerClaimRequest, SecurityAlert, SecurityAlertPort, SessionId,
        SessionThrottleApplyRequest, SessionThrottleConsumeRequest, SessionThrottleDecision,
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

        fn load_delivery(
            &self,
            query: &AlertDeliveryQuery,
        ) -> PortResult<Option<AlertDeliveryStatus>> {
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

        fn remove_contribution(
            &self,
            request: &OverlayRemoveRequest,
        ) -> PortResult<OverlaySnapshot> {
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
            CanonicalBody::new(bytes)
                .unwrap_or_else(|error| panic!("canonical contribution: {error}")),
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
            effect_id: EffectId::new("effect-egress")
                .unwrap_or_else(|error| panic!("effect: {error}")),
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

    fn throttle_request(
        operation: EffectOperation,
        expected_version_hash: Digest32,
    ) -> EffectRequest {
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
        let backend: Arc<dyn ResponseEffectBackend> =
            Arc::new(EscalateAlertBackend::new(alert_store));
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

    #[test]
    fn session_target_derivation_matches_the_enforcement_guard() {
        let context = SecurityInvocationContextV1::new(
            tenant(),
            session(),
            PrincipalId::new("principal-a").unwrap_or_else(|error| panic!("principal: {error}")),
            IsolationEpochId::new("epoch-a")
                .unwrap_or_else(|error| panic!("isolation epoch: {error}")),
            LineageId::new("lineage-a").unwrap_or_else(|error| panic!("lineage: {error}")),
            1,
        );
        let guard_target = containment_target(
            &context,
            ContainmentTargetKind::Session,
            context.session_id().as_str(),
        )
        .unwrap_or_else(|error| panic!("guard target: {error}"));
        let effect_target = session_containment_target(context.tenant_id(), context.session_id())
            .unwrap_or_else(|error| panic!("effect target: {error}"));
        assert_eq!(effect_target, guard_target);

        let mut legacy_preimage = b"chio.security.containment-target.v1\0".to_vec();
        legacy_preimage.extend_from_slice(b"session");
        legacy_preimage.push(0);
        legacy_preimage.extend_from_slice(context.session_id().as_str().as_bytes());
        let legacy_digest = chio_core::sha256(&legacy_preimage);
        let mut legacy_hex = String::with_capacity(64);
        for byte in legacy_digest.as_bytes() {
            legacy_hex.push_str(format!("{byte:02x}").as_str());
        }
        let legacy_target = TenantScopedId {
            tenant_id: context.tenant_id().clone(),
            id: RecordId::new(format!("session-{legacy_hex}"))
                .unwrap_or_else(|error| panic!("legacy target id: {error}")),
        };
        assert_eq!(effect_target, legacy_target);
    }

    #[test]
    fn neutral_containment_commitments_match_the_legacy_adapter_domains() {
        #[derive(Serialize)]
        struct LegacyOverlayCommitment<'a> {
            schema_version: u8,
            target: &'a TenantScopedId,
            generation: u64,
            effective_posture_rank: u32,
            active_contributions: &'a OverlayContributions,
        }

        #[derive(Serialize)]
        struct LegacyInstalledCommitment<'a> {
            schema_version: u8,
            target: &'a TenantScopedId,
            effect_id: &'a str,
            posture_rank: u32,
            contribution_hash: Digest32,
            expires_at_unix_ms: Option<u64>,
        }

        let target = session_containment_target(&tenant(), &session())
            .unwrap_or_else(|error| panic!("target: {error}"));
        let contribution = OverlayContribution {
            effect_id: EffectId::new("compatibility-effect")
                .unwrap_or_else(|error| panic!("effect id: {error}")),
            posture_rank: 7,
            contribution_hash: Digest32::new([41_u8; 32]),
            expires_at_unix_ms: Some(90_000),
        };
        let contributions = OverlayContributions::new(vec![contribution.clone()])
            .unwrap_or_else(|error| panic!("contributions: {error}"));
        let snapshot = OverlaySnapshot {
            target: target.clone(),
            generation: 1,
            effective_posture_rank: 7,
            active_contributions: contributions,
            highest_fencing_token: 9,
        };
        let legacy_overlay = super::domain_hash(
            b"chio.response-effect-overlay-state.v1\0",
            &LegacyOverlayCommitment {
                schema_version: 1,
                target: &target,
                generation: 1,
                effective_posture_rank: 7,
                active_contributions: &snapshot.active_contributions,
            },
        )
        .unwrap_or_else(|error| panic!("legacy overlay hash: {error}"));
        assert_eq!(
            containment_overlay_version_hash(&snapshot),
            Ok(legacy_overlay)
        );

        let legacy_installed = super::domain_hash(
            b"chio.response-effect-overlay-contribution.v1\0",
            &LegacyInstalledCommitment {
                schema_version: 1,
                target: &target,
                effect_id: contribution.effect_id.as_str(),
                posture_rank: contribution.posture_rank,
                contribution_hash: contribution.contribution_hash,
                expires_at_unix_ms: contribution.expires_at_unix_ms,
            },
        )
        .unwrap_or_else(|error| panic!("legacy installed hash: {error}"));
        assert_eq!(
            containment_installed_version_hash(&target, &contribution),
            Ok(legacy_installed)
        );
    }

    #[test]
    fn suspend_session_apply_and_ack_loss_query_bind_the_exact_contribution() {
        let store = Arc::new(RecordingOverlayStore::default());
        let target = session_containment_target(&tenant(), &session())
            .unwrap_or_else(|error| panic!("target: {error}"));
        let base_hash = session_overlay_version_hash(store.as_ref(), &target)
            .unwrap_or_else(|error| panic!("base version: {error}"));
        let port = port(Arc::clone(&store));
        let apply = request(EffectOperation::Apply, base_hash, 4);
        assert_eq!(
            port.load_result(&query(&apply)),
            Ok(EffectExecutionStatus::NotExecuted)
        );
        let result = port
            .execute(&apply)
            .unwrap_or_else(|error| panic!("apply: {error}"));
        assert!(result.applied);
        let snapshot = store
            .snapshot(&target)
            .unwrap_or_else(|| panic!("session overlay missing"));
        assert_eq!(snapshot.active_contributions.len(), 1);
        assert_eq!(
            snapshot.active_contributions.as_slice()[0].effect_id,
            apply.effect_id
        );
        assert_eq!(snapshot.active_contributions.as_slice()[0].posture_rank, 4);
        assert_eq!(
            snapshot.active_contributions.as_slice()[0].expires_at_unix_ms,
            Some(apply.plan_expires_at_unix_ms)
        );
        assert_eq!(
            result.resulting_version_hash,
            containment_installed_version_hash(
                &target,
                &snapshot.active_contributions.as_slice()[0]
            )
            .unwrap_or_else(|error| panic!("installed result hash: {error}"))
        );
        assert_eq!(
            port.load_result(&query(&apply)),
            Ok(EffectExecutionStatus::Completed {
                result: result.clone()
            })
        );
        assert_eq!(port.execute(&apply), Ok(result));
        assert_eq!(store.counts().0, 1, "ack recovery must not apply twice");
    }

    #[test]
    fn overlapping_session_suspensions_remove_only_their_own_contribution() {
        let store = Arc::new(RecordingOverlayStore::default());
        let port = port(Arc::clone(&store));
        let target = session_containment_target(&tenant(), &session())
            .unwrap_or_else(|error| panic!("target: {error}"));
        let first_base = session_overlay_version_hash(store.as_ref(), &target)
            .unwrap_or_else(|error| panic!("first base: {error}"));
        let first = request(EffectOperation::Apply, first_base, 3);
        let first_applied = port
            .execute(&first)
            .unwrap_or_else(|error| panic!("first apply: {error}"));

        let second_base = session_overlay_version_hash(store.as_ref(), &target)
            .unwrap_or_else(|error| panic!("second base: {error}"));
        let mut second = request(EffectOperation::Apply, second_base, 8);
        second.action_id =
            ActionId::new("action-b").unwrap_or_else(|error| panic!("second action: {error}"));
        second.effect_id =
            EffectId::new("effect-b").unwrap_or_else(|error| panic!("second effect: {error}"));
        second.idempotency_key = RecordId::new("response_effect_command:command-b")
            .unwrap_or_else(|error| panic!("second command: {error}"));
        let second_applied = port
            .execute(&second)
            .unwrap_or_else(|error| panic!("second apply: {error}"));

        let mut remove_first = first.clone();
        remove_first.operation = EffectOperation::Remove;
        remove_first.expected_version_hash = first_applied.resulting_version_hash;
        remove_first.idempotency_key = RecordId::new("response_effect_command:remove-first")
            .unwrap_or_else(|error| panic!("remove first key: {error}"));
        let restored = port
            .execute(&remove_first)
            .unwrap_or_else(|error| panic!("remove first: {error}"));
        assert!(!restored.applied);
        let after_first = store
            .snapshot(&target)
            .unwrap_or_else(|| panic!("overlay after first removal missing"));
        assert_eq!(after_first.active_contributions.len(), 1);
        assert_eq!(
            after_first.active_contributions.as_slice()[0].effect_id,
            second.effect_id
        );
        assert_eq!(after_first.effective_posture_rank, 8);

        let mut remove_second = second.clone();
        remove_second.operation = EffectOperation::Remove;
        remove_second.expected_version_hash = second_applied.resulting_version_hash;
        remove_second.idempotency_key = RecordId::new("response_effect_command:remove-second")
            .unwrap_or_else(|error| panic!("remove second key: {error}"));
        port.execute(&remove_second)
            .unwrap_or_else(|error| panic!("remove second: {error}"));
        let after_second = store
            .snapshot(&target)
            .unwrap_or_else(|| panic!("overlay after second removal missing"));
        assert!(after_second.active_contributions.is_empty());
        assert_eq!(after_second.effective_posture_rank, 0);
    }

    #[test]
    fn completed_remove_can_be_retried_without_false_mutation() {
        let store = Arc::new(RecordingOverlayStore::default());
        let port = port(Arc::clone(&store));
        let target = session_containment_target(&tenant(), &session())
            .unwrap_or_else(|error| panic!("target: {error}"));
        let base = session_overlay_version_hash(store.as_ref(), &target)
            .unwrap_or_else(|error| panic!("base: {error}"));
        let apply = request(EffectOperation::Apply, base, 5);
        let applied = port
            .execute(&apply)
            .unwrap_or_else(|error| panic!("apply: {error}"));
        let mut remove = apply;
        remove.operation = EffectOperation::Remove;
        remove.expected_version_hash = applied.resulting_version_hash;
        remove.idempotency_key = RecordId::new("response_effect_command:remove")
            .unwrap_or_else(|error| panic!("remove key: {error}"));
        let first = port
            .execute(&remove)
            .unwrap_or_else(|error| panic!("first remove: {error}"));
        assert!(!first.applied);
        let removed_snapshot = store
            .snapshot(&target)
            .unwrap_or_else(|| panic!("removed overlay missing"));
        assert_eq!(
            first.resulting_version_hash,
            containment_overlay_version_hash(&removed_snapshot)
                .unwrap_or_else(|error| panic!("removed result hash: {error}"))
        );
        assert_eq!(
            port.load_result(&query(&remove)),
            Ok(EffectExecutionStatus::Completed {
                result: first.clone()
            })
        );
        let retry = port
            .execute(&remove)
            .unwrap_or_else(|error| panic!("retry remove: {error}"));
        assert_eq!(retry, first);
        assert_eq!(store.counts().1, 1);
        assert!(store
            .snapshot(&target)
            .unwrap_or_else(|| panic!("overlay after retry missing"))
            .active_contributions
            .is_empty());
    }

    #[test]
    fn sqlite_overlay_executes_under_the_real_scheduler_fence() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("response-effects.db"))
                .unwrap_or_else(|error| panic!("open SQLite store: {error}")),
        );
        let now = now_unix_ms();
        let action_id =
            ActionId::new("action-a").unwrap_or_else(|error| panic!("action id: {error}"));
        let plan_body =
            CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan body: {error}"));
        let plan = ResponsePlanRecord {
            tenant_id: tenant(),
            action_id: action_id.clone(),
            generation: 0,
            state: RecordId::new("active").unwrap_or_else(|error| panic!("plan state: {error}")),
            canonical_body: plan_body.clone(),
            body_hash: Digest32::new(*chio_core::sha256(plan_body.as_bytes()).as_bytes()),
            due_at_unix_ms: Some(now.saturating_sub(1)),
        };
        store
            .create(&plan)
            .unwrap_or_else(|error| panic!("create scheduled response: {error}"));
        let work = store
            .claim_due(&SchedulerClaimRequest {
                tenant_id: tenant(),
                claim_id: RecordId::new("effect-port-sqlite-claim")
                    .unwrap_or_else(|error| panic!("claim id: {error}")),
                lease_owner_id: LeaseOwnerId::new("effect-port-worker")
                    .unwrap_or_else(|error| panic!("lease owner: {error}")),
                now_unix_ms: now,
                lease_expires_at_unix_ms: now.saturating_add(60_000),
                max_claims: 1,
            })
            .unwrap_or_else(|error| panic!("claim response: {error}"));
        assert_eq!(work.len(), 1);

        let target = session_containment_target(&tenant(), &session())
            .unwrap_or_else(|error| panic!("target: {error}"));
        let base = session_overlay_version_hash(store.as_ref(), &target)
            .unwrap_or_else(|error| panic!("base version: {error}"));
        let port = ActiveResponseEffectPort::session_suspension_only(Arc::new(
            SessionSuspensionOverlayBackend::new(store.clone()),
        ));
        let mut apply = request(EffectOperation::Apply, base, 6);
        apply.scheduler_fencing_token = work[0].fencing_token;
        apply.plan_expires_at_unix_ms = now.saturating_add(30_000);
        let applied = port
            .execute(&apply)
            .unwrap_or_else(|error| panic!("apply through SQLite: {error}"));
        assert!(applied.applied);

        let mut remove = apply;
        remove.operation = EffectOperation::Remove;
        remove.expected_version_hash = applied.resulting_version_hash;
        remove.idempotency_key = RecordId::new("response_effect_command:sqlite-remove")
            .unwrap_or_else(|error| panic!("remove command: {error}"));
        let removed = port
            .execute(&remove)
            .unwrap_or_else(|error| panic!("remove through SQLite: {error}"));
        assert!(!removed.applied);
        assert!(store
            .load_effective(&target)
            .unwrap_or_else(|error| panic!("load final overlay: {error}"))
            .unwrap_or_else(|| panic!("final overlay state missing"))
            .active_contributions
            .is_empty());
    }

    #[test]
    fn restrict_egress_backend_is_canonical_ack_safe_and_destination_scoped() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let store = Arc::new(
            SqliteSecurityStateStore::open(directory.path().join("response-egress.db"))
                .unwrap_or_else(|error| panic!("open SQLite store: {error}")),
        );
        let now = now_unix_ms();
        let action_id =
            ActionId::new("action-a").unwrap_or_else(|error| panic!("action id: {error}"));
        let plan_body =
            CanonicalBody::new(b"{}".to_vec()).unwrap_or_else(|error| panic!("plan body: {error}"));
        store
            .create(&ResponsePlanRecord {
                tenant_id: tenant(),
                action_id: action_id.clone(),
                generation: 0,
                state: RecordId::new("active")
                    .unwrap_or_else(|error| panic!("plan state: {error}")),
                canonical_body: plan_body.clone(),
                body_hash: Digest32::new(*chio_core::sha256(plan_body.as_bytes()).as_bytes()),
                due_at_unix_ms: Some(now.saturating_sub(1)),
            })
            .unwrap_or_else(|error| panic!("create scheduled response: {error}"));
        let work = store
            .claim_due(&SchedulerClaimRequest {
                tenant_id: tenant(),
                claim_id: RecordId::new("effect-port-egress-claim")
                    .unwrap_or_else(|error| panic!("claim id: {error}")),
                lease_owner_id: LeaseOwnerId::new("effect-port-egress-worker")
                    .unwrap_or_else(|error| panic!("lease owner: {error}")),
                now_unix_ms: now,
                lease_expires_at_unix_ms: now.saturating_add(60_000),
                max_claims: 1,
            })
            .unwrap_or_else(|error| panic!("claim response: {error}"));
        assert_eq!(work.len(), 1);

        let key = EgressRestrictionSessionKey {
            tenant_id: tenant(),
            session_id: session(),
        };
        let base = egress_restriction_version_hash(store.as_ref(), &key)
            .unwrap_or_else(|error| panic!("egress base version: {error}"));
        let backend = Arc::new(RestrictEgressOverlayBackend::new(store.clone()));
        ResponseEffectBackend::ensure_ready(backend.as_ref())
            .unwrap_or_else(|error| panic!("egress readiness: {error}"));
        let routed: Arc<dyn ResponseEffectBackend> = backend;
        let port = ActiveResponseEffectPort::from_backends(vec![routed])
            .unwrap_or_else(|error| panic!("egress router: {error}"));

        let malformed = egress_request(EffectOperation::Apply, base, &["server-b", "server-a"]);
        let malformed_error = require_error(port.execute(&malformed));
        assert_eq!(malformed_error.kind(), PortErrorKind::InvalidData);

        let mut apply = egress_request(EffectOperation::Apply, base, &["server-a", "server-b"]);
        apply.scheduler_fencing_token = work[0].fencing_token;
        apply.plan_expires_at_unix_ms = now.saturating_add(30_000);
        let applied = port
            .execute(&apply)
            .unwrap_or_else(|error| panic!("apply egress restriction: {error}"));
        assert!(applied.applied);
        assert_eq!(
            port.load_result(&query(&apply)),
            Ok(EffectExecutionStatus::Completed {
                result: applied.clone()
            })
        );
        assert_eq!(port.execute(&apply), Ok(applied.clone()));

        let matching = store
            .evaluate_destination(&chio_security_types::ports::EgressDestinationQuery {
                key: key.clone(),
                destination_id: chio_security_types::ports::DestinationId::new("server-a")
                    .unwrap_or_else(|error| panic!("matching destination: {error}")),
            })
            .unwrap_or_else(|error| panic!("matching decision: {error}"));
        let nonmatching = store
            .evaluate_destination(&chio_security_types::ports::EgressDestinationQuery {
                key: key.clone(),
                destination_id: chio_security_types::ports::DestinationId::new("server-c")
                    .unwrap_or_else(|error| panic!("nonmatching destination: {error}")),
            })
            .unwrap_or_else(|error| panic!("nonmatching decision: {error}"));
        assert!(matching.denied);
        assert!(!nonmatching.denied);

        let mut rebound = apply.clone();
        rebound.effect_id = EffectId::new("effect-rebound")
            .unwrap_or_else(|error| panic!("rebound effect: {error}"));
        rebound.target = ResponseTarget::Session {
            session_id: SessionId::new("session-rebound")
                .unwrap_or_else(|error| panic!("rebound session: {error}")),
        };
        let rebound_error = require_error(port.execute(&rebound));
        assert_eq!(rebound_error.kind(), PortErrorKind::Conflict);

        let mut remove = apply;
        remove.operation = EffectOperation::Remove;
        remove.expected_version_hash = applied.resulting_version_hash;
        remove.idempotency_key = RecordId::new("response_effect_command:egress-remove")
            .unwrap_or_else(|error| panic!("remove command: {error}"));
        let removed = port
            .execute(&remove)
            .unwrap_or_else(|error| panic!("remove egress restriction: {error}"));
        assert!(!removed.applied);
        assert_eq!(
            port.load_result(&query(&remove)),
            Ok(EffectExecutionStatus::Completed {
                result: removed.clone()
            })
        );
        assert_eq!(port.execute(&remove), Ok(removed.clone()));
        assert!(
            !store
                .evaluate_destination(&chio_security_types::ports::EgressDestinationQuery {
                    key,
                    destination_id: chio_security_types::ports::DestinationId::new("server-a")
                        .unwrap_or_else(|error| panic!("final destination: {error}")),
                })
                .unwrap_or_else(|error| panic!("final decision: {error}"))
                .denied
        );
    }

    #[test]
    fn throttle_backend_recovers_apply_and_remove_ack_loss_across_restart() {
        let store = Arc::new(RecordingThrottleStore::default());
        store.lose_next_apply_ack();
        let empty = empty_session_throttle_snapshot(super::SessionThrottleKey {
            tenant_id: tenant(),
            session_id: session(),
        })
        .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
        let apply = throttle_request(
            EffectOperation::Apply,
            session_throttle_version_hash(&empty)
                .unwrap_or_else(|error| panic!("empty throttle version: {error}")),
        );
        let port = throttle_port(store.clone());
        assert_eq!(
            port.load_result(&query(&apply)),
            Ok(EffectExecutionStatus::NotExecuted)
        );
        let applied = port
            .execute(&apply)
            .unwrap_or_else(|error| panic!("recover throttle apply ack: {error}"));
        assert!(applied.applied);
        assert_eq!(applied.effect_id, apply.effect_id);
        assert_eq!(store.counts().0, 1);
        assert_eq!(port.execute(&apply), Ok(applied.clone()));
        assert_eq!(store.counts().0, 1);

        let restarted = throttle_port(store.clone());
        assert_eq!(
            restarted.load_result(&query(&apply)),
            Ok(EffectExecutionStatus::Completed {
                result: applied.clone()
            })
        );
        assert_eq!(restarted.execute(&apply), Ok(applied.clone()));
        assert_eq!(store.counts().0, 1);

        store.lose_next_remove_ack();
        let mut remove = apply;
        remove.operation = EffectOperation::Remove;
        remove.expected_version_hash = applied.resulting_version_hash;
        remove.idempotency_key = RecordId::new("response_effect_command:throttle-remove")
            .unwrap_or_else(|error| panic!("throttle remove command: {error}"));
        let removed = restarted
            .execute(&remove)
            .unwrap_or_else(|error| panic!("recover throttle remove ack: {error}"));
        assert!(!removed.applied);
        assert_eq!(store.counts().1, 1);
        let restarted_again = throttle_port(store.clone());
        assert_eq!(restarted_again.execute(&remove), Ok(removed.clone()));
        assert_eq!(
            restarted_again.load_result(&query(&remove)),
            Ok(EffectExecutionStatus::Completed { result: removed })
        );
        assert_eq!(store.counts().1, 1);
    }

    #[test]
    fn throttle_backend_rejects_rebinding_noncanonical_limits_and_outage() {
        let store = Arc::new(RecordingThrottleStore::default());
        let empty = empty_session_throttle_snapshot(super::SessionThrottleKey {
            tenant_id: tenant(),
            session_id: session(),
        })
        .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
        let base = session_throttle_version_hash(&empty)
            .unwrap_or_else(|error| panic!("empty throttle version: {error}"));
        let apply = throttle_request(EffectOperation::Apply, base);
        let port = throttle_port(store.clone());
        port.execute(&apply)
            .unwrap_or_else(|error| panic!("apply throttle before hostility: {error}"));

        let mut wrong_action = query(&apply);
        wrong_action.action_id = ActionId::new("action-throttle-wrong")
            .unwrap_or_else(|error| panic!("wrong throttle action: {error}"));
        assert_eq!(
            require_error(port.load_result(&wrong_action)).kind(),
            PortErrorKind::Conflict
        );
        let mut wrong_plan = query(&apply);
        wrong_plan.plan_hash = Digest32::new([81_u8; 32]);
        let mut wrong_effect = query(&apply);
        wrong_effect.effect_id = EffectId::new("effect-throttle-wrong")
            .unwrap_or_else(|error| panic!("wrong throttle effect: {error}"));
        let mut wrong_contribution = query(&apply);
        wrong_contribution.contribution_hash = Digest32::new([82_u8; 32]);
        let mut wrong_fence = query(&apply);
        wrong_fence.scheduler_fencing_token = 83;
        for wrong in [wrong_plan, wrong_effect, wrong_contribution, wrong_fence] {
            assert_eq!(
                require_error(port.load_result(&wrong)).kind(),
                PortErrorKind::Conflict
            );
        }
        let mut rebound = apply.clone();
        rebound.target = ResponseTarget::Session {
            session_id: SessionId::new("session-throttle-rebound")
                .unwrap_or_else(|error| panic!("rebound throttle session: {error}")),
        };
        assert_eq!(
            require_error(port.execute(&rebound)).kind(),
            PortErrorKind::Conflict
        );
        let mut cross_tenant = apply.clone();
        cross_tenant.tenant_id = TenantId::new("tenant-throttle-rebound")
            .unwrap_or_else(|error| panic!("rebound throttle tenant: {error}"));
        assert_eq!(
            require_error(port.execute(&cross_tenant)).kind(),
            PortErrorKind::Conflict
        );

        let mut noncanonical = throttle_request(EffectOperation::Apply, base);
        let bytes = br#"{"window_ms":5000, "max_invocations":3}"#.to_vec();
        noncanonical.canonical_contribution = CanonicalBody::new(bytes.clone())
            .unwrap_or_else(|error| panic!("noncanonical throttle limits: {error}"));
        noncanonical.contribution_hash = Digest32::new(*chio_core::sha256(&bytes).as_bytes());
        noncanonical.idempotency_key =
            RecordId::new("response_effect_command:throttle-noncanonical")
                .unwrap_or_else(|error| panic!("noncanonical throttle command: {error}"));
        assert_eq!(
            require_error(port.execute(&noncanonical)).kind(),
            PortErrorKind::IntegrityFailure
        );

        store.fail();
        assert_eq!(
            require_error(port.load_result(&query(&apply))).kind(),
            PortErrorKind::Unavailable
        );
    }

    #[test]
    fn escalate_alert_recovers_page_ack_loss_retry_and_backend_restart() {
        let store = Arc::new(RecordingAlertStore::default());
        store.lose_next_page_ack();
        let request = alert_request();
        let port = alert_port(store.clone());
        assert_eq!(
            port.load_result(&query(&request)),
            Ok(EffectExecutionStatus::NotExecuted)
        );

        let result = port
            .execute(&request)
            .unwrap_or_else(|error| panic!("execute alert after ack loss: {error}"));
        assert!(result.applied);
        assert_eq!(result.effect_id, request.effect_id);
        assert_ne!(result.resulting_version_hash, Digest32::new([0_u8; 32]));
        let (alert, status) = store.first_entry();
        assert!(matches!(status, AlertDeliveryStatus::Pending { .. }));
        assert!(alert
            .event_id
            .as_str()
            .starts_with("active_response_alert_event:"));
        assert!(alert
            .idempotency_key
            .as_str()
            .starts_with("active_response_alert_command:"));
        assert_ne!(alert.event_id, alert.idempotency_key);
        assert_ne!(alert.finding_id_hash, alert.evidence_hash);
        assert_ne!(
            result.resulting_version_hash,
            alert
                .action_id_hash
                .unwrap_or_else(|| panic!("alert action hash missing"))
        );
        assert_eq!(store.counts().0, 1);

        assert_eq!(port.execute(&request), Ok(result.clone()));
        assert_eq!(store.counts().0, 1);
        let restarted = alert_port(store.clone());
        assert_eq!(
            restarted.load_result(&query(&request)),
            Ok(EffectExecutionStatus::Completed {
                result: result.clone()
            })
        );
        assert_eq!(restarted.execute(&request), Ok(result));
        assert_eq!(store.counts().0, 1);
    }

    #[test]
    fn escalate_alert_exact_query_rejects_wrong_bindings_and_remove() {
        let store = Arc::new(RecordingAlertStore::default());
        let port = alert_port(store.clone());
        let request = alert_request();
        port.execute(&request)
            .unwrap_or_else(|error| panic!("execute bound alert: {error}"));

        let mut wrong_tenant = query(&request);
        wrong_tenant.tenant_id =
            TenantId::new("tenant-wrong").unwrap_or_else(|error| panic!("wrong tenant: {error}"));
        wrong_tenant.target = ResponseTarget::Tenant {
            tenant_id: wrong_tenant.tenant_id.clone(),
        };
        let mut wrong_action = query(&request);
        wrong_action.action_id =
            ActionId::new("action-wrong").unwrap_or_else(|error| panic!("wrong action: {error}"));
        let mut wrong_plan = query(&request);
        wrong_plan.plan_hash = Digest32::new([41_u8; 32]);
        let mut wrong_effect = query(&request);
        wrong_effect.effect_id =
            EffectId::new("effect-wrong").unwrap_or_else(|error| panic!("wrong effect: {error}"));
        let mut wrong_contribution = query(&request);
        wrong_contribution.contribution_hash = Digest32::new([42_u8; 32]);
        let mut wrong_fence = query(&request);
        wrong_fence.scheduler_fencing_token = 43;
        for wrong in [
            wrong_tenant,
            wrong_action,
            wrong_plan,
            wrong_effect,
            wrong_contribution,
            wrong_fence,
        ] {
            assert_eq!(
                port.load_result(&wrong),
                Ok(EffectExecutionStatus::NotExecuted)
            );
        }

        let mut tenant_rebound = request.clone();
        tenant_rebound.target = ResponseTarget::Tenant {
            tenant_id: TenantId::new("tenant-rebound")
                .unwrap_or_else(|error| panic!("rebound tenant: {error}")),
        };
        assert_eq!(
            require_error(port.execute(&tenant_rebound)).kind(),
            PortErrorKind::InvalidData
        );

        let mut noncanonical = request.clone();
        let noncanonical_bytes = br#"{"z":1,"a":2}"#.to_vec();
        noncanonical.canonical_contribution = CanonicalBody::new(noncanonical_bytes.clone())
            .unwrap_or_else(|error| panic!("noncanonical alert body: {error}"));
        noncanonical.contribution_hash =
            Digest32::new(*chio_core::sha256(&noncanonical_bytes).as_bytes());
        assert_eq!(
            require_error(port.execute(&noncanonical)).kind(),
            PortErrorKind::IntegrityFailure
        );

        let mut wrong_hash = request.clone();
        wrong_hash.contribution_hash = Digest32::new([44_u8; 32]);
        assert_eq!(
            require_error(port.execute(&wrong_hash)).kind(),
            PortErrorKind::IntegrityFailure
        );

        let mut remove = request;
        remove.operation = EffectOperation::Remove;
        remove.idempotency_key = RecordId::new("response_effect_command:alert-remove")
            .unwrap_or_else(|error| panic!("remove command: {error}"));
        assert_eq!(
            require_error(port.execute(&remove)).kind(),
            PortErrorKind::InvalidData
        );
        assert_eq!(store.counts().0, 1);
    }

    #[test]
    fn escalate_alert_pending_and_delivered_replay_return_one_stable_result() {
        let store = Arc::new(RecordingAlertStore::default());
        let port = alert_port(store.clone());
        let request = alert_request();
        let result = port
            .execute(&request)
            .unwrap_or_else(|error| panic!("execute pending alert: {error}"));
        assert!(matches!(
            store.first_entry().1,
            AlertDeliveryStatus::Pending { .. }
        ));

        store.mark_delivered(now_unix_ms());
        assert_eq!(port.execute(&request), Ok(result.clone()));
        assert_eq!(
            port.load_result(&query(&request)),
            Ok(EffectExecutionStatus::Completed { result })
        );
        assert!(matches!(
            store.first_entry().1,
            AlertDeliveryStatus::Delivered { .. }
        ));
        assert_eq!(store.counts().0, 1);
    }

    #[test]
    fn escalate_alert_distinguishes_tamper_from_outbox_unavailability() {
        let request = alert_request();
        let tampered_store = Arc::new(RecordingAlertStore::default());
        let tampered_port = alert_port(tampered_store.clone());
        tampered_port
            .execute(&request)
            .unwrap_or_else(|error| panic!("execute alert before tamper: {error}"));
        tampered_store.tamper_evidence();
        assert_eq!(
            require_error(tampered_port.load_result(&query(&request))).kind(),
            PortErrorKind::IntegrityFailure
        );

        let unavailable_store = Arc::new(RecordingAlertStore::default());
        let unavailable_port = alert_port(unavailable_store.clone());
        unavailable_port
            .execute(&request)
            .unwrap_or_else(|error| panic!("execute alert before outage: {error}"));
        unavailable_store.fail();
        assert_eq!(
            require_error(unavailable_port.load_result(&query(&request))).kind(),
            PortErrorKind::Unavailable
        );
    }

    #[test]
    fn sqlite_escalate_alert_survives_restart_and_rejects_rehashed_storage_tamper() {
        let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let path = directory.path().join("effect-alerts.sqlite");
        let config = AlertOutboxConfig {
            base_retry_ms: 10,
            max_retry_ms: 100,
            max_attempts: 3,
        };
        let request = alert_request();
        let outbox = Arc::new(
            SqliteSiemOutbox::open(
                &path,
                vec![Arc::new(NoopAlertBackend) as Arc<dyn AlertBackend>],
                config,
            )
            .unwrap_or_else(|error| panic!("open alert outbox: {error}")),
        );
        let alert_store: Arc<dyn EscalateAlertStore> = outbox.clone();
        let backend: Arc<dyn ResponseEffectBackend> =
            Arc::new(EscalateAlertBackend::new(alert_store));
        let port = ActiveResponseEffectPort::from_backends(vec![backend])
            .unwrap_or_else(|error| panic!("SQLite alert router: {error}"));
        let result = port
            .execute(&request)
            .unwrap_or_else(|error| panic!("persist SQLite alert: {error}"));
        drop(port);
        drop(outbox);

        let reopened = Arc::new(
            SqliteSiemOutbox::open(
                &path,
                vec![Arc::new(NoopAlertBackend) as Arc<dyn AlertBackend>],
                config,
            )
            .unwrap_or_else(|error| panic!("reopen alert outbox: {error}")),
        );
        let alert_store: Arc<dyn EscalateAlertStore> = reopened.clone();
        let backend: Arc<dyn ResponseEffectBackend> =
            Arc::new(EscalateAlertBackend::new(alert_store));
        let restarted = ActiveResponseEffectPort::from_backends(vec![backend])
            .unwrap_or_else(|error| panic!("restarted alert router: {error}"));
        assert_eq!(
            restarted.load_result(&query(&request)),
            Ok(EffectExecutionStatus::Completed {
                result: result.clone()
            })
        );
        assert_eq!(restarted.execute(&request), Ok(result));

        let connection = rusqlite::Connection::open(&path)
            .unwrap_or_else(|error| panic!("open alert tamper connection: {error}"));
        let command_json: Vec<u8> = connection
            .query_row(
                "SELECT command_json FROM chio_security_alert_outbox",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|error| panic!("load stored alert command: {error}"));
        let mut stored_alert: SecurityAlert = serde_json::from_slice(&command_json)
            .unwrap_or_else(|error| panic!("decode stored alert command: {error}"));
        stored_alert.evidence_hash = Digest32::new([88_u8; 32]);
        let tampered_json = chio_core::canonical_json_bytes(&stored_alert)
            .unwrap_or_else(|error| panic!("canonical tampered alert: {error}"));
        let tampered_hash = chio_core::sha256(&tampered_json);
        connection
            .execute(
                "UPDATE chio_security_alert_outbox SET command_json = ?1, command_hash = ?2",
                rusqlite::params![tampered_json, tampered_hash.as_bytes().as_slice()],
            )
            .unwrap_or_else(|error| panic!("tamper alert outbox: {error}"));
        assert_eq!(
            require_error(restarted.load_result(&query(&request))).kind(),
            PortErrorKind::IntegrityFailure
        );
    }

    #[test]
    fn alert_and_throttle_are_probed_but_cannot_make_an_incomplete_router_ready() {
        let alerts = Arc::new(RecordingAlertStore::default());
        let alert_store: Arc<dyn EscalateAlertStore> = alerts.clone();
        let alert_backend: Arc<dyn ResponseEffectBackend> =
            Arc::new(EscalateAlertBackend::new(alert_store));
        let overlays = Arc::new(RecordingOverlayStore::default());
        let suspension_backend: Arc<dyn ResponseEffectBackend> =
            Arc::new(SessionSuspensionOverlayBackend::new(overlays.clone()));
        let throttles = Arc::new(RecordingThrottleStore::default());
        let throttle_store: Arc<dyn SessionThrottleStore> = throttles.clone();
        let throttle_backend: Arc<dyn ResponseEffectBackend> =
            Arc::new(SessionThrottleBackend::new(throttle_store));
        let router = ActiveResponseEffectPort::from_backends(vec![
            alert_backend,
            throttle_backend,
            suspension_backend,
        ])
        .unwrap_or_else(|error| panic!("partial alert router: {error}"));
        assert_eq!(
            require_error(router.ensure_effects_ready()).kind(),
            PortErrorKind::Unavailable
        );
        assert!(alerts.counts().2 > 0, "alert backend was not probed");
        assert!(throttles.counts().2 > 0, "throttle backend was not probed");
        assert!(overlays.counts().2 > 0, "overlay backend was not probed");
    }

    #[test]
    fn unsupported_effects_fail_closed_before_overlay_mutation() {
        let store = Arc::new(RecordingOverlayStore::default());
        let port = port(Arc::clone(&store));
        let base = Digest32::new([0; 32]);
        for (kind, target) in [
            (
                ResponseEffectKind::EscalateAlert,
                ResponseTarget::Tenant {
                    tenant_id: tenant(),
                },
            ),
            (
                ResponseEffectKind::ThrottleSession,
                ResponseTarget::Session {
                    session_id: session(),
                },
            ),
            (
                ResponseEffectKind::RestrictEgress,
                ResponseTarget::Session {
                    session_id: session(),
                },
            ),
            (
                ResponseEffectKind::SuspendCapabilitySet,
                ResponseTarget::CapabilitySet {
                    affected_set_hash: Digest32::new([3; 32]),
                },
            ),
            (
                ResponseEffectKind::FreezeIssuance,
                ResponseTarget::Lineage {
                    lineage_id: LineageId::new("lineage-a")
                        .unwrap_or_else(|error| panic!("lineage: {error}")),
                },
            ),
        ] {
            let mut unsupported = request(EffectOperation::Apply, base, 1);
            unsupported.effect_kind = kind;
            unsupported.target = target;
            let error = require_error(port.execute(&unsupported));
            assert_eq!(error.kind(), PortErrorKind::Unavailable);
        }
        assert_eq!(store.counts().0, 0);
        assert_eq!(store.counts().1, 0);
    }

    #[test]
    fn global_readiness_probes_installed_backend_but_rejects_incomplete_matrix() {
        let store = Arc::new(RecordingOverlayStore::default());
        let port = port(Arc::clone(&store));
        let error = require_error(port.ensure_effects_ready());
        assert_eq!(error.kind(), PortErrorKind::Unavailable);
        assert!(store.counts().2 > 0, "installed backend was not probed");

        store.fail_reads();
        let unavailable = require_error(port.ensure_effects_ready());
        assert_eq!(unavailable.kind(), PortErrorKind::Unavailable);
    }

    #[test]
    fn malformed_or_rebound_session_effects_fail_before_mutation() {
        let store = Arc::new(RecordingOverlayStore::default());
        let port = port(Arc::clone(&store));
        let target = session_containment_target(&tenant(), &session())
            .unwrap_or_else(|error| panic!("target: {error}"));
        let base = session_overlay_version_hash(store.as_ref(), &target)
            .unwrap_or_else(|error| panic!("base: {error}"));

        let mut zero_rank = request(EffectOperation::Apply, base, 0);
        let zero_error = require_error(port.execute(&zero_rank));
        assert_eq!(zero_error.kind(), PortErrorKind::InvalidData);

        let stale = request(EffectOperation::Apply, Digest32::new([71; 32]), 2);
        let stale_error = require_error(port.execute(&stale));
        assert_eq!(stale_error.kind(), PortErrorKind::Conflict);

        zero_rank = request(EffectOperation::Apply, base, 2);
        zero_rank.contribution_hash = Digest32::new([99; 32]);
        let hash_error = require_error(port.execute(&zero_rank));
        assert_eq!(hash_error.kind(), PortErrorKind::IntegrityFailure);

        let mut noncanonical = request(EffectOperation::Apply, base, 2);
        noncanonical.canonical_contribution =
            CanonicalBody::new(b"{ \"posture_rank\": 2 }".to_vec())
                .unwrap_or_else(|error| panic!("noncanonical contribution: {error}"));
        noncanonical.contribution_hash = Digest32::new(
            *chio_core::sha256(noncanonical.canonical_contribution.as_bytes()).as_bytes(),
        );
        let canonical_error = require_error(port.execute(&noncanonical));
        assert_eq!(canonical_error.kind(), PortErrorKind::IntegrityFailure);

        let mut unbound_command = request(EffectOperation::Apply, base, 2);
        unbound_command.idempotency_key = RecordId::new("unbound-command")
            .unwrap_or_else(|error| panic!("unbound command: {error}"));
        let command_error = require_error(port.execute(&unbound_command));
        assert_eq!(command_error.kind(), PortErrorKind::InvalidData);

        let mut wrong_target = request(EffectOperation::Apply, base, 2);
        wrong_target.target = ResponseTarget::Lineage {
            lineage_id: LineageId::new("lineage-a")
                .unwrap_or_else(|error| panic!("lineage: {error}")),
        };
        let target_error = require_error(port.execute(&wrong_target));
        assert_eq!(target_error.kind(), PortErrorKind::InvalidData);
        assert_eq!(store.counts().0, 0);
        assert_eq!(store.counts().1, 0);
    }
}
