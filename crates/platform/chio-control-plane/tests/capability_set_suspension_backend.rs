use std::sync::{Arc, Mutex};

use chio_control_plane::security::adapters::effect_port::{
    CapabilitySetSuspensionBackend, ResponseEffectBackend,
};
use chio_core::canonical::canonical_json_bytes;
use chio_security_types::ports::{
    capability_set_suspension_version_hash, empty_capability_set_suspension_snapshot,
    response_affected_set_hash, ActionId, CanonicalBody, CapabilitySetSuspensionApplyRequest,
    CapabilitySetSuspensionKey, CapabilitySetSuspensionRemoveRequest,
    CapabilitySetSuspensionSnapshot, CapabilitySetSuspensionSpec, CapabilitySetSuspensionStore,
    CapabilitySuspensionDecision, CapabilitySuspensionQuery, Digest32, EffectExecutionStatus,
    EffectId, EffectOperation, EffectRequest, EffectResult, EffectResultQuery, PortError,
    PortErrorKind, PortResult, RecordId, RecordIdSet, TenantId,
};
use chio_security_types::{ResponseEffectKind, ResponseTarget};

#[derive(Default)]
struct FakeState {
    snapshot: Option<CapabilitySetSuspensionSnapshot>,
    commands: Vec<(EffectRequest, EffectResult)>,
    lose_apply_ack: bool,
    lose_remove_ack: bool,
    tamper_result: bool,
    unavailable: bool,
}

#[derive(Default)]
struct FakeSuspensionStore {
    state: Mutex<FakeState>,
}

impl FakeSuspensionStore {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state
            .lock()
            .unwrap_or_else(|error| panic!("fake suspension state poisoned: {error}"))
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

impl CapabilitySetSuspensionStore for FakeSuspensionStore {
    fn ensure_capability_set_suspensions_ready(&self) -> PortResult<()> {
        if self.state().unavailable {
            Err(PortError::unavailable())
        } else {
            Ok(())
        }
    }

    fn apply_capability_set_suspension(
        &self,
        request: &CapabilitySetSuspensionApplyRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        let mut state = self.state();
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        state.snapshot = Some(request.command.resulting_snapshot.clone());
        state.commands.push((
            request.command.request.clone(),
            request.command.result.clone(),
        ));
        if state.lose_apply_ack {
            state.lose_apply_ack = false;
            return Err(PortError::unavailable());
        }
        Ok(request.command.resulting_snapshot.clone())
    }

    fn remove_capability_set_suspension(
        &self,
        request: &CapabilitySetSuspensionRemoveRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        let mut state = self.state();
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        state.snapshot = Some(request.command.resulting_snapshot.clone());
        state.commands.push((
            request.command.request.clone(),
            request.command.result.clone(),
        ));
        if state.lose_remove_ack {
            state.lose_remove_ack = false;
            return Err(PortError::unavailable());
        }
        Ok(request.command.resulting_snapshot.clone())
    }

    fn load_capability_set_suspensions(
        &self,
        key: &CapabilitySetSuspensionKey,
    ) -> PortResult<Option<CapabilitySetSuspensionSnapshot>> {
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

    fn evaluate_capability_suspension(
        &self,
        _query: &CapabilitySuspensionQuery,
    ) -> PortResult<CapabilitySuspensionDecision> {
        Err(PortError::unavailable())
    }

    fn load_capability_set_suspension_result(
        &self,
        query: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        let state = self.state();
        if state.unavailable {
            return Err(PortError::unavailable());
        }
        let Some((request, result)) = state
            .commands
            .iter()
            .find(|(request, _)| request_matches_query(request, query))
        else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        if !request_matches_query(request, query) {
            return Err(PortError::conflict());
        }
        let mut result = result.clone();
        if state.tamper_result {
            result.resulting_version_hash = Digest32::new([99_u8; 32]);
        }
        Ok(EffectExecutionStatus::Completed { result })
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-capability-backend").unwrap_or_else(|error| panic!("tenant id: {error}"))
}

fn affected(values: &[&str]) -> RecordIdSet {
    RecordIdSet::new(
        values
            .iter()
            .map(|value| RecordId::new(*value).unwrap_or_else(|error| panic!("record id: {error}")))
            .collect(),
    )
    .unwrap_or_else(|error| panic!("affected set: {error}"))
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::new(*chio_core::sha256(bytes).as_bytes())
}

fn apply_request(affected_ids: &RecordIdSet) -> EffectRequest {
    let tenant_id = tenant();
    let affected_set_hash = response_affected_set_hash(&tenant_id, affected_ids)
        .unwrap_or_else(|error| panic!("affected set hash: {error}"));
    let key = CapabilitySetSuspensionKey {
        tenant_id: tenant_id.clone(),
        affected_set_hash,
    };
    let empty = empty_capability_set_suspension_snapshot(key)
        .unwrap_or_else(|error| panic!("empty suspension snapshot: {error}"));
    let contribution = canonical_json_bytes(&CapabilitySetSuspensionSpec {
        affected_ids: affected_ids.clone(),
    })
    .unwrap_or_else(|error| panic!("canonical contribution: {error}"));
    EffectRequest {
        tenant_id,
        action_id: ActionId::new("action-capability-backend")
            .unwrap_or_else(|error| panic!("action id: {error}")),
        plan_hash: digest(b"plan-capability-backend"),
        effect_id: EffectId::new("effect-capability-backend")
            .unwrap_or_else(|error| panic!("effect id: {error}")),
        effect_kind: ResponseEffectKind::SuspendCapabilitySet,
        target: ResponseTarget::CapabilitySet { affected_set_hash },
        plan_expires_at_unix_ms: u64::MAX,
        operation: EffectOperation::Apply,
        idempotency_key: RecordId::new("response_effect_command:capability-backend-apply")
            .unwrap_or_else(|error| panic!("idempotency key: {error}")),
        expected_version_hash: capability_set_suspension_version_hash(&empty)
            .unwrap_or_else(|error| panic!("empty version: {error}")),
        scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
            "capability-backend-worker",
        )
        .unwrap_or_else(|error| panic!("scheduler owner: {error}")),
        scheduler_fencing_token: 7,
        canonical_contribution: CanonicalBody::new(contribution.clone())
            .unwrap_or_else(|error| panic!("canonical body: {error}")),
        contribution_hash: digest(&contribution),
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
        contribution_hash: request.contribution_hash,
        scheduler_lease_owner_id: request.scheduler_lease_owner_id.clone(),
        scheduler_fencing_token: request.scheduler_fencing_token,
    }
}

fn require_error<T>(result: Result<T, PortError>) -> PortError {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn apply_and_remove_ack_loss_reconcile_across_backend_restart() {
    let store = Arc::new(FakeSuspensionStore::default());
    store.state().lose_apply_ack = true;
    let backend = CapabilitySetSuspensionBackend::new(store.clone());
    let apply = apply_request(&affected(&["capability-a", "capability-b"]));
    let applied = backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("reconcile apply ack loss: {error}"));
    assert!(applied.applied);

    let restarted = CapabilitySetSuspensionBackend::new(store.clone());
    assert_eq!(restarted.execute(&apply), Ok(applied.clone()));
    let mut remove = apply.clone();
    remove.operation = EffectOperation::Remove;
    remove.idempotency_key = RecordId::new("response_effect_command:capability-backend-remove")
        .unwrap_or_else(|error| panic!("idempotency key: {error}"));
    remove.expected_version_hash = applied.resulting_version_hash;
    store.state().lose_remove_ack = true;
    let removed = restarted
        .execute(&remove)
        .unwrap_or_else(|error| panic!("reconcile remove ack loss: {error}"));
    assert!(!removed.applied);
    assert!(store
        .state()
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.contributions.is_empty()));
}

#[test]
fn target_rebinding_outage_and_tampered_result_fail_closed() {
    let store = Arc::new(FakeSuspensionStore::default());
    let backend = CapabilitySetSuspensionBackend::new(store.clone());
    let affected_ids = affected(&["capability-a", "capability-b"]);
    let apply = apply_request(&affected_ids);
    let mut rebound = apply.clone();
    rebound.target = ResponseTarget::CapabilitySet {
        affected_set_hash: digest(b"wrong affected set"),
    };
    assert_eq!(
        require_error(backend.execute(&rebound)).kind(),
        PortErrorKind::InvalidData
    );

    store.state().unavailable = true;
    assert_eq!(
        require_error(backend.execute(&apply)).kind(),
        PortErrorKind::Unavailable
    );
    store.state().unavailable = false;
    backend
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply exact suspension: {error}"));
    store.state().tamper_result = true;
    assert_eq!(
        require_error(backend.load_result(&query(&apply))).kind(),
        PortErrorKind::IntegrityFailure
    );
}
