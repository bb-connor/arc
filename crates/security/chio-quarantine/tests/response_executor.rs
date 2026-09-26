mod response_support;

use chio_core_types::receipt::security::{ActiveDefenseEffectOutcome, ActiveDefenseReceiptBody};
use chio_quarantine::{
    build_response_plan, decode_response_record, ResponseExecutor, ResponseStateMachine,
};
use chio_security_types::ports::{
    response_affected_set_hash, ActionId, AlertDeliveryQuery, AlertDeliveryStatus,
    BlastRadiusFenceAcquisition, BlastRadiusQueryBounds, BlastRadiusRequest, BlastRadiusResult,
    BlastRadiusSeeds, BlastRadiusSnapshotMetadata, CanonicalBody, CreateOutcome, Digest32,
    EffectExecutionStatus, EffectOperation, EffectPort, EffectRequest, EffectResult,
    EffectResultQuery, IssuanceFreezeSpec, LeaseOwnerId, LineageId, OpaqueReceiptRef, PortError,
    PortResult, ReceiptAppendRequest, RecordId, RecordIdSet, ResponseCasRequest,
    ResponseEffectCasRequest, ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey,
    ResponsePlanRecord, ResponseReceiptCursor, ResponseReceiptCursorCasRequest,
    ResponseScheduledMutationCasRequest, ResponseSchedulerStore, ResponseStore, ScheduledWork,
    SchedulerClaimRequest, SchedulerHealthAckRequest, SchedulerLeaseReleaseRequest,
    SchedulerLeaseRenewRequest, SchedulerRetryRequest, SchedulerRetryState, SchedulerWorkKey,
    SecurityAlert, SecurityAlertPort, SecurityReceiptSink, SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind,
    ResponseEffectProgress, ResponseEffectSpec, ResponseMutationRecord, ResponsePlanInput,
    ResponseState, ResponseTarget, ResponseTransitionCause,
};
use response_support::{record, TestResponseStore};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

fn digest(value: u8) -> Digest32 {
    Digest32::new([value; 32])
}

fn contribution(value: u8) -> (CanonicalBody, Digest32) {
    let body = CanonicalBody::new(format!("{{\"posture_rank\":{value}}}").into_bytes())
        .unwrap_or_else(|error| panic!("contribution body: {error}"));
    let hash = Digest32::new(*chio_core_types::sha256(body.as_bytes()).as_bytes());
    (body, hash)
}

fn create_plan(store: Arc<CrashStore>) -> ResponsePlanRecord {
    create_plan_with_effects(store, vec![effect(3)])
}

fn create_plan_for_effect_kind_and_crash_boundary(
    store: Arc<CrashStore>,
    kind: ResponseEffectKind,
    crash_case: CrashCase,
) -> ResponsePlanRecord {
    let focal = effect_for_kind(kind);
    let needs_reversible_neighbor = matches!(
        crash_case,
        CrashCase::AfterResultBeforeNextEffect
            | CrashCase::DuringRollbackBeforePort
            | CrashCase::AfterRestoreBeforeResult
    ) && !kind.is_reversible();
    let mut effects = Vec::new();
    if kind == ResponseEffectKind::SuspendCapabilitySet {
        effects.push(freeze_effect());
    }
    effects.push(focal);
    if matches!(crash_case, CrashCase::AfterResultBeforeNextEffect) || needs_reversible_neighbor {
        effects.push(effect(4));
    }
    create_plan_with_effects(store, effects)
}

fn create_overlapping_plan(store: Arc<CrashStore>) -> ResponsePlanRecord {
    create_plan_with_effects(store, vec![effect(3), effect(4)])
}

fn create_freeze_then_throttle_plan(store: Arc<CrashStore>) -> ResponsePlanRecord {
    create_plan_with_effects(store, vec![freeze_effect(), effect(3)])
}

fn effect(posture_rank: u8) -> ResponseEffectSpec {
    let (canonical_contribution, contribution_hash) = contribution(posture_rank);
    ResponseEffectSpec {
        kind: ResponseEffectKind::ThrottleSession,
        target: ResponseTarget::Session {
            session_id: SessionId::new("executor-session")
                .unwrap_or_else(|error| panic!("session id: {error}")),
        },
        canonical_contribution,
        contribution_hash,
        observed_base_version_hash: digest(20),
    }
}

fn effect_for_kind(kind: ResponseEffectKind) -> ResponseEffectSpec {
    let (canonical_contribution, contribution_hash) = contribution(3);
    let target = match kind {
        ResponseEffectKind::EscalateAlert => ResponseTarget::Tenant {
            tenant_id: TenantId::new("executor-tenant")
                .unwrap_or_else(|error| panic!("tenant id: {error}")),
        },
        ResponseEffectKind::ThrottleSession
        | ResponseEffectKind::RestrictEgress
        | ResponseEffectKind::SuspendSession => ResponseTarget::Session {
            session_id: SessionId::new("executor-session")
                .unwrap_or_else(|error| panic!("session id: {error}")),
        },
        ResponseEffectKind::SuspendCapabilitySet => ResponseTarget::CapabilitySet {
            affected_set_hash: digest(41),
        },
        ResponseEffectKind::FreezeIssuance => return freeze_effect(),
    };
    ResponseEffectSpec {
        kind,
        target,
        canonical_contribution,
        contribution_hash,
        observed_base_version_hash: digest(20),
    }
}

fn freeze_effect() -> ResponseEffectSpec {
    let tenant_id = TenantId::new("executor-tenant")
        .unwrap_or_else(|error| panic!("freeze tenant id: {error}"));
    let action_id = ActionId::new("executor-action")
        .unwrap_or_else(|error| panic!("freeze action id: {error}"));
    let lineage_id = LineageId::new("executor-session")
        .unwrap_or_else(|error| panic!("freeze lineage id: {error}"));
    let affected_ids = RecordIdSet::new(vec![record("executor-session")])
        .unwrap_or_else(|error| panic!("freeze affected ids: {error}"));
    let affected_set_hash = response_affected_set_hash(&tenant_id, &affected_ids)
        .unwrap_or_else(|error| panic!("freeze affected set hash: {error:?}"));
    let query_bounds = BlastRadiusQueryBounds {
        max_depth: 4,
        max_nodes: 16,
        max_edges: 32,
    };
    let spec = IssuanceFreezeSpec {
        lineage_id: lineage_id.clone(),
        acquisition: BlastRadiusFenceAcquisition {
            request: BlastRadiusRequest {
                tenant_id,
                action_id,
                seed_ids: BlastRadiusSeeds::new(vec![record("executor-session")])
                    .unwrap_or_else(|error| panic!("freeze seeds: {error}")),
                query_bounds: query_bounds.clone(),
            },
            approved_result: BlastRadiusResult::Exact {
                metadata: BlastRadiusSnapshotMetadata {
                    query_bounds,
                    source_lineage_version: 1,
                    commit_index: 1,
                    authoritative_commit_index: 1,
                    completeness_watermark: Some(1),
                },
                sorted_affected_ids: affected_ids,
                affected_set_hash,
                graph_slice_hash: digest(44),
            },
            expires_at_unix_ms: 900,
        },
    };
    let bytes = chio_core_types::canonical_json_bytes(&spec)
        .unwrap_or_else(|error| panic!("canonical freeze effect: {error}"));
    let canonical_contribution = CanonicalBody::new(bytes.clone())
        .unwrap_or_else(|error| panic!("freeze contribution: {error}"));
    ResponseEffectSpec {
        kind: ResponseEffectKind::FreezeIssuance,
        target: ResponseTarget::Lineage { lineage_id },
        canonical_contribution,
        contribution_hash: Digest32::new(*chio_core_types::sha256(&bytes).as_bytes()),
        observed_base_version_hash: digest(21),
    }
}

fn create_plan_with_effects(
    store: Arc<CrashStore>,
    effects: Vec<ResponseEffectSpec>,
) -> ResponsePlanRecord {
    let plan = build_response_plan(ResponsePlanInput {
        action_id: ActionId::new("executor-action")
            .unwrap_or_else(|error| panic!("action id: {error}")),
        trigger_finding_id: record("executor-finding"),
        trigger_finding_hash: digest(31),
        trigger_finding_receipt_id: OpaqueReceiptRef::new("executor-finding-receipt")
            .unwrap_or_else(|error| panic!("finding receipt id: {error}")),
        tenant_id: TenantId::new("executor-tenant")
            .unwrap_or_else(|error| panic!("tenant id: {error}")),
        policy_version: record("executor-policy"),
        policy_hash: digest(32),
        affected_ids: vec![record("executor-session")],
        effects,
        ttl_ms: 900,
        created_at_unix_ms: 100,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record("executor-capability"),
            capability_digest: digest(30),
            expires_at_unix_ms: 2_000,
            executor_subject: record("executor-subject"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record("executor-submitter"),
        reason_hash: digest(31),
    })
    .unwrap_or_else(|error| panic!("build plan: {error}"));
    ResponseStateMachine::new(store)
        .create(plan)
        .unwrap_or_else(|error| panic!("create plan: {error}"))
}

fn work(record: &ResponsePlanRecord, token: u64, lease_expiry: u64) -> ScheduledWork {
    ScheduledWork {
        tenant_id: record.tenant_id.clone(),
        action_id: record.action_id.clone(),
        lease_owner_id: LeaseOwnerId::new(format!("executor-worker-{token}"))
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        lease_expires_at_unix_ms: lease_expiry,
        fencing_token: token,
    }
}

#[test]
fn applying_lease_renewal_requires_an_unexpired_application_lease_and_exact_live_fence() {
    let harness = Harness::new();
    let planned = create_plan(Arc::clone(&harness.store));
    let machine = ResponseStateMachine::new(Arc::clone(&harness.store));
    let applying = machine
        .transition(
            &planned,
            &chio_quarantine::ResponseTransitionRequest {
                expected_generation: planned.generation,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms: 110,
                applying_lease_expires_at_unix_ms: Some(500),
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("enter applying: {error}"));
    let takeover = work(&planned, 2, 900);
    harness.store.install_work(takeover.clone());

    assert!(machine
        .transition(
            &applying,
            &chio_quarantine::ResponseTransitionRequest {
                expected_generation: applying.generation,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms: 400,
                applying_lease_expires_at_unix_ms: Some(900),
                error_code: None,
            },
        )
        .is_err());

    let foreign = work(&planned, 3, 950);
    assert!(machine
        .renew_applying_lease(&applying, &foreign, 400)
        .is_err());
    assert!(machine
        .renew_applying_lease(&applying, &takeover, 500)
        .is_err());
    assert!(machine
        .renew_applying_lease(&applying, &takeover, 600)
        .is_err());

    let renewed = machine
        .renew_applying_lease(&applying, &takeover, 400)
        .unwrap_or_else(|error| panic!("renew applying lease: {error}"));
    let snapshot = decode_response_record(&renewed)
        .unwrap_or_else(|error| panic!("decode renewed response: {error}"));
    assert_eq!(snapshot.state, ResponseState::Applying);
    assert_eq!(snapshot.applying_lease_expires_at_unix_ms, Some(900));
    assert_eq!(snapshot.due_at_unix_ms, Some(900));
    assert!(matches!(
        snapshot.mutations.as_slice().last(),
        Some(ResponseMutationRecord::Transition(transition))
            if transition.from_state == ResponseState::Applying
                && transition.to_state == ResponseState::Applying
                && transition.cause == ResponseTransitionCause::ApplyingLeaseRenewed
                && transition.applying_lease_expires_at_unix_ms == Some(900)
                && transition.scheduler_lease_owner_id.as_ref() == Some(&takeover.lease_owner_id)
                && transition.scheduler_fencing_token == Some(takeover.fencing_token)
    ));
    assert!(machine
        .renew_applying_lease(&renewed, &takeover, 601)
        .is_err());
}

#[test]
fn scheduler_takeover_between_prevalidation_and_response_cas_is_rejected() {
    let harness = Harness::new();
    let planned = create_plan(Arc::clone(&harness.store));
    let machine = ResponseStateMachine::new(Arc::clone(&harness.store));
    let applying = machine
        .transition(
            &planned,
            &chio_quarantine::ResponseTransitionRequest {
                expected_generation: planned.generation,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms: 110,
                applying_lease_expires_at_unix_ms: Some(500),
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("enter applying: {error}"));
    let original = work(&planned, 1, 850);
    let takeover = work(&planned, 2, 900);
    harness.store.install_work(original.clone());
    harness
        .store
        .arm_takeover_during_applying_lease_cas(takeover.clone());

    assert!(machine
        .renew_applying_lease(&applying, &original, 400)
        .is_err());
    assert_eq!(
        harness
            .store
            .load_plan(&ResponsePlanKey {
                tenant_id: applying.tenant_id.clone(),
                action_id: applying.action_id.clone(),
            })
            .unwrap_or_else(|error| panic!("load response after takeover: {error}")),
        Some(applying.clone())
    );

    let renewed = machine
        .renew_applying_lease(&applying, &takeover, 400)
        .unwrap_or_else(|error| panic!("renew under takeover fence: {error}"));
    let snapshot = decode_response_record(&renewed)
        .unwrap_or_else(|error| panic!("decode takeover renewal: {error}"));
    assert!(matches!(
        snapshot.mutations.as_slice().last(),
        Some(ResponseMutationRecord::Transition(transition))
            if transition.scheduler_lease_owner_id.as_ref() == Some(&takeover.lease_owner_id)
                && transition.scheduler_fencing_token == Some(takeover.fencing_token)
    ));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreCrash {
    BeforeIntent,
    BeforeAppliedResult,
    BeforeRestoredResult,
    BeforeReceiptCursorCas,
    AfterReceiptCursorCas,
}

struct CrashStore {
    inner: TestResponseStore,
    crash: Mutex<Option<StoreCrash>>,
    durable_work: Mutex<Option<ScheduledWork>>,
    takeover_during_applying_lease_cas: Mutex<Option<ScheduledWork>>,
    effect_transitions: Mutex<Vec<ResponseEffectCasRequest>>,
}

impl CrashStore {
    fn new() -> Self {
        Self {
            inner: TestResponseStore::default(),
            crash: Mutex::new(None),
            durable_work: Mutex::new(None),
            takeover_during_applying_lease_cas: Mutex::new(None),
            effect_transitions: Mutex::new(Vec::new()),
        }
    }

    fn arm(&self, crash: StoreCrash) {
        *self
            .crash
            .lock()
            .unwrap_or_else(|_| panic!("crash mutex poisoned")) = Some(crash);
    }

    fn trip(&self, crash: StoreCrash) -> PortResult<()> {
        let mut armed = self.crash.lock().map_err(|_| PortError::unavailable())?;
        if *armed == Some(crash) {
            *armed = None;
            return Err(PortError::unavailable());
        }
        Ok(())
    }

    fn install_work(&self, work: ScheduledWork) {
        *self
            .durable_work
            .lock()
            .unwrap_or_else(|_| panic!("work mutex poisoned")) = Some(work);
    }

    fn arm_takeover_during_applying_lease_cas(&self, work: ScheduledWork) {
        *self
            .takeover_during_applying_lease_cas
            .lock()
            .unwrap_or_else(|_| panic!("takeover mutex poisoned")) = Some(work);
    }

    fn effect_transition_id(&self, state: &str) -> RecordId {
        self.effect_transitions
            .lock()
            .unwrap_or_else(|_| panic!("effect transition mutex poisoned"))
            .iter()
            .find(|request| request.record.state.as_str() == state)
            .map(|request| request.transition_id.clone())
            .unwrap_or_else(|| panic!("{state} effect transition missing"))
    }
}

impl ResponseStore for CrashStore {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        self.inner.load_plan(key)
    }

    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome> {
        self.inner.create(record)
    }

    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord> {
        self.inner.compare_and_swap(request)
    }

    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        self.inner.load_effect(key)
    }

    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome> {
        self.trip(StoreCrash::BeforeIntent)?;
        self.inner.persist_effect(record)
    }

    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord> {
        match request.record.state.as_str() {
            "applied" => self.trip(StoreCrash::BeforeAppliedResult)?,
            "restored" => self.trip(StoreCrash::BeforeRestoredResult)?,
            _ => {}
        }
        let updated = self.inner.compare_and_swap_effect(request)?;
        self.effect_transitions
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(request.clone());
        Ok(updated)
    }

    fn load_receipt_cursor(
        &self,
        key: &ResponsePlanKey,
    ) -> PortResult<Option<ResponseReceiptCursor>> {
        self.inner.load_receipt_cursor(key)
    }

    fn initialize_receipt_cursor(
        &self,
        cursor: &ResponseReceiptCursor,
    ) -> PortResult<CreateOutcome> {
        self.inner.initialize_receipt_cursor(cursor)
    }

    fn compare_and_swap_receipt_cursor(
        &self,
        request: &ResponseReceiptCursorCasRequest,
    ) -> PortResult<ResponseReceiptCursor> {
        self.trip(StoreCrash::BeforeReceiptCursorCas)?;
        let updated = self.inner.compare_and_swap_receipt_cursor(request)?;
        self.trip(StoreCrash::AfterReceiptCursorCas)?;
        Ok(updated)
    }

    fn claim_due(&self, request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>> {
        self.inner.claim_due(request)
    }
}

impl ResponseSchedulerStore for CrashStore {
    fn load_retry(&self, _key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>> {
        Ok(None)
    }

    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()> {
        let current = self
            .durable_work
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if current.as_ref() == Some(work) {
            Ok(())
        } else {
            Err(PortError::conflict())
        }
    }

    fn compare_and_swap_scheduled_mutation(
        &self,
        request: &ResponseScheduledMutationCasRequest,
    ) -> PortResult<ResponsePlanRecord> {
        let mut current = self
            .durable_work
            .lock()
            .map_err(|_| PortError::unavailable())?;
        if current.as_ref() != Some(&request.work) {
            return Err(PortError::conflict());
        }
        if let Some(takeover) = self
            .takeover_during_applying_lease_cas
            .lock()
            .map_err(|_| PortError::unavailable())?
            .take()
        {
            *current = Some(takeover);
        }
        if current.as_ref() != Some(&request.work) {
            return Err(PortError::conflict());
        }
        self.inner.compare_and_swap(&ResponseCasRequest {
            record: request.candidate.clone(),
            expected_generation: request.current.generation,
            transition_id: request.transition_id.clone(),
        })
    }

    fn renew_lease(&self, request: &SchedulerLeaseRenewRequest) -> PortResult<ScheduledWork> {
        self.validate_lease(&request.work)?;
        let renewed = ScheduledWork {
            lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
            ..request.work.clone()
        };
        self.install_work(renewed.clone());
        Ok(renewed)
    }

    fn record_retry(&self, _request: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState> {
        Err(PortError::unavailable())
    }

    fn acknowledge_health_event(
        &self,
        _request: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState> {
        Err(PortError::unavailable())
    }

    fn release_lease(&self, request: &SchedulerLeaseReleaseRequest) -> PortResult<()> {
        self.validate_lease(&request.work)?;
        *self
            .durable_work
            .lock()
            .map_err(|_| PortError::unavailable())? = None;
        Ok(())
    }
}

#[derive(Default)]
struct EffectState {
    replay: BTreeMap<String, (EffectRequest, EffectResult)>,
    queries: Vec<EffectResultQuery>,
    installed: BTreeMap<String, Digest32>,
    apply_mutations: usize,
    remove_mutations: usize,
    apply_order: Vec<String>,
    remove_order: Vec<String>,
    fail_remove: bool,
    fail_remove_after_commit_once: bool,
    query_fault: Option<QueryFault>,
}

#[derive(Clone, Copy)]
enum QueryFault {
    Unknown,
    Unavailable,
}

#[derive(Default)]
struct IdempotentEffects {
    state: Mutex<EffectState>,
}

impl IdempotentEffects {
    fn state(&self) -> MutexGuard<'_, EffectState> {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("effect mutex poisoned"))
    }

    fn mutation_counts(&self) -> (usize, usize) {
        let state = self.state();
        (state.apply_mutations, state.remove_mutations)
    }

    fn fail_remove(&self) {
        self.state().fail_remove = true;
    }

    fn fail_remove_after_commit_once(&self) {
        self.state().fail_remove_after_commit_once = true;
    }

    fn mutation_order(&self) -> (Vec<String>, Vec<String>) {
        let state = self.state();
        (state.apply_order.clone(), state.remove_order.clone())
    }

    fn set_query_fault(&self, fault: QueryFault) {
        self.state().query_fault = Some(fault);
    }

    fn contract_calls(&self) -> (Vec<EffectRequest>, Vec<EffectResultQuery>) {
        let state = self.state();
        let requests = state
            .replay
            .values()
            .map(|(request, _)| request.clone())
            .collect();
        (requests, state.queries.clone())
    }
}

impl EffectPort for IdempotentEffects {
    fn ensure_effects_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn execute(&self, request: &EffectRequest) -> PortResult<EffectResult> {
        let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
        if let Some((stored_request, result)) = state.replay.get(request.idempotency_key.as_str()) {
            if stored_request != request {
                return Err(PortError::conflict());
            }
            return Ok(result.clone());
        }
        let result = match request.operation {
            EffectOperation::Apply => {
                let resulting_version_hash = digest(70);
                state.installed.insert(
                    request.effect_id.as_str().to_owned(),
                    resulting_version_hash,
                );
                state.apply_mutations = state.apply_mutations.saturating_add(1);
                state
                    .apply_order
                    .push(request.effect_id.as_str().to_owned());
                EffectResult {
                    effect_id: request.effect_id.clone(),
                    resulting_version_hash,
                    applied: true,
                }
            }
            EffectOperation::Remove => {
                if state.fail_remove {
                    return Err(PortError::unavailable());
                }
                let installed = state
                    .installed
                    .get(request.effect_id.as_str())
                    .ok_or_else(PortError::conflict)?;
                if installed != &request.expected_version_hash {
                    return Err(PortError::conflict());
                }
                state.installed.remove(request.effect_id.as_str());
                state.remove_mutations = state.remove_mutations.saturating_add(1);
                state
                    .remove_order
                    .push(request.effect_id.as_str().to_owned());
                EffectResult {
                    effect_id: request.effect_id.clone(),
                    resulting_version_hash: digest(20),
                    applied: false,
                }
            }
        };
        let fail_after_commit = request.operation == EffectOperation::Remove
            && std::mem::take(&mut state.fail_remove_after_commit_once);
        state.replay.insert(
            request.idempotency_key.as_str().to_owned(),
            (request.clone(), result.clone()),
        );
        if fail_after_commit {
            return Err(PortError::unavailable());
        }
        Ok(result)
    }

    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
        state.queries.push(query.clone());
        match state.query_fault {
            Some(QueryFault::Unknown) => return Ok(EffectExecutionStatus::Unknown),
            Some(QueryFault::Unavailable) => return Err(PortError::unavailable()),
            None => {}
        }
        let Some((request, result)) = state.replay.get(query.idempotency_key.as_str()) else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        if request.tenant_id != query.tenant_id
            || request.action_id != query.action_id
            || request.plan_hash != query.plan_hash
            || request.effect_id != query.effect_id
            || request.effect_kind != query.effect_kind
            || request.target != query.target
            || request.plan_expires_at_unix_ms != query.plan_expires_at_unix_ms
            || request.operation != query.operation
            || request.expected_version_hash != query.expected_version_hash
            || request.contribution_hash != query.contribution_hash
        {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: result.clone(),
        })
    }
}

#[test]
fn executor_effect_contract_binds_plan_identity_and_typed_route_on_apply_and_remove() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let planned_snapshot = decode_response_record(&planned)
        .unwrap_or_else(|error| panic!("decode planned response: {error}"));
    let effect = planned_snapshot
        .plan
        .effects
        .as_slice()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("response effect missing"));

    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("effect contract apply failed: {error}"));
    let rollback_work = work(&active, 2, 1_500);
    harness.store.install_work(rollback_work.clone());
    executor
        .execute(&active, &rollback_work, 1_000)
        .unwrap_or_else(|error| panic!("effect contract rollback failed: {error}"));

    let (requests, queries) = harness.effects.contract_calls();
    assert_eq!(requests.len(), 2);
    assert_eq!(queries.len(), 2);
    for request in &requests {
        assert_eq!(request.tenant_id, planned_snapshot.plan.tenant_id);
        assert_eq!(request.action_id, planned_snapshot.plan.action_id);
        assert_eq!(request.plan_hash, planned_snapshot.plan.plan_hash);
        assert_eq!(request.effect_id, effect.effect_id);
        assert_eq!(request.effect_kind, effect.kind);
        assert_eq!(request.target, effect.target);
        assert_eq!(
            request.plan_expires_at_unix_ms,
            planned_snapshot.plan.expires_at_unix_ms
        );
        let query = queries
            .iter()
            .find(|query| {
                query.operation == request.operation
                    && query.idempotency_key == request.idempotency_key
            })
            .unwrap_or_else(|| panic!("matching effect result query missing"));
        assert_eq!(query.tenant_id, request.tenant_id);
        assert_eq!(query.action_id, request.action_id);
        assert_eq!(query.plan_hash, request.plan_hash);
        assert_eq!(query.effect_id, request.effect_id);
        assert_eq!(query.effect_kind, request.effect_kind);
        assert_eq!(query.target, request.target);
        assert_eq!(
            query.plan_expires_at_unix_ms,
            request.plan_expires_at_unix_ms
        );
        assert_eq!(query.contribution_hash, request.contribution_hash);
    }
}

#[test]
fn effect_receipts_bind_the_effect_cas_transition_that_produced_the_evidence() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("truthful receipt apply failed: {error}"));
    let rollback_work = work(&active, 2, 1_500);
    harness.store.install_work(rollback_work.clone());
    executor
        .execute(&active, &rollback_work, 1_000)
        .unwrap_or_else(|error| panic!("truthful receipt rollback failed: {error}"));

    let applied_transition_id = harness.store.effect_transition_id("applied");
    let restored_transition_id = harness.store.effect_transition_id("restored");
    let receipts = harness.receipts.receipts();
    let transition_generations = receipts
        .iter()
        .filter_map(|receipt| {
            let ActiveDefenseReceiptBody::EffectTransition(body) = receipt else {
                return None;
            };
            Some((&body.outcome, body.generation))
        })
        .collect::<Vec<_>>();
    assert!(transition_generations.iter().any(|(outcome, generation)| {
        matches!(outcome, ActiveDefenseEffectOutcome::Requested) && *generation == 1
    }));
    assert!(transition_generations.iter().any(|(outcome, generation)| {
        matches!(outcome, ActiveDefenseEffectOutcome::Applied { .. }) && *generation == 2
    }));
    assert!(transition_generations.iter().any(|(outcome, generation)| {
        matches!(outcome, ActiveDefenseEffectOutcome::RollbackRequested) && *generation == 3
    }));
    assert!(transition_generations.iter().any(|(outcome, generation)| {
        matches!(outcome, ActiveDefenseEffectOutcome::Restored { .. }) && *generation == 4
    }));
    let applied_receipts: Vec<_> = receipts
        .iter()
        .filter(|receipt| {
            matches!(
                receipt,
                ActiveDefenseReceiptBody::EffectTransition(body)
                    if matches!(body.outcome, ActiveDefenseEffectOutcome::Applied { .. })
            )
        })
        .collect();
    let restored_receipts: Vec<_> = receipts
        .iter()
        .filter(|receipt| {
            matches!(
                receipt,
                ActiveDefenseReceiptBody::EffectTransition(body)
                    if matches!(body.outcome, ActiveDefenseEffectOutcome::Restored { .. })
            )
        })
        .collect();

    assert!(!applied_receipts.is_empty());
    assert!(!restored_receipts.is_empty());
    assert!(applied_receipts
        .iter()
        .all(|receipt| receipt.header().transition_id == applied_transition_id));
    assert!(restored_receipts
        .iter()
        .all(|receipt| receipt.header().transition_id == restored_transition_id));

    let requests = harness.receipts.requests();
    for request in &requests {
        assert_ne!(
            request.evidence_id.as_str(),
            request.transition_id.as_str(),
            "receipt evidence id must never replace the persisted transition id"
        );
        let receipt: ActiveDefenseReceiptBody =
            serde_json::from_slice(request.canonical_body.as_bytes())
                .unwrap_or_else(|error| panic!("decode receipt request: {error}"));
        assert_eq!(request.transition_id, receipt.header().transition_id);
        assert_eq!(
            request.occurred_at_unix_ms,
            receipt.header().occurred_at_unix_ms
        );
    }
    assert!(requests.iter().any(|request| {
        request.transition_id == applied_transition_id && request.occurred_at_unix_ms == 110
    }));
    assert!(requests.iter().any(|request| {
        request.transition_id == restored_transition_id && request.occurred_at_unix_ms == 1_000
    }));
}

#[test]
fn active_execution_evidence_binds_exact_response_and_effect_transitions() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_overlapping_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("active evidence apply failed: {error}"));
    let snapshot = decode_response_record(&active)
        .unwrap_or_else(|error| panic!("decode active evidence response: {error}"));

    let evidence = executor
        .active_execution_evidence(&active)
        .unwrap_or_else(|error| panic!("build active execution evidence: {error}"));

    assert_eq!(evidence.tenant_id, snapshot.plan.tenant_id);
    assert_eq!(evidence.action_id, snapshot.plan.action_id);
    assert_eq!(evidence.plan_hash, snapshot.plan.plan_hash);
    assert_eq!(evidence.response_generation, active.generation);
    assert_eq!(evidence.response_body_hash, active.body_hash);
    assert!(evidence.failure.is_none());
    assert_eq!(
        evidence.response_transition_id,
        snapshot
            .mutations
            .as_slice()
            .last()
            .unwrap_or_else(|| panic!("active response transition missing"))
            .transition_id()
            .clone()
    );
    assert_eq!(evidence.effects.len(), snapshot.plan.effects.len());
    for (effect_evidence, effect) in evidence
        .effects
        .iter()
        .zip(snapshot.plan.effects.as_slice())
    {
        assert_eq!(effect_evidence.effect_id, effect.effect_id);
        assert_eq!(effect_evidence.generation, 1);
        assert_eq!(effect_evidence.resulting_version_hash, digest(70));
        let persisted = harness
            .store
            .load_effect(&ResponseEffectKey {
                tenant_id: snapshot.plan.tenant_id.clone(),
                effect_id: effect.effect_id.clone(),
            })
            .unwrap_or_else(|error| panic!("load evidence effect: {error}"))
            .unwrap_or_else(|| panic!("evidence effect missing"));
        let transition = harness
            .store
            .effect_transitions
            .lock()
            .unwrap_or_else(|_| panic!("effect transition mutex poisoned"))
            .iter()
            .find(|request| request.record == persisted)
            .map(|request| request.transition_id.clone())
            .unwrap_or_else(|| panic!("persisted effect transition missing"));
        assert_eq!(effect_evidence.transition_id, transition);
    }
}

#[derive(Default)]
struct ReceiptState {
    receipts: Vec<ActiveDefenseReceiptBody>,
    requests: Vec<ReceiptAppendRequest>,
    fail_effect_state: Option<String>,
}

fn effect_outcome_state(receipt: &ActiveDefenseReceiptBody) -> Option<&'static str> {
    let ActiveDefenseReceiptBody::EffectTransition(body) = receipt else {
        return None;
    };
    Some(match &body.outcome {
        ActiveDefenseEffectOutcome::Planned => "planned",
        ActiveDefenseEffectOutcome::Requested => "apply_requested",
        ActiveDefenseEffectOutcome::Applied { .. } => "applied",
        ActiveDefenseEffectOutcome::ApplyFailed { .. } => "apply_failed",
        ActiveDefenseEffectOutcome::RollbackRequested => "rollback_requested",
        ActiveDefenseEffectOutcome::Restored { .. } => "restored",
        ActiveDefenseEffectOutcome::RollbackFailed { .. } => "rollback_failed",
        ActiveDefenseEffectOutcome::NoRollbackRequired => "no_rollback_required",
    })
}

#[derive(Default)]
struct TestReceipts {
    state: Mutex<ReceiptState>,
}

impl TestReceipts {
    fn fail_once_on_effect_state(&self, state: &str) {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("receipt mutex poisoned"))
            .fail_effect_state = Some(state.to_owned());
    }

    fn receipts(&self) -> Vec<ActiveDefenseReceiptBody> {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("receipt mutex poisoned"))
            .receipts
            .clone()
    }

    fn requests(&self) -> Vec<ReceiptAppendRequest> {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("receipt mutex poisoned"))
            .requests
            .clone()
    }
}

impl SecurityReceiptSink for TestReceipts {
    fn ensure_receipts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        let receipt: ActiveDefenseReceiptBody =
            serde_json::from_slice(request.canonical_body.as_bytes())
                .map_err(|_| PortError::invalid_data())?;
        if receipt
            .body_digest()
            .map_err(|_| PortError::invalid_data())?
            != request.body_hash
            || receipt
                .evidence_id()
                .map_err(|_| PortError::invalid_data())?
                != request.evidence_id
            || receipt.header().tenant_id != request.tenant_id
            || receipt.header().transition_id != request.transition_id
            || receipt.header().occurred_at_unix_ms != request.occurred_at_unix_ms
            || receipt.kind().as_str() != request.evidence_type.as_str()
            || request.evidence_id.as_str() == request.transition_id.as_str()
        {
            return Err(PortError::invalid_data());
        }
        let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
        let effect_state = effect_outcome_state(&receipt);
        let lose_ack = state
            .fail_effect_state
            .as_deref()
            .is_some_and(|expected| effect_state == Some(expected));
        if lose_ack {
            state.fail_effect_state = None;
        }
        if !state.receipts.iter().any(|stored| stored == &receipt) {
            state.receipts.push(receipt);
        }
        match state
            .requests
            .iter()
            .find(|stored| stored.evidence_id == request.evidence_id)
        {
            Some(stored) if stored != request => return Err(PortError::conflict()),
            Some(_) => {}
            None => state.requests.push(request.clone()),
        }
        if lose_ack {
            return Err(PortError::unavailable());
        }
        Ok(request.evidence_id.clone())
    }
}

#[derive(Default)]
struct TestAlerts {
    alerts: Mutex<BTreeMap<String, SecurityAlert>>,
}

impl TestAlerts {
    fn count(&self) -> usize {
        self.alerts
            .lock()
            .unwrap_or_else(|_| panic!("alert mutex poisoned"))
            .len()
    }

    fn alerts(&self) -> Vec<SecurityAlert> {
        self.alerts
            .lock()
            .unwrap_or_else(|_| panic!("alert mutex poisoned"))
            .values()
            .cloned()
            .collect()
    }
}

impl SecurityAlertPort for TestAlerts {
    fn ensure_alerts_ready(&self) -> PortResult<()> {
        Ok(())
    }

    fn page(&self, alert: &SecurityAlert) -> PortResult<AlertDeliveryStatus> {
        let mut alerts = self.alerts.lock().map_err(|_| PortError::unavailable())?;
        match alerts.get(alert.idempotency_key.as_str()) {
            Some(existing) if existing != alert => return Err(PortError::conflict()),
            Some(_) => {}
            None => {
                alerts.insert(alert.idempotency_key.as_str().to_owned(), alert.clone());
            }
        }
        Ok(AlertDeliveryStatus::Delivered {
            attempts: 1,
            delivered_at_unix_ms: alert.occurred_at_unix_ms,
        })
    }

    fn load_delivery(&self, query: &AlertDeliveryQuery) -> PortResult<Option<AlertDeliveryStatus>> {
        let alerts = self.alerts.lock().map_err(|_| PortError::unavailable())?;
        match alerts.get(query.alert.idempotency_key.as_str()) {
            Some(existing) if existing == &query.alert => {
                Ok(Some(AlertDeliveryStatus::Delivered {
                    attempts: 1,
                    delivered_at_unix_ms: query.alert.occurred_at_unix_ms,
                }))
            }
            Some(_) => Err(PortError::conflict()),
            None => Ok(None),
        }
    }
}

struct Harness {
    store: Arc<CrashStore>,
    effects: Arc<IdempotentEffects>,
    receipts: Arc<TestReceipts>,
    alerts: Arc<TestAlerts>,
}

impl Harness {
    fn new() -> Self {
        Self {
            store: Arc::new(CrashStore::new()),
            effects: Arc::new(IdempotentEffects::default()),
            receipts: Arc::new(TestReceipts::default()),
            alerts: Arc::new(TestAlerts::default()),
        }
    }

    fn executor(
        &self,
    ) -> ResponseExecutor<CrashStore, IdempotentEffects, TestReceipts, TestAlerts> {
        ResponseExecutor::new(
            Arc::clone(&self.store),
            Arc::clone(&self.effects),
            Arc::clone(&self.receipts),
            Arc::clone(&self.alerts),
        )
    }

    fn load(&self, record: &ResponsePlanRecord) -> ResponsePlanRecord {
        self.store
            .load_plan(&ResponsePlanKey {
                tenant_id: record.tenant_id.clone(),
                action_id: record.action_id.clone(),
            })
            .unwrap_or_else(|error| panic!("load plan: {error}"))
            .unwrap_or_else(|| panic!("plan missing"))
    }
}

#[derive(Clone, Copy, Debug)]
enum CrashCase {
    BeforeIntentPersistence,
    AfterIntentBeforePort,
    AfterPortBeforeResult,
    AfterResultBeforeNextEffect,
    DuringRollbackBeforePort,
    AfterRestoreBeforeResult,
}

#[test]
fn freeze_apply_yields_before_the_next_effect() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_freeze_then_throttle_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());

    let after_freeze = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("apply freeze boundary: {error}"));
    let after_freeze_snapshot = decode_response_record(&after_freeze)
        .unwrap_or_else(|error| panic!("decode freeze boundary: {error}"));
    let [freeze, downstream] = after_freeze_snapshot.plan.effects.as_slice() else {
        panic!("freeze boundary plan shape changed");
    };
    assert_eq!(after_freeze_snapshot.state, ResponseState::Applying);
    assert_eq!(
        after_freeze_snapshot.effect_progress(&freeze.effect_id),
        Some(ResponseEffectProgress::Applied)
    );
    assert_eq!(
        after_freeze_snapshot.effect_progress(&downstream.effect_id),
        Some(ResponseEffectProgress::Planned)
    );
    assert_eq!(harness.effects.mutation_counts().0, 1);

    let active = executor
        .execute(&after_freeze, &apply_work, 111)
        .unwrap_or_else(|error| panic!("resume after freeze maintenance boundary: {error}"));
    assert_eq!(
        decode_response_record(&active)
            .unwrap_or_else(|error| panic!("decode resumed response: {error}"))
            .state,
        ResponseState::Active
    );
    assert_eq!(harness.effects.mutation_counts().0, 2);
}

#[test]
fn reconciled_freeze_apply_yields_before_the_next_effect() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_freeze_then_throttle_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    harness.store.arm(StoreCrash::BeforeAppliedResult);
    assert!(executor.execute(&planned, &apply_work, 110).is_err());
    assert_eq!(harness.effects.mutation_counts().0, 1);

    let pending = harness.load(&planned);
    let takeover_work = work(&pending, 2, 1_500);
    harness.store.install_work(takeover_work.clone());
    let after_reconciliation = executor
        .execute(&pending, &takeover_work, 900)
        .unwrap_or_else(|error| panic!("reconcile freeze apply: {error}"));
    let reconciled_snapshot = decode_response_record(&after_reconciliation)
        .unwrap_or_else(|error| panic!("decode reconciled freeze: {error}"));
    let [freeze, downstream] = reconciled_snapshot.plan.effects.as_slice() else {
        panic!("reconciled freeze plan shape changed");
    };
    assert_eq!(reconciled_snapshot.state, ResponseState::Applying);
    assert_eq!(
        reconciled_snapshot.effect_progress(&freeze.effect_id),
        Some(ResponseEffectProgress::Applied)
    );
    assert_eq!(
        reconciled_snapshot.effect_progress(&downstream.effect_id),
        Some(ResponseEffectProgress::Planned)
    );
    assert_eq!(harness.effects.mutation_counts().0, 1);
}

#[test]
fn executor_every_effect_kind_six_boundary_crash_matrix_converges_exactly_once() {
    for effect_kind in [
        ResponseEffectKind::EscalateAlert,
        ResponseEffectKind::ThrottleSession,
        ResponseEffectKind::RestrictEgress,
        ResponseEffectKind::SuspendSession,
        ResponseEffectKind::SuspendCapabilitySet,
        ResponseEffectKind::FreezeIssuance,
    ] {
        for crash_case in [
            CrashCase::BeforeIntentPersistence,
            CrashCase::AfterIntentBeforePort,
            CrashCase::AfterPortBeforeResult,
            CrashCase::AfterResultBeforeNextEffect,
            CrashCase::DuringRollbackBeforePort,
            CrashCase::AfterRestoreBeforeResult,
        ] {
            let harness = Harness::new();
            let executor = harness.executor();
            let planned = create_plan_for_effect_kind_and_crash_boundary(
                Arc::clone(&harness.store),
                effect_kind,
                crash_case,
            );
            let planned_snapshot = decode_response_record(&planned)
                .unwrap_or_else(|error| panic!("decode planned crash matrix response: {error}"));
            let expected_apply_count = planned_snapshot.plan.effects.as_slice().len();
            let expected_remove_count = planned_snapshot
                .plan
                .effects
                .as_slice()
                .iter()
                .filter(|effect| effect.kind.is_reversible())
                .count();
            let apply_work = work(&planned, 1, 900);
            harness.store.install_work(apply_work.clone());

            match crash_case {
                CrashCase::BeforeIntentPersistence => harness.store.arm(StoreCrash::BeforeIntent),
                CrashCase::AfterIntentBeforePort => harness
                    .receipts
                    .fail_once_on_effect_state("apply_requested"),
                CrashCase::AfterPortBeforeResult => {
                    harness.store.arm(StoreCrash::BeforeAppliedResult)
                }
                CrashCase::AfterResultBeforeNextEffect => {
                    harness.receipts.fail_once_on_effect_state("applied")
                }
                CrashCase::DuringRollbackBeforePort | CrashCase::AfterRestoreBeforeResult => {}
            }

            let first_apply = executor.execute(&planned, &apply_work, 110);
            if matches!(
                crash_case,
                CrashCase::BeforeIntentPersistence
                    | CrashCase::AfterIntentBeforePort
                    | CrashCase::AfterPortBeforeResult
                    | CrashCase::AfterResultBeforeNextEffect
            ) {
                assert!(
                    first_apply.is_err(),
                    "effect {effect_kind:?}, crash {crash_case:?} did not trip"
                );
            }
            let mut active = if first_apply.is_ok() {
                first_apply.unwrap_or_else(|error| panic!("apply failed: {error}"))
            } else {
                harness.load(&planned)
            };
            for _ in 0..3 {
                if decode_response_record(&active)
                    .unwrap_or_else(|error| panic!("decode applying recovery: {error}"))
                    .state
                    == ResponseState::Active
                {
                    break;
                }
                active = executor
                    .execute(&active, &apply_work, 111)
                    .unwrap_or_else(|error| panic!("apply recovery failed: {error}"));
            }
            assert_eq!(
                decode_response_record(&active)
                    .unwrap_or_else(|error| panic!("decode active: {error}"))
                    .state,
                ResponseState::Active,
                "effect {effect_kind:?}, crash {crash_case:?}"
            );
            assert_eq!(
                harness.effects.mutation_counts().0,
                expected_apply_count,
                "effect {effect_kind:?}, crash {crash_case:?}"
            );

            let rollback_work = work(&active, 2, 1_500);
            harness.store.install_work(rollback_work.clone());
            match crash_case {
                CrashCase::DuringRollbackBeforePort if expected_remove_count > 0 => harness
                    .receipts
                    .fail_once_on_effect_state("rollback_requested"),
                CrashCase::AfterRestoreBeforeResult if expected_remove_count > 0 => {
                    harness.store.arm(StoreCrash::BeforeRestoredResult)
                }
                _ => {}
            }
            let first_rollback = executor.execute(&active, &rollback_work, 1_000);
            if expected_remove_count > 0
                && matches!(
                    crash_case,
                    CrashCase::DuringRollbackBeforePort | CrashCase::AfterRestoreBeforeResult
                )
            {
                assert!(
                    first_rollback.is_err(),
                    "effect {effect_kind:?}, crash {crash_case:?} did not trip"
                );
            }
            let mut lifted = if first_rollback.is_ok() {
                first_rollback.unwrap_or_else(|error| panic!("rollback failed: {error}"))
            } else {
                harness.load(&active)
            };
            for _ in 0..2 {
                if decode_response_record(&lifted)
                    .unwrap_or_else(|error| panic!("decode rollback recovery: {error}"))
                    .state
                    == ResponseState::Lifted
                {
                    break;
                }
                lifted = executor
                    .execute(&lifted, &rollback_work, 1_001)
                    .unwrap_or_else(|error| panic!("rollback recovery failed: {error}"));
            }
            assert_eq!(
                decode_response_record(&lifted)
                    .unwrap_or_else(|error| panic!("decode lifted: {error}"))
                    .state,
                ResponseState::Lifted,
                "effect {effect_kind:?}, crash {crash_case:?}"
            );
            assert_eq!(
                harness.effects.mutation_counts(),
                (expected_apply_count, expected_remove_count),
                "effect {effect_kind:?}, crash {crash_case:?}"
            );
            if !effect_kind.is_reversible() {
                let alert_effect_id = planned_snapshot.plan.effects.as_slice()[0]
                    .effect_id
                    .as_str();
                assert!(
                    harness
                        .effects
                        .state()
                        .installed
                        .contains_key(alert_effect_id),
                    "nonreversible alert evidence must not be rolled back"
                );
            }
        }
    }
}

#[test]
fn executor_overlap_removes_contributions_in_reverse_application_order() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_overlapping_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("overlap apply failed: {error}"));
    let snapshot = decode_response_record(&active)
        .unwrap_or_else(|error| panic!("decode overlap active: {error}"));
    assert_eq!(snapshot.state, ResponseState::Active);
    let expected_apply_order: Vec<String> = snapshot
        .plan
        .effects
        .as_slice()
        .iter()
        .map(|effect| effect.effect_id.as_str().to_owned())
        .collect();
    let expected_remove_order: Vec<String> = expected_apply_order.iter().rev().cloned().collect();
    assert_eq!(
        harness.effects.mutation_order(),
        (expected_apply_order.clone(), Vec::new())
    );

    let rollback_work = work(&active, 2, 1_500);
    harness.store.install_work(rollback_work.clone());
    let lifted = executor
        .execute(&active, &rollback_work, 1_000)
        .unwrap_or_else(|error| panic!("overlap rollback failed: {error}"));
    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("decode overlap lifted: {error}"))
            .state,
        ResponseState::Lifted
    );
    assert_eq!(
        harness.effects.mutation_order(),
        (expected_apply_order, expected_remove_order)
    );
    assert_eq!(harness.effects.mutation_counts(), (2, 2));
}

#[test]
fn receipt_truth_rollback_failure_never_reports_lifted() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("apply failed: {error}"));
    harness.effects.fail_remove();
    let rollback_work = work(&active, 2, 1_500);
    harness.store.install_work(rollback_work.clone());
    let partial = executor
        .execute(&active, &rollback_work, 1_000)
        .unwrap_or_else(|error| panic!("rollback failure handling failed: {error}"));
    let snapshot = decode_response_record(&partial)
        .unwrap_or_else(|error| panic!("decode partial rollback: {error}"));
    assert_eq!(snapshot.state, ResponseState::RollbackPartial);
    assert!(snapshot.operator_page_required);
    assert_eq!(harness.alerts.count(), 1);
    let alert = harness
        .alerts
        .alerts()
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("rollback alert missing"));
    let mutation = snapshot
        .mutations
        .as_slice()
        .last()
        .unwrap_or_else(|| panic!("rollback transition missing"));
    assert_eq!(alert.occurred_at_unix_ms, mutation.occurred_at_unix_ms());
    assert_ne!(alert.event_id, alert.idempotency_key);
    assert_eq!(alert.evidence_hash, partial.body_hash);
    let receipts = harness.receipts.receipts();
    assert!(receipts.iter().any(|receipt| {
        matches!(
            receipt,
            ActiveDefenseReceiptBody::ResponseStateTransition(body)
                if body.to_state == ResponseState::RollbackPartial
        )
    }));
    assert!(!receipts.iter().any(|receipt| {
        matches!(
            receipt,
            ActiveDefenseReceiptBody::LiftRollbackCompletion(body)
                if body.final_state == ResponseState::Lifted
        )
    }));
}

#[test]
fn rollback_retry_reconciles_the_prior_attempt_before_issuing_another_remove() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("apply failed: {error}"));

    harness.effects.fail_remove_after_commit_once();
    let first_rollback_work = work(&active, 2, 1_500);
    harness.store.install_work(first_rollback_work.clone());
    let partial = executor
        .execute(&active, &first_rollback_work, 1_000)
        .unwrap_or_else(|error| panic!("record rollback acknowledgement loss: {error}"));
    assert_eq!(
        decode_response_record(&partial)
            .unwrap_or_else(|error| panic!("decode partial rollback: {error}"))
            .state,
        ResponseState::RollbackPartial
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 1));

    let retry_work = work(&partial, 3, 2_000);
    harness.store.install_work(retry_work.clone());
    let lifted = executor
        .execute(&partial, &retry_work, 1_100)
        .unwrap_or_else(|error| panic!("reconcile completed prior remove: {error}"));
    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("decode lifted response: {error}"))
            .state,
        ResponseState::Lifted
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 1));
    assert_eq!(harness.effects.mutation_order().1.len(), 1);
}

#[test]
fn executor_crash_stale_takeover_pending_apply_never_calls_effect_port() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let first_work = work(&planned, 1, 900);
    harness.store.install_work(first_work.clone());
    harness
        .receipts
        .fail_once_on_effect_state("apply_requested");
    assert!(executor.execute(&planned, &first_work, 110).is_err());
    assert_eq!(harness.effects.mutation_counts(), (0, 0));

    let takeover_work = work(&planned, 2, 900);
    harness.store.install_work(takeover_work.clone());
    let pending = harness.load(&planned);
    assert!(executor.execute(&pending, &first_work, 111).is_err());
    assert_eq!(harness.effects.mutation_counts(), (0, 0));

    let reconciled = harness.load(&planned);
    let active = executor
        .execute(&reconciled, &takeover_work, 112)
        .unwrap_or_else(|error| panic!("takeover apply failed: {error}"));
    assert_eq!(
        decode_response_record(&active)
            .unwrap_or_else(|error| panic!("decode active: {error}"))
            .state,
        ResponseState::Active
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 0));
}

#[test]
fn receipt_cursor_ack_loss_reloads_exact_committed_head() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let work = work(&planned, 1, 900);
    harness.store.install_work(work.clone());
    harness.store.arm(StoreCrash::AfterReceiptCursorCas);

    let active = executor
        .execute(&planned, &work, 110)
        .unwrap_or_else(|error| panic!("cursor ack-loss recovery failed: {error}"));

    assert_eq!(
        decode_response_record(&active)
            .unwrap_or_else(|error| panic!("decode active response: {error}"))
            .state,
        ResponseState::Active
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 0));
}

#[test]
fn receipt_cursor_cas_failure_retries_without_running_effect_early() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let work = work(&planned, 1, 900);
    harness.store.install_work(work.clone());
    harness.store.arm(StoreCrash::BeforeReceiptCursorCas);

    assert!(executor.execute(&planned, &work, 110).is_err());
    assert_eq!(harness.effects.mutation_counts(), (0, 0));

    let active = executor
        .execute(&harness.load(&planned), &work, 111)
        .unwrap_or_else(|error| panic!("cursor CAS retry failed: {error}"));
    assert_eq!(
        decode_response_record(&active)
            .unwrap_or_else(|error| panic!("decode active response: {error}"))
            .state,
        ResponseState::Active
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 0));
}

#[test]
fn executor_crash_takeover_at_apply_deadline_reconciles_applied_journal_before_rollback() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let first_work = work(&planned, 1, 900);
    harness.store.install_work(first_work.clone());
    harness.receipts.fail_once_on_effect_state("applied");
    assert!(executor.execute(&planned, &first_work, 110).is_err());
    assert_eq!(harness.effects.mutation_counts(), (1, 0));

    let takeover_work = work(&planned, 2, 1_500);
    harness.store.install_work(takeover_work.clone());
    let pending = harness.load(&planned);
    let lifted = executor
        .execute(&pending, &takeover_work, 900)
        .unwrap_or_else(|error| panic!("deadline takeover recovery failed: {error}"));
    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("decode deadline recovery: {error}"))
            .state,
        ResponseState::Lifted
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 1));
}

#[test]
fn executor_crash_takeover_at_apply_deadline_queries_port_before_result_gap() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let first_work = work(&planned, 1, 900);
    harness.store.install_work(first_work.clone());
    harness.store.arm(StoreCrash::BeforeAppliedResult);
    assert!(executor.execute(&planned, &first_work, 110).is_err());
    assert_eq!(harness.effects.mutation_counts(), (1, 0));

    let takeover_work = work(&planned, 2, 1_500);
    harness.store.install_work(takeover_work.clone());
    let pending = harness.load(&planned);
    let lifted = executor
        .execute(&pending, &takeover_work, 900)
        .unwrap_or_else(|error| panic!("port-result query recovery failed: {error}"));
    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("decode query recovery: {error}"))
            .state,
        ResponseState::Lifted
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 1));
}

#[test]
fn executor_crash_apply_not_executed_at_deadline_never_creates_late_mutation() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let first_work = work(&planned, 1, 900);
    harness.store.install_work(first_work.clone());
    harness
        .receipts
        .fail_once_on_effect_state("apply_requested");
    assert!(executor.execute(&planned, &first_work, 110).is_err());
    assert_eq!(harness.effects.mutation_counts(), (0, 0));

    let takeover_work = work(&planned, 2, 1_500);
    harness.store.install_work(takeover_work.clone());
    let pending = harness.load(&planned);
    let lifted = executor
        .execute(&pending, &takeover_work, 900)
        .unwrap_or_else(|error| panic!("not-executed deadline recovery failed: {error}"));
    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("decode not-executed recovery: {error}"))
            .state,
        ResponseState::Lifted
    );
    assert_eq!(harness.effects.mutation_counts(), (0, 0));
}

#[test]
fn executor_crash_unknown_apply_outcome_at_deadline_stays_restrictive_and_nonterminal() {
    for fault in [QueryFault::Unknown, QueryFault::Unavailable] {
        let harness = Harness::new();
        let executor = harness.executor();
        let planned = create_plan(Arc::clone(&harness.store));
        let first_work = work(&planned, 1, 900);
        harness.store.install_work(first_work.clone());
        harness
            .receipts
            .fail_once_on_effect_state("apply_requested");
        assert!(executor.execute(&planned, &first_work, 110).is_err());
        harness.effects.set_query_fault(fault);

        let takeover_work = work(&planned, 2, 1_500);
        harness.store.install_work(takeover_work.clone());
        let pending = harness.load(&planned);
        assert!(executor.execute(&pending, &takeover_work, 900).is_err());
        assert_eq!(
            decode_response_record(&harness.load(&planned))
                .unwrap_or_else(|error| panic!("decode unknown outcome: {error}"))
                .state,
            ResponseState::Applying
        );
        assert_eq!(harness.effects.mutation_counts(), (0, 0));
    }
}

#[test]
fn executor_crash_stale_takeover_pending_rollback_never_calls_effect_port() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("apply failed: {error}"));

    let first_rollback_work = work(&active, 2, 1_500);
    harness.store.install_work(first_rollback_work.clone());
    harness
        .receipts
        .fail_once_on_effect_state("rollback_requested");
    assert!(executor
        .execute(&active, &first_rollback_work, 1_000)
        .is_err());
    assert_eq!(harness.effects.mutation_counts(), (1, 0));

    let takeover_work = work(&active, 3, 1_500);
    harness.store.install_work(takeover_work.clone());
    let pending = harness.load(&active);
    assert!(executor
        .execute(&pending, &first_rollback_work, 1_001)
        .is_err());
    assert_eq!(harness.effects.mutation_counts(), (1, 0));

    let reconciled = harness.load(&active);
    let lifted = executor
        .execute(&reconciled, &takeover_work, 1_002)
        .unwrap_or_else(|error| panic!("takeover rollback failed: {error}"));
    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("decode lifted: {error}"))
            .state,
        ResponseState::Lifted
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 1));
}
