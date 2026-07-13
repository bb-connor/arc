mod response_support;

use chio_quarantine::{
    build_response_plan, decode_response_record, ResponseExecutionReceipt, ResponseExecutor,
    ResponseStateMachine,
};
use chio_security_types::ports::{
    ActionId, CanonicalBody, CreateOutcome, Digest32, EffectExecutionStatus, EffectOperation,
    EffectPort, EffectRequest, EffectResult, EffectResultQuery, LeaseOwnerId, OpaqueReceiptRef,
    PortError, PortResult, ReceiptAppendRequest, ResponseCasRequest, ResponseEffectCasRequest,
    ResponseEffectKey, ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord,
    ResponseSchedulerStore, ResponseStore, ScheduledWork, SchedulerClaimRequest,
    SchedulerHealthAckRequest, SchedulerLeaseReleaseRequest, SchedulerLeaseRenewRequest,
    SchedulerRetryRequest, SchedulerRetryState, SchedulerWorkKey, SecurityAlert, SecurityAlertPort,
    SecurityReceiptSink, SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec,
    ResponsePlanInput, ResponseState, ResponseTarget,
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

fn create_overlapping_plan(store: Arc<CrashStore>) -> ResponsePlanRecord {
    create_plan_with_effects(store, vec![effect(3), effect(4)])
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

fn create_plan_with_effects(
    store: Arc<CrashStore>,
    effects: Vec<ResponseEffectSpec>,
) -> ResponsePlanRecord {
    let plan = build_response_plan(ResponsePlanInput {
        action_id: ActionId::new("executor-action")
            .unwrap_or_else(|error| panic!("action id: {error}")),
        trigger_finding_id: record("executor-finding"),
        tenant_id: TenantId::new("executor-tenant")
            .unwrap_or_else(|error| panic!("tenant id: {error}")),
        policy_version: record("executor-policy"),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoreCrash {
    BeforeIntent,
    BeforeAppliedResult,
    BeforeRestoredResult,
}

struct CrashStore {
    inner: TestResponseStore,
    crash: Mutex<Option<StoreCrash>>,
    durable_work: Mutex<Option<ScheduledWork>>,
}

impl CrashStore {
    fn new() -> Self {
        Self {
            inner: TestResponseStore::default(),
            crash: Mutex::new(None),
            durable_work: Mutex::new(None),
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
        self.inner.compare_and_swap_effect(request)
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
    installed: BTreeMap<String, Digest32>,
    apply_mutations: usize,
    remove_mutations: usize,
    apply_order: Vec<String>,
    remove_order: Vec<String>,
    fail_remove: bool,
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

    fn mutation_order(&self) -> (Vec<String>, Vec<String>) {
        let state = self.state();
        (state.apply_order.clone(), state.remove_order.clone())
    }

    fn set_query_fault(&self, fault: QueryFault) {
        self.state().query_fault = Some(fault);
    }
}

impl EffectPort for IdempotentEffects {
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
        state.replay.insert(
            request.idempotency_key.as_str().to_owned(),
            (request.clone(), result.clone()),
        );
        Ok(result)
    }

    fn load_result(&self, query: &EffectResultQuery) -> PortResult<EffectExecutionStatus> {
        let state = self.state.lock().map_err(|_| PortError::unavailable())?;
        match state.query_fault {
            Some(QueryFault::Unknown) => return Ok(EffectExecutionStatus::Unknown),
            Some(QueryFault::Unavailable) => return Err(PortError::unavailable()),
            None => {}
        }
        let Some((request, result)) = state.replay.get(query.idempotency_key.as_str()) else {
            return Ok(EffectExecutionStatus::NotExecuted);
        };
        if request.tenant_id != query.tenant_id
            || request.effect_id != query.effect_id
            || request.operation != query.operation
            || request.expected_version_hash != query.expected_version_hash
        {
            return Err(PortError::conflict());
        }
        Ok(EffectExecutionStatus::Completed {
            result: result.clone(),
        })
    }
}

#[derive(Default)]
struct ReceiptState {
    receipts: Vec<ResponseExecutionReceipt>,
    fail_effect_state: Option<String>,
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

    fn receipts(&self) -> Vec<ResponseExecutionReceipt> {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("receipt mutex poisoned"))
            .receipts
            .clone()
    }
}

impl SecurityReceiptSink for TestReceipts {
    fn sign_and_append(&self, request: &ReceiptAppendRequest) -> PortResult<OpaqueReceiptRef> {
        let receipt: ResponseExecutionReceipt =
            serde_json::from_slice(request.canonical_body.as_bytes())
                .map_err(|_| PortError::invalid_data())?;
        let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
        let effect_state = receipt.effect_state.as_ref().map(|value| value.as_str());
        if state
            .fail_effect_state
            .as_deref()
            .is_some_and(|expected| effect_state == Some(expected))
        {
            state.fail_effect_state = None;
            return Err(PortError::unavailable());
        }
        if !state.receipts.iter().any(|stored| stored == &receipt) {
            state.receipts.push(receipt);
        }
        OpaqueReceiptRef::new(format!("receipt-{}", request.transition_id.as_str()))
            .map_err(PortError::from)
    }
}

#[derive(Default)]
struct TestAlerts {
    alerts: Mutex<Vec<SecurityAlert>>,
}

impl TestAlerts {
    fn count(&self) -> usize {
        self.alerts
            .lock()
            .unwrap_or_else(|_| panic!("alert mutex poisoned"))
            .len()
    }
}

impl SecurityAlertPort for TestAlerts {
    fn page(&self, alert: &SecurityAlert) -> PortResult<()> {
        self.alerts
            .lock()
            .map_err(|_| PortError::unavailable())?
            .push(alert.clone());
        Ok(())
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

#[derive(Clone, Copy)]
enum CrashCase {
    BeforeIntentPersistence,
    AfterIntentBeforePort,
    AfterPortBeforeResult,
    AfterResultBeforeNextEffect,
    DuringRollbackBeforePort,
    AfterRestoreBeforeResult,
}

#[test]
fn executor_crash_matrix_converges_without_duplicate_external_mutation() {
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
        let planned = create_plan(Arc::clone(&harness.store));
        let apply_work = work(&planned, 1, 900);
        harness.store.install_work(apply_work.clone());

        match crash_case {
            CrashCase::BeforeIntentPersistence => harness.store.arm(StoreCrash::BeforeIntent),
            CrashCase::AfterIntentBeforePort => harness
                .receipts
                .fail_once_on_effect_state("apply_requested"),
            CrashCase::AfterPortBeforeResult => harness.store.arm(StoreCrash::BeforeAppliedResult),
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
            assert!(first_apply.is_err());
        }
        let active = if first_apply.is_ok() {
            first_apply.unwrap_or_else(|error| panic!("apply failed: {error}"))
        } else {
            let current = harness.load(&planned);
            executor
                .execute(&current, &apply_work, 111)
                .unwrap_or_else(|error| panic!("apply recovery failed: {error}"))
        };
        assert_eq!(
            decode_response_record(&active)
                .unwrap_or_else(|error| panic!("decode active: {error}"))
                .state,
            ResponseState::Active
        );
        assert_eq!(harness.effects.mutation_counts().0, 1);

        let rollback_work = work(&active, 2, 1_500);
        harness.store.install_work(rollback_work.clone());
        match crash_case {
            CrashCase::DuringRollbackBeforePort => harness
                .receipts
                .fail_once_on_effect_state("rollback_requested"),
            CrashCase::AfterRestoreBeforeResult => {
                harness.store.arm(StoreCrash::BeforeRestoredResult)
            }
            _ => {}
        }
        let first_rollback = executor.execute(&active, &rollback_work, 1_000);
        if matches!(
            crash_case,
            CrashCase::DuringRollbackBeforePort | CrashCase::AfterRestoreBeforeResult
        ) {
            assert!(first_rollback.is_err());
        }
        let lifted = if first_rollback.is_ok() {
            first_rollback.unwrap_or_else(|error| panic!("rollback failed: {error}"))
        } else {
            let current = harness.load(&active);
            executor
                .execute(&current, &rollback_work, 1_001)
                .unwrap_or_else(|error| panic!("rollback recovery failed: {error}"))
        };
        assert_eq!(
            decode_response_record(&lifted)
                .unwrap_or_else(|error| panic!("decode lifted: {error}"))
                .state,
            ResponseState::Lifted
        );
        assert_eq!(harness.effects.mutation_counts(), (1, 1));
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
    let receipts = harness.receipts.receipts();
    assert!(receipts
        .iter()
        .any(|receipt| receipt.state == ResponseState::RollbackPartial));
    assert!(!receipts
        .iter()
        .any(|receipt| receipt.state == ResponseState::Lifted));
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
