use chio_quarantine::{
    build_response_plan, decode_response_record, ExecutorError, ResponseScheduler,
    ResponseStateMachine, ResponseTransitionRequest, ScheduledResponseExecutor, SchedulerError,
    SchedulerPolicy, SchedulerTickRequest, SchedulerWorkOutcome,
};
use chio_security_types::ports::{
    ActionId, CanonicalBody, CreateOutcome, Digest32, LeaseOwnerId, PortError, PortResult,
    RecordId, ResponseCasRequest, ResponseEffectCasRequest, ResponseEffectKey,
    ResponseEffectRecord, ResponsePlanKey, ResponsePlanRecord, ResponseSchedulerStore,
    ResponseStore, ScheduledWork, SchedulerClaimRequest, SchedulerHealthAckRequest,
    SchedulerHealthPageRequest, SchedulerHealthPort, SchedulerLeaseReleaseRequest,
    SchedulerLeaseRenewRequest, SchedulerRetryRequest, SchedulerRetryState, SchedulerWorkKey,
    SessionId, TenantId,
};
use chio_security_types::{
    OperatorCapabilityBinding, ResponseApprovalRequirement, ResponseEffectKind, ResponseEffectSpec,
    ResponsePlanInput, ResponseState, ResponseTarget,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

fn digest(value: u8) -> Digest32 {
    Digest32::new([value; 32])
}

fn record(value: &str) -> RecordId {
    RecordId::new(value).unwrap_or_else(|error| panic!("record id: {error}"))
}

fn plan(store: Arc<SchedulerStore>) -> ResponsePlanRecord {
    plan_with_action(store, "scheduler-action")
}

fn plan_with_action(store: Arc<SchedulerStore>, action_id: &str) -> ResponsePlanRecord {
    let contribution = CanonicalBody::new(b"{\"posture_rank\":3}".to_vec())
        .unwrap_or_else(|error| panic!("contribution: {error}"));
    let contribution_hash =
        Digest32::new(*chio_core_types::sha256(contribution.as_bytes()).as_bytes());
    let plan = build_response_plan(ResponsePlanInput {
        action_id: ActionId::new(action_id).unwrap_or_else(|error| panic!("action id: {error}")),
        trigger_finding_id: record("scheduler-finding"),
        tenant_id: TenantId::new("scheduler-tenant")
            .unwrap_or_else(|error| panic!("tenant id: {error}")),
        policy_version: record("scheduler-policy"),
        affected_ids: vec![record("scheduler-session")],
        effects: vec![ResponseEffectSpec {
            kind: ResponseEffectKind::ThrottleSession,
            target: ResponseTarget::Session {
                session_id: SessionId::new("scheduler-session")
                    .unwrap_or_else(|error| panic!("session id: {error}")),
            },
            canonical_contribution: contribution,
            contribution_hash,
            observed_base_version_hash: digest(20),
        }],
        ttl_ms: 900,
        created_at_unix_ms: 100,
        operator_capability: OperatorCapabilityBinding {
            capability_id: record("scheduler-capability"),
            capability_digest: digest(30),
            expires_at_unix_ms: 2_000,
            executor_subject: record("scheduler-subject"),
        },
        approval_requirement: ResponseApprovalRequirement::Automatic,
        submitter: record("scheduler-submitter"),
        reason_hash: digest(31),
    })
    .unwrap_or_else(|error| panic!("build plan: {error}"));
    ResponseStateMachine::new(store)
        .create(plan)
        .unwrap_or_else(|error| panic!("create plan: {error}"))
}

fn policy() -> SchedulerPolicy {
    SchedulerPolicy {
        lease_duration_ms: 100,
        base_backoff_ms: 10,
        max_backoff_ms: 40,
        operator_page_threshold_ms: 50,
        max_claims: 1,
    }
}

fn tick(now_unix_ms: u64, claim: &str) -> SchedulerTickRequest {
    SchedulerTickRequest {
        tenant_id: TenantId::new("scheduler-tenant")
            .unwrap_or_else(|error| panic!("tenant id: {error}")),
        claim_id: record(claim),
        lease_owner_id: LeaseOwnerId::new("scheduler-worker")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        now_unix_ms,
    }
}

#[derive(Default)]
struct SchedulerState {
    plan: Option<ResponsePlanRecord>,
    transitions: BTreeMap<String, ResponseCasRequest>,
    effects: BTreeMap<String, ResponseEffectRecord>,
    effect_transitions: BTreeMap<String, ResponseEffectCasRequest>,
    work: Option<ScheduledWork>,
    retry: Option<SchedulerRetryState>,
    next_fencing_token: u64,
    fail_health_ack_once: bool,
}

#[derive(Default)]
struct SchedulerStore {
    state: Mutex<SchedulerState>,
}

impl SchedulerStore {
    fn state(&self) -> PortResult<MutexGuard<'_, SchedulerState>> {
        self.state.lock().map_err(|_| PortError::unavailable())
    }

    fn install_work(&self, work: ScheduledWork) {
        let mut state = self
            .state()
            .unwrap_or_else(|error| panic!("scheduler state: {error}"));
        state.next_fencing_token = state.next_fencing_token.max(work.fencing_token);
        state.work = Some(work);
    }

    fn fail_next_health_ack(&self) {
        self.state()
            .unwrap_or_else(|error| panic!("scheduler state: {error}"))
            .fail_health_ack_once = true;
    }

    fn retry(&self) -> Option<SchedulerRetryState> {
        self.state()
            .unwrap_or_else(|error| panic!("scheduler state: {error}"))
            .retry
            .clone()
    }

    fn work(&self) -> Option<ScheduledWork> {
        self.state()
            .unwrap_or_else(|error| panic!("scheduler state: {error}"))
            .work
            .clone()
    }
}

impl ResponseStore for SchedulerStore {
    fn load_plan(&self, key: &ResponsePlanKey) -> PortResult<Option<ResponsePlanRecord>> {
        let state = self.state()?;
        Ok(state
            .plan
            .as_ref()
            .filter(|plan| plan.tenant_id == key.tenant_id && plan.action_id == key.action_id)
            .cloned())
    }

    fn create(&self, record: &ResponsePlanRecord) -> PortResult<CreateOutcome> {
        let mut state = self.state()?;
        match state.plan.as_ref() {
            Some(existing) if existing == record => Ok(CreateOutcome::Existing),
            Some(_) => Err(PortError::conflict()),
            None => {
                state.plan = Some(record.clone());
                Ok(CreateOutcome::Created)
            }
        }
    }

    fn compare_and_swap(&self, request: &ResponseCasRequest) -> PortResult<ResponsePlanRecord> {
        let mut state = self.state()?;
        if let Some(existing) = state.transitions.get(request.transition_id.as_str()) {
            if existing != request {
                return Err(PortError::conflict());
            }
            return state.plan.clone().ok_or_else(PortError::integrity_failure);
        }
        let current = state.plan.as_ref().ok_or_else(PortError::invalid_data)?;
        if current.tenant_id != request.record.tenant_id
            || current.action_id != request.record.action_id
            || current.generation != request.expected_generation
        {
            return Err(PortError::conflict());
        }
        state
            .transitions
            .insert(request.transition_id.as_str().to_owned(), request.clone());
        state.plan = Some(request.record.clone());
        Ok(request.record.clone())
    }

    fn load_effect(&self, key: &ResponseEffectKey) -> PortResult<Option<ResponseEffectRecord>> {
        let state = self.state()?;
        Ok(state
            .effects
            .get(key.effect_id.as_str())
            .filter(|effect| effect.tenant_id == key.tenant_id)
            .cloned())
    }

    fn persist_effect(&self, record: &ResponseEffectRecord) -> PortResult<CreateOutcome> {
        let mut state = self.state()?;
        match state.effects.get(record.effect_id.as_str()) {
            Some(existing) if existing == record => Ok(CreateOutcome::Existing),
            Some(_) => Err(PortError::conflict()),
            None => {
                state
                    .effects
                    .insert(record.effect_id.as_str().to_owned(), record.clone());
                Ok(CreateOutcome::Created)
            }
        }
    }

    fn compare_and_swap_effect(
        &self,
        request: &ResponseEffectCasRequest,
    ) -> PortResult<ResponseEffectRecord> {
        let mut state = self.state()?;
        if let Some(existing) = state.effect_transitions.get(request.transition_id.as_str()) {
            if existing != request {
                return Err(PortError::conflict());
            }
            return state
                .effects
                .get(request.record.effect_id.as_str())
                .cloned()
                .ok_or_else(PortError::integrity_failure);
        }
        let current = state
            .effects
            .get(request.record.effect_id.as_str())
            .ok_or_else(PortError::invalid_data)?;
        if current.generation != request.expected_generation {
            return Err(PortError::conflict());
        }
        state
            .effect_transitions
            .insert(request.transition_id.as_str().to_owned(), request.clone());
        state.effects.insert(
            request.record.effect_id.as_str().to_owned(),
            request.record.clone(),
        );
        Ok(request.record.clone())
    }

    fn claim_due(&self, request: &SchedulerClaimRequest) -> PortResult<Vec<ScheduledWork>> {
        let mut state = self.state()?;
        let Some(plan) = state.plan.as_ref() else {
            return Ok(Vec::new());
        };
        let due = plan
            .due_at_unix_ms
            .is_some_and(|due| due <= request.now_unix_ms);
        let retry_ready = state
            .retry
            .as_ref()
            .is_none_or(|retry| retry.not_before_unix_ms <= request.now_unix_ms);
        let lease_available = state
            .work
            .as_ref()
            .is_none_or(|work| work.lease_expires_at_unix_ms <= request.now_unix_ms);
        if !due || !retry_ready || !lease_available {
            return Ok(Vec::new());
        }
        let tenant_id = plan.tenant_id.clone();
        let action_id = plan.action_id.clone();
        state.next_fencing_token = state
            .next_fencing_token
            .checked_add(1)
            .ok_or_else(PortError::integrity_failure)?;
        let work = ScheduledWork {
            tenant_id,
            action_id,
            lease_owner_id: request.lease_owner_id.clone(),
            lease_expires_at_unix_ms: request.lease_expires_at_unix_ms,
            fencing_token: state.next_fencing_token,
        };
        state.work = Some(work.clone());
        Ok(vec![work])
    }
}

impl ResponseSchedulerStore for SchedulerStore {
    fn load_retry(&self, key: &SchedulerWorkKey) -> PortResult<Option<SchedulerRetryState>> {
        let state = self.state()?;
        Ok(state
            .retry
            .as_ref()
            .filter(|retry| retry.key == *key)
            .cloned())
    }

    fn validate_lease(&self, work: &ScheduledWork) -> PortResult<()> {
        let state = self.state()?;
        if state.work.as_ref() == Some(work) {
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
        self.state()?.work = Some(renewed.clone());
        Ok(renewed)
    }

    fn record_retry(&self, request: &SchedulerRetryRequest) -> PortResult<SchedulerRetryState> {
        self.validate_lease(&request.work)?;
        let mut state = self.state()?;
        let current_attempts = state
            .retry
            .as_ref()
            .map(|retry| retry.attempts)
            .unwrap_or(0);
        if current_attempts != request.expected_attempts {
            return Err(PortError::conflict());
        }
        let retry = SchedulerRetryState {
            key: SchedulerWorkKey {
                tenant_id: request.work.tenant_id.clone(),
                action_id: request.work.action_id.clone(),
            },
            attempts: request
                .expected_attempts
                .checked_add(1)
                .ok_or_else(PortError::integrity_failure)?,
            last_error: request.error_code.clone(),
            first_failure_at_unix_ms: request.first_failure_at_unix_ms,
            not_before_unix_ms: request.not_before_unix_ms,
            health_event_id: request.health_event_id.clone(),
            health_event_delivered: state
                .retry
                .as_ref()
                .is_some_and(|retry| retry.health_event_delivered),
        };
        state.retry = Some(retry.clone());
        state.work = None;
        Ok(retry)
    }

    fn acknowledge_health_event(
        &self,
        request: &SchedulerHealthAckRequest,
    ) -> PortResult<SchedulerRetryState> {
        let mut state = self.state()?;
        if state.fail_health_ack_once {
            state.fail_health_ack_once = false;
            return Err(PortError::unavailable());
        }
        let retry = state.retry.as_mut().ok_or_else(PortError::invalid_data)?;
        if retry.key != request.key || retry.health_event_id.as_ref() != Some(&request.event_id) {
            return Err(PortError::conflict());
        }
        retry.health_event_delivered = true;
        Ok(retry.clone())
    }

    fn release_lease(&self, request: &SchedulerLeaseReleaseRequest) -> PortResult<()> {
        self.validate_lease(&request.work)?;
        let mut state = self.state()?;
        state.work = None;
        if request.clear_retry_state {
            state.retry = None;
        }
        Ok(())
    }
}

#[derive(Default)]
struct UnavailableExecutor {
    calls: Mutex<usize>,
}

impl UnavailableExecutor {
    fn calls(&self) -> usize {
        *self
            .calls
            .lock()
            .unwrap_or_else(|_| panic!("executor mutex poisoned"))
    }
}

impl ScheduledResponseExecutor for UnavailableExecutor {
    fn execute_scheduled(
        &self,
        _current: &ResponsePlanRecord,
        _work: &ScheduledWork,
        _now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| ExecutorError::Store(PortError::unavailable()))?;
        *calls = calls.saturating_add(1);
        Err(ExecutorError::Store(PortError::unavailable()))
    }
}

#[derive(Default)]
struct UnknownOutcomeExecutor {
    calls: Mutex<usize>,
}

impl ScheduledResponseExecutor for UnknownOutcomeExecutor {
    fn execute_scheduled(
        &self,
        _current: &ResponsePlanRecord,
        _work: &ScheduledWork,
        _now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| ExecutorError::Store(PortError::unavailable()))?;
        *calls = calls.saturating_add(1);
        Err(ExecutorError::EffectOutcomeUnknown)
    }
}

#[derive(Default)]
struct RoutingExecutor {
    states: Mutex<Vec<ResponseState>>,
}

impl RoutingExecutor {
    fn states(&self) -> Vec<ResponseState> {
        self.states
            .lock()
            .unwrap_or_else(|_| panic!("routing mutex poisoned"))
            .clone()
    }
}

impl ScheduledResponseExecutor for RoutingExecutor {
    fn execute_scheduled(
        &self,
        current: &ResponsePlanRecord,
        _work: &ScheduledWork,
        _now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        let state = decode_response_record(current)
            .map_err(|_| ExecutorError::InvalidEffectJournal)?
            .state;
        self.states
            .lock()
            .map_err(|_| ExecutorError::Store(PortError::unavailable()))?
            .push(state);
        Err(ExecutorError::Store(PortError::unavailable()))
    }
}

struct PassthroughExecutor;

impl ScheduledResponseExecutor for PassthroughExecutor {
    fn execute_scheduled(
        &self,
        current: &ResponsePlanRecord,
        _work: &ScheduledWork,
        _now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        Ok(current.clone())
    }
}

struct SubstitutionExecutor {
    record: ResponsePlanRecord,
}

impl ScheduledResponseExecutor for SubstitutionExecutor {
    fn execute_scheduled(
        &self,
        _current: &ResponsePlanRecord,
        _work: &ScheduledWork,
        _now_unix_ms: u64,
    ) -> Result<ResponsePlanRecord, ExecutorError> {
        Ok(self.record.clone())
    }
}

#[derive(Default)]
struct TestHealthSink {
    state: Mutex<TestHealthState>,
}

#[derive(Default)]
struct TestHealthState {
    calls: usize,
    pages: BTreeMap<String, SchedulerHealthPageRequest>,
}

impl TestHealthSink {
    fn pages(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("health mutex poisoned"))
            .pages
            .len()
    }

    fn calls(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|_| panic!("health mutex poisoned"))
            .calls
    }
}

impl SchedulerHealthPort for TestHealthSink {
    fn page_once(&self, request: &SchedulerHealthPageRequest) -> PortResult<()> {
        let mut state = self.state.lock().map_err(|_| PortError::unavailable())?;
        state.calls = state.calls.saturating_add(1);
        match state.pages.get(request.event_id.as_str()) {
            Some(existing) if existing == request => Ok(()),
            Some(_) => Err(PortError::conflict()),
            None => {
                state
                    .pages
                    .insert(request.event_id.as_str().to_owned(), request.clone());
                Ok(())
            }
        }
    }
}

#[test]
fn scheduler_fencing_direct_process_rejects_clock_rollback() {
    let store = Arc::new(SchedulerStore::default());
    let planned = plan(Arc::clone(&store));
    let executor = Arc::new(UnavailableExecutor::default());
    let health = Arc::new(TestHealthSink::default());
    let scheduler =
        ResponseScheduler::new(Arc::clone(&store), Arc::clone(&executor), health, policy())
            .unwrap_or_else(|error| panic!("scheduler: {error}"));
    assert!(scheduler
        .tick(&tick(900, "clock-observation"))
        .unwrap_or_else(|error| panic!("early tick: {error}"))
        .is_empty());
    let work = ScheduledWork {
        tenant_id: planned.tenant_id,
        action_id: planned.action_id,
        lease_owner_id: LeaseOwnerId::new("scheduler-worker")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        lease_expires_at_unix_ms: 2_000,
        fencing_token: 1,
    };
    store.install_work(work.clone());
    assert!(matches!(
        scheduler.process(&work, 800),
        Err(SchedulerError::ClockRollback)
    ));
    assert_eq!(executor.calls(), 0);
}

#[test]
fn scheduler_ttl_sustained_retry_age_pages_at_threshold() {
    let store = Arc::new(SchedulerStore::default());
    let _planned = plan(Arc::clone(&store));
    let executor = Arc::new(UnavailableExecutor::default());
    let health = Arc::new(TestHealthSink::default());
    let scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::clone(&executor),
        Arc::clone(&health),
        policy(),
    )
    .unwrap_or_else(|error| panic!("scheduler: {error}"));

    let first = scheduler
        .tick(&tick(1_000, "outage-claim-1"))
        .unwrap_or_else(|error| panic!("first outage tick: {error}"));
    assert!(matches!(
        first.as_slice(),
        [SchedulerWorkOutcome::RetryScheduled {
            attempts: 1,
            not_before_unix_ms: 1_010,
            error_code,
            ..
        }] if error_code.as_str() == "store.unavailable"
    ));
    assert!(scheduler
        .tick(&tick(1_009, "outage-early"))
        .unwrap_or_else(|error| panic!("early retry tick: {error}"))
        .is_empty());
    for (now, claim, attempts, not_before) in [
        (1_010, "outage-claim-2", 2, 1_030),
        (1_030, "outage-claim-3", 3, 1_070),
        (1_070, "outage-claim-4", 4, 1_110),
    ] {
        let outcomes = scheduler
            .tick(&tick(now, claim))
            .unwrap_or_else(|error| panic!("outage retry tick: {error}"));
        assert!(matches!(
            outcomes.as_slice(),
            [SchedulerWorkOutcome::RetryScheduled {
                attempts: actual_attempts,
                not_before_unix_ms,
                error_code,
                ..
            }] if *actual_attempts == attempts
                && *not_before_unix_ms == not_before
                && error_code.as_str() == "store.unavailable"
        ));
    }
    assert_eq!(executor.calls(), 4);
    assert_eq!(health.pages(), 1);
}

#[test]
fn scheduler_ttl_unknown_effect_outcome_retries_and_pages_without_false_completion() {
    let store = Arc::new(SchedulerStore::default());
    let _planned = plan(Arc::clone(&store));
    let executor = Arc::new(UnknownOutcomeExecutor::default());
    let health = Arc::new(TestHealthSink::default());
    let scheduler =
        ResponseScheduler::new(Arc::clone(&store), executor, Arc::clone(&health), policy())
            .unwrap_or_else(|error| panic!("scheduler: {error}"));
    for (now, claim) in [
        (1_000, "unknown-outcome-1"),
        (1_010, "unknown-outcome-2"),
        (1_030, "unknown-outcome-3"),
        (1_070, "unknown-outcome-4"),
    ] {
        let outcomes = scheduler
            .tick(&tick(now, claim))
            .unwrap_or_else(|error| panic!("unknown outcome tick: {error}"));
        assert!(matches!(
            outcomes.as_slice(),
            [SchedulerWorkOutcome::RetryScheduled { error_code, .. }]
                if error_code.as_str() == "response.effect_outcome_unknown"
        ));
    }
    assert_eq!(health.pages(), 1);
    let retry = store
        .retry()
        .unwrap_or_else(|| panic!("unknown outcome retry missing"));
    assert_eq!(retry.attempts, 4);
    assert!(retry.health_event_delivered);
}

#[test]
fn scheduler_ttl_restart_replays_one_deterministic_health_event_then_acks_once() {
    let store = Arc::new(SchedulerStore::default());
    let _planned = plan(Arc::clone(&store));
    let executor = Arc::new(UnavailableExecutor::default());
    let health = Arc::new(TestHealthSink::default());
    let scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::clone(&executor),
        Arc::clone(&health),
        policy(),
    )
    .unwrap_or_else(|error| panic!("scheduler: {error}"));

    for (now, claim) in [
        (1_000, "restart-outage-1"),
        (1_010, "restart-outage-2"),
        (1_030, "restart-outage-3"),
    ] {
        let outcomes = scheduler
            .tick(&tick(now, claim))
            .unwrap_or_else(|error| panic!("outage tick: {error}"));
        assert_eq!(outcomes.len(), 1);
    }
    store.fail_next_health_ack();
    let threshold = scheduler
        .tick(&tick(1_070, "restart-outage-threshold"))
        .unwrap_or_else(|error| panic!("threshold tick: {error}"));
    assert!(matches!(
        threshold.as_slice(),
        [chio_quarantine::SchedulerWorkOutcome::ProcessingFailed { .. }]
    ));
    let pending = store
        .retry()
        .unwrap_or_else(|| panic!("pending retry state missing"));
    assert_eq!(pending.first_failure_at_unix_ms, 1_000);
    assert!(pending.health_event_id.is_some());
    assert!(!pending.health_event_delivered);
    assert_eq!(health.pages(), 1);
    assert_eq!(health.calls(), 1);

    let restarted = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::clone(&executor),
        Arc::clone(&health),
        policy(),
    )
    .unwrap_or_else(|error| panic!("restarted scheduler: {error}"));
    let replay = restarted
        .tick(&tick(1_110, "restart-outage-replay"))
        .unwrap_or_else(|error| panic!("replay tick: {error}"));
    assert_eq!(replay.len(), 1);
    let delivered = store
        .retry()
        .unwrap_or_else(|| panic!("delivered retry state missing"));
    assert_eq!(delivered.first_failure_at_unix_ms, 1_000);
    assert!(delivered.health_event_delivered);
    assert_eq!(health.pages(), 1);
    assert_eq!(health.calls(), 2);

    let duplicate_retry = restarted
        .tick(&tick(1_150, "restart-outage-duplicate"))
        .unwrap_or_else(|error| panic!("duplicate retry tick: {error}"));
    assert_eq!(duplicate_retry.len(), 1);
    assert_eq!(health.pages(), 1);
    assert_eq!(health.calls(), 2);
}

#[test]
fn scheduler_ttl_exact_early_delayed_and_large_forward_jump_dispatch_once() {
    let store = Arc::new(SchedulerStore::default());
    let _planned = plan(Arc::clone(&store));
    let executor = Arc::new(UnavailableExecutor::default());
    let scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::clone(&executor),
        Arc::new(TestHealthSink::default()),
        policy(),
    )
    .unwrap_or_else(|error| panic!("scheduler: {error}"));
    assert!(scheduler
        .tick(&tick(999, "ttl-early"))
        .unwrap_or_else(|error| panic!("early tick: {error}"))
        .is_empty());
    let exact = scheduler
        .tick(&tick(1_000, "ttl-exact"))
        .unwrap_or_else(|error| panic!("exact tick: {error}"));
    assert!(matches!(
        exact.as_slice(),
        [SchedulerWorkOutcome::RetryScheduled {
            attempts: 1,
            not_before_unix_ms: 1_010,
            ..
        }]
    ));
    assert_eq!(executor.calls(), 1);

    for (now, label) in [(1_500, "ttl-delayed"), (1_000_000, "ttl-forward-jump")] {
        let delayed_store = Arc::new(SchedulerStore::default());
        let _delayed_plan = plan(Arc::clone(&delayed_store));
        let delayed_executor = Arc::new(UnavailableExecutor::default());
        let delayed_scheduler = ResponseScheduler::new(
            Arc::clone(&delayed_store),
            Arc::clone(&delayed_executor),
            Arc::new(TestHealthSink::default()),
            policy(),
        )
        .unwrap_or_else(|error| panic!("delayed scheduler: {error}"));
        let outcomes = delayed_scheduler
            .tick(&tick(now, label))
            .unwrap_or_else(|error| panic!("delayed tick: {error}"));
        assert_eq!(outcomes.len(), 1);
        assert_eq!(delayed_executor.calls(), 1);
    }
}

#[test]
fn scheduler_fencing_contention_waits_for_expiry_and_stale_takeover_loses() {
    let store = Arc::new(SchedulerStore::default());
    let planned = plan(Arc::clone(&store));
    let executor = Arc::new(UnavailableExecutor::default());
    let health = Arc::new(TestHealthSink::default());
    let stale_scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::clone(&executor),
        Arc::clone(&health),
        policy(),
    )
    .unwrap_or_else(|error| panic!("stale scheduler: {error}"));
    let takeover_scheduler =
        ResponseScheduler::new(Arc::clone(&store), Arc::clone(&executor), health, policy())
            .unwrap_or_else(|error| panic!("takeover scheduler: {error}"));
    let stale_work = ScheduledWork {
        tenant_id: planned.tenant_id,
        action_id: planned.action_id,
        lease_owner_id: LeaseOwnerId::new("stale-worker")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        lease_expires_at_unix_ms: 1_100,
        fencing_token: 1,
    };
    store.install_work(stale_work.clone());
    assert!(takeover_scheduler
        .tick(&tick(1_050, "takeover-too-early"))
        .unwrap_or_else(|error| panic!("early takeover: {error}"))
        .is_empty());
    let takeover = takeover_scheduler
        .tick(&tick(1_100, "takeover-exact"))
        .unwrap_or_else(|error| panic!("takeover: {error}"));
    assert_eq!(takeover.len(), 1);
    assert_eq!(executor.calls(), 1);
    assert!(matches!(
        stale_scheduler.process(&stale_work, 1_100),
        Ok(SchedulerWorkOutcome::LeaseLost { .. })
    ));
}

#[test]
fn scheduler_fencing_renewal_preserves_token_and_only_current_lease_releases() {
    let store = Arc::new(SchedulerStore::default());
    let planned = plan(Arc::clone(&store));
    let executor = Arc::new(UnavailableExecutor::default());
    let scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::clone(&executor),
        Arc::new(TestHealthSink::default()),
        policy(),
    )
    .unwrap_or_else(|error| panic!("scheduler: {error}"));
    let work = ScheduledWork {
        tenant_id: planned.tenant_id,
        action_id: planned.action_id,
        lease_owner_id: LeaseOwnerId::new("renew-worker")
            .unwrap_or_else(|error| panic!("lease owner id: {error}")),
        lease_expires_at_unix_ms: 1_050,
        fencing_token: 7,
    };
    store.install_work(work.clone());
    let renewed = scheduler
        .renew(&work, 1_020)
        .unwrap_or_else(|error| panic!("renew: {error}"));
    assert_eq!(renewed.fencing_token, work.fencing_token);
    assert_eq!(renewed.lease_owner_id, work.lease_owner_id);
    assert_eq!(renewed.lease_expires_at_unix_ms, 1_120);
    assert!(scheduler.release_for_shutdown(&work).is_err());
    scheduler
        .release_for_shutdown(&renewed)
        .unwrap_or_else(|error| panic!("release: {error}"));
    assert!(store.work().is_none());
    let after_release = scheduler
        .tick(&tick(1_020, "claim-after-release"))
        .unwrap_or_else(|error| panic!("claim after release: {error}"));
    assert_eq!(after_release.len(), 1);
    assert_eq!(executor.calls(), 1);
}

#[test]
fn scheduler_fencing_restart_routes_persisted_apply_and_rollback_states() {
    let routing = Arc::new(RoutingExecutor::default());
    let health = Arc::new(TestHealthSink::default());

    let applying_store = Arc::new(SchedulerStore::default());
    let applying_plan = plan(Arc::clone(&applying_store));
    let applying_machine = ResponseStateMachine::new(Arc::clone(&applying_store));
    applying_machine
        .transition(
            &applying_plan,
            &ResponseTransitionRequest {
                expected_generation: applying_plan.generation,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms: 200,
                applying_lease_expires_at_unix_ms: Some(500),
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("persist applying: {error}"));
    let applying_restart = ResponseScheduler::new(
        Arc::clone(&applying_store),
        Arc::clone(&routing),
        Arc::clone(&health),
        policy(),
    )
    .unwrap_or_else(|error| panic!("applying restart: {error}"));
    assert_eq!(
        applying_restart
            .tick(&tick(500, "restart-applying"))
            .unwrap_or_else(|error| panic!("route applying: {error}"))
            .len(),
        1
    );

    let rollback_store = Arc::new(SchedulerStore::default());
    let rollback_plan = plan(Arc::clone(&rollback_store));
    let rollback_machine = ResponseStateMachine::new(Arc::clone(&rollback_store));
    let applying = rollback_machine
        .transition(
            &rollback_plan,
            &ResponseTransitionRequest {
                expected_generation: rollback_plan.generation,
                target_state: ResponseState::Applying,
                occurred_at_unix_ms: 110,
                applying_lease_expires_at_unix_ms: Some(900),
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("enter applying: {error}"));
    let partial = rollback_machine
        .transition(
            &applying,
            &ResponseTransitionRequest {
                expected_generation: applying.generation,
                target_state: ResponseState::ApplyPartial,
                occurred_at_unix_ms: 120,
                applying_lease_expires_at_unix_ms: None,
                error_code: Some(
                    chio_security_types::ports::ErrorCode::new("response.injected_failure")
                        .unwrap_or_else(|error| panic!("error code: {error}")),
                ),
            },
        )
        .unwrap_or_else(|error| panic!("enter partial: {error}"));
    rollback_machine
        .transition(
            &partial,
            &ResponseTransitionRequest {
                expected_generation: partial.generation,
                target_state: ResponseState::RollingBack,
                occurred_at_unix_ms: 121,
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("persist rollback: {error}"));
    let rollback_restart = ResponseScheduler::new(
        Arc::clone(&rollback_store),
        Arc::clone(&routing),
        health,
        policy(),
    )
    .unwrap_or_else(|error| panic!("rollback restart: {error}"));
    assert_eq!(
        rollback_restart
            .tick(&tick(121, "restart-rollback"))
            .unwrap_or_else(|error| panic!("route rollback: {error}"))
            .len(),
        1
    );
    assert_eq!(
        routing.states(),
        vec![ResponseState::Applying, ResponseState::RollingBack]
    );
}

#[test]
fn scheduler_fencing_broken_executor_cannot_complete_nonterminal_state() {
    let store = Arc::new(SchedulerStore::default());
    let _planned = plan(Arc::clone(&store));
    let scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::new(PassthroughExecutor),
        Arc::new(TestHealthSink::default()),
        policy(),
    )
    .unwrap_or_else(|error| panic!("scheduler: {error}"));
    let outcomes = scheduler
        .tick(&tick(1_000, "broken-executor"))
        .unwrap_or_else(|error| panic!("broken executor tick: {error}"));
    assert!(matches!(
        outcomes.as_slice(),
        [SchedulerWorkOutcome::RetryScheduled { .. }]
    ));
    assert!(store.retry().is_some());
}

#[test]
fn scheduler_fencing_substituted_terminal_record_never_releases_claimed_action() {
    let store = Arc::new(SchedulerStore::default());
    let _planned = plan(Arc::clone(&store));

    let other_store = Arc::new(SchedulerStore::default());
    let other_planned = plan_with_action(Arc::clone(&other_store), "substituted-action");
    let substituted = ResponseStateMachine::new(other_store)
        .transition(
            &other_planned,
            &ResponseTransitionRequest {
                expected_generation: other_planned.generation,
                target_state: ResponseState::Expired,
                occurred_at_unix_ms: 1_000,
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("expire substituted plan: {error}"));
    let scheduler = ResponseScheduler::new(
        Arc::clone(&store),
        Arc::new(SubstitutionExecutor {
            record: substituted,
        }),
        Arc::new(TestHealthSink::default()),
        policy(),
    )
    .unwrap_or_else(|error| panic!("scheduler: {error}"));
    assert!(matches!(
        scheduler.tick(&tick(1_000, "substitution")),
        Err(SchedulerError::InvalidExecutionRecord)
    ));
    assert!(store.work().is_some());
    assert!(store.retry().is_none());
}
