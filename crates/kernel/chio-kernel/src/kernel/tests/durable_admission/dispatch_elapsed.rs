//! Tool dispatch time is measured on the kernel's authority clock.
use super::*;
use chio_security_types::clock::{
    Clock, ClockError, ClockReading, FixedClock, MonotonicInstant, UnixMillis,
};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const NOW_MS: u64 = 1_800_000_000_000;

#[derive(Default)]
struct Script {
    reads: u64,
    monotonic_ms: u64,
    step_ms: u64,
    unavailable: bool,
    fail_read: Option<u64>,
    regress_read: Option<u64>,
}

/// Authority time under test control. Every read is counted, so a fault can
/// target exactly one read.
#[derive(Default)]
struct ScriptedClock(Mutex<Script>);

impl ScriptedClock {
    fn script(&self) -> MutexGuard<'_, Script> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn reads(&self) -> u64 {
        self.script().reads
    }

    fn advance(&self, millis: u64) {
        self.script().monotonic_ms += millis;
    }

    fn fail_read(&self, read: u64) {
        self.script().fail_read = Some(read);
    }

    fn regress_read(&self, read: u64) {
        self.script().regress_read = Some(read);
    }
}

impl Clock for ScriptedClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        let mut script = self.script();
        script.reads += 1;
        script.monotonic_ms += script.step_ms;
        if script.unavailable || script.fail_read == Some(script.reads) {
            return Err(ClockError::Unavailable);
        }
        let monotonic_ms = if script.regress_read == Some(script.reads) {
            script
                .monotonic_ms
                .checked_sub(1)
                .ok_or(ClockError::Overflow)?
        } else {
            script.monotonic_ms
        };
        Ok(ClockReading::new(
            UnixMillis::new(NOW_MS),
            MonotonicInstant::from_nanos(monotonic_ms * 1_000_000),
        ))
    }
}

struct TimedServer {
    invocations: Arc<AtomicU64>,
    on_invoke: Box<dyn Fn() + Send + Sync>,
}

#[async_trait::async_trait]
impl ToolServerConnection for TimedServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".to_owned()]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        (self.on_invoke)();
        Ok(serde_json::json!({"tool": tool_name, "echo": arguments}))
    }
}

struct Fixture {
    kernel: ChioKernel,
    request: ToolCallRequest,
    store: Arc<TestAdmissionOperationStore>,
    invocations: Arc<AtomicU64>,
}

fn fixture(
    request_id: &str,
    clock: Arc<dyn Clock>,
    on_invoke: impl Fn() + Send + Sync + 'static,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut kernel = ChioKernel::new_with_clock(config, clock);
    kernel.enable_unsafe_ephemeral_financial_dispatch_for_development();
    let fence = admission_test_fence();
    let store = Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel.set_durable_admission_store(store.clone(), store.clone(), fence)?;
    kernel.set_budget_store_handle(store.budget_store());
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(TimedServer {
        invocations: invocations.clone(),
        on_invoke: Box::new(on_invoke),
    }));
    let agent = make_keypair();
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let grants = vec![grant];
    let capability = make_capability(&kernel, &agent, make_scope(grants), 300);
    let request = make_request_with_arguments(
        request_id,
        &capability,
        "mutate",
        "durable-server",
        serde_json::json!({"record": "ledger-7"}),
    );
    Ok(Fixture {
        kernel,
        request,
        store,
        invocations,
    })
}

fn evaluate(fixture: &Fixture, nested: bool) -> Result<ToolCallResponse, KernelError> {
    if !nested {
        return fixture.kernel.evaluate_tool_call_blocking(&fixture.request);
    }
    let session = fixture
        .kernel
        .open_session("elapsed-parent".into(), Vec::new())?;
    fixture.kernel.activate_session(&session)?;
    let parent = make_operation_context(&session, "parent-request", "elapsed-parent");
    fixture
        .kernel
        .begin_session_request(&parent, OperationKind::ToolCall, true)?;
    fixture.kernel.evaluate_tool_call_with_nested_flow_client(
        &parent,
        &fixture.request,
        &mut NoopNestedFlowClient,
        None,
    )
}

fn recorded_elapsed_millis(fixture: &Fixture) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    Ok(fixture
        .store
        .state
        .lock()
        .map_err(|_| "test admission state lock")?
        .raw_outcome
        .as_ref()
        .map(RawInvocationOutcomeV1::elapsed_millis))
}

fn assert_completed(fixture: &Fixture, elapsed_millis: u64) -> TestResult {
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(recorded_elapsed_millis(fixture)?, Some(elapsed_millis));
    Ok(())
}

/// A clock fault around a committed dispatch never yields a recorded return
/// and never releases the operation as not executed.
fn assert_outcome_unknown(
    fixture: &Fixture,
    response: Result<ToolCallResponse, KernelError>,
    effects: u64,
    clock_error: ClockError,
) -> TestResult {
    let response = response?;
    let reason = format!(
        "dispatch outcome is unknown after transport_return: {}",
        KernelError::Clock(clock_error).report().code
    );
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(reason.as_str()));
    assert_eq!(response.output, None);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), effects);
    let operation = assert_original_unknown_incident(
        &fixture.store,
        &fixture.request,
        &chio_core::receipt::decision::Decision::Deny {
            reason,
            guard: "kernel".into(),
        },
    );
    assert_unknown_replay(Ok(response), &operation, &fixture.store);
    assert_eq!(fixture.kernel.receipt_log().len(), 1);
    assert_eq!(recorded_elapsed_millis(fixture)?, None);
    let budget = fixture.store.budget_store();
    let hold_id = operation
        .budget_hold_id()
        .ok_or("missing original hold ID")?;
    let hold = budget
        .get_budget_hold(hold_id.as_str())?
        .ok_or("missing original hold")?;
    assert_eq!(hold.hold_id, hold_id.as_str());
    assert_eq!(hold.capability_id, fixture.request.capability.id);
    assert_eq!(hold.grant_index, 0);
    assert_eq!(
        hold.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reconciled
    );
    // This grant reserves an invocation only; it makes no monetary-custody claim.
    assert_eq!(hold.authorized_exposure_units, 0);
    let quota_key = crate::budget_store::BudgetQuotaKey::grant(&fixture.request.capability.id, 0);
    let quota = budget
        .get_invocation_quota_usage(&quota_key)?
        .ok_or("missing committed quota")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (0, 1)
    );
    // An unknown outcome must not admit another effect or refund captured quota.
    assert_unknown_replay(
        fixture.kernel.evaluate_tool_call_blocking(&fixture.request),
        &operation,
        &fixture.store,
    );
    assert_eq!(fixture.kernel.receipt_log().len(), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), effects);
    assert_eq!(fixture.store.operation(), operation);
    assert_eq!(budget.get_budget_hold(hold_id.as_str())?, Some(hold));
    assert_eq!(budget.get_invocation_quota_usage(&quota_key)?, Some(quota));
    Ok(())
}

fn elapsed_follows_the_authority_clock(nested: bool) -> TestResult {
    let clock = Arc::new(ScriptedClock::default());
    let during = clock.clone();
    let fixture = fixture("elapsed-authority", clock, move || during.advance(7))?;
    assert_eq!(evaluate(&fixture, nested)?.verdict, Verdict::Allow);
    assert_completed(&fixture, 7)
}

fn fixed_authority_clock_records_zero_elapsed(nested: bool) -> TestResult {
    let fixture = fixture(
        "elapsed-fixed",
        Arc::new(FixedClock::from_millis(NOW_MS)),
        || {},
    )?;
    assert_eq!(evaluate(&fixture, nested)?.verdict, Verdict::Allow);
    assert_completed(&fixture, 0)
}

fn start_read_failure_retains_the_committed_operation(nested: bool) -> TestResult {
    let probe_clock = Arc::new(ScriptedClock::default());
    // Give every read a distinct instant. A one-step recorded duration proves
    // the last pre-invocation read is the timer start, with no intervening read.
    probe_clock.script().step_ms = 1_000;
    let at_invoke = Arc::new(AtomicU64::new(0));
    let (observed, observer) = (probe_clock.clone(), at_invoke.clone());
    let probe = fixture("elapsed-start-fault", probe_clock.clone(), move || {
        observer.store(observed.reads(), Ordering::SeqCst);
    })?;
    let before = probe_clock.reads();
    assert_eq!(evaluate(&probe, nested)?.verdict, Verdict::Allow);
    assert_completed(&probe, 1_000)?;
    // The checked calibration must fail if dispatch grows another clock read.
    let start_read_offset = at_invoke.load(Ordering::SeqCst) - before;

    let clock = Arc::new(ScriptedClock::default());
    let fixture = fixture("elapsed-start-fault", clock.clone(), || {})?;
    clock.fail_read(clock.reads() + start_read_offset);
    let response = evaluate(&fixture, nested);
    assert_outcome_unknown(&fixture, response, 0, ClockError::Unavailable)
}

fn end_read_failure_retains_the_executed_operation(nested: bool) -> TestResult {
    let clock = Arc::new(ScriptedClock::default());
    let during = clock.clone();
    let fixture = fixture("elapsed-end-fault", clock, move || {
        during.fail_read(during.reads() + 1);
    })?;
    let response = evaluate(&fixture, nested);
    assert_outcome_unknown(&fixture, response, 1, ClockError::Unavailable)
}

fn monotonic_regression_retains_the_executed_operation(nested: bool) -> TestResult {
    let clock = Arc::new(ScriptedClock::default());
    clock.advance(1_000);
    let during = clock.clone();
    let fixture = fixture("elapsed-regression", clock, move || {
        during.regress_read(during.reads() + 1);
    })?;
    let response = evaluate(&fixture, nested);
    assert_outcome_unknown(&fixture, response, 1, ClockError::MonotonicRegression)
}

fn persistent_end_read_failure_withholds_the_terminal_receipt(nested: bool) -> TestResult {
    let clock = Arc::new(ScriptedClock::default());
    let during = clock.clone();
    let fixture = fixture("elapsed-persistent-end-fault", clock, move || {
        during.script().unavailable = true;
    })?;
    let result = evaluate(&fixture, nested);
    assert!(
        matches!(result, Err(KernelError::Clock(ClockError::Unavailable))),
        "{result:?}"
    );
    let operation = fixture.store.operation();
    assert_eq!(
        operation.state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert!(operation.terminal_replay().is_none());
    assert!(operation.dispatch_commit().is_some());
    assert_eq!(recorded_elapsed_millis(&fixture)?, None);
    let budget = fixture.store.budget_store();
    let hold_id = operation
        .budget_hold_id()
        .ok_or("missing original hold ID")?;
    let hold = budget
        .get_budget_hold(hold_id.as_str())?
        .ok_or("missing original hold")?;
    let quota_key = crate::budget_store::BudgetQuotaKey::grant(&fixture.request.capability.id, 0);
    let quota = budget
        .get_invocation_quota_usage(&quota_key)?
        .ok_or("missing committed quota")?;
    assert_eq!(
        (quota.reserved_invocations, quota.captured_invocations),
        (0, 1)
    );
    let replay = fixture.kernel.evaluate_tool_call_blocking(&fixture.request);
    assert!(
        matches!(replay, Err(KernelError::Clock(ClockError::Unavailable))),
        "{replay:?}"
    );
    assert_eq!(fixture.store.operation(), operation);
    assert_eq!(budget.get_budget_hold(hold_id.as_str())?, Some(hold));
    assert_eq!(budget.get_invocation_quota_usage(&quota_key)?, Some(quota));
    assert!(fixture
        .store
        .state
        .lock()
        .map_err(|_| "test admission state lock")?
        .receipt
        .is_none());
    assert!(fixture.kernel.receipt_log().is_empty());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn ordinary_dispatch_elapsed_follows_the_authority_clock() -> TestResult {
    elapsed_follows_the_authority_clock(false)
}

#[test]
fn nested_dispatch_elapsed_follows_the_authority_clock() -> TestResult {
    elapsed_follows_the_authority_clock(true)
}

#[test]
fn ordinary_fixed_authority_clock_records_zero_elapsed() -> TestResult {
    fixed_authority_clock_records_zero_elapsed(false)
}

#[test]
fn nested_fixed_authority_clock_records_zero_elapsed() -> TestResult {
    fixed_authority_clock_records_zero_elapsed(true)
}

#[test]
fn ordinary_start_read_failure_retains_the_committed_operation() -> TestResult {
    start_read_failure_retains_the_committed_operation(false)
}

#[test]
fn nested_start_read_failure_retains_the_committed_operation() -> TestResult {
    start_read_failure_retains_the_committed_operation(true)
}

#[test]
fn ordinary_end_read_failure_retains_the_executed_operation() -> TestResult {
    end_read_failure_retains_the_executed_operation(false)
}

#[test]
fn nested_end_read_failure_retains_the_executed_operation() -> TestResult {
    end_read_failure_retains_the_executed_operation(true)
}

#[test]
fn ordinary_monotonic_regression_retains_the_executed_operation() -> TestResult {
    monotonic_regression_retains_the_executed_operation(false)
}

#[test]
fn nested_monotonic_regression_retains_the_executed_operation() -> TestResult {
    monotonic_regression_retains_the_executed_operation(true)
}

#[test]
fn ordinary_persistent_end_read_failure_withholds_the_terminal_receipt() -> TestResult {
    persistent_end_read_failure_withholds_the_terminal_receipt(false)
}

#[test]
fn nested_persistent_end_read_failure_withholds_the_terminal_receipt() -> TestResult {
    persistent_end_read_failure_withholds_the_terminal_receipt(true)
}
