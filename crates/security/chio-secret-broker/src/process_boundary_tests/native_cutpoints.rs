//! Real broker death at durable boundaries, with an independent TLS observer.
use super::*;
use chio_kernel::budget_store::BudgetInvocationQuota;
use std::sync::Mutex;

#[path = "native_cutpoint_adapters.rs"]
mod adapters;
pub(super) use adapters::{wrap_connection, wrap_participant};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
const NO_EFFECT_ENV: &str = "CHIO_BOUNDARY_EXPECT_NO_EFFECT";
const EFFECT_GATE_ENV: &str = "CHIO_BOUNDARY_EFFECT_GATE";
const ZERO_EFFECT_REPORT: &str = "CHIO_BOUNDARY_NO_PROVIDER_CONNECTIONS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    Registered,
    Captured,
    ProviderEffect,
}

pub(super) struct Control {
    point: Point,
    broker_pid: u32,
    effect_gate: PathBuf,
    triggered: AtomicBool,
    dispatch_calls: std::sync::atomic::AtomicUsize,
    quotas: Mutex<Vec<BudgetInvocationQuota>>,
}

impl Control {
    #[cfg(feature = "real-linux-enforcement")]
    pub(super) fn was_captured(&self) -> bool {
        self.point != Point::Registered
    }

    pub(super) fn new(point: Point, broker_pid: u32, root: &Path) -> Self {
        Self {
            point,
            broker_pid,
            effect_gate: root.join("provider-effect-observed"),
            triggered: AtomicBool::new(false),
            dispatch_calls: std::sync::atomic::AtomicUsize::new(0),
            quotas: Mutex::new(Vec::new()),
        }
    }

    fn kill_at(&self, point: Point) {
        if self.point != point {
            return;
        }
        assert!(!self.triggered.swap(true, Ordering::SeqCst));
        let pid = rustix::process::Pid::from_raw(
            i32::try_from(self.broker_pid).test_expect("owned PID range"),
        )
        .test_expect("owned broker PID");
        rustix::process::kill_process(pid, rustix::process::Signal::KILL)
            .test_expect("kill owned broker at exact cutpoint");
        // The controller retains Child until verification. Its unreaped PID
        // cannot be reused, and observing Z closes the signal-delivery race.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = fs::read_to_string(format!("/proc/{}/status", self.broker_pid))
                .test_expect("owned broker status after SIGKILL");
            if status.lines().any(|line| line.starts_with("State:\tZ")) {
                break;
            }
            assert!(Instant::now() < deadline, "broker survived its cutpoint");
            thread::sleep(Duration::from_millis(2));
        }
    }

    pub(super) fn start_observer(
        self: &Arc<Self>,
        command: &mut Command,
    ) -> Option<JoinHandle<()>> {
        if self.point != Point::ProviderEffect {
            command.env(NO_EFFECT_ENV, "1");
            return None;
        }
        command.env(EFFECT_GATE_ENV, &self.effect_gate);
        let control = Arc::clone(self);
        Some(thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !control.effect_gate.exists() {
                assert!(
                    Instant::now() < deadline,
                    "provider effect was never observed"
                );
                thread::sleep(Duration::from_millis(2));
            }
            assert_eq!(
                fs::read(&control.effect_gate).test_expect("provider effect marker"),
                b"observed"
            );
            control.kill_at(Point::ProviderEffect);
            write_private(
                &control.effect_gate.with_extension("release"),
                b"broker-dead",
            );
        }))
    }

    pub(super) fn verify_capture_and_replay(
        &self,
        host: &host::NativeHost,
        replay_allowed: impl FnOnce() -> bool,
    ) -> TestResult {
        assert!(
            self.triggered.load(Ordering::SeqCst),
            "cutpoint was not reached"
        );
        let now_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        let store = host.authority.admission_operation_store();
        let fence = host.authority.mutation_fence();
        let (operation, _) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request", &host.request.request_id)?,
                &fence,
                now_ms,
            )?
            .ok_or("original operation disappeared after broker death")?;
        let expected_capture = u32::from(self.point != Point::Registered);
        if expected_capture == 1 {
            assert_eq!(
                operation.state(),
                AdmissionOperationState::OutcomeUnknownAfterDispatch
            );
            let custody = store
                .load_admission_budget_custody(operation.binding().operation_id(), &fence, now_ms)?
                .ok_or("captured custody disappeared after broker death")?;
            assert_eq!(custody.invocation_state, BudgetInvocationState::Captured);
        } else {
            assert_ne!(
                operation.state(),
                AdmissionOperationState::OutcomeUnknownAfterDispatch
            );
        }
        let quotas = self
            .quotas
            .lock()
            .test_expect("original quota observation")
            .clone();
        assert_eq!(
            quotas.len(),
            3,
            "original parent, aggregate and broker quotas"
        );
        let budget = host.authority.budget_store();
        for quota in quotas.iter() {
            let usage = budget.get_invocation_quota_usage(&quota.key)?;
            assert_eq!(
                usage.as_ref().map_or(0, |usage| usage.captured_invocations),
                expected_capture
            );
            assert_eq!(
                usage.as_ref().map_or(0, |usage| usage.reserved_invocations),
                0
            );
        }
        let before = budget.list_mutation_events(100, Some(&host.request.capability.id), None)?;
        let dispatches = usize::from(self.point != Point::Registered);
        assert_eq!(self.dispatch_calls.load(Ordering::SeqCst), dispatches);
        assert!(
            !replay_allowed(),
            "broker death authorized another delivery"
        );
        assert_eq!(self.dispatch_calls.load(Ordering::SeqCst), dispatches);
        assert_eq!(
            budget.list_mutation_events(100, Some(&host.request.capability.id), None)?,
            before
        );
        for quota in quotas.iter() {
            let usage = budget.get_invocation_quota_usage(&quota.key)?;
            assert_eq!(
                usage.as_ref().map_or(0, |usage| usage.captured_invocations),
                expected_capture
            );
            assert_eq!(
                usage.as_ref().map_or(0, |usage| usage.reserved_invocations),
                0
            );
        }
        Ok(())
    }

    pub(super) fn verify_provider(
        &self,
        output: &Output,
        execute: &BrokerExecuteRequest,
        canary: &[u8],
    ) -> TestResult {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_raw_absent(canary, &output.stdout, "cutpoint provider stdout");
        assert_raw_absent(canary, &output.stderr, "cutpoint provider stderr");
        if self.point == Point::ProviderEffect {
            let report: UpstreamBoundaryReport =
                report_from_output(&output.stdout, UPSTREAM_REPORT_PREFIX);
            assert_eq!(report.connection_count, 1);
            assert_eq!(report.credential_matches, 1);
            assert!(report.authorization_exact_bearer_canary);
            assert_eq!(
                report.request_sha256,
                hex::encode(Sha256::digest(expected_boundary_http_request(
                    execute, canary
                )))
            );
        } else {
            assert!(std::str::from_utf8(&output.stdout)?.contains(ZERO_EFFECT_REPORT));
            assert!(!std::str::from_utf8(&output.stdout)?.contains(UPSTREAM_REPORT_PREFIX));
        }
        Ok(())
    }
}

pub(in super::super) fn observe_no_effect(listener: &TcpListener) -> bool {
    if std::env::var_os(NO_EFFECT_ENV).is_none() {
        return false;
    }
    assert_eq!(required_environment(NO_EFFECT_ENV), "1");
    let complete = PathBuf::from(required_environment(FALLBACK_MARKER_ENV));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut quiet_deadline = None;
    loop {
        match listener.accept() {
            Ok(_) => panic!("broker death before send still reached the provider"),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("zero-effect provider observation failed: {error}"),
        }
        let now = Instant::now();
        if complete.exists() && quiet_deadline.is_none() {
            quiet_deadline = Some(now + Duration::from_millis(250));
        }
        if quiet_deadline.is_some_and(|quiet| now >= quiet) {
            break;
        }
        assert!(now < deadline, "zero-effect observation did not complete");
        thread::sleep(Duration::from_millis(2));
    }
    println!("{ZERO_EFFECT_REPORT}");
    true
}

pub(in super::super) fn hold_provider_response() -> bool {
    let Some(gate) = std::env::var_os(EFFECT_GATE_ENV).map(PathBuf::from) else {
        return false;
    };
    write_private(&gate, b"observed");
    let released = gate.with_extension("release");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !released.exists() {
        assert!(Instant::now() < deadline, "broker death was not observed");
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        fs::read(released).test_expect("broker death marker"),
        b"broker-dead"
    );
    true
}

#[test]
fn native_broker_death_after_registration_has_no_effect_or_capture() -> TestResult {
    run_native_delivery_with_cutpoint(DeliveryRoute::ObservedMcp, None, Some(Point::Registered))
}

#[test]
fn native_broker_death_after_capture_retains_all_quotas_without_effect() -> TestResult {
    run_native_delivery_with_cutpoint(DeliveryRoute::ObservedMcp, None, Some(Point::Captured))
}

#[test]
fn native_broker_death_after_provider_effect_retains_capture_and_refuses_replay() -> TestResult {
    run_native_delivery_with_cutpoint(
        DeliveryRoute::ObservedMcp,
        None,
        Some(Point::ProviderEffect),
    )
}

#[cfg(feature = "real-linux-enforcement")]
#[test]
fn confined_broker_process_cutpoints_preserve_provider_and_quota_observations() -> TestResult {
    for point in [Point::Registered, Point::Captured, Point::ProviderEffect] {
        run_native_delivery_with_cutpoint(DeliveryRoute::ConfinedMcp, None, Some(point))?;
    }
    Ok(())
}
