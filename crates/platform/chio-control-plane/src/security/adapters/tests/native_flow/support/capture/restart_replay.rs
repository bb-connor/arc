// Separates a restarted worker's replay from a fence crossing inside capture.
// The original evaluation pauses after retention and before the store capture,
// which is the only window where an elapsed fence surfaces as the store stage
// policy_expired rather than a resolver clock or egress deadline refusal.
use super::*;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

const HANG_GUARD: Duration = Duration::from_secs(60);
const LIVE_OWNER: &str =
    "durable admission failed: operation already has a live evaluation or recovery owner";
const RECONCILIATION_REQUIRED: &str = "security dispatch outcome requires reconciliation: security native dispatch capture callback failed; authoritative recovery required";
const UNCONFIRMED_REPLAY: &str =
    "durable admission failed: native preparation requires original pre-budget authority";

#[derive(Clone, Default)]
struct Transcript(Arc<Mutex<Vec<String>>>);

impl Transcript {
    fn push(&self, line: String) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }

    fn lines(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[derive(Default)]
struct WarnFields {
    message: Option<String>,
    stage: Option<String>,
    fault: Option<String>,
}

impl Visit for WarnFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "native_capture_stage" => self.stage = Some(value.to_owned()),
            "native_dispatch_fault" => self.fault = Some(value.to_owned()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = Some(format!("{value:?}")),
            "native_capture_stage" => self.stage = Some(format!("{value:?}")),
            "native_dispatch_fault" => self.fault = Some(format!("{value:?}")),
            _ => {}
        }
    }
}

// Records WARN events in the order the host would print them, without
// request identifiers or payloads.
impl<S: tracing::Subscriber> Layer<S> for Transcript {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        let mut fields = WarnFields::default();
        event.record(&mut fields);
        let mut line = format!(
            "WARN {} {}",
            event.metadata().target(),
            fields.message.unwrap_or_default()
        );
        if let Some(stage) = fields.stage {
            line.push_str(&format!(" native_capture_stage={stage}"));
        }
        if let Some(fault) = fields.fault {
            line.push_str(&format!(" native_dispatch_fault={fault}"));
        }
        self.push(line);
    }
}

struct Paused {
    deadline: u64,
}

/// Plans with the real resolver and retains through the public capture
/// authority, then holds the first evaluation before the store capture.
struct WindowHook {
    resolver: NativeFlowResolver,
    paused: SyncSender<Paused>,
    resume: Mutex<Receiver<()>>,
    used: AtomicBool,
    phases: Mutex<Vec<(&'static str, Duration)>>,
}

impl WindowHook {
    fn phase(&self, name: &'static str, since: std::time::Instant) {
        self.phases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((name, since.elapsed()));
    }

    fn hold(&self, deadline: u64) -> Result<(), KernelError> {
        if self.used.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        self.paused
            .send(Paused { deadline })
            .map_err(|_| KernelError::Internal("window observer left".into()))?;
        self.resume
            .lock()
            .map_err(|_| KernelError::Internal("window barrier poisoned".into()))?
            .recv_timeout(HANG_GUARD)
            .map_err(|_| KernelError::Internal("window observer did not resume".into()))
    }
}

impl SecurityPreDispatchHook for WindowHook {
    fn name(&self) -> &str {
        "native-capture-window"
    }

    fn supports_native_dispatch(&self) -> bool {
        true
    }

    fn native_authority_binding(
        &self,
    ) -> Result<Option<NativeSecurityAuthorityBindingV1>, KernelError> {
        self.resolver.native_authority_binding()
    }

    fn prepare_native_admission(
        &self,
        context: &NativeSecurityAdmissionContext<'_>,
        authority: &NativeSecurityFlowJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver.prepare_native_admission(context, authority)
    }

    fn prepare_native_output(
        &self,
        context: &chio_kernel::tool_outcome::DurableSecurityReleaseContext<'_>,
        authority: &chio_kernel::NativeSecurityOutputJoinAuthority<'_>,
    ) -> Result<(), KernelError> {
        self.resolver.prepare_native_output(context, authority)
    }

    fn commit_native_dispatch(
        &self,
        authority: &mut chio_kernel::NativeSecurityDispatchCaptureAuthority<'_, '_>,
    ) -> Result<(), KernelError> {
        let started = std::time::Instant::now();
        let planned = self
            .resolver
            .prepare_dispatch(authority.prepare_egress()?)
            .map_err(|error| KernelError::GuardDenied(error.to_string()))?;
        let policy = planned.policy_evidence().canonical_bytes().to_vec();
        let deadline = planned
            .admission()
            .egress_fence_plan
            .as_ref()
            .map(|plan| plan.expires_at_unix_ms)
            .ok_or_else(|| KernelError::Internal("window hook requires an egress plan".into()))?;
        drop(planned);
        self.phase("resolve", started);
        let retaining = std::time::Instant::now();
        let grant_index = authority.grant_index()?;
        let retained = authority.prepare_egress()?;
        let (prepared, _, ledger) =
            retained.retain_for_capture(Some(deadline), grant_index, &policy)?;
        self.phase("retain_for_capture", retaining);
        self.hold(deadline)?;
        let capturing = std::time::Instant::now();
        let captured = authority.capture(prepared, &ledger, &policy).map(|_| ());
        self.phase("store_capture", capturing);
        self.phase("resolve_to_capture_total", started);
        captured
    }

    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "native capture window reached legacy dispatch".into(),
        ))
    }
}

type Evaluation = std::thread::Result<Result<chio_kernel::ToolCallResponse, KernelError>>;

fn outcome(label: &str, result: Evaluation) -> String {
    match result {
        Ok(Ok(response)) => format!(
            "{label}: {:?} {}",
            response.verdict,
            response.reason.unwrap_or_default()
        ),
        Ok(Err(error)) => format!("{label}: error {error}"),
        Err(_) => format!("{label}: panicked"),
    }
}

/// Run one evaluation on its own thread with the shared transcript as its
/// subscriber, so a lock wait inside the kernel cannot hang the test.
fn evaluate_on_thread(
    kernel: &Arc<ChioKernel>,
    fixture_request: &ToolCallRequest,
    fixture_context: &SecurityInvocationContext,
    transcript: &Transcript,
) -> Receiver<Evaluation> {
    let (sender, receiver) = sync_channel(1);
    let kernel = kernel.clone();
    let request = fixture_request.clone();
    let context = fixture_context.clone();
    let transcript = transcript.clone();
    std::thread::spawn(move || {
        let _subscriber = tracing::subscriber::set_default(Registry::default().with(transcript));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)
        }));
        let _ = sender.send(result);
    });
    receiver
}

fn finished(receiver: &Receiver<Evaluation>, label: &str) -> TestResult<String> {
    match receiver.recv_timeout(HANG_GUARD) {
        Ok(result) => Ok(outcome(label, result)),
        Err(RecvTimeoutError::Timeout) => Err(format!("{label} did not finish").into()),
        Err(RecvTimeoutError::Disconnected) => Err(format!("{label} thread vanished").into()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Control {
    /// Restart replay while the original is paused, then release in time.
    ReplayOnly,
    /// No restart: the paused window alone crosses the policy fence.
    FenceOnly,
    /// Restart replay while paused, and the window crosses the fence.
    ReplayAndFence,
}

struct Observed {
    transcript: Vec<String>,
    state: AdmissionOperationState,
    invocations: usize,
    quota: (u32, u32),
}

fn run(control: Control) -> TestResult<Observed> {
    let mut fixture = Fixture::combined_native_credentials()?;
    let (paused, observed) = sync_channel(1);
    let (resume, waiting) = sync_channel(1);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(Arc::new(WindowHook {
            resolver: NativeFlowResolver::new(
                fixture.binding.clone(),
                super::super::super::registry(true, InformationLabel::bottom())?,
                Arc::new(CountingEmptyClassifier::new()),
                fixture.clock.clone(),
                flow_config(),
            )?,
            paused,
            resume: Mutex::new(waiting),
            used: AtomicBool::new(false),
            phases: Mutex::new(Vec::new()),
        }));
    let kernel = Arc::new(fixture.kernel);
    let transcript = Transcript::default();

    // Attempt 1 enters the capture window and stops before the store capture.
    let first = evaluate_on_thread(&kernel, &fixture.request, &fixture.context, &transcript);
    let window = match observed.recv_timeout(HANG_GUARD) {
        Ok(window) => window,
        Err(_) => {
            let early = finished(&first, "attempt 1")?;
            return Err(format!("attempt 1 never reached the capture window: {early}").into());
        }
    };
    transcript.push("attempt 1: paused after retention, before store capture".into());

    if control != Control::FenceOnly {
        // Attempt 2: the restarted worker resends the same operation.
        let second = evaluate_on_thread(&kernel, &fixture.request, &fixture.context, &transcript);
        transcript.push(finished(&second, "attempt 2")?);
    }
    if control != Control::ReplayOnly {
        fixture.clock.advance_to(window.deadline)?;
        transcript.push("clock: advanced to the policy fence".into());
    }
    resume.send(())?;
    transcript.push(finished(&first, "attempt 1")?);

    // Attempt 3: the next restarted worker resends the same operation again.
    let third = evaluate_on_thread(&kernel, &fixture.request, &fixture.context, &transcript);
    transcript.push(finished(&third, "attempt 3")?);

    let store = fixture.authority.admission_operation_store();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            fixture.clock.snapshot(),
        )?
        .ok_or("original operation")?;
    let quota = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .map_or((0, 0), |usage| {
            (usage.reserved_invocations, usage.captured_invocations)
        });
    let transcript = transcript.lines();
    eprintln!("control {control:?}:");
    for line in &transcript {
        eprintln!("  {line}");
    }
    eprintln!("  state={:?} quota={quota:?}", operation.state());
    Ok(Observed {
        transcript,
        state: operation.state(),
        invocations: fixture.invocations.load(Ordering::SeqCst),
        quota,
    })
}

fn contains(transcript: &[String], needle: &str) -> bool {
    transcript.iter().any(|line| line.contains(needle))
}

fn position(transcript: &[String], needle: &str) -> TestResult<usize> {
    transcript
        .iter()
        .position(|line| line.contains(needle))
        .ok_or_else(|| format!("transcript lacks {needle:?}: {transcript:#?}").into())
}

#[test]
fn restart_replay_alone_is_refused_and_the_original_completes() -> TestResult {
    let observed = run(Control::ReplayOnly)?;
    let lines = &observed.transcript;
    assert!(
        contains(lines, &format!("attempt 2: Deny {LIVE_OWNER}")),
        "{lines:#?}"
    );
    assert!(contains(lines, "attempt 1: Allow"), "{lines:#?}");
    assert!(
        !contains(lines, "native_capture_stage=policy_expired"),
        "{lines:#?}"
    );
    assert!(!contains(lines, UNCONFIRMED_REPLAY), "{lines:#?}");
    assert_eq!(observed.state, AdmissionOperationState::Completed);
    assert_eq!(observed.invocations, 1);
    assert_eq!(observed.quota, (0, 1));
    Ok(())
}

#[test]
fn fence_crossing_inside_capture_wedges_without_any_restart() -> TestResult {
    let observed = run(Control::FenceOnly)?;
    let lines = &observed.transcript;
    assert!(!contains(lines, LIVE_OWNER), "{lines:#?}");
    let expired = position(lines, "native_capture_stage=policy_expired")?;
    let rejected = position(lines, "native_dispatch_fault=capture_store_rejected")?;
    let first = position(lines, &format!("attempt 1: Deny {RECONCILIATION_REQUIRED}"))?;
    let third = position(lines, &format!("attempt 3: Deny {UNCONFIRMED_REPLAY}"))?;
    assert!(
        expired < rejected && rejected < first && first < third,
        "{lines:#?}"
    );
    assert_eq!(observed.invocations, 0);
    Ok(())
}

#[test]
fn restart_replay_plus_fence_crossing_reproduces_the_hosted_sequence() -> TestResult {
    let replayed = run(Control::ReplayAndFence)?;
    let lines = &replayed.transcript;
    let owner = position(lines, &format!("attempt 2: Deny {LIVE_OWNER}"))?;
    let expired = position(lines, "native_capture_stage=policy_expired")?;
    let rejected = position(lines, "native_dispatch_fault=capture_store_rejected")?;
    let first = position(lines, &format!("attempt 1: Deny {RECONCILIATION_REQUIRED}"))?;
    let third = position(lines, &format!("attempt 3: Deny {UNCONFIRMED_REPLAY}"))?;
    assert!(
        owner < expired && expired < rejected && rejected < first && first < third,
        "{lines:#?}"
    );
    assert_eq!(replayed.invocations, 0);

    // The replay changes no custody: the terminal state, quota and effects
    // match the fence-only control exactly.
    let fence_only = run(Control::FenceOnly)?;
    assert_eq!(replayed.state, fence_only.state);
    assert_eq!(replayed.quota, fence_only.quota);
    assert_eq!(replayed.invocations, fence_only.invocations);
    Ok(())
}

#[test]
fn unpaused_capture_window_phase_timings() -> TestResult {
    let mut fixture = Fixture::combined_native_credentials()?;
    let (paused, _observed) = sync_channel(1);
    let (_resume, waiting) = sync_channel(1);
    let hook = Arc::new(WindowHook {
        resolver: NativeFlowResolver::new(
            fixture.binding.clone(),
            super::super::super::registry(true, InformationLabel::bottom())?,
            Arc::new(CountingEmptyClassifier::new()),
            fixture.clock.clone(),
            flow_config(),
        )?,
        paused,
        resume: Mutex::new(waiting),
        // Already used: the evaluation never holds.
        used: AtomicBool::new(true),
        phases: Mutex::new(Vec::new()),
    });
    fixture.kernel.set_security_pre_dispatch_hook(hook.clone());
    let started = std::time::Instant::now();
    let response = fixture
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context)?;
    let total = started.elapsed();
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let phases = hook
        .phases
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    eprintln!("unpaused phases:");
    for (name, elapsed) in &phases {
        eprintln!("  {name} = {} ms", elapsed.as_millis());
    }
    eprintln!("  whole_evaluation = {} ms", total.as_millis());
    assert_eq!(phases.len(), 4, "{phases:?}");
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}
