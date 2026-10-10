// Deterministic in-flight races over the original native owner.
use super::*;
use chio_kernel::RevocationStore;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

type NativeRaceResult = Result<chio_kernel::ToolCallResponse, KernelError>;

enum NativeRaceEvent {
    Entered,
    Finished(Box<std::thread::Result<NativeRaceResult>>),
}

enum NativeRaceProtocolError {
    FinishedBeforeEntered { cause: Option<Box<KernelError>> },
    WorkerPanicked,
    EnteredAgain,
}

impl std::fmt::Display for NativeRaceProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FinishedBeforeEntered { cause } => {
                formatter.write_str("native evaluation finished before required capture entry")?;
                if let Some(cause) = cause {
                    write!(formatter, " ({})", cause.report().code)?;
                }
                Ok(())
            }
            Self::WorkerPanicked => formatter.write_str("native race worker panicked"),
            Self::EnteredAgain => formatter.write_str("native race entered capture more than once"),
        }
    }
}

impl std::fmt::Debug for NativeRaceProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // A failed test reports the phase and error code, never a response or output.
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for NativeRaceProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FinishedBeforeEntered { cause: Some(cause) } => Some(cause.as_ref()),
            _ => None,
        }
    }
}

struct NativeRaceWorker {
    resume: Option<SyncSender<()>>,
    observed: Option<Receiver<NativeRaceEvent>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl NativeRaceWorker {
    fn spawn(
        resume: SyncSender<()>,
        observed: Receiver<NativeRaceEvent>,
        events: SyncSender<NativeRaceEvent>,
        evaluate: impl FnOnce() -> NativeRaceResult + Send + 'static,
    ) -> Self {
        let worker = std::thread::spawn(move || {
            // Even a worker panic must wake the observer: the installed hook
            // retains another sender, so channel disconnection alone is insufficient.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(evaluate));
            let _ = events.send(NativeRaceEvent::Finished(Box::new(result)));
        });
        Self {
            resume: Some(resume),
            observed: Some(observed),
            worker: Some(worker),
        }
    }

    fn receive(&self) -> TestResult<NativeRaceEvent> {
        Ok(self
            .observed
            .as_ref()
            .ok_or("native race observer missing")?
            .recv()?)
    }

    fn wait_for_capture(&mut self) -> TestResult {
        match self.receive()? {
            NativeRaceEvent::Entered => Ok(()),
            NativeRaceEvent::Finished(result) => match *result {
                Ok(result) => Err(NativeRaceProtocolError::FinishedBeforeEntered {
                    cause: result.err().map(Box::new),
                }
                .into()),
                Err(_) => Err(NativeRaceProtocolError::WorkerPanicked.into()),
            },
        }
    }

    fn finish(mut self) -> TestResult<NativeRaceResult> {
        self.resume
            .as_ref()
            .ok_or("native race resume sender missing")?
            .send(())?;
        drop(self.resume.take());
        let result = match self.receive()? {
            NativeRaceEvent::Finished(result) => *result,
            NativeRaceEvent::Entered => return Err(NativeRaceProtocolError::EnteredAgain.into()),
        };
        drop(self.observed.take());
        if let Some(worker) = self.worker.take() {
            worker
                .join()
                .map_err(|_| NativeRaceProtocolError::WorkerPanicked)?;
        }
        result.map_err(|_| NativeRaceProtocolError::WorkerPanicked.into())
    }
}

impl Drop for NativeRaceWorker {
    fn drop(&mut self) {
        // Disconnect the pause first, then the event channel. A worker leaving
        // the pause must not block sending Finished into a full event buffer.
        drop(self.resume.take());
        drop(self.observed.take());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, Copy)]
enum Pause {
    BeforeCapture,
    AfterCapture,
}
struct PauseHook {
    resolver: NativeFlowResolver,
    pause: Pause,
    events: SyncSender<NativeRaceEvent>,
    resume: Mutex<Receiver<()>>,
}
impl PauseHook {
    fn rendezvous(&self) -> Result<(), KernelError> {
        self.events
            .send(NativeRaceEvent::Entered)
            .map_err(|_| KernelError::Internal("capture observer left".into()))?;
        self.resume
            .lock()
            .map_err(|_| KernelError::Internal("capture barrier poisoned".into()))?
            .recv()
            .map_err(|_| KernelError::Internal("capture observer disconnected".into()))
    }
}
impl SecurityPreDispatchHook for PauseHook {
    fn name(&self) -> &str {
        "native-capture-rendezvous"
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
        if matches!(self.pause, Pause::BeforeCapture) {
            self.rendezvous()?;
        }
        self.resolver.commit_native_dispatch(authority)?;
        if matches!(self.pause, Pause::AfterCapture) {
            self.rendezvous()?;
        }
        Ok(())
    }
    fn commit(
        &self,
        _: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Err(KernelError::Internal(
            "native race reached legacy dispatch".into(),
        ))
    }
}

fn race(pause: Pause, revoke: bool) -> TestResult {
    let mut fixture = super::super::super::public_fixture()?;
    let (events, observed) = sync_channel(1);
    let (resume, waiting) = sync_channel(1);
    fixture
        .kernel
        .set_security_pre_dispatch_hook(Arc::new(PauseHook {
            resolver: resolver(fixture.binding.clone(), None, fixture.clock.clone())?,
            pause,
            events: events.clone(),
            resume: Mutex::new(waiting),
        }));
    let kernel = Arc::new(fixture.kernel);
    let mut worker = NativeRaceWorker::spawn(resume, observed, events, {
        let kernel = kernel.clone();
        let request = fixture.request.clone();
        let context = fixture.context.clone();
        move || kernel.evaluate_tool_call_blocking_with_security_context(&request, &context)
    });
    worker.wait_for_capture()?;
    if revoke {
        fixture
            .authority
            .revocation_store()
            .revoke(&fixture.request.capability.id)?;
    } else {
        assert_eq!(
            kernel.reconcile_recoverable_admissions()?,
            0,
            "recovery must skip the live evaluation"
        );
        let duplicate = kernel
            .evaluate_tool_call_blocking_with_security_context(&fixture.request, &fixture.context);
        if let Ok(response) = duplicate {
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
            assert!(
                response
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("live evaluation or recovery owner")),
                "{:?}",
                response.reason
            );
        }
    }
    let result = worker.finish()?;
    let store = fixture.authority.admission_operation_store();
    let (operation, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request", &fixture.request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("original race operation")?;
    let usage = fixture
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        .ok_or("race quota")?;
    if revoke {
        if let Ok(response) = result {
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
        }
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        let captured = matches!(pause, Pause::AfterCapture);
        assert_eq!(operation.dispatch_commit().is_some(), captured);
        assert_eq!(
            (usage.reserved_invocations, usage.captured_invocations),
            if captured { (0, 1) } else { (0, 0) }
        );
        if !captured {
            assert_eq!(
                operation.state(),
                AdmissionOperationState::CompensatedBeforeDispatch
            );
            let old_fence = fixture.authority.mutation_fence();
            drop(store);
            drop(kernel);
            drop(fixture.authority);
            let authority = SqliteAuthorityStore::open_serving_with_clock(
                fixture._directory.path().join("admission.db"),
                fixture._directory.path().join("locks"),
                fixture.clock.clone(),
            )?;
            assert!(authority.mutation_fence().owner_epoch > old_fence.owner_epoch);
            let (mut recovered, invocations) = open_kernel(
                fixture._directory.path(),
                &authority,
                &fixture.signer,
                fixture.clock.clone(),
            )?;
            recovered.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
            recovered.set_security_pre_dispatch_hook(Arc::new(resolver(
                fixture.binding,
                None,
                fixture.clock.clone(),
            )?));
            recovered.reconcile_durable_admission_startup()?;
            let (current, _) = authority
                .admission_operation_store()
                .load_retained_tool_request(
                    operation.binding().operation_id(),
                    &authority.mutation_fence(),
                    now_ms()?,
                )?
                .ok_or("original revoked operation")?;
            assert_eq!(
                current.state(),
                AdmissionOperationState::CompensatedBeforeDispatch
            );
            assert_eq!(current.binding(), operation.binding());
            let usage = authority
                .budget_store()
                .get_invocation_quota_usage(&BudgetQuotaKey::grant(
                    &fixture.request.capability.id,
                    0,
                ))?
                .ok_or("reconciled quota")?;
            assert_eq!(
                (usage.reserved_invocations, usage.captured_invocations),
                (0, 0)
            );
            let response = recovered.evaluate_tool_call_blocking_with_security_context(
                &fixture.request,
                &fixture.context,
            )?;
            assert_eq!(response.verdict, Verdict::Deny);
            assert!(response.output.is_none());
            assert_eq!(invocations.load(Ordering::SeqCst), 0);
        }
    } else {
        let response = result?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(response.receipt.verify_signature()?);
        assert_eq!(operation.state(), AdmissionOperationState::Completed);
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
        assert_eq!(
            (usage.reserved_invocations, usage.captured_invocations),
            (0, 1)
        );
        let replay = kernel.evaluate_tool_call_blocking_with_security_context(
            &fixture.request,
            &fixture.context,
        )?;
        assert_eq!(
            chio_core::canonical_json_bytes(&response.receipt)?,
            chio_core::canonical_json_bytes(&replay.receipt)?
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    }
    Ok(())
}

#[test]
fn revocation_wins_before_native_capture() -> TestResult {
    race(Pause::BeforeCapture, true)
}
#[test]
fn revocation_after_native_capture_fences_connector_handoff() -> TestResult {
    race(Pause::AfterCapture, true)
}
#[test]
fn duplicate_native_start_cannot_steal_the_live_operation() -> TestResult {
    race(Pause::BeforeCapture, false)
}

#[test]
fn evaluation_failure_before_capture_preserves_the_actual_typed_cause() -> TestResult {
    let (events, observed) = sync_channel(1);
    let (resume, waiting) = sync_channel(1);
    let mut worker = NativeRaceWorker::spawn(resume, observed, events, move || {
        drop(waiting);
        Err(KernelError::CapabilityRevoked("protocol-control".into()))
    });
    let error = match worker.wait_for_capture() {
        Ok(()) => return Err("an early failure was accepted as capture entry".into()),
        Err(error) => error,
    };
    let protocol = error
        .downcast_ref::<NativeRaceProtocolError>()
        .ok_or("early failure lost its protocol category")?;
    assert!(matches!(
        protocol,
        NativeRaceProtocolError::FinishedBeforeEntered { cause: Some(_) }
    ));
    let cause = std::error::Error::source(protocol)
        .and_then(|cause| cause.downcast_ref::<KernelError>())
        .ok_or("early evaluation failure lost its typed source")?;
    assert!(matches!(
        cause,
        KernelError::CapabilityRevoked(id) if id == "protocol-control"
    ));
    drop(worker);
    Ok(())
}

#[test]
fn worker_panic_before_capture_reports_completion_instead_of_waiting_for_entry() -> TestResult {
    let (events, observed) = sync_channel(1);
    let (resume, waiting) = sync_channel(1);
    let mut worker = NativeRaceWorker::spawn(resume, observed, events, move || {
        drop(waiting);
        panic!("injected native race worker panic");
    });
    let error = match worker.wait_for_capture() {
        Ok(()) => return Err("a worker panic was accepted as capture entry".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error.downcast_ref::<NativeRaceProtocolError>(),
        Some(NativeRaceProtocolError::WorkerPanicked)
    ));
    drop(worker);
    Ok(())
}

#[test]
fn observer_unwind_disconnects_a_full_event_channel_before_joining() -> TestResult {
    let (events, observed) = sync_channel(1);
    let (resume, waiting) = sync_channel(1);
    let (buffered, buffer_observed) = sync_channel(1);
    let capture_events = events.clone();
    let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let worker_released = Arc::clone(&released);
    let resource = Arc::new(());
    let retained_resource = Arc::downgrade(&resource);
    let worker = NativeRaceWorker::spawn(resume, observed, events, move || {
        let _owned_resource = resource;
        capture_events
            .send(NativeRaceEvent::Entered)
            .map_err(|_| KernelError::Internal("protocol observer left".into()))?;
        buffered
            .send(())
            .map_err(|_| KernelError::Internal("protocol observer left".into()))?;
        match waiting.recv() {
            Err(_) => {
                worker_released.store(true, Ordering::SeqCst);
                Err(KernelError::Internal(
                    "protocol observer disconnected".into(),
                ))
            }
            Ok(()) => Err(KernelError::Internal(
                "unwinding observer incorrectly resumed evaluation".into(),
            )),
        }
    });
    // The Entered event occupies the only slot. Cleanup must disconnect both
    // channels before joining, or the worker's Finished send can block forever.
    buffer_observed.recv()?;
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned_worker = worker;
        panic!("injected native race observer unwind");
    }));
    let panic = match unwind {
        Err(panic) => panic,
        Ok(()) => return Err("observer unwind control did not unwind".into()),
    };
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("injected native race observer unwind")
    );
    assert!(released.load(Ordering::SeqCst));
    assert_eq!(retained_resource.strong_count(), 0);
    Ok(())
}
