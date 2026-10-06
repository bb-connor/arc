use super::*;
use crate::proxy::state::admission_maintenance::{MaintenanceControl, MaintenanceLifecycle};
use std::sync::Condvar;

#[derive(Default)]
struct GateState {
    closed: bool,
    entered: bool,
    returned: bool,
}

#[derive(Default)]
pub(super) struct CaptureGate {
    state: StdMutex<GateState>,
    changed: Condvar,
}

impl CaptureGate {
    pub(super) fn wait(&self) -> Result<(), PaymentError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PaymentError::RailError("fixture gate lock".into()))?;
        if state.closed {
            state.entered = true;
            self.changed.notify_all();
            state = self
                .changed
                .wait_while(state, |state| state.closed)
                .map_err(|_| PaymentError::RailError("fixture gate lock".into()))?;
        }
        state.returned = true;
        Ok(())
    }

    fn close(&self) -> TestResult {
        let mut state = self.state.lock().map_err(|_| "gate lock")?;
        state.closed = true;
        state.entered = false;
        state.returned = false;
        Ok(())
    }

    fn release(&self) -> TestResult {
        self.state.lock().map_err(|_| "gate lock")?.closed = false;
        self.changed.notify_all();
        Ok(())
    }

    fn entered(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.entered)
            .unwrap_or(false)
    }

    fn returned(&self) -> bool {
        self.state
            .lock()
            .map(|state| state.returned)
            .unwrap_or(false)
    }
}

async fn wait_until(mut ready: impl FnMut() -> bool) -> TestResult {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !ready() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if !ready() {
        return Err("actual maintenance event did not arrive before fixture deadline".into());
    }
    Ok(())
}

fn start(
    fixture: &Fixture,
    controller: Arc<ShutdownController>,
) -> Result<AdmissionMaintenance, ProtectError> {
    let kernel = fixture
        .state
        .mediation_kernel
        .as_ref()
        .ok_or_else(|| ProtectError::Config("fixture omitted its original kernel".into()))?;
    AdmissionMaintenance::spawn(kernel.clone(), true, controller, Duration::from_millis(10))
}

#[tokio::test]
async fn admission_host_retry_known_pending_keeps_health_ready() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (operation, status) = fixture.prepare_pending().await?;
    fixture
        .source
        .advance_past(status.deferral.retry_not_before_unix_ms)?;
    let controller = Arc::new(ShutdownController::manual());
    let mut owner = start(&fixture, controller.clone())?;
    let control = owner.control();
    wait_until(|| control.health().ticks_completed > 0).await?;
    assert_eq!(control.health().lifecycle, MaintenanceLifecycle::Ready);
    assert!(control.failure().is_none());
    assert!(!controller.is_shutdown());
    let status = fixture
        .authority
        .admission_operation_store()
        .load_recovery_status(
            &operation,
            &fixture.authority.mutation_fence(),
            fixture.state.clock.millis()?,
        )?
        .ok_or("retained pending marker")?;
    assert!(status.quarantined);
    assert!(status.deferral.attempt_count >= 2);
    assert_eq!(fixture.trace.dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.trace.financial_effects.load(Ordering::SeqCst), 0);
    owner.stop_and_join(Duration::from_secs(1)).await;
    assert!(control.health().worker_joined);
    Ok(())
}

#[tokio::test]
async fn admission_host_retry_busy_kernel_shutdown_does_not_deadlock() -> TestResult {
    let fixture = Fixture::new()?;
    let kernel = fixture
        .state
        .mediation_kernel
        .as_ref()
        .ok_or("original kernel")?;
    let held_request = kernel.lock().await;
    let controller = Arc::new(ShutdownController::manual());
    let owner = start(&fixture, controller.clone())?;
    let control = owner.control();
    wait_until(|| control.health().busy_skips > 0).await?;
    let started = std::time::Instant::now();
    drop(owner);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(control.health().worker_joined);
    assert!(!control.health().worker_running);
    assert!(!controller.is_shutdown());
    drop(held_request);
    Ok(())
}

#[tokio::test]
async fn admission_host_retry_global_clock_fault_stops_ticks_with_native_cause() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.source.rejected.store(true, Ordering::SeqCst);
    let controller = Arc::new(ShutdownController::manual());
    let mut owner = start(&fixture, controller.clone())?;
    let control = owner.control();
    wait_until(|| controller.is_shutdown()).await?;
    owner.stop_and_join(Duration::from_secs(1)).await;
    assert_eq!(control.health().lifecycle, MaintenanceLifecycle::Failed);
    let native = control.failure().ok_or("native global clock failure")?;
    assert!(matches!(
        native.as_ref(),
        KernelError::Clock(ClockError::Unavailable)
    ));
    let projected = ProtectError::MediationMaintenance(native.clone());
    assert!(
        matches!(&projected, ProtectError::MediationMaintenance(error)
        if matches!(error.as_ref(), KernelError::Clock(ClockError::Unavailable)))
    );
    let mut source = std::error::Error::source(&projected);
    let mut found_clock = false;
    while let Some(error) = source {
        if error.downcast_ref::<ClockError>() == Some(&ClockError::Unavailable) {
            found_clock = true;
        }
        source = error.source();
    }
    assert!(found_clock, "native clock cause must remain downcastable");
    let attempts = control.health().ticks_attempted;
    fixture.source.rejected.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(control.health().ticks_attempted, attempts);
    assert_eq!(fixture.trace.dispatches.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.trace.financial_effects.load(Ordering::SeqCst), 0);
    assert!(control.health().worker_joined);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_host_retry_shutdown_joins_before_kernel_retirement() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (_, status) = fixture.prepare_pending().await?;
    fixture
        .source
        .advance_past(status.deferral.retry_not_before_unix_ms)?;
    fixture.trace.pending.store(false, Ordering::SeqCst);
    fixture.trace.gate.close()?;
    let weak = Arc::downgrade(
        fixture
            .state
            .mediation_kernel
            .as_ref()
            .ok_or("original kernel")?,
    );
    let trace = fixture.trace.clone();
    let mut owner = start(&fixture, Arc::new(ShutdownController::manual()))?;
    let control = owner.control();
    wait_until(|| trace.gate.entered()).await?;
    let Fixture {
        state,
        _directory: directory,
        authority,
        ..
    } = fixture;
    drop(state);
    let joined = tokio::spawn(async move {
        owner.stop_and_join(Duration::from_millis(20)).await;
        owner
    });
    wait_until(|| control.health().shutdown_overdue).await?;
    assert!(!joined.is_finished());
    assert!(
        weak.upgrade().is_some(),
        "the original kernel must remain owned during its active tick"
    );
    assert!(!trace.gate.returned());
    assert_eq!(trace.financial_effects.load(Ordering::SeqCst), 0);
    trace.gate.release()?;
    let owner = joined.await?;
    assert!(control.health().worker_joined);
    assert!(trace.gate.returned());
    assert!(
        weak.upgrade().is_none(),
        "native completion and join precede original kernel retirement"
    );
    let captures = trace.captures.lock().map_err(|_| "capture trace")?.len();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        trace.captures.lock().map_err(|_| "capture trace")?.len(),
        captures
    );
    assert_eq!(trace.dispatches.load(Ordering::SeqCst), 1);
    assert_eq!(trace.financial_effects.load(Ordering::SeqCst), 1);
    drop(owner);
    drop(authority);
    drop(directory);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_host_retry_cancelled_owner_joins_current_tick() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (_, status) = fixture.prepare_pending().await?;
    fixture
        .source
        .advance_past(status.deferral.retry_not_before_unix_ms)?;
    fixture.trace.pending.store(false, Ordering::SeqCst);
    fixture.trace.gate.close()?;
    let weak = Arc::downgrade(
        fixture
            .state
            .mediation_kernel
            .as_ref()
            .ok_or("original kernel")?,
    );
    let trace = fixture.trace.clone();
    let owner = start(&fixture, Arc::new(ShutdownController::manual()))?;
    let control: Arc<MaintenanceControl> = owner.control();
    wait_until(|| trace.gate.entered()).await?;
    let Fixture {
        state,
        _directory: directory,
        authority,
        ..
    } = fixture;
    drop(state);
    let cancellation = tokio::spawn(async move {
        let _owner = owner;
        std::future::pending::<()>().await;
    });
    tokio::task::yield_now().await;
    let release_trace = trace.clone();
    let releasing = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        let held_during_call = weak.upgrade().is_some();
        let released = release_trace.gate.release().is_ok();
        (held_during_call, released, weak)
    });
    cancellation.abort();
    let cancelled = cancellation
        .await
        .err()
        .ok_or("cancelled serving owner task")?;
    assert!(cancelled.is_cancelled());
    let (held, released, weak) = releasing.join().map_err(|_| "fixture releaser panicked")?;
    assert!(held && released);
    assert!(control.health().worker_joined);
    assert!(trace.gate.returned());
    assert!(weak.upgrade().is_none());
    let captures = trace.captures.lock().map_err(|_| "capture trace")?.len();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(
        trace.captures.lock().map_err(|_| "capture trace")?.len(),
        captures
    );
    assert_eq!(trace.dispatches.load(Ordering::SeqCst), 1);
    drop(authority);
    drop(directory);
    Ok(())
}
