//! Process-owned retries on the original mediation kernel and payment rail.
use super::*;
use chio_kernel::{ChioKernel, KernelError};
use std::sync::{Condvar, Mutex as StdMutex};
use std::thread::{self, JoinHandle};
use std::time::Instant;

const ADMISSION_CANDIDATES_PER_TICK: usize = 16;
const JOIN_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintenanceLifecycle {
    Running,
    Ready,
    Failed,
    Stopped,
}

#[derive(Clone, Debug)]
pub(crate) struct MaintenanceHealth {
    pub(crate) lifecycle: MaintenanceLifecycle,
    pub(crate) ticks_attempted: u64,
    pub(crate) ticks_completed: u64,
    pub(crate) recovered: u64,
    pub(crate) reaped: u64,
    pub(crate) busy_skips: u64,
    pub(crate) worker_running: bool,
    pub(crate) worker_joined: bool,
    pub(crate) shutdown_overdue: bool,
    pub(crate) worker_panicked: bool,
    pub(crate) last_error_code: Option<String>,
}

struct State {
    stop: bool,
    health: MaintenanceHealth,
    failure: Option<Arc<KernelError>>,
}

pub(crate) struct MaintenanceControl {
    state: StdMutex<State>,
    wake: Condvar,
}

impl MaintenanceControl {
    fn new() -> Self {
        Self {
            state: StdMutex::new(State {
                stop: false,
                health: MaintenanceHealth {
                    lifecycle: MaintenanceLifecycle::Running,
                    ticks_attempted: 0,
                    ticks_completed: 0,
                    recovered: 0,
                    reaped: 0,
                    busy_skips: 0,
                    worker_running: true,
                    worker_joined: false,
                    shutdown_overdue: false,
                    worker_panicked: false,
                    last_error_code: None,
                },
                failure: None,
            }),
            wake: Condvar::new(),
        }
    }

    pub(crate) fn health(&self) -> MaintenanceHealth {
        match self.state.lock() {
            Ok(state) => state.health.clone(),
            Err(poisoned) => {
                let mut health = poisoned.into_inner().health.clone();
                health.lifecycle = MaintenanceLifecycle::Failed;
                health.last_error_code = Some("maintenance-health-unavailable".into());
                health
            }
        }
    }

    pub(crate) fn failure(&self) -> Option<Arc<KernelError>> {
        match self.state.lock() {
            Ok(state) => state.failure.clone(),
            Err(poisoned) => poisoned.into_inner().failure.clone(),
        }
    }

    fn update(&self, update: impl FnOnce(&mut State)) -> Result<(), KernelError> {
        let mut state = self.state.lock().map_err(|_| {
            KernelError::Internal("mediation maintenance health lock is poisoned".into())
        })?;
        update(&mut state);
        Ok(())
    }

    fn request_stop(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.stop = true;
        self.wake.notify_all();
    }

    fn wait_for_tick(&self, interval: Duration) -> Result<bool, KernelError> {
        let state = self.state.lock().map_err(|_| {
            KernelError::Internal("mediation maintenance health lock is poisoned".into())
        })?;
        let (state, _) = self
            .wake
            .wait_timeout_while(state, interval, |state| !state.stop)
            .map_err(|_| {
                KernelError::Internal("mediation maintenance wake lock is poisoned".into())
            })?;
        Ok(!state.stop)
    }

    fn fail(&self, failure: KernelError) {
        let code = failure.report().code;
        tracing::error!(code = %code, "owned mediation maintenance failed; requesting drain");
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.stop = true;
        state.health.lifecycle = MaintenanceLifecycle::Failed;
        state.health.last_error_code = Some(code);
        state.failure = Some(Arc::new(failure));
        self.wake.notify_all();
    }

    fn panicked(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.stop = true;
        state.health.lifecycle = MaintenanceLifecycle::Failed;
        state.health.worker_panicked = true;
        self.wake.notify_all();
        tracing::error!("owned mediation maintenance panicked; requesting drain");
    }

    fn finished(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.health.worker_running = false;
        if state.health.lifecycle != MaintenanceLifecycle::Failed {
            state.health.lifecycle = MaintenanceLifecycle::Stopped;
        }
        self.wake.notify_all();
    }
}

/// The retained native handle is always joined, including cancellation Drop.
pub(crate) struct AdmissionMaintenance {
    control: Arc<MaintenanceControl>,
    join: Option<JoinHandle<()>>,
}

impl AdmissionMaintenance {
    pub(crate) fn spawn(
        kernel: Arc<Mutex<ChioKernel>>,
        hold_capable: bool,
        controller: Arc<ShutdownController>,
        interval: Duration,
    ) -> Result<Self, ProtectError> {
        let control = Arc::new(MaintenanceControl::new());
        let worker_control = control.clone();
        let runtime = tokio::runtime::Handle::current();
        let join = thread::Builder::new()
            .name("chio-protect-admission-maintenance".into())
            .spawn(move || {
                let _entered_original_runtime = runtime.enter();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_worker(&kernel, hold_capable, &worker_control, interval)
                }));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        worker_control.fail(error);
                        controller.trigger();
                    }
                    Err(_) => {
                        // Panic payloads may contain private adapter data.
                        worker_control.panicked();
                        controller.trigger();
                    }
                }
                worker_control.finished();
            })?;
        Ok(Self {
            control,
            join: Some(join),
        })
    }

    pub(crate) fn control(&self) -> Arc<MaintenanceControl> {
        self.control.clone()
    }

    pub(crate) async fn stop_and_join(&mut self, grace: Duration) {
        self.control.request_stop();
        let started = Instant::now();
        let mut overdue = false;
        while self.join.as_ref().is_some_and(|join| !join.is_finished()) {
            if !overdue && started.elapsed() >= grace {
                overdue = true;
                let _ = self.control.update(|state| {
                    state.health.shutdown_overdue = true;
                });
                tracing::error!(
                    "mediation maintenance shutdown grace elapsed; retaining authority until join"
                );
            }
            tokio::time::sleep(JOIN_POLL_INTERVAL).await;
        }
        self.join_now();
    }

    fn join_now(&mut self) {
        self.control.request_stop();
        if let Some(join) = self.join.take() {
            if join.join().is_err() {
                self.control.panicked();
            }
            let _ = self.control.update(|state| {
                state.health.worker_running = false;
                state.health.worker_joined = true;
            });
        }
    }
}

impl Drop for AdmissionMaintenance {
    fn drop(&mut self) {
        // try_lock tick entry never waits for a Tokio request holder. Custom
        // synchronous rails can still delay this mandatory ownership barrier.
        self.join_now();
    }
}

fn run_worker(
    kernel: &Mutex<ChioKernel>,
    hold_capable: bool,
    control: &MaintenanceControl,
    interval: Duration,
) -> Result<(), KernelError> {
    while control.wait_for_tick(interval)? {
        control.update(|state| {
            state.health.ticks_attempted = state.health.ticks_attempted.saturating_add(1);
        })?;
        let Ok(kernel) = kernel.try_lock() else {
            control.update(|state| {
                state.health.busy_skips = state.health.busy_skips.saturating_add(1);
            })?;
            continue;
        };
        // Exactly one physical page on this original kernel. Ok(0) can mean a
        // known parked item or concurrent progress; it does not settle money.
        let recovered =
            kernel.reconcile_recoverable_admissions_batch(ADMISSION_CANDIDATES_PER_TICK)?;
        control.update(|state| {
            state.health.recovered = state
                .health
                .recovered
                .saturating_add(u64::try_from(recovered).unwrap_or(u64::MAX));
        })?;
        let reaped = if hold_capable {
            let now = kernel.authority_clock_reading()?.unix_millis().get() / 1_000;
            let now = i64::try_from(now).map_err(|_| {
                KernelError::Clock(chio_security_types::clock::ClockError::Overflow)
            })?;
            kernel.reap_expired_reserved_budget_holds(now)?
        } else {
            0
        };
        control.update(|state| {
            state.health.reaped = state
                .health
                .reaped
                .saturating_add(u64::try_from(reaped).unwrap_or(u64::MAX));
            state.health.ticks_completed = state.health.ticks_completed.saturating_add(1);
            state.health.lifecycle = MaintenanceLifecycle::Ready;
        })?;
    }
    Ok(())
}
