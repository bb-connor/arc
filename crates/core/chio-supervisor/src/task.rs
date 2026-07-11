//! Supervised tokio task: retains the join handle, records each iteration's
//! outcome, restarts with capped backoff, and trips the health flag on a panic, a
//! failed iteration, or an exhausted restart budget.

use crate::config::{backoff_delay, SupervisedOutcome, SupervisorConfig};
use crate::health::HealthFlag;
use crate::time::now_unix_ms;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};
use tokio::task::{AbortHandle, JoinHandle};

/// Shared slot holding the abort handle for the iteration child that is currently
/// running, so the supervisor can cancel it on shutdown.
type ActiveChild = Arc<Mutex<Option<AbortHandle>>>;

/// A supervised tokio task that owns its join handle and a [`HealthFlag`]. Retaining
/// the handle is the fix for the historical pattern of spawning a long-lived loop and
/// dropping the handle, which made the task's death invisible.
pub struct SupervisedTask {
    handle: JoinHandle<()>,
    health: HealthFlag,
    /// Abort handle for the iteration child that is currently running. Each
    /// iteration runs in its own child task, so aborting only the supervisor loop
    /// drops (and thereby detaches) that child, leaving a worker running after its
    /// health handle is gone. Cancelling this on shutdown stops it too.
    active_child: ActiveChild,
}

impl SupervisedTask {
    /// Spawn a supervised task whose `iteration` is invoked in a loop. Each iteration
    /// runs in its own child task so a panic across an `.await` surfaces as a failure
    /// to this supervisor rather than silently finishing the loop. A panicked or
    /// failed iteration is recorded and restarted with capped backoff.
    pub fn spawn<F, Fut>(config: SupervisorConfig, iteration: F) -> Self
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = SupervisedOutcome> + Send + 'static,
    {
        let health = HealthFlag::new(config.tcb_critical);
        let active_child: ActiveChild = Arc::new(Mutex::new(None));
        let handle = supervise_task_tracking_child(
            config,
            health.clone(),
            Arc::clone(&active_child),
            iteration,
        );
        Self {
            handle,
            health,
            active_child,
        }
    }

    /// A cloneable handle to this task's health.
    #[must_use]
    pub fn health(&self) -> HealthFlag {
        self.health.clone()
    }

    /// Whether the supervisor loop itself has finished (terminal `Failed`, runtime
    /// shutdown, or a clean `Shutdown` outcome). A secondary backstop for surfaces
    /// that want to trip a flag when the whole supervisor exits.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }

    /// Abort the supervisor loop and the iteration child it is currently running.
    /// Used during process shutdown. Aborting only the supervisor loop would drop
    /// its join handle and detach the child, leaving a worker running unsupervised.
    pub fn abort(&self) {
        self.handle.abort();
        if let Ok(mut slot) = self.active_child.lock() {
            if let Some(child) = slot.take() {
                child.abort();
            }
        }
    }
}

/// Supervise `iteration` in a loop and return the retained [`JoinHandle`]. Each
/// iteration runs inside a child task so that a panic - which can occur across an
/// `.await` point where `catch_unwind` cannot cleanly capture it - surfaces as a
/// `JoinError` and is classified as a restart-worthy failure. Where the runtime is
/// configured to abort on panic, the process aborts loudly instead and the
/// orchestrator restarts it: the same fail-loud outcome as the synchronous worker.
pub fn supervise_task<F, Fut>(
    config: SupervisorConfig,
    health: HealthFlag,
    iteration: F,
) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = SupervisedOutcome> + Send + 'static,
{
    // The standalone primitive exposes no shutdown handle, so it tracks the active
    // child in a private slot it never reads back.
    supervise_task_tracking_child(config, health, Arc::new(Mutex::new(None)), iteration)
}

/// Supervise `iteration` in a loop, publishing each running child's abort handle
/// into `active_child` so [`SupervisedTask::abort`] can cancel the in-flight
/// iteration rather than detaching it.
fn supervise_task_tracking_child<F, Fut>(
    config: SupervisorConfig,
    health: HealthFlag,
    active_child: ActiveChild,
    mut iteration: F,
) -> JoinHandle<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = SupervisedOutcome> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            // Build the iteration future OUTSIDE the child task, but under
            // `catch_unwind`. A closure that panics while producing its future
            // (work that runs synchronously before the first `.await`) would
            // otherwise unwind THIS supervisor task, ending the loop while the
            // retained health flag still reads Healthy: a dead worker
            // masquerading as live. Catch that panic and classify it exactly like
            // a panic inside the future (a restart-worthy failure).
            let spawned = catch_unwind(AssertUnwindSafe(&mut iteration)).map(tokio::spawn);
            let outcome = match spawned {
                Ok(handle) => {
                    // Publish the child's abort handle before awaiting it, so a
                    // concurrent shutdown cancels this iteration instead of
                    // detaching it.
                    if let Ok(mut slot) = active_child.lock() {
                        *slot = Some(handle.abort_handle());
                    }
                    match handle.await {
                        Ok(outcome) => outcome,
                        Err(join_error) if join_error.is_panic() => SupervisedOutcome::Restart,
                        Err(_cancelled) => return,
                    }
                }
                Err(_panic) => SupervisedOutcome::Restart,
            };
            match outcome {
                SupervisedOutcome::Shutdown => return,
                SupervisedOutcome::Continue => {
                    // A completed iteration resets the consecutive-failure
                    // counter and stamps liveness, so isolated faults separated
                    // by healthy iterations never accumulate into a false trip.
                    // A tripped level is never lowered here.
                    health.record_ok(now_unix_ms());
                    continue;
                }
                SupervisedOutcome::Restart => {
                    let now = now_unix_ms();
                    let count = health.record_failure(
                        format!("{} iteration panicked or failed", config.name),
                        now,
                        config.trip_after,
                    );
                    if count >= config.max_restarts {
                        health.escalate_failed(now);
                        return;
                    }
                    tokio::time::sleep(backoff_delay(&config, count)).await;
                }
            }
        }
    })
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::HealthLevel;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn fast_config(name: &'static str, tcb: bool, max_restarts: u32) -> SupervisorConfig {
        SupervisorConfig {
            name,
            tcb_critical: tcb,
            trip_after: 2,
            max_restarts,
            base_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(2),
        }
    }

    #[tokio::test]
    async fn continue_iterations_keep_the_flag_healthy() {
        let ticks = Arc::new(AtomicU32::new(0));
        let worker_ticks = Arc::clone(&ticks);
        let task = SupervisedTask::spawn(fast_config("healthy", false, 5), move || {
            let worker_ticks = Arc::clone(&worker_ticks);
            async move {
                let seen = worker_ticks.fetch_add(1, Ordering::SeqCst);
                if seen >= 3 {
                    SupervisedOutcome::Shutdown
                } else {
                    SupervisedOutcome::Continue
                }
            }
        });
        let health = task.health();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !task.is_finished() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or(());
        assert_eq!(health.level(), HealthLevel::Healthy);
        assert!(ticks.load(Ordering::SeqCst) >= 3);
    }

    #[tokio::test]
    async fn panicking_iteration_is_recorded_and_escalates() {
        let task = SupervisedTask::spawn(fast_config("panic", true, 3), || async {
            panic!("iteration blew up");
        });
        let health = task.health();
        tokio::time::timeout(Duration::from_secs(3), async {
            while health.level() != HealthLevel::Failed {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or(());
        assert_eq!(health.level(), HealthLevel::Failed);
        assert!(health.is_serving_closed());
        assert!(task.is_finished());
    }

    #[tokio::test]
    async fn panic_building_the_iteration_is_recorded_and_escalates() {
        // A closure that panics BEFORE returning its future panics inside the
        // supervisor task itself, not inside a child task, so no JoinError is
        // produced. The supervisor must still record it as a failure and escalate
        // to Failed rather than leaving a dead loop that reads Healthy.
        let task = SupervisedTask::spawn(
            fast_config("build-panic", true, 3),
            || -> std::future::Ready<SupervisedOutcome> {
                panic!("closure blew up before building the future");
            },
        );
        let health = task.health();
        tokio::time::timeout(Duration::from_secs(3), async {
            while health.level() != HealthLevel::Failed {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or(());
        assert_eq!(health.level(), HealthLevel::Failed);
        assert!(health.is_serving_closed());
        assert!(task.is_finished());
    }

    #[tokio::test]
    async fn failing_iteration_trips_to_degraded() {
        let task = SupervisedTask::spawn(fast_config("fail", false, 100), || async {
            SupervisedOutcome::Restart
        });
        let health = task.health();
        tokio::time::timeout(Duration::from_secs(3), async {
            while health.level() == HealthLevel::Healthy {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or(());
        assert_eq!(health.level(), HealthLevel::Degraded);
        task.abort();
    }

    #[tokio::test]
    async fn interleaved_restart_and_continue_never_trips() {
        // The async supervisor obeys the same honesty rule as the synchronous
        // one: a failed iteration followed by a successful one must reset the
        // consecutive-failure counter, so non-consecutive faults never
        // accumulate into a false trip. Without the reset on Continue, the second
        // Restart alone would trip this worker to Degraded.
        let phase = Arc::new(AtomicU32::new(0));
        let worker_phase = Arc::clone(&phase);
        let task = SupervisedTask::spawn(fast_config("interleave", false, 1000), move || {
            let worker_phase = Arc::clone(&worker_phase);
            async move {
                match worker_phase.fetch_add(1, Ordering::SeqCst) {
                    0 | 2 | 4 => SupervisedOutcome::Restart,
                    1 | 3 => SupervisedOutcome::Continue,
                    _ => {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        SupervisedOutcome::Continue
                    }
                }
            }
        });
        let health = task.health();
        tokio::time::timeout(Duration::from_secs(5), async {
            while phase.load(Ordering::SeqCst) < 6 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or(());
        assert_eq!(health.level(), HealthLevel::Healthy);
        task.abort();
    }

    #[tokio::test]
    async fn abort_cancels_the_in_flight_child_iteration() {
        // Each iteration runs in its own child task. Aborting the supervisor must
        // cancel the running child too; if the child is merely detached it keeps
        // running unsupervised after the health handle is gone.
        let started = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(AtomicBool::new(false));
        let worker_started = Arc::clone(&started);
        let worker_completed = Arc::clone(&completed);
        let task = SupervisedTask::spawn(fast_config("abort-child", false, 5), move || {
            let worker_started = Arc::clone(&worker_started);
            let worker_completed = Arc::clone(&worker_completed);
            async move {
                worker_started.store(true, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(500)).await;
                // Only reached if the child ran to completion instead of being
                // cancelled by the abort below.
                worker_completed.store(true, Ordering::SeqCst);
                SupervisedOutcome::Continue
            }
        });

        // Abort while the child is mid-sleep.
        tokio::time::timeout(Duration::from_secs(2), async {
            while !started.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or(());
        task.abort();

        // Wait well past the child's remaining sleep: a detached child would
        // finish and set `completed`, a cancelled one never does.
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(
            started.load(Ordering::SeqCst),
            "the iteration should have started"
        );
        assert!(
            !completed.load(Ordering::SeqCst),
            "abort must cancel the in-flight child iteration, not detach it to run to completion"
        );
    }
}
