//! Supervised tokio task: retains the join handle, records each iteration's
//! outcome, restarts with capped backoff, and trips the health flag on a panic, a
//! failed iteration, or an exhausted restart budget.

use crate::config::{backoff_delay, SupervisedOutcome, SupervisorConfig};
use crate::health::HealthFlag;
use crate::time::now_unix_ms;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use tokio::task::JoinHandle;

/// A supervised tokio task that owns its join handle and a [`HealthFlag`]. Retaining
/// the handle is the fix for the historical pattern of spawning a long-lived loop and
/// dropping the handle, which made the task's death invisible.
pub struct SupervisedTask {
    handle: JoinHandle<()>,
    health: HealthFlag,
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
        let handle = supervise_task(config, health.clone(), iteration);
        Self { handle, health }
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

    /// Abort the supervisor loop. Used during process shutdown.
    pub fn abort(&self) {
        self.handle.abort();
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
                Ok(handle) => match handle.await {
                    Ok(outcome) => outcome,
                    Err(join_error) if join_error.is_panic() => SupervisedOutcome::Restart,
                    Err(_cancelled) => return,
                },
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
    use std::sync::atomic::{AtomicU32, Ordering};
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
}
