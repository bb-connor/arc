use super::*;
use chio_test_support::prelude::*;
use futures_util::FutureExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// Bounds every wait in this module.
const HANG_GUARD: Duration = Duration::from_secs(30);
/// How long held work waits for its release when nothing sends it. It is
/// shorter than `HANG_GUARD`, so a failure surfaces as an assertion.
const PAUSE_BOUND: Duration = Duration::from_secs(10);
const LANE: &str = "test_lane";

/// Work that reports when it starts, then waits for the test to release it
/// and reports again when it ends.
struct HeldWork {
    release: mpsc::Sender<()>,
    started: tokio::sync::mpsc::UnboundedReceiver<()>,
    ended: tokio::sync::mpsc::UnboundedReceiver<()>,
}

impl HeldWork {
    fn new() -> (Self, impl FnOnce() -> u32 + Send + 'static) {
        let (release, released) = mpsc::channel::<()>();
        let (started_tx, started) = tokio::sync::mpsc::unbounded_channel();
        let (ended_tx, ended) = tokio::sync::mpsc::unbounded_channel();
        let work = move || {
            let _ = started_tx.send(());
            let _ = released.recv_timeout(PAUSE_BOUND);
            let _ = ended_tx.send(());
            7
        };
        (
            Self {
                release,
                started,
                ended,
            },
            work,
        )
    }

    async fn wait_started(&mut self) {
        tokio::time::timeout(HANG_GUARD, self.started.recv())
            .await
            .test_unwrap()
            .test_unwrap();
    }
}

/// Submits work on `lane` and polls it exactly once. Work that would wait for
/// admission is not ready and fails the `test_unwrap`.
fn submit_polled_once(lane: &BlockingLane, ran: &Arc<AtomicBool>) -> Result<(), BlockingLaneError> {
    let ran = Arc::clone(ran);
    run_bounded_blocking(lane, move || ran.store(true, Ordering::SeqCst))
        .now_or_never()
        .test_unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn admitted_work_runs_off_the_async_worker_and_returns_its_permit() {
    let lane = BlockingLane::new(LANE, 2);
    let worker = std::thread::current().id();
    let ran_on = run_bounded_blocking(&lane, || std::thread::current().id())
        .await
        .test_unwrap();
    assert_ne!(ran_on, worker);
    assert_eq!(lane.available_permits(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn saturated_lane_refuses_at_once_without_running_the_work() {
    let lane = BlockingLane::new(LANE, 1);
    let (mut held, work) = HeldWork::new();
    let admitted = tokio::spawn({
        let lane = lane.clone();
        async move { run_bounded_blocking(&lane, work).await }
    });
    held.wait_started().await;
    assert_eq!(lane.available_permits(), 0);

    let ran = Arc::new(AtomicBool::new(false));
    let refused = submit_polled_once(&lane, &ran);
    assert_eq!(refused, Err(BlockingLaneError::Saturated(LANE)));
    assert!(!ran.load(Ordering::SeqCst));
    let refusal = refused.test_unwrap_err();
    assert_eq!(refusal.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        refusal.to_string(),
        "blocking lane `test_lane` is at capacity"
    );

    held.release.send(()).test_unwrap();
    let value = tokio::time::timeout(HANG_GUARD, admitted)
        .await
        .test_unwrap()
        .test_unwrap();
    assert_eq!(value, Ok(7));
    assert_eq!(lane.available_permits(), 1);
    assert_eq!(run_bounded_blocking(&lane, || 8).await, Ok(8));
}

#[tokio::test(flavor = "current_thread")]
async fn cancelled_caller_keeps_the_permit_until_the_work_returns() {
    let lane = BlockingLane::new(LANE, 1);
    let (mut held, work) = HeldWork::new();
    let admitted = tokio::spawn({
        let lane = lane.clone();
        async move { run_bounded_blocking(&lane, work).await }
    });
    held.wait_started().await;

    admitted.abort();
    let cancelled = tokio::time::timeout(HANG_GUARD, admitted)
        .await
        .test_unwrap()
        .test_unwrap_err();
    assert!(cancelled.is_cancelled());
    assert_eq!(lane.available_permits(), 0);
    let ran = Arc::new(AtomicBool::new(false));
    assert_eq!(
        submit_polled_once(&lane, &ran),
        Err(BlockingLaneError::Saturated(LANE))
    );
    assert!(!ran.load(Ordering::SeqCst));

    held.release.send(()).test_unwrap();
    tokio::time::timeout(HANG_GUARD, lane.wait_for_free_permit())
        .await
        .test_unwrap();
    // The dropped caller's work still ran to its end.
    tokio::time::timeout(HANG_GUARD, held.ended.recv())
        .await
        .test_unwrap()
        .test_unwrap();
    assert_eq!(lane.available_permits(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn panicked_work_answers_a_fixed_message_without_panic_text_and_returns_its_permit() {
    const PANIC_TEXT: &str = "secret blocking panic payload 7f3a";
    let lane = BlockingLane::new(LANE, 1);
    let failed = run_bounded_blocking(&lane, || -> u32 { panic!("{PANIC_TEXT}") })
        .await
        .test_unwrap_err();
    assert_eq!(failed, BlockingLaneError::Join(LANE));
    assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        failed.to_string(),
        "blocking work in lane `test_lane` did not complete"
    );
    assert!(!format!("{failed:?}").contains(PANIC_TEXT));
    assert_eq!(lane.available_permits(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn lane_without_capacity_refuses_every_call() {
    let lane = BlockingLane::new(LANE, 0);
    let ran = Arc::new(AtomicBool::new(false));
    assert_eq!(
        submit_polled_once(&lane, &ran),
        Err(BlockingLaneError::Saturated(LANE))
    );
    assert!(!ran.load(Ordering::SeqCst));
}
