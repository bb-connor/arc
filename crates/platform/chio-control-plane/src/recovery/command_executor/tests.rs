//! Rejected duplicate work must not reserve another principal's capacity.
use super::*;
use std::{
    error::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Condvar,
    },
    time::Duration,
};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

#[derive(Default)]
struct RefusalGate {
    released: Mutex<bool>,
    changed: Condvar,
    timed_out: AtomicBool,
}
impl RefusalGate {
    fn pause(&self) {
        let Ok(released) = self.released.lock() else {
            self.timed_out.store(true, Ordering::SeqCst);
            return;
        };
        let Ok((released, timeout)) =
            self.changed
                .wait_timeout_while(released, Duration::from_secs(3), |released| !*released)
        else {
            self.timed_out.store(true, Ordering::SeqCst);
            return;
        };
        if !*released && timeout.timed_out() {
            self.timed_out.store(true, Ordering::SeqCst);
        }
    }
    fn release(&self) {
        if let Ok(mut released) = self.released.lock() {
            *released = true;
            self.changed.notify_all();
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_principal_work_cannot_reserve_other_principal_capacity() -> TestResult {
    // A local real pool avoids unrelated shared-executor tests changing the
    // capacity premise. Every occupied permit belongs to an accepted job.
    let executor = Arc::new(CommandExecutor::new());
    tokio::time::timeout(Duration::from_secs(2), executor.ready()).await??;
    let principal = "checked-authority:checked-subject".to_owned();
    let (started, observed_started) = mpsc::channel();
    let mut releases = Vec::new();
    let mut accepted = Vec::new();
    for _ in 0..PER_PRINCIPAL {
        let (release, pending) = oneshot::channel();
        let started = started.clone();
        accepted.push(executor.try_submit(principal.clone(), None, async move {
            started
                .send(())
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
            pending
                .await
                .map_err(|_| RecoveryRuntimeError::Unavailable)?;
            Ok(())
        })?);
        releases.push(release);
    }
    for _ in 0..PER_PRINCIPAL {
        observed_started.recv_timeout(Duration::from_secs(2))?;
    }
    assert_eq!(
        executor.capacity.available_permits(),
        WORKERS - PER_PRINCIPAL
    );
    assert_eq!(
        executor
            .principals
            .lock()
            .map_err(|_| "principal map poisoned")?
            .get(&principal)
            .copied(),
        Some(PER_PRINCIPAL),
    );

    let gate = Arc::new(RefusalGate::default());
    let (entered, observed_entered) = mpsc::channel();
    let observer_gate = gate.clone();
    let observed_principal = principal.clone();
    *executor
        .principal_refusal_observer
        .lock()
        .map_err(|_| "observer poisoned")? = Some(Arc::new(move |principal| {
        if principal == observed_principal {
            let _ = entered.send(());
            observer_gate.pause();
        }
    }));
    let mut rejected = Vec::new();
    for _ in 0..(WORKERS - PER_PRINCIPAL) {
        let executor = executor.clone();
        let principal = principal.clone();
        rejected.push(thread::spawn(move || {
            executor.try_submit(principal, None, async { Ok(()) })
        }));
    }
    for _ in 0..(WORKERS - PER_PRINCIPAL) {
        observed_entered.recv_timeout(Duration::from_secs(2))?;
    }
    // The duplicate submissions are known principal refusals. They must not
    // prevent this distinct principal's real job from being admitted.
    let other = executor.try_submit("checked-authority:other-subject".to_owned(), None, async {
        Ok(())
    });

    // Finish every real job and paused refusal before the owning assertion.
    // A failing assertion cannot leave work, locks or test observers behind.
    gate.release();
    for rejected in rejected {
        let rejected = rejected
            .join()
            .map_err(|_| "duplicate submitter panicked")?;
        assert!(matches!(rejected, Err(RecoveryRuntimeError::Unavailable)));
    }
    for release in releases {
        let _ = release.send(());
    }
    for accepted in accepted {
        tokio::time::timeout(Duration::from_secs(2), accepted).await???;
    }
    *executor
        .principal_refusal_observer
        .lock()
        .map_err(|_| "observer poisoned")? = None;
    assert!(
        !gate.timed_out.load(Ordering::SeqCst),
        "refusal pause timed out"
    );
    assert!(
        other.is_ok(),
        "rejected duplicates reserved capacity needed by another principal"
    );
    tokio::time::timeout(Duration::from_secs(2), other?).await???;
    // Reply publication precedes the worker's affine permit drop. Wait for
    // that real cleanup before asserting the final allocator state.
    tokio::time::timeout(Duration::from_secs(2), async {
        while executor.capacity.available_permits() != WORKERS {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(executor
        .principals
        .lock()
        .map_err(|_| "principal map poisoned")?
        .is_empty());
    assert_eq!(executor.capacity.available_permits(), WORKERS);
    Ok(())
}

// Exercise a 192 KiB inline future on the ordinary OS-thread stack. The
// synthetic payload does not measure the native driver size. These data
// computations exercise stack use and grant no native effect authority.
const INLINE_PHASE_BYTES: usize = 192 * 1024;

struct InlineOwnedPhase {
    bytes: [u8; INLINE_PHASE_BYTES],
    pending: oneshot::Receiver<()>,
    started: Option<mpsc::Sender<String>>,
    completions: Arc<std::sync::atomic::AtomicUsize>,
}

impl Future for InlineOwnedPhase {
    type Output = Result<u64, RecoveryRuntimeError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let phase = self.get_mut();
        if let Some(started) = phase.started.take() {
            let name = thread::current().name().unwrap_or_default().to_owned();
            if started.send(name).is_err() {
                return std::task::Poll::Ready(Err(RecoveryRuntimeError::Unavailable));
            }
        }
        match std::pin::Pin::new(&mut phase.pending).poll(context) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(Err(_)) => {
                std::task::Poll::Ready(Err(RecoveryRuntimeError::Unavailable))
            }
            std::task::Poll::Ready(Ok(())) => {
                let result = bounded_inline_read_frame(&phase.bytes);
                phase.completions.fetch_add(1, Ordering::SeqCst);
                std::task::Poll::Ready(Ok(result))
            }
        }
    }
}

#[inline(never)]
fn bounded_inline_read_frame(bytes: &[u8; INLINE_PHASE_BYTES]) -> u64 {
    let mut frame = [0_u8; 160 * 1024];
    frame[0] = bytes[0];
    let result = bounded_inline_validation_frame(bytes);
    u64::from(std::hint::black_box(&frame)[0]) + result
}

#[inline(never)]
fn bounded_inline_validation_frame(bytes: &[u8; INLINE_PHASE_BYTES]) -> u64 {
    let mut frame = [0_u8; 256 * 1024];
    frame[0] = bytes[INLINE_PHASE_BYTES - 1];
    u64::from(std::hint::black_box(&frame)[0])
}

#[tokio::test(flavor = "current_thread")]
async fn large_owned_future_completes_on_default_worker_stack() -> TestResult {
    let executor = Arc::new(CommandExecutor::new());
    tokio::time::timeout(Duration::from_secs(2), executor.ready()).await??;
    let (release, pending) = oneshot::channel();
    let (started, observed_started) = mpsc::channel();
    let completions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let future = InlineOwnedPhase {
        bytes: [7_u8; INLINE_PHASE_BYTES],
        pending,
        started: Some(started),
        completions: completions.clone(),
    };
    let actual_future_bytes = std::mem::size_of_val(&future);
    assert!(actual_future_bytes >= INLINE_PHASE_BYTES);
    let response = executor.try_submit("checked-authority:large-future".into(), None, future)?;
    let worker = observed_started.recv_timeout(Duration::from_secs(2))?;
    assert!(worker.starts_with("chio-recovery-command-"));
    assert_eq!(completions.load(Ordering::SeqCst), 0);
    release
        .send(())
        .map_err(|_| "owning worker lost its pending phase")?;
    let result = tokio::time::timeout(Duration::from_secs(2), response).await???;
    assert_eq!(result, 14);
    assert_eq!(completions.load(Ordering::SeqCst), 1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while executor.capacity.available_permits() != WORKERS {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    assert!(executor
        .principals
        .lock()
        .map_err(|_| "principal map poisoned")?
        .is_empty());
    assert_eq!(executor.capacity.available_permits(), WORKERS);
    Ok(())
}
