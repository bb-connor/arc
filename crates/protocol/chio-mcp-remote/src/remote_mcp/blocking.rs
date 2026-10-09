//! Synchronous persistence (SQLite, fsync) and actor joins run on the blocking
//! pool with owned inputs, never on async worker threads.

use super::*;

/// A blocking job that did not complete. Callers treat it as a failed operation.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum BlockingError {
    Panicked,
    Cancelled,
}

impl std::fmt::Display for BlockingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Panicked => formatter.write_str("blocking persistence task panicked"),
            Self::Cancelled => formatter.write_str("blocking persistence task was cancelled"),
        }
    }
}

pub(super) async fn run_blocking<T, F>(job: F) -> Result<T, BlockingError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(job).await.map_err(|error| {
        if error.is_panic() {
            BlockingError::Panicked
        } else {
            BlockingError::Cancelled
        }
    })
}

/// `run_blocking` for jobs that already return `CliError`.
pub(super) async fn blocking_cli<T, F>(job: F) -> Result<T, CliError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, CliError> + Send + 'static,
{
    run_blocking(job)
        .await
        .map_err(|error| CliError::cli_other_error(error.to_string()))?
}

/// `run_blocking` for jobs that return an HTTP refusal. A lost job is a 503.
pub(super) async fn blocking_response<T, F>(job: F) -> Result<T, Response>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Response> + Send + 'static,
{
    match run_blocking(job).await {
        Ok(result) => result,
        Err(error) => {
            error!(error = %error, "blocking persistence task did not complete");
            Err(plain_http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "persistence task did not complete",
            ))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_job_does_not_stall_the_only_async_worker() {
        let ticks = Arc::new(AtomicU64::new(0));
        let ticker = {
            let ticks = ticks.clone();
            tokio::spawn(async move {
                loop {
                    ticks.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                }
            })
        };
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let job = tokio::spawn(run_blocking(move || {
            let _ = started_tx.send(());
            release_rx.recv().is_ok()
        }));
        while started_rx.try_recv().is_err() {
            tokio::task::yield_now().await;
        }
        // The job is parked off-thread. If it ran inline, this task could never
        // observe the ticker advance, and the release below would never run.
        let before = ticks.load(Ordering::SeqCst);
        while ticks.load(Ordering::SeqCst) <= before {
            tokio::task::yield_now().await;
        }
        release_tx.send(()).unwrap();
        assert_eq!(job.await.unwrap(), Ok(true));
        ticker.abort();
    }

    #[tokio::test]
    async fn panicking_job_surfaces_as_exact_error() {
        let result = run_blocking(|| -> u8 { panic!("job failed") }).await;
        assert_eq!(result, Err(BlockingError::Panicked));
        let cli = blocking_cli(|| -> Result<(), CliError> { panic!("job failed") }).await;
        assert!(cli
            .err()
            .is_some_and(|error| error.to_string().contains("panicked")));
    }
}
