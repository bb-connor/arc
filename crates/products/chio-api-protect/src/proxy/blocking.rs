//! Synchronous kernel and store work runs on Tokio's blocking pool.

/// The blocking worker did not return a value: it panicked or the runtime is
/// shutting down. Callers deny the request; the panic payload is never read
/// because it may carry private adapter data.
#[derive(Debug, thiserror::Error)]
#[error("blocking worker did not complete")]
pub(crate) struct WorkerFailed;

/// Run `operation` on the blocking pool and wait for it without occupying an
/// async worker thread. The closure owns every handle it touches, so no async
/// lock guard or borrowed request state crosses into SQLite, payment-rail or
/// kernel bridge work.
pub(crate) async fn blocking<T, F>(operation: F) -> Result<T, WorkerFailed>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            tracing::warn!(
                panicked = error.is_panic(),
                "blocking worker did not complete"
            );
            WorkerFailed
        })
}
