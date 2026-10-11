//! Bounded admission for blocking work started by async request handlers.
//!
//! A lane is a fixed number of permits. Work is admitted only while a permit
//! is free at the moment of the call: admission never waits, so a saturated
//! lane refuses at once instead of queueing callers or blocking-pool threads.

use std::sync::Arc;

use axum::http::StatusCode;
use tokio::sync::Semaphore;

/// A named, fixed-capacity admission lane for blocking work.
///
/// Clones share one set of permits. A lane bounds only the work submitted to
/// it, so a route family that owns a lane can exhaust only its own capacity.
#[derive(Clone, Debug)]
pub(crate) struct BlockingLane {
    name: &'static str,
    permits: Arc<Semaphore>,
}

impl BlockingLane {
    pub(crate) fn new(name: &'static str, capacity: usize) -> Self {
        Self {
            name,
            permits: Arc::new(Semaphore::new(capacity)),
        }
    }

    /// Permits not held by admitted work at this moment.
    #[cfg(test)]
    pub(crate) fn available_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Returns once a permit is free, without keeping it.
    #[cfg(test)]
    pub(crate) async fn wait_for_free_permit(&self) {
        drop(self.permits.acquire().await);
    }
}

/// Why work submitted to a lane produced no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BlockingLaneError {
    /// Every permit was held, so the work was refused before it started.
    #[error("blocking lane `{0}` is at capacity")]
    Saturated(&'static str),
    /// The work panicked or its runtime shut down before it returned. No
    /// panic payload is carried, so no panic text can reach a caller.
    #[error("blocking work in lane `{0}` did not complete")]
    Join(&'static str),
}

impl BlockingLaneError {
    /// 503 for a saturated lane, which a caller may retry, and 500 for work
    /// that did not complete.
    pub(crate) fn status(self) -> StatusCode {
        match self {
            Self::Saturated(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Join(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Runs `work` on Tokio's blocking pool under one permit from `lane`.
///
/// Admission never waits: without a free permit the call returns
/// [`BlockingLaneError::Saturated`] before any work starts. The permit moves
/// into the blocking closure and is released only after `work` returns, so
/// `work` must return a fully materialized value (an owned, buffered body,
/// never a reader that does more work later). Dropping the returned future
/// does not stop the work, and its permit stays held until the work ends.
pub(crate) async fn run_bounded_blocking<T, F>(
    lane: &BlockingLane,
    work: F,
) -> Result<T, BlockingLaneError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let name = lane.name;
    let permit = Arc::clone(&lane.permits)
        .try_acquire_owned()
        .map_err(|_| BlockingLaneError::Saturated(name))?;
    tokio::task::spawn_blocking(move || {
        let value = work();
        drop(permit);
        value
    })
    .await
    .map_err(|_| BlockingLaneError::Join(name))
}

#[cfg(test)]
#[path = "blocking_tests.rs"]
mod tests;
