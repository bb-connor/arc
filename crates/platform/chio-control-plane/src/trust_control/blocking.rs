//! Synchronous store, registry and file work of trust-control handlers runs on
//! Tokio's blocking pool.

use super::*;

/// Run the synchronous remainder of a handler on the blocking pool and return
/// its response unchanged. The closure owns its state handle and inputs, so no
/// async worker waits on SQLite, registry files or fsync. A worker that does
/// not complete is an internal error, and nothing it did is reported.
pub(crate) async fn blocking_response<F>(operation: F) -> Response
where
    F: FnOnce() -> Response + Send + 'static,
{
    match tokio::task::spawn_blocking(operation).await {
        Ok(response) => response,
        Err(_) => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "trust-control worker did not complete",
        ),
    }
}
