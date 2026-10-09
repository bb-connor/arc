//! HTTP admission for passport status and certification registry writes.
//!
//! A registry write is one locked file transaction (load, change, capacity
//! check, atomic replace) run on the blocking pool. Admission never waits:
//! without a free permit the request is refused at once with 503. The permit
//! moves into the blocking closure together with the transaction, which owns
//! the registry lock, so a request dropped mid-write releases neither before
//! the transaction ends, and nothing awaits while the lock is held.

use std::sync::LazyLock;

use serde::Serialize;

use super::*;
use crate::passport_verifier::RegistryUpdateError;

/// Registry write transactions running at once across the process.
const REGISTRY_WRITE_PERMITS: usize = 2;

static REGISTRY_WRITE_LANE: LazyLock<Arc<tokio::sync::Semaphore>> =
    LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(REGISTRY_WRITE_PERMITS)));

/// The registry file configured for `subject`, or the 409 answered when the
/// service was started without `flag`.
pub(super) fn configured_registry_file(
    path: Option<&Path>,
    flag: &str,
    subject: &str,
) -> Result<PathBuf, Response> {
    path.map(Path::to_path_buf).ok_or_else(|| {
        plain_http_error(
            StatusCode::CONFLICT,
            &format!("{subject} administration requires {flag} on the trust-control service"),
        )
    })
}

/// Runs `update` behind the process registry write lane and answers with its
/// JSON outcome or its error.
pub(super) async fn run_registry_update<T: Serialize + Send + 'static>(
    update: impl FnOnce() -> Result<T, RegistryUpdateError> + Send + 'static,
) -> Response {
    run_registry_update_in(&REGISTRY_WRITE_LANE, update).await
}

/// Runs `update` on the blocking pool under a permit from `lane`, refusing at
/// once with 503 when `lane` has none free.
pub(super) async fn run_registry_update_in<T: Serialize + Send + 'static>(
    lane: &Arc<tokio::sync::Semaphore>,
    update: impl FnOnce() -> Result<T, RegistryUpdateError> + Send + 'static,
) -> Response {
    let Ok(permit) = Arc::clone(lane).try_acquire_owned() else {
        return plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "registry writes are at capacity; nothing was changed, retry",
        );
    };
    let outcome = tokio::task::spawn_blocking(move || {
        let outcome = update();
        drop(permit);
        outcome
    })
    .await;
    match outcome {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => registry_update_error_response(error),
        Err(_) => plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "registry write did not complete",
        ),
    }
}

fn registry_update_error_response(error: RegistryUpdateError) -> Response {
    let status = match &error {
        RegistryUpdateError::Busy => StatusCode::SERVICE_UNAVAILABLE,
        RegistryUpdateError::Load(_) => StatusCode::CONFLICT,
        RegistryUpdateError::Refused(error) if error.to_string().contains("was not found") => {
            StatusCode::NOT_FOUND
        }
        RegistryUpdateError::Refused(_) => StatusCode::BAD_REQUEST,
        RegistryUpdateError::Unsupported | RegistryUpdateError::Persist(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    plain_http_error(status, &CliError::from(error).to_string())
}

#[cfg(test)]
#[path = "registry_write_lane/tests.rs"]
mod tests;
