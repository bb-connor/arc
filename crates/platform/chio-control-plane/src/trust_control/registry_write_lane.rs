//! HTTP admission for bounded registry writes.
//!
//! A registry write is one locked file transaction (load, change, capacity
//! check, atomic replace) run on the blocking pool. Admission never waits:
//! without a free permit the request is refused at once with 503. The permit
//! moves into the blocking closure together with the transaction, which owns
//! the registry lock, so a request dropped mid-write releases neither before
//! the transaction ends, and nothing awaits while the lock is held.

use serde::Serialize;

use super::*;
use crate::passport_verifier::{RegistryTransactionError, RegistryUpdateError};

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

/// An operation refusal retains its original HTTP status without inferring
/// the status from an error message.
pub(super) enum RegistryOperationError {
    Configuration(String),
    InvalidEntitlement(String),
    BadRequest(String),
    Authority(Box<Response>),
}

impl RegistryOperationError {
    pub(super) fn configuration(error: impl std::fmt::Display) -> Self {
        Self::Configuration(error.to_string())
    }

    pub(super) fn invalid_entitlement(error: impl std::fmt::Display) -> Self {
        Self::InvalidEntitlement(error.to_string())
    }

    pub(super) fn bad_request(error: impl std::fmt::Display) -> Self {
        Self::BadRequest(error.to_string())
    }

    pub(super) fn authority(response: Response) -> Self {
        Self::Authority(Box::new(response))
    }

    pub(super) fn into_response(self) -> Response {
        let (status, error) = match self {
            Self::Configuration(error) => (StatusCode::CONFLICT, error),
            Self::InvalidEntitlement(error) => (StatusCode::UNAUTHORIZED, error),
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, error),
            Self::Authority(response) => return *response,
        };
        plain_http_error(status, &error)
    }
}

/// Runs a transaction whose operation carries an explicit HTTP refusal.
pub(super) async fn run_registry_transaction<T: Serialize + Send + 'static>(
    lane: &BlockingLane,
    update: impl FnOnce() -> Result<T, RegistryTransactionError<RegistryOperationError>>
        + Send
        + 'static,
) -> Response {
    run_registry_response_in(lane, move || match update() {
        Ok(value) => Json(value).into_response(),
        Err(RegistryTransactionError::Registry(error)) => registry_update_error_response(error),
        Err(RegistryTransactionError::Refused(error)) => error.into_response(),
    })
    .await
}

/// Runs `update` behind the supplied service lane and answers with its
/// JSON outcome or its error.
pub(super) async fn run_registry_update<T: Serialize + Send + 'static>(
    lane: &BlockingLane,
    update: impl FnOnce() -> Result<T, RegistryUpdateError> + Send + 'static,
) -> Response {
    run_registry_update_in(lane, update).await
}

/// Runs `update` on the blocking pool under a permit from `lane`, refusing at
/// once with 503 when `lane` has none free.
pub(super) async fn run_registry_update_in<T: Serialize + Send + 'static>(
    lane: &BlockingLane,
    update: impl FnOnce() -> Result<T, RegistryUpdateError> + Send + 'static,
) -> Response {
    run_registry_response_in(lane, move || match update() {
        Ok(value) => Json(value).into_response(),
        Err(error) => registry_update_error_response(error),
    })
    .await
}

/// One permit owner serves both transaction adapters. It stays in the blocking
/// closure until the full transaction and response construction have ended.
async fn run_registry_response_in(
    lane: &BlockingLane,
    update: impl FnOnce() -> Response + Send + 'static,
) -> Response {
    match run_bounded_blocking(lane, update).await {
        Ok(response) => response,
        Err(BlockingLaneError::Saturated(_)) => plain_http_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "registry writes are at capacity; nothing was changed, retry",
        ),
        Err(BlockingLaneError::Join(_)) => plain_http_error(
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
