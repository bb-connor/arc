//! HTTP status of federated-issuance store refusals.

use axum::http::StatusCode;
use chio_federation::issuance_requests::IssuanceStoreError;

/// Status a handler reports for `error`. A store that is busy, unavailable
/// or failed an integrity check is never reported as throttling.
#[must_use]
pub fn issuance_store_status(error: &IssuanceStoreError) -> StatusCode {
    match error {
        IssuanceStoreError::AlreadySubmitted(_)
        | IssuanceStoreError::Expired(_)
        | IssuanceStoreError::NotPending(_)
        | IssuanceStoreError::NotClaimed(_) => StatusCode::CONFLICT,
        IssuanceStoreError::Full => StatusCode::TOO_MANY_REQUESTS,
        IssuanceStoreError::NotFound(_) => StatusCode::NOT_FOUND,
        IssuanceStoreError::InvalidPageLimit(_) => StatusCode::BAD_REQUEST,
        IssuanceStoreError::InvalidTimestamp => StatusCode::INTERNAL_SERVER_ERROR,
        IssuanceStoreError::Busy
        | IssuanceStoreError::Unavailable
        | IssuanceStoreError::Integrity => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
#[path = "issuance_requests_tests.rs"]
mod tests;
