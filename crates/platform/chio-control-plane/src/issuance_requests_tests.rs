use super::*;

#[test]
fn store_refusals_map_to_http_statuses() {
    for (error, status) in [
        (
            IssuanceStoreError::AlreadySubmitted("c".into()),
            StatusCode::CONFLICT,
        ),
        (
            IssuanceStoreError::Expired("c".into()),
            StatusCode::CONFLICT,
        ),
        (IssuanceStoreError::Full, StatusCode::TOO_MANY_REQUESTS),
        (
            IssuanceStoreError::NotFound("c".into()),
            StatusCode::NOT_FOUND,
        ),
        (
            IssuanceStoreError::NotPending("c".into()),
            StatusCode::CONFLICT,
        ),
        (
            IssuanceStoreError::NotClaimed("c".into()),
            StatusCode::CONFLICT,
        ),
        (
            IssuanceStoreError::InvalidTimestamp,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (IssuanceStoreError::Busy, StatusCode::SERVICE_UNAVAILABLE),
        (
            IssuanceStoreError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            IssuanceStoreError::Integrity,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
    ] {
        assert_eq!(issuance_store_status(&error), status, "{error}");
    }
}
