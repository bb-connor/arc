//! Revocation routes keep persisting at a registry filled to its admission
//! boundary, and refuse an over-long operator reason as a client error.

use super::*;
use crate::certify::revocation_capacity as certification_fixture;
use crate::passport_verifier::revocation_capacity_tests as passport_fixture;
use crate::signed_input::REVOCATION_REASON_LIMIT_BYTES as REASON_LIMIT;
use axum::body::{to_bytes, Body};
use axum::http::Request;
use serde_json::{json, Value};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "service-secret";

async fn call(
    state: &TrustServiceState,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header("content-type", "application/json");
    let request = match body {
        Some(body) => request.body(Body::from(serde_json::to_vec(&body)?))?,
        None => request.body(Body::empty())?,
    };
    let response = super::super::build_router(state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

fn passport_state(path: &Path) -> TrustServiceState {
    let mut state = metrics_state(TOKEN);
    state.config.passport_statuses_file = Some(path.to_path_buf());
    state
}

fn certification_state(path: &Path) -> TrustServiceState {
    let mut state = metrics_state(TOKEN);
    state.config.certification_registry_file = Some(path.to_path_buf());
    state
}

async fn stored_status(
    state: &TrustServiceState,
    uri: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, record) = call(state, "GET", uri, None).await?;
    assert_eq!(status, StatusCode::OK, "{record}");
    Ok(record["status"].clone())
}

#[tokio::test]
async fn passport_status_revocations_persist_at_a_full_registry() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let registry = passport_fixture::full_registry(&path)?;
    let state = passport_state(&path);
    let reason = passport_fixture::largest_reason();
    for passport_id in registry.passports.keys().take(3) {
        let (status, body) = call(
            &state,
            "POST",
            &format!("/v1/passport/statuses/{passport_id}/revoke"),
            Some(json!({ "reason": reason, "revokedAt": u64::MAX })),
        )
        .await?;
        let stored = stored_status(&state, &format!("/v1/passport/statuses/{passport_id}")).await?;
        assert_eq!(
            (status, stored),
            (StatusCode::OK, json!("revoked")),
            "revocation of {passport_id}: {body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn passport_status_revocation_reason_past_the_bound_is_a_client_error() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("passport-statuses.json");
    let registry = passport_fixture::full_registry(&path)?;
    let state = passport_state(&path);
    let before = std::fs::read(&path)?;
    let passport_id = registry.passports.keys().next().ok_or("one record")?;
    let (status, body) = call(
        &state,
        "POST",
        &format!("/v1/passport/statuses/{passport_id}/revoke"),
        Some(json!({ "reason": "r".repeat(REASON_LIMIT + 1), "revokedAt": u64::MAX })),
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains(&format!(
                "revocation reason must be at most {REASON_LIMIT} bytes once JSON-escaped"
            ))),
        "{body}"
    );
    let stored = stored_status(&state, &format!("/v1/passport/statuses/{passport_id}")).await?;
    assert_eq!(stored, json!("active"));
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[tokio::test]
async fn certification_revocations_persist_at_a_full_registry() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("certifications.json");
    let registry = certification_fixture::full_registry(&path)?;
    let state = certification_state(&path);
    let reason = certification_fixture::largest_reason();
    for artifact_id in registry.artifacts.keys().take(3) {
        let (status, body) = call(
            &state,
            "POST",
            &format!("/v1/certifications/{artifact_id}/revoke"),
            Some(json!({ "reason": reason, "revokedAt": u64::MAX })),
        )
        .await?;
        let stored = stored_status(&state, &format!("/v1/certifications/{artifact_id}")).await?;
        assert_eq!(
            (status, stored),
            (StatusCode::OK, json!("revoked")),
            "revocation of {artifact_id}: {body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn certification_reason_or_dispute_note_past_the_bound_is_a_client_error() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("certifications.json");
    let (_, artifact_id) = certification_fixture::one_published(&path)?;
    let state = certification_state(&path);
    let before = std::fs::read(&path)?;
    let over = "r".repeat(REASON_LIMIT + 1);
    let cases = [
        (
            format!("/v1/certifications/{artifact_id}/revoke"),
            json!({ "reason": over, "revokedAt": certification_fixture::PUBLISHED_AT + 1 }),
            "revocation reason must be at most",
        ),
        (
            format!("/v1/certifications/{artifact_id}/dispute"),
            json!({
                "state": "resolved-revoked",
                "note": over,
                "updatedAt": certification_fixture::PUBLISHED_AT + 1,
            }),
            "dispute note must be at most",
        ),
    ];
    for (uri, request, message) in cases {
        let (status, body) = call(&state, "POST", &uri, Some(request)).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains(message)),
            "{uri}: {body}"
        );
        let stored = stored_status(&state, &format!("/v1/certifications/{artifact_id}")).await?;
        assert_eq!(stored, json!("active"));
        assert_eq!(std::fs::read(&path)?, before);
    }
    Ok(())
}

#[tokio::test]
async fn a_revocation_while_another_writer_holds_the_registry_is_busy_and_changes_nothing(
) -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let passports = directory.path().join("passport-statuses.json");
    let passport = passport_fixture::passport(91)?;
    let record = PassportStatusRegistry::update(&passports, |registry| {
        registry.publish(
            &passport,
            passport_fixture::PUBLISHED_AT,
            Default::default(),
        )
    })?;
    let certifications = directory.path().join("certifications.json");
    let (_, artifact_id) = certification_fixture::one_published(&certifications)?;
    let cases = [
        (
            passport_state(&passports),
            passports.clone(),
            format!("/v1/passport/statuses/{}", record.passport_id),
        ),
        (
            certification_state(&certifications),
            certifications.clone(),
            format!("/v1/certifications/{artifact_id}"),
        ),
    ];
    for (state, path, resource) in cases {
        let revoke = format!("{resource}/revoke");
        let request = json!({ "reason": "compromised", "revokedAt": u64::MAX });
        let held = crate::signed_input::lock_registry(&path).map_err(CliError::from)?;
        let before = std::fs::read(&path)?;
        let (status, body) = call(&state, "POST", &revoke, Some(request.clone())).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(
            body["error"]
                .as_str()
                .is_some_and(|error| error.contains("being written by another writer")),
            "{body}"
        );
        assert_eq!(std::fs::read(&path)?, before);
        assert_eq!(stored_status(&state, &resource).await?, json!("active"));

        drop(held);
        let (status, body) = call(&state, "POST", &revoke, Some(request)).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(stored_status(&state, &resource).await?, json!("revoked"));
    }
    Ok(())
}
