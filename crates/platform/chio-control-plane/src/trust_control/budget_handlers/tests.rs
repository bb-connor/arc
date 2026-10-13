use super::{budget_internal_error, validate_budget_request_identity};
use axum::body::to_bytes;
use axum::http::StatusCode;
use chio_kernel::budget_store::BudgetStoreError;
use chio_test_support::prelude::*;

#[test]
fn budget_identity_rejects_empty_values() {
    assert!(validate_budget_request_identity("hold", "hold:event").is_ok());
    for (hold_id, event_id) in [("", "event"), ("hold", ""), ("", "")] {
        let response = match validate_budget_request_identity(hold_id, event_id) {
            Ok(()) => panic!("invalid budget identity was accepted"),
            Err(response) => response,
        };
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn fenced_budget_error_is_service_unavailable_without_internal_details() {
    let response = budget_internal_error(
        &BudgetStoreError::Fenced {
            expected_epoch: 41,
            actual_epoch: Some(42),
        },
        "budget serving owner changed",
    );
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_expect("read public fenced response");
    let body = String::from_utf8_lossy(&body);
    assert!(body.contains("budget serving owner changed"));
    assert!(!body.contains("41"));
    assert!(!body.contains("42"));
}
