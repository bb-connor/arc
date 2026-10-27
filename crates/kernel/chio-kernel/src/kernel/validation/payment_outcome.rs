//! Receipt metadata preserves the actual payment capture and release outcomes.

use super::*;
use crate::payment::{PaymentAdapter, PaymentResult};

pub(super) fn retained_payment_capture_metadata(
    request: &ToolCallRequest,
    authorization: &PaymentAuthorization,
    error: &PaymentError,
) -> serde_json::Value {
    let error_code = error.code();
    warn!(
        request_id = %request.request_id,
        authorization_id = %authorization.authorization_id,
        error_code,
        reason = %redacted!(error),
        audit_fault = "post_execution_payment_capture_outcome_unknown",
        "payment capture outcome is unknown; retaining the positive authorization"
    );
    serde_json::json!({
        "financial": {
            "authorization_id": authorization.authorization_id,
            "payment_reference": authorization.authorization_id,
            "settlement_status": SettlementStatus::Failed,
            "release_outcome": "not_released",
            "payment_authorization_retained": true,
            "payment_capture_ambiguous": true,
            "payment_capture_error_code": error_code,
            "payment_capture_attempt_reference": request.request_id
        }
    })
}

pub(super) fn release_unsettled_payment_metadata(
    adapter: &dyn PaymentAdapter,
    request: &ToolCallRequest,
    authorization: &PaymentAuthorization,
    result: &PaymentResult,
) -> serde_json::Map<String, serde_json::Value> {
    let mut financial = serde_json::Map::from_iter([
        (
            "authorization_id".into(),
            serde_json::json!(authorization.authorization_id),
        ),
        (
            "payment_reference".into(),
            serde_json::json!(result.transaction_id),
        ),
        (
            "capture_status".into(),
            serde_json::json!(result.settlement_status),
        ),
        (
            "settlement_status".into(),
            serde_json::json!(result.settlement_status.to_receipt_status()),
        ),
        (
            "payment_release_attempt_reference".into(),
            serde_json::json!(request.request_id),
        ),
    ]);
    match adapter.release(&authorization.authorization_id, &request.request_id) {
        Ok(release) => {
            let released =
                release.settlement_status == crate::payment::RailSettlementStatus::Released;
            financial.insert(
                "release_outcome".into(),
                serde_json::json!(release.settlement_status),
            );
            financial.insert(
                "payment_release_reference".into(),
                serde_json::json!(release.transaction_id),
            );
            financial.insert(
                "payment_release_confirmed".into(),
                serde_json::json!(released),
            );
            financial.insert(
                "payment_authorization_retained".into(),
                serde_json::json!(!released),
            );
            if !released {
                warn!(
                    request_id = %request.request_id,
                    authorization_id = %authorization.authorization_id,
                    release_status = ?release.settlement_status,
                    audit_fault = "post_execution_payment_release_unconfirmed",
                    "payment release returned an unconfirmed terminal state"
                );
            }
        }
        Err(error) => {
            let error_code = error.code();
            financial.insert(
                "release_outcome".into(),
                serde_json::json!("outcome_unknown"),
            );
            financial.insert(
                "payment_release_error_code".into(),
                serde_json::json!(error_code),
            );
            financial.insert("payment_release_confirmed".into(), serde_json::json!(false));
            financial.insert(
                "payment_authorization_retained".into(),
                serde_json::json!(true),
            );
            warn!(
                request_id = %request.request_id,
                authorization_id = %authorization.authorization_id,
                error_code,
                reason = %redacted!(&error),
                audit_fault = "post_execution_payment_release_outcome_unknown",
                "payment release outcome is unknown; retaining the authorization"
            );
        }
    }
    financial
}
