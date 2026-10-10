//! Node-local operator recovery of the authenticated receipt query snapshot.
//!
//! `POST /v1/receipts/query/snapshot/recovery` with the service token may
//! raise this node's snapshot quota and requests an immediate resource retry.
//! The body is `{}` (retry only) or `{"quotaBytes": <u64>}`; the route's JSON
//! contract bounds it to 256 bytes and authenticates before reading it. The
//! request is never forwarded to a leader: each node owns its projection.
//!
//! Quotas never grow on their own and a decrease is refused. With no quota
//! increase a retry ends only a resource backoff; an explicit increase can wake
//! either backoff. A serving projection is not rebuilt. Every rebuild
//! authenticates what it publishes. The response acknowledges what was
//! scheduled, not that a rebuild succeeded.
//!
//! A raised quota is runtime-only: it is lost on restart, which applies the
//! configured `--receipt-query-snapshot-quota-bytes` again. Change that setting
//! to keep the larger quota.
use super::report_validation::validate_service_auth;
use super::*;
use chio_store_sqlite::receipt_query_snapshot::{
    ReceiptQuerySnapshotRecovery, ReceiptQuerySnapshotRecoveryError,
};

pub(crate) const RECEIPT_QUERY_SNAPSHOT_RECOVERY_PATH: &str =
    "/v1/receipts/query/snapshot/recovery";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ReceiptQuerySnapshotRecoveryRequest {
    /// Runtime quota to raise to; absent, the request only retries.
    #[serde(default)]
    quota_bytes: Option<u64>,
}

/// The work is a few atomic updates under short in-process locks with no await
/// after the body is decoded, so a dropped request either changed nothing or
/// completed. Nothing is queued.
pub(crate) async fn handle_receipt_query_snapshot_recovery(
    State(state): State<TrustServiceState>,
    headers: HeaderMap,
    Json(request): Json<ReceiptQuerySnapshotRecoveryRequest>,
) -> Response {
    if let Err(response) = validate_service_auth(&headers, &state.config.service_token) {
        return response;
    }
    let Some(snapshots) = state.receipt_query_snapshots.as_ref() else {
        return plain_http_error(
            StatusCode::CONFLICT,
            "receipt query snapshots are not running on this node",
        );
    };
    let outcome = match snapshots.request_recovery(request.quota_bytes) {
        Ok(outcome) => outcome,
        Err(error) => {
            let status = match error {
                ReceiptQuerySnapshotRecoveryError::QuotaOutOfBounds { .. } => {
                    StatusCode::BAD_REQUEST
                }
                ReceiptQuerySnapshotRecoveryError::QuotaBelowCurrent { .. } => StatusCode::CONFLICT,
                ReceiptQuerySnapshotRecoveryError::Stopped
                | ReceiptQuerySnapshotRecoveryError::Poisoned => StatusCode::SERVICE_UNAVAILABLE,
            };
            return plain_http_error(status, &error.to_string());
        }
    };
    let quota_bytes = snapshots.recovery_status().requested_quota_bytes;
    info!(
        requested_quota_bytes = ?request.quota_bytes,
        quota_bytes,
        ?outcome,
        "receipt query snapshot operator recovery"
    );
    match outcome {
        ReceiptQuerySnapshotRecovery::Scheduled { epoch } => (
            StatusCode::ACCEPTED,
            Json(json!({
                "recovery": "scheduled",
                "retryEpoch": epoch,
                "quotaBytes": quota_bytes,
                "quotaPersisted": false,
            })),
        )
            .into_response(),
        ReceiptQuerySnapshotRecovery::Serving => (
            StatusCode::OK,
            Json(json!({
                "recovery": "serving",
                "quotaBytes": quota_bytes,
                "quotaPersisted": false,
            })),
        )
            .into_response(),
    }
}
