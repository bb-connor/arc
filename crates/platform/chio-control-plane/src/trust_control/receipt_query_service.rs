//! HTTP admission for authenticated receipt reads and full evidence exports.
//!
//! Acquire before entering the blocking pool. The closure owns the permit,
//! including when the HTTP future is dropped while its work is still running.
use super::*;
use chio_kernel::receipt_query::{
    ReceiptQueryResult, ReceiptQuerySnapshotError, ReceiptSnapshotWatermark,
};
use chio_store_sqlite::receipt_query_snapshot::{ReceiptQuerySnapshotState, ReceiptQuerySnapshots};

pub(super) async fn run_bounded<T: Send + 'static>(
    lane: Arc<tokio::sync::Semaphore>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Response> {
    let permit = lane
        .try_acquire_owned()
        .map_err(|_| snapshot_error_response(ReceiptQuerySnapshotError::Busy.into()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work()
    })
    .await
    .map_err(|error| {
        plain_http_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("receipt worker failed: {error}"),
        )
    })
}

fn snapshots(state: &TrustServiceState) -> Result<Arc<ReceiptQuerySnapshots>, Response> {
    // Retain the existing unconfigured-service error contract.
    state.receipt_store()?;
    state.receipt_query_snapshots.clone().ok_or_else(|| {
        snapshot_error_response(
            ReceiptQuerySnapshotError::Unavailable("service not started".into()).into(),
        )
    })
}

/// Keep response construction, including eager JSON serialization, inside the
/// blocking task and its permit. Cancellation does not release that permit.
pub(super) async fn run_bounded_response<T: IntoResponse + Send + 'static>(
    lane: Arc<tokio::sync::Semaphore>,
    work: impl FnOnce() -> T + Send + 'static,
) -> Response {
    match run_bounded(lane, move || work().into_response()).await {
        Ok(response) => response,
        Err(response) => response,
    }
}

/// Query and fully render a page under one blocking-worker admission permit.
pub(super) async fn query_response(
    state: &TrustServiceState,
    query: ReceiptQuery,
    render: impl FnOnce(ReceiptQueryResult) -> Response + Send + 'static,
) -> Response {
    let snapshots = match snapshots(state) {
        Ok(snapshots) => snapshots,
        Err(response) => return response,
    };
    run_bounded_response(
        Arc::clone(&state.receipt_query_lane),
        move || match snapshots.query_receipts(&query) {
            Ok(result) => render(result),
            Err(error) => snapshot_error_response(error),
        },
    )
    .await
}

/// Load and fully render a point lookup under the same admission permit.
pub(super) async fn load_response(
    state: &TrustServiceState,
    id: String,
    context: ReceiptReadContext,
    render: impl FnOnce(Option<ChioReceipt>, ReceiptSnapshotWatermark) -> Response + Send + 'static,
) -> Response {
    let snapshots = match snapshots(state) {
        Ok(snapshots) => snapshots,
        Err(response) => return response,
    };
    run_bounded_response(
        Arc::clone(&state.receipt_query_lane),
        move || match snapshots.load_receipt(&id, &context) {
            Ok((receipt, watermark)) => render(receipt, watermark),
            Err(error) => snapshot_error_response(error),
        },
    )
    .await
}

pub(super) async fn health(state: &TrustServiceState) -> Value {
    let Some(snapshots) = state.receipt_query_snapshots.clone() else {
        return json!({"configured": state.receipt_store.is_some(), "state": if state.receipt_store.is_some() { "unavailable" } else { "unconfigured" }});
    };
    // Process-owned telemetry only: public polls never borrow receipt admission
    // or a snapshot database hold. The watermark identifies the sampled version.
    let status = snapshots.health_status();
    let (phase, reason, progress) = match status.state {
        ReceiptQuerySnapshotState::WaitingForWriterSeed => ("waiting_for_writer_seed", None, None),
        ReceiptQuerySnapshotState::Building {
            authenticated_entries,
            target_entries,
        } => (
            "building",
            None,
            Some(
                json!({"authenticatedEntries": authenticated_entries, "targetEntries": target_entries}),
            ),
        ),
        ReceiptQuerySnapshotState::Ready => ("ready", None, None),
        ReceiptQuerySnapshotState::Invalid { reason } => ("invalid", Some(reason), None),
        ReceiptQuerySnapshotState::Unavailable { reason } => ("unavailable", Some(reason), None),
        ReceiptQuerySnapshotState::Stopped => ("stopped", None, None),
    };
    json!({"configured": true, "state": phase, "reason": reason, "progress": progress,
        "watermark": status.watermark, "usedBytes": status.used_bytes, "quotaBytes": status.quota_bytes,
        "toolReceipts": status.tool_receipts, "dimensions": status.dimensions, "dimensionBytes": status.dimension_bytes,
        "lastRecertificationMs": status.last_recertification_ms})
}
