//! Authenticated query metadata is present at every HTTP read boundary.
use super::*;
use axum::body::Body;
use axum::http::header::AUTHORIZATION;
use axum::http::Request;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn fixture() -> Result<(tempfile::TempDir, TrustServiceState), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let store = Arc::new(SqliteReceiptStore::open(
        directory.path().join("receipts.db"),
    )?);
    let mut state = metrics_state("snapshot-secret");
    state.config.receipt_db_path = Some(directory.path().join("receipts.db"));
    use chio_store_sqlite::receipt_query_snapshot::{
        ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
    };
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    tokio::time::timeout(Duration::from_secs(10), async {
        while snapshots.status().state != ReceiptQuerySnapshotState::Ready {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    state.receipt_query_snapshots = Some(snapshots);
    state.receipt_store = Some(store);
    Ok((directory, state))
}

async fn response_body(
    state: TrustServiceState,
    uri: &str,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let request = Request::builder()
        .uri(uri)
        .header(AUTHORIZATION, "Bearer snapshot-secret")
        .body(Body::empty())?;
    let response = super::super::build_router(state).oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "{uri} returned {status}: {error}; body={}",
            String::from_utf8_lossy(&bytes)
        )
    })?;
    Ok((status, body))
}

#[tokio::test]
async fn every_receipt_read_route_reports_an_authenticated_watermark() -> TestResult {
    let (_directory, state) = fixture().await?;
    for uri in [
        "/v1/receipts/query",
        TOOL_RECEIPTS_PATH,
        "/v1/receipts/tools?receiptId=absent",
        "/v1/agents/absent/receipts",
    ] {
        let (status, body) = response_body(state.clone(), uri).await?;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert!(
            body["snapshot"]["id"]
                .as_str()
                .is_some_and(|id| !id.is_empty()),
            "{uri} lacks authenticated snapshot metadata: {body}"
        );
        assert_eq!(body["snapshot"]["throughEntrySeq"], 0);
        assert!(body["snapshot"]["checkpointSeq"].is_null());
        assert!(body["snapshot"]["observedAt"].as_u64().is_some());
        assert!(body["snapshot"]["recertifiedAt"].as_u64().is_some());
    }
    Ok(())
}

#[tokio::test]
async fn health_reports_snapshot_readiness_and_resource_usage() -> TestResult {
    let (_directory, state) = fixture().await?;
    let (status, body) = response_body(state, "/health").await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["receiptQuerySnapshot"]["state"], "ready", "{body}");
    assert!(body["receiptQuerySnapshot"]["usedBytes"].as_u64().is_some());
    assert!(body["receiptQuerySnapshot"]["watermark"]["id"].is_string());
    Ok(())
}

#[tokio::test]
async fn snapshot_errors_preserve_codes_status_and_retry_contracts() -> TestResult {
    use chio_kernel::receipt_query::ReceiptQuerySnapshotError as E;
    for (error, expected_status, retry) in [
        (
            E::Building {
                authenticated_entries: 2,
                target_entries: 9,
            },
            503,
            Some("5"),
        ),
        (E::Stale, 503, Some("2")),
        (E::Busy, 503, Some("1")),
        (E::Unavailable("capacity".into()), 503, None),
        (E::Invalid("leaf".into()), 500, None),
        (E::WorkBudgetExhausted("query".into()), 422, None),
    ] {
        let code = error.wire_code();
        let response = snapshot_error_response(error.into());
        assert_eq!(response.status().as_u16(), expected_status);
        assert_eq!(
            response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            retry
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
        let body: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["code"], code);
        assert!(body["error"].is_string());
    }
    let response = snapshot_error_response(ReceiptStoreError::Conflict("legacy".into()));
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    assert!(serde_json::from_slice::<Value>(&bytes)?
        .get("code")
        .is_none());
    Ok(())
}

#[tokio::test]
async fn receipt_admission_is_nonqueued_and_authentication_precedes_it() -> TestResult {
    let (_directory, state) = fixture().await?;
    let _held = Arc::clone(&state.receipt_query_lane).try_acquire_many_owned(4)?;
    for uri in [
        "/v1/receipts/query",
        TOOL_RECEIPTS_PATH,
        "/v1/receipts/tools?receiptId=absent",
        "/v1/agents/absent/receipts",
    ] {
        let (status, body) = response_body(state.clone(), uri).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{uri}: {body}");
        assert_eq!(body["code"], "receipt_query_busy");
        let request = Request::builder().uri(uri).body(Body::empty())?;
        let response = super::super::build_router(state.clone())
            .oneshot(request)
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_export_keeps_its_permit_until_blocking_work_stops() -> TestResult {
    use crate::trust_control::receipt_query_service::run_bounded;
    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let worker_lane = Arc::clone(&lane);
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let request = tokio::spawn(async move {
        run_bounded(worker_lane, move || {
            let _ = entered.send(());
            release_rx
                .recv()
                .map_err(|error| ReceiptStoreError::Io(std::io::Error::other(error)))?;
            Ok::<(), ReceiptStoreError>(())
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(10), entered_rx).await??;
    request.abort();
    assert!(request
        .await
        .test_expect_err("HTTP future was cancelled")
        .is_cancelled());
    assert_eq!(lane.available_permits(), 0);
    let refused = run_bounded(Arc::clone(&lane), || ())
        .await
        .test_expect_err("busy export must refuse");
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.headers()["retry-after"], "1");
    release.send(())?;
    let _released = tokio::time::timeout(Duration::from_secs(10), lane.acquire()).await??;
    Ok(())
}

#[tokio::test]
async fn export_lane_refuses_a_second_export_without_borrowing_read_capacity() -> TestResult {
    let (_directory, state) = fixture().await?;
    let _held = Arc::clone(&state.evidence_export_lane).try_acquire_owned()?;
    let request = Request::builder()
        .method("POST")
        .uri("/v1/evidence/export")
        .header(AUTHORIZATION, "Bearer snapshot-secret")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "query": chio_kernel::evidence_export::EvidenceExportQuery::admin_all(),
            "requireProofs": false,
        }))?))?;
    let response = super::super::build_router(state.clone())
        .oneshot(request)
        .await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "receipt_query_busy");
    assert_eq!(state.receipt_query_lane.available_permits(), 4);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_response_finalization_keeps_the_export_lane_occupied() -> TestResult {
    use crate::trust_control::receipt_query_service::{run_bounded, run_bounded_response};

    struct PausedFinalization {
        entered: tokio::sync::oneshot::Sender<()>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl IntoResponse for PausedFinalization {
        fn into_response(self) -> Response {
            let _ = self.entered.send(());
            match self.release.recv() {
                Ok(()) => Json(json!({"finalized": true})).into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
    }

    let lane = Arc::new(tokio::sync::Semaphore::new(1));
    let worker_lane = Arc::clone(&lane);
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let request = tokio::spawn(async move {
        run_bounded_response(worker_lane, move || PausedFinalization {
            entered,
            release: release_rx,
        })
        .await
    });
    tokio::time::timeout(Duration::from_secs(10), entered_rx).await??;
    request.abort();
    let second = run_bounded(Arc::clone(&lane), || ()).await;
    // Release even on the original implementation, where finalization blocks
    // an async worker and the second export was incorrectly admitted.
    release.send(())?;
    let cancelled = request.await;
    assert_eq!(
        second
            .test_expect_err("finalization must retain the export permit")
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(cancelled
        .test_expect_err("cancelled request")
        .is_cancelled());
    let _released = tokio::time::timeout(Duration::from_secs(10), lane.acquire()).await??;
    Ok(())
}

/// Core C1 counts signature checks in the service itself. This HTTP control
/// distinguishes that service from per-call corpus authentication: an edit to
/// an unreturned row cannot change a pinned answer, while selecting it refuses.
#[tokio::test]
async fn http_pages_use_the_pinned_projection_and_refuse_a_changed_returned_leaf() -> TestResult {
    use chio_core::crypto::Keypair;
    use chio_core::receipt::body::ChioReceipt;
    use chio_store_sqlite::receipt_query_snapshot::{
        ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
    };
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let signer = Arc::new(Keypair::from_seed(&[43; 32]));
    store.enable_background_checkpoints(chio_store_sqlite::BackgroundCheckpointSigner {
        keypair: Arc::clone(&signer),
        max_batch: 10,
    })?;
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    let mut appended = Vec::new();
    for index in 0..400 {
        let mut body = template.clone();
        body.timestamp = 100 + index;
        body.tenant_id = Some("snapshot-tenant".to_string());
        let receipt = ChioReceipt::sign(body, &signer)?;
        store.append_chio_receipt(&receipt)?;
        appended.push(receipt);
        if index == 199 {
            store.flush_receipt_writes()?;
            assert_eq!(
                store.archive_receipts_before(
                    300,
                    &directory.path().join("archive.db").to_string_lossy()
                )?,
                200
            );
        }
    }
    store.flush_receipt_writes()?;
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    tokio::time::timeout(Duration::from_secs(30), async {
        while snapshots.status().state != ReceiptQuerySnapshotState::Ready {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let mut state = metrics_state("snapshot-secret");
    state.config.receipt_db_path = Some(path.clone());
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state
        .config
        .tenant_read_tokens
        .insert("snapshot-tenant".into(), "tenant-secret".into());
    let original = appended
        .last()
        .test_expect("fixture contains a live final row");
    let mut tampered = original.clone();
    tampered.content_hash = "changed-after-publication".to_string();
    let connection = rusqlite::Connection::open(path)?;
    connection.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
        false,
    )?;
    assert_eq!(
        connection.execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![serde_json::to_string(&tampered)?, original.id]
        )?,
        1
    );
    let expected_ids: Vec<_> = appended
        .iter()
        .take(10)
        .map(|receipt| receipt.id.as_str())
        .collect();
    for _ in 0..10 {
        let request = Request::builder()
            .uri("/v1/receipts/query?limit=10")
            .header(AUTHORIZATION, "Bearer tenant-secret")
            .body(Body::empty())?;
        let response = super::super::build_router(state.clone())
            .oneshot(request)
            .await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
        let body: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["totalCount"], 400);
        assert_eq!(body["snapshot"]["throughEntrySeq"], 400);
        let ids: Vec<_> = body["receipts"]
            .as_array()
            .test_expect("receipt array")
            .iter()
            .map(|receipt| receipt["id"].as_str().test_expect("receipt id"))
            .collect();
        assert_eq!(ids, expected_ids);
    }
    let (status, body) = response_body(
        state,
        &format!("/v1/receipts/tools?receiptId={}", original.id),
    )
    .await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_invalid");
    snapshots.shutdown();
    Ok(())
}
