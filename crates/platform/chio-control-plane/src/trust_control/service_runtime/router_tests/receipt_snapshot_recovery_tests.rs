//! A real projection quota is a recoverable HTTP availability condition, and
//! the node-local operator route is the only HTTP way to raise it or retry.
//! Waits block on the snapshot service's own notifications; their timeouts
//! only bound a hang, and claims are asserted on how backoff waits ended.
use super::*;
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_store_sqlite::receipt_query_snapshot::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotRecoveryStatus, ReceiptQuerySnapshotState,
    ReceiptQuerySnapshots,
};

const HANG: Duration = Duration::from_secs(300);
const MIB: u64 = 1024 * 1024;
const SERVICE: &str = "Bearer snapshot-secret";

/// A node whose snapshot history exceeds its 1 MiB quota. The first resource
/// wait is 30 s and later ones double, so no assertion below can be met by a
/// backoff deadline without the deadline counter showing it.
struct QuotaBound {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    state: TrustServiceState,
    snapshots: Arc<ReceiptQuerySnapshots>,
    selected: ChioReceipt,
}

async fn quota_bound(seed: u8) -> Result<QuotaBound, Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let signer = Keypair::from_seed(&[seed; 32]);
    let template = super::super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    let mut selected = None;
    for index in 0..192 {
        let mut body = template.clone();
        body.id = format!("quota-receipt-{index}");
        body.timestamp += index;
        body.tool_name = format!("{index}-{}", "x".repeat(8192));
        let receipt = ChioReceipt::sign(body, &signer)?;
        store.append_chio_receipt(&receipt)?;
        selected = Some(receipt);
    }
    store.flush_receipt_writes()?;
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig {
            quota_bytes: MIB,
            step_rows: 32,
            insert_rows: 16,
            invalid_retry_backoff: Duration::from_secs(3_600),
            ..ReceiptQuerySnapshotConfig::default()
        },
    )?);
    let status = wait_for(&snapshots, |status| {
        matches!(status.state, ReceiptQuerySnapshotState::Unavailable { .. })
    })
    .await?;
    assert!(
        matches!(&status.state, ReceiptQuerySnapshotState::Unavailable { reason }
            if reason.contains("backing storage or configured quota")),
        "{status:?}"
    );
    let mut state = metrics_state("snapshot-secret");
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-read-secret".into());
    state.config.receipt_db_path = Some(path.clone());
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    Ok(QuotaBound {
        _directory: directory,
        path,
        state,
        snapshots,
        selected: selected.test_expect("appended receipts"),
    })
}

async fn wait_for(
    snapshots: &Arc<ReceiptQuerySnapshots>,
    done: impl FnMut(&ReceiptQuerySnapshotRecoveryStatus) -> bool + Send + 'static,
) -> Result<ReceiptQuerySnapshotRecoveryStatus, Box<dyn std::error::Error>> {
    let snapshots = Arc::clone(snapshots);
    Ok(tokio::task::spawn_blocking(move || snapshots.wait_for_recovery(HANG, done)).await?)
}

async fn shutdown(snapshots: &Arc<ReceiptQuerySnapshots>) -> TestResult {
    let snapshots = Arc::clone(snapshots);
    tokio::task::spawn_blocking(move || snapshots.shutdown()).await?;
    Ok(())
}

async fn recover(
    state: &TrustServiceState,
    credential: Option<&str>,
    body: Body,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let mut request = Request::builder()
        .method("POST")
        .uri(RECEIPT_QUERY_SNAPSHOT_RECOVERY_PATH)
        .header("content-type", "application/json");
    if let Some(credential) = credential {
        request = request.header(AUTHORIZATION, credential);
    }
    let response = super::super::super::build_router(state.clone())
        .oneshot(request.body(body)?)
        .await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, body))
}

async fn public_snapshot_health(
    state: &TrustServiceState,
) -> Result<Value, Box<dyn std::error::Error>> {
    let request = Request::builder().uri("/health").body(Body::empty())?;
    let response = super::super::super::build_router(state.clone())
        .oneshot(request)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let body: Value = serde_json::from_slice(&bytes)?;
    Ok(body["receiptQuerySnapshot"].clone())
}

fn lineage(body: &Value) -> Option<String> {
    body["snapshot"]["id"]
        .as_str()
        .and_then(|id| id.split(':').next())
        .map(str::to_owned)
}

fn assert_unchanged(status: &ReceiptQuerySnapshotRecoveryStatus, retry_requested: u64) {
    assert_eq!(status.requested_quota_bytes, MIB, "{status:?}");
    assert_eq!(status.retry_requested, retry_requested, "{status:?}");
    assert_eq!(
        (status.retry_wakes, status.quota_wakes),
        (0, 0),
        "{status:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_recovery_route_exists_while_reads_are_unavailable_at_quota() -> TestResult {
    let node = quota_bound(68).await?;
    let (status, body) = response_body(node.state.clone(), "/v1/receipts/query?limit=1").await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_unavailable");
    let (status, body) = recover(
        &node.state,
        Some(SERVICE),
        Body::from(r#"{"quotaBytes":8388608}"#),
    )
    .await?;
    shutdown(&node.snapshots).await?;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "the operator recovery route must accept a node-local quota increase: {body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_reads_recover_after_quota_growth_and_still_verify_selected_payloads() -> TestResult {
    let node = quota_bound(67).await?;
    assert_eq!(
        public_snapshot_health(&node.state).await?,
        json!({"configured": true, "state": "unavailable"}),
        "public health must not disclose quota, usage or diagnostic text while unavailable"
    );
    let (status, body) = response_body(node.state.clone(), "/v1/receipts/query?limit=1").await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_unavailable");

    let (status, body) = recover(
        &node.state,
        Some(SERVICE),
        Body::from(r#"{"quotaBytes":8388608}"#),
    )
    .await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(
        body,
        json!({
            "recovery": "scheduled",
            "retryEpoch": 1,
            "quotaBytes": 8 * MIB,
            "quotaPersisted": false,
        })
    );
    let recovered = wait_for(&node.snapshots, |status| {
        status.state == ReceiptQuerySnapshotState::Ready
    })
    .await?;
    assert_eq!(recovered.state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(
        (
            recovered.quota_wakes,
            recovered.retry_wakes,
            recovered.deadline_wakes
        ),
        (1, 0, 0),
        "the request, not the 30 s backoff deadline, must end the wait"
    );
    assert_eq!(
        (recovered.retry_requested, recovered.retry_answered),
        (1, 1)
    );
    let (status, body) = response_body(node.state.clone(), "/v1/receipts/query?limit=1").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["totalCount"], 192);
    let served = lineage(&body);
    assert!(served.is_some(), "{body}");

    // A serving projection is not rebuilt, and a decrease is refused.
    let (status, body) = recover(&node.state, Some(SERVICE), Body::from("{}")).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"recovery": "serving", "quotaBytes": 8 * MIB, "quotaPersisted": false})
    );
    let (status, body) = recover(
        &node.state,
        Some(SERVICE),
        Body::from(r#"{"quotaBytes":4194304}"#),
    )
    .await?;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let after = node.snapshots.recovery_status();
    assert_eq!(after.requested_quota_bytes, 8 * MIB);
    assert_eq!((after.retry_requested, after.retry_answered), (1, 1));
    let (status, body) = response_body(node.state.clone(), "/v1/receipts/query?limit=1").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(lineage(&body), served);

    let original = &node.selected;
    let mut changed = original.clone();
    changed.content_hash = "changed-after-recovery".to_string();
    let connection = rusqlite::Connection::open(&node.path)?;
    connection.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
        false,
    )?;
    assert_eq!(
        connection.execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![serde_json::to_string(&changed)?, original.id],
        )?,
        1
    );
    let (status, body) = response_body(
        node.state.clone(),
        &format!("/v1/receipts/tools?receiptId={}", original.id),
    )
    .await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_invalid");
    shutdown(&node.snapshots).await?;
    assert_eq!(
        public_snapshot_health(&node.state).await?,
        json!({"configured": true, "state": "stopped"})
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_retry_wakes_an_unchanged_quota_backoff_by_request_not_by_its_deadline(
) -> TestResult {
    let node = quota_bound(69).await?;
    for (body, expected) in [
        (
            format!(r#"{{"quotaBytes":{}}}"#, "9".repeat(250)),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
        (
            r#"{"quotaBytes":8388608,"grow":true}"#.to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            r#"{"quotaBytes":-1}"#.to_string(),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            r#"{"quotaBytes":1024}"#.to_string(),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let (status, response) =
            recover(&node.state, Some(SERVICE), Body::from(body.clone())).await?;
        assert_eq!(status, expected, "{body}: {response}");
    }
    assert_unchanged(&node.snapshots.recovery_status(), 0);

    let (status, body) = recover(&node.state, Some(SERVICE), Body::from("{}")).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(
        body,
        json!({
            "recovery": "scheduled",
            "retryEpoch": 1,
            "quotaBytes": MIB,
            "quotaPersisted": false,
        })
    );
    let woken = wait_for(&node.snapshots, |status| status.retry_answered >= 1).await?;
    assert_eq!(woken.retry_answered, 1, "{woken:?}");
    assert_eq!(
        (woken.retry_wakes, woken.quota_wakes, woken.deadline_wakes),
        (1, 0, 0),
        "the retry request, not the 30 s backoff deadline, must end the wait"
    );
    assert_eq!(
        woken.requested_quota_bytes, MIB,
        "a retry never grows the quota"
    );
    let unavailable = wait_for(&node.snapshots, |status| {
        matches!(status.state, ReceiptQuerySnapshotState::Unavailable { .. })
    })
    .await?;
    assert!(
        matches!(&unavailable.state, ReceiptQuerySnapshotState::Unavailable { reason }
            if reason.contains("backing storage or configured quota")),
        "{unavailable:?}"
    );
    let (status, body) = response_body(node.state.clone(), "/v1/receipts/query?limit=1").await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    shutdown(&node.snapshots).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_recovery_refuses_missing_wrong_and_tenant_tokens_before_reading_the_body(
) -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let node = quota_bound(70).await?;
    let counted = || {
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&polls);
        let stream = futures_util::stream::once(async move {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(br#"{"quotaBytes":8388608}"#))
        });
        (Body::from_stream(stream), polls)
    };
    for credential in [
        None,
        Some("Bearer forged-snapshot-secret"),
        Some("Bearer tenant-read-secret"),
        Some("Basic snapshot-secret"),
    ] {
        let (body, polls) = counted();
        let (status, response) = recover(&node.state, credential, body).await?;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{credential:?}: {response}"
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0, "{credential:?}");
    }
    assert_unchanged(&node.snapshots.recovery_status(), 0);

    let (body, polls) = counted();
    let (status, response) = recover(&node.state, Some(SERVICE), body).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert_eq!(node.snapshots.recovery_status().retry_requested, 1);
    shutdown(&node.snapshots).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_recovery_request_changes_nothing_and_a_stopped_service_refuses_cleanly(
) -> TestResult {
    let node = quota_bound(71).await?;
    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel::<()>();
    let mut reached = Some(reached_tx);
    let mut sent = false;
    let stream = futures_util::stream::poll_fn(move |_| {
        if !sent {
            sent = true;
            return std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(
                axum::body::Bytes::from_static(br#"{"quotaBytes":"#),
            )));
        }
        if let Some(reached) = reached.take() {
            let _ = reached.send(());
        }
        std::task::Poll::Pending
    });
    let request = Request::builder()
        .method("POST")
        .uri(RECEIPT_QUERY_SNAPSHOT_RECOVERY_PATH)
        .header("content-type", "application/json")
        .header(AUTHORIZATION, SERVICE)
        .body(Body::from_stream(stream))?;
    let pending =
        tokio::spawn(super::super::super::build_router(node.state.clone()).oneshot(request));
    tokio::time::timeout(HANG, reached_rx).await??;
    pending.abort();
    let dropped = pending.await;
    assert!(dropped.is_err_and(|error| error.is_cancelled()));
    assert_unchanged(&node.snapshots.recovery_status(), 0);

    let (status, body) = recover(&node.state, Some(SERVICE), Body::from("{}")).await?;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["retryEpoch"], 1);
    let woken = wait_for(&node.snapshots, |status| status.retry_answered >= 1).await?;
    assert_eq!(
        (woken.retry_wakes, woken.deadline_wakes),
        (1, 0),
        "{woken:?}"
    );

    shutdown(&node.snapshots).await?;
    let (status, body) = recover(
        &node.state,
        Some(SERVICE),
        Body::from(r#"{"quotaBytes":8388608}"#),
    )
    .await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], "receipt query snapshot service is stopped");
    let stopped = node.snapshots.recovery_status();
    assert_eq!(stopped.state, ReceiptQuerySnapshotState::Stopped);
    assert_eq!(stopped.requested_quota_bytes, MIB);
    assert_eq!(stopped.retry_requested, 1);
    Ok(())
}
