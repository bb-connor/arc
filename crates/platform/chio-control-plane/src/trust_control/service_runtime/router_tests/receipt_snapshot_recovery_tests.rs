//! A real projection quota is a recoverable HTTP availability condition.
use super::*;
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_store_sqlite::receipt_query_snapshot::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};

#[tokio::test]
async fn http_reads_recover_after_quota_growth_and_still_verify_selected_payloads() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let signer = Keypair::from_seed(&[67; 32]);
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
            quota_bytes: 1024 * 1024,
            step_rows: 32,
            insert_rows: 16,
            invalid_retry_backoff: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    )?);
    tokio::time::timeout(Duration::from_secs(30), async {
        while !matches!(
            snapshots.status().state,
            ReceiptQuerySnapshotState::Unavailable { .. }
        ) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let mut state = metrics_state("snapshot-secret");
    state.config.receipt_db_path = Some(path.clone());
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    let (status, body) = response_body(state.clone(), "/v1/receipts/query?limit=1").await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_unavailable");
    snapshots.increase_quota_bytes(8 * 1024 * 1024)?;
    tokio::time::timeout(Duration::from_secs(30), async {
        while snapshots.status().state != ReceiptQuerySnapshotState::Ready {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let (status, body) = response_body(state.clone(), "/v1/receipts/query?limit=1").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["totalCount"], 192);
    let original = selected.test_expect("appended receipts");
    let mut changed = original.clone();
    changed.content_hash = "changed-after-recovery".to_string();
    let connection = rusqlite::Connection::open(path)?;
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
        state,
        &format!("/v1/receipts/tools?receiptId={}", original.id),
    )
    .await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_invalid");
    snapshots.shutdown();
    Ok(())
}
