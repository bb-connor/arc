//! HTTP evidence exports select from the authenticated snapshot, including
//! when another tenant's unselected payload changes after publication.
use super::*;
use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request};
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_store_sqlite::receipt_query_snapshot::{
    ReceiptQuerySnapshotConfig, ReceiptQuerySnapshotState, ReceiptQuerySnapshots,
};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn export(
    state: TrustServiceState,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/evidence/export")
        .header(AUTHORIZATION, "Bearer tenant-secret")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "query": chio_kernel::evidence_export::EvidenceExportQuery::tenant_scoped("tenant-a"),
            "requireProofs": false,
        }))?))?;
    let response = super::super::build_router(state).oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"error": String::from_utf8_lossy(&bytes)}));
    Ok((status, body))
}

#[tokio::test]
async fn export_requires_an_authenticated_snapshot_instead_of_scanning_the_store() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let store = Arc::new(SqliteReceiptStore::open(
        directory.path().join("receipts.db"),
    )?);
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-secret".into());
    let (status, body) = export(state).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_unavailable");
    Ok(())
}

#[tokio::test]
async fn tenant_export_does_not_reauthenticate_unselected_tenant_payloads() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let signer = Arc::new(Keypair::from_seed(&[43; 32]));
    store.enable_background_checkpoints(chio_store_sqlite::BackgroundCheckpointSigner {
        keypair: Arc::clone(&signer),
        max_batch: 2,
    })?;
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    let mut other = None;
    let mut selected_id = None;
    for (id, tenant, timestamp) in [
        ("selected", "tenant-a", 100),
        ("unselected", "tenant-b", 101),
    ] {
        let mut body = template.clone();
        body.id = id.into();
        body.tenant_id = Some(tenant.into());
        body.timestamp = timestamp;
        let receipt = ChioReceipt::sign(body, &signer)?;
        store.append_chio_receipt(&receipt)?;
        if tenant == "tenant-b" {
            other = Some(receipt);
        } else {
            selected_id = Some(receipt.id.clone());
        }
    }
    store.flush_receipt_writes()?;
    let archive = directory.path().join("archive.db");
    assert_eq!(
        store.archive_receipts_before(102, archive.to_str().test_expect("archive path"))?,
        2
    );
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_secs(60),
            ..ReceiptQuerySnapshotConfig::default()
        },
    )?);
    tokio::time::timeout(Duration::from_secs(10), async {
        while snapshots.status().state != ReceiptQuerySnapshotState::Ready {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    let baseline = store.build_evidence_export_bundle(
        &chio_kernel::evidence_export::EvidenceExportQuery::tenant_scoped("tenant-a"),
    )?;
    assert_eq!(baseline.tool_receipts.len(), 1);
    assert_eq!(baseline.inclusion_proofs.len(), 1);
    let mut tampered = other.test_expect("other tenant receipt");
    tampered.content_hash = "changed-after-publication".into();
    let connection = rusqlite::Connection::open(&archive)?;
    connection.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
        false,
    )?;
    assert_eq!(
        connection.execute(
            "UPDATE claim_receipt_log_entries SET raw_json = ?1 WHERE receipt_id = ?2",
            rusqlite::params![serde_json::to_string(&tampered)?, tampered.id]
        )?,
        1
    );
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-secret".into());
    let (status, body) = export(state).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let receipts = body["bundle"]["toolReceipts"]
        .as_array()
        .test_expect("receipt array");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0]["receipt"]["id"],
        selected_id.test_expect("selected receipt id")
    );
    assert_eq!(body["snapshot"]["throughEntrySeq"], 2);
    snapshots.shutdown();
    Ok(())
}
