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

async fn wait_until_ready(snapshots: Arc<ReceiptQuerySnapshots>) -> TestResult {
    let status = tokio::task::spawn_blocking(move || {
        // A hang guard, not a snapshot construction performance requirement.
        snapshots.wait_for_recovery(Duration::from_secs(600), |status| {
            !matches!(
                status.state,
                ReceiptQuerySnapshotState::WaitingForWriterSeed
                    | ReceiptQuerySnapshotState::Building { .. }
            )
        })
    })
    .await?;
    assert_eq!(status.state, ReceiptQuerySnapshotState::Ready, "{status:?}");
    Ok(())
}

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
    wait_until_ready(Arc::clone(&snapshots)).await?;
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

#[tokio::test]
async fn oversized_tenant_export_returns_422_without_bundle_or_snapshot_invalidation() -> TestResult
{
    let directory = chio_test_support::private_tempdir()?;
    let store = Arc::new(SqliteReceiptStore::open(
        directory.path().join("receipts.db"),
    )?);
    let signer = Keypair::from_seed(&[43; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    for index in 0..4_097_u64 {
        let mut body = template.clone();
        body.id = format!("over-budget-{index}");
        body.tenant_id = Some("tenant-a".into());
        body.timestamp = 100 + index;
        store.append_chio_receipt(&ChioReceipt::sign(body, &signer)?)?;
    }
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    wait_until_ready(Arc::clone(&snapshots)).await?;
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-secret".into());
    let (status, body) = export(state).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "receipt_query_work_budget_exhausted");
    assert!(body.get("bundle").is_none(), "{body}");
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(
        snapshots
            .query_receipts(
                &chio_kernel::evidence_export::EvidenceExportQuery::tenant_scoped("tenant-a")
                    .as_receipt_query(None)
            )?
            .total_count,
        4_097
    );
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn legacy_lineage_refusal_returns_typed_422_and_preserves_other_tenants() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    assert_eq!(
        connection.execute(
            "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, provenance) VALUES ('cap-legacy', 'legacy-subject', 'legacy-issuer', 1, 100, '{}', 0, 'legacy_projection')",
            [],
        )?,
        1
    );
    drop(connection);
    let signer = Keypair::from_seed(&[43; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    for (id, tenant, capability) in [
        ("legacy-a", "tenant-a", "cap-legacy"),
        ("plain-b", "tenant-b", "cap-plain"),
    ] {
        let mut body = template.clone();
        body.id = id.into();
        body.tenant_id = Some(tenant.into());
        body.capability_id = capability.into();
        store.append_chio_receipt(&ChioReceipt::sign(body, &signer)?)?;
    }
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    wait_until_ready(Arc::clone(&snapshots)).await?;
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-secret".into());
    state
        .config
        .tenant_read_tokens
        .insert("tenant-b".into(), "tenant-b-secret".into());
    let (status, body) = export(state.clone()).await?;
    let request = Request::builder()
        .method("POST")
        .uri("/v1/evidence/export")
        .header(AUTHORIZATION, "Bearer tenant-b-secret")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "query": chio_kernel::evidence_export::EvidenceExportQuery::tenant_scoped("tenant-b"),
            "requireProofs": false,
        }))?))?;
    let response = super::super::build_router(state).oneshot(request).await?;
    let b_status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    let b_body: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "receipt_query_export_refused");
    assert_eq!(body["error"], "receipt evidence export refused: capability lineage cap-legacy uses legacy projection provenance outside the local migration boundary");
    assert!(body.get("bundle").is_none(), "{body}");
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(b_status, StatusCode::OK, "{b_body}");
    assert_eq!(
        b_body["bundle"]["toolReceipts"]
            .as_array()
            .test_expect("receipts")
            .len(),
        1
    );
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn invalid_signed_lineage_is_a_typed_refusal_without_dropping_other_tenants() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let signer = Keypair::from_seed(&[43; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    for (id, tenant, capability) in [
        ("bad-a", "tenant-a", "cap-bad-signed"),
        ("plain-b", "tenant-b", "cap-plain"),
    ] {
        let mut body = template.clone();
        body.id = id.into();
        body.tenant_id = Some(tenant.into());
        body.capability_id = capability.into();
        store.append_chio_receipt(&ChioReceipt::sign(body, &signer)?)?;
    }
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    wait_until_ready(Arc::clone(&snapshots)).await?;
    let connection = rusqlite::Connection::open(&path)?;
    let inserted = connection.execute(
        "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, provenance) VALUES ('cap-bad-signed', 'bad-subject', 'bad-issuer', 1, 100, '{}', 0, 'signed_token')",
        [],
    );
    assert_eq!(inserted?, 1);
    drop(connection);
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-secret".into());
    state
        .config
        .tenant_read_tokens
        .insert("tenant-b".into(), "tenant-b-secret".into());
    let (status, body) = export(state.clone()).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "receipt_query_export_refused");
    assert_eq!(body["error"], "receipt evidence export refused: capability lineage cap-bad-signed claims signed-token provenance without a signed token");
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/evidence/export")
        .header(AUTHORIZATION, "Bearer tenant-b-secret")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "query": chio_kernel::evidence_export::EvidenceExportQuery::tenant_scoped("tenant-b"),
            "requireProofs": false,
        }))?))?;
    let response = super::super::build_router(state).oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn captured_legacy_attribution_tamper_invalidates_before_export_refusal() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, provenance) VALUES ('cap-legacy', 'legacy-subject', 'legacy-issuer', 1, 100, '{}', 0, 'legacy_projection')",
        [],
    )?;
    drop(connection);
    let signer = Keypair::from_seed(&[43; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    for (id, tenant, capability) in [
        ("legacy-a", "tenant-a", "cap-legacy"),
        ("plain-b", "tenant-b", "cap-plain"),
    ] {
        let mut body = template.clone();
        body.id = id.into();
        body.tenant_id = Some(tenant.into());
        body.capability_id = capability.into();
        store.append_chio_receipt(&ChioReceipt::sign(body, &signer)?)?;
    }
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    wait_until_ready(Arc::clone(&snapshots)).await?;
    let mut by_subject =
        chio_kernel::evidence_export::EvidenceExportQuery::tenant_scoped("tenant-a")
            .as_receipt_query(None);
    by_subject.agent_subject = Some("legacy-subject".into());
    assert_eq!(snapshots.query_receipts(&by_subject)?.total_count, 1);
    let connection = rusqlite::Connection::open(&path)?;
    let updated = connection.execute(
        "UPDATE capability_lineage SET subject_key = 'tampered-subject' WHERE capability_id = 'cap-legacy'",
        [],
    );
    assert_eq!(updated?, 1);
    drop(connection);
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-secret".into());
    let (status, body) = export(state).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_invalid");
    assert_eq!(body["error"], "receipt query snapshot failed authentication: current unsigned capability attribution differs from the authenticated snapshot");
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    snapshots.shutdown();
    Ok(())
}

const SNAPSHOT_INVALID_ATTRIBUTION: &str = "receipt query snapshot failed authentication: current unsigned capability attribution differs from the authenticated snapshot";

/// Legacy lineage rows with one tenant-a receipt each, one unrelated tenant-b
/// receipt, a ready snapshot, and a router state with both tenant tokens.
async fn legacy_lineage_router(
    capabilities: &[(&str, &str, u64)],
) -> Result<
    (
        tempfile::TempDir,
        std::path::PathBuf,
        Arc<ReceiptQuerySnapshots>,
        TrustServiceState,
    ),
    Box<dyn std::error::Error>,
> {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let connection = rusqlite::Connection::open(&path)?;
    for (capability, subject, _) in capabilities {
        connection.execute(
            "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, provenance) VALUES (?1, ?2, 'legacy-issuer', 1, 100, '{}', 0, 'legacy_projection')",
            rusqlite::params![capability, subject],
        )?;
    }
    drop(connection);
    let signer = Keypair::from_seed(&[43; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    for (index, (capability, _, timestamp)) in capabilities.iter().enumerate() {
        let mut body = template.clone();
        body.id = format!("receipt-a-{index}");
        body.tenant_id = Some("tenant-a".into());
        body.capability_id = (*capability).into();
        body.timestamp = *timestamp;
        store.append_chio_receipt(&ChioReceipt::sign(body, &signer)?)?;
    }
    let mut body = template;
    body.id = "plain-b".into();
    body.tenant_id = Some("tenant-b".into());
    body.capability_id = "cap-plain".into();
    store.append_chio_receipt(&ChioReceipt::sign(body, &signer)?)?;
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    wait_until_ready(Arc::clone(&snapshots)).await?;
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-secret".into());
    state
        .config
        .tenant_read_tokens
        .insert("tenant-b".into(), "tenant-b-secret".into());
    Ok((directory, path, snapshots, state))
}

/// Out-of-band lineage edit with triggers left enabled.
fn edit_lineage(path: &std::path::Path, sql: &str) -> TestResult {
    let connection = rusqlite::Connection::open(path)?;
    assert_eq!(connection.execute(sql, [])?, 1);
    Ok(())
}

async fn tenant_b_export_status(
    state: TrustServiceState,
) -> Result<StatusCode, Box<dyn std::error::Error>> {
    let request = Request::builder()
        .method("POST")
        .uri("/v1/evidence/export")
        .header(AUTHORIZATION, "Bearer tenant-b-secret")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&json!({
            "query": chio_kernel::evidence_export::EvidenceExportQuery::tenant_scoped("tenant-b"),
            "requireProofs": false,
        }))?))?;
    Ok(super::super::build_router(state)
        .oneshot(request)
        .await?
        .status())
}

async fn assert_http_export_invalidates(
    snapshots: &ReceiptQuerySnapshots,
    state: TrustServiceState,
) -> TestResult {
    let (status, body) = export(state).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_invalid");
    assert_eq!(body["error"], SNAPSHOT_INVALID_ATTRIBUTION);
    assert!(body.get("bundle").is_none(), "{body}");
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn non_utf8_captured_subject_returns_snapshot_invalid() -> TestResult {
    let (_directory, path, snapshots, state) =
        legacy_lineage_router(&[("cap-legacy", "legacy-subject", 100)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET subject_key = CAST(x'ff' AS TEXT) WHERE capability_id = 'cap-legacy'")?;
    assert_http_export_invalidates(&snapshots, state).await?;
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn oversized_captured_subject_returns_snapshot_invalid() -> TestResult {
    let (_directory, path, snapshots, state) =
        legacy_lineage_router(&[("cap-legacy", "legacy-subject", 100)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET subject_key = 'changed-' || hex(zeroblob(16777216)) WHERE capability_id = 'cap-legacy'")?;
    assert_http_export_invalidates(&snapshots, state).await?;
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn earlier_lineage_refusal_does_not_mask_a_later_attribution_change_over_http() -> TestResult
{
    let (_directory, path, snapshots, state) =
        legacy_lineage_router(&[("cap-1", "subject-1", 100), ("cap-2", "subject-2", 200)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET subject_key = 'changed-subject' WHERE capability_id = 'cap-2'")?;
    assert_http_export_invalidates(&snapshots, state).await?;
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn non_utf8_unattributed_lineage_column_returns_typed_refusal() -> TestResult {
    let (_directory, path, snapshots, state) =
        legacy_lineage_router(&[("cap-legacy", "legacy-subject", 100)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET issuer_key = CAST(x'ff' AS TEXT) WHERE capability_id = 'cap-legacy'")?;
    let (status, body) = export(state.clone()).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "receipt_query_export_refused");
    assert_eq!(
        body["error"],
        "receipt evidence export refused: capability lineage row contains invalid metadata"
    );
    assert!(body.get("bundle").is_none(), "{body}");
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(tenant_b_export_status(state).await?, StatusCode::OK);
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn oversized_unrelated_lineage_metadata_returns_bounded_refusal() -> TestResult {
    let (_directory, path, snapshots, state) =
        legacy_lineage_router(&[("cap-legacy", "legacy-subject", 100)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET grants_json = hex(zeroblob(16777216)) WHERE capability_id = 'cap-legacy'")?;
    let (status, body) = export(state.clone()).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "receipt_query_work_budget_exhausted");
    assert!(body.get("bundle").is_none(), "{body}");
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(tenant_b_export_status(state).await?, StatusCode::OK);
    snapshots.shutdown();
    Ok(())
}
