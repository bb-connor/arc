//! HTTP evidence exports select from the authenticated snapshot, including
//! when another tenant's unselected payload changes after publication.
use super::*;
use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request};
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::EvidenceExportReceiptQuery;
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

/// Records a signed-token lineage row for `id` whose subject is `subject`.
fn record_signed_lineage(
    store: &SqliteReceiptStore,
    id: &str,
    subject: &Keypair,
) -> Result<String, Box<dyn std::error::Error>> {
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: Keypair::from_seed(&[44; 32]).public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 1,
            expires_at: 4_000_000_000,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &Keypair::from_seed(&[44; 32]),
    )?;
    store.record_capability_snapshot(&token, None)?;
    Ok(subject.public_key().to_hex())
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
            "query": chio_core::receipt::evidence::EvidenceExportQuery::tenant_scoped("tenant-a"),
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
    state.config.access = crate::trust_control::caller_credentials::tests::test_access_with_roles(
        "snapshot-secret",
        None,
        &[("tenant-a", "tenant-secret")],
    );
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
        &chio_core::receipt::evidence::EvidenceExportQuery::tenant_scoped("tenant-a"),
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
    state.config.access = crate::trust_control::caller_credentials::tests::test_access_with_roles(
        "snapshot-secret",
        None,
        &[("tenant-a", "tenant-secret")],
    );
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
    state.config.access = crate::trust_control::caller_credentials::tests::test_access_with_roles(
        "snapshot-secret",
        None,
        &[("tenant-a", "tenant-secret")],
    );
    let (status, body) = export(state).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "receipt_query_work_budget_exhausted");
    assert!(body.get("bundle").is_none(), "{body}");
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(
        snapshots
            .query_receipts(
                &chio_core::receipt::evidence::EvidenceExportQuery::tenant_scoped("tenant-a")
                    .as_receipt_query(None)
            )?
            .total_count,
        4_097
    );
    snapshots.shutdown();
    Ok(())
}

const REFUSED_LINEAGE: &str = "INSERT INTO capability_lineage (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, delegation_depth, provenance) VALUES ('cap-bad-signed', 'bad-subject', 'bad-issuer', 1, 100, '{}', 0, 'signed_token')";

/// A tenant-a receipt of `cap-bad-signed`, with signed attribution when
/// `signed`, and a tenant-b receipt without signed attribution, of
/// `cap-bad-signed` when `shared` and of another capability otherwise; a
/// ready snapshot and a router state with both tenant tokens.
async fn refused_lineage_router(
    signed: bool,
    shared: bool,
    config: ReceiptQuerySnapshotConfig,
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
    let signer = Keypair::from_seed(&[43; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    let other = if shared {
        "cap-bad-signed"
    } else {
        "cap-plain"
    };
    for (id, tenant, capability, attributed) in [
        ("bad-a", "tenant-a", "cap-bad-signed", signed),
        ("plain-b", "tenant-b", other, false),
    ] {
        let mut body = template.clone();
        body.id = id.into();
        body.tenant_id = Some(tenant.into());
        body.capability_id = capability.into();
        if attributed {
            body.metadata = Some(json!({
                "attribution": {"subject_key": "signed-subject", "issuer_key": "signed-issuer", "delegation_depth": 0}
            }));
        }
        store.append_chio_receipt(&ChioReceipt::sign(body, &signer)?)?;
    }
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(Arc::clone(&store), config)?);
    wait_until_ready(Arc::clone(&snapshots)).await?;
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state.config.access = crate::trust_control::caller_credentials::tests::test_access_with_roles(
        "snapshot-secret",
        None,
        &[
            ("tenant-a", "tenant-secret"),
            ("tenant-b", "tenant-b-secret"),
        ],
    );
    Ok((directory, path, snapshots, state))
}

fn insert_refused_lineage(path: &std::path::Path) -> TestResult {
    let connection = rusqlite::Connection::open(path)?;
    assert_eq!(connection.execute(REFUSED_LINEAGE, [])?, 1);
    Ok(())
}

/// Wait until an extension cycle that began after this call has completed:
/// the second change of the observation time, as cycles run one at a time.
/// Returns early when the snapshot leaves `Ready`.
async fn await_extension_cycle(snapshots: Arc<ReceiptQuerySnapshots>) -> TestResult {
    tokio::task::spawn_blocking(move || {
        let observed =
            |status: &chio_store_sqlite::receipt_query_snapshot::ReceiptQuerySnapshotStatus| {
                status
                    .watermark
                    .as_ref()
                    .map(|watermark| watermark.observed_at_unix_ms)
            };
        let mut seen = observed(&snapshots.status());
        let mut changes = 0;
        // A hang guard, not an extension cadence requirement.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while changes < 2 {
            let status = snapshots.status();
            if status.state != ReceiptQuerySnapshotState::Ready {
                return;
            }
            let current = observed(&status);
            if current != seen {
                changes += 1;
                seen = current;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no extension cycle completed"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    })
    .await?;
    Ok(())
}

async fn assert_typed_refusal_keeps_other_tenants(
    snapshots: &ReceiptQuerySnapshots,
    state: TrustServiceState,
) -> TestResult {
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
            "query": chio_core::receipt::evidence::EvidenceExportQuery::tenant_scoped("tenant-b"),
            "requireProofs": false,
        }))?))?;
    let response = super::super::build_router(state).oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn invalid_signed_lineage_is_a_typed_refusal_without_dropping_other_tenants() -> TestResult {
    let (_directory, path, snapshots, state) =
        refused_lineage_router(true, false, ReceiptQuerySnapshotConfig::default()).await?;
    insert_refused_lineage(&path)?;
    assert_typed_refusal_keeps_other_tenants(&snapshots, state).await?;
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn invalid_signed_lineage_seen_by_extension_first_is_the_same_typed_refusal() -> TestResult {
    let (_directory, path, snapshots, state) =
        refused_lineage_router(true, false, ReceiptQuerySnapshotConfig::default()).await?;
    insert_refused_lineage(&path)?;
    await_extension_cycle(Arc::clone(&snapshots)).await?;
    assert_typed_refusal_keeps_other_tenants(&snapshots, state).await?;
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn refused_lineage_of_unattributed_receipts_fails_the_snapshot_after_extension() -> TestResult
{
    let (_directory, path, snapshots, state) =
        refused_lineage_router(false, false, ReceiptQuerySnapshotConfig::default()).await?;
    insert_refused_lineage(&path)?;
    await_extension_cycle(Arc::clone(&snapshots)).await?;
    assert_reader_refusal_fails_the_snapshot(&snapshots, state).await
}

const READER_REFUSAL_BODY: &str = "receipt query snapshot failed authentication: capability lineage of cap-bad-signed is refused by the local reader: Conversion error from type Text at index: 10, conflict: capability lineage cap-bad-signed claims signed-token provenance without a signed token";

async fn assert_reader_refusal_fails_the_snapshot(
    snapshots: &ReceiptQuerySnapshots,
    state: TrustServiceState,
) -> TestResult {
    let (status, body) = export(state).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_invalid");
    assert_eq!(body["error"], READER_REFUSAL_BODY);
    assert_eq!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid {
            reason: READER_REFUSAL_BODY
                .trim_start_matches("receipt query snapshot failed authentication: ")
                .into()
        }
    );
    snapshots.shutdown();
    Ok(())
}

async fn pause_extension(snapshots: Arc<ReceiptQuerySnapshots>) -> TestResult {
    tokio::task::spawn_blocking(move || {
        snapshots.pause_extension_for_test(true);
        assert!(snapshots.wait_for_paused_extension_for_test(Duration::from_secs(60)));
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn refused_lineage_shared_with_unattributed_receipts_fails_the_snapshot_when_export_reads_it_first(
) -> TestResult {
    let (_directory, path, snapshots, state) = refused_lineage_router(
        true,
        true,
        ReceiptQuerySnapshotConfig {
            extension_tick: Duration::from_secs(3_600),
            ..ReceiptQuerySnapshotConfig::default()
        },
    )
    .await?;
    pause_extension(Arc::clone(&snapshots)).await?;
    insert_refused_lineage(&path)?;
    assert_reader_refusal_fails_the_snapshot(&snapshots, state).await
}

#[tokio::test]
async fn refused_lineage_shared_with_unattributed_receipts_fails_the_snapshot_after_extension(
) -> TestResult {
    let (_directory, path, snapshots, state) =
        refused_lineage_router(true, true, ReceiptQuerySnapshotConfig::default()).await?;
    insert_refused_lineage(&path)?;
    await_extension_cycle(Arc::clone(&snapshots)).await?;
    assert_reader_refusal_fails_the_snapshot(&snapshots, state).await
}

#[tokio::test]
async fn captured_attribution_tamper_invalidates_before_export_refusal() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let subject = record_signed_lineage(&store, "cap-signed", &Keypair::from_seed(&[45; 32]))?;
    let signer = Keypair::from_seed(&[43; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    for (id, tenant, capability) in [
        ("signed-a", "tenant-a", "cap-signed"),
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
        chio_core::receipt::evidence::EvidenceExportQuery::tenant_scoped("tenant-a")
            .as_receipt_query(None);
    by_subject.agent_subject = Some(subject);
    assert_eq!(snapshots.query_receipts(&by_subject)?.total_count, 1);
    let connection = rusqlite::Connection::open(&path)?;
    let updated = connection.execute(
        "UPDATE capability_lineage SET subject_key = 'tampered-subject' WHERE capability_id = 'cap-signed'",
        [],
    );
    assert_eq!(updated?, 1);
    drop(connection);
    let mut state = metrics_state("snapshot-secret");
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state.config.access = crate::trust_control::caller_credentials::tests::test_access_with_roles(
        "snapshot-secret",
        None,
        &[("tenant-a", "tenant-secret")],
    );
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

/// Signed lineage rows with one tenant-a receipt each, one unrelated tenant-b
/// receipt, a ready snapshot, and a router state with both tenant tokens.
async fn signed_lineage_router(
    capabilities: &[(&str, u64)],
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
    for (index, (capability, _)) in capabilities.iter().enumerate() {
        let seed = u8::try_from(index)?.wrapping_add(50);
        record_signed_lineage(&store, capability, &Keypair::from_seed(&[seed; 32]))?;
    }
    let signer = Keypair::from_seed(&[43; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    for (index, (capability, timestamp)) in capabilities.iter().enumerate() {
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
    state.config.access = crate::trust_control::caller_credentials::tests::test_access_with_roles(
        "snapshot-secret",
        None,
        &[
            ("tenant-a", "tenant-secret"),
            ("tenant-b", "tenant-b-secret"),
        ],
    );
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
            "query": chio_core::receipt::evidence::EvidenceExportQuery::tenant_scoped("tenant-b"),
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
        signed_lineage_router(&[("cap-signed", 100)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET subject_key = CAST(x'ff' AS TEXT) WHERE capability_id = 'cap-signed'")?;
    assert_http_export_invalidates(&snapshots, state).await?;
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn oversized_captured_subject_returns_snapshot_invalid() -> TestResult {
    let (_directory, path, snapshots, state) =
        signed_lineage_router(&[("cap-signed", 100)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET subject_key = 'changed-' || hex(zeroblob(16777216)) WHERE capability_id = 'cap-signed'")?;
    assert_http_export_invalidates(&snapshots, state).await?;
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn earlier_lineage_refusal_does_not_mask_a_later_attribution_change_over_http() -> TestResult
{
    let (_directory, path, snapshots, state) =
        signed_lineage_router(&[("cap-1", 100), ("cap-2", 200)]).await?;
    edit_lineage(
        &path,
        "UPDATE capability_lineage SET signed_capability_json = NULL WHERE capability_id = 'cap-1'",
    )?;
    edit_lineage(&path, "UPDATE capability_lineage SET subject_key = 'changed-subject' WHERE capability_id = 'cap-2'")?;
    assert_http_export_invalidates(&snapshots, state).await?;
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn non_utf8_lineage_issuer_of_unsigned_receipts_returns_snapshot_invalid() -> TestResult {
    let (_directory, path, snapshots, state) =
        signed_lineage_router(&[("cap-signed", 100)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET issuer_key = CAST(x'ff' AS TEXT) WHERE capability_id = 'cap-signed'")?;
    let (status, body) = export(state.clone()).await?;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["code"], "receipt_query_snapshot_invalid");
    assert_eq!(
        body["error"],
        "receipt query snapshot failed authentication: capability lineage of cap-signed is refused by the local reader: invalid utf-8 sequence of 1 bytes from index 0 at index 2"
    );
    assert!(body.get("bundle").is_none(), "{body}");
    assert!(matches!(
        snapshots.status().state,
        ReceiptQuerySnapshotState::Invalid { .. }
    ));
    assert_eq!(
        tenant_b_export_status(state).await?,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    snapshots.shutdown();
    Ok(())
}

#[tokio::test]
async fn oversized_unrelated_lineage_metadata_returns_bounded_refusal() -> TestResult {
    let (_directory, path, snapshots, state) =
        signed_lineage_router(&[("cap-signed", 100)]).await?;
    edit_lineage(&path, "UPDATE capability_lineage SET grants_json = hex(zeroblob(16777216)) WHERE capability_id = 'cap-signed'")?;
    let (status, body) = export(state.clone()).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["code"], "receipt_query_work_budget_exhausted");
    assert!(body.get("bundle").is_none(), "{body}");
    assert_eq!(snapshots.status().state, ReceiptQuerySnapshotState::Ready);
    assert_eq!(tenant_b_export_status(state).await?, StatusCode::OK);
    snapshots.shutdown();
    Ok(())
}
