//! The six tenant-scoped routes, through the real router: a tenant credential
//! reads only its own tenant and is refused every other tenant's data.
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

const ADMIN: &str = "Bearer tenant-routes-admin";
const TENANT_A: &str = "Bearer tenant-a-secret";

struct Fixture {
    _directory: tempfile::TempDir,
    state: TrustServiceState,
    snapshots: Arc<ReceiptQuerySnapshots>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.snapshots.shutdown();
    }
}

async fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let path = directory.path().join("receipts.db");
    let store = Arc::new(SqliteReceiptStore::open(&path)?);
    let signer = Keypair::from_seed(&[61; 32]);
    let template = super::receipt_store_ownership_tests::signed_receipt(&signer)?.body();
    for (id, tenant) in [
        ("receipt-tenant-a", "tenant-a"),
        ("receipt-tenant-b", "tenant-b"),
    ] {
        let mut body = template.clone();
        body.id = id.into();
        body.tenant_id = Some(tenant.into());
        store.append_chio_receipt(&ChioReceipt::sign(body, &signer)?)?;
    }
    let snapshots = Arc::new(ReceiptQuerySnapshots::start(
        Arc::clone(&store),
        ReceiptQuerySnapshotConfig::default(),
    )?);
    let waiting = Arc::clone(&snapshots);
    let status = tokio::task::spawn_blocking(move || {
        waiting.wait_for_recovery(Duration::from_secs(600), |status| {
            !matches!(
                status.state,
                ReceiptQuerySnapshotState::WaitingForWriterSeed
                    | ReceiptQuerySnapshotState::Building { .. }
            )
        })
    })
    .await?;
    assert_eq!(status.state, ReceiptQuerySnapshotState::Ready, "{status:?}");
    let mut state = metrics_state("tenant-routes-admin");
    state.config.receipt_db_path = Some(path);
    state.receipt_store = Some(store);
    state.receipt_query_snapshots = Some(Arc::clone(&snapshots));
    state.config.access = crate::trust_control::caller_credentials::tests::test_access_with_roles(
        "tenant-routes-admin",
        None,
        &[("tenant-a", "tenant-a-secret")],
    );
    Ok(Fixture {
        _directory: directory,
        state,
        snapshots,
    })
}

async fn send(
    state: &TrustServiceState,
    method: &str,
    uri: &str,
    bearer: &str,
    body: Option<Value>,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, bearer);
    let body = match body {
        Some(body) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&body)?)
        }
        None => Body::empty(),
    };
    let response = super::super::build_router(state.clone())
        .oneshot(builder.body(body)?)
        .await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024).await?;
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "error": String::from_utf8_lossy(&bytes) }));
    Ok((status, body))
}

/// The tenants of the returned receipts, sorted with duplicates kept.
fn receipt_tenants(body: &Value) -> Vec<String> {
    let mut tenants: Vec<String> = body["receipts"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|receipt| {
            receipt
                .get("receipt")
                .unwrap_or(receipt)
                .get("tenant_id")
                .or_else(|| receipt.get("tenantId"))
                .and_then(Value::as_str)
                .unwrap_or("untenanted")
                .to_string()
        })
        .collect();
    tenants.sort();
    tenants
}

#[tokio::test]
async fn tenant_credential_reads_only_its_tenant_on_receipt_query_and_tool_list() -> TestResult {
    let fixture = fixture().await?;
    for uri in ["/v1/receipts/query", TOOL_RECEIPTS_PATH] {
        let (status, body) = send(&fixture.state, "GET", uri, ADMIN, None).await?;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(
            receipt_tenants(&body),
            ["tenant-a", "tenant-b"],
            "{uri}: {body}"
        );
        let (status, body) = send(&fixture.state, "GET", uri, TENANT_A, None).await?;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(receipt_tenants(&body), ["tenant-a"], "{uri}: {body}");
    }
    let (status, body) = send(
        &fixture.state,
        "GET",
        &format!("{TOOL_RECEIPTS_PATH}?receiptId=any-receipt"),
        TENANT_A,
        None,
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"],
        "receipt point-load by id requires a deployment credential"
    );
    Ok(())
}

#[tokio::test]
async fn tenant_credential_reads_only_its_tenant_on_agent_receipts() -> TestResult {
    let fixture = fixture().await?;
    let subject =
        super::receipt_store_ownership_tests::signed_receipt(&Keypair::from_seed(&[61; 32]))?
            .body()
            .kernel_key
            .to_hex();
    let uri = AGENT_RECEIPTS_PATH.replace("{subject_key}", &subject);
    let (status, admin) = send(&fixture.state, "GET", &uri, ADMIN, None).await?;
    assert_eq!(status, StatusCode::OK, "{admin}");
    let (status, tenant) = send(&fixture.state, "GET", &uri, TENANT_A, None).await?;
    assert_eq!(status, StatusCode::OK, "{tenant}");
    let tenant_tenants = receipt_tenants(&tenant);
    assert!(
        tenant_tenants.iter().all(|tenant| tenant == "tenant-a"),
        "tenant-a read another tenant: {tenant}"
    );
    assert!(
        receipt_tenants(&admin).len() >= tenant_tenants.len(),
        "{admin}"
    );
    Ok(())
}

#[tokio::test]
async fn tenant_credential_is_refused_child_receipts() -> TestResult {
    let fixture = fixture().await?;
    let (status, body) = send(&fixture.state, "GET", CHILD_RECEIPTS_PATH, TENANT_A, None).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"],
        "tenant credential cannot list child receipts until child receipts carry tenant attribution"
    );
    Ok(())
}

#[tokio::test]
async fn tenant_credential_cannot_export_another_tenants_evidence() -> TestResult {
    let fixture = fixture().await?;
    let (status, body) = send(
        &fixture.state,
        "POST",
        EVIDENCE_EXPORT_PATH,
        TENANT_A,
        Some(json!({
            "query": chio_kernel::evidence_export::EvidenceExportQuery::tenant_scoped("tenant-b"),
            "requireProofs": false,
        })),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"],
        "tenant credential cannot export evidence for another tenant"
    );
    Ok(())
}

#[tokio::test]
async fn tenant_credential_cannot_read_another_tenants_credit_limit() -> TestResult {
    let fixture = fixture().await?;
    let (status, body) = send(
        &fixture.state,
        "POST",
        FISCAL_MARKETPLACE_CREDIT_LIMIT_PATH,
        TENANT_A,
        Some(json!({ "tenant_id": "tenant-b", "currency": "USD" })),
    )
    .await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"],
        "tenant credential cannot request another tenant's credit limit"
    );
    Ok(())
}

#[tokio::test]
async fn tenant_credential_is_refused_deployment_only_report_routes() -> TestResult {
    let fixture = fixture().await?;
    let (status, body) = send(&fixture.state, "GET", OPERATOR_REPORT_PATH, TENANT_A, None).await?;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"],
        "tenant credential cannot use a deployment-only route"
    );
    Ok(())
}
