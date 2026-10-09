//! Receipt routes use the service's one store. The configured path cannot be
//! opened, so a handler that still opened its own store (starting a writer
//! and its full seed per request) would fail these requests.
use super::*;
use axum::body::Body;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::Request;
use chio_core::crypto::Keypair;
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
use tower::ServiceExt;

fn signed_receipt(keypair: &Keypair) -> Result<ChioReceipt, Box<dyn std::error::Error>> {
    Ok(ChioReceipt::sign(
        ChioReceiptBody {
            id: "shared-store-receipt".to_string(),
            timestamp: 100,
            capability_id: "shared-store-capability".to_string(),
            tool_server: "shared-store-server".to_string(),
            tool_name: "shared-store-tool".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({ "probe": true }))?,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "shared-store-content".to_string(),
            policy_hash: "shared-store-policy".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )?)
}

async fn body_text(
    response: axum::response::Response,
) -> Result<String, Box<dyn std::error::Error>> {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok(String::from_utf8(bytes.to_vec())?)
}

#[tokio::test]
async fn receipt_routes_share_the_service_store_and_never_open_the_configured_path(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let store = Arc::new(SqliteReceiptStore::open(
        directory.path().join("receipts.sqlite3"),
    )?);
    let unopenable = directory.path().join("absent").join("receipts.sqlite3");
    let mut state = metrics_state("service-secret");
    state.config.receipt_db_path = Some(unopenable.clone());
    state.receipt_store = Some(Arc::clone(&store));
    let router = super::super::build_router(state);

    let receipt = signed_receipt(&Keypair::generate())?;
    let append = Request::builder()
        .method("POST")
        .uri(TOOL_RECEIPTS_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer service-secret")
        .body(Body::from(serde_json::to_vec(&receipt)?))?;
    let response = router.clone().oneshot(append).await?;
    let status = response.status();
    assert_eq!(status, StatusCode::OK, "{}", body_text(response).await?);
    assert_eq!(
        store
            .load_chio_receipt(&receipt.id)?
            .map(|stored| stored.id),
        Some(receipt.id.clone())
    );

    let reads = [
        format!("{TOOL_RECEIPTS_PATH}?receiptId={}", receipt.id),
        TOOL_RECEIPTS_PATH.to_string(),
        RECEIPT_QUERY_PATH.to_string(),
        CHILD_RECEIPTS_PATH.to_string(),
        RECEIPT_ANALYTICS_PATH.to_string(),
    ];
    for uri in reads {
        let request = Request::builder()
            .uri(&uri)
            .header(AUTHORIZATION, "Bearer service-secret")
            .body(Body::empty())?;
        let response = router.clone().oneshot(request).await?;
        let status = response.status();
        let body = body_text(response).await?;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        if uri.starts_with(TOOL_RECEIPTS_PATH) || uri == RECEIPT_QUERY_PATH {
            assert!(body.contains(&receipt.id), "{uri}: {body}");
        }
    }
    assert!(!unopenable.exists());
    assert!(!directory.path().join("absent").exists());
    Ok(())
}
