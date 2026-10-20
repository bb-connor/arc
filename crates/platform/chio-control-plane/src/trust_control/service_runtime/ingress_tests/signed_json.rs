use super::*;
use crate::trust_control::json_ingress::SignedJson;
use axum::routing::post;

async fn post_body(path: &str, body: &str) -> Result<StatusCode, Box<dyn std::error::Error>> {
    let router = Router::new()
        .route(
            TOOL_RECEIPTS_PATH,
            post(|SignedJson(value): SignedJson<serde_json::Value>| async move { Json(value) }),
        )
        .route(
            "/unsigned",
            post(|SignedJson(value): SignedJson<serde_json::Value>| async move { Json(value) }),
        );
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    Ok(response.status())
}

#[tokio::test]
async fn signed_json_refuses_duplicate_keys_at_every_depth(
) -> Result<(), Box<dyn std::error::Error>> {
    let honest = r#"{"id":"r","metadata":{"surface":{"lane":"a"}}}"#;
    assert_eq!(post_body(TOOL_RECEIPTS_PATH, honest).await?, StatusCode::OK);
    for duplicate in [
        r#"{"id":"r","id":"s","metadata":{"surface":{"lane":"a"}}}"#,
        r#"{"id":"r","metadata":{"surface":{"lane":"a"},"surface":{"lane":"b"}}}"#,
        r#"{"id":"r","metadata":{"surface":{"lane":"a","lane":"b"}}}"#,
    ] {
        assert_eq!(
            post_body(TOOL_RECEIPTS_PATH, duplicate).await?,
            StatusCode::BAD_REQUEST,
            "{duplicate}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn signed_json_refuses_a_route_without_a_signed_contract(
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_body("/unsigned", r#"{"id":"r"}"#).await?,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    Ok(())
}
