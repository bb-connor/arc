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

async fn post_lineage(
    body: Vec<u8>,
    validated: bool,
) -> Result<(StatusCode, String), Box<dyn std::error::Error>> {
    let mut router = Router::new().route(
        LINEAGE_RECORD_PATH,
        post(|SignedJson(value): SignedJson<serde_json::Value>| async move { Json(value) }),
    );
    if validated {
        router = router.route_layer(axum::middleware::from_fn(
            crate::trust_control::json_ingress::validate,
        ));
    }
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(LINEAGE_RECORD_PATH)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))?,
        )
        .await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok((status, String::from_utf8(bytes.to_vec())?))
}

#[tokio::test]
async fn signed_json_bounds_the_body_with_and_without_the_validating_layer(
) -> Result<(), Box<dyn std::error::Error>> {
    let bound = 1024 * 1024;
    let honest = br#"{"id":"r"}"#;
    let mut at_bound = honest.to_vec();
    at_bound.resize(bound, b' ');
    let mut over_bound = at_bound.clone();
    over_bound.push(b' ');
    for validated in [false, true] {
        let (status, body) = post_lineage(at_bound.clone(), validated).await?;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, r#"{"id":"r"}"#),
            "{validated}"
        );
        let (status, body) = post_lineage(over_bound.clone(), validated).await?;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{validated}");
        assert!(
            body.contains("JSON request body exceeds its limit"),
            "{validated}: {body}"
        );
        let (status, _) = post_lineage(br#"{"id":"r","id":"s"}"#.to_vec(), validated).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{validated}");
    }
    Ok(())
}
