//! Integration test: ARC tower middleware with Tonic gRPC.
//!
//! Verifies that the ArcLayer integrates with Tonic's tower-based architecture.
//! Since Tonic services are tower services, the ARC middleware works
//! transparently as a layer. This test exercises the layer at the tower level
//! using raw HTTP/2-style requests as Tonic would send them.

use arc_core_types::crypto::Keypair;
use arc_tower::ArcLayer;
use http::Request;
use tower::{Layer, Service, ServiceExt};

/// Simulate a gRPC unary call (POST with application/grpc content type).
/// gRPC calls are always POST, so they require a capability token.
#[tokio::test]
async fn grpc_post_denied_without_capability() {
    let keypair = Keypair::generate();
    let layer = ArcLayer::new(keypair, "test-policy-grpc".to_string());

    let inner = tower::service_fn(|_req: Request<()>| async {
        panic!("inner should not be called");
        #[allow(unreachable_code)]
        Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
    });

    let mut service = layer.layer(inner);

    // gRPC requests are always POST.
    let req = Request::builder()
        .method("POST")
        .uri("http://localhost/my.service.MyService/GetItem")
        .header("content-type", "application/grpc")
        .body(())
        .unwrap_or_else(|e| panic!("build failed: {e}"));

    let resp: http::Response<()> = service
        .ready()
        .await
        .unwrap_or_else(|e| panic!("ready failed: {e}"))
        .call(req)
        .await
        .unwrap_or_else(|e| panic!("call failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    assert!(resp.headers().contains_key("x-arc-receipt-id"));
}

/// gRPC call with capability token should be allowed.
#[tokio::test]
async fn grpc_post_allowed_with_capability() {
    let keypair = Keypair::generate();
    let layer = ArcLayer::new(keypair, "test-policy-grpc".to_string());

    let inner = tower::service_fn(|_req: Request<()>| async {
        let mut resp = http::Response::new(());
        resp.headers_mut().insert(
            "content-type",
            http::HeaderValue::from_static("application/grpc"),
        );
        Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(resp)
    });

    let mut service = layer.layer(inner);

    let req = Request::builder()
        .method("POST")
        .uri("http://localhost/my.service.MyService/CreateItem")
        .header("content-type", "application/grpc")
        .header("x-arc-capability", "grpc-cap-token")
        .body(())
        .unwrap_or_else(|e| panic!("build failed: {e}"));

    let resp: http::Response<()> = service
        .ready()
        .await
        .unwrap_or_else(|e| panic!("ready failed: {e}"))
        .call(req)
        .await
        .unwrap_or_else(|e| panic!("call failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    assert!(resp.headers().contains_key("x-arc-receipt-id"));
}

/// Verify that the receipt ID is a valid UUIDv7 format.
#[tokio::test]
async fn grpc_receipt_id_format() {
    let keypair = Keypair::generate();
    let layer = ArcLayer::new(keypair, "test-policy-grpc".to_string());

    let inner = tower::service_fn(|_req: Request<()>| async {
        Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
    });

    let mut service = layer.layer(inner);

    let req = Request::builder()
        .method("POST")
        .uri("http://localhost/my.service.MyService/ListItems")
        .header("content-type", "application/grpc")
        .header("x-arc-capability", "grpc-cap-token")
        .body(())
        .unwrap_or_else(|e| panic!("build failed: {e}"));

    let resp: http::Response<()> = service
        .ready()
        .await
        .unwrap_or_else(|e| panic!("ready failed: {e}"))
        .call(req)
        .await
        .unwrap_or_else(|e| panic!("call failed: {e}"));

    let receipt_id = resp
        .headers()
        .get("x-arc-receipt-id")
        .unwrap_or_else(|| panic!("missing receipt id"))
        .to_str()
        .unwrap_or_else(|e| panic!("invalid header value: {e}"));

    // UUIDv7 format: 8-4-4-4-12 hex chars.
    assert_eq!(receipt_id.len(), 36);
    assert_eq!(receipt_id.chars().filter(|c| *c == '-').count(), 4);
}

/// gRPC call with bearer token for identity extraction.
#[tokio::test]
async fn grpc_bearer_identity() {
    let keypair = Keypair::generate();
    let layer = ArcLayer::new(keypair, "test-policy-grpc".to_string());

    let inner = tower::service_fn(|_req: Request<()>| async {
        Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(()))
    });

    let mut service = layer.layer(inner);

    let req = Request::builder()
        .method("POST")
        .uri("http://localhost/my.service.MyService/GetItem")
        .header("content-type", "application/grpc")
        .header("authorization", "Bearer grpc-secret-token")
        .header("x-arc-capability", "grpc-cap")
        .body(())
        .unwrap_or_else(|e| panic!("build failed: {e}"));

    let resp: http::Response<()> = service
        .ready()
        .await
        .unwrap_or_else(|e| panic!("ready failed: {e}"))
        .call(req)
        .await
        .unwrap_or_else(|e| panic!("call failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    assert!(resp.headers().contains_key("x-arc-receipt-id"));
}
