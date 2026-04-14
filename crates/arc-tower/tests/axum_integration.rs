//! Integration test: ARC tower middleware with Axum.
//!
//! Verifies that the ArcLayer correctly integrates with Axum's router,
//! producing signed receipts for allowed requests and denying requests
//! without capability tokens.

use arc_core_types::crypto::Keypair;
use arc_tower::{ArcEvaluator, ArcService};
use axum::{body::Body, routing::get, routing::post, Router};
use http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;
use tower_layer::Layer;

/// A thin Layer wrapper that adapts ArcService's error type to Infallible
/// for Axum compatibility. Axum requires layers with Error: Into<Infallible>.
#[derive(Clone)]
struct AxumArcLayer {
    evaluator: ArcEvaluator,
}

impl AxumArcLayer {
    fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            evaluator: ArcEvaluator::new(keypair, policy_hash),
        }
    }
}

impl<S> Layer<S> for AxumArcLayer {
    type Service = AxumArcService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AxumArcService {
            inner: ArcService::new(inner, self.evaluator.clone()),
        }
    }
}

/// Wrapper service that maps ArcService errors to Infallible for Axum.
#[derive(Clone)]
struct AxumArcService<S> {
    inner: ArcService<S>,
}

impl<S, ReqBody> tower_service::Service<Request<ReqBody>> for AxumArcService<S>
where
    S: tower_service::Service<Request<ReqBody>, Response = http::Response<Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ReqBody: Send + 'static,
{
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        // ArcService always reports ready when inner is ready.
        match self.inner.poll_ready(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(_)) => {
                // Map errors to a 502 response internally; never return Infallible error.
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let fut = tower_service::Service::call(&mut self.inner, req);
        Box::pin(async move {
            match fut.await {
                Ok(resp) => Ok(resp),
                Err(_) => {
                    // Return a 502 error response instead of propagating.
                    let resp = http::Response::builder()
                        .status(http::StatusCode::BAD_GATEWAY)
                        .body(Body::from("ARC evaluation error"))
                        .unwrap_or_else(|_| http::Response::new(Body::from("internal error")));
                    Ok(resp)
                }
            }
        })
    }
}

fn build_app(keypair: Keypair) -> Router {
    let layer = AxumArcLayer::new(keypair, "test-policy-axum".to_string());
    Router::new()
        .route("/pets", get(list_pets))
        .route("/pets", post(create_pet))
        .route("/pets/{pet_id}", get(get_pet))
        .layer(layer)
}

async fn list_pets() -> &'static str {
    r#"[{"id":1,"name":"Fido"}]"#
}

async fn create_pet() -> (http::StatusCode, &'static str) {
    (http::StatusCode::CREATED, r#"{"id":2,"name":"Rex"}"#)
}

async fn get_pet(axum::extract::Path(pet_id): axum::extract::Path<String>) -> String {
    format!(r#"{{"id":{},"name":"Buddy"}}"#, pet_id)
}

#[tokio::test]
async fn axum_get_allowed_with_receipt() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("GET")
        .uri("/pets")
        .body(Body::empty())
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);

    // Verify receipt ID header is present.
    let receipt_id = resp
        .headers()
        .get("x-arc-receipt-id")
        .unwrap_or_else(|| panic!("missing x-arc-receipt-id header"));
    assert!(!receipt_id.is_empty());

    // Verify response body.
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body collect failed: {e}"))
        .to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap_or_else(|e| panic!("utf8 failed: {e}"));
    assert!(body_str.contains("Fido"));
}

#[tokio::test]
async fn axum_post_denied_without_capability() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"Rex"}"#))
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
    assert!(resp.headers().contains_key("x-arc-receipt-id"));
}

#[tokio::test]
async fn axum_post_allowed_with_capability() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("POST")
        .uri("/pets")
        .header("content-type", "application/json")
        .header("x-arc-capability", "cap-token-axum-test")
        .body(Body::from(r#"{"name":"Rex"}"#))
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::CREATED);
    assert!(resp.headers().contains_key("x-arc-receipt-id"));
}

#[tokio::test]
async fn axum_path_parameter_with_receipt() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("GET")
        .uri("/pets/42")
        .body(Body::empty())
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    assert!(resp.headers().contains_key("x-arc-receipt-id"));

    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|e| panic!("body collect failed: {e}"))
        .to_bytes();
    let body_str = std::str::from_utf8(&body).unwrap_or_else(|e| panic!("utf8 failed: {e}"));
    assert!(body_str.contains("42"));
}

#[tokio::test]
async fn axum_bearer_identity_in_receipt() {
    let keypair = Keypair::generate();
    let app = build_app(keypair);

    let req = Request::builder()
        .method("GET")
        .uri("/pets")
        .header("authorization", "Bearer secret-token-123")
        .body(Body::empty())
        .unwrap_or_else(|e| panic!("build request failed: {e}"));

    let resp = app
        .oneshot(req)
        .await
        .unwrap_or_else(|e| panic!("oneshot failed: {e}"));

    assert_eq!(resp.status(), http::StatusCode::OK);
    assert!(resp.headers().contains_key("x-arc-receipt-id"));
}
