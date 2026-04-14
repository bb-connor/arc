//! ARC tower Service implementation.

use std::task::{Context, Poll};

use tower_service::Service;

use crate::evaluator::ArcEvaluator;

/// Tower `Service` that evaluates HTTP requests against the ARC kernel.
///
/// For each request, the service:
/// 1. Extracts the caller identity from request headers
/// 2. Evaluates the request against the ARC policy
/// 3. If denied, returns a 403 JSON error response
/// 4. If allowed, forwards to the inner service with receipt ID in response headers
#[derive(Clone)]
pub struct ArcService<S> {
    inner: S,
    evaluator: ArcEvaluator,
}

impl<S> ArcService<S> {
    /// Create a new ARC service wrapping the inner service.
    pub fn new(inner: S, evaluator: ArcEvaluator) -> Self {
        Self { inner, evaluator }
    }
}

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for ArcService<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = http::Response<ResBody>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: http::Request<ReqBody>) -> Self::Future {
        let evaluator = self.evaluator.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let method = req.method().as_str().to_string();
            let path = req.uri().path().to_string();
            let headers = req.headers().clone();

            // Extract caller identity.
            let identity_fn = evaluator.identity_extractor();
            let caller = identity_fn(&headers);

            // Evaluate the request.
            let result = match evaluator.evaluate(&method, &path, caller, &headers, None, 0) {
                Ok(r) => r,
                Err(e) => {
                    if evaluator.is_fail_open() {
                        // Fail-open: pass through to inner service.
                        return inner.call(req).await.map_err(Into::into);
                    }
                    tracing::error!("ARC evaluation failed: {e}");
                    let mut response = http::Response::new(ResBody::default());
                    *response.status_mut() = http::StatusCode::BAD_GATEWAY;
                    return Ok(response);
                }
            };

            // Check verdict.
            if result.verdict.is_denied() {
                let status = if let arc_http_core::Verdict::Deny { http_status, .. } =
                    &result.verdict
                {
                    http::StatusCode::from_u16(*http_status).unwrap_or(http::StatusCode::FORBIDDEN)
                } else {
                    http::StatusCode::FORBIDDEN
                };

                let mut response = http::Response::new(ResBody::default());
                *response.status_mut() = status;
                response.headers_mut().insert(
                    "x-arc-receipt-id",
                    http::HeaderValue::from_str(&result.receipt.id)
                        .unwrap_or_else(|_| http::HeaderValue::from_static("unknown")),
                );
                return Ok(response);
            }

            // Forward to inner service.
            let mut response = inner.call(req).await.map_err(Into::into)?;

            // Attach receipt ID to response.
            if let Ok(val) = http::HeaderValue::from_str(&result.receipt.id) {
                response.headers_mut().insert("x-arc-receipt-id", val);
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::ArcEvaluator;
    use arc_core_types::crypto::Keypair;
    use tower::ServiceExt;

    fn make_service() -> (Keypair, ArcEvaluator) {
        let keypair = Keypair::generate();
        let evaluator = ArcEvaluator::new(keypair.clone(), "test-policy".to_string());
        (keypair, evaluator)
    }

    #[tokio::test]
    async fn service_allows_get() {
        let (_kp, evaluator) = make_service();

        let inner = tower::service_fn(|_req: http::Request<()>| async {
            Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(
                (),
            ))
        });

        let mut service = ArcService::new(inner, evaluator);

        let req = http::Request::builder()
            .method("GET")
            .uri("/pets")
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

    #[tokio::test]
    async fn service_denies_post_without_capability() {
        let (_kp, evaluator) = make_service();

        let inner = tower::service_fn(|_req: http::Request<()>| async {
            panic!("inner should not be called for denied requests");
            #[allow(unreachable_code)]
            Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(
                (),
            ))
        });

        let mut service = ArcService::new(inner, evaluator);

        let req = http::Request::builder()
            .method("POST")
            .uri("/pets")
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

    #[tokio::test]
    async fn service_allows_post_with_capability() {
        let (_kp, evaluator) = make_service();

        let inner = tower::service_fn(|_req: http::Request<()>| async {
            Ok::<http::Response<()>, Box<dyn std::error::Error + Send + Sync>>(http::Response::new(
                (),
            ))
        });

        let mut service = ArcService::new(inner, evaluator);

        let req = http::Request::builder()
            .method("POST")
            .uri("/pets")
            .header("x-arc-capability", "cap-token-123")
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
}
