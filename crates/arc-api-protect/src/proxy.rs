//! Reverse proxy server that evaluates requests and forwards to upstream.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use tokio::sync::Mutex;
use tracing::{info, warn};

use arc_core_types::crypto::Keypair;
use arc_http_core::{HttpMethod, HttpReceipt};
use arc_openapi::DefaultPolicy;

use crate::error::ProtectError;
use crate::evaluator::{RequestEvaluator, RouteEntry};

/// Configuration for the protect proxy.
#[derive(Debug, Clone)]
pub struct ProtectConfig {
    /// Upstream URL to proxy to.
    pub upstream: String,
    /// OpenAPI spec content (YAML or JSON).
    pub spec_content: String,
    /// Address to listen on (e.g., "127.0.0.1:9090").
    pub listen_addr: String,
    /// Optional SQLite path for receipt persistence.
    pub receipt_db: Option<String>,
}

/// Stored receipts for inspection and querying.
struct ReceiptLog {
    receipts: Vec<HttpReceipt>,
}

/// Shared proxy state.
struct ProxyState {
    evaluator: RequestEvaluator,
    upstream: String,
    http_client: reqwest::Client,
    receipt_log: Mutex<ReceiptLog>,
}

/// The protect proxy.
pub struct ProtectProxy {
    config: ProtectConfig,
}

impl ProtectProxy {
    pub fn new(config: ProtectConfig) -> Self {
        Self { config }
    }

    /// Build the route table from the OpenAPI spec.
    /// Parses the spec directly to preserve path and method information.
    fn build_routes(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        let spec = arc_openapi::OpenApiSpec::parse(spec_content)?;
        let mut routes = Vec::new();

        for (path, path_item) in &spec.paths {
            for (method_str, operation) in &path_item.operations {
                let method = match method_str.as_str() {
                    "GET" => HttpMethod::Get,
                    "POST" => HttpMethod::Post,
                    "PUT" => HttpMethod::Put,
                    "PATCH" => HttpMethod::Patch,
                    "DELETE" => HttpMethod::Delete,
                    "HEAD" => HttpMethod::Head,
                    "OPTIONS" => HttpMethod::Options,
                    _ => continue,
                };

                let policy = DefaultPolicy::for_method(method);
                routes.push(RouteEntry {
                    pattern: path.clone(),
                    method,
                    operation_id: operation.operation_id.clone(),
                    policy,
                });
            }
        }

        Ok(routes)
    }

    /// Start the proxy server. This blocks until the server shuts down.
    pub async fn run(self) -> Result<(), ProtectError> {
        let routes = Self::build_routes(&self.config.spec_content)?;
        let route_count = routes.len();

        let keypair = Keypair::generate();
        let policy_hash = arc_core_types::sha256_hex(self.config.spec_content.as_bytes());

        let evaluator = RequestEvaluator::new(routes, keypair, policy_hash);

        let state = Arc::new(ProxyState {
            evaluator,
            upstream: self.config.upstream.clone(),
            http_client: reqwest::Client::new(),
            receipt_log: Mutex::new(ReceiptLog {
                receipts: Vec::new(),
            }),
        });

        let app = Router::new()
            .route("/{*path}", any(proxy_handler))
            .route("/", any(proxy_handler))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| ProtectError::Config(format!("cannot bind {}: {e}", self.config.listen_addr)))?;

        info!(
            "arc api protect: proxying {} routes to {} on {}",
            route_count, self.config.upstream, self.config.listen_addr
        );

        axum::serve(listener, app)
            .await
            .map_err(ProtectError::Io)?;

        Ok(())
    }

    /// Build routes from spec content for testing.
    pub fn routes_from_spec(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        Self::build_routes(spec_content)
    }
}

/// Axum handler that evaluates the request and proxies to upstream.
async fn proxy_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let method = match request.method().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        _ => {
            return (StatusCode::METHOD_NOT_ALLOWED, "unsupported method").into_response();
        }
    };

    let path = request.uri().path().to_string();

    // Extract relevant headers.
    let mut headers = HashMap::new();
    for (name, value) in request.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_string(), v.to_string());
        }
    }

    // Read body for hashing.
    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            warn!("failed to read request body: {e}");
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };
    let body_length = body_bytes.len() as u64;
    let body_hash = if body_bytes.is_empty() {
        None
    } else {
        Some(arc_core_types::sha256_hex(&body_bytes))
    };

    // Evaluate.
    let result = match state.evaluator.evaluate(
        method,
        &path,
        &headers,
        body_hash,
        body_length,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("evaluation error: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "evaluation error").into_response();
        }
    };

    // Store receipt.
    {
        let mut log = state.receipt_log.lock().await;
        log.receipts.push(result.receipt.clone());
    }

    // If denied, return structured 403.
    if result.verdict.is_denied() {
        let error_body = serde_json::json!({
            "error": "arc_access_denied",
            "message": match &result.verdict {
                arc_http_core::Verdict::Deny { reason, .. } => reason.clone(),
                _ => "access denied".to_string(),
            },
            "receipt_id": result.receipt.id,
            "suggestion": "provide a valid capability token in the X-Arc-Capability header",
        });
        return (
            StatusCode::FORBIDDEN,
            [("content-type", "application/json")],
            serde_json::to_string(&error_body).unwrap_or_default(),
        )
            .into_response();
    }

    // Proxy to upstream.
    let upstream_url = format!(
        "{}{}",
        state.upstream.trim_end_matches('/'),
        &path
    );

    let mut upstream_req = state.http_client.request(
        match method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        },
        &upstream_url,
    );

    // Forward selected headers.
    for (k, v) in &headers {
        let lower = k.to_lowercase();
        if lower == "content-type" || lower == "accept" || lower == "user-agent" {
            upstream_req = upstream_req.header(k.as_str(), v.as_str());
        }
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    match upstream_req.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);

            let mut response_builder = Response::builder().status(status);

            // Forward response headers.
            for (name, value) in resp.headers() {
                response_builder = response_builder.header(name.as_str(), value.as_bytes());
            }

            // Add receipt ID header.
            response_builder = response_builder.header("X-Arc-Receipt-Id", &result.receipt.id);

            match resp.bytes().await {
                Ok(body) => response_builder
                    .body(Body::from(body))
                    .unwrap_or_else(|_| {
                        (StatusCode::BAD_GATEWAY, "bad gateway").into_response()
                    }),
                Err(_) => (StatusCode::BAD_GATEWAY, "failed to read upstream response")
                    .into_response(),
            }
        }
        Err(e) => {
            warn!("upstream error: {e}");
            (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_openapi::PolicyDecision;

    const PETSTORE_YAML: &str = r#"
openapi: "3.0.0"
info:
  title: Petstore
  version: "1.0.0"
paths:
  /pets:
    get:
      operationId: listPets
      summary: List all pets
      responses:
        "200":
          description: A list of pets
    post:
      operationId: createPet
      summary: Create a pet
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        "201":
          description: Created
  /pets/{petId}:
    get:
      operationId: showPetById
      summary: Info for a specific pet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: A pet
    delete:
      operationId: deletePet
      summary: Delete a pet
      parameters:
        - name: petId
          in: path
          required: true
          schema:
            type: string
      responses:
        "204":
          description: Deleted
"#;

    #[test]
    fn build_routes_from_petstore() {
        let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).unwrap();
        assert!(!routes.is_empty());

        // Should have GET and POST for /pets, GET and DELETE for /pets/{petId}
        let get_pets = routes.iter().find(|r| {
            r.method == HttpMethod::Get && r.pattern.contains("/pets")
                && !r.pattern.contains("{petId}")
        });
        assert!(get_pets.is_some());

        let post_pets = routes.iter().find(|r| r.method == HttpMethod::Post);
        assert!(post_pets.is_some());
        assert_eq!(post_pets.map(|r| r.policy.clone()), Some(PolicyDecision::DenyByDefault));

        let delete_pet = routes.iter().find(|r| r.method == HttpMethod::Delete);
        assert!(delete_pet.is_some());
    }

    #[test]
    fn get_routes_allowed_by_default() {
        let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).unwrap();
        let get_routes: Vec<_> = routes.iter().filter(|r| r.method == HttpMethod::Get).collect();
        for route in get_routes {
            assert_eq!(route.policy, PolicyDecision::SessionAllow);
        }
    }

    #[test]
    fn side_effect_routes_denied_by_default() {
        let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).unwrap();
        let mut_routes: Vec<_> = routes
            .iter()
            .filter(|r| r.method.requires_capability())
            .collect();
        for route in mut_routes {
            assert_eq!(route.policy, PolicyDecision::DenyByDefault);
        }
    }
}
