//! Reverse proxy server that evaluates requests and forwards to upstream.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post};
use axum::Router;
use rusqlite::{params, Connection};
use tokio::sync::Mutex;
use tracing::{info, warn};

use arc_core_types::crypto::Keypair;
use arc_http_core::{
    ArcHttpRequest, EvaluateResponse, HealthResponse, HttpMethod, HttpReceipt, SidecarStatus,
    Verdict, VerifyReceiptResponse,
};
use arc_openapi::{ArcExtensions, DefaultPolicy};

use crate::error::ProtectError;
use crate::evaluator::{RequestEvaluator, RouteEntry};
use crate::spec_discovery::{discover_spec, load_spec_from_file};

/// Configuration for the protect proxy.
#[derive(Debug, Clone)]
pub struct ProtectConfig {
    /// Upstream URL to proxy to.
    pub upstream: String,
    /// Optional in-memory OpenAPI spec content (YAML or JSON).
    pub spec_content: Option<String>,
    /// Optional OpenAPI spec path. When omitted, the proxy auto-discovers the spec.
    pub spec_path: Option<String>,
    /// Address to listen on (e.g., "127.0.0.1:9090").
    pub listen_addr: String,
    /// Optional SQLite path for receipt persistence.
    pub receipt_db: Option<String>,
}

/// Stored receipts for inspection and querying.
struct ReceiptLog {
    receipts: Vec<HttpReceipt>,
}

struct SqliteReceiptStore {
    connection: Connection,
}

impl SqliteReceiptStore {
    fn open(path: &str) -> Result<Self, ProtectError> {
        let connection = Connection::open(path)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        connection
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS http_receipts (
                    id TEXT PRIMARY KEY,
                    receipt_json TEXT NOT NULL
                );
                ",
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(Self { connection })
    }

    fn load_receipts(&self) -> Result<Vec<HttpReceipt>, ProtectError> {
        let mut statement = self
            .connection
            .prepare("SELECT receipt_json FROM http_receipts ORDER BY rowid ASC")
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;

        let mut receipts = Vec::new();
        for row in rows {
            let receipt_json =
                row.map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            let receipt: HttpReceipt = serde_json::from_str(&receipt_json)
                .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn append(&mut self, receipt: &HttpReceipt) -> Result<(), ProtectError> {
        let receipt_json = serde_json::to_string(receipt)
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        self.connection
            .execute(
                "INSERT OR REPLACE INTO http_receipts (id, receipt_json) VALUES (?1, ?2)",
                params![receipt.id, receipt_json],
            )
            .map_err(|error| ProtectError::ReceiptStore(error.to_string()))?;
        Ok(())
    }
}

/// Shared proxy state.
struct ProxyState {
    evaluator: RequestEvaluator,
    upstream: String,
    http_client: reqwest::Client,
    receipt_log: Mutex<ReceiptLog>,
    receipt_store: Option<Mutex<SqliteReceiptStore>>,
}

/// The protect proxy.
pub struct ProtectProxy {
    config: ProtectConfig,
}

impl ProtectProxy {
    pub fn new(config: ProtectConfig) -> Self {
        Self { config }
    }

    async fn load_spec_content(&self) -> Result<String, ProtectError> {
        if let Some(spec_content) = &self.config.spec_content {
            return Ok(spec_content.clone());
        }
        if let Some(spec_path) = &self.config.spec_path {
            return load_spec_from_file(spec_path);
        }
        discover_spec(&self.config.upstream).await
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

                let extensions = ArcExtensions::from_operation(&operation.raw);
                let policy = DefaultPolicy::for_method_with_extensions(method, &extensions);
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
        let spec_content = self.load_spec_content().await?;
        let routes = Self::build_routes(&spec_content)?;
        let route_count = routes.len();

        let keypair = Keypair::generate();
        let policy_hash = arc_core_types::sha256_hex(spec_content.as_bytes());

        let evaluator = RequestEvaluator::new(routes, keypair, policy_hash);

        let (receipt_log, receipt_store) = if let Some(path) = &self.config.receipt_db {
            let store = SqliteReceiptStore::open(path)?;
            let receipts = store.load_receipts()?;
            (ReceiptLog { receipts }, Some(Mutex::new(store)))
        } else {
            (
                ReceiptLog {
                    receipts: Vec::new(),
                },
                None,
            )
        };

        let state = Arc::new(ProxyState {
            evaluator,
            upstream: self.config.upstream.clone(),
            http_client: reqwest::Client::new(),
            receipt_log: Mutex::new(receipt_log),
            receipt_store,
        });

        let app = build_app(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind(&self.config.listen_addr)
            .await
            .map_err(|e| {
                ProtectError::Config(format!("cannot bind {}: {e}", self.config.listen_addr))
            })?;

        info!(
            "arc api protect: proxying {} routes to {} on {}",
            route_count, self.config.upstream, self.config.listen_addr
        );

        axum::serve(listener, app).await.map_err(ProtectError::Io)?;

        Ok(())
    }

    /// Build routes from spec content for testing.
    pub fn routes_from_spec(spec_content: &str) -> Result<Vec<RouteEntry>, ProtectError> {
        Self::build_routes(spec_content)
    }
}

fn build_app(state: Arc<ProxyState>) -> Router {
    Router::new()
        .route("/arc/evaluate", post(sidecar_evaluate_handler))
        .route("/arc/verify", post(sidecar_verify_handler))
        .route("/arc/health", get(sidecar_health_handler))
        .route("/{*path}", any(proxy_handler))
        .route("/", any(proxy_handler))
        .with_state(state)
}

/// Axum handler that evaluates the request and proxies to upstream.
async fn proxy_handler(State(state): State<Arc<ProxyState>>, request: Request<Body>) -> Response {
    let uri = request.uri().clone();
    let raw_headers = request.headers().clone();
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

    let path = uri.path().to_string();
    let query = parse_query_params(uri.query());
    let forwarded_query = forwarded_query_string(uri.query());

    // Extract relevant headers.
    let mut headers = HashMap::new();
    for (name, value) in &raw_headers {
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
    let result =
        match state
            .evaluator
            .evaluate(method, &path, &query, &headers, body_hash, body_length)
        {
            Ok(r) => r,
            Err(e) => {
                warn!("evaluation error: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "evaluation error").into_response();
            }
        };

    // If denied, return structured 403.
    if result.verdict.is_denied() {
        let denied_status = StatusCode::from_u16(verdict_http_status(&result.verdict))
            .unwrap_or(StatusCode::FORBIDDEN);
        let final_receipt = match finalize_and_record_receipt(
            &state,
            &result.receipt,
            denied_status.as_u16(),
        )
        .await
        {
            Ok(receipt) => receipt,
            Err(response) => return response,
        };
        let error_body = serde_json::json!({
            "error": "arc_access_denied",
            "message": match &result.verdict {
                Verdict::Deny { reason, .. } => reason.clone(),
                _ => "access denied".to_string(),
            },
            "receipt_id": final_receipt.id,
            "suggestion": "provide a valid capability token in the X-Arc-Capability header or arc_capability query parameter",
        });
        return Response::builder()
            .status(denied_status)
            .header("content-type", "application/json")
            .header("X-Arc-Receipt-Id", &final_receipt.id)
            .body(Body::from(
                serde_json::to_string(&error_body).unwrap_or_default(),
            ))
            .unwrap_or_else(|_| denied_status.into_response());
    }

    // Proxy to upstream.
    let mut upstream_url = format!("{}{}", state.upstream.trim_end_matches('/'), &path);
    if let Some(raw_query) = forwarded_query {
        upstream_url.push('?');
        upstream_url.push_str(&raw_query);
    }

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

    // Forward end-to-end request headers while keeping ARC transport and
    // hop-by-hop connection details local to the proxy.
    for (name, value) in &raw_headers {
        if should_forward_request_header(name.as_str()) {
            upstream_req = upstream_req.header(name, value);
        }
    }

    if !body_bytes.is_empty() {
        upstream_req = upstream_req.body(body_bytes.to_vec());
    }

    match upstream_req.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let response_headers = resp.headers().clone();
            let final_receipt =
                match finalize_and_record_receipt(&state, &result.receipt, status.as_u16()).await {
                    Ok(receipt) => receipt,
                    Err(response) => return response,
                };

            let mut response_builder = Response::builder().status(status);

            // Forward response headers.
            for (name, value) in &response_headers {
                response_builder = response_builder.header(name.as_str(), value.as_bytes());
            }

            // Add receipt ID header.
            response_builder = response_builder.header("X-Arc-Receipt-Id", &final_receipt.id);

            match resp.bytes().await {
                Ok(body) => response_builder
                    .body(Body::from(body))
                    .unwrap_or_else(|_| (StatusCode::BAD_GATEWAY, "bad gateway").into_response()),
                Err(error) => {
                    finalize_bad_gateway(
                        &state,
                        &result.receipt,
                        format!("failed to read upstream response: {error}"),
                    )
                    .await
                }
            }
        }
        Err(e) => {
            warn!("upstream error: {e}");
            finalize_bad_gateway(&state, &result.receipt, format!("upstream error: {e}")).await
        }
    }
}

async fn sidecar_evaluate_handler(
    State(state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let transport_query = parse_query_params(parts.uri.query());
    let presented_capability = extract_transport_capability(&parts.headers, &transport_query);
    let body_bytes = match axum::body::to_bytes(body, 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read evaluation body: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "arc_bad_request",
                    "message": "failed to read evaluation body",
                })),
            )
                .into_response();
        }
    };

    let arc_request: ArcHttpRequest = match serde_json::from_slice(&body_bytes) {
        Ok(request) => request,
        Err(error) => {
            warn!("failed to decode ArcHttpRequest: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "arc_bad_request",
                    "message": format!("invalid ArcHttpRequest payload: {error}"),
                })),
            )
                .into_response();
        }
    };

    let result = match state
        .evaluator
        .evaluate_arc_request(arc_request, presented_capability.as_deref())
    {
        Ok(result) => result,
        Err(error) => {
            warn!("sidecar evaluation error: {error}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "error": "arc_evaluation_failed",
                    "message": error.to_string(),
                })),
            )
                .into_response();
        }
    };

    if let Err(error) = record_receipt(&state, &result.receipt).await {
        warn!("failed to persist receipt: {error}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "error": "arc_receipt_persistence_failed",
                "message": error.to_string(),
            })),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        axum::Json(EvaluateResponse {
            verdict: result.verdict,
            receipt: result.receipt,
            evidence: result.evidence,
            // Phase 1.1: this proxy path does not mint execution nonces
            // today. When the kernel gets a nonce config, the caller
            // lifts the nonce out of the kernel's tool-call response and
            // populates this field; for now it stays `None`, which keeps
            // the JSON wire shape identical to the pre-1.1 contract.
            execution_nonce: None,
        }),
    )
        .into_response()
}

async fn sidecar_verify_handler(
    State(_state): State<Arc<ProxyState>>,
    request: Request<Body>,
) -> Response {
    let (_parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!("failed to read verify body: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "arc_bad_request",
                    "message": "failed to read receipt verification body",
                })),
            )
                .into_response();
        }
    };

    let receipt: HttpReceipt = match serde_json::from_slice(&body_bytes) {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!("failed to decode HttpReceipt: {error}");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(serde_json::json!({
                    "error": "arc_bad_request",
                    "message": format!("invalid HttpReceipt payload: {error}"),
                })),
            )
                .into_response();
        }
    };

    let valid = receipt.verify_signature().unwrap_or(false);
    (StatusCode::OK, axum::Json(VerifyReceiptResponse { valid })).into_response()
}

async fn sidecar_health_handler(State(_state): State<Arc<ProxyState>>) -> Response {
    (
        StatusCode::OK,
        axum::Json(HealthResponse {
            status: SidecarStatus::Healthy,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
        .into_response()
}

fn parse_query_params(raw_query: Option<&str>) -> HashMap<String, String> {
    raw_query
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn forwarded_query_string(raw_query: Option<&str>) -> Option<String> {
    let raw_query = raw_query?;
    let filtered = url::form_urlencoded::parse(raw_query.as_bytes())
        .filter(|(key, _)| key != "arc_capability")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();

    if filtered.is_empty() {
        return None;
    }

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in filtered {
        serializer.append_pair(&key, &value);
    }
    let query = serializer.finish();
    (!query.is_empty()).then_some(query)
}

fn should_forward_request_header(name: &str) -> bool {
    !matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "x-arc-capability"
    )
}

fn verdict_http_status(verdict: &Verdict) -> u16 {
    match verdict {
        Verdict::Allow => 200,
        Verdict::Deny { http_status, .. } => *http_status,
        Verdict::Cancel { .. } | Verdict::Incomplete { .. } => 500,
    }
}

fn extract_transport_capability(
    headers: &axum::http::HeaderMap,
    query: &HashMap<String, String>,
) -> Option<String> {
    headers
        .get("x-arc-capability")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .or_else(|| query.get("arc_capability").cloned())
}

async fn record_receipt(
    state: &Arc<ProxyState>,
    receipt: &HttpReceipt,
) -> Result<(), ProtectError> {
    if let Some(store) = &state.receipt_store {
        let mut store = store.lock().await;
        store.append(receipt)?;
    }

    let mut log = state.receipt_log.lock().await;
    log.receipts.push(receipt.clone());
    Ok(())
}

async fn finalize_and_record_receipt(
    state: &Arc<ProxyState>,
    decision_receipt: &HttpReceipt,
    response_status: u16,
) -> Result<HttpReceipt, Response> {
    let receipt = state
        .evaluator
        .finalize_receipt(decision_receipt, response_status)
        .map_err(|error| {
            warn!("failed to finalize receipt: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to finalize receipt",
            )
                .into_response()
        })?;

    record_receipt(state, &receipt).await.map_err(|error| {
        warn!("failed to persist receipt: {error}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist receipt",
        )
            .into_response()
    })?;

    Ok(receipt)
}

async fn finalize_bad_gateway(
    state: &Arc<ProxyState>,
    decision_receipt: &HttpReceipt,
    message: String,
) -> Response {
    match finalize_and_record_receipt(state, decision_receipt, StatusCode::BAD_GATEWAY.as_u16())
        .await
    {
        Ok(receipt) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("X-Arc-Receipt-Id", &receipt.id)
            .body(Body::from(message))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response()),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_core_types::capability::{ArcScope, CapabilityToken, CapabilityTokenBody};
    use arc_http_core::{
        http_status_scope, ARC_HTTP_STATUS_SCOPE_DECISION, ARC_HTTP_STATUS_SCOPE_FINAL,
    };
    use arc_openapi::PolicyDecision;
    use axum::body::to_bytes;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

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

    fn valid_capability_token_json(id: &str) -> String {
        let issuer = Keypair::generate();
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope: ArcScope::default(),
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
            },
            &issuer,
        )
        .expect("token should sign");
        serde_json::to_string(&token).expect("token should serialize")
    }

    struct MockUpstreamServer {
        base_url: String,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
        handle: thread::JoinHandle<()>,
    }

    impl MockUpstreamServer {
        fn spawn(status: u16, headers: Vec<(&str, &str)>, body: &str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream listener");
            let address = listener.local_addr().expect("listener address");
            let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
            let request_log = Arc::clone(&requests);
            let headers = headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), value.to_string()))
                .collect::<Vec<_>>();
            let body = body.to_string();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept upstream connection");
                let request = read_http_request(&mut stream);
                request_log.lock().expect("request log lock").push(request);
                write_http_response(&mut stream, status, &headers, &body);
            });
            Self {
                base_url: format!("http://{}", address),
                requests,
                handle,
            }
        }

        fn base_url(&self) -> String {
            self.base_url.clone()
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().expect("request log lock").clone()
        }

        fn join(self) {
            self.handle.join().expect("join mock upstream thread");
        }
    }

    fn test_state(routes: Vec<RouteEntry>, upstream: String) -> Arc<ProxyState> {
        test_state_with_receipt_db(routes, upstream, None)
    }

    fn test_state_with_receipt_db(
        routes: Vec<RouteEntry>,
        upstream: String,
        receipt_db: Option<&str>,
    ) -> Arc<ProxyState> {
        let receipt_store = receipt_db.map(|path| {
            Mutex::new(SqliteReceiptStore::open(path).expect("open sqlite receipt store"))
        });
        Arc::new(ProxyState {
            evaluator: RequestEvaluator::new(
                routes,
                Keypair::generate(),
                "test-policy".to_string(),
            ),
            upstream,
            http_client: reqwest::Client::new(),
            receipt_log: Mutex::new(ReceiptLog {
                receipts: receipt_db
                    .map(|path| {
                        SqliteReceiptStore::open(path)
                            .expect("open sqlite receipt store")
                            .load_receipts()
                            .expect("load persisted receipts")
                    })
                    .unwrap_or_default(),
            }),
            receipt_store,
        })
    }

    fn temp_receipt_db_path() -> String {
        let mut path = std::env::temp_dir();
        path.push(format!("arc-api-protect-test-{}.db", uuid::Uuid::now_v7()));
        path.to_string_lossy().to_string()
    }

    fn read_http_request<R: Read>(stream: &mut R) -> String {
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        loop {
            let read = stream.read(&mut chunk).expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if header_end.is_none() {
                header_end = find_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_content_length(&request[..end]);
                }
            }
            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }

        String::from_utf8(request).expect("request should be valid UTF-8")
    }

    fn find_header_end(request: &[u8]) -> Option<usize> {
        request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
    }

    fn parse_content_length(headers: &[u8]) -> usize {
        String::from_utf8_lossy(headers)
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    fn write_http_response<W: Write>(
        stream: &mut W,
        status: u16,
        headers: &[(String, String)],
        body: &str,
    ) {
        let mut response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            http_status_text(status),
            body.len(),
        );
        for (name, value) in headers {
            response.push_str(&format!("{name}: {value}\r\n"));
        }
        response.push_str("\r\n");
        response.push_str(body);
        stream
            .write_all(response.as_bytes())
            .expect("write upstream response");
    }

    fn http_status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            502 => "Bad Gateway",
            _ => "Unknown",
        }
    }

    #[test]
    fn build_routes_from_petstore() {
        let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).unwrap();
        assert!(!routes.is_empty());

        // Should have GET and POST for /pets, GET and DELETE for /pets/{petId}
        let get_pets = routes.iter().find(|r| {
            r.method == HttpMethod::Get
                && r.pattern.contains("/pets")
                && !r.pattern.contains("{petId}")
        });
        assert!(get_pets.is_some());

        let post_pets = routes.iter().find(|r| r.method == HttpMethod::Post);
        assert!(post_pets.is_some());
        assert_eq!(
            post_pets.map(|r| r.policy.clone()),
            Some(PolicyDecision::DenyByDefault)
        );

        let delete_pet = routes.iter().find(|r| r.method == HttpMethod::Delete);
        assert!(delete_pet.is_some());
    }

    #[test]
    fn get_routes_allowed_by_default() {
        let routes = ProtectProxy::routes_from_spec(PETSTORE_YAML).unwrap();
        let get_routes: Vec<_> = routes
            .iter()
            .filter(|r| r.method == HttpMethod::Get)
            .collect();
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

    #[test]
    fn x_arc_side_effects_true_overrides_safe_method() {
        let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /dangerous-read:
    get:
      operationId: dangerousRead
      x-arc-side-effects: true
      responses:
        "200":
          description: ok
"#;

        let routes = ProtectProxy::routes_from_spec(spec).unwrap();
        let route = routes
            .iter()
            .find(|route| route.pattern == "/dangerous-read" && route.method == HttpMethod::Get)
            .expect("route");

        assert_eq!(route.policy, PolicyDecision::DenyByDefault);
    }

    #[test]
    fn x_arc_side_effects_false_overrides_mutating_method() {
        let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /safe-post:
    post:
      operationId: safePost
      x-arc-side-effects: false
      responses:
        "200":
          description: ok
"#;

        let routes = ProtectProxy::routes_from_spec(spec).unwrap();
        let route = routes
            .iter()
            .find(|route| route.pattern == "/safe-post" && route.method == HttpMethod::Post)
            .expect("route");

        assert_eq!(route.policy, PolicyDecision::SessionAllow);
    }

    #[test]
    fn x_arc_approval_required_forces_deny() {
        let spec = r#"
openapi: 3.1.0
info:
  title: Override Test
  version: 1.0.0
paths:
  /approved-read:
    get:
      operationId: approvedRead
      x-arc-side-effects: false
      x-arc-approval-required: true
      responses:
        "200":
          description: ok
"#;

        let routes = ProtectProxy::routes_from_spec(spec).unwrap();
        let route = routes
            .iter()
            .find(|route| route.pattern == "/approved-read" && route.method == HttpMethod::Get)
            .expect("route");

        assert_eq!(route.policy, PolicyDecision::DenyByDefault);
    }

    #[test]
    fn forwarded_query_string_strips_arc_capability() {
        let token = valid_capability_token_json("cap-query");
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("source", "test")
            .append_pair("arc_capability", &token)
            .append_pair("mode", "full")
            .finish();

        assert_eq!(
            forwarded_query_string(Some(&query)).as_deref(),
            Some("source=test&mode=full")
        );
    }

    #[tokio::test]
    async fn proxy_handler_denies_without_capability_and_records_receipt() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"fido"}"#))
            .expect("request");

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let receipt_id = response
            .headers()
            .get("x-arc-receipt-id")
            .and_then(|value| value.to_str().ok())
            .expect("receipt id header")
            .to_string();
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"], "arc_access_denied");
        assert_eq!(
            json["suggestion"],
            "provide a valid capability token in the X-Arc-Capability header or arc_capability query parameter"
        );
        assert!(json["receipt_id"].as_str().is_some());

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert_eq!(log.receipts[0].id, receipt_id);
        assert_eq!(log.receipts[0].response_status, 403);
        assert_eq!(
            http_status_scope(log.receipts[0].metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_FINAL)
        );
        assert!(log.receipts[0]
            .verify_signature()
            .expect("receipt signature"));
    }

    #[tokio::test]
    async fn proxy_handler_forwards_allowed_requests_and_end_to_end_headers() {
        let server = MockUpstreamServer::spawn(
            201,
            vec![("content-type", "application/json"), ("x-upstream", "ok")],
            r#"{"ok":true}"#,
        );
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            server.base_url(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets?source=test")
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("user-agent", "arc-test")
            .header("authorization", "Bearer upstream-token")
            .header("x-request-id", "req-123")
            .header("x-arc-capability", valid_capability_token_json("cap-proxy"))
            .header("x-custom-app", "secret")
            .header("connection", "keep-alive")
            .body(Body::from(r#"{"name":"fido"}"#))
            .expect("request");

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        let receipt_id = response
            .headers()
            .get("x-arc-receipt-id")
            .and_then(|value| value.to_str().ok())
            .expect("receipt id header")
            .to_string();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get("x-upstream")
                .and_then(|value| value.to_str().ok()),
            Some("ok")
        );

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        assert_eq!(body.as_ref(), br#"{"ok":true}"#);

        let requests = server.requests();
        server.join();

        assert_eq!(requests.len(), 1);
        let request_text = requests[0].to_ascii_lowercase();
        assert!(request_text.contains("post /pets?source=test http/1.1"));
        assert!(request_text.contains("content-type: application/json"));
        assert!(request_text.contains("accept: application/json"));
        assert!(request_text.contains("user-agent: arc-test"));
        assert!(request_text.contains("authorization: bearer upstream-token"));
        assert!(request_text.contains("x-request-id: req-123"));
        assert!(request_text.contains("x-custom-app: secret"));
        assert!(!request_text.contains("x-arc-capability:"));
        assert!(!request_text.contains("connection: keep-alive"));
        assert!(request_text.contains(r#"{"name":"fido"}"#));

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert_eq!(log.receipts[0].id, receipt_id);
        assert_eq!(log.receipts[0].response_status, 201);
        assert_eq!(log.receipts[0].capability_id.as_deref(), Some("cap-proxy"));
        assert_eq!(
            http_status_scope(log.receipts[0].metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_FINAL)
        );
    }

    #[tokio::test]
    async fn proxy_handler_strips_query_capability_before_forwarding_upstream() {
        let server =
            MockUpstreamServer::spawn(200, vec![("content-type", "application/json")], "{}");
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            server.base_url(),
        );
        let token = valid_capability_token_json("cap-query");
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("source", "test")
            .append_pair("arc_capability", &token)
            .append_pair("mode", "full")
            .finish();
        let request = Request::builder()
            .method("POST")
            .uri(format!("/pets?{query}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"fido"}"#))
            .expect("request");

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let requests = server.requests();
        server.join();

        assert_eq!(requests.len(), 1);
        let request_text = requests[0].to_ascii_lowercase();
        assert!(request_text.contains("post /pets?source=test&mode=full http/1.1"));
        assert!(!request_text.contains("arc_capability"));

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert_eq!(log.receipts[0].capability_id.as_deref(), Some("cap-query"));
    }

    #[tokio::test]
    async fn proxy_handler_rejects_unsupported_methods_before_evaluation() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let request = Request::builder()
            .method("TRACE")
            .uri("/pets")
            .body(Body::empty())
            .expect("request");

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        assert_eq!(body.as_ref(), b"unsupported method");
        let log = state.receipt_log.lock().await;
        assert!(log.receipts.is_empty());
    }

    #[tokio::test]
    async fn proxy_handler_surfaces_upstream_failures_after_allowing_request() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Get,
                operation_id: Some("listPets".to_string()),
                policy: PolicyDecision::SessionAllow,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let request = Request::builder()
            .method("GET")
            .uri("/pets")
            .body(Body::empty())
            .expect("request");

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let text = String::from_utf8(body.to_vec()).expect("utf8 body");
        assert!(text.contains("upstream error:"));

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert_eq!(log.receipts[0].response_status, 502);
        assert_eq!(
            http_status_scope(log.receipts[0].metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_FINAL)
        );
    }

    #[tokio::test]
    async fn proxy_handler_denies_invalid_capability_tokens() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets")
            .header("x-arc-capability", "not-json")
            .body(Body::from(r#"{"name":"fido"}"#))
            .expect("request");

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"], "arc_access_denied");

        let log = state.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert!(log.receipts[0].capability_id.is_none());
        assert_eq!(
            http_status_scope(log.receipts[0].metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_FINAL)
        );
    }

    #[tokio::test]
    async fn sidecar_evaluate_returns_200_with_deny_verdict() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let body = ArcHttpRequest::new(
            "req-sidecar-deny".to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            arc_http_core::CallerIdentity::anonymous(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/arc/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&body).expect("serialize request"),
            ))
            .expect("request");

        let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let evaluation: EvaluateResponse =
            serde_json::from_slice(&bytes).expect("decode evaluate response");
        assert!(evaluation
            .receipt
            .verify_signature()
            .expect("receipt signature"));
        assert!(evaluation.verdict.is_denied());
        assert!(evaluation.receipt.is_denied());
        assert_eq!(
            http_status_scope(evaluation.receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[tokio::test]
    async fn sidecar_evaluate_validates_transport_capability_header() {
        let state = test_state(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
        );
        let token = valid_capability_token_json("cap-sidecar");
        let mut body = ArcHttpRequest::new(
            "req-sidecar-allow".to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            arc_http_core::CallerIdentity::anonymous(),
        );
        body.capability_id = Some("cap-sidecar".to_string());
        let request = Request::builder()
            .method("POST")
            .uri("/arc/evaluate")
            .header("content-type", "application/json")
            .header("x-arc-capability", token)
            .body(Body::from(
                serde_json::to_vec(&body).expect("serialize request"),
            ))
            .expect("request");

        let response = sidecar_evaluate_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let evaluation: EvaluateResponse =
            serde_json::from_slice(&bytes).expect("decode evaluate response");
        assert!(evaluation.verdict.is_allowed());
        assert_eq!(
            evaluation.receipt.capability_id.as_deref(),
            Some("cap-sidecar")
        );
        assert_eq!(
            http_status_scope(evaluation.receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[tokio::test]
    async fn sidecar_verify_reports_signature_validity() {
        let state = test_state(Vec::new(), "http://127.0.0.1:1".to_string());
        let keypair = Keypair::generate();
        let receipt = HttpReceipt::sign(
            arc_http_core::HttpReceiptBody {
                id: "receipt-verify".to_string(),
                request_id: "req-verify".to_string(),
                route_pattern: "/pets".to_string(),
                method: HttpMethod::Get,
                caller_identity_hash: "caller-hash".to_string(),
                session_id: None,
                verdict: arc_http_core::Verdict::Allow,
                evidence: Vec::new(),
                response_status: 200,
                timestamp: 1_700_000_000,
                content_hash: "hash".to_string(),
                policy_hash: "policy".to_string(),
                capability_id: None,
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign receipt");
        let request = Request::builder()
            .method("POST")
            .uri("/arc/verify")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&receipt).expect("serialize receipt"),
            ))
            .expect("request");

        let response = sidecar_verify_handler(State(state), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("response body");
        let verification: VerifyReceiptResponse =
            serde_json::from_slice(&bytes).expect("decode verify response");
        assert!(verification.valid);
    }

    #[tokio::test]
    async fn proxy_handler_persists_receipts_when_receipt_db_configured() {
        let receipt_db = temp_receipt_db_path();
        let state = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/pets")
            .body(Body::from(r#"{"name":"fido"}"#))
            .expect("request");

        let response = proxy_handler(State(Arc::clone(&state)), request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let reloaded = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let log = reloaded.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 1);
        assert!(log.receipts[0]
            .verify_signature()
            .expect("receipt signature"));

        let _ = std::fs::remove_file(receipt_db);
    }

    #[tokio::test]
    async fn persisted_receipts_are_visible_across_proxy_and_sidecar_flows() {
        let receipt_db = temp_receipt_db_path();
        let proxy_state = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Post,
                operation_id: Some("createPet".to_string()),
                policy: PolicyDecision::DenyByDefault,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let denied_request = Request::builder()
            .method("POST")
            .uri("/pets")
            .body(Body::from(r#"{"name":"fido"}"#))
            .expect("request");
        let denied_response = proxy_handler(State(Arc::clone(&proxy_state)), denied_request).await;
        assert_eq!(denied_response.status(), StatusCode::FORBIDDEN);

        let sidecar_state = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Get,
                operation_id: Some("listPets".to_string()),
                policy: PolicyDecision::SessionAllow,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        {
            let log = sidecar_state.receipt_log.lock().await;
            assert_eq!(log.receipts.len(), 1);
        }

        let body = ArcHttpRequest::new(
            "req-sidecar-persisted".to_string(),
            HttpMethod::Get,
            "/pets".to_string(),
            "/pets".to_string(),
            arc_http_core::CallerIdentity::anonymous(),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/arc/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&body).expect("serialize request"),
            ))
            .expect("request");

        let response = sidecar_evaluate_handler(State(Arc::clone(&sidecar_state)), request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let reloaded = test_state_with_receipt_db(
            vec![RouteEntry {
                pattern: "/pets".to_string(),
                method: HttpMethod::Get,
                operation_id: Some("listPets".to_string()),
                policy: PolicyDecision::SessionAllow,
            }],
            "http://127.0.0.1:1".to_string(),
            Some(&receipt_db),
        );
        let log = reloaded.receipt_log.lock().await;
        assert_eq!(log.receipts.len(), 2);

        let _ = std::fs::remove_file(receipt_db);
    }
}
