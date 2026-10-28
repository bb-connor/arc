//! Chio Lambda Extension entry point.
//!
//! The binary is packaged as a Lambda Extension Layer and runs alongside the
//! function handler. On cold start it registers with the Runtime API, spawns
//! an HTTP server on `127.0.0.1:9090`, and loops processing INVOKE /
//! SHUTDOWN events.
//!
//! The extension is a detect-only observer. Each evaluation yields an
//! unsigned observation record with `authorized: false`, never a Chio
//! receipt and never an authorization. Each observation is written through to
//! DynamoDB before the evaluator answers. A failed or timed-out write, or an
//! unreadable clock, fails the evaluate request instead of answering without a
//! stored record or stamping a fallback time.
//!
//! All configuration comes from environment variables so a Lambda function
//! can opt in purely through the AWS Console or IaC. Missing or malformed
//! config fails *closed* -- the extension exits with a non-zero code and the
//! function handler's localhost:9090 calls will fail loudly.

#![deny(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use chio_core_types::canonical::UntrustedJsonText;
use chio_core_types::capability::token::CapabilityToken;
use chio_core_types::crypto::PublicKey;
use chio_kernel_core::clock::{SystemClock, UnixMillis};
use chio_kernel_core::{
    evaluate as evaluate_capability, Clock, EvaluateInput, FixedClock, Guard,
    PortableToolCallRequest,
};

#[cfg(test)]
use chio_core_types::crypto::Keypair;

mod lifecycle;
mod observation_store;

use observation_store::{DynamoStore, ObservationRecord, ObservationStore, WRITE_TIMEOUT};

/// Name the extension registers as with the Runtime API. The Lambda
/// Extensions contract requires this to match the filename of the binary
/// inside the `/opt/extensions/` directory.
const EXTENSION_NAME: &str = "chio";

/// Default local address the evaluator listens on. The spec pins this to
/// 9090 so SDKs can hard-code their base URL.
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:9090";

/// Environment variable naming the DynamoDB table observations are written to.
const OBSERVATION_TABLE_ENV: &str = "CHIO_OBSERVATION_TABLE";

/// Environment variable selecting the guard pipeline. Required.
const GUARDS_ENV: &str = "CHIO_GUARDS";

/// Optional override for the evaluator listen address. Most callers will
/// leave this unset.
const LISTEN_ADDR_ENV: &str = "CHIO_EXTENSION_ADDR";
const TRUSTED_ISSUERS_ENV: &str = "CHIO_TRUSTED_ISSUERS";
const CAPABILITY_TOKENS_ENV: &str = "CHIO_CAPABILITY_TOKENS_JSON";

#[derive(Debug, thiserror::Error)]
enum BootError {
    #[error("missing required environment variable {0}")]
    MissingEnv(&'static str),
    #[error("invalid listen address {addr}: {source}")]
    InvalidAddr {
        addr: String,
        source: std::net::AddrParseError,
    },
    #[error("failed to bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    #[error("unsupported CHIO_GUARDS value {0:?}; the only bundled guard set is \"none\"")]
    UnsupportedGuards(String),
    #[error("lifecycle error: {0}")]
    Lifecycle(#[from] lifecycle::LifecycleError),
}

/// Guard pipeline selected by deployment configuration. No guard
/// implementations are bundled, so the only selection is the explicit empty
/// set, spelled `CHIO_GUARDS=none`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GuardSet {
    None,
}

impl GuardSet {
    fn parse(value: &str) -> Result<Self, BootError> {
        match value {
            "none" => Ok(Self::None),
            other => Err(BootError::UnsupportedGuards(other.to_string())),
        }
    }

    fn guards(self) -> &'static [&'static dyn Guard] {
        match self {
            Self::None => &[],
        }
    }
}

fn main() -> std::process::ExitCode {
    // Initialise tracing as early as possible so register / bind errors land
    // in CloudWatch.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("chio_lambda_extension=info,warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Tokio runtime: current-thread flavor is plenty -- the extension is not
    // CPU-bound and every task is either a short HTTP request or a Runtime
    // API poll.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("failed to build tokio runtime: {err}");
            return std::process::ExitCode::from(1);
        }
    };

    match runtime.block_on(run()) {
        Ok(()) => std::process::ExitCode::from(0),
        Err(err) => {
            error!(?err, "chio-lambda-extension exiting with error");
            std::process::ExitCode::from(2)
        }
    }
}

async fn run() -> Result<(), BootError> {
    let table = std::env::var(OBSERVATION_TABLE_ENV)
        .map_err(|_| BootError::MissingEnv(OBSERVATION_TABLE_ENV))?;
    let guards = GuardSet::parse(
        &std::env::var(GUARDS_ENV).map_err(|_| BootError::MissingEnv(GUARDS_ENV))?,
    )?;
    let listen_addr_str =
        std::env::var(LISTEN_ADDR_ENV).unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_string());
    let listen_addr: SocketAddr =
        listen_addr_str
            .parse()
            .map_err(|source| BootError::InvalidAddr {
                addr: listen_addr_str.clone(),
                source,
            })?;

    info!(
        %listen_addr,
        %table,
        ?guards,
        "chio-lambda-extension starting"
    );

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let state = Arc::new(AppState {
        store: Box::new(DynamoStore::new(
            aws_sdk_dynamodb::Client::new(&config),
            table,
        )),
        clock: native_clock(),
        guards,
    });

    // Register with the Runtime API BEFORE starting the evaluator. If the
    // Runtime API refuses us we don't want to let the function hit a
    // localhost:9090 that will never route its calls.
    let handle = lifecycle::register(EXTENSION_NAME).await?;

    // Start the evaluator server.
    let listener = TcpListener::bind(listen_addr)
        .await
        .map_err(|source| BootError::Bind {
            addr: listen_addr,
            source,
        })?;
    info!(%listen_addr, "evaluator listening");
    let server_state = state.clone();
    let server = tokio::spawn(async move {
        if let Err(err) = serve(listener, server_state).await {
            error!(?err, "evaluator server error");
        }
    });

    let lifecycle_result = lifecycle::run_loop(handle).await;

    // Best-effort: once we've returned from the lifecycle loop the Runtime
    // API is done with us. Aborting the server keeps the Tokio runtime from
    // holding the process open.
    server.abort();
    lifecycle_result.map_err(BootError::from)
}

/// The native trusted clock read by every evaluation.
fn native_clock() -> Box<dyn Clock> {
    Box::new(SystemClock)
}

/// Shared state between the lifecycle loop and the HTTP evaluator.
struct AppState {
    store: Box<dyn ObservationStore>,
    clock: Box<dyn Clock>,
    guards: GuardSet,
}

// ---------------------------------------------------------------------------
// Evaluation request / response wire types. Kept deliberately small so an
// SDK can hand-roll the client.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluateRequest {
    #[serde(default)]
    capability_id: String,
    #[serde(default)]
    tool_server: String,
    #[serde(default)]
    tool_name: String,
    #[serde(default)]
    capability: Option<serde_json::Value>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    arguments: Option<serde_json::Value>,
}

/// Unsigned detect-only observation. `authorized` and `authoritative` are
/// always false; `decision` reports the portable evaluation outcome only.
#[derive(Debug, Serialize)]
struct EvaluateResponse {
    observation_id: String,
    decision: &'static str,
    authorized: bool,
    authoritative: bool,
    boundary_class: &'static str,
    reason: Option<String>,
    metadata: Option<serde_json::Value>,
    capability_id: String,
    tool_server: String,
    tool_name: String,
    timestamp: u64,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    extension: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: &'static str,
    message: String,
}

async fn serve(listener: TcpListener, state: Arc<AppState>) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle(req, state.clone()));
            if let Err(err) = ServerBuilder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, service)
                .into_future()
                .await
            {
                warn!(?err, "connection error");
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let response = match (method.as_str(), path.as_str()) {
        ("GET", "/health") | ("GET", "/chio/health") => ok_json(&HealthResponse {
            status: "ok",
            extension: EXTENSION_NAME,
        }),
        ("POST", "/v1/evaluate") => {
            let (parts, body) = req.into_parts();
            match read_body(body).await {
                Ok(body) => match decode_evaluate_request(&body) {
                    Ok(mut request) => {
                        if let Err(error) =
                            hydrate_request_from_headers(&parts.headers, &mut request)
                        {
                            error_json(StatusCode::BAD_REQUEST, "invalid_capability", error)
                        } else {
                            evaluate(request, state).await
                        }
                    }
                    Err(err) => error_json(StatusCode::BAD_REQUEST, "invalid_json", err),
                },
                Err(err) => error_json(
                    StatusCode::BAD_REQUEST,
                    "body_read_error",
                    format!("failed to read request body: {err}"),
                ),
            }
        }
        _ => error_json(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("{method} {path}"),
        ),
    };
    Ok(response)
}

fn decode_evaluate_request(body: &[u8]) -> Result<EvaluateRequest, String> {
    let text = std::str::from_utf8(body)
        .map_err(|error| format!("failed to decode evaluate request: {error}"))?;
    UntrustedJsonText::new(text)
        .decode_document()
        .map_err(|error| format!("failed to decode evaluate request: {error}"))
}

async fn read_body(body: Incoming) -> Result<Vec<u8>, hyper::Error> {
    let collected = body.collect().await?;
    Ok(collected.to_bytes().to_vec())
}

fn hydrate_request_from_headers(
    headers: &hyper::HeaderMap,
    request: &mut EvaluateRequest,
) -> Result<(), String> {
    if request.capability.is_none() {
        if let Some(raw_capability) = headers.get("x-chio-capability") {
            let raw_capability = raw_capability
                .to_str()
                .map_err(|error| format!("invalid x-chio-capability header: {error}"))?;
            request.capability = Some(
                UntrustedJsonText::new(raw_capability)
                    .decode_document()
                    .map_err(|error| format!("invalid x-chio-capability JSON: {error}"))?,
            );
        }
    }

    if request.capability_id.is_empty() {
        if let Some(capability) = request.capability.as_ref() {
            let capability: CapabilityToken = serde_json::from_value(capability.clone())
                .map_err(|error| format!("invalid capability token: {error}"))?;
            request.capability_id = capability.id;
        }
    }

    Ok(())
}

async fn evaluate(request: EvaluateRequest, state: Arc<AppState>) -> Response<Full<Bytes>> {
    let now = match state.clock.unix_millis() {
        Ok(now) => now,
        Err(err) => {
            return error_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "clock_unavailable",
                err.code().to_string(),
            )
        }
    };

    let (decision, reason) = evaluate_request(&request, now, state.guards);

    let observation_id = uuid::Uuid::now_v7().to_string();
    let response = EvaluateResponse {
        observation_id: observation_id.clone(),
        decision,
        authorized: false,
        authoritative: false,
        boundary_class: "detect_only",
        reason: reason.clone(),
        metadata: request.metadata.clone(),
        capability_id: request.capability_id.clone(),
        tool_server: request.tool_server.clone(),
        tool_name: request.tool_name.clone(),
        timestamp: now.as_secs(),
    };

    let payload_json = match serde_json::to_string(&response) {
        Ok(payload_json) => payload_json,
        Err(err) => {
            return error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "observation_unrecorded",
                format!("failed to encode observation: {err}"),
            )
        }
    };
    let record = ObservationRecord {
        observation_id,
        timestamp: now.as_secs(),
        capability_id: request.capability_id.clone(),
        tool_server: request.tool_server.clone(),
        tool_name: request.tool_name.clone(),
        decision: decision.to_string(),
        reason,
        payload_json,
    };

    // The observation is stored before the caller hears the outcome.
    let message = match tokio::time::timeout(WRITE_TIMEOUT, state.store.put(&record)).await {
        Ok(Ok(())) => return ok_json(&response),
        Ok(Err(err)) => err.to_string(),
        Err(_) => format!("observation write exceeded {WRITE_TIMEOUT:?}"),
    };
    warn!(%message, "refusing evaluate request");
    error_json(
        StatusCode::SERVICE_UNAVAILABLE,
        "observation_unrecorded",
        message,
    )
}

fn evaluate_request(
    request: &EvaluateRequest,
    now: UnixMillis,
    guards: GuardSet,
) -> (&'static str, Option<String>) {
    if request.tool_server.is_empty() {
        return ("deny", Some("missing tool_server".into()));
    }
    if request.tool_name.is_empty() {
        return ("deny", Some("missing tool_name".into()));
    }

    let capability = match resolve_capability(request) {
        Ok(capability) => capability,
        Err(reason) => return ("deny", Some(reason)),
    };
    if request.capability_id.is_empty() {
        return ("deny", Some("missing capability_id".into()));
    }
    if capability.id != request.capability_id {
        return (
            "deny",
            Some("capability_id does not match resolved capability token".into()),
        );
    }

    let trusted_issuers = match resolve_trusted_issuers() {
        Ok(trusted_issuers) if !trusted_issuers.is_empty() => trusted_issuers,
        Ok(_) => return ("deny", Some("missing trusted_issuers".into())),
        Err(reason) => return ("deny", Some(reason)),
    };

    let portable_request = PortableToolCallRequest {
        request_id: format!("lambda-eval-{}", uuid::Uuid::now_v7()),
        tool_name: request.tool_name.clone(),
        server_id: request.tool_server.clone(),
        agent_id: capability.subject.to_hex(),
        arguments: request.arguments.clone().unwrap_or(serde_json::Value::Null),
    };
    let clock = FixedClock::from_millis(now.get());
    let verdict = evaluate_capability(EvaluateInput {
        request: &portable_request,
        capability: &capability,
        trusted_issuers: &trusted_issuers,
        clock: &clock,
        guards: guards.guards(),
        session_filesystem_roots: None,
    });

    if verdict.is_allow() {
        ("allow", None)
    } else {
        (
            "deny",
            verdict
                .reason
                .or_else(|| Some("capability evaluation denied the request".into())),
        )
    }
}

fn resolve_capability(request: &EvaluateRequest) -> Result<CapabilityToken, String> {
    if let Some(capability) = request.capability.as_ref() {
        return serde_json::from_value(capability.clone())
            .map_err(|error| format!("invalid capability token: {error}"));
    }

    let raw = std::env::var(CAPABILITY_TOKENS_ENV)
        .map_err(|_| format!("missing {CAPABILITY_TOKENS_ENV} and no inline capability token"))?;
    let tokens: serde_json::Map<String, serde_json::Value> = UntrustedJsonText::new(&raw)
        .decode_document()
        .map_err(|error| format!("invalid {CAPABILITY_TOKENS_ENV}: {error}"))?;
    let capability = tokens
        .get(&request.capability_id)
        .ok_or_else(|| format!("unknown capability_id {}", request.capability_id))?;
    serde_json::from_value(capability.clone()).map_err(|error| {
        format!(
            "invalid capability token for {}: {error}",
            request.capability_id
        )
    })
}

fn resolve_trusted_issuers() -> Result<Vec<PublicKey>, String> {
    let raw = std::env::var(TRUSTED_ISSUERS_ENV)
        .map_err(|_| format!("missing {TRUSTED_ISSUERS_ENV} deployment configuration"))?;
    let issuer_values = serde_json::from_str::<Vec<String>>(&raw)
        .map_err(|error| format!("invalid {TRUSTED_ISSUERS_ENV}: {error}"))?;

    issuer_values
        .into_iter()
        .map(|value| {
            PublicKey::from_hex(&value)
                .map_err(|error| format!("invalid trusted issuer {value}: {error}"))
        })
        .collect()
}

fn ok_json<T: Serialize>(body: &T) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    build_response(StatusCode::OK, bytes)
}

fn error_json(status: StatusCode, error: &'static str, message: String) -> Response<Full<Bytes>> {
    let body = ErrorResponse { error, message };
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    build_response(status, bytes)
}

fn build_response(status: StatusCode, bytes: Vec<u8>) -> Response<Full<Bytes>> {
    let body = Full::new(Bytes::from(bytes));
    let builder = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    match builder.body(body) {
        Ok(response) => response,
        Err(_) => {
            let mut fallback = Response::new(Full::new(Bytes::from_static(b"{}")));
            *fallback.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    mod numeric;

    use super::*;
    use crate::observation_store::{StoreError, StoreFuture};
    use chio_core_types::capability::scope::{ChioScope, Operation, ToolGrant};
    use chio_core_types::capability::token::CapabilityTokenBody;
    use std::ffi::OsString;
    use std::future::Future;
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Mutex;

    /// Fixed evaluation time inside every fixture capability window.
    const FIXTURE_NOW_SECS: u64 = 1_760_000_000;

    static ENV_LOCK: Mutex<()> = Mutex::const_new(());

    async fn with_env_var<T>(key: &str, value: &str, future: impl Future<Output = T>) -> T {
        let _guard = ENV_LOCK.lock().await;
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        let output = future.await;
        restore_env_var(key, previous);
        output
    }

    fn restore_env_var(key: &str, previous: Option<OsString>) {
        match previous {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }

    #[derive(Clone, Default)]
    struct RecordingStore(Arc<StdMutex<Vec<ObservationRecord>>>);

    impl RecordingStore {
        fn records(&self) -> Vec<ObservationRecord> {
            self.0.lock().unwrap().clone()
        }
    }

    impl ObservationStore for RecordingStore {
        fn put<'a>(&'a self, record: &'a ObservationRecord) -> StoreFuture<'a> {
            self.0.lock().unwrap().push(record.clone());
            Box::pin(async { Ok(()) })
        }
    }

    struct FailingStore;

    impl ObservationStore for FailingStore {
        fn put<'a>(&'a self, _record: &'a ObservationRecord) -> StoreFuture<'a> {
            Box::pin(async { Err(StoreError("table unavailable".into())) })
        }
    }

    struct HangingStore;

    impl ObservationStore for HangingStore {
        fn put<'a>(&'a self, _record: &'a ObservationRecord) -> StoreFuture<'a> {
            Box::pin(std::future::pending())
        }
    }

    fn state_with(store: impl ObservationStore + 'static, clock: FixedClock) -> Arc<AppState> {
        Arc::new(AppState {
            store: Box::new(store),
            clock: Box::new(clock),
            guards: GuardSet::None,
        })
    }

    fn recording_state() -> (Arc<AppState>, RecordingStore) {
        let store = RecordingStore::default();
        let state = state_with(store.clone(), FixedClock::new(FIXTURE_NOW_SECS));
        (state, store)
    }

    fn signed_capability(issuer: &Keypair) -> CapabilityToken {
        let subject = Keypair::generate();
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "cap".into(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "srv".into(),
                        tool_name: "tool".into(),
                        operations: vec![Operation::Invoke],
                        constraints: Vec::new(),
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at: 1,
                expires_at: FIXTURE_NOW_SECS + 3_600,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            issuer,
        )
        .unwrap()
    }

    fn request_for(capability: &CapabilityToken) -> EvaluateRequest {
        EvaluateRequest {
            capability_id: "cap".into(),
            tool_server: "srv".into(),
            tool_name: "tool".into(),
            capability: Some(serde_json::to_value(capability).unwrap()),
            metadata: None,
            arguments: None,
        }
    }

    async fn evaluate_trusting(
        issuer: &Keypair,
        request: EvaluateRequest,
        state: Arc<AppState>,
    ) -> Response<Full<Bytes>> {
        let trusted = serde_json::to_string(&vec![issuer.public_key().to_hex()]).unwrap();
        with_env_var(TRUSTED_ISSUERS_ENV, &trusted, evaluate(request, state)).await
    }

    async fn body_json(response: Response<Full<Bytes>>) -> serde_json::Value {
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn evaluate_denies_missing_capability_id() {
        let issuer = Keypair::generate();
        let mut request = request_for(&signed_capability(&issuer));
        request.capability_id = String::new();
        let (state, _) = recording_state();
        let response = evaluate(request, state).await;
        assert_eq!(response.status(), StatusCode::OK);
        let parsed = body_json(response).await;
        assert_eq!(parsed["decision"], "deny");
        assert_eq!(parsed["reason"], "missing capability_id");
    }

    #[tokio::test]
    async fn evaluate_denies_missing_tool_name() {
        let issuer = Keypair::generate();
        let mut request = request_for(&signed_capability(&issuer));
        request.tool_name = String::new();
        let (state, _) = recording_state();
        let parsed = body_json(evaluate(request, state).await).await;
        assert_eq!(parsed["decision"], "deny");
    }

    #[tokio::test]
    async fn evaluate_observes_well_formed_request_without_authorizing() {
        let issuer = Keypair::generate();
        let mut request = request_for(&signed_capability(&issuer));
        request.arguments = Some(serde_json::json!({"q": "hello"}));
        request.metadata = Some(serde_json::json!({"trace_id": "trace-1"}));
        let (state, _) = recording_state();
        let parsed = body_json(evaluate_trusting(&issuer, request, state).await).await;
        assert_eq!(parsed["decision"], "allow");
        assert_eq!(parsed["authorized"], false);
        assert_eq!(parsed["authoritative"], false);
        assert_eq!(parsed["boundary_class"], "detect_only");
        assert_eq!(parsed["timestamp"], FIXTURE_NOW_SECS);
        assert_eq!(parsed["metadata"]["trace_id"], "trace-1");
        assert!(parsed["observation_id"].as_str().is_some());
        assert!(parsed.get("receipt_id").is_none());
        assert!(parsed.get("receipt_kind").is_none());
    }

    #[tokio::test]
    async fn evaluate_writes_observation_before_answering() {
        let issuer = Keypair::generate();
        let (state, store) = recording_state();
        let request = request_for(&signed_capability(&issuer));
        let response = evaluate_trusting(&issuer, request, state).await;
        assert_eq!(response.status(), StatusCode::OK);
        let parsed = body_json(response).await;
        let records = store.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].observation_id, parsed["observation_id"]);
        assert_eq!(records[0].decision, "allow");
        assert_eq!(records[0].timestamp, FIXTURE_NOW_SECS);
    }

    #[tokio::test]
    async fn evaluate_records_every_sequential_call_without_capacity_limit() {
        let issuer = Keypair::generate();
        let (state, store) = recording_state();
        let capability = signed_capability(&issuer);
        let trusted = serde_json::to_string(&vec![issuer.public_key().to_hex()]).unwrap();
        let calls = 2_500;
        with_env_var(TRUSTED_ISSUERS_ENV, &trusted, async {
            for _ in 0..calls {
                let response = evaluate(request_for(&capability), state.clone()).await;
                assert_eq!(response.status(), StatusCode::OK);
            }
        })
        .await;
        assert_eq!(store.records().len(), calls);
    }

    #[tokio::test]
    async fn evaluate_fails_closed_when_write_fails() {
        let issuer = Keypair::generate();
        let state = state_with(FailingStore, FixedClock::new(FIXTURE_NOW_SECS));
        let request = request_for(&signed_capability(&issuer));
        let response = evaluate_trusting(&issuer, request, state).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let parsed = body_json(response).await;
        assert_eq!(parsed["error"], "observation_unrecorded");
        assert_eq!(
            parsed["message"],
            "observation write failed: table unavailable"
        );
        assert!(parsed.get("decision").is_none());
        assert!(parsed.get("observation_id").is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn evaluate_fails_closed_when_write_times_out() {
        let issuer = Keypair::generate();
        let state = state_with(HangingStore, FixedClock::new(FIXTURE_NOW_SECS));
        let request = request_for(&signed_capability(&issuer));
        let response = evaluate_trusting(&issuer, request, state).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let parsed = body_json(response).await;
        assert_eq!(parsed["error"], "observation_unrecorded");
        assert!(parsed["message"]
            .as_str()
            .unwrap_or_default()
            .contains("exceeded"));
        assert!(parsed.get("decision").is_none());
    }

    #[tokio::test]
    async fn evaluate_fails_closed_when_clock_is_unreadable() {
        let issuer = Keypair::generate();
        let store = RecordingStore::default();
        let state = state_with(store.clone(), FixedClock::new(u64::MAX));
        let request = request_for(&signed_capability(&issuer));
        let response = evaluate_trusting(&issuer, request, state).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let parsed = body_json(response).await;
        assert_eq!(parsed["error"], "clock_unavailable");
        assert_eq!(parsed["message"], "urn:chio:error:kernel:clock-overflow");
        assert!(store.records().is_empty());
    }

    #[tokio::test]
    async fn evaluate_denies_expired_capability_at_injected_time() {
        let issuer = Keypair::generate();
        let state = state_with(
            RecordingStore::default(),
            FixedClock::new(FIXTURE_NOW_SECS + 7_200),
        );
        let request = request_for(&signed_capability(&issuer));
        let parsed = body_json(evaluate_trusting(&issuer, request, state).await).await;
        assert_eq!(parsed["decision"], "deny");
    }

    #[tokio::test]
    async fn evaluate_denies_issuer_outside_deployment_configuration() {
        let trusted_issuer = Keypair::generate();
        let untrusted_issuer = Keypair::generate();
        let request = request_for(&signed_capability(&untrusted_issuer));
        let (state, _) = recording_state();
        let parsed = body_json(evaluate_trusting(&trusted_issuer, request, state).await).await;
        assert_eq!(parsed["decision"], "deny");
        let reason = parsed["reason"].as_str().unwrap_or_default();
        assert!(
            reason.contains("issuer") || reason.contains("trust"),
            "{reason}"
        );
    }

    #[tokio::test]
    async fn evaluate_denies_without_resolvable_capability_token() {
        let request = EvaluateRequest {
            capability_id: "cap".into(),
            tool_server: "srv".into(),
            tool_name: "tool".into(),
            capability: None,
            metadata: None,
            arguments: None,
        };
        let (state, _) = recording_state();
        let parsed = body_json(evaluate(request, state).await).await;
        assert_eq!(parsed["decision"], "deny");
        assert!(parsed["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("capability"));
    }

    #[test]
    fn guard_set_requires_explicit_none() {
        assert_eq!(GuardSet::parse("none").unwrap(), GuardSet::None);
        assert!(GuardSet::None.guards().is_empty());
        for value in ["", "None", "default", "all"] {
            assert!(matches!(
                GuardSet::parse(value),
                Err(BootError::UnsupportedGuards(_))
            ));
        }
    }

    #[test]
    fn request_hydration_accepts_header_capability_and_arguments() {
        let issuer = Keypair::generate();
        let capability = signed_capability(&issuer);
        let mut request: EvaluateRequest = serde_json::from_value(serde_json::json!({
            "tool_server": "srv",
            "tool_name": "tool",
            "arguments": { "q": "hello" }
        }))
        .unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-chio-capability",
            serde_json::to_string(&capability).unwrap().parse().unwrap(),
        );

        hydrate_request_from_headers(&headers, &mut request).unwrap();
        assert_eq!(request.capability_id, "cap");
        assert_eq!(request.arguments, Some(serde_json::json!({ "q": "hello" })));
    }

    #[test]
    fn evaluate_request_rejects_unknown_fields() {
        for field in ["parameters", "trusted_issuers", "scope"] {
            let err = serde_json::from_value::<EvaluateRequest>(serde_json::json!({
                "tool_server": "srv",
                "tool_name": "tool",
                field: "x"
            }))
            .unwrap_err();
            assert!(
                err.to_string()
                    .starts_with(&format!("unknown field `{field}`")),
                "{err}"
            );
        }
    }

    const REPEATED_KEY: &str = "urn:chio:error:attest:signed-json-invalid-input";

    fn repeat_member(json: &str, member: &str) -> String {
        assert_eq!(json.matches(member).count(), 1, "{member} occurs once");
        json.replacen(member, &format!("{member},{member}"), 1)
    }

    #[tokio::test]
    async fn request_body_header_and_configured_tokens_refuse_a_repeated_key() {
        let issuer = Keypair::generate();
        let capability = signed_capability(&issuer);
        let token = serde_json::to_string(&capability).unwrap();
        let member = r#""id":"cap""#;

        let body = serde_json::json!({
            "capability_id": "cap",
            "tool_server": "srv",
            "tool_name": "tool",
            "capability": capability,
        })
        .to_string();
        assert_eq!(
            decode_evaluate_request(body.as_bytes())
                .unwrap()
                .capability
                .and_then(|token| token["id"].as_str().map(str::to_owned)),
            Some("cap".to_string())
        );
        assert_eq!(
            decode_evaluate_request(repeat_member(&body, member).as_bytes()).err(),
            Some(format!("failed to decode evaluate request: {REPEATED_KEY}"))
        );

        let bare = br#"{"tool_server":"srv","tool_name":"tool"}"#;
        let mut request = decode_evaluate_request(bare).unwrap();
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-chio-capability", token.parse().unwrap());
        hydrate_request_from_headers(&headers, &mut request).unwrap();
        assert_eq!(request.capability_id, "cap");

        let mut request = decode_evaluate_request(bare).unwrap();
        headers.insert(
            "x-chio-capability",
            repeat_member(&token, member).parse().unwrap(),
        );
        assert_eq!(
            hydrate_request_from_headers(&headers, &mut request).err(),
            Some(format!("invalid x-chio-capability JSON: {REPEATED_KEY}"))
        );

        request.capability_id = "cap".into();
        let configured = format!(r#"{{"cap":{token}}}"#);
        let resolved = with_env_var(CAPABILITY_TOKENS_ENV, &configured, async {
            resolve_capability(&request)
        })
        .await;
        assert_eq!(resolved.map(|token| token.id), Ok("cap".to_string()));
        let configured = format!(r#"{{"cap":{token},"cap-b":{{"id":7}}}}"#);
        let resolved = with_env_var(CAPABILITY_TOKENS_ENV, &configured, async {
            resolve_capability(&request)
        })
        .await;
        assert_eq!(resolved.map(|token| token.id), Ok("cap".to_string()));
        let configured = format!(r#"{{"cap":{token},"cap":{token}}}"#);
        let resolved = with_env_var(CAPABILITY_TOKENS_ENV, &configured, async {
            resolve_capability(&request)
        })
        .await;
        assert_eq!(
            resolved.err(),
            Some(format!("invalid {CAPABILITY_TOKENS_ENV}: {REPEATED_KEY}"))
        );
    }
}
