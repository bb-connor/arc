use super::*;
use axum::extract::OriginalUri;
use axum::http::header::{
    ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_LENGTH,
};
use axum::http::{Method, Request};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use tokio::sync::Semaphore;

const DASHBOARD_REPORT_TIMEOUT: Duration = Duration::from_secs(5);
const DASHBOARD_REPORT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const DASHBOARD_REPORT_MAX_HEADER_BYTES: usize = 16 * 1024;
const DASHBOARD_REPORT_MAX_HTTP1_HEADERS: usize = 64;
const DASHBOARD_REPORT_MAX_IN_FLIGHT: usize = 4;

type DashboardReportClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;

#[derive(Clone)]
pub(crate) struct DashboardReportBridge {
    client: DashboardReportClient,
    origin: url::Url,
    token: Arc<str>,
    validators: Arc<HashMap<&'static str, jsonschema::Validator>>,
    upstream_permits: Arc<Semaphore>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DashboardReportAvailability {
    pub(crate) observability: bool,
    pub(crate) alerts: bool,
    pub(crate) trends: bool,
    pub(crate) alert_handoff: bool,
    pub(crate) alert_delivery: bool,
    pub(crate) alert_assurance: bool,
    pub(crate) alert_assurance_export: bool,
    pub(crate) alert_assurance_replay: bool,
    pub(crate) alert_assurance_retention: bool,
    pub(crate) alert_assurance_archive: bool,
    pub(crate) alert_assurance_closeout: bool,
    pub(crate) alert_assurance_archive_package: bool,
    pub(crate) alert_assurance_archive_extraction: bool,
    pub(crate) alert_assurance_physical_archive: bool,
    pub(crate) alert_assurance_retention_handoff: bool,
    pub(crate) alert_assurance_archive_restore_drill: bool,
    pub(crate) alert_assurance_external_retention_review: bool,
}

impl DashboardReportAvailability {
    pub(crate) fn from_bridge(bridge: Option<&DashboardReportBridge>) -> Self {
        Self {
            observability: bridge.is_some(),
            alerts: false,
            trends: false,
            alert_handoff: false,
            alert_delivery: false,
            alert_assurance: false,
            alert_assurance_export: false,
            alert_assurance_replay: false,
            alert_assurance_retention: false,
            alert_assurance_archive: false,
            alert_assurance_closeout: false,
            alert_assurance_archive_package: false,
            alert_assurance_archive_extraction: false,
            alert_assurance_physical_archive: false,
            alert_assurance_retention_handoff: false,
            alert_assurance_archive_restore_drill: false,
            alert_assurance_external_retention_review: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DashboardReport {
    Observability,
}

impl DashboardReport {
    const ALL: [Self; 1] = [Self::Observability];

    fn from_path(path: &str) -> Option<Self> {
        (path == "/v1/chio/pheromone/observability").then_some(Self::Observability)
    }

    fn path(self) -> &'static str {
        match self {
            Self::Observability => "/v1/chio/pheromone/observability",
        }
    }

    fn schema(self) -> &'static str {
        match self {
            Self::Observability => "chio.pheromone.relay-observability-report.v1",
        }
    }

    fn schema_document(self) -> &'static str {
        match self {
            Self::Observability => include_str!(
                "../../../../../spec/schemas/chio-pheromone/v1/relay-observability-report.schema.json"
            ),
        }
    }
}

fn compile_dashboard_report_validators(
) -> Result<HashMap<&'static str, jsonschema::Validator>, CliError> {
    let mut validators = HashMap::with_capacity(DashboardReport::ALL.len());
    for report in DashboardReport::ALL {
        let schema: serde_json::Value =
            serde_json::from_str(report.schema_document()).map_err(|_| {
                CliError::cli_other_error(format!(
                    "dashboard report schema {} is not valid JSON",
                    report.schema()
                ))
            })?;
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(&schema)
            .map_err(|_| {
                CliError::cli_other_error(format!(
                    "dashboard report schema {} could not be compiled",
                    report.schema()
                ))
            })?;
        validators.insert(report.schema(), validator);
    }
    Ok(validators)
}

fn build_dashboard_report_client() -> Result<DashboardReportClient, CliError> {
    let connector_builder = hyper_rustls::HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(rustls::crypto::aws_lc_rs::default_provider())
        .map_err(|_| {
            CliError::cli_other_error(
                "dashboard report TLS roots could not be initialized".to_string(),
            )
        })?
        .https_or_http()
        .enable_http1()
        .enable_http2();
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    http_connector.set_connect_timeout(Some(DASHBOARD_REPORT_TIMEOUT));
    let connector = connector_builder.wrap_connector(http_connector);

    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(DASHBOARD_REPORT_MAX_IN_FLIGHT)
        .http1_max_buf_size(DASHBOARD_REPORT_MAX_HEADER_BYTES)
        .http1_max_headers(DASHBOARD_REPORT_MAX_HTTP1_HEADERS)
        .http2_max_header_list_size(DASHBOARD_REPORT_MAX_HEADER_BYTES as u32);
    Ok(builder.build(connector))
}

fn dashboard_report_authorization(token: &str) -> Option<HeaderValue> {
    let mut authorization = HeaderValue::try_from(format!("Bearer {token}")).ok()?;
    authorization.set_sensitive(true);
    Some(authorization)
}

impl DashboardReportBridge {
    pub(crate) fn from_config(config: &TrustServiceConfig) -> Result<Option<Self>, CliError> {
        let (Some(origin), Some(token)) = (
            config.dashboard_report_origin.as_deref(),
            config.dashboard_report_token.as_deref(),
        ) else {
            if config.dashboard_report_origin.is_some() || config.dashboard_report_token.is_some() {
                return Err(CliError::cli_other_error(
                    "dashboard report bridge configuration is incomplete".to_string(),
                ));
            }
            return Ok(None);
        };
        let origin = url::Url::parse(origin).map_err(|_| {
            CliError::cli_other_error("dashboard report origin is not a valid URL".to_string())
        })?;
        let client = build_dashboard_report_client()?;
        let validators = compile_dashboard_report_validators()?;
        Ok(Some(Self {
            client,
            origin,
            token: Arc::from(token),
            validators: Arc::new(validators),
            upstream_permits: Arc::new(Semaphore::new(DASHBOARD_REPORT_MAX_IN_FLIGHT)),
        }))
    }

    async fn fetch(&self, report: DashboardReport) -> Response {
        let _permit = match Arc::clone(&self.upstream_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return dashboard_report_error(StatusCode::SERVICE_UNAVAILABLE),
        };
        match tokio::time::timeout(DASHBOARD_REPORT_TIMEOUT, self.fetch_bounded(report)).await {
            Ok(response) => response,
            Err(_) => dashboard_report_error(StatusCode::BAD_GATEWAY),
        }
    }

    async fn fetch_bounded(&self, report: DashboardReport) -> Response {
        let url = match self.origin.join(report.path().trim_start_matches('/')) {
            Ok(url) => url,
            Err(_) => return dashboard_report_error(StatusCode::BAD_GATEWAY),
        };
        let authorization = match dashboard_report_authorization(&self.token) {
            Some(value) => value,
            None => return dashboard_report_error(StatusCode::BAD_GATEWAY),
        };
        let request = match Request::builder()
            .method(Method::GET)
            .uri(url.as_str())
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .header(ACCEPT_ENCODING, HeaderValue::from_static("identity"))
            .header(AUTHORIZATION, authorization)
            .body(Empty::<Bytes>::new())
        {
            Ok(request) => request,
            Err(_) => return dashboard_report_error(StatusCode::BAD_GATEWAY),
        };
        let mut upstream = match self.client.request(request).await {
            Ok(response) => response,
            Err(_) => return dashboard_report_error(StatusCode::BAD_GATEWAY),
        };

        if !upstream.status().is_success() || !upstream_headers_are_bounded_json(upstream.headers())
        {
            return dashboard_report_error(StatusCode::BAD_GATEWAY);
        }

        let mut body = Vec::new();
        while let Some(frame) = upstream.body_mut().frame().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(_) => return dashboard_report_error(StatusCode::BAD_GATEWAY),
            };
            let Ok(chunk) = frame.into_data() else {
                return dashboard_report_error(StatusCode::BAD_GATEWAY);
            };
            let Some(next_len) = body.len().checked_add(chunk.len()) else {
                return dashboard_report_error(StatusCode::BAD_GATEWAY);
            };
            if next_len > DASHBOARD_REPORT_MAX_BODY_BYTES {
                return dashboard_report_error(StatusCode::BAD_GATEWAY);
            }
            body.extend_from_slice(&chunk);
        }

        let raw = match std::str::from_utf8(&body) {
            Ok(raw) => raw,
            Err(_) => return dashboard_report_error(StatusCode::BAD_GATEWAY),
        };
        if chio_core_types::canonical_json_bytes_from_str(raw).is_err() {
            return dashboard_report_error(StatusCode::BAD_GATEWAY);
        }
        let value: serde_json::Value = match serde_json::from_str(raw) {
            Ok(value) => value,
            Err(_) => return dashboard_report_error(StatusCode::BAD_GATEWAY),
        };
        let Some(validator) = self.validators.get(report.schema()) else {
            return dashboard_report_error(StatusCode::BAD_GATEWAY);
        };
        if !validator.is_valid(&value) {
            return dashboard_report_error(StatusCode::BAD_GATEWAY);
        }

        super::dashboard_auth::with_dashboard_no_store(Json(value).into_response())
    }
}

fn upstream_headers_are_bounded_json(headers: &HeaderMap) -> bool {
    let mut bytes = 0usize;
    for (name, value) in headers {
        let Some(next) = bytes
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
        else {
            return false;
        };
        if next > DASHBOARD_REPORT_MAX_HEADER_BYTES {
            return false;
        }
        bytes = next;
    }

    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    if content_types.next().and_then(|value| value.to_str().ok()) != Some("application/json")
        || content_types.next().is_some()
    {
        return false;
    }
    if headers.contains_key(CONTENT_ENCODING) {
        return false;
    }

    let mut content_lengths = headers.get_all(CONTENT_LENGTH).iter();
    let Some(content_length) = content_lengths.next() else {
        return true;
    };
    if content_lengths.next().is_some() {
        return false;
    }
    content_length
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length <= DASHBOARD_REPORT_MAX_BODY_BYTES)
}

fn dashboard_report_error(status: StatusCode) -> Response {
    let response = plain_http_error(status, "dashboard report is unavailable");
    super::dashboard_auth::with_dashboard_no_store(response)
}

pub(crate) async fn handle_dashboard_report(
    State(state): State<TrustServiceState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> Response {
    if method != Method::GET {
        return dashboard_report_error(StatusCode::METHOD_NOT_ALLOWED);
    }
    if let Err(response) = super::dashboard_auth::validate_dashboard_session(&headers, &state) {
        return response;
    }
    if uri.query().is_some() {
        return dashboard_report_error(StatusCode::BAD_REQUEST);
    }
    let Some(report) = DashboardReport::from_path(uri.path()) else {
        return dashboard_report_error(StatusCode::NOT_FOUND);
    };
    let Some(bridge) = state.dashboard_report_bridge.as_ref() else {
        return dashboard_report_error(StatusCode::NOT_FOUND);
    };
    bridge.fetch(report).await
}

pub(crate) fn install_dashboard_report_routes(
    router: Router<TrustServiceState>,
) -> Router<TrustServiceState> {
    DashboardReport::ALL
        .into_iter()
        .fold(router, |router, report| {
            router.route(report.path(), axum::routing::any(handle_dashboard_report))
        })
}

pub(crate) fn install_dashboard_report_fallback(
    router: Router<TrustServiceState>,
) -> Router<TrustServiceState> {
    router.route(
        "/v1/chio/pheromone/{*report}",
        axum::routing::any(|| async { dashboard_report_error(StatusCode::NOT_FOUND) }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::header::{CACHE_CONTROL, SET_COOKIE};
    use chio_test_support::prelude::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    const VALID_OBSERVABILITY_REPORT: &str = include_str!(
        "../../../../../examples/chio-3vendor/fixtures/pheromone/relay/relay-observability-report.json"
    );

    fn test_bridge(origin: &str) -> DashboardReportBridge {
        DashboardReportBridge {
            client: build_dashboard_report_client().test_unwrap(),
            origin: url::Url::parse(origin).test_unwrap(),
            token: Arc::from("relay-read-secret"),
            validators: Arc::new(compile_dashboard_report_validators().test_unwrap()),
            upstream_permits: Arc::new(Semaphore::new(DASHBOARD_REPORT_MAX_IN_FLIGHT)),
        }
    }

    fn serve_once(response: String) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
        let address = listener.local_addr().test_unwrap();
        let worker = thread::spawn(move || {
            let (mut stream, _) = listener.accept().test_unwrap();
            let mut request = vec![0_u8; 16 * 1024];
            let read = stream.read(&mut request).test_unwrap();
            request.truncate(read);
            stream.write_all(response.as_bytes()).test_unwrap();
            stream.flush().test_unwrap();
            String::from_utf8(request).test_unwrap()
        });
        (format!("http://{address}/"), worker)
    }

    #[test]
    fn dashboard_report_paths_are_an_exact_get_only_allowlist() {
        let report = DashboardReport::Observability;
        assert_eq!(DashboardReport::from_path(report.path()), Some(report));
        assert_eq!(
            report.schema(),
            "chio.pheromone.relay-observability-report.v1"
        );
        for rejected in [
            "/v1/chio/pheromone/batches",
            "/v1/chio/pheromone/catchup",
            "/v1/chio/pheromone/metrics",
            "/v1/chio/pheromone/alerts",
            "/v1/chio/pheromone/trends",
            "/v1/chio/pheromone/alert-handoff",
            "/v1/chio/pheromone/alert-delivery",
            "/v1/chio/pheromone/alert-assurance",
            "/v1/chio/pheromone/alert-assurance/export",
            "/v1/chio/pheromone/alert-assurance/replay",
            "/v1/chio/pheromone/alert-assurance/retention",
            "/v1/chio/pheromone/alert-assurance/archive",
            "/v1/chio/pheromone/alert-assurance/closeout",
            "/v1/chio/pheromone/alert-assurance/archive-package",
            "/v1/chio/pheromone/alert-assurance/archive-extraction",
            "/v1/chio/pheromone/alert-assurance/physical-archive",
            "/v1/chio/pheromone/alert-assurance/retention-handoff",
            "/v1/chio/pheromone/alert-assurance/archive-restore-drill",
            "/v1/chio/pheromone/alert-assurance/external-retention-review",
            "/v1/chio/pheromone/../admin",
            "/v1/chio/pheromone/alert-assurance/export/../archive",
            "/v1/chio/pheromone/observability/",
        ] {
            assert_eq!(DashboardReport::from_path(rejected), None, "{rejected}");
        }
    }

    #[test]
    fn upstream_headers_require_one_bounded_unencoded_json_document() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1024"));
        assert!(upstream_headers_are_bounded_json(&headers));

        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        assert!(!upstream_headers_are_bounded_json(&headers));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!upstream_headers_are_bounded_json(&headers));
        headers.remove(CONTENT_ENCODING);
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("2097153"));
        assert!(!upstream_headers_are_bounded_json(&headers));
    }

    #[test]
    fn upstream_authorization_header_is_sensitive() {
        let authorization =
            dashboard_report_authorization("relay-read-secret").test_expect("authorization");
        assert!(authorization.is_sensitive());
    }

    #[tokio::test]
    async fn bridge_load_sheds_before_contacting_upstream_when_saturated() {
        let listener = TcpListener::bind("127.0.0.1:0").test_unwrap();
        listener.set_nonblocking(true).test_unwrap();
        let origin = format!("http://{}/", listener.local_addr().test_unwrap());
        let bridge = test_bridge(&origin);
        let permits = Arc::clone(&bridge.upstream_permits)
            .try_acquire_many_owned(DASHBOARD_REPORT_MAX_IN_FLIGHT as u32)
            .test_unwrap();

        let response = bridge.fetch(DashboardReport::Observability).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
        drop(permits);
    }

    #[tokio::test]
    async fn bridge_rejects_http1_headers_at_the_transport_limit() {
        let oversized_header = "a".repeat(DASHBOARD_REPORT_MAX_HEADER_BYTES);
        let (origin, worker) = serve_once(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Oversized: {oversized_header}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ));

        let response = test_bridge(&origin)
            .fetch(DashboardReport::Observability)
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let _ = worker.join();
    }

    #[tokio::test]
    async fn bridge_sends_only_the_server_read_token_and_synthesizes_response_headers() {
        let body = VALID_OBSERVABILITY_REPORT;
        let (origin, worker) = serve_once(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: upstream=secret\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ));
        let response = test_bridge(&origin)
            .fetch(DashboardReport::Observability)
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
        assert!(response.headers().get(SET_COOKIE).is_none());
        let response_body = to_bytes(response.into_body(), DASHBOARD_REPORT_MAX_BODY_BYTES)
            .await
            .test_unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response_body).test_unwrap()["schema"],
            DashboardReport::Observability.schema()
        );

        let request = worker.join().test_unwrap();
        assert!(request.starts_with("GET /v1/chio/pheromone/observability HTTP/1.1\r\n"));
        let normalized = request
            .replace("Authorization:", "authorization:")
            .replace("Cookie:", "cookie:")
            .replace("Set-Cookie:", "set-cookie:");
        assert!(normalized.contains("\r\nauthorization: Bearer relay-read-secret\r\n"));
        assert!(!normalized.contains("\r\ncookie:"));
        assert!(!normalized.contains("\r\nset-cookie:"));
    }

    #[tokio::test]
    async fn bridge_rejects_redirects_without_contacting_the_destination() {
        let destination = TcpListener::bind("127.0.0.1:0").test_unwrap();
        destination.set_nonblocking(true).test_unwrap();
        let location = format!(
            "http://{}/v1/chio/pheromone/observability",
            destination.local_addr().test_unwrap()
        );
        let (origin, worker) = serve_once(format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ));
        let response = test_bridge(&origin)
            .fetch(DashboardReport::Observability)
            .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        drop(worker.join().test_unwrap());
        assert!(matches!(
            destination.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[tokio::test]
    async fn bridge_rejects_oversize_not_found_and_wrong_schema_responses() {
        let cases = [
            (
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2097153\r\nConnection: close\r\n\r\n".to_string(),
                StatusCode::BAD_GATEWAY,
            ),
            (
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_string(),
                StatusCode::BAD_GATEWAY,
            ),
            ({
                let body = r#"{"schema":"chio.pheromone.relay-alert-report.v1"}"#;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }, StatusCode::BAD_GATEWAY),
        ];

        for (raw_response, expected) in cases {
            let (origin, worker) = serve_once(raw_response);
            let response = test_bridge(&origin)
                .fetch(DashboardReport::Observability)
                .await;
            assert_eq!(response.status(), expected);
            drop(worker.join().test_unwrap());
        }
    }

    #[tokio::test]
    async fn bridge_rejects_structurally_invalid_and_duplicate_key_reports() {
        let valid: serde_json::Value =
            serde_json::from_str(VALID_OBSERVABILITY_REPORT).test_unwrap();
        let mut missing_required = valid.clone();
        missing_required
            .as_object_mut()
            .test_expect("observability object")
            .remove("directory");
        let mut wrong_type = valid.clone();
        wrong_type["accepted"] = serde_json::Value::String("true".to_string());
        let mut unknown_field = valid;
        unknown_field["queue"]["upstreamToken"] =
            serde_json::Value::String("must-not-pass".to_string());
        let duplicate_key = VALID_OBSERVABILITY_REPORT.replacen(
            "\"schema\": \"chio.pheromone.relay-observability-report.v1\",",
            "\"schema\": \"chio.pheromone.relay-observability-report.v1\",\n  \"schema\": \"chio.pheromone.relay-observability-report.v1\",",
            1,
        );
        let bodies = [
            serde_json::to_string(&missing_required).test_unwrap(),
            serde_json::to_string(&wrong_type).test_unwrap(),
            serde_json::to_string(&unknown_field).test_unwrap(),
            duplicate_key,
        ];

        for body in bodies {
            let (origin, worker) = serve_once(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            ));
            let response = test_bridge(&origin)
                .fetch(DashboardReport::Observability)
                .await;
            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            drop(worker.join().test_unwrap());
        }
    }
}
