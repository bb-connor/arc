//! Real upstream observations for the reserved control-credential boundary.

use super::*;
use axum::http::{HeaderMap, HeaderValue};

const SECRET: &str = "sidecar-control-containment-test-secret";

struct TaskGuard<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for TaskGuard<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Upstream {
    address: SocketAddr,
    received: Arc<Mutex<Vec<HeaderMap>>>,
    _task: TaskGuard<std::io::Result<()>>,
}

impl Upstream {
    async fn start() -> Self {
        // Binding failure fails the test; this boundary has no platform skip.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .test_unwrap();
        let address = listener.local_addr().test_unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let handler_received = Arc::clone(&received);
        let app = Router::new().fallback(any(move |headers: HeaderMap| {
            let received = Arc::clone(&handler_received);
            async move {
                received.lock().await.push(headers);
                (StatusCode::OK, "upstream response")
            }
        }));
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        Self {
            address,
            received,
            _task: TaskGuard(task),
        }
    }

    fn proxy_state(&self, token: Option<&str>) -> Arc<ProxyState> {
        let mut state = test_state(Vec::new(), format!("http://{}", self.address));
        Arc::get_mut(&mut state).test_unwrap().sidecar_control_token = token.map(str::to_owned);
        state
    }
}

fn data_request(path: &str, headers: &[(&str, HeaderValue)]) -> Request<Body> {
    let mut request = Request::builder()
        .uri(path)
        .body(Body::empty())
        .test_unwrap();
    for (name, value) in headers {
        request.headers_mut().append(
            axum::http::HeaderName::from_bytes(name.as_bytes()).test_unwrap(),
            value.clone(),
        );
    }
    request
}

async fn call_proxy(state: &Arc<ProxyState>, request: Request<Body>) -> Response {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        build_app(Arc::clone(state)).oneshot(request),
    )
    .await
    .test_unwrap()
    .test_unwrap()
}

async fn assert_contained(headers: &[(&str, HeaderValue)], path: &str) {
    let upstream = Upstream::start().await;
    let state = upstream.proxy_state(Some(SECRET));
    let response = call_proxy(&state, data_request(path, headers)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = to_bytes(response.into_body(), 4096).await.test_unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
    assert_eq!(body["error"], "chio_control_credential_wrong_route");
    assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    assert!(upstream.received.lock().await.is_empty());
    assert!(state.receipt_log.lock().await.receipts.is_empty());
    assert!(state.tool_receipt_log.lock().await.receipts.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_bearer_is_denied_before_upstream_dispatch() {
    assert_contained(
        &[(
            "authorization",
            format!("Bearer {SECRET}").parse().test_unwrap(),
        )],
        "/pets",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_bearer_cannot_leak_reserved_credential() {
    for value in [
        format!("bEaReR {SECRET}"),
        format!("Bearer  {SECRET} "),
        format!("Bearer\t{SECRET}"),
        format!("Bearer \"{SECRET}\""),
        format!("Bearer other-token, Bearer {SECRET}"),
        format!("Bearer {SECRET}, Bearer other-token"),
        format!("Bearer prefix-{SECRET}-suffix"),
    ] {
        assert_contained(&[("authorization", value.parse().test_unwrap())], "/pets").await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_headers_cannot_hide_reserved_credential() {
    let reserved = HeaderValue::from_str(&format!("Bearer {SECRET}")).test_unwrap();
    let ordinary = HeaderValue::from_static("Bearer upstream-token");
    for values in [
        [reserved.clone(), ordinary.clone()],
        [ordinary, reserved.clone()],
        [reserved.clone(), reserved],
    ] {
        assert_contained(
            &[
                ("authorization", values[0].clone()),
                ("authorization", values[1].clone()),
            ],
            "/pets",
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_authorization_headers_cannot_forward_control_credential() {
    for name in [
        "x-api-key",
        "cookie",
        "x-chio-sidecar-control-token",
        "x-custom",
    ] {
        assert_contained(
            &[(
                name,
                format!("prefix={SECRET}; suffix=value")
                    .parse()
                    .test_unwrap(),
            )],
            "/pets",
        )
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_utf8_header_cannot_hide_control_credential() {
    let mut bytes = vec![0xff];
    bytes.extend_from_slice(SECRET.as_bytes());
    bytes.push(0xfe);
    assert_contained(
        &[("x-custom", HeaderValue::from_bytes(&bytes).test_unwrap())],
        "/pets",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_operator_path_cannot_fall_through_with_control_credential() {
    assert_contained(
        &[(
            "authorization",
            format!("Bearer {SECRET}").parse().test_unwrap(),
        )],
        "/v1/capabilities/typo",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_upstream_authentication_is_preserved() {
    let upstream = Upstream::start().await;
    let state = upstream.proxy_state(Some(SECRET));
    for value in [
        "Bearer upstream-token",
        "Basic dXNlcjpwYXNz",
        "Digest username=\"operator\", nonce=\"upstream\"",
    ] {
        let response = call_proxy(
            &state,
            data_request("/pets", &[("authorization", value.parse().test_unwrap())]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            upstream.received.lock().await.last().test_unwrap()[AUTHORIZATION],
            value
        );
    }
    assert_eq!(upstream.received.lock().await.len(), 3);
    assert_eq!(state.receipt_log.lock().await.receipts.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_control_configuration_preserves_proxy_authentication() {
    for token in [None, Some(""), Some(" \t\n")] {
        let upstream = Upstream::start().await;
        let state = upstream.proxy_state(token);
        let value = HeaderValue::from_str(&format!("Bearer {SECRET}")).test_unwrap();
        let response = call_proxy(
            &state,
            data_request("/pets", &[("authorization", value.clone())]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(upstream.received.lock().await[0][AUTHORIZATION], value);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrelated_duplicate_and_binary_headers_remain_byte_preserved() {
    let upstream = Upstream::start().await;
    let state = upstream.proxy_state(Some(SECRET));
    let binary = HeaderValue::from_bytes(&[0xff, b'a', 0xfe]).test_unwrap();
    let response = call_proxy(
        &state,
        data_request(
            "/pets",
            &[
                ("x-upstream", HeaderValue::from_static("first")),
                ("x-upstream", HeaderValue::from_static("second")),
                ("x-binary", binary.clone()),
            ],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let observed = upstream.received.lock().await;
    assert_eq!(
        observed[0].get_all("x-upstream").iter().collect::<Vec<_>>(),
        vec!["first", "second"]
    );
    assert_eq!(observed[0]["x-binary"], binary);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn excessive_header_scan_is_denied_before_upstream_dispatch() {
    let upstream = Upstream::start().await;
    let state = upstream.proxy_state(Some(SECRET));
    let response = call_proxy(
        &state,
        data_request(
            "/pets",
            &[("x-padding", "x".repeat(65_537).parse().test_unwrap())],
        ),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    assert!(upstream.received.lock().await.is_empty());
    assert!(state.receipt_log.lock().await.receipts.is_empty());
}

#[tokio::test]
async fn invalid_control_configuration_rejects_before_runtime_io() {
    for token in [
        "x".repeat(513),
        "invalid token".into(),
        "invalid,token".into(),
        "=padding".into(),
        "foo=bar".into(),
        "non-ascii-\u{e9}".into(),
    ] {
        let directory = tempfile::tempdir().test_unwrap();
        let receipt_db = directory.path().join("state/receipts.db");
        let observed = std::sync::atomic::AtomicBool::new(false);
        let error = ProtectProxy::new(ProtectConfig {
            upstream: "http://127.0.0.1:1".into(),
            spec_content: None,
            spec_path: Some(
                directory
                    .path()
                    .join("missing-spec.yaml")
                    .to_string_lossy()
                    .into_owned(),
            ),
            listen_addr: "127.0.0.1:0".into(),
            receipt_db: Some(receipt_db.to_string_lossy().into_owned()),
            allow_ephemeral_receipts: false,
            sidecar_control_token: Some(token.clone()),
            signer_seed_hex: None,
            trusted_capability_issuers: Vec::new(),
            control_url: None,
            control_token: None,
            budget_db: None,
            revocation_db: None,
            require_nonce: false,
            allow_advisory: false,
            upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
        })
        .run_with_observer(|_| observed.store(true, std::sync::atomic::Ordering::SeqCst))
        .await
        .test_unwrap_err();
        assert!(
            matches!(&error, ProtectError::Config(message) if message.contains("control token")),
            "{error}"
        );
        assert!(!error.to_string().contains(&token));
        assert!(!observed.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!receipt_db.parent().test_unwrap().exists());
    }
}

#[test]
fn configuration_grammar_and_size_bounds_are_shared_by_authentication() {
    for token in ["a", "aZ09-._~+/", "YQ==", &"x".repeat(512)] {
        assert!(validate_sidecar_control_token(Some(token)).is_ok());
        let request = data_request(
            "/approvals/pending",
            &[(
                "authorization",
                format!("Bearer {token}").parse().test_unwrap(),
            )],
        );
        assert!(require_sidecar_control_request(&request, Some(token)).is_ok());
    }
    for token in [
        "=padding",
        "abc=def",
        "two words",
        "one,two",
        "one\"two",
        &"x".repeat(513),
    ] {
        assert!(validate_sidecar_control_token(Some(token)).is_err());
        let request = data_request(
            "/approvals/pending",
            &[(
                "authorization",
                format!("Bearer {token}").parse().test_unwrap(),
            )],
        );
        assert!(require_sidecar_control_request(&request, Some(token)).is_err());
        assert!(matches!(
            check_proxy_control_credential(request.headers(), Some(token)),
            Err(ProxyControlCredentialError::InvalidConfiguration),
        ));
    }
}

#[test]
fn exact_scan_budget_admits_and_counts_every_duplicate_field() {
    let mut headers = HeaderMap::new();
    headers.append(
        "x",
        HeaderValue::from_str(&"x".repeat(32_767)).test_unwrap(),
    );
    headers.append(
        "x",
        HeaderValue::from_str(&"y".repeat(32_767)).test_unwrap(),
    );
    assert!(check_proxy_control_credential(&headers, Some(SECRET)).is_ok());
    headers.append("x", HeaderValue::from_static(""));
    assert!(matches!(
        check_proxy_control_credential(&headers, Some(SECRET)),
        Err(ProxyControlCredentialError::HeaderBudgetExceeded),
    ));
}

#[test]
fn maximum_token_and_header_sizes_are_admitted_without_a_match() {
    let token = "z".repeat(512);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x",
        HeaderValue::from_str(&"x".repeat(65_535)).test_unwrap(),
    );
    assert!(check_proxy_control_credential(&headers, Some(&token)).is_ok());
}

#[test]
fn complete_control_bytes_are_detected_at_every_offset_but_near_matches_are_not() {
    for offset in 0..32 {
        let mut header = vec![b'x'; offset];
        header.extend_from_slice(SECRET.as_bytes());
        header.extend_from_slice(&[b'x'; 32]);
        let mut headers = HeaderMap::new();
        headers.insert("x", HeaderValue::from_bytes(&header).test_unwrap());
        assert!(matches!(
            check_proxy_control_credential(&headers, Some(SECRET)),
            Err(ProxyControlCredentialError::ReservedCredential),
        ));
    }
    for position in 0..SECRET.len() {
        let mut header = SECRET.as_bytes().to_vec();
        header[position] = b'Z';
        let mut headers = HeaderMap::new();
        headers.insert("x", HeaderValue::from_bytes(&header).test_unwrap());
        assert!(check_proxy_control_credential(&headers, Some(SECRET)).is_ok());
    }
    for value in ["", &SECRET[..SECRET.len() - 1]] {
        let mut headers = HeaderMap::new();
        headers.insert("x", HeaderValue::from_str(value).test_unwrap());
        assert!(check_proxy_control_credential(&headers, Some(SECRET)).is_ok());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normalized_configuration_is_identical_for_authentication_and_containment() {
    let upstream = Upstream::start().await;
    let token = format!(" \t{SECRET}\n");
    let state = upstream.proxy_state(Some(&token));
    let headers = [(
        "authorization",
        format!("Bearer {SECRET}").parse().test_unwrap(),
    )];
    let allowed = call_proxy(&state, data_request("/approvals/pending", &headers)).await;
    assert_eq!(allowed.status(), StatusCode::OK);
    let denied = call_proxy(&state, data_request("/pets", &headers)).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    assert!(upstream.received.lock().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serving_proxy_rejects_control_headers_without_waiting_for_request_body() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let upstream = Upstream::start().await;
    let (ready, listening) = tokio::sync::oneshot::channel();
    let proxy = ProtectProxy::new(ProtectConfig {
        upstream: format!("http://{}", upstream.address),
        spec_content: Some(PETSTORE_YAML.into()),
        spec_path: None,
        listen_addr: "127.0.0.1:0".into(),
        receipt_db: None,
        allow_ephemeral_receipts: true,
        sidecar_control_token: Some(SECRET.into()),
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        control_url: None,
        control_token: None,
        budget_db: None,
        revocation_db: None,
        require_nonce: false,
        allow_advisory: false,
        upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    });
    let _proxy_task = TaskGuard(tokio::spawn(proxy.run_with_observer(move |address| {
        let _ = ready.send(address);
    })));
    let address = tokio::time::timeout(std::time::Duration::from_secs(5), listening)
        .await
        .test_unwrap()
        .test_unwrap();
    let mut connection = tokio::net::TcpStream::connect(address).await.test_unwrap();
    // Advertise a body and withhold it. Rejection must not await its first byte.
    connection.write_all(format!(
        "POST /pets HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {SECRET}\r\nContent-Length: 1\r\nConnection: close\r\n\r\n"
    ).as_bytes()).await.test_unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connection.read_to_end(&mut response),
    )
    .await
    .test_unwrap()
    .test_unwrap();
    let text = String::from_utf8(response).test_unwrap();
    assert!(text.starts_with("HTTP/1.1 403"));
    assert!(text.contains("chio_control_credential_wrong_route"));
    assert!(!text.contains(SECRET));
    assert!(upstream.received.lock().await.is_empty());
}
