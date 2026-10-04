//! Proxy admission must agree with decoded upstream route interpretation.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p0p1_encoded_paths_cannot_change_upstream_authority() {
    let paths = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let recorded = paths.clone();
    // Model an upstream router that percent-decodes and normalizes before
    // dispatching. Only loopback traffic is used by this regression.
    let upstream = Router::new().fallback(any(move |request: Request<Body>| {
        let decoded = percent_encoding::percent_decode_str(request.uri().path())
            .decode_utf8()
            .test_unwrap();
        let mut decoded = decoded.into_owned();
        while decoded.contains("//") {
            decoded = decoded.replace("//", "/");
        }
        let normalized = url::Url::parse(&format!("http://upstream{decoded}")).test_unwrap();
        recorded.lock().test_unwrap().push(normalized.path().into());
        async { StatusCode::OK }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .test_unwrap();
    let url = format!("http://{}", listener.local_addr().test_unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await });
    // Establish the actual interpretation difference independently of admission.
    reqwest::get(format!("{url}/safe/%2e%2e%2fadmin"))
        .await
        .test_unwrap();
    assert_eq!(*paths.lock().test_unwrap(), vec!["/admin"]);
    paths.lock().test_unwrap().clear();
    let mut routes = ProtectProxy::routes_from_spec(
        "openapi: 3.1.0\ninfo: {title: Path, version: '1'}\npaths:\n  /safe/{id}:\n    get:\n      responses: {'200': {description: ok}}\n  /safe/{id}/{tail}:\n    get:\n      responses: {'200': {description: ok}}\n",
    ).test_unwrap();
    routes.push(crate::evaluator::RouteEntry {
        pattern: "/safe/admin".into(),
        method: chio_http_core::HttpMethod::Get,
        operation_id: None,
        policy: PolicyDecision::DenyByDefault,
    });
    let app = build_app(test_state(routes, url));
    for path in [
        "/safe//admin",
        "/safe/admin/",
        "/safe/%2e%2e%2fadmin",
        "/safe/..%2Fadmin",
        "/safe/..%5cadmin",
        "/safe/%252e%252e%252fadmin",
        "/safe/%61dmin",
        "/safe/ad%6din",
        "/safe/%2e%2e/admin",
        "/safe/../admin",
        "/safe/%2E./admin",
        "/safe/%00admin",
        "/safe/%3fadmin",
        "/safe/%23admin",
        "/safe/%GG",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .test_unwrap(),
            )
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert!(
            paths.lock().test_unwrap().is_empty(),
            "{path} reached upstream"
        );
    }
    for path in [
        "/safe/alice",
        "/safe/Alice%20Smith",
        "/safe/%E2%82%AC",
        "/safe/%61lice",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .test_unwrap(),
            )
            .await
            .test_unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    assert_eq!(paths.lock().test_unwrap().len(), 4);
    server.abort();
}
