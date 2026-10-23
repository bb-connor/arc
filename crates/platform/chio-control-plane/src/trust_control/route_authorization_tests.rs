use std::collections::BTreeMap;

use axum::body::Body;
use axum::extract::Query;
use axum::http::{HeaderValue, Request as HttpRequest};
use axum::routing::{MethodFilter, MethodRouter};
use axum::{Extension, Router};
use chio_core::crypto::Keypair;
use chio_security_types::clock::FixedClock;
use chio_test_support::prelude::*;
use tower::ServiceExt;

use super::super::caller_credentials::tests::{
    config, credential, fresh_nonce, peer, signed_peer_headers, signed_peer_headers_for,
    DEPLOYMENT, SELF_NODE,
};
use super::super::caller_credentials::{
    sign_cluster_peer_request, PeerAddressing, TrustAccess, TrustAccessConfig,
};
use super::*;

const NOW: u64 = 1_792_234_800;
const NODE_B: &str = "https://node-b.example:9101";
const NODE_C: &str = "https://node-c.example:9101";

const ROUTER_SOURCES: [&str; 2] = [
    include_str!("service_runtime/router.rs"),
    include_str!("health.rs"),
];

fn strip_line_comments(text: &str) -> String {
    text.lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

fn balanced_args(text: &str, open: usize) -> &str {
    let mut depth = 0_usize;
    for (offset, byte) in text.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return &text[open + 1..open + offset];
                }
            }
            _ => {}
        }
    }
    &text[open + 1..]
}

fn method_registrations(handlers: &str) -> Vec<&'static str> {
    let bytes = handlers.as_bytes();
    let mut found = Vec::new();
    for (name, method) in [
        ("get(", "GET"),
        ("post(", "POST"),
        ("put(", "PUT"),
        ("delete(", "DELETE"),
        ("patch(", "PATCH"),
    ] {
        for (index, _) in handlers.match_indices(name) {
            let preceded_by_ident =
                index > 0 && (bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_');
            if !preceded_by_ident {
                found.push(method);
            }
        }
    }
    found
}

/// Every `(method, path expression)` the trust-control router registers.
fn router_registrations() -> Vec<(String, String)> {
    let mut registrations = Vec::new();
    for source in ROUTER_SOURCES {
        let text = strip_line_comments(source);
        for (index, _) in text.match_indices(".route(") {
            let args = balanced_args(&text, index + ".route".len());
            let Some((path, handlers)) = args.split_once(',') else {
                panic!("route registration without handlers: {args}");
            };
            for method in method_registrations(handlers) {
                registrations.push((method.to_string(), path.trim().to_string()));
            }
        }
    }
    registrations.sort();
    registrations
}

#[test]
fn route_table_covers_every_router_route() {
    let router = router_registrations();
    let mut table: Vec<(String, String)> = ROUTE_TABLE
        .iter()
        .map(|rule| {
            (
                rule.method.as_str().to_string(),
                rule.path_source.to_string(),
            )
        })
        .collect();
    table.sort();
    assert_eq!(router.len(), 211);
    let mut unique = router.clone();
    unique.dedup();
    assert_eq!(
        unique.len(),
        router.len(),
        "a router route is registered twice"
    );
    assert_eq!(
        router, table,
        "every router route has exactly one table row"
    );
}

#[test]
fn route_table_rows_are_well_formed() {
    let mut keys = std::collections::BTreeSet::new();
    for rule in ROUTE_TABLE {
        assert!(
            keys.insert((rule.method, rule.path)),
            "duplicate row {} {}",
            rule.method.as_str(),
            rule.path
        );
        let internal_path = rule.path.starts_with("/v1/internal/");
        assert_eq!(
            internal_path,
            rule.listener == Listener::Internal,
            "{}",
            rule.path
        );
        match rule.credential {
            RouteCredential::Caller
            | RouteCredential::Deployment
            | RouteCredential::FindingBuyerOrCaller => {
                let scope = rule.scope.test_unwrap();
                assert!(!scope.is_cluster(), "{}", rule.path);
                assert_ne!(rule.tenant, TenantRule::NotApplicable, "{}", rule.path);
            }
            RouteCredential::Peer => {
                assert!(rule.scope.test_unwrap().is_cluster(), "{}", rule.path);
                assert_eq!(rule.listener, Listener::Internal, "{}", rule.path);
                assert_eq!(rule.tenant, TenantRule::NotApplicable, "{}", rule.path);
            }
            RouteCredential::Anonymous
            | RouteCredential::FindingSeller
            | RouteCredential::WalletHolder => {
                assert_eq!(rule.scope, None, "{}", rule.path);
                assert_eq!(rule.listener, Listener::Public, "{}", rule.path);
                assert_eq!(rule.tenant, TenantRule::NotApplicable, "{}", rule.path);
            }
        }
    }
}

#[test]
fn openings_bearing_peer_routes_require_the_openings_scope() {
    let openings: Vec<&str> = ROUTE_TABLE
        .iter()
        .filter(|rule| rule.scope == Some(Scope::ClusterOpeningsReplicate))
        .map(|rule| rule.path)
        .collect();
    assert_eq!(
        openings,
        vec![
            "/v1/internal/cluster/snapshot",
            "/v1/internal/receipts/tools/delta"
        ]
    );
}

struct Fixture {
    public: Router,
    internal: Router,
    node_b: Keypair,
    node_c: Keypair,
}

fn non_cluster_scopes() -> impl Iterator<Item = Scope> {
    Scope::ALL
        .iter()
        .copied()
        .filter(|scope| !scope.is_cluster())
}

fn scope_names(scopes: impl Iterator<Item = Scope>) -> Vec<&'static str> {
    scopes.map(Scope::as_str).collect()
}

fn fixture_config(node_b: &Keypair, node_c: &Keypair) -> String {
    let all = scope_names(non_cluster_scopes());
    let reads = scope_names(non_cluster_scopes().filter(|scope| scope.as_str().ends_with(":read")));
    let mut body = String::new();
    body.push_str(&credential(
        "operator",
        "caller",
        "operator-secret",
        &all,
        None,
    ));
    body.push_str(&credential(
        "kernel",
        "deployment",
        "kernel-secret",
        &all,
        None,
    ));
    body.push_str(&credential(
        "readers",
        "caller",
        "readers-secret",
        &reads,
        None,
    ));
    body.push_str(&credential(
        "tenant-a",
        "deployment",
        "tenant-a-secret",
        &all,
        Some("tenant-a"),
    ));
    for scope in non_cluster_scopes() {
        let id = scope.as_str().replace(':', ".");
        body.push_str(&credential(
            &format!("only.{id}"),
            "deployment",
            &format!("only-{id}"),
            &[scope.as_str()],
            None,
        ));
        let rest = scope_names(non_cluster_scopes().filter(|other| *other != scope));
        body.push_str(&credential(
            &format!("all-but.{id}"),
            "deployment",
            &format!("all-but-{id}"),
            &rest,
            None,
        ));
    }
    body.push_str(&peer(
        NODE_B,
        node_b,
        &["cluster:replicate", "cluster-openings:replicate"],
    ));
    body.push_str(&peer(NODE_C, node_c, &["cluster:replicate"]));
    config(&body)
}

#[derive(serde::Deserialize)]
struct TenantQuery {
    tenant: Option<String>,
}

async fn echo(
    Extension(grant): Extension<RouteGrant>,
    Query(query): Query<TenantQuery>,
) -> Response {
    let body = match grant {
        RouteGrant::Unchanged => "unchanged".to_string(),
        RouteGrant::Caller(caller) => match caller.tenant_for_request(query.tenant.as_deref()) {
            Ok(_) => format!("caller:{}", caller.credential_id),
            Err(error) => return error.into_response(),
        },
        RouteGrant::Peer(peer) => format!("peer:{}", peer.node_id),
    };
    (StatusCode::OK, body).into_response()
}

fn method_filter(method: RouteMethod) -> MethodFilter {
    match method {
        RouteMethod::Get => MethodFilter::GET,
        RouteMethod::Post => MethodFilter::POST,
        RouteMethod::Put => MethodFilter::PUT,
        RouteMethod::Delete => MethodFilter::DELETE,
    }
}

fn mounted_router(authorizer: RouteAuthorizer) -> Router {
    let mut by_path: BTreeMap<&str, MethodRouter> = BTreeMap::new();
    for rule in ROUTE_TABLE {
        let entry = by_path.remove(rule.path).unwrap_or_else(MethodRouter::new);
        by_path.insert(rule.path, entry.on(method_filter(rule.method), echo));
    }
    let mut router = Router::new().route("/v1/unlisted", axum::routing::get(echo));
    for (path, methods) in by_path {
        router = router.route(path, methods);
    }
    router.route_layer(axum::middleware::from_fn_with_state(
        Arc::new(authorizer),
        authorize_route,
    ))
}

fn authorizer_for(listener: Listener, text: &str) -> RouteAuthorizer {
    let config = TrustAccessConfig::from_toml_str(text).test_unwrap();
    let node_keypair = config.peers.identity().map(|_| Keypair::generate());
    let access = TrustAccess::from_parts(config, node_keypair).test_unwrap();
    RouteAuthorizer::new(listener, Arc::new(access), Arc::new(FixedClock::new(NOW)))
}

fn fixture() -> Fixture {
    let node_b = Keypair::generate();
    let node_c = Keypair::generate();
    let text = fixture_config(&node_b, &node_c);
    Fixture {
        public: mounted_router(authorizer_for(Listener::Public, &text)),
        internal: mounted_router(authorizer_for(Listener::Internal, &text)),
        node_b,
        node_c,
    }
}

fn concrete(path: &str) -> String {
    let mut out = String::new();
    let mut in_param = false;
    for character in path.chars() {
        match character {
            '{' => {
                in_param = true;
                out.push('p');
            }
            '}' => in_param = false,
            _ if in_param => {}
            _ => out.push(character),
        }
    }
    out
}

fn bearer(secret: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {secret}")).test_unwrap(),
    );
    headers
}

fn scope_secret(prefix: &str, scope: Scope) -> String {
    format!("{prefix}-{}", scope.as_str().replace(':', "."))
}

async fn call(
    router: &Router,
    rule: &RouteRule,
    query: &str,
    headers: HeaderMap,
) -> (StatusCode, String) {
    send(
        router,
        rule.method.as_str(),
        rule,
        query,
        headers,
        Vec::new(),
    )
    .await
}

async fn send(
    router: &Router,
    method: &str,
    rule: &RouteRule,
    query: &str,
    headers: HeaderMap,
    body: Vec<u8>,
) -> (StatusCode, String) {
    let uri = if query.is_empty() {
        concrete(rule.path)
    } else {
        format!("{}?{query}", concrete(rule.path))
    };
    let mut request = HttpRequest::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .test_unwrap();
    *request.headers_mut() = headers;
    let response = router.clone().oneshot(request).await.test_unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .test_unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn peer_headers(keypair: &Keypair, node: &str, rule: &RouteRule, query: &str) -> HeaderMap {
    signed_request_headers(keypair, node, rule.method.as_str(), rule, query, b"")
}

fn signed_request_headers(
    keypair: &Keypair,
    node: &str,
    method: &str,
    rule: &RouteRule,
    query: &str,
    body: &[u8],
) -> HeaderMap {
    let path = concrete(rule.path);
    let target = PeerRequestTarget {
        method,
        path: &path,
        query,
        body,
    };
    signed_peer_headers(
        keypair,
        node,
        &target,
        i64::try_from(NOW).test_unwrap(),
        Some(4),
    )
}

fn rows(credentials: &[RouteCredential]) -> impl Iterator<Item = &'static RouteRule> + '_ {
    ROUTE_TABLE
        .iter()
        .filter(move |rule| credentials.contains(&rule.credential))
}

fn router_for<'a>(fixture: &'a Fixture, rule: &RouteRule) -> &'a Router {
    match rule.listener {
        Listener::Public => &fixture.public,
        Listener::Internal => &fixture.internal,
    }
}

const CREDENTIAL_ROUTES: [RouteCredential; 2] =
    [RouteCredential::Caller, RouteCredential::Deployment];

#[tokio::test]
async fn unknown_route_refuses() {
    let fixture = fixture();
    let rule = RouteRule {
        method: RouteMethod::Get,
        path: "/v1/unlisted",
        path_source: "\"/v1/unlisted\"",
        listener: Listener::Public,
        credential: RouteCredential::Anonymous,
        scope: None,
        tenant: TenantRule::NotApplicable,
    };
    for router in [&fixture.public, &fixture.internal] {
        let (status, body) = call(router, &rule, "", bearer("operator-secret")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains("route is not served on this trust-control listener"));
    }
}

#[tokio::test]
async fn anonymous_and_self_authenticating_routes_pass_unchanged() {
    let fixture = fixture();
    for rule in rows(&[
        RouteCredential::Anonymous,
        RouteCredential::FindingSeller,
        RouteCredential::WalletHolder,
    ]) {
        let (status, body) = call(&fixture.public, rule, "", HeaderMap::new()).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "unchanged"),
            "{}",
            rule.path
        );
    }
}

#[tokio::test]
async fn scope_required_per_route() {
    let fixture = fixture();
    for rule in rows(&CREDENTIAL_ROUTES) {
        let scope = rule.scope.test_unwrap();
        let router = router_for(&fixture, rule);
        let (status, body) = call(router, rule, "", bearer(&scope_secret("only", scope))).await;
        assert_eq!(status, StatusCode::OK, "{} {}", rule.path, body);
        let (status, body) = call(router, rule, "", bearer(&scope_secret("all-but", scope))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", rule.path);
        assert!(
            body.contains(&format!("lacks scope {scope}")),
            "{} {body}",
            rule.path
        );
    }
}

#[tokio::test]
async fn read_scope_cannot_write() {
    let fixture = fixture();
    for rule in rows(&CREDENTIAL_ROUTES) {
        let scope = rule.scope.test_unwrap();
        let router = router_for(&fixture, rule);
        let (status, body) = call(router, rule, "", bearer("readers-secret")).await;
        if scope.as_str().ends_with(":read") && rule.credential == RouteCredential::Caller {
            assert_eq!(status, StatusCode::OK, "{} {body}", rule.path);
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "{} {body}", rule.path);
        }
    }
}

#[tokio::test]
async fn write_scope_cannot_read_other_family() {
    let fixture = fixture();
    let writes: Vec<Scope> = non_cluster_scopes()
        .filter(|scope| !scope.as_str().ends_with(":read"))
        .collect();
    for rule in rows(&CREDENTIAL_ROUTES) {
        let scope = rule.scope.test_unwrap();
        if !scope.as_str().ends_with(":read") {
            continue;
        }
        let router = router_for(&fixture, rule);
        for write in &writes {
            let (status, body) =
                call(router, rule, "", bearer(&scope_secret("only", *write))).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{} {write} {body}",
                rule.path
            );
            assert!(body.contains(&format!("lacks scope {scope}")), "{body}");
        }
    }
}

#[tokio::test]
async fn tenant_credential_refused_on_deployment_only_routes() {
    let fixture = fixture();
    for rule in rows(&CREDENTIAL_ROUTES).filter(|rule| rule.tenant == TenantRule::DeploymentOnly) {
        let (status, body) = call(
            router_for(&fixture, rule),
            rule,
            "",
            bearer("tenant-a-secret"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", rule.path);
        assert!(
            body.contains("tenant credential cannot use a deployment-only route"),
            "{} {body}",
            rule.path
        );
    }
}

#[tokio::test]
async fn tenant_credential_cross_tenant_read_refused() {
    let fixture = fixture();
    let scoped: Vec<&RouteRule> = rows(&CREDENTIAL_ROUTES)
        .filter(|rule| rule.tenant == TenantRule::TenantScoped)
        .collect();
    let scoped_paths: Vec<&str> = scoped.iter().map(|rule| rule.path).collect();
    for path in [
        "/v1/receipts/query",
        "/v1/receipts/tools",
        "/v1/agents/{subject_key}/receipts",
    ] {
        assert!(scoped_paths.contains(&path), "{path}");
    }
    for rule in scoped {
        let router = router_for(&fixture, rule);
        let (status, body) = call(router, rule, "tenant=tenant-a", bearer("tenant-a-secret")).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "caller:tenant-a"),
            "{}",
            rule.path
        );
        let (status, body) = call(router, rule, "tenant=tenant-b", bearer("tenant-a-secret")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", rule.path);
        assert!(
            body.contains("tenant credential cannot act for another tenant"),
            "{body}"
        );
        let (status, _) = call(router, rule, "tenant=tenant-b", bearer("operator-secret")).await;
        assert_eq!(status, StatusCode::OK, "{}", rule.path);
    }
    let reports = rows(&CREDENTIAL_ROUTES)
        .filter(|rule| rule.path.starts_with("/v1/reports/"))
        .collect::<Vec<_>>();
    assert!(!reports.is_empty());
    for rule in reports {
        let (status, _) = call(
            &fixture.public,
            rule,
            "tenant=tenant-b",
            bearer("tenant-a-secret"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", rule.path);
    }
}

#[tokio::test]
async fn peer_credential_refused_on_public_routes() {
    let fixture = fixture();
    for rule in rows(&CREDENTIAL_ROUTES).filter(|rule| rule.listener == Listener::Public) {
        let signed = peer_headers(&fixture.node_b, NODE_B, rule, "");
        let (status, body) = call(&fixture.public, rule, "", signed.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
        assert!(body.contains("cluster peer authentication is refused on a caller route"));
        let mut both = signed;
        both.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer operator-secret"),
        );
        let (status, _) = call(&fixture.public, rule, "", both).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
    }
}

#[tokio::test]
async fn caller_credential_refused_on_peer_routes() {
    let fixture = fixture();
    for rule in rows(&[RouteCredential::Peer]) {
        for secret in ["operator-secret", "kernel-secret"] {
            let (status, body) = call(&fixture.internal, rule, "", bearer(secret)).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
            assert!(body.contains("caller credentials are refused on a cluster peer route"));
        }
        let mut both = peer_headers(&fixture.node_b, NODE_B, rule, "");
        both.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer kernel-secret"),
        );
        let (status, _) = call(&fixture.internal, rule, "", both).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
    }
}

#[tokio::test]
async fn pinned_peers_reach_peer_routes_within_their_scopes() {
    let fixture = fixture();
    for rule in rows(&[RouteCredential::Peer]) {
        let query = "afterSeq=9";
        let signed = peer_headers(&fixture.node_b, NODE_B, rule, query);
        let (status, body) = call(&fixture.internal, rule, query, signed).await;
        assert_eq!(status, StatusCode::OK, "{} {body}", rule.path);
        assert_eq!(body, format!("peer:{NODE_B}"));
        let signed = peer_headers(&fixture.node_c, NODE_C, rule, query);
        let (status, body) = call(&fixture.internal, rule, query, signed).await;
        if rule.scope == Some(Scope::ClusterOpeningsReplicate) {
            assert_eq!(status, StatusCode::FORBIDDEN, "{}", rule.path);
            assert!(body.contains("cluster peer lacks scope cluster-openings:replicate"));
        } else {
            assert_eq!(status, StatusCode::OK, "{} {body}", rule.path);
        }
        let replayed = peer_headers(&fixture.node_b, NODE_B, rule, "afterSeq=0");
        let (status, body) = call(&fixture.internal, rule, query, replayed).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
        assert!(
            body.contains("does not verify under a pinned key"),
            "{body}"
        );
    }
}

#[tokio::test]
async fn deployment_credential_of_other_deployment_refused() {
    let fixture = fixture();
    let other = config(&credential(
        "kernel",
        "deployment",
        "dep-b-kernel-secret",
        &scope_names(non_cluster_scopes()),
        None,
    ))
    .replace(&format!("\"{DEPLOYMENT}\""), "\"dep-b\"");
    let other_public = mounted_router(authorizer_for(Listener::Public, &other));
    let other_internal = mounted_router(authorizer_for(Listener::Internal, &other));
    for rule in rows(&CREDENTIAL_ROUTES) {
        let router = match rule.listener {
            Listener::Public => &other_public,
            Listener::Internal => &other_internal,
        };
        let (status, _) = call(router, rule, "", bearer("kernel-secret")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
        let (status, _) = call(router, rule, "", bearer("dep-b-kernel-secret")).await;
        assert_eq!(status, StatusCode::OK, "{}", rule.path);
        let (status, _) = call(
            router_for(&fixture, rule),
            rule,
            "",
            bearer("dep-b-kernel-secret"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
    }
}

#[tokio::test]
async fn internal_listener_refuses_without_credential() {
    let fixture = fixture();
    let internal: Vec<&RouteRule> = ROUTE_TABLE
        .iter()
        .filter(|rule| rule.listener == Listener::Internal)
        .collect();
    assert_eq!(internal.len(), 11);
    for rule in internal {
        let (status, _) = call(&fixture.internal, rule, "", HeaderMap::new()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
    }
}

#[tokio::test]
async fn internal_routes_absent_from_public_listener() {
    let fixture = fixture();
    for rule in ROUTE_TABLE {
        let headers = match rule.credential {
            RouteCredential::Peer => peer_headers(&fixture.node_b, NODE_B, rule, ""),
            _ => bearer("kernel-secret"),
        };
        let wrong = match rule.listener {
            Listener::Public => &fixture.internal,
            Listener::Internal => &fixture.public,
        };
        let (status, body) = call(wrong, rule, "", headers).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}", rule.path);
        assert!(body.contains("route is not served on this trust-control listener"));
    }
}

#[tokio::test]
async fn service_token_secret_no_longer_authenticates_cluster_routes() {
    let fixture = fixture();
    let issued_at = i64::try_from(NOW).test_unwrap();
    for rule in rows(&[RouteCredential::Peer]) {
        let path = concrete(rule.path);
        let hmac = chio_core::sha256_hex(
            &chio_core::canonical_json_bytes(&serde_json::json!({
                "scheme": "chio.cluster.peer.v1",
                "serviceToken": "service-secret",
                "nodeId": NODE_B,
                "endpoint": path,
                "issuedAt": issued_at,
                "term": null,
            }))
            .test_unwrap(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(CLUSTER_NODE_ID_HEADER, HeaderValue::from_static(NODE_B));
        headers.insert(
            CLUSTER_AUTH_ISSUED_AT_HEADER,
            HeaderValue::from_str(&issued_at.to_string()).test_unwrap(),
        );
        headers.insert(
            CLUSTER_AUTH_SIGNATURE_HEADER,
            HeaderValue::from_str(&hmac).test_unwrap(),
        );
        let (status, _) = call(&fixture.internal, rule, "", headers).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
    }
    for rule in rows(&CREDENTIAL_ROUTES) {
        let (status, _) = call(
            router_for(&fixture, rule),
            rule,
            "",
            bearer("service-secret"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
    }
}

#[tokio::test]
async fn existing_client_routes_keep_access_under_mapped_scopes() {
    let fixture = fixture();
    for rule in rows(&CREDENTIAL_ROUTES) {
        let secret = match rule.credential {
            RouteCredential::Deployment => "kernel-secret",
            _ => "operator-secret",
        };
        let (status, body) = call(router_for(&fixture, rule), rule, "", bearer(secret)).await;
        assert_eq!(status, StatusCode::OK, "{} {body}", rule.path);
        if rule.credential == RouteCredential::Deployment {
            let (status, body) = call(
                router_for(&fixture, rule),
                rule,
                "",
                bearer("operator-secret"),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{}", rule.path);
            assert!(
                body.contains("route requires a deployment credential"),
                "{body}"
            );
        }
    }
}

fn peer_row(path: &str) -> &'static RouteRule {
    ROUTE_TABLE
        .iter()
        .find(|rule| rule.path == path && rule.credential == RouteCredential::Peer)
        .test_unwrap()
}

#[tokio::test]
async fn peer_partition_body_is_bound_by_the_signature() {
    let fixture = fixture();
    let rule = peer_row("/v1/internal/cluster/partition");
    assert_eq!(rule.method, RouteMethod::Post);
    let signed_body = br#"{"blocked":["https://node-c.example:9101"]}"#.to_vec();
    let headers = signed_request_headers(&fixture.node_b, NODE_B, "POST", rule, "", &signed_body);
    let (status, body) = send(
        &fixture.internal,
        "POST",
        rule,
        "",
        headers.clone(),
        br#"{"blocked":[]}"#.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        body.contains("cluster peer request body does not match its signed digest"),
        "{body}"
    );
    let (status, body) = send(&fixture.internal, "POST", rule, "", headers, signed_body).await;
    assert_eq!((status, body), (StatusCode::OK, format!("peer:{NODE_B}")));
}

#[tokio::test]
async fn peer_request_replay_refused() {
    let fixture = fixture();
    let rule = peer_row("/v1/internal/cluster/status");
    let headers = peer_headers(&fixture.node_b, NODE_B, rule, "");
    let (status, _) = call(&fixture.internal, rule, "", headers.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(&fixture.internal, rule, "", headers).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        body.contains("cluster peer nonce was already used"),
        "{body}"
    );
}

#[tokio::test]
async fn peer_route_body_over_bound_refused() {
    let fixture = fixture();
    let rule = peer_row("/v1/internal/cluster/partition");
    let oversized = vec![b'x'; PEER_ROUTE_MAX_BODY_BYTES + 1];
    let headers = signed_request_headers(&fixture.node_b, NODE_B, "POST", rule, "", &oversized);
    let (status, body) = send(&fixture.internal, "POST", rule, "", headers, oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        body.contains("cluster peer request body exceeds its bound"),
        "{body}"
    );
}

#[tokio::test]
async fn head_follows_get_rows() {
    let fixture = fixture();
    for rule in ROUTE_TABLE
        .iter()
        .filter(|rule| rule.method == RouteMethod::Get)
    {
        let router = router_for(&fixture, rule);
        let (allowed, refused) = match rule.credential {
            RouteCredential::Peer => (
                signed_request_headers(&fixture.node_b, NODE_B, "HEAD", rule, "", b""),
                HeaderMap::new(),
            ),
            RouteCredential::Deployment => (bearer("kernel-secret"), HeaderMap::new()),
            RouteCredential::Caller => (bearer("operator-secret"), HeaderMap::new()),
            _ => (HeaderMap::new(), bearer("operator-secret")),
        };
        let (status, _) = send(router, "HEAD", rule, "", allowed, Vec::new()).await;
        assert_eq!(status, StatusCode::OK, "HEAD {}", rule.path);
        if matches!(
            rule.credential,
            RouteCredential::Peer | RouteCredential::Deployment | RouteCredential::Caller
        ) {
            let (status, _) = send(router, "HEAD", rule, "", refused, Vec::new()).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "HEAD {}", rule.path);
        }
    }
}

#[tokio::test]
async fn peer_authorization_for_another_receiver_refused() {
    let fixture = fixture();
    let rule = peer_row("/v1/internal/cluster/partition");
    let body = br#"{"blocked":[]}"#.to_vec();
    let path = concrete(rule.path);
    let target = PeerRequestTarget {
        method: "POST",
        path: &path,
        query: "",
        body: &body,
    };
    let headers = signed_peer_headers_for(
        &fixture.node_b,
        NODE_B,
        NODE_C,
        &target,
        i64::try_from(NOW).test_unwrap(),
        Some(4),
    );
    let (status, response) = send(&fixture.internal, "POST", rule, "", headers, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        response.contains("cluster peer signature does not verify under a pinned key"),
        "{response}"
    );
}

#[tokio::test]
async fn peer_authorization_for_another_deployment_refused() {
    let fixture = fixture();
    let rule = peer_row("/v1/internal/cluster/partition");
    let body = br#"{"blocked":[]}"#.to_vec();
    let path = concrete(rule.path);
    let target = PeerRequestTarget {
        method: "POST",
        path: &path,
        query: "",
        body: &body,
    };
    let issued_at = i64::try_from(NOW).test_unwrap();
    let other_deployment = sign_cluster_peer_request(
        &fixture.node_b,
        &PeerAddressing {
            deployment: "dep-b",
            sender: NODE_B,
            recipient: SELF_NODE,
        },
        &target,
        &fresh_nonce(),
        issued_at,
        Some(4),
    )
    .test_unwrap();
    let mut headers = signed_peer_headers(&fixture.node_b, NODE_B, &target, issued_at, Some(4));
    for (name, value) in [
        (CLUSTER_AUTH_SIGNATURE_HEADER, other_deployment.signature),
        (CLUSTER_AUTH_NONCE_HEADER, other_deployment.nonce),
    ] {
        headers.insert(name, HeaderValue::from_str(&value).test_unwrap());
    }
    let (status, response) = send(&fixture.internal, "POST", rule, "", headers, body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        response.contains("cluster peer signature does not verify under a pinned key"),
        "{response}"
    );
}

#[tokio::test]
async fn finding_buyer_routes_hold_caller_credentials_to_caller_rules() {
    let fixture = fixture();
    let buyer_rows: Vec<&RouteRule> = rows(&[RouteCredential::FindingBuyerOrCaller]).collect();
    assert_eq!(buyer_rows.len(), 3);
    for rule in buyer_rows {
        let scope = rule.scope.test_unwrap();
        let (status, body) = call(&fixture.public, rule, "", bearer("finding-buyer-token")).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::OK, "unchanged"),
            "{}",
            rule.path
        );
        let (status, body) = call(
            &fixture.public,
            rule,
            "",
            bearer(&scope_secret("only", scope)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{} {body}", rule.path);
        assert!(body.starts_with("caller:"), "{body}");
        let (status, body) = call(
            &fixture.public,
            rule,
            "",
            bearer(&scope_secret("all-but", scope)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{} {body}", rule.path);
        let (status, _) = call(&fixture.public, rule, "", bearer("tenant-a-secret")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", rule.path);
        let signed = peer_headers(&fixture.node_b, NODE_B, rule, "");
        let (status, _) = call(&fixture.public, rule, "", signed).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
    }
}
