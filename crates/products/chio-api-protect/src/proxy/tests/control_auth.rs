//! Exercise the production router: network locality never confers authority.

use super::*;
use axum::extract::ConnectInfo;
use axum::http::HeaderValue;

pub(super) const TEST_CONTROL_TOKEN: &str = "api-protect-fixture-control-token";

pub(super) fn with_peer_addr(mut request: Request<Body>, peer: SocketAddr) -> Request<Body> {
    // Match the capped listener's actual extension type, including local peers.
    request
        .extensions_mut()
        .insert(ConnectInfo(CappedPeerAddr(peer)));
    request
}

pub(super) fn with_authenticated_control_peer(mut request: Request<Body>) -> Request<Body> {
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {TEST_CONTROL_TOKEN}")).test_unwrap(),
    );
    with_loopback_peer(request)
}

const CONTROL_TOKEN: &str = "control-boundary-test-token";
const CONTROL_ROUTES: &[(&str, &str)] = &[
    ("GET", "/approvals/pending"),
    ("GET", "/approvals/ap-control"),
    ("POST", "/approvals/submit"),
    ("POST", "/approvals/batch/respond"),
    ("POST", "/approvals/ap-control/operator-respond"),
    ("POST", "/approvals/ap-control/respond"),
    ("POST", "/approvals/threshold/proposals"),
    ("GET", "/approvals/threshold/proposals/ap-control"),
    ("POST", "/approvals/threshold/proposals/ap-control/respond"),
    ("POST", "/approvals/threshold/proposals/ap-control/deliver"),
    ("POST", "/v1/capabilities/mint"),
    ("POST", "/v1/capabilities"),
    ("POST", "/v1/capabilities/release"),
    ("POST", "/v1/capabilities/validate"),
    ("POST", "/v1/capabilities/attenuate"),
    ("POST", "/v1/receipts"),
    ("POST", "/v1/reconcile"),
    ("GET", "/metrics"),
];

fn control_state(token: Option<&str>) -> Arc<ProxyState> {
    let mut state = test_state(Vec::new(), "http://127.0.0.1:1".to_owned());
    Arc::get_mut(&mut state).test_unwrap().sidecar_control_token = token.map(str::to_owned);
    state
}

async fn assert_routes_forbidden(
    configured_token: Option<&str>,
    peer: Option<SocketAddr>,
    authorization: &[&str],
) {
    let state = control_state(configured_token);
    let app = build_app(state);
    for &(method, uri) in CONTROL_ROUTES {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            // Authentication must run before deserialization or store access.
            .body(Body::from("not JSON"))
            .test_unwrap();
        for value in authorization {
            request
                .headers_mut()
                .append(AUTHORIZATION, HeaderValue::from_str(value).test_unwrap());
        }
        if let Some(peer) = peer {
            request = with_peer_addr(request, peer);
        }
        let response = app.clone().oneshot(request).await.test_unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {uri}");
        let bytes = to_bytes(response.into_body(), 4096).await.test_unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).test_unwrap();
        assert_eq!(body["error"], "chio_control_forbidden", "{method} {uri}");
        assert!(!String::from_utf8_lossy(&bytes).contains(CONTROL_TOKEN));
    }
}

#[tokio::test]
async fn unconfigured_control_denies_ipv4_loopback_on_every_route() {
    assert_routes_forbidden(None, Some("127.0.0.1:4100".parse().test_unwrap()), &[]).await;
}

#[tokio::test]
async fn unconfigured_control_denies_ipv6_loopback_on_every_route() {
    assert_routes_forbidden(None, Some("[::1]:4100".parse().test_unwrap()), &[]).await;
}

#[tokio::test]
async fn unconfigured_control_denies_unknown_and_remote_peers() {
    for peer in [None, Some("192.0.2.1:4100".parse().test_unwrap())] {
        assert_routes_forbidden(None, peer, &["Bearer control-boundary-test-token"]).await;
    }
}

#[tokio::test]
async fn blank_control_configuration_denies_even_loopback() {
    for token in ["", "   ", "\t\r\n"] {
        assert_routes_forbidden(
            Some(token),
            Some("127.0.0.1:4100".parse().test_unwrap()),
            &["Bearer control-boundary-test-token"],
        )
        .await;
    }
}

#[tokio::test]
async fn configured_control_denies_missing_and_wrong_credentials() {
    for authorization in [&[][..], &["Bearer wrong-token"][..]] {
        assert_routes_forbidden(
            Some(CONTROL_TOKEN),
            Some("127.0.0.1:4100".parse().test_unwrap()),
            authorization,
        )
        .await;
    }
}

#[tokio::test]
async fn duplicate_authorization_headers_are_rejected_in_either_order() {
    for headers in [
        ["Bearer control-boundary-test-token", "Bearer wrong-token"],
        ["Bearer wrong-token", "Bearer control-boundary-test-token"],
        [
            "Bearer control-boundary-test-token",
            "Bearer control-boundary-test-token",
        ],
    ] {
        assert_routes_forbidden(Some(CONTROL_TOKEN), None, &headers).await;
    }
}

#[tokio::test]
async fn malformed_authorization_is_rejected_on_every_route() {
    for header in [
        "Bearer control-boundary-test-token, Bearer wrong-token",
        "Basic control-boundary-test-token",
        "Bearer  control-boundary-test-token",
        "Bearer control-boundary-test-token ",
        "Bearer\tcontrol-boundary-test-token",
    ] {
        assert_routes_forbidden(Some(CONTROL_TOKEN), None, &[header]).await;
    }
}

#[tokio::test]
async fn forwarded_localhost_headers_do_not_authenticate_control_requests() {
    let state = control_state(None);
    let request = with_peer_addr(
        Request::builder()
            .uri("/approvals/pending")
            .header("forwarded", "for=127.0.0.1;host=localhost")
            .header("x-forwarded-for", "127.0.0.1")
            .header("x-real-ip", "127.0.0.1")
            .body(Body::empty())
            .test_unwrap(),
        "192.0.2.1:4100".parse().test_unwrap(),
    );
    let response = build_app(state).oneshot(request).await.test_unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unauthenticated_loopback_cannot_sign_or_resolve_operator_approval() {
    let state = control_state(None);
    let (mut approval, _, _) = pending_approval_request("ap-control");
    approval.trusted_approvers = vec![state.signer_keypair.public_key()];
    state
        .approval_admin
        .store()
        .store_pending(&approval)
        .test_unwrap();
    let request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/approvals/ap-control/operator-respond")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"outcome":"approved"}"#))
            .test_unwrap(),
        "127.0.0.1:4100".parse().test_unwrap(),
    );
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        state
            .approval_admin
            .store()
            .get_pending("ap-control")
            .test_unwrap(),
        Some(approval),
    );
    assert!(state
        .approval_admin
        .store()
        .get_resolution("ap-control")
        .test_unwrap()
        .is_none());
}

#[tokio::test]
async fn unauthenticated_loopback_cannot_revoke_capabilities() {
    let state = control_state(None);
    let request = with_peer_addr(
        Request::builder()
            .method("POST")
            .uri("/v1/capabilities/release")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"capability_id":"cap-control"}"#))
            .test_unwrap(),
        "127.0.0.1:4100".parse().test_unwrap(),
    );
    let response = build_app(Arc::clone(&state))
        .oneshot(request)
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!state.capability_is_revoked("cap-control").await);
    assert!(state.revoked_capability_ids.lock().await.is_empty());
}

#[tokio::test]
async fn authenticated_control_works_without_peer_metadata() {
    let state = control_state(Some(CONTROL_TOKEN));
    let request = Request::builder()
        .uri("/approvals/pending")
        .header(AUTHORIZATION, "bEaReR control-boundary-test-token")
        .body(Body::empty())
        .test_unwrap();
    let response = build_app(state).oneshot(request).await.test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn public_liveness_is_available_without_control_credentials() {
    let response = build_app(control_state(None))
        .oneshot(
            Request::builder()
                .uri("/chio/live")
                .body(Body::empty())
                .test_unwrap(),
        )
        .await
        .test_unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
