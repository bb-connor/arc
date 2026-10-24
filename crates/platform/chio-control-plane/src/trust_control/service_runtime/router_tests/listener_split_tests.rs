//! The public router serves no `/v1/internal/*` route and the internal router
//! serves nothing else; each refuses the other's routes as absent.
use super::*;
use crate::trust_control::route_authorization::{Listener, RouteCredential, ROUTE_TABLE};
use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request};
use tower::ServiceExt;

const ROUTE_ABSENT: &str = "route is not served on this trust-control listener";

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

async fn send(router: axum::Router, method: &str, path: &str) -> (StatusCode, String) {
    let request = Request::builder()
        .method(method)
        .uri(concrete(path))
        .header(AUTHORIZATION, "Bearer split-secret")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .test_unwrap();
    let response = router.oneshot(request).await.test_unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn public_router_has_no_internal_paths() {
    let state = metrics_state("split-secret");
    for rule in ROUTE_TABLE
        .iter()
        .filter(|rule| rule.listener == Listener::Internal)
    {
        let public = super::super::build_router(state.clone());
        let (status, body) = send(public, rule.method.as_str(), rule.path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}", rule.path);
        assert!(body.contains(ROUTE_ABSENT), "{} {body}", rule.path);
    }
}

#[tokio::test]
async fn public_router_refuses_unrouted_api_paths_before_any_fallback() {
    let state = metrics_state("split-secret");
    for path in ["/v1", "/v1/no-such-route", "/v1/internal/no-such-route"] {
        let public = super::super::build_router(state.clone());
        let (status, body) = send(public, "GET", path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(body.contains(ROUTE_ABSENT), "{path} {body}");
    }
}

#[tokio::test]
async fn internal_router_serves_no_public_path() {
    let state = metrics_state("split-secret");
    for rule in ROUTE_TABLE
        .iter()
        .filter(|rule| rule.listener == Listener::Public && rule.path.starts_with("/v1"))
    {
        let internal = super::super::build_internal_router(state.clone());
        let (status, body) = send(internal, rule.method.as_str(), rule.path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}", rule.path);
        assert!(body.contains(ROUTE_ABSENT), "{} {body}", rule.path);
    }
    for rule in ROUTE_TABLE
        .iter()
        .filter(|rule| rule.listener == Listener::Public && !rule.path.starts_with("/v1"))
    {
        let internal = super::super::build_internal_router(state.clone());
        let (status, _) = send(internal, rule.method.as_str(), rule.path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}", rule.path);
    }
}

#[tokio::test]
async fn internal_router_refuses_caller_credentials_on_peer_routes() {
    let state = metrics_state("split-secret");
    for rule in ROUTE_TABLE.iter().filter(|rule| {
        rule.listener == Listener::Internal && rule.credential == RouteCredential::Peer
    }) {
        let internal = super::super::build_internal_router(state.clone());
        let (status, body) = send(internal, rule.method.as_str(), rule.path).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{}", rule.path);
        assert!(
            body.contains("caller credentials are refused on a cluster peer route"),
            "{} {body}",
            rule.path
        );
    }
}
