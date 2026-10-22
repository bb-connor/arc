//! The public router serves no `/v1/internal/*` route and the internal router
//! serves nothing else; each refuses the other's routes as absent.
use super::*;
use crate::trust_control::route_authorization::{Listener, ROUTE_TABLE};
use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request};
use tower::ServiceExt;

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

async fn status(router: axum::Router, method: &str, path: &str) -> StatusCode {
    let request = Request::builder()
        .method(method)
        .uri(concrete(path))
        .header(AUTHORIZATION, "Bearer split-secret")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .test_unwrap();
    router.oneshot(request).await.test_unwrap().status()
}

#[tokio::test]
async fn public_router_has_no_internal_paths() {
    let state = metrics_state("split-secret");
    for rule in ROUTE_TABLE
        .iter()
        .filter(|rule| rule.listener == Listener::Internal)
    {
        let public = super::super::build_router(state.clone());
        assert_eq!(
            status(public, rule.method.as_str(), rule.path).await,
            StatusCode::NOT_FOUND,
            "{}",
            rule.path
        );
    }
}

#[tokio::test]
async fn internal_router_serves_no_public_path() {
    let state = metrics_state("split-secret");
    for rule in ROUTE_TABLE
        .iter()
        .filter(|rule| rule.listener == Listener::Public)
    {
        let internal = super::super::build_internal_router(state.clone());
        let status = status(internal, rule.method.as_str(), rule.path).await;
        assert!(
            matches!(
                status,
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{} {status}",
            rule.path
        );
    }
}

#[tokio::test]
async fn internal_router_refuses_caller_credentials_on_peer_routes() {
    let state = metrics_state("split-secret");
    for rule in ROUTE_TABLE.iter().filter(|rule| {
        rule.listener == Listener::Internal
            && rule.credential == crate::trust_control::route_authorization::RouteCredential::Peer
    }) {
        let internal = super::super::build_internal_router(state.clone());
        assert_eq!(
            status(internal, rule.method.as_str(), rule.path).await,
            StatusCode::UNAUTHORIZED,
            "{}",
            rule.path
        );
    }
}
