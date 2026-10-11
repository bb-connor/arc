//! An initialize request that carries MCP-Session-Id is malformed, whatever the
//! named session's state, and must not resolve that session first.
use super::*;

const UNKNOWN_SESSION: &str = "bogus-session";

fn initialize_message(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{
        "protocolVersion":"2025-11-25","capabilities":{},
        "clientInfo":{"name":"initialize-session-header","version":"1"}}})
}

async fn drain(response: Response) {
    tokio::time::timeout(WAIT, axum::body::to_bytes(response.into_body(), 64 * 1024))
        .await
        .expect("terminal body deadline")
        .unwrap();
}

/// Status, issued session header and up to 2 KiB of body.
async fn outcome(response: Response) -> (StatusCode, Option<axum::http::HeaderValue>, String) {
    let status = response.status();
    let issued = response.headers().get(MCP_SESSION_ID_HEADER).cloned();
    (status, issued, body_detail(response).await)
}

fn assert_initialize_session_header_refusal(
    outcome: &(StatusCode, Option<axum::http::HeaderValue>, String),
    session: &str,
) {
    let (status, issued, body) = outcome;
    assert_eq!(
        *status,
        StatusCode::BAD_REQUEST,
        "initialize naming MCP-Session-Id {session} answered {status}: {body}"
    );
    assert!(issued.is_none(), "malformed initialize issued a session");
    let body: Value = serde_json::from_str(body).unwrap();
    assert_eq!(body["error"]["code"], -32600);
    assert_eq!(
        body["error"]["message"],
        "initialize request must not include MCP-Session-Id"
    );
}

#[tokio::test]
async fn initialize_with_unknown_session_header_is_malformed_before_session_resolution() {
    let fixture = fixture(0, None);
    assert!(
        fixture
            .state
            .sessions
            .lookup(UNKNOWN_SESSION)
            .await
            .is_none(),
        "setup precondition: the named session must be unknown to the ledger"
    );
    // The same body without the header reaches the initialize branch, so an
    // unknown-session answer can only come from resolving the header first.
    let accepted = post(&fixture, None, &initialize_message(1)).await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert!(accepted.headers().contains_key(MCP_SESSION_ID_HEADER));
    drain(accepted).await;

    let refused =
        outcome(post(&fixture, Some(UNKNOWN_SESSION), &initialize_message(2)).await).await;
    assert_initialize_session_header_refusal(&refused, UNKNOWN_SESSION);
    assert!(fixture
        .state
        .sessions
        .lookup(UNKNOWN_SESSION)
        .await
        .is_none());
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}

#[tokio::test]
async fn initialize_with_known_session_header_is_malformed_and_the_session_still_routes() {
    let fixture = fixture(0, None);
    let session = initialize(&fixture, false).await;
    initialized(&fixture, &session).await;

    let refused =
        outcome(post(&fixture, Some(&session.session_id), &initialize_message(2)).await).await;
    assert_initialize_session_header_refusal(&refused, &session.session_id);

    let ping = post(
        &fixture,
        Some(&session.session_id),
        &json!({"jsonrpc":"2.0","id":3,"method":"ping","params":{}}),
    )
    .await;
    assert_eq!(ping.status(), StatusCode::OK);
    let pong = next_message(&mut ping.into_body(), |message| message["id"] == 3).await;
    assert_eq!(pong["result"], json!({}));
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}

#[tokio::test]
async fn unknown_session_on_non_initialize_post_is_still_not_found() {
    let fixture = fixture(0, None);
    for message in [
        json!({"jsonrpc":"2.0","id":4,"method":"ping","params":{}}),
        // Only the top-level method names initialize.
        json!({"jsonrpc":"2.0","id":5,"method":"ping","params":{"method":"initialize"}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    ] {
        let (status, issued, body) =
            outcome(post(&fixture, Some(UNKNOWN_SESSION), &message).await).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{message} with unknown session answered {status}: {body}"
        );
        assert_eq!(body, "unknown MCP session");
        assert!(issued.is_none());
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn initialize_without_id_naming_a_session_keeps_request_shape_precedence() {
    let fixture = fixture(0, None);
    let session = initialize(&fixture, false).await;
    initialized(&fixture, &session).await;
    let mut no_id = initialize_message(6);
    no_id.as_object_mut().unwrap().remove("id");
    for named in [session.session_id.as_str(), UNKNOWN_SESSION] {
        let (status, issued, body) = outcome(post(&fixture, Some(named), &no_id).await).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "id-less initialize naming {named} answered {status}: {body}"
        );
        assert!(issued.is_none());
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["error"]["code"], -32600);
        assert_eq!(
            body["error"]["message"],
            "initialize must be a JSON-RPC request with an id"
        );
    }
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}
