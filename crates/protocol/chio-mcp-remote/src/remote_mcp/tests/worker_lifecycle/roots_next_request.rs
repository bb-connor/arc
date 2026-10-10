//! A roots refresh queued by `notifications/initialized` or
//! `notifications/roots/list_changed` is carried by the next client request's
//! own POST stream, before that request is dispatched. It is never broadcast,
//! retained for GET replay, or classified as a standalone request.
use super::*;

/// How long a stream is watched for a message that must not arrive.
const ABSENCE_WINDOW: Duration = Duration::from_millis(300);

fn ping(id: u64) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"ping","params":{}})
}

/// The first message on `body` within `window` that satisfies `expected`.
async fn message_within(
    body: &mut Body,
    window: Duration,
    expected: impl Fn(&Value) -> bool,
) -> Option<Value> {
    tokio::time::timeout(window, next_message(body, expected))
        .await
        .ok()
}

/// The next request's stream must carry `roots/list` before the request's
/// own terminal response.
async fn roots_request_before_response(body: &mut Body, request_id: u64) -> Value {
    let first = message_within(body, WAIT, |message| {
        message["method"] == "roots/list" || message["id"] == request_id
    })
    .await
    .unwrap_or_else(|| {
        panic!("request {request_id} stream carried neither roots/list nor its response")
    });
    assert_eq!(
        first["method"], "roots/list",
        "request {request_id} was answered before its roots refresh: {first}"
    );
    first
}

/// Wait until the worker has handled the preceding notification: it either
/// published a roots request or released the notification's ingress.
async fn notification_handled(
    session: &RemoteSession,
    observer: &mut broadcast::Receiver<RemoteSessionEvent>,
) {
    tokio::time::timeout(WAIT, async {
        loop {
            while let Ok(event) = observer.try_recv() {
                if event.message["method"] == "roots/list" {
                    return;
                }
            }
            if session.input_tx.usage().unwrap().messages == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the worker did not handle the notification");
}

async fn answer_roots(fixture: &Fixture, session: &RemoteSession, request: &Value, uri: &str) {
    let reply = post(
        fixture,
        Some(&session.session_id),
        &json!({"jsonrpc":"2.0","id":request["id"],
            "result":{"roots":[{"uri":uri,"name":"root"}]}}),
    )
    .await;
    assert_eq!(reply.status(), StatusCode::ACCEPTED);
    assert!(axum::body::to_bytes(reply.into_body(), 1024)
        .await
        .unwrap()
        .is_empty());
}

fn retained_roots_requests(session: &RemoteSession) -> usize {
    session
        .retained_notification_events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.message["method"] == "roots/list")
        .count()
}

async fn published_kind(
    observer: &mut broadcast::Receiver<RemoteSessionEvent>,
    request: &Value,
) -> RemoteSessionEventKind {
    tokio::time::timeout(WAIT, async {
        loop {
            let event = observer.recv().await.unwrap();
            if event.message["method"] == "roots/list" && event.message["id"] == request["id"] {
                break event.kind;
            }
        }
    })
    .await
    .expect("the carried roots/list was not published to the session")
}

#[tokio::test]
async fn next_request_stream_carries_roots_before_its_own_response_without_a_get() {
    let fixture = fixture(0, None);
    let session = initialize(&fixture, true).await;
    let mut barrier = session.subscribe();
    initialized(&fixture, &session).await;
    notification_handled(&session, &mut barrier).await;

    let mut observer = session.subscribe();
    let response = post(&fixture, Some(&session.session_id), &ping(9)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let roots = roots_request_before_response(&mut body, 9).await;
    assert_eq!(
        published_kind(&mut observer, &roots).await,
        RemoteSessionEventKind::RequestCorrelated
    );
    assert_eq!(retained_roots_requests(&session), 0);
    answer_roots(&fixture, &session, &roots, "file:///workspace").await;
    let pong = next_message(&mut body, |message| message["id"] == 9).await;
    assert_eq!(pong["result"], json!({}));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}

#[tokio::test]
async fn get_attached_before_initialized_leaves_roots_on_the_next_request_stream() {
    let fixture = fixture(0, None);
    let session = initialize(&fixture, true).await;
    let get = handle_get(
        State(fixture.state.clone()),
        get_request(&session.session_id),
    )
    .await;
    assert_eq!(get.status(), StatusCode::OK);
    let mut get_body = get.into_body();
    let mut barrier = session.subscribe();
    initialized(&fixture, &session).await;
    notification_handled(&session, &mut barrier).await;
    assert!(
        message_within(&mut get_body, ABSENCE_WINDOW, |message| message["method"]
            == "roots/list")
        .await
        .is_none(),
        "the attached GET carried a roots/list after initialized"
    );

    let response = post(&fixture, Some(&session.session_id), &ping(10)).await;
    let mut body = response.into_body();
    let roots = roots_request_before_response(&mut body, 10).await;
    assert_eq!(retained_roots_requests(&session), 0);
    answer_roots(&fixture, &session, &roots, "file:///workspace").await;
    let pong = next_message(&mut body, |message| message["id"] == 10).await;
    assert_eq!(pong["result"], json!({}));
    assert!(
        message_within(&mut get_body, ABSENCE_WINDOW, |message| message["method"]
            == "roots/list")
        .await
        .is_none(),
        "the request-correlated roots/list reached the GET"
    );
    drop(get_body);
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}

#[tokio::test]
async fn cancelling_the_triggering_request_during_its_roots_refresh_dispatches_nothing() {
    let fixture = fixture(0, None);
    let session = initialize(&fixture, true).await;
    let mut barrier = session.subscribe();
    initialized(&fixture, &session).await;
    notification_handled(&session, &mut barrier).await;

    let call = post(&fixture, Some(&session.session_id), &read_call(7)).await;
    assert_eq!(call.status(), StatusCode::OK);
    let mut call_body = call.into_body();
    let roots = roots_request_before_response(&mut call_body, 7).await;
    let cancel = post(
        &fixture,
        Some(&session.session_id),
        &json!({"jsonrpc":"2.0","method":"notifications/cancelled",
            "params":{"requestId":7,"reason":"client cancelled"}}),
    )
    .await;
    assert_eq!(cancel.status(), StatusCode::ACCEPTED);
    let outcome = next_message(&mut call_body, |message| message["id"] == 7).await;
    assert_eq!(outcome["error"]["code"], -32800, "{outcome}");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    // A client is done with a stream once its terminal response arrives.
    drop(call_body);

    // The refresh was not obtained, so the next request carries it again.
    let response = post(&fixture, Some(&session.session_id), &ping(8)).await;
    let mut body = response.into_body();
    let again = roots_request_before_response(&mut body, 8).await;
    assert_ne!(again["id"], roots["id"]);
    answer_roots(&fixture, &session, &again, "file:///workspace").await;
    let pong = next_message(&mut body, |message| message["id"] == 8).await;
    assert_eq!(pong["result"], json!({}));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}

#[tokio::test]
async fn roots_list_changed_is_refreshed_on_the_next_request_stream() {
    let fixture = fixture(0, None);
    let session = initialize(&fixture, true).await;
    let mut barrier = session.subscribe();
    initialized(&fixture, &session).await;
    notification_handled(&session, &mut barrier).await;

    let response = post(&fixture, Some(&session.session_id), &ping(11)).await;
    let mut body = response.into_body();
    let first = roots_request_before_response(&mut body, 11).await;
    answer_roots(&fixture, &session, &first, "file:///workspace/a").await;
    next_message(&mut body, |message| message["id"] == 11).await;
    // A client is done with a stream once its terminal response arrives.
    drop(body);

    let mut barrier = session.subscribe();
    let changed = post(
        &fixture,
        Some(&session.session_id),
        &json!({"jsonrpc":"2.0","method":"notifications/roots/list_changed"}),
    )
    .await;
    assert_eq!(changed.status(), StatusCode::ACCEPTED);
    assert!(axum::body::to_bytes(changed.into_body(), 1024)
        .await
        .unwrap()
        .is_empty());
    notification_handled(&session, &mut barrier).await;

    let response = post(&fixture, Some(&session.session_id), &ping(12)).await;
    let mut body = response.into_body();
    let second = roots_request_before_response(&mut body, 12).await;
    assert_ne!(second["id"], first["id"]);
    assert_eq!(retained_roots_requests(&session), 0);
    answer_roots(&fixture, &session, &second, "file:///workspace/b").await;
    let pong = next_message(&mut body, |message| message["id"] == 12).await;
    assert_eq!(pong["result"], json!({}));
    fixture.state.sessions.shutdown_all_active().await.unwrap();
}
