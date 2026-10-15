//! Session-owned completion of a restricted credential call.
//!
//! The terminal response is verified and persisted by a task the session owns,
//! so the outcome is durable whether or not the POST stream that dispatched the
//! call is still attached. A retry with the same `chioRequestId` then replays
//! the persisted outcome instead of meeting the pending fence.
use super::*;

/// The terminal SSE payload for a restricted call. `None` emits nothing.
pub(super) type CallOutcome = Option<(Option<String>, Value)>;

fn uncertain(request_id: &Value, message: &str) -> CallOutcome {
    Some((
        None,
        json!({"jsonrpc":"2.0","id":request_id,"error":{"code":-32603,"message":message}}),
    ))
}

pub(super) struct PendingCompletion {
    pub(super) state: RemoteAppState,
    pub(super) session: Arc<RemoteSession>,
    pub(super) events: broadcast::Receiver<RemoteSessionEvent>,
    pub(super) stream_lock: tokio::sync::OwnedMutexGuard<()>,
    pub(super) request_id: Value,
    pub(super) request_generation: McpRequestGeneration,
    pub(super) call: Box<remote_mcp_session_credentials::CredentialCall>,
    pub(super) credential: remote_mcp_session_credentials::SessionCredential,
    pub(super) response_method: String,
}

/// Start completion. The task holds the session's request ownership until the
/// call is terminal, exactly as an attached stream would.
pub(super) fn spawn(pending: PendingCompletion) -> tokio::sync::oneshot::Receiver<CallOutcome> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = sender.send(complete(pending).await);
    });
    receiver
}

async fn complete(pending: PendingCompletion) -> CallOutcome {
    let PendingCompletion {
        state,
        session,
        mut events,
        stream_lock,
        request_id,
        request_generation,
        call,
        credential,
        response_method,
    } = pending;
    let _stream_lock = stream_lock;
    let mut response_deadline = Box::pin(session.response_deadline());
    loop {
        let received = tokio::select! {
            biased;
            received = session_worker::receive(&session, &mut events) => Some(received),
            () = response_deadline.as_mut() => None,
        };
        let Some(received) = received else {
            warn!(session_id = %session.session_id, "remote MCP request exceeded its response deadline");
            session_worker::close(&state, &session).await;
            return uncertain(
                &request_id,
                "request response deadline exceeded; session closed; effect is uncertain",
            );
        };
        let event = match received {
            Ok(event) => event,
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, session_id = %session.session_id, "remote SSE consumer lagged behind session output");
                session_worker::close(&state, &session).await;
                return uncertain(
                    &request_id,
                    "session response was lost; effect is uncertain",
                );
            }
            Err(broadcast::error::RecvError::Closed) => {
                // The session ended before the terminal response. The pending
                // fence stays: the effect may exist and nothing proves otherwise.
                session_worker::close(&state, &session).await;
                return uncertain(&request_id, "session worker stopped; effect is uncertain");
            }
        };
        if event.kind == RemoteSessionEventKind::RequestCorrelated
            && event.request_generation != Some(request_generation)
        {
            continue;
        }
        if !is_terminal_response_for_request(&event.message, &request_id) {
            continue;
        }
        let should_emit = should_emit_post_stream_event(
            &event,
            Some(&request_id),
            session.has_active_notification_stream(),
        );
        let finish_state = state.clone();
        let message = event.message.clone();
        let finished = tokio::task::spawn_blocking(move || {
            remote_mcp_session_credentials::finish_call(&finish_state, &call, &message)
        })
        .await;
        let Ok(Ok(mut response)) = finished else {
            // The effect may already exist. Withhold success and leave the
            // durable pending fence in place.
            return uncertain(
                &request_id,
                "credential outcome persistence failed; effect is uncertain",
            );
        };
        if !should_emit {
            return None;
        }
        credential.restrict_response(&response_method, &mut response);
        return Some((Some(event.event_id), response));
    }
}

/// The POST response for a restricted call: a priming event, then the outcome
/// the session-owned task produced. Dropping this stream never cancels it.
pub(super) fn respond(pending: PendingCompletion) -> Response {
    let session = pending.session.clone();
    let request_id = pending.request_id.clone();
    let outcome = spawn(pending);
    let stream = stream! {
        yield Ok::<Event, Infallible>(
            Event::default()
                .id(match session.next_stream_event_id() { Ok(id) => id, Err(_) => return })
                .retry(std::time::Duration::from_millis(DEFAULT_STREAM_RETRY_MILLIS))
                .data("")
        );
        let outcome = outcome.await.unwrap_or_else(|_| {
            uncertain(&request_id, "session worker stopped; effect is uncertain")
        });
        if let Some((event_id, message)) = outcome {
            let event = Event::default().data(message.to_string());
            yield Ok(match event_id {
                Some(event_id) => event.id(event_id),
                None => event,
            });
        }
    };
    response_with_mode(Sse::new(stream).into_response(), "post_request_sse")
}
