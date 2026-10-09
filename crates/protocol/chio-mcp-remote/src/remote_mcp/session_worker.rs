//! A trusted actor lifetime ends HTTP waits even while the session owns its event sender.
use super::*;

pub(super) struct WorkerExit(tokio::sync::watch::Sender<bool>);
impl WorkerExit {
    pub(super) fn new(session: &RemoteSession) -> Self {
        Self(session.worker_serving_closed.clone())
    }
}
impl Drop for WorkerExit {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

pub(super) async fn receive(
    session: &RemoteSession,
    events: &mut broadcast::Receiver<RemoteSessionEvent>,
) -> Result<RemoteSessionEvent, broadcast::error::RecvError> {
    let mut exited = session.worker_serving_closed.subscribe();
    if *exited.borrow_and_update() {
        return Err(broadcast::error::RecvError::Closed);
    }
    tokio::select! {
        biased;
        _ = exited.changed() => Err(broadcast::error::RecvError::Closed),
        event = events.recv() => event,
    }
}

pub(super) async fn acquire_request_owner(
    session: &RemoteSession,
) -> Option<tokio::sync::OwnedMutexGuard<()>> {
    let mut exited = session.worker_serving_closed.subscribe();
    if *exited.borrow_and_update() {
        return None;
    }
    tokio::select! {
        biased;
        _ = exited.changed() => None,
        owner = session.active_request_stream.clone().lock_owned() => {
            if *exited.borrow() { None } else { Some(owner) }
        },
    }
}

pub(super) async fn close(state: &RemoteAppState, session: &Arc<RemoteSession>) {
    session.worker_serving_closed.send_replace(true);
    if let Err(error) = state.sessions.mark_closed(session).await {
        warn!(error = %error, session_id = %session.session_id,
            "failed to retain terminal diagnostics for stopped MCP worker");
        // A clock failure cannot make a dead actor serve again. Remove resume
        // authority under the same lifecycle lock as renewal, without inventing
        // a clock reading or signed terminal epoch.
        let stopped = session.clone();
        let released = run_blocking(move || {
            let mut lifecycle = stopped
                .lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Err(error) = stopped.remove_resumable_record() {
                error!(error = %error, session_id = %stopped.session_id,
                    "stopped MCP worker resume-state removal requires operator reconciliation");
            }
            lifecycle.state = RemoteSessionState::Closed;
            lifecycle.deadline = None;
            lifecycle.drain_deadline_at = None;
        })
        .await;
        if let Err(error) = released {
            error!(error = %error, session_id = %session.session_id,
                "stopped MCP worker resume-state release did not complete");
        }
        state.sessions.remove_active(&session.session_id).await;
        let stopped = session.clone();
        if let Ok(Err(error)) = run_blocking(move || stopped.shutdown_upstream_transport()).await {
            warn!(error = %error, session_id = %session.session_id,
                "stopped MCP worker upstream shutdown failed");
        }
    }
}

/// Waits for the next event of one admitted request. The route is lossless, so
/// a response already queued when the actor exits is still delivered. Session
/// notifications arrive from the loss-tolerant observer; request-correlated
/// observer copies are ignored because the route carries them.
pub(super) async fn receive_request_event(
    session: &RemoteSession,
    routed: &mut RequestEvents,
    observer: &mut broadcast::Receiver<RemoteSessionEvent>,
) -> Result<RemoteSessionEvent, RequestEventsError> {
    let mut exited = session.worker_serving_closed.subscribe();
    let mut observer_open = true;
    loop {
        if *exited.borrow_and_update() {
            return routed.try_recv();
        }
        tokio::select! {
            biased;
            _ = exited.changed() => return routed.try_recv(),
            event = observer.recv(), if observer_open => match event {
                Ok(event) if event.kind != RemoteSessionEventKind::RequestCorrelated => {
                    return Ok(event);
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, session_id = %session.session_id,
                        "remote request observer lagged; session notifications were skipped");
                }
                Err(broadcast::error::RecvError::Closed) => observer_open = false,
            },
            event = routed.recv() => return event,
        }
    }
}
