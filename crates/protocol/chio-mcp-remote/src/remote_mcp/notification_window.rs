//! Hosted GET notification delivery from the retained session window.
//!
//! The session broadcast only wakes a GET stream. Notifications are read from
//! the retained window in sequence order, so a broadcast lag loses nothing the
//! window still holds. When the window can no longer show that it holds every
//! session-owned notification after the stream's cursor, the stream receives a
//! resync pass of re-read hints in standard MCP vocabulary. Resync items are
//! retained in the same window and are never broadcast to other consumers.
use super::*;

/// Consecutive incomplete lags after which a GET stream ends with
/// [`RESYNC_REQUIRED_EVENT`] instead of starting another pass.
const RESYNC_MAX_PASSES: u32 = 3;
const RESYNC_REQUIRED_EVENT: &str = "chio-resync-required";

/// The `list_changed` notifications a session declared, in resync order.
pub(super) fn declared_resync_catalogs(
    tools: bool,
    resources: bool,
    prompts: bool,
) -> Vec<&'static str> {
    [
        (tools, "notifications/tools/list_changed"),
        (resources, "notifications/resources/list_changed"),
        (prompts, "notifications/prompts/list_changed"),
    ]
    .into_iter()
    .filter_map(|(declared, method)| declared.then_some(method))
    .collect()
}

/// The re-read instruction a notification carries. Two notifications with the
/// same meaning tell a client to re-read the same thing.
fn reread_meaning(message: &Value) -> Option<(String, Option<String>)> {
    let method = message.get("method")?.as_str()?;
    match method {
        "notifications/tools/list_changed"
        | "notifications/resources/list_changed"
        | "notifications/prompts/list_changed" => Some((method.to_owned(), None)),
        "notifications/resources/updated" => Some((
            method.to_owned(),
            Some(message.pointer("/params/uri")?.as_str()?.to_owned()),
        )),
        _ => None,
    }
}

/// Retain one session-owned notification. A newer re-read hint replaces every
/// older retained hint with the same meaning, and the window keeps the newest
/// `DEFAULT_NOTIFICATION_REPLAY_WINDOW` entries.
pub(super) fn retain(
    window: &mut VecDeque<RetainedRemoteSessionEvent>,
    event: RetainedRemoteSessionEvent,
) {
    if let Some(meaning) = reread_meaning(&event.message) {
        window.retain(|older| reread_meaning(&older.message).as_ref() != Some(&meaning));
    }
    window.push_back(event);
    while window.len() > DEFAULT_NOTIFICATION_REPLAY_WINDOW {
        window.pop_front();
    }
}

pub(super) enum GetNext {
    Deliver { event_id: String, message: Value },
    ResyncRequired,
    Ended,
}

pub(super) struct GetNotificationSource {
    session: Arc<RemoteSession>,
    events: broadcast::Receiver<RemoteSessionEvent>,
    delivered_through: u64,
    pending: VecDeque<RetainedRemoteSessionEvent>,
    incomplete_passes: u32,
}

impl GetNotificationSource {
    /// `replay` is the validated replay after `delivered_through`, in sequence
    /// order. The receiver must be subscribed before that replay was taken.
    pub(super) fn new(
        session: Arc<RemoteSession>,
        events: broadcast::Receiver<RemoteSessionEvent>,
        delivered_through: u64,
        replay: Vec<RemoteSessionEvent>,
    ) -> Self {
        Self {
            session,
            events,
            delivered_through,
            pending: replay
                .into_iter()
                .map(|event| RetainedRemoteSessionEvent {
                    seq: event.seq,
                    event_id: event.event_id,
                    message: event.message,
                })
                .collect(),
            incomplete_passes: 0,
        }
    }

    pub(super) async fn next(&mut self) -> GetNext {
        loop {
            if *self.session.worker_serving_closed.borrow() {
                return GetNext::Ended;
            }
            if let Some(event) = self.pending.pop_front() {
                if event.seq > self.delivered_through {
                    self.delivered_through = event.seq;
                    return GetNext::Deliver {
                        event_id: event.event_id,
                        message: event.message,
                    };
                }
                continue;
            }
            match session_worker::receive(&self.session, &mut self.events).await {
                Ok(_) => self.incomplete_passes = 0,
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    if !self.window_is_complete() {
                        self.incomplete_passes = self.incomplete_passes.saturating_add(1);
                        if self.incomplete_passes > RESYNC_MAX_PASSES {
                            return GetNext::ResyncRequired;
                        }
                        if self.resync(skipped).is_err() {
                            return GetNext::Ended;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return GetNext::Ended,
            }
            self.collect();
        }
    }

    fn window(&self) -> std::sync::MutexGuard<'_, VecDeque<RetainedRemoteSessionEvent>> {
        self.session
            .retained_notification_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queue every retained notification after the cursor, in sequence order.
    fn collect(&mut self) {
        let delivered_through = self.delivered_through;
        let retained = self
            .window()
            .iter()
            .filter(|event| event.seq > delivered_through)
            .cloned()
            .collect::<Vec<_>>();
        self.pending.extend(retained);
    }

    /// The window still holds every session-owned notification after the
    /// cursor only if nothing after the cursor was evicted from its front.
    fn window_is_complete(&self) -> bool {
        self.window()
            .front()
            .is_some_and(|oldest| oldest.seq <= self.delivered_through.saturating_add(1))
    }

    /// Retain one re-read hint per declared catalog and live subscription,
    /// plus a warning naming the skipped count. Subscription authority is
    /// checked before any resource update is retained.
    fn resync(&self, skipped: u64) -> Result<(), ClockError> {
        let session = &self.session;
        let mut items = session
            .resync_catalogs
            .iter()
            .map(|method| json!({"jsonrpc": "2.0", "method": method}))
            .collect::<Vec<_>>();
        if session.subscription_authority_expired() {
            session.latch_subscription_authority_lost();
        } else {
            let uris = session
                .subscriptions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            items.extend(uris.into_iter().map(|uri| {
                json!({"jsonrpc": "2.0", "method": "notifications/resources/updated",
                    "params": {"uri": uri}})
            }));
        }
        items.push(json!({"jsonrpc": "2.0", "method": "notifications/message",
        "params": {"level": "warning", "logger": "chio",
            "data": format!(
                "notification stream skipped {skipped} session events; \
                 re-read every listed catalog and subscribed resource"
            )}}));
        let mut window = self.window();
        for message in items {
            let seq = crate::clock::next_counter(&session.next_event_id)?;
            retain(
                &mut window,
                RetainedRemoteSessionEvent {
                    seq,
                    event_id: format!("{}-{seq}", session.session_id),
                    message,
                },
            );
        }
        Ok(())
    }
}

/// The GET notification SSE response for an attached session.
pub(super) fn get_response(
    state: RemoteAppState,
    attachment: NotificationStreamAttachment,
    source: GetNotificationSource,
    priming_event_id: Option<String>,
    mode: &'static str,
) -> Response {
    let stream = stream! {
        let _attachment = attachment;
        let mut source = source;
        if let Some(id) = priming_event_id {
            yield Ok::<Event, Infallible>(Event::default().id(id)
                .retry(std::time::Duration::from_millis(DEFAULT_STREAM_RETRY_MILLIS)).data(""));
        }
        loop {
            match source.next().await {
                GetNext::Deliver { event_id, message } => {
                    yield Ok(Event::default().id(event_id).data(message.to_string()));
                }
                GetNext::ResyncRequired => {
                    warn!(session_id = %source.session.session_id,
                        "remote GET stream lagged through every resync pass");
                    yield Ok(Event::default().event(RESYNC_REQUIRED_EVENT).data(""));
                    break;
                }
                GetNext::Ended => {
                    warn!(session_id = %source.session.session_id,
                        "remote GET session output ended");
                    session_worker::close(&state, &source.session).await;
                    break;
                }
            }
        }
    };
    response_with_mode(Sse::new(stream).into_response(), mode)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "notification_window_tests.rs"]
mod tests;
