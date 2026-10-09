//! Session output fan-out. The broadcast is loss-tolerant and carries
//! notifications for observers. Request-correlated output is also delivered on a
//! per-request route that is registered before the request is enqueued and
//! never drops an event.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{mpsc, oneshot};

/// Capacity of one request's non-terminal event queue.
///
/// A request-correlated event is either a server-initiated request issued on
/// behalf of the in-flight request (sampling, elicitation, roots) or the
/// terminal response. Notifications are never routed here; they travel on the
/// loss-tolerant observer broadcast. Server-initiated requests are issued
/// serially by the upstream tool call and each waits for the client's answer,
/// so a well-behaved request has a handful outstanding at most. 64 leaves wide
/// margin over that while keeping per-request memory fixed. The terminal
/// response never uses this queue: it has its own slot, so a full queue cannot
/// displace it.
pub(crate) const REQUEST_ROUTE_CAPACITY: usize = 64;

#[derive(Debug)]
struct RequestRoute {
    generation: McpRequestGeneration,
    tx: mpsc::Sender<RemoteSessionEvent>,
    terminal: Option<oneshot::Sender<RemoteSessionEvent>>,
    overflowed: Arc<AtomicBool>,
}

type RouteTable = Arc<StdMutex<Vec<RequestRoute>>>;

fn lock_routes(
    routes: &StdMutex<Vec<RequestRoute>>,
) -> std::sync::MutexGuard<'_, Vec<RequestRoute>> {
    routes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestRouteError {
    Duplicate,
}

impl From<RequestRouteError> for CliError {
    fn from(error: RequestRouteError) -> Self {
        match error {
            RequestRouteError::Duplicate => chio_kernel::KernelError::GovernedTransactionDenied(
                "remote MCP request is already registered for delivery".into(),
            )
            .into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestEventsError {
    Closed,
    /// The request produced more non-terminal events than its queue holds.
    /// Events were discarded, so the request is failed rather than resumed.
    Overflowed,
}

#[derive(Clone, Debug)]
pub(crate) struct SessionEventBus {
    broadcast: broadcast::Sender<RemoteSessionEvent>,
    routes: RouteTable,
}

impl SessionEventBus {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            broadcast: broadcast::channel(capacity).0,
            routes: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<RemoteSessionEvent> {
        self.broadcast.subscribe()
    }

    #[cfg(test)]
    pub(crate) fn receiver_count(&self) -> usize {
        self.broadcast.receiver_count()
    }

    /// Registers the lossless route for one admitted request. A generation that
    /// already has a live route is refused.
    pub(crate) fn register_request(
        &self,
        generation: McpRequestGeneration,
    ) -> Result<RequestEvents, RequestRouteError> {
        let mut routes = lock_routes(&self.routes);
        if routes.iter().any(|route| route.generation == generation) {
            return Err(RequestRouteError::Duplicate);
        }
        let (tx, rx) = mpsc::channel(REQUEST_ROUTE_CAPACITY);
        let (terminal_tx, terminal_rx) = oneshot::channel();
        let overflowed = Arc::new(AtomicBool::new(false));
        routes.push(RequestRoute {
            generation,
            tx,
            terminal: Some(terminal_tx),
            overflowed: overflowed.clone(),
        });
        Ok(RequestEvents {
            generation,
            rx,
            terminal_rx: Some(terminal_rx),
            pending_terminal: None,
            overflowed,
            finished: false,
            routes: self.routes.clone(),
        })
    }

    /// Request-correlated events reach their registered route before the
    /// observer broadcast, so a lagging observer cannot affect them. Delivery
    /// never blocks the caller: a response takes the route's terminal slot, and
    /// any other event that finds the queue full is discarded and marks that
    /// route overflowed. Other routes and the broadcast are unaffected.
    pub(crate) fn send(
        &self,
        event: RemoteSessionEvent,
    ) -> Result<usize, broadcast::error::SendError<RemoteSessionEvent>> {
        if event.kind == RemoteSessionEventKind::RequestCorrelated {
            if let Some(generation) = event.request_generation {
                let mut routes = lock_routes(&self.routes);
                if let Some(route) = routes
                    .iter_mut()
                    .find(|route| route.generation == generation)
                {
                    route.deliver(event.clone());
                }
            }
        }
        self.broadcast.send(event)
    }
}

impl RequestRoute {
    fn deliver(&mut self, event: RemoteSessionEvent) {
        if event.message.get("method").is_none() {
            if let Some(terminal) = self.terminal.take() {
                let _ = terminal.send(event);
            }
            return;
        }
        if self.overflowed.load(Ordering::Acquire) {
            return;
        }
        if self.tx.try_send(event).is_err() {
            self.overflowed.store(true, Ordering::Release);
        }
    }
}

/// Receiving half of one request's route. Dropping it removes the route.
pub(crate) struct RequestEvents {
    generation: McpRequestGeneration,
    rx: mpsc::Receiver<RemoteSessionEvent>,
    terminal_rx: Option<oneshot::Receiver<RemoteSessionEvent>>,
    pending_terminal: Option<RemoteSessionEvent>,
    overflowed: Arc<AtomicBool>,
    finished: bool,
    routes: RouteTable,
}

async fn wait_terminal(
    slot: &mut Option<oneshot::Receiver<RemoteSessionEvent>>,
) -> Option<RemoteSessionEvent> {
    match slot {
        Some(receiver) => {
            let outcome = receiver.await.ok();
            *slot = None;
            outcome
        }
        None => std::future::pending().await,
    }
}

impl RequestEvents {
    /// Returns the next event that is already available. Queued events precede
    /// the terminal response, which precedes nothing else. The overflow flag is
    /// read before the queue is drained so every event sent ahead of it is
    /// delivered first.
    fn poll_ready(&mut self) -> Option<Result<RemoteSessionEvent, RequestEventsError>> {
        if self.finished {
            return Some(Err(RequestEventsError::Closed));
        }
        let overflowed = self.overflowed.load(Ordering::Acquire);
        if self.pending_terminal.is_none() {
            if let Some(receiver) = self.terminal_rx.as_mut() {
                if let Ok(event) = receiver.try_recv() {
                    self.terminal_rx = None;
                    self.pending_terminal = Some(event);
                }
            }
        }
        if let Ok(event) = self.rx.try_recv() {
            return Some(Ok(event));
        }
        if overflowed {
            self.finished = true;
            return Some(Err(RequestEventsError::Overflowed));
        }
        self.pending_terminal.take().map(|event| {
            self.finished = true;
            Ok(event)
        })
    }

    pub(crate) async fn recv(&mut self) -> Result<RemoteSessionEvent, RequestEventsError> {
        loop {
            if let Some(ready) = self.poll_ready() {
                return ready;
            }
            tokio::select! {
                biased;
                event = self.rx.recv() => {
                    if let Some(event) = event {
                        return Ok(event);
                    }
                    self.finished = true;
                    return Err(RequestEventsError::Closed);
                }
                terminal = wait_terminal(&mut self.terminal_rx) => match terminal {
                    Some(event) => self.pending_terminal = Some(event),
                    None => {
                        self.finished = true;
                        return Err(RequestEventsError::Closed);
                    }
                },
            }
        }
    }

    pub(crate) fn try_recv(&mut self) -> Result<RemoteSessionEvent, RequestEventsError> {
        self.poll_ready().unwrap_or(Err(RequestEventsError::Closed))
    }
}

impl Drop for RequestEvents {
    fn drop(&mut self) {
        lock_routes(&self.routes).retain(|route| route.generation != self.generation);
    }
}
