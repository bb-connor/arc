//! Session output fan-out. The broadcast is loss-tolerant and carries
//! notifications for observers. Request-correlated output is also delivered on a
//! per-request route that is registered before the request is enqueued and
//! never drops an event.

use super::*;
use tokio::sync::mpsc;

#[derive(Debug)]
struct RequestRoute {
    generation: McpRequestGeneration,
    tx: mpsc::UnboundedSender<RemoteSessionEvent>,
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
pub(super) enum RequestRouteError {
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
pub(super) enum RequestEventsError {
    Closed,
}

#[derive(Clone, Debug)]
pub(super) struct SessionEventBus {
    broadcast: broadcast::Sender<RemoteSessionEvent>,
    routes: RouteTable,
}

impl SessionEventBus {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            broadcast: broadcast::channel(capacity).0,
            routes: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    pub(super) fn subscribe(&self) -> broadcast::Receiver<RemoteSessionEvent> {
        self.broadcast.subscribe()
    }

    #[cfg(test)]
    pub(super) fn receiver_count(&self) -> usize {
        self.broadcast.receiver_count()
    }

    /// Registers the lossless route for one admitted request. A generation that
    /// already has a live route is refused.
    pub(super) fn register_request(
        &self,
        generation: McpRequestGeneration,
    ) -> Result<RequestEvents, RequestRouteError> {
        let mut routes = lock_routes(&self.routes);
        if routes.iter().any(|route| route.generation == generation) {
            return Err(RequestRouteError::Duplicate);
        }
        let (tx, rx) = mpsc::unbounded_channel();
        routes.push(RequestRoute { generation, tx });
        Ok(RequestEvents {
            generation,
            rx,
            routes: self.routes.clone(),
        })
    }

    /// Request-correlated events reach their registered route before the
    /// observer broadcast, so a lagging observer cannot affect them.
    pub(super) fn send(
        &self,
        event: RemoteSessionEvent,
    ) -> Result<usize, broadcast::error::SendError<RemoteSessionEvent>> {
        if event.kind == RemoteSessionEventKind::RequestCorrelated {
            if let Some(generation) = event.request_generation {
                let routes = lock_routes(&self.routes);
                if let Some(route) = routes.iter().find(|route| route.generation == generation) {
                    let _ = route.tx.send(event.clone());
                }
            }
        }
        self.broadcast.send(event)
    }
}

/// Receiving half of one request's route. Dropping it removes the route.
pub(super) struct RequestEvents {
    generation: McpRequestGeneration,
    rx: mpsc::UnboundedReceiver<RemoteSessionEvent>,
    routes: RouteTable,
}

impl RequestEvents {
    pub(super) async fn recv(&mut self) -> Result<RemoteSessionEvent, RequestEventsError> {
        self.rx.recv().await.ok_or(RequestEventsError::Closed)
    }

    pub(super) fn try_recv(&mut self) -> Result<RemoteSessionEvent, RequestEventsError> {
        self.rx
            .try_recv()
            .map_err(|_| RequestEventsError::Closed)
    }
}

impl Drop for RequestEvents {
    fn drop(&mut self) {
        lock_routes(&self.routes).retain(|route| route.generation != self.generation);
    }
}
