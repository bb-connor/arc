//! Session request ownership at the pre-dispatch and sync-bridge boundaries.

use super::*;

#[path = "session_boundary/pre_dispatch_cancellation.rs"]
mod pre_dispatch_cancellation;

const HOLD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Parks the first caller of a kernel hook until the test releases it. Later
/// callers pass straight through, and every wait is bounded.
struct Checkpoint {
    armed: AtomicBool,
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

struct CheckpointControl {
    entered: mpsc::Receiver<()>,
    release: mpsc::Sender<()>,
}

fn checkpoint() -> (StdArc<Checkpoint>, CheckpointControl) {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    (
        StdArc::new(Checkpoint {
            armed: AtomicBool::new(true),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }),
        CheckpointControl {
            entered: entered_rx,
            release: release_tx,
        },
    )
}

impl Checkpoint {
    fn hold(&self) -> Result<(), String> {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return Ok(());
        }
        self.entered
            .send(())
            .map_err(|_| "checkpoint observer unavailable".to_string())?;
        self.release
            .lock()
            .map_err(|_| "checkpoint release lock poisoned".to_string())?
            .recv_timeout(HOLD_TIMEOUT)
            .map_err(|_| "checkpoint release timed out".to_string())
    }
}

/// Request-owned session state for one request, read from the live kernel.
#[derive(Debug, PartialEq)]
struct RequestState {
    inflight: bool,
    threshold_binding: Option<crate::session::PendingThresholdApproval>,
    cancellation_requested: bool,
    dispatch_active: bool,
    terminal: Option<OperationTerminalState>,
    lineage_terminal: Option<OperationTerminalState>,
    invocations: u64,
}

impl RequestState {
    fn read(fixture: &Fixture, context: &OperationContext) -> TestResult<Self> {
        let session = fixture
            .kernel
            .session(&context.session_id)
            .ok_or("session missing")?;
        let inflight = session.inflight().get(&context.request_id);
        Ok(Self {
            inflight: inflight.is_some(),
            threshold_binding: inflight
                .as_ref()
                .and_then(|request| request.pending_threshold_approval.clone()),
            cancellation_requested: inflight
                .as_ref()
                .is_some_and(|request| request.cancellation_requested),
            dispatch_active: session.is_request_dispatch_active(&context.request_id),
            terminal: session.terminal().get(&context.request_id),
            lineage_terminal: session
                .request_lineage(&context.request_id)
                .ok_or("request lineage missing")?
                .terminal_state,
            invocations: fixture.invocations.load(Ordering::SeqCst),
        })
    }

    /// An approved retry owns the wait: in flight, binding taken, not dispatched.
    fn claimed() -> Self {
        Self {
            inflight: true,
            threshold_binding: None,
            cancellation_requested: false,
            dispatch_active: false,
            terminal: None,
            lineage_terminal: None,
            invocations: 0,
        }
    }

    fn finished(terminal: OperationTerminalState, invocations: u64) -> Self {
        Self {
            inflight: false,
            threshold_binding: None,
            cancellation_requested: false,
            dispatch_active: false,
            terminal: Some(terminal.clone()),
            lineage_terminal: Some(terminal),
            invocations,
        }
    }
}
