use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chio_quarantine::SchedulerError;
use chio_security_types::ports::{PortError, PortErrorKind, TenantId};

use super::{
    PlanningRecoveryResponseWorkerPort, ProductionResponseWorker,
    ProductionResponseWorkerLoopConfig, ResponseAdmissionPass, ResponseWorkerHealth,
    ResponseWorkerLifecycle, ResponseWorkerPort, ResponseWorkerTick, ResponseWorkerTickError,
};

type TickScript =
    Box<dyn Fn(u64) -> Result<ResponseWorkerTick, ResponseWorkerTickError> + Send + Sync>;

/// Recovery port whose ticks follow a script keyed by the tick sequence.
struct ScriptedRecoveryPort {
    script: TickScript,
}

impl ScriptedRecoveryPort {
    fn new(
        script: impl Fn(u64) -> Result<ResponseWorkerTick, ResponseWorkerTickError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            script: Box::new(script),
        }
    }
}

impl ResponseWorkerPort for ScriptedRecoveryPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }

    fn tick(
        &self,
        tick_sequence: u64,
        _: bool,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        (self.script)(tick_sequence)
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }
}

/// Admission pass that records each run and optionally fails it.
#[derive(Default)]
struct CountingAdmission {
    runs: AtomicU64,
    failure: Option<PortError>,
}

impl CountingAdmission {
    fn runs(&self) -> u64 {
        self.runs.load(Ordering::Acquire)
    }
}

impl ResponseAdmissionPass for CountingAdmission {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }

    fn run_once(&self) -> Result<(), ResponseWorkerTickError> {
        self.runs.fetch_add(1, Ordering::AcqRel);
        match &self.failure {
            Some(error) => Err(error.clone().into()),
            None => Ok(()),
        }
    }
}

fn clean_tick() -> ResponseWorkerTick {
    ResponseWorkerTick {
        tenant_id: TenantId::new("tenant-planning-recovery")
            .unwrap_or_else(|error| panic!("tenant: {error}")),
        declassification_receipts_appended: 0,
        declassification_receipts_acknowledged: 0,
        declassification_receipts_pending: 0,
        declassification_receipts_compacted: 0,
        claimed: 0,
        completed_action_ids: Vec::new(),
        retry_action_ids: Vec::new(),
        lease_lost_action_ids: Vec::new(),
    }
}

fn composed(
    recovery: ScriptedRecoveryPort,
    admission: &Arc<CountingAdmission>,
) -> PlanningRecoveryResponseWorkerPort {
    let admission: Arc<dyn ResponseAdmissionPass> = admission.clone();
    PlanningRecoveryResponseWorkerPort::new(Arc::new(recovery), admission)
}

/// Every recovery error other than a terminal cleanup backlog: global store,
/// integrity and clock faults, and declassification outbox failures.
type RecoveryFailureCase = (&'static str, fn() -> ResponseWorkerTickError);

fn fatal_recovery_errors() -> Vec<RecoveryFailureCase> {
    vec![
        ("store unavailable", || {
            ResponseWorkerTickError::Port(PortError::unavailable())
        }),
        ("store integrity", || {
            ResponseWorkerTickError::Port(PortError::integrity_failure())
        }),
        ("clock rollback", || {
            ResponseWorkerTickError::Scheduler(SchedulerError::ClockRollback)
        }),
        ("declassification integrity", || {
            ResponseWorkerTickError::DeclassificationOutbox(PortError::integrity_failure())
        }),
        ("declassification no progress", || {
            ResponseWorkerTickError::DeclassificationOutboxNoProgress(2)
        }),
    ]
}

fn same_error(left: &ResponseWorkerTickError, right: &ResponseWorkerTickError) -> bool {
    use ResponseWorkerTickError::{
        DeclassificationOutbox, DeclassificationOutboxNoProgress, Port, Scheduler,
        TerminalSchedulerCleanupPending,
    };
    match (left, right) {
        (Port(left), Port(right))
        | (DeclassificationOutbox(left), DeclassificationOutbox(right)) => {
            left.kind() == right.kind() && left.code() == right.code()
        }
        (Scheduler(SchedulerError::ClockRollback), Scheduler(SchedulerError::ClockRollback))
        | (TerminalSchedulerCleanupPending, TerminalSchedulerCleanupPending) => true,
        (DeclassificationOutboxNoProgress(left), DeclassificationOutboxNoProgress(right)) => {
            left == right
        }
        _ => false,
    }
}

#[test]
fn a_terminal_cleanup_backlog_still_admits_and_keeps_the_pending_error() {
    let admission = Arc::new(CountingAdmission::default());
    let port = composed(
        ScriptedRecoveryPort::new(|_| {
            Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
        }),
        &admission,
    );

    let result = port.tick(1, false);

    assert!(
        matches!(
            result,
            Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
        ),
        "the backlog must stay visible to worker health: {result:?}"
    );
    assert_eq!(admission.runs(), 1);
}

#[test]
fn a_failed_admission_during_a_terminal_cleanup_backlog_keeps_the_pending_error() {
    let admission = Arc::new(CountingAdmission {
        runs: AtomicU64::new(0),
        failure: Some(PortError::integrity_failure()),
    });
    let port = composed(
        ScriptedRecoveryPort::new(|_| {
            Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
        }),
        &admission,
    );

    let result = port.tick(1, false);

    assert!(
        matches!(
            result,
            Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
        ),
        "{result:?}"
    );
    assert_eq!(admission.runs(), 1);
}

#[test]
fn a_shutdown_tick_with_a_terminal_cleanup_backlog_admits_nothing() {
    let admission = Arc::new(CountingAdmission::default());
    let port = composed(
        ScriptedRecoveryPort::new(|_| {
            Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
        }),
        &admission,
    );

    let result = port.tick(1, true);

    assert!(
        matches!(
            result,
            Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
        ),
        "{result:?}"
    );
    assert_eq!(admission.runs(), 0);
}

#[test]
fn every_other_recovery_error_stops_the_tick_before_admission() {
    for (case, error) in fatal_recovery_errors() {
        let admission = Arc::new(CountingAdmission::default());
        let port = composed(ScriptedRecoveryPort::new(move |_| Err(error())), &admission);

        let result = port.tick(1, false);

        match result {
            Err(returned) => assert!(
                same_error(&returned, &error()),
                "{case}: the original recovery error must be returned, got {returned:?}"
            ),
            Ok(_) => panic!("{case}: a failed recovery tick reported success"),
        }
        assert_eq!(
            admission.runs(),
            0,
            "{case}: admission ran after a fatal fault"
        );
    }
}

#[test]
fn a_clean_recovery_tick_returns_the_admission_error() {
    let admission = Arc::new(CountingAdmission {
        runs: AtomicU64::new(0),
        failure: Some(PortError::integrity_failure()),
    });
    let port = composed(ScriptedRecoveryPort::new(|_| Ok(clean_tick())), &admission);

    match port.tick(1, false) {
        Err(ResponseWorkerTickError::Port(error)) => {
            assert_eq!(error.kind(), PortErrorKind::IntegrityFailure);
        }
        other => panic!("the admission error must reach worker health: {other:?}"),
    }
    assert_eq!(admission.runs(), 1);
}

async fn observe_failing_worker(
    after_publication: fn() -> ResponseWorkerTickError,
    admission: &Arc<CountingAdmission>,
) -> ResponseWorkerHealth {
    let recovery = ScriptedRecoveryPort::new(move |sequence| {
        if sequence == 0 {
            Ok(clean_tick())
        } else {
            Err(after_publication())
        }
    });
    let port: Arc<dyn ResponseWorkerPort> = Arc::new(composed(recovery, admission));
    let worker = Arc::new(
        ProductionResponseWorker::new(port).unwrap_or_else(|error| panic!("worker: {error}")),
    );
    let mut handle = worker
        .start_parked(ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(10),
        })
        .await
        .unwrap_or_else(|error| panic!("start worker: {error}"));
    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm worker: {error}"));
    handle
        .release_publication()
        .unwrap_or_else(|error| panic!("release publication: {error}"));
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("publication readiness: {error}"));

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let health = worker.health();
            if health.ticks_attempted >= 4 && !health.tick_in_flight {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the worker stopped ticking"));
    let health = worker.health();
    assert!(
        matches!(
            worker.ensure_ready(),
            Err(ResponseWorkerTickError::WorkerNotReady(
                ResponseWorkerLifecycle::Degraded
            ))
        ),
        "a failing recovery tick must keep readiness closed"
    );
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown worker: {error}"));
    health
}

#[tokio::test]
async fn a_worker_admits_through_a_terminal_cleanup_backlog_with_readiness_closed() {
    let admission = Arc::new(CountingAdmission::default());

    let health = observe_failing_worker(
        || ResponseWorkerTickError::TerminalSchedulerCleanupPending,
        &admission,
    )
    .await;

    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Degraded);
    assert_eq!(
        health.last_error,
        Some(ResponseWorkerTickError::TerminalSchedulerCleanupPending.to_string())
    );
    assert!(
        admission.runs() >= 4,
        "admission stopped during the backlog after {} runs",
        admission.runs()
    );
}

#[tokio::test]
async fn a_worker_with_a_fatal_recovery_fault_admits_nothing_after_it() {
    let admission = Arc::new(CountingAdmission::default());

    let health = observe_failing_worker(
        || ResponseWorkerTickError::Port(PortError::unavailable()),
        &admission,
    )
    .await;

    assert_eq!(health.lifecycle, ResponseWorkerLifecycle::Degraded);
    assert_eq!(
        health.last_error,
        Some(ResponseWorkerTickError::Port(PortError::unavailable()).to_string())
    );
    assert_eq!(
        admission.runs(),
        1,
        "only the clean publication tick may admit"
    );
}

#[test]
fn a_successful_shutdown_tick_admits_nothing() {
    let admission = Arc::new(CountingAdmission::default());
    let port = composed(ScriptedRecoveryPort::new(|_| Ok(clean_tick())), &admission);

    let result = port.tick(1, true);

    assert!(
        result.is_ok(),
        "shutdown must retain the recovery outcome: {result:?}"
    );
    assert_eq!(admission.runs(), 0, "shutdown must never admit new work");
}
