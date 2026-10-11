use super::*;

struct AdmissionClosedPort {
    recovery: ScriptedWorkerPort,
}

impl ResponseWorkerPort for AdmissionClosedPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Err(ResponseWorkerTickError::Port(PortError::unavailable()))
    }

    fn ensure_recovery_ready(&self) -> Result<(), ResponseWorkerTickError> {
        self.recovery.ensure_ready()
    }

    fn tick(
        &self,
        tick_sequence: u64,
        shutdown_requested: bool,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        self.recovery.tick(tick_sequence, shutdown_requested)
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        self.recovery.shutdown()
    }
}

fn is_unavailable_port(result: Result<(), ResponseWorkerTickError>) -> bool {
    matches!(
        result,
        Err(ResponseWorkerTickError::Port(error))
            if error.kind() == chio_security_types::ports::PortErrorKind::Unavailable
    )
}

#[tokio::test]
async fn recovery_readiness_starts_the_worker_while_admission_stays_closed() {
    let port = Arc::new(AdmissionClosedPort {
        recovery: ScriptedWorkerPort::with_ticks(
            (0..1_000).map(|_| Ok(tick("recovery-only-tick"))).collect(),
        ),
    });
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("recovery-ready worker: {error}")),
    );
    let mut handle = worker
        .start_parked(ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(10),
        })
        .await
        .unwrap_or_else(|error| panic!("recovery-ready start: {error}"));
    handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm: {error}"));
    handle
        .release_publication()
        .unwrap_or_else(|error| panic!("release publication: {error}"));
    handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("initial recovery tick: {error}"));

    assert!(port.recovery.tick_calls() >= 1);
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Ready);
    assert!(is_unavailable_port(worker.ensure_ready()));
    assert!(is_unavailable_port(worker.ensure_bootstrap_ready()));
    handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown: {error}"));
    assert_eq!(port.recovery.shutdown_calls(), 1);

    port.recovery.set_ready(false);
    match ProductionResponseWorker::new_for_test(Arc::clone(&port)) {
        Ok(_) => panic!("worker constructed without recovery readiness"),
        Err(ResponseWorkerTickError::Port(error)) => assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::Unavailable
        ),
        Err(error) => panic!("worker construction failed for the wrong reason: {error}"),
    }
}
