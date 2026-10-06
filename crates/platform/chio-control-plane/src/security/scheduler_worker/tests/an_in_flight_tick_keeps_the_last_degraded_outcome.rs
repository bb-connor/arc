use super::*;

#[derive(Default)]
struct DegradedThenWedgedPort {
    wedged: AtomicBool,
    release: AtomicBool,
}

impl ResponseWorkerPort for DegradedThenWedgedPort {
    fn ensure_ready(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }

    fn tick(
        &self,
        tick_sequence: u64,
        _: bool,
    ) -> Result<ResponseWorkerTick, ResponseWorkerTickError> {
        if tick_sequence == 0 {
            return Err(ResponseWorkerTickError::Port(PortError::unavailable()));
        }
        self.wedged.store(true, Ordering::Release);
        while !self.release.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        Ok(tick("released"))
    }

    fn shutdown(&self) -> Result<(), ResponseWorkerTickError> {
        Ok(())
    }
}

#[test]
fn an_in_flight_tick_keeps_the_last_degraded_outcome() {
    let port = Arc::new(DegradedThenWedgedPort::default());
    let worker = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("worker: {error}")),
    );
    assert!(worker.tick_once().is_err());
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Degraded);

    let ticking = Arc::clone(&worker);
    let in_flight = std::thread::spawn(move || ticking.tick_once());
    while !port.wedged.load(Ordering::Acquire) {
        std::thread::yield_now();
    }
    let during = worker.health();
    port.release.store(true, Ordering::Release);
    let completed = in_flight.join();

    assert!(during.tick_in_flight);
    assert_eq!(during.lifecycle, ResponseWorkerLifecycle::Degraded);
    assert!(matches!(completed, Ok(Ok(_))));
    assert_eq!(worker.health().lifecycle, ResponseWorkerLifecycle::Ready);
}
