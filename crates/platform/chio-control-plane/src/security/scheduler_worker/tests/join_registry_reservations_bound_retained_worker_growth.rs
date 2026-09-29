use super::*;
use crate::security::scheduler_worker::tests::*;

#[test]
fn join_registry_reservations_bound_retained_worker_growth() {
    let registry = Arc::new(ResponseWorkerReaperRegistry::new());
    let mut permits = Vec::new();
    for _ in 0..MAX_RESPONSE_WORKER_JOIN_OWNERS {
        permits.push(
            registry
                .acquire_without_service_for_test()
                .unwrap_or_else(|error| panic!("join permit: {error}")),
        );
    }
    assert!(matches!(
        registry.acquire_without_service_for_test(),
        Err(ResponseWorkerTickError::WorkerReaperCapacity)
    ));
    drop(permits);
    assert_eq!(registry.lock_state().join_owners, 0);
}
