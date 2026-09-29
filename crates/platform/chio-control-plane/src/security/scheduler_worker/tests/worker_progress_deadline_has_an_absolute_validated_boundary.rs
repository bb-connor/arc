use super::*;


#[test]
fn worker_progress_deadline_has_an_absolute_validated_boundary() {
    let rapid = ProductionResponseWorkerLoopConfig {
        tick_interval: Duration::from_millis(1),
    };
    assert_eq!(rapid.progress_deadline(), MIN_WORKER_PROGRESS_DEADLINE);

    let boundary = ProductionResponseWorkerLoopConfig {
        tick_interval: Duration::from_secs(30),
    };
    let validated = boundary
        .validate()
        .unwrap_or_else(|error| panic!("valid progress boundary rejected: {error}"));
    assert_eq!(validated, boundary);
    assert_eq!(boundary.progress_deadline(), MAX_WORKER_PROGRESS_DEADLINE);

    let above_boundary = ProductionResponseWorkerLoopConfig {
        tick_interval: Duration::from_secs(30) + Duration::from_nanos(1),
    };
    assert!(matches!(
        above_boundary.validate(),
        Err(ResponseWorkerTickError::InvalidConfig)
    ));
}
