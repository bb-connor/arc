use super::*;


#[tokio::test]
async fn terminated_primary_reuses_its_durable_port_without_concurrent_ticks() {
    let failure = ResponseWorkerTickError::WorkerCrash(
        ErrorCode::new("response.primary_crash")
            .unwrap_or_else(|error| panic!("error code: {error}")),
    );
    let port = Arc::new(ScriptedWorkerPort::with_ticks(vec![
        Err(failure),
        Ok(tick("teardown-recovery")),
    ]));
    let primary = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("primary worker: {error}")),
    );
    let mut primary_handle = primary
        .start_parked(ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(10),
        })
        .await
        .unwrap_or_else(|error| panic!("start primary: {error}"));
    primary_handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm primary: {error}"));
    primary_handle
        .release_publication()
        .unwrap_or_else(|error| panic!("release primary: {error}"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while primary.health().lifecycle != ResponseWorkerLifecycle::Failed {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("primary did not fail"));
    assert!(primary_handle.shutdown().await.is_err());
    assert!(primary.shutdown_is_complete());

    let recovery = Arc::new(
        ProductionResponseWorker::new_for_test(Arc::clone(&port))
            .unwrap_or_else(|error| panic!("recovery worker: {error}")),
    );
    let mut recovery_handle = recovery
        .start_parked(ProductionResponseWorkerLoopConfig {
            tick_interval: Duration::from_millis(10),
        })
        .await
        .unwrap_or_else(|error| panic!("start recovery: {error}"));
    recovery_handle
        .arm()
        .await
        .unwrap_or_else(|error| panic!("arm recovery: {error}"));
    recovery_handle
        .release_publication()
        .unwrap_or_else(|error| panic!("release recovery: {error}"));
    recovery_handle
        .wait_for_publication_readiness()
        .await
        .unwrap_or_else(|error| panic!("recovery publication readiness: {error}"));
    tokio::time::timeout(Duration::from_secs(1), async {
        while port.tick_calls() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("recovery worker did not tick"));
    recovery_handle
        .shutdown()
        .await
        .unwrap_or_else(|error| panic!("shutdown recovery: {error}"));

    assert_eq!(port.maximum_concurrent_ticks(), 1);
}
