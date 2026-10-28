use super::*;

#[test]
fn live_lease_on_a_retired_store_is_refused_as_store_retired() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let live = work(&planned, 1, 900);
    harness.store.install_work(live.clone());
    harness.store.retire();

    let error = expect_err(executor.execute(&planned, &live, 110));
    assert_eq!(
        error.code(),
        "urn:chio:error:kernel:response-executor-store-retired"
    );
    assert_eq!(harness.effects.mutation_counts(), (0, 0));
}

#[test]
fn superseded_lease_on_a_writable_store_is_stale() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let superseded = work(&planned, 1, 900);
    harness.store.install_work(work(&planned, 2, 900));

    let error = expect_err(executor.execute(&planned, &superseded, 110));
    assert!(matches!(error, ExecutorError::StaleLease), "{error:?}");
    assert_eq!(
        error.code(),
        "urn:chio:error:kernel:response-executor-stale-lease"
    );
    assert_eq!(harness.effects.mutation_counts(), (0, 0));
}
