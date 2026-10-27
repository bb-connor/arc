use super::*;

#[test]
fn takeover_after_apply_query_returns_stale_lease_before_effect() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let first_work = work(&planned, 1, 900);
    let takeover = work(&planned, 2, 900);
    harness.store.install_work(first_work.clone());
    harness.effects.state().takeover_on_query = Some((
        EffectOperation::Apply,
        Arc::clone(&harness.store),
        takeover.clone(),
    ));

    assert!(matches!(
        expect_err(executor.execute(&planned, &first_work, 110)),
        ExecutorError::StaleLease
    ));
    assert!(harness.effects.state().takeover_on_query.is_none());
    assert_eq!(harness.effects.mutation_counts(), (0, 0));
    let pending = harness.load(&planned);
    let active = executor
        .execute(&pending, &takeover, 111)
        .unwrap_or_else(|error| panic!("takeover apply failed: {error}"));
    assert_eq!(
        decode_response_record(&active)
            .unwrap_or_else(|error| panic!("decode active response: {error}"))
            .state,
        ResponseState::Active
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 0));
}

#[test]
fn takeover_after_rollback_query_returns_stale_lease_before_effect() {
    let harness = Harness::new();
    let executor = harness.executor();
    let planned = create_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("initial apply failed: {error}"));
    assert_eq!(harness.effects.mutation_counts(), (1, 0));
    let rollback = work(&active, 2, 1_500);
    let takeover = work(&active, 3, 1_500);
    harness.store.install_work(rollback.clone());
    harness.effects.state().takeover_on_query = Some((
        EffectOperation::Remove,
        Arc::clone(&harness.store),
        takeover.clone(),
    ));

    assert!(matches!(
        expect_err(executor.execute(&active, &rollback, 1_000)),
        ExecutorError::StaleLease
    ));
    assert!(harness.effects.state().takeover_on_query.is_none());
    assert_eq!(harness.effects.mutation_counts(), (1, 0));
    let pending = harness.load(&active);
    let lifted = executor
        .execute(&pending, &takeover, 1_001)
        .unwrap_or_else(|error| panic!("takeover rollback failed: {error}"));
    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("decode lifted response: {error}"))
            .state,
        ResponseState::Lifted
    );
    assert_eq!(harness.effects.mutation_counts(), (1, 1));
}
