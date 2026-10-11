use super::*;
use chio_quarantine::ExecutorError;

/// Every durable side of one response that a scheduled pass can grow.
#[derive(Debug, Eq, PartialEq)]
struct DurableFootprint {
    record: ResponsePlanRecord,
    mutations: usize,
    receipts: usize,
    receipt_requests: usize,
    alerts: usize,
    effect_mutations: (usize, usize),
    effect_queries: usize,
    effect_transitions: usize,
}

impl DurableFootprint {
    fn capture(harness: &Harness, record: &ResponsePlanRecord) -> Self {
        let record = harness.load(record);
        let mutations = decode_response_record(&record)
            .unwrap_or_else(|error| panic!("decode response: {error}"))
            .mutations
            .as_slice()
            .len();
        Self {
            record,
            mutations,
            receipts: harness.receipts.receipts().len(),
            receipt_requests: harness.receipts.requests().len(),
            alerts: harness.alerts.count(),
            effect_mutations: harness.effects.mutation_counts(),
            effect_queries: harness.effects.contract_calls().1.len(),
            effect_transitions: harness
                .store
                .effect_transitions
                .lock()
                .unwrap_or_else(|_| panic!("effect transition mutex poisoned"))
                .len(),
        }
    }
}

fn failed_rollbacks(record: &ResponsePlanRecord) -> usize {
    decode_response_record(record)
        .unwrap_or_else(|error| panic!("decode response: {error}"))
        .mutations
        .as_slice()
        .iter()
        .filter(|mutation| {
            matches!(
                mutation,
                ResponseMutationRecord::Rollback(rollback)
                    if matches!(
                        rollback.outcome,
                        chio_security_types::ResponseRollbackOutcome::Failed { .. }
                    )
            )
        })
        .count()
}

/// Applies the single reversible effect, then expires the plan with every
/// remove failing, leaving one recorded rollback failure.
fn first_rollback_failure(
    harness: &Harness,
    executor: &ResponseExecutor<CrashStore, IdempotentEffects, TestReceipts, TestAlerts>,
) -> ResponsePlanRecord {
    let planned = create_plan(Arc::clone(&harness.store));
    let apply_work = work(&planned, 1, 900);
    harness.store.install_work(apply_work.clone());
    let active = executor
        .execute(&planned, &apply_work, 110)
        .unwrap_or_else(|error| panic!("apply failed: {error}"));
    harness.effects.fail_remove();
    let rollback_work = work(&active, 2, 1_500);
    harness.store.install_work(rollback_work.clone());
    let partial = executor
        .execute(&active, &rollback_work, 1_000)
        .unwrap_or_else(|error| panic!("first rollback failure: {error}"));
    let snapshot = decode_response_record(&partial)
        .unwrap_or_else(|error| panic!("decode partial rollback: {error}"));
    assert_eq!(snapshot.state, ResponseState::RollbackPartial);
    assert_eq!(failed_rollbacks(&partial), 1);
    partial
}

fn assert_due(record: &ResponsePlanRecord, now_unix_ms: u64) {
    let due = decode_response_record(record)
        .unwrap_or_else(|error| panic!("decode response: {error}"))
        .due_at_unix_ms
        .unwrap_or_else(|| panic!("rollback partial response has no due time"));
    assert!(
        now_unix_ms >= due,
        "the response must be due at {now_unix_ms}, due at {due}"
    );
}

#[test]
fn budget_exhausted_rollback_partial_rests_unchanged_when_due() {
    let harness = Harness::new();
    let executor = harness.executor();
    let first_failure = first_rollback_failure(&harness, &executor);

    let before_retry = DurableFootprint::capture(&harness, &first_failure);
    assert_due(&first_failure, 1_100);
    let retry_work = work(&first_failure, 3, 2_000);
    harness.store.install_work(retry_work.clone());
    let exhausted = executor
        .execute(&first_failure, &retry_work, 1_100)
        .unwrap_or_else(|error| panic!("in-budget rollback retry: {error}"));
    let after_retry = DurableFootprint::capture(&harness, &exhausted);
    assert!(after_retry.record.generation > before_retry.record.generation);
    assert!(after_retry.effect_queries > before_retry.effect_queries);
    assert_eq!(failed_rollbacks(&exhausted), 2);

    let rested = DurableFootprint::capture(&harness, &exhausted);
    let mut current = exhausted.clone();
    for (token, now_unix_ms) in [(4, 1_200), (5, 1_300), (6, 1_400), (7, 1_500)] {
        assert_due(&current, now_unix_ms);
        let due_work = work(&current, token, 2_000);
        harness.store.install_work(due_work.clone());
        current = executor
            .execute(&current, &due_work, now_unix_ms)
            .unwrap_or_else(|error| panic!("budget-exhausted pass at {now_unix_ms}: {error}"));
        assert_eq!(
            DurableFootprint::capture(&harness, &current),
            rested,
            "a due pass over a budget-exhausted rollback changed durable state at {now_unix_ms}"
        );
    }
    assert_eq!(current, exhausted);

    let snapshot = decode_response_record(&current)
        .unwrap_or_else(|error| panic!("decode rested response: {error}"));
    assert_eq!(snapshot.state, ResponseState::RollbackPartial);
    assert!(snapshot.operator_page_required);
    let effect_id = snapshot
        .plan
        .effects
        .as_slice()
        .first()
        .map(|effect| effect.effect_id.clone())
        .unwrap_or_else(|| panic!("plan has no effect"));
    assert_eq!(
        snapshot.effect_progress(&effect_id),
        Some(ResponseEffectProgress::RollbackFailed)
    );
    assert!(harness
        .effects
        .state()
        .installed
        .contains_key(effect_id.as_str()));

    let stale_work = work(&current, 8, 1_600);
    harness.store.install_work(stale_work.clone());
    assert!(matches!(
        executor.execute(&current, &stale_work, 1_600),
        Err(ExecutorError::StaleLease)
    ));
    assert_eq!(DurableFootprint::capture(&harness, &current), rested);
}

#[test]
fn rollback_partial_within_budget_is_retried_when_due() {
    let harness = Harness::new();
    let executor = harness.executor();
    let first_failure = first_rollback_failure(&harness, &executor);
    let before_retry = DurableFootprint::capture(&harness, &first_failure);
    harness.effects.state().fail_remove = false;

    assert_due(&first_failure, 1_100);
    let retry_work = work(&first_failure, 3, 2_000);
    harness.store.install_work(retry_work.clone());
    let lifted = executor
        .execute(&first_failure, &retry_work, 1_100)
        .unwrap_or_else(|error| panic!("in-budget rollback retry: {error}"));
    let after_retry = DurableFootprint::capture(&harness, &lifted);

    assert_eq!(
        decode_response_record(&lifted)
            .unwrap_or_else(|error| panic!("decode lifted response: {error}"))
            .state,
        ResponseState::Lifted
    );
    assert!(after_retry.record.generation > before_retry.record.generation);
    assert!(after_retry.mutations > before_retry.mutations);
    assert!(after_retry.effect_queries > before_retry.effect_queries);
    assert_eq!(after_retry.effect_mutations, (1, 1));
    assert_eq!(failed_rollbacks(&lifted), 1);
}
