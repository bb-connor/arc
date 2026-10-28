use super::*;
use chio_kernel::budget_store::BudgetHoldCleanupCustody;
use std::sync::{Arc, Barrier};

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) fn assert_replayed_authorization(
    first: BudgetAuthorizeHoldDecision,
    replay: BudgetAuthorizeHoldDecision,
) {
    let BudgetAuthorizeHoldDecision::Authorized(mut expected) = first else {
        panic!("first decision must authorize the hold");
    };
    assert_eq!(expected.cleanup_custody, BudgetHoldCleanupCustody::Fresh);
    expected.cleanup_custody = BudgetHoldCleanupCustody::Replayed;
    assert_eq!(replay, BudgetAuthorizeHoldDecision::Authorized(expected));
}

fn authorize_request() -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: "cap-cleanup-custody".to_string(),
        grant_index: 0,
        max_invocations: None,
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(1_000),
        hold_id: Some("hold-cleanup-custody".to_string()),
        event_id: Some("hold-cleanup-custody:authorize".to_string()),
        authority: None,
    }
}

fn authorized(
    store: &SqliteBudgetStore,
) -> Result<BudgetHoldAuthorizationRecord, BudgetStoreError> {
    match store.authorize_budget_hold(authorize_request())? {
        BudgetAuthorizeHoldDecision::Authorized(record) => Ok(record),
        other => Err(BudgetStoreError::Invariant(format!(
            "unexpected decision: {other:?}"
        ))),
    }
}

#[test]
fn standalone_replay_after_reopen_never_recovers_fresh_custody() -> TestResult {
    let (_path_dir, path) = temp_sqlite_path("chio-budget-cleanup-custody-reopen");
    let store = SqliteBudgetStore::open(&path)?;
    let first = authorized(&store)?;
    assert_eq!(first.cleanup_custody, BudgetHoldCleanupCustody::Fresh);
    assert_eq!(store.max_mutation_event_seq()?, 1);
    drop(store);

    let reopened = SqliteBudgetStore::open(&path)?;
    let mut expected = first;
    expected.cleanup_custody = BudgetHoldCleanupCustody::Replayed;
    for _ in 0..2 {
        assert_eq!(authorized(&reopened)?, expected);
        assert_eq!(reopened.max_mutation_event_seq()?, 1);
        assert_eq!(
            reopened
                .get_usage("cap-cleanup-custody", 0)?
                .expect("usage")
                .committed_cost_units()?,
            100
        );
    }
    drop(reopened);
    fs::remove_file(path)?;
    Ok(())
}

#[test]
fn independent_connections_report_only_one_fresh_authorization() -> TestResult {
    let (_path_dir, path) = temp_sqlite_path("chio-budget-cleanup-custody-race");
    let stores = [
        SqliteBudgetStore::open(&path)?,
        SqliteBudgetStore::open(&path)?,
    ];
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = stores
        .into_iter()
        .map(|store| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                authorized(&store)
            })
        })
        .collect();
    let mut records = Vec::new();
    for thread in threads {
        records.push(thread.join().expect("authorization worker")?);
    }
    assert_eq!(
        records
            .iter()
            .filter(|record| record.cleanup_custody == BudgetHoldCleanupCustody::Fresh)
            .count(),
        1
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record.cleanup_custody == BudgetHoldCleanupCustody::Replayed)
            .count(),
        1
    );
    let reopened = SqliteBudgetStore::open(&path)?;
    assert_eq!(reopened.max_mutation_event_seq()?, 1);
    assert_eq!(
        reopened
            .get_usage("cap-cleanup-custody", 0)?
            .expect("usage")
            .committed_cost_units()?,
        100
    );
    drop(reopened);
    fs::remove_file(path)?;
    Ok(())
}
