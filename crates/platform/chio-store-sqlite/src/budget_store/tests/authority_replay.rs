use super::*;

type RichState = (
    Option<BudgetUsageRecord>,
    Vec<BudgetMutationRecord>,
    Option<SqliteBudgetHold>,
    u64,
);

fn case_capability(case: &str) -> String {
    format!("cap-authority-replay-{case}")
}

fn case_hold(case: &str) -> String {
    format!("hold-authority-replay-{case}")
}

fn authorize_request(
    case: &str,
    authority: Option<BudgetEventAuthority>,
) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: case_capability(case),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 100,
        max_cost_per_invocation: Some(100),
        max_total_cost_units: Some(100),
        hold_id: Some(case_hold(case)),
        event_id: Some(format!("{case}:authorize")),
        authority,
    }
}

fn capture_request(
    case: &str,
    authority: Option<BudgetEventAuthority>,
) -> BudgetCaptureInvocationRequest {
    BudgetCaptureInvocationRequest {
        capability_id: case_capability(case),
        grant_index: 0,
        hold_id: case_hold(case),
        event_id: format!("{case}:capture-invocation"),
        trusted_time: None,
        authority,
    }
}

fn rich_state(store: &SqliteBudgetStore, case: &str) -> Result<RichState, BudgetStoreError> {
    let capability_id = case_capability(case);
    let hold_id = case_hold(case);
    let usage = store.get_usage(&capability_id, 0)?;
    let events = store.list_mutation_events(32, Some(&capability_id), Some(0))?;
    let hold = {
        let mut connection = store.connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let hold = SqliteBudgetStore::load_hold(&transaction, &hold_id)?;
        transaction.rollback()?;
        hold
    };
    Ok((usage, events, hold, store.max_mutation_event_seq()?))
}

fn assert_exact_authority_replay<F>(
    store: &SqliteBudgetStore,
    case: &str,
    expected: &BudgetEventAuthority,
    mut replay: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(Option<BudgetEventAuthority>) -> Result<(), BudgetStoreError>,
{
    let before = rich_state(store, case)?;
    for supplied in [
        None,
        Some(authority("other-budget-authority", "other-lease", 99)),
    ] {
        let error = replay(supplied).expect_err("changed replay authority must fail closed");
        assert!(error
            .to_string()
            .contains("authority metadata does not match the original mutation"));
        assert_eq!(rich_state(store, case)?, before);
    }
    replay(Some(expected.clone()))?;
    assert_eq!(rich_state(store, case)?, before);
    Ok(())
}

#[test]
fn sqlite_rich_replays_require_the_persisted_authority_after_reopen(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-rich-authority-replay");
    let expected = authority("budget-primary", "lease-7", 7);
    {
        let store = SqliteBudgetStore::open(&path)?;
        for case in [
            "authorize",
            "capture",
            "reverse",
            "release",
            "reconcile",
            "cancel",
        ] {
            store.authorize_budget_hold(authorize_request(case, Some(expected.clone())))?;
        }
        store
            .capture_invocation_reservations(capture_request("capture", Some(expected.clone())))?;
        store.reverse_budget_hold(BudgetReverseHoldRequest {
            capability_id: case_capability("reverse"),
            grant_index: 0,
            reversed_exposure_units: 100,
            hold_id: Some(case_hold("reverse")),
            event_id: Some("reverse:reverse".to_string()),
            expected_cumulative_approval_state: None,
            authority: Some(expected.clone()),
        })?;
        store.release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: case_capability("release"),
            grant_index: 0,
            released_exposure_units: 100,
            hold_id: Some(case_hold("release")),
            event_id: Some("release:release".to_string()),
            authority: Some(expected.clone()),
        })?;
        store.capture_invocation_reservations(capture_request(
            "reconcile",
            Some(expected.clone()),
        ))?;
        store.reconcile_budget_hold(BudgetReconcileHoldRequest {
            capability_id: case_capability("reconcile"),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 75,
            hold_id: Some(case_hold("reconcile")),
            event_id: Some("reconcile:reconcile".to_string()),
            authority: Some(expected.clone()),
        })?;
        store.capture_invocation_reservations(capture_request("cancel", Some(expected.clone())))?;
        store.cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
            capability_id: case_capability("cancel"),
            grant_index: 0,
            hold_id: case_hold("cancel"),
            event_id: "cancel:cancel".to_string(),
            authority: Some(expected.clone()),
        })?;
    }

    let store = SqliteBudgetStore::open(&path)?;
    assert_exact_authority_replay(&store, "authorize", &expected, |authority| {
        store
            .authorize_budget_hold(authorize_request("authorize", authority))
            .map(|_| ())
    })?;
    assert_exact_authority_replay(&store, "capture", &expected, |authority| {
        store
            .capture_invocation_reservations(capture_request("capture", authority))
            .map(|_| ())
    })?;
    assert_exact_authority_replay(&store, "reverse", &expected, |authority| {
        store
            .reverse_budget_hold(BudgetReverseHoldRequest {
                capability_id: case_capability("reverse"),
                grant_index: 0,
                reversed_exposure_units: 100,
                hold_id: Some(case_hold("reverse")),
                event_id: Some("reverse:reverse".to_string()),
                expected_cumulative_approval_state: None,
                authority,
            })
            .map(|_| ())
    })?;
    assert_exact_authority_replay(&store, "release", &expected, |authority| {
        store
            .release_budget_hold(BudgetReleaseHoldRequest {
                capability_id: case_capability("release"),
                grant_index: 0,
                released_exposure_units: 100,
                hold_id: Some(case_hold("release")),
                event_id: Some("release:release".to_string()),
                authority,
            })
            .map(|_| ())
    })?;
    assert_exact_authority_replay(&store, "reconcile", &expected, |authority| {
        store
            .reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: case_capability("reconcile"),
                grant_index: 0,
                exposed_cost_units: 100,
                realized_spend_units: 75,
                hold_id: Some(case_hold("reconcile")),
                event_id: Some("reconcile:reconcile".to_string()),
                authority,
            })
            .map(|_| ())
    })?;
    assert_exact_authority_replay(&store, "cancel", &expected, |authority| {
        store
            .cancel_captured_before_dispatch(BudgetCancelCapturedBeforeDispatchRequest {
                capability_id: case_capability("cancel"),
                grant_index: 0,
                hold_id: case_hold("cancel"),
                event_id: "cancel:cancel".to_string(),
                authority,
            })
            .map(|_| ())
    })?;

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn sqlite_held_reconciliation_requires_invocation_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-budget-held-reconcile-capture-fence");
    let store = SqliteBudgetStore::open(&path)?;
    let case = "capture-fence";
    let expected = authority("budget-primary", "lease-7", 7);
    store.authorize_budget_hold(authorize_request(case, Some(expected.clone())))?;
    let before = rich_state(&store, case)?;
    let reconcile = BudgetReconcileHoldRequest {
        capability_id: case_capability(case),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 75,
        hold_id: Some(case_hold(case)),
        event_id: Some(format!("{case}:reconcile")),
        authority: Some(expected.clone()),
    };
    let error = store
        .reconcile_budget_hold(reconcile.clone())
        .expect_err("held reconciliation before invocation capture must fail closed");
    assert!(error
        .to_string()
        .contains("invocation was not captured before reconciliation"));
    assert_eq!(rich_state(&store, case)?, before);

    store.capture_invocation_reservations(capture_request(case, Some(expected)))?;
    let reconciled = store.reconcile_budget_hold(reconcile)?;
    assert_eq!(reconciled.invocation_state, BudgetInvocationState::Captured);
    assert_eq!(reconciled.monetary_state, BudgetMonetaryState::Reconciled);
    let usage = store
        .get_usage(&case_capability(case), 0)?
        .ok_or_else(|| std::io::Error::other("reconciled usage missing"))?;
    assert_usage_totals(&usage, 0, 75);

    let _ = fs::remove_file(path);
    Ok(())
}

fn assert_replay_refused(
    store: &SqliteBudgetStore,
    case: &str,
    current: &BudgetEventAuthority,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = rich_state(store, case)?;
    let request = authorize_request(case, Some(current.clone()));
    let error = store
        .replay_budget_authorization(&request, current)
        .expect_err("an unreplayable authorization must fail closed");
    assert!(
        matches!(&error, BudgetStoreError::Invariant(message) if message == expected),
        "unexpected replay refusal: {error}"
    );
    assert_eq!(rich_state(store, case)?, before);
    Ok(())
}

#[test]
fn sqlite_renewed_lease_replays_an_authorization_under_its_original_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-budget-renewed-lease-replay");
    let store = SqliteBudgetStore::open(&path)?;
    let original = authority("budget-primary", "budget-primary#term-2", 2);
    let renewed = authority("budget-primary", "budget-primary#term-3", 3);
    let mismatch = |case: &str| {
        format!("budget event_id `{case}:authorize` authority metadata does not match the original mutation")
    };
    for case in ["renewed", "conflict", "foreign", "future", "same-epoch"] {
        let admitted = match case {
            "foreign" => authority("budget-standby", "budget-standby#term-2", 2),
            "future" => authority("budget-primary", "budget-primary#term-4", 4),
            _ => original.clone(),
        };
        store.authorize_budget_hold(authorize_request(case, Some(admitted)))?;
    }

    // The ordinary path keeps the exact-authority contract under the renewed lease.
    let before = rich_state(&store, "renewed")?;
    let error = store
        .authorize_budget_hold(authorize_request("renewed", Some(renewed.clone())))
        .expect_err("an ordinary authorization under another lease must fail closed");
    assert!(
        matches!(&error, BudgetStoreError::Invariant(message) if *message == mismatch("renewed"))
    );
    assert_eq!(rich_state(&store, "renewed")?, before);

    // The replay-only path returns the original decision and metadata unchanged.
    let decision =
        store.replay_budget_authorization(&authorize_request("renewed", None), &renewed)?;
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = decision else {
        return Err("renewed-lease replay did not return the original authorization".into());
    };
    assert_eq!(authorized.metadata.authority, Some(original.clone()));
    assert_eq!(
        authorized.metadata.event_id.as_deref(),
        Some("renewed:authorize")
    );
    assert_eq!(rich_state(&store, "renewed")?, before);

    // A changed payload, another authority, a later epoch than the caller's lease
    // and a different lease at the same epoch all stay refused.
    let before = rich_state(&store, "conflict")?;
    let mut conflicting = authorize_request("conflict", Some(renewed.clone()));
    conflicting.requested_exposure_units = 90;
    let error = store
        .replay_budget_authorization(&conflicting, &renewed)
        .expect_err("a conflicting replay must fail closed");
    assert!(matches!(&error, BudgetStoreError::Invariant(message)
        if message == "budget event_id `conflict:authorize` was reused for a different mutation"));
    assert_eq!(rich_state(&store, "conflict")?, before);
    assert_replay_refused(&store, "foreign", &renewed, &mismatch("foreign"))?;
    assert_replay_refused(&store, "future", &renewed, &mismatch("future"))?;
    assert_replay_refused(
        &store,
        "same-epoch",
        &authority("budget-primary", "budget-primary#reissued-2", 2),
        &mismatch("same-epoch"),
    )?;

    // Replay never admits a mutation that does not already exist.
    assert_replay_refused(
        &store,
        "missing",
        &renewed,
        "budget event_id `missing:authorize` has no authorization to replay",
    )?;
    let (usage, events, hold, _) = rich_state(&store, "missing")?;
    assert!(usage.is_none() && events.is_empty() && hold.is_none());

    let _ = fs::remove_file(path);
    Ok(())
}
