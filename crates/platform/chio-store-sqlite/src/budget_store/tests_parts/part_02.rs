#[test]
fn concurrent_composite_authorizations_admit_exactly_one_final_unit() {
    let path = unique_db_path("chio-composite-budget-concurrency");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let stores = [
        SqliteBudgetStore::open(&path).unwrap(),
        SqliteBudgetStore::open(&path).unwrap(),
    ];
    let mut threads = Vec::new();
    for (index, store) in stores.into_iter().enumerate() {
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .authorize_composite_hold(composite_authorize_input(
                    &format!("hold-race-{index}"),
                    &format!("event-race-{index}"),
                    1,
                ))
                .unwrap()
                .is_authorized()
        }));
    }
    let outcomes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|allowed| **allowed).count(), 1);

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );
    let _ = fs::remove_file(path);
}

#[test]
fn composite_invocation_capture_is_atomic_idempotent_and_restart_durable() {
    let path = unique_db_path("chio-composite-budget-capture");
    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-capture-1".to_string()),
        event_id: Some("event-capture-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-capture-1")),
    };
    let captured = {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .authorize_composite_hold(composite_authorize_input(
                "hold-capture-1",
                "event-authorize-capture-1",
                2,
            ))
            .unwrap()
            .is_authorized());
        store
            .capture_invocation_reservations(capture_request.clone())
            .unwrap()
    };
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Exposed);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_invocation_only_capture_terminalizes_the_base_hold() {
    let path = unique_db_path("chio-composite-budget-invocation-only");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let mut authorization = composite_authorize_input(
        "hold-invocation-only-1",
        "event-authorize-invocation-only-1",
        1,
    );
    authorization.requested_exposure_units = 0;
    authorization.max_cost_per_invocation = None;
    authorization.max_total_cost_units = None;
    let authorized = store.authorize_composite_hold(authorization).unwrap();
    let BudgetAuthorizeHoldDecision::Authorized(authorized) = authorized else {
        panic!("invocation-only composite authorization should pass");
    };
    assert_eq!(authorized.monetary_state, BudgetMonetaryHoldState::None);

    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-invocation-only-1".to_string()),
        event_id: Some("event-capture-invocation-only-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-invocation-only-1")),
    };
    let captured = store
        .capture_invocation_reservations(capture_request.clone())
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::None);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    assert_eq!(
        persisted_hold_disposition(&store, "hold-invocation-only-1"),
        HoldDisposition::Captured
    );

    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );
    let _ = fs::remove_file(path);
}

#[test]
fn composite_invocation_only_reconcile_accepts_zero_monetary_state() {
    let path = unique_db_path("chio-composite-budget-invocation-only-reconcile");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let mut authorization = composite_authorize_input(
        "hold-invocation-only-reconcile-1",
        "event-authorize-invocation-only-reconcile-1",
        1,
    );
    authorization.requested_exposure_units = 0;
    authorization.max_cost_per_invocation = None;
    authorization.max_total_cost_units = None;
    assert!(store
        .authorize_composite_hold(authorization)
        .unwrap()
        .is_authorized());

    let reconcile_request = BudgetReconcileHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 0,
        realized_spend_units: 0,
        hold_id: Some("hold-invocation-only-reconcile-1".to_string()),
        event_id: Some("event-reconcile-invocation-only-reconcile-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding(
            "hold-invocation-only-reconcile-1",
        )),
    };
    let reconciled = store
        .reconcile_budget_hold(reconcile_request.clone())
        .unwrap();
    assert_eq!(
        reconciled.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(
        reconciled.monetary_state,
        BudgetMonetaryHoldState::Reconciled
    );

    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.reconcile_budget_hold(reconcile_request).unwrap(),
        reconciled
    );
    let _ = fs::remove_file(path);
}

#[test]
fn artifact_bound_hold_rejects_ordinary_invocation_capture() {
    let path = unique_db_path("chio-composite-budget-combined-only");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let mut authorization =
        composite_authorize_input("hold-combined-only-1", "event-authorize-combined-only-1", 2);
    authorization.authorization_artifact_digests = vec!["11".repeat(32)];
    assert!(store
        .authorize_composite_hold(authorization)
        .unwrap()
        .is_authorized());
    let error = store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some("hold-combined-only-1".to_string()),
            event_id: Some("event-capture-combined-only-1".to_string()),
            authority: None,
            admission_operation: Some(composite_admission_binding("hold-combined-only-1")),
        })
        .expect_err("artifact-bound capture must use AdmissionCaptureAuthority");
    assert!(error
        .to_string()
        .contains("combined admission capture authority"));
    let _ = fs::remove_file(path);
}

#[test]
fn composite_reverse_restores_every_reserved_quota_and_survives_restart() {
    let path = unique_db_path("chio-composite-budget-reverse");
    let reverse_request = BudgetReverseHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        reversed_exposure_units: 100,
        hold_id: Some("hold-reverse-composite-1".to_string()),
        event_id: Some("event-reverse-composite-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-reverse-composite-1")),
    };
    let reversed = {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .authorize_composite_hold(composite_authorize_input(
                "hold-reverse-composite-1",
                "event-authorize-reverse-composite-1",
                1,
            ))
            .unwrap()
            .is_authorized());
        store.reverse_budget_hold(reverse_request.clone()).unwrap()
    };
    assert_eq!(
        reversed.invocation_state,
        BudgetInvocationReservationState::Reversed
    );
    assert_eq!(reversed.monetary_state, BudgetMonetaryHoldState::Reversed);
    assert!(reversed
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 0
        ));

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.reverse_budget_hold(reverse_request).unwrap(),
        reversed
    );
    let exact = reopened
        .get_mutation_event_by_id("event-reverse-composite-1")
        .unwrap()
        .expect("exact composite reverse event");
    assert_eq!(
        exact.invocation_counts_after,
        reversed.invocation_counts_after
    );
    assert_eq!(exact.invocation_state, reversed.invocation_state);
    assert_eq!(exact.monetary_state, reversed.monetary_state);
    assert_eq!(exact.revocation_set, reversed.revocation_set);
    assert_eq!(
        exact
            .total_cost_exposed_after
            .checked_add(exact.total_cost_realized_spend_after)
            .expect("committed total"),
        reversed.committed_cost_units_after
    );
    assert_eq!(
        reopened
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        0
    );
    assert!(reopened
        .authorize_composite_hold(composite_authorize_input(
            "hold-reverse-composite-2",
            "event-authorize-reverse-composite-2",
            1,
        ))
        .unwrap()
        .is_authorized());

    let _ = fs::remove_file(path);
}

#[test]
fn composite_reconcile_preserves_captured_invocation_evidence() {
    let path = unique_db_path("chio-composite-budget-reconcile");
    let reconcile_request = BudgetReconcileHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 30,
        hold_id: Some("hold-reconcile-composite-1".to_string()),
        event_id: Some("event-reconcile-composite-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-reconcile-composite-1")),
    };
    let reconciled = {
        let store = SqliteBudgetStore::open(&path).unwrap();
        assert!(store
            .authorize_composite_hold(composite_authorize_input(
                "hold-reconcile-composite-1",
                "event-authorize-reconcile-composite-1",
                2,
            ))
            .unwrap()
            .is_authorized());
        store
            .capture_invocation_reservations(BudgetCaptureInvocationRequest {
                capability_id: "leaf".to_string(),
                grant_index: 0,
                hold_id: Some("hold-reconcile-composite-1".to_string()),
                event_id: Some("event-capture-reconcile-composite-1".to_string()),
                authority: None,
                admission_operation: Some(composite_admission_binding(
                    "hold-reconcile-composite-1",
                )),
            })
            .unwrap();
        store
            .reconcile_budget_hold(reconcile_request.clone())
            .unwrap()
    };
    assert_eq!(
        reconciled.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(
        reconciled.monetary_state,
        BudgetMonetaryHoldState::Reconciled
    );
    assert_eq!(reconciled.committed_cost_units_after, 30);
    assert!(reconciled
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.reconcile_budget_hold(reconcile_request).unwrap(),
        reconciled
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_reconcile_before_invocation_capture_consumes_reserved_capacity() {
    let path = unique_db_path("chio-composite-budget-reconcile-first");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-reconcile-first-1",
            "event-authorize-reconcile-first-1",
            1,
        ))
        .unwrap()
        .is_authorized());

    let reconcile_request = BudgetReconcileHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 30,
        hold_id: Some("hold-reconcile-first-1".to_string()),
        event_id: Some("event-reconcile-first-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-reconcile-first-1")),
    };
    let reconciled = store
        .reconcile_budget_hold(reconcile_request.clone())
        .unwrap();
    assert_eq!(
        reconciled.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(
        reconciled.monetary_state,
        BudgetMonetaryHoldState::Reconciled
    );
    assert!(reconciled
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));

    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-reconcile-first-1".to_string()),
        event_id: Some("event-capture-reconcile-first-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-reconcile-first-1")),
    };
    let captured = store
        .capture_invocation_reservations(capture_request.clone())
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Reconciled);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    assert_eq!(
        store
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );
    assert_eq!(
        persisted_hold_disposition(&store, "hold-reconcile-first-1"),
        HoldDisposition::Reconciled
    );
    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.reconcile_budget_hold(reconcile_request).unwrap(),
        reconciled
    );
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_partial_release_preserves_invocation_state_and_remaining_exposure() {
    let path = unique_db_path("chio-composite-budget-release");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-release-composite-1",
            "event-authorize-release-composite-1",
            2,
        ))
        .unwrap()
        .is_authorized());
    store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some("hold-release-composite-1".to_string()),
            event_id: Some("event-capture-release-composite-1".to_string()),
            authority: None,
            admission_operation: Some(composite_admission_binding("hold-release-composite-1")),
        })
        .unwrap();
    let partial = store
        .release_budget_hold(BudgetReleaseHoldRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            released_exposure_units: 40,
            hold_id: Some("hold-release-composite-1".to_string()),
            event_id: Some("event-release-composite-1".to_string()),
            authority: None,
            admission_operation: Some(composite_admission_binding("hold-release-composite-1")),
        })
        .unwrap();
    assert_eq!(
        partial.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(partial.monetary_state, BudgetMonetaryHoldState::Exposed);
    assert_eq!(partial.committed_cost_units_after, 60);

    let final_request = BudgetReleaseHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        released_exposure_units: 60,
        hold_id: Some("hold-release-composite-1".to_string()),
        event_id: Some("event-release-composite-2".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-release-composite-1")),
    };
    let released = store.release_budget_hold(final_request.clone()).unwrap();
    assert_eq!(
        released.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(released.monetary_state, BudgetMonetaryHoldState::Released);
    assert_eq!(released.committed_cost_units_after, 0);
    drop(store);

    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.release_budget_hold(final_request).unwrap(),
        released
    );
    let _ = fs::remove_file(path);
}

#[test]
fn composite_full_release_before_invocation_capture_consumes_reserved_capacity() {
    let path = unique_db_path("chio-composite-budget-release-first");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-release-first-1",
            "event-authorize-release-first-1",
            1,
        ))
        .unwrap()
        .is_authorized());

    let release_request = BudgetReleaseHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        released_exposure_units: 100,
        hold_id: Some("hold-release-first-1".to_string()),
        event_id: Some("event-release-first-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-release-first-1")),
    };
    let released = store.release_budget_hold(release_request.clone()).unwrap();
    assert_eq!(
        released.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(released.monetary_state, BudgetMonetaryHoldState::Released);
    assert!(released
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));

    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-release-first-1".to_string()),
        event_id: Some("event-capture-release-first-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-release-first-1")),
    };
    let captured = store
        .capture_invocation_reservations(capture_request.clone())
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Released);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    assert_eq!(
        store
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );
    assert_eq!(
        persisted_hold_disposition(&store, "hold-release-first-1"),
        HoldDisposition::Released
    );
    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened.release_budget_hold(release_request).unwrap(),
        released
    );
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );

    let _ = fs::remove_file(path);
}

#[test]
fn composite_monetary_capture_preserves_captured_invocation_evidence() {
    let path = unique_db_path("chio-composite-budget-monetary-capture");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-monetary-capture-1",
            "event-authorize-monetary-capture-1",
            2,
        ))
        .unwrap()
        .is_authorized());
    store
        .capture_invocation_reservations(BudgetCaptureInvocationRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            hold_id: Some("hold-monetary-capture-1".to_string()),
            event_id: Some("event-invocation-monetary-capture-1".to_string()),
            authority: None,
            admission_operation: Some(composite_admission_binding("hold-monetary-capture-1")),
        })
        .unwrap();
    let captured = store
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "leaf".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 25,
            hold_id: Some("hold-monetary-capture-1".to_string()),
            event_id: Some("event-monetary-capture-1".to_string()),
            authority: None,
            admission_operation: Some(composite_admission_binding("hold-monetary-capture-1")),
        })
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
    assert_eq!(captured.committed_cost_units_after, 25);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    let _ = fs::remove_file(path);
}

#[test]
fn composite_monetary_capture_before_invocation_capture_consumes_reserved_capacity() {
    let path = unique_db_path("chio-composite-budget-monetary-capture-first");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-monetary-capture-first-1",
            "event-authorize-monetary-capture-first-1",
            1,
        ))
        .unwrap()
        .is_authorized());

    let monetary_capture_request = BudgetCaptureHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 25,
        hold_id: Some("hold-monetary-capture-first-1".to_string()),
        event_id: Some("event-monetary-capture-first-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-monetary-capture-first-1")),
    };
    let monetary_captured = store
        .capture_budget_hold(monetary_capture_request.clone())
        .unwrap();
    assert_eq!(
        monetary_captured.invocation_state,
        BudgetInvocationReservationState::Authorized
    );
    assert_eq!(
        monetary_captured.monetary_state,
        BudgetMonetaryHoldState::Captured
    );
    assert!(monetary_captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));

    let capture_request = BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-monetary-capture-first-1".to_string()),
        event_id: Some("event-capture-monetary-capture-first-1".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding("hold-monetary-capture-first-1")),
    };
    let captured = store
        .capture_invocation_reservations(capture_request.clone())
        .unwrap();
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
    assert!(captured
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 0 && usage.captured_invocations_after == 1
        ));
    assert_eq!(
        store
            .get_usage("leaf", 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        1
    );
    assert_eq!(
        persisted_hold_disposition(&store, "hold-monetary-capture-first-1"),
        HoldDisposition::Captured
    );
    drop(store);
    let reopened = SqliteBudgetStore::open(&path).unwrap();
    assert_eq!(
        reopened
            .capture_budget_hold(monetary_capture_request)
            .unwrap(),
        monetary_captured
    );
    assert_eq!(
        reopened
            .capture_invocation_reservations(capture_request)
            .unwrap(),
        captured
    );

    let _ = fs::remove_file(path);
}

#[test]
fn budget_usage_query_rejects_negative_persisted_counter() {
    let path = unique_db_path("chio-budget-negative-usage");
    let store = SqliteBudgetStore::open(&path).unwrap();
    import_usage_with_immutable_maximum(
        &store,
        &usage_record("cap-negative", 0, 1, 10, 1, 0, 0),
        u32::MAX,
    )
    .unwrap();
    {
        let connection = store.connection().unwrap();
        connection
            .execute(
                r#"
                    UPDATE capability_grant_budgets
                    SET invocation_count = -1
                    WHERE capability_id = 'cap-negative' AND grant_index = 0
                    "#,
                [],
            )
            .unwrap();
    }

    let error = store
        .list_all_usages()
        .expect_err("negative persisted budget counters must fail closed");
    assert!(
        error
            .to_string()
            .contains("budget field `invocation_count` was negative"),
        "unexpected error: {error}"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_rejects_pre_split_budget_schema() {
    let path = unique_db_path("chio-budget-pre-split-schema");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
                    CREATE TABLE capability_grant_budgets (
                        capability_id TEXT NOT NULL,
                        grant_index INTEGER NOT NULL,
                        invocation_count INTEGER NOT NULL,
                        updated_at INTEGER NOT NULL,
                        total_cost_charged INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (capability_id, grant_index)
                    );
                    INSERT INTO capability_grant_budgets (
                        capability_id,
                        grant_index,
                        invocation_count,
                        updated_at,
                        total_cost_charged
                    ) VALUES ('cap-1', 0, 1, 10, 55);
                    "#,
            )
            .unwrap();
    }

    let error = match SqliteBudgetStore::open(&path) {
        Ok(_) => panic!("pre-split budget schema should be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains(
        "missing split cost columns `total_cost_exposed` and `total_cost_realized_spend`"
    ));

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_upsert_usage_keeps_newer_seq_state() {
    let path = unique_db_path("chio-budget-upsert");
    let store = SqliteBudgetStore::open(&path).unwrap();
    import_usage_with_immutable_maximum(
        &store,
        &usage_record("cap-1", 0, 3, 10, 3, 300, 0),
        u32::MAX,
    )
    .unwrap();
    import_usage_with_immutable_maximum(
        &store,
        &usage_record("cap-1", 0, 2, 9, 2, 200, 0),
        u32::MAX,
    )
    .unwrap();

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 3);
    assert_usage_totals(&records[0], 300, 0);
    assert_eq!(records[0].seq, 3);

    let _ = fs::remove_file(path);
}

#[test]
fn legacy_usage_import_rejects_nonzero_invocations_without_quota_authority() {
    let path = unique_db_path("chio-budget-upsert-requires-quota");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let record = usage_record("cap-unscoped-import", 0, 1, 10, 3, 0, 0);
    let existing_quota = compatibility_quota_usage_record("cap-unscoped-import", 0, 10, 0, 0, 0);
    store
        .import_snapshot_records_with_invocation_quotas(&[], &[existing_quota], &[])
        .unwrap();

    let error = store
        .upsert_usage(&record)
        .expect_err("nonzero replicated usage must carry quota authority in this import");
    assert!(error
        .to_string()
        .contains("omitted its immutable invocation quota"));
    assert!(store.get_usage("cap-unscoped-import", 0).unwrap().is_none());

    let _ = fs::remove_file(path);
}

#[test]
fn legacy_event_imports_reject_invocation_events_without_quota_authority() {
    let path = unique_db_path("chio-budget-event-import-requires-quota");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let event = import_integrity_record("event-without-quota", 1);
    let existing_quota = compatibility_quota_usage_record("cap-import-integrity", 0, 10, 0, 0, 0);
    store
        .import_snapshot_records_with_invocation_quotas(&[], &[existing_quota], &[])
        .unwrap();

    for error in [
        store
            .import_snapshot_records(&[], std::slice::from_ref(&event))
            .expect_err("snapshot event import must carry immutable quota authority"),
        store
            .import_mutation_record(&event)
            .expect_err("single event import must carry immutable quota authority"),
    ] {
        assert!(
            error
                .to_string()
                .contains("omitted its immutable quota projection"),
            "unexpected import error: {error}"
        );
        assert_eq!(store.max_mutation_event_seq().unwrap(), 0);
        assert_eq!(replication_floor(&store), 0);
    }

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_uses_seq_for_same_key_delta_queries() {
    let path = unique_db_path("chio-budget-seq-delta");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
    let first = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(first.len(), 1);
    let first_seq = first[0].seq;

    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());
    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

    let delta = store.list_usages_after(10, Some(first_seq)).unwrap();
    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].invocation_count, 3);
    assert!(delta[0].seq > first_seq);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_query_bounds_reject_unrepresentable_sqlite_integers() {
    let path = unique_db_path("chio-budget-query-bounds");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(matches!(
        store.list_usages_after(10, Some(u64::MAX)),
        Err(BudgetStoreError::Overflow(_))
    ));
    assert!(matches!(
        store.list_mutation_events_after_seq(10, u64::MAX),
        Err(BudgetStoreError::Overflow(_))
    ));
    if usize::BITS > 63 {
        assert!(matches!(
            store.list_usages(usize::MAX, None),
            Err(BudgetStoreError::Overflow(_))
        ));
        assert!(matches!(
            store.list_mutation_events(usize::MAX, None, None),
            Err(BudgetStoreError::Overflow(_))
        ));
    }

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_budget_store_preserves_imported_seq_across_failover_writes() {
    let path = unique_db_path("chio-budget-seq-floor");
    let store = SqliteBudgetStore::open(&path).unwrap();

    import_usage_with_immutable_maximum(&store, &usage_record("cap-1", 0, 3, 10, 42, 0, 0), 5)
        .unwrap();
    assert!(store.try_increment("cap-1", 0, Some(5)).unwrap());

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].invocation_count, 4);
    assert_eq!(records[0].seq, 43);

    let _ = fs::remove_file(path);
}

// --- try_charge_cost tests ---

#[test]
fn budget_store_try_charge_cost_within_limits_returns_true_sqlite() {
    let path = unique_db_path("chio-charge-cost-ok");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // 100 units, cap is 200 per invocation, total cap is 1000
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap();
    assert!(ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 100, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_exceeds_per_invocation_cap_sqlite() {
    let path = unique_db_path("chio-charge-cost-per-inv");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // 500 units > max_cost_per_invocation of 200
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
        .unwrap();
    assert!(!ok);

    // Nothing should have been charged
    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert!(records.is_empty() || records[0].invocation_count == 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_exceeds_total_cap_sqlite() {
    let path = unique_db_path("chio-charge-cost-total");
    let store = SqliteBudgetStore::open(&path).unwrap();
    // First charge 900 of 1000 budget
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
        .unwrap());
    // Second charge of 200 would exceed the total cap of 1000
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
        .unwrap();
    assert!(!ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 900, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_atomic_increment_sqlite() {
    let path = unique_db_path("chio-charge-cost-atomic");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, None, 100, Some(200), Some(1000))
        .unwrap());
    assert!(store
        .try_charge_cost("cap-1", 0, None, 150, Some(200), Some(1000))
        .unwrap());

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 2);
    assert_usage_totals(&records[0], 250, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_charge_and_increment_share_one_immutable_invocation_quota() {
    let path = unique_db_path("chio-charge-increment-shared-quota");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store
        .try_charge_cost("cap-shared-quota", 0, Some(2), 0, None, None)
        .unwrap());
    assert!(store.try_increment("cap-shared-quota", 0, Some(2)).unwrap());
    assert!(!store
        .try_charge_cost("cap-shared-quota", 0, Some(2), 0, None, None)
        .unwrap());

    let error = store
        .try_charge_cost("cap-shared-quota", 0, Some(3), 0, None, None)
        .expect_err("the charge path must not replace the immutable maximum");
    assert!(error
        .to_string()
        .contains("presented with a different maximum"));

    let (legacy_count, maximum, captured): (u32, u32, u32) = store
        .connection()
        .unwrap()
        .query_row(
            r#"
            SELECT legacy.invocation_count, quota.max_invocations, quota.captured_invocations
            FROM capability_grant_budgets AS legacy
            JOIN budget_invocation_quota_usage AS quota
              ON quota.profile = 'chio.grant-invocation.v1'
             AND quota.owner_id = legacy.capability_id
             AND quota.grant_index_key = legacy.grant_index
            WHERE legacy.capability_id = 'cap-shared-quota'
              AND legacy.grant_index = 0
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((legacy_count, maximum, captured), (2, 2, 2));

    let _ = fs::remove_file(path);
}

#[test]
fn denied_sqlite_charge_freezes_its_invocation_maximum() {
    let path = unique_db_path("chio-charge-denial-freezes-quota");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(!store
        .try_charge_cost("cap-denied-charge", 0, Some(0), 0, None, None)
        .unwrap());
    let error = store
        .try_increment("cap-denied-charge", 0, Some(1))
        .expect_err("a denied charge must not leave a fresh maximum authority path");
    assert!(error
        .to_string()
        .contains("presented with a different maximum"));

    let (maximum, captured): (u32, u32) = store
        .connection()
        .unwrap()
        .query_row(
            r#"
            SELECT max_invocations, captured_invocations
            FROM budget_invocation_quota_usage
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'cap-denied-charge'
              AND grant_index_key = 0
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((maximum, captured), (0, 0));

    let _ = fs::remove_file(path);
}

#[test]
fn denied_sqlite_charge_exact_replay_preserves_quota_event_sequence() {
    let path = unique_db_path("chio-charge-denial-replay-sequence");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(!store
        .try_charge_cost_with_ids(
            "cap-denied-replay",
            0,
            Some(0),
            0,
            None,
            None,
            Some("hold-denied-replay"),
            Some("event-denied-replay"),
        )
        .unwrap());
    let event_seq = store
        .mutation_event_seq_for_event_id("event-denied-replay")
        .unwrap()
        .unwrap();
    assert!(!store
        .try_charge_cost_with_ids(
            "cap-denied-replay",
            0,
            Some(0),
            0,
            None,
            None,
            Some("hold-denied-replay"),
            Some("event-denied-replay"),
        )
        .unwrap());
    let (maximum, captured, quota_seq): (u32, u32, i64) = store
        .connection()
        .unwrap()
        .query_row(
            r#"
            SELECT max_invocations, captured_invocations, seq
            FROM budget_invocation_quota_usage
            WHERE profile = 'chio.grant-invocation.v1'
              AND owner_id = 'cap-denied-replay'
              AND grant_index_key = 0
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let quota_seq = u64::try_from(quota_seq)
        .unwrap_or_else(|error| panic!("quota sequence is outside the u64 range: {error}"));
    assert_eq!((maximum, captured, quota_seq), (0, 0, event_seq));

    let _ = fs::remove_file(path);
}

#[test]
fn sqlite_legacy_reverse_updates_the_shared_quota_and_replays_exactly(
) -> Result<(), BudgetStoreError> {
    let path = unique_db_path("chio-charge-reverse-shared-quota");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store
        .try_charge_cost_with_ids(
            "cap-reverse-shared",
            0,
            Some(1),
            5,
            None,
            None,
            Some("hold-reverse-shared"),
            Some("event-authorize-reverse-shared"),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids(
            "cap-reverse-shared",
            0,
            5,
            Some("hold-reverse-shared"),
            Some("event-reverse-shared"),
        )
        .unwrap();
    let reverse_event = store
        .list_mutation_events(10, Some("cap-reverse-shared"), Some(0))?
        .into_iter()
        .find(|event| event.event_id == "event-reverse-shared")
        .ok_or_else(|| {
            BudgetStoreError::Invariant("reverse mutation event was not persisted".to_string())
        })?;
    assert_eq!(reverse_event.usage_seq, Some(reverse_event.event_seq));
    let after_reverse: (u32, u32, u32, u64) = store.connection()?.query_row(
        r#"
            SELECT legacy.invocation_count, quota.reserved_invocations,
                   quota.captured_invocations, quota.seq
            FROM capability_grant_budgets AS legacy
            JOIN budget_invocation_quota_usage AS quota
              ON quota.profile = 'chio.grant-invocation.v1'
             AND quota.owner_id = legacy.capability_id
             AND quota.grant_index_key = legacy.grant_index
            WHERE legacy.capability_id = 'cap-reverse-shared'
              AND legacy.grant_index = 0
            "#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, test_row_u64(row, 3)?)),
    )?;
    assert_eq!(after_reverse, (0, 0, 0, reverse_event.event_seq));
    drop(store);

    let reopened = SqliteBudgetStore::open(&path)?;
    reopened
        .reverse_charge_cost_with_ids(
            "cap-reverse-shared",
            0,
            5,
            Some("hold-reverse-shared"),
            Some("event-reverse-shared"),
        )
        .unwrap();
    let after_replay: (u32, u32, u32, u64) = reopened.connection()?.query_row(
        r#"
            SELECT legacy.invocation_count, quota.reserved_invocations,
                   quota.captured_invocations, quota.seq
            FROM capability_grant_budgets AS legacy
            JOIN budget_invocation_quota_usage AS quota
              ON quota.profile = 'chio.grant-invocation.v1'
             AND quota.owner_id = legacy.capability_id
             AND quota.grant_index_key = legacy.grant_index
            WHERE legacy.capability_id = 'cap-reverse-shared'
              AND legacy.grant_index = 0
            "#,
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, test_row_u64(row, 3)?)),
    )?;
    assert_eq!(after_replay, after_reverse);
    assert!(reopened.try_increment("cap-reverse-shared", 0, Some(1))?);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn compatibility_quota_snapshot_blocks_changed_maximum_after_promotion() {
    let source_path = unique_db_path("chio-quota-replication-source");
    let target_path = unique_db_path("chio-quota-replication-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();

    assert!(source
        .try_increment("cap-quota-replication", 0, Some(1))
        .unwrap());
    let usages = source.list_all_usages().unwrap();
    let quotas = source
        .list_compatibility_invocation_quota_usages_after(10, None)
        .unwrap();
    let events = source
        .list_mutation_events(10, Some("cap-quota-replication"), Some(0))
        .unwrap();
    assert_eq!(quotas.len(), 1);

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target
        .import_snapshot_records_with_invocation_quotas(&usages, &quotas, &events)
        .unwrap();
    target
        .import_snapshot_records_with_invocation_quotas(&usages, &quotas, &events)
        .unwrap();
    assert!(!target
        .try_increment("cap-quota-replication", 0, Some(1))
        .unwrap());
    let error = target
        .try_increment("cap-quota-replication", 0, Some(2))
        .expect_err("promotion must not repin a replicated immutable maximum");
    assert!(error.to_string().contains("different maximum"));

    let conflicting = compatibility_quota_usage_record(
        "cap-quota-replication",
        0,
        2,
        1,
        quotas[0].updated_at.saturating_add(1),
        quotas[0].seq.saturating_add(10),
    );
    let unrelated_usage = usage_record(
        "cap-quota-replication-rollback",
        0,
        0,
        quotas[0].updated_at.saturating_add(1),
        quotas[0].seq.saturating_add(9),
        25,
        0,
    );
    let floor_before_conflict = replication_floor(&target);
    let error = target
        .import_snapshot_records_with_invocation_quotas(
            std::slice::from_ref(&unrelated_usage),
            &[conflicting],
            &[],
        )
        .expect_err("a newer replication row must not replace the immutable maximum");
    assert!(error.to_string().contains("immutable maximum"));
    assert!(target
        .get_usage("cap-quota-replication-rollback", 0)
        .unwrap()
        .is_none());
    assert_eq!(replication_floor(&target), floor_before_conflict);
    assert_eq!(
        target
            .get_compatibility_invocation_quota_usage("cap-quota-replication", 0)
            .unwrap()
            .unwrap()
            .usage
            .quota
            .max_invocations(),
        1
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn denied_only_replication_requires_quota_and_freezes_zero_maximum() {
    let source_path = unique_db_path("chio-denied-quota-replication-source");
    let target_path = unique_db_path("chio-denied-quota-replication-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();

    assert!(!source
        .try_increment("cap-denied-quota-replication", 0, Some(0))
        .unwrap());
    assert!(source.list_all_usages().unwrap().is_empty());
    let quotas = source
        .list_compatibility_invocation_quota_usages_after(10, None)
        .unwrap();
    let events = source
        .list_mutation_events(10, Some("cap-denied-quota-replication"), Some(0))
        .unwrap();
    assert_eq!(quotas.len(), 1);
    assert_eq!(quotas[0].usage.quota.max_invocations(), 0);
    assert_eq!(quotas[0].usage.captured_invocations_after, 0);

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    let error = target
        .import_snapshot_records_with_invocation_quotas(&[], &[], &events)
        .expect_err("a denied-only event without its quota must fail closed");
    assert!(error.to_string().contains("omitted its immutable quota"));
    assert_eq!(target.max_mutation_event_seq().unwrap(), 0);
    assert!(target
        .get_compatibility_invocation_quota_usage("cap-denied-quota-replication", 0)
        .unwrap()
        .is_none());

    target
        .import_snapshot_records_with_invocation_quotas(&[], &quotas, &events)
        .unwrap();
    assert!(!target
        .try_increment("cap-denied-quota-replication", 0, Some(0))
        .unwrap());
    let error = target
        .try_increment("cap-denied-quota-replication", 0, Some(1))
        .expect_err("a promoted denied-only follower must retain maximum zero");
    assert!(error.to_string().contains("different maximum"));

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn reversed_compatibility_quota_round_trip_retains_original_maximum() {
    let source_path = unique_db_path("chio-reversed-quota-replication-source");
    let target_path = unique_db_path("chio-reversed-quota-replication-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();

    assert!(source
        .try_charge_cost_with_ids(
            "cap-reversed-quota-replication",
            0,
            Some(1),
            5,
            None,
            None,
            Some("hold-reversed-quota-replication"),
            Some("event-reversed-quota-authorize"),
        )
        .unwrap());
    source
        .reverse_charge_cost_with_ids(
            "cap-reversed-quota-replication",
            0,
            5,
            Some("hold-reversed-quota-replication"),
            Some("event-reversed-quota-reverse"),
        )
        .unwrap();
    let usages = source.list_all_usages().unwrap();
    let quotas = source
        .list_compatibility_invocation_quota_usages_after(10, None)
        .unwrap();
    let events = source
        .list_mutation_events(10, Some("cap-reversed-quota-replication"), Some(0))
        .unwrap();
    assert_eq!(usages[0].invocation_count, 0);
    assert_eq!(quotas[0].usage.captured_invocations_after, 0);

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    target
        .import_snapshot_records_with_invocation_quotas(&usages, &quotas, &events)
        .unwrap();
    let error = target
        .try_increment("cap-reversed-quota-replication", 0, Some(2))
        .expect_err("reverse replication must not erase the original maximum");
    assert!(error.to_string().contains("different maximum"));
    assert!(target
        .try_increment("cap-reversed-quota-replication", 0, Some(1))
        .unwrap());

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn concurrent_sqlite_fresh_database_initialization_waits_for_schema_writer() {
    let path = unique_db_path("chio-concurrent-fresh-open");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                SqliteBudgetStore::open(path)
            })
        })
        .collect::<Vec<_>>();

    for thread in threads {
        thread
            .join()
            .unwrap_or_else(|_| panic!("concurrent open thread panicked"))
            .unwrap_or_else(|error| panic!("concurrent fresh open failed: {error}"));
    }

    let _ = fs::remove_file(path);
}

#[test]
fn concurrent_sqlite_increment_and_charge_consume_one_shared_last_unit() {
    let path = unique_db_path("chio-charge-increment-last-unit");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let stores = [
        SqliteBudgetStore::open(&path).unwrap(),
        SqliteBudgetStore::open(&path).unwrap(),
    ];
    let mut threads = Vec::new();

    for (store, charge) in stores.into_iter().zip([false, true]) {
        let barrier = std::sync::Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            if charge {
                store.try_charge_cost("cap-last-unit", 0, Some(1), 0, None, None)
            } else {
                store.try_increment("cap-last-unit", 0, Some(1))
            }
        }));
    }

    let outcomes = threads
        .into_iter()
        .map(|thread| thread.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outcomes.iter().filter(|allowed| **allowed).count(), 1);

    let store = SqliteBudgetStore::open(&path).unwrap();
    let (legacy_count, maximum, captured): (u32, u32, u32) = store
        .connection()
        .unwrap()
        .query_row(
            r#"
            SELECT legacy.invocation_count, quota.max_invocations, quota.captured_invocations
            FROM capability_grant_budgets AS legacy
            JOIN budget_invocation_quota_usage AS quota
              ON quota.profile = 'chio.grant-invocation.v1'
             AND quota.owner_id = legacy.capability_id
             AND quota.grant_index_key = legacy.grant_index
            WHERE legacy.capability_id = 'cap-last-unit'
              AND legacy.grant_index = 0
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!((legacy_count, maximum, captured), (1, 1, 1));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_within_limits_returns_true_inmemory() {
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap();
    assert!(ok);

    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_eq!(records[0].invocation_count, 1);
    assert_usage_totals(&records[0], 100, 0);
}

#[test]
fn budget_store_try_charge_cost_exceeds_per_invocation_cap_inmemory() {
    let store = InMemoryBudgetStore::new();
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 500, Some(200), Some(1000))
        .unwrap();
    assert!(!ok);
}

#[test]
fn budget_store_try_charge_cost_exceeds_total_cap_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 900, Some(1000), Some(1000))
        .unwrap());
    let ok = store
        .try_charge_cost("cap-1", 0, Some(10), 200, Some(1000), Some(1000))
        .unwrap();
    assert!(!ok);
}

#[test]
fn budget_usage_record_includes_split_cost_state() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, None, 42, None, None)
        .unwrap());
    let records = store.list_usages(10, Some("cap-1")).unwrap();
    assert_usage_totals(&records[0], 42, 0);
}

#[test]
fn budget_store_reverse_charge_cost_restores_prior_state_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reverse_charge_cost("cap-1", 0, 100).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 0);
    assert_usage_totals(&record, 0, 0);
}

#[test]
fn budget_store_reverse_charge_cost_restores_prior_state_sqlite() {
    let path = unique_db_path("chio-reverse-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reverse_charge_cost("cap-1", 0, 100).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 0);
    assert_usage_totals(&record, 0, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_reduce_charge_cost_releases_exposure_only_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reduce_charge_cost("cap-1", 0, 25).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 75, 0);
}

#[test]
fn budget_store_reduce_charge_cost_releases_exposure_only_sqlite() {
    let path = unique_db_path("chio-reduce-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.reduce_charge_cost("cap-1", 0, 25).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 75, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_settle_charge_cost_moves_exposure_to_realized_inmemory() {
    let store = InMemoryBudgetStore::new();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 0, 75);
}

#[test]
fn budget_store_settle_charge_cost_moves_exposure_to_realized_sqlite() {
    let path = unique_db_path("chio-settle-charge");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost("cap-1", 0, Some(10), 100, Some(200), Some(1000))
        .unwrap());

    store.settle_charge_cost("cap-1", 0, 100, 75).unwrap();

    let record = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(record.invocation_count, 1);
    assert_usage_totals(&record, 0, 75);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_try_charge_cost_with_ids_is_idempotent_inmemory() {
    let store = InMemoryBudgetStore::new();
    let hold_id = "hold-cap-1-0";
    let event_id = "hold-cap-1-0:authorize";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());
    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[0].allowed, Some(true));
}

#[test]
fn budget_store_event_retry_after_reopen_is_idempotent_sqlite() {
    let path = unique_db_path("chio-charge-cost-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-1-0";
    let event_id = "hold-cap-1-0:authorize";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let before_reopen = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(before_reopen.invocation_count, 1);
    assert_usage_totals(&before_reopen, 100, 0);
    drop(store);

    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
        )
        .unwrap());

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_id, event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[0].kind, BudgetMutationKind::AuthorizeExposure);
    assert_eq!(events[0].allowed, Some(true));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_settle_with_ids_is_idempotent_and_append_only_sqlite() {
    let path = unique_db_path("chio-settle-charge-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-1-0";
    let authorize_event_id = "hold-cap-1-0:authorize";
    let reconcile_event_id = "hold-cap-1-0:reconcile";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-1",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
        )
        .unwrap());
    store
        .settle_charge_cost_with_ids("cap-1", 0, 100, 75, Some(hold_id), Some(reconcile_event_id))
        .unwrap();
    store
        .settle_charge_cost_with_ids("cap-1", 0, 100, 75, Some(hold_id), Some(reconcile_event_id))
        .unwrap();

    let usage = store.get_usage("cap-1", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 75);

    let events = store
        .list_mutation_events(10, Some("cap-1"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[1].event_id, reconcile_event_id);
    assert_eq!(events[1].hold_id.as_deref(), Some(hold_id));
    assert_eq!(events[1].kind, BudgetMutationKind::ReconcileSpend);
    assert_eq!(events[1].exposure_units, 100);
    assert_eq!(events[1].realized_spend_units, 75);
    assert_eq!(events[1].total_cost_exposed_after, 0);
    assert_eq!(events[1].total_cost_realized_spend_after, 75);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_rejects_cumulative_spend_outside_sqlite_integer_range() {
    let store = SqliteBudgetStore::open_in_memory().unwrap();
    assert!(store
        .try_charge_cost("cap-overflow", 0, None, 1, None, None)
        .unwrap());
    store
        .connection()
        .unwrap()
        .execute(
            "UPDATE capability_grant_budgets \
             SET total_cost_realized_spend = ?1 \
             WHERE capability_id = ?2 AND grant_index = 0",
            params![i64::MAX, "cap-overflow"],
        )
        .unwrap();

    let error = store
        .settle_charge_cost("cap-overflow", 0, 1, 1)
        .expect_err("cumulative spend beyond SQLite INTEGER must fail closed");
    assert!(matches!(error, BudgetStoreError::Overflow(_)));
    assert!(
        error
            .to_string()
            .contains("total_cost_realized_spend exceeds SQLite INTEGER range"),
        "unexpected error: {error}"
    );

    let usage = store.get_usage("cap-overflow", 0).unwrap().unwrap();
    assert_usage_totals(&usage, 1, i64::MAX as u64);
}
