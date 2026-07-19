#[test]
fn budget_store_capture_is_terminal_truthful_and_exact_after_reopen_sqlite() {
    let path = unique_db_path("chio-capture-charge-exact");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-capture-0";
    let authorize_event_id = "hold-cap-capture-0:authorize";
    let capture_event_id = "hold-cap-capture-0:capture";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-capture",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
        )
        .unwrap());
    let request = BudgetCaptureHoldRequest {
        capability_id: "cap-capture".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 70,
        hold_id: Some(hold_id.to_string()),
        event_id: Some(capture_event_id.to_string()),
        authority: None,
        admission_operation: None,
    };
    let captured = store.capture_budget_hold(request.clone()).unwrap();
    assert_eq!(captured.monetary_state, BudgetMonetaryHoldState::Captured);
    assert_eq!(captured.exposure_units, 100);
    assert_eq!(captured.realized_spend_units, 70);
    assert_eq!(captured.committed_cost_units_after, 70);
    assert_eq!(captured.invocation_count_after, 1);

    let usage = store.get_usage("cap-capture", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 70);
    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("captured hold state");
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(hold.disposition, HoldDisposition::Captured);
    }
    let events = store
        .list_mutation_events(10, Some("cap-capture"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].event_id, capture_event_id);
    assert_eq!(events[1].kind, BudgetMutationKind::CaptureExposure);
    assert_eq!(events[1].monetary_state, BudgetMonetaryHoldState::Captured);
    drop(store);

    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .try_charge_cost_with_ids(
            "cap-capture",
            0,
            Some(10),
            10,
            Some(200),
            Some(1000),
            Some("hold-cap-capture-1"),
            Some("hold-cap-capture-1:authorize"),
        )
        .unwrap());
    let usage_before_retry = store.get_usage("cap-capture", 0).unwrap().unwrap();
    assert_eq!(usage_before_retry.invocation_count, 2);
    assert_usage_totals(&usage_before_retry, 10, 70);

    assert_eq!(store.capture_budget_hold(request).unwrap(), captured);
    assert_eq!(
        store.get_usage("cap-capture", 0).unwrap().unwrap(),
        usage_before_retry
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("cap-capture"), Some(0))
            .unwrap()
            .len(),
        3
    );

    let reconcile_error = store
        .settle_charge_cost_with_ids(
            "cap-capture",
            0,
            100,
            70,
            Some(hold_id),
            Some("hold-cap-capture-0:reconcile"),
        )
        .expect_err("a captured hold must not be reconciled again");
    assert!(reconcile_error.to_string().contains("is no longer open"));
    assert_eq!(
        store.get_usage("cap-capture", 0).unwrap().unwrap(),
        usage_before_retry
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("cap-capture"), Some(0))
            .unwrap()
            .len(),
        3
    );

    let _ = fs::remove_file(path);
}

#[test]
fn high_level_authorize_retry_returns_original_allowed_snapshot_after_later_write() {
    let path = unique_db_path("chio-budget-authorize-allowed-snapshot-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let leased = authority("budget-primary", "lease-1", 1);
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-authorize-snapshot".to_string(),
        0,
        Some(5),
        100,
        Some(100),
        Some(500),
        Some("hold-authorize-snapshot-0".to_string()),
        Some("event-authorize-snapshot".to_string()),
        Some(leased.clone()),
    );
    let first = store.authorize_budget_hold(request.clone()).unwrap();
    assert!(first.is_authorized());
    let later = BudgetAuthorizeHoldRequest::legacy(
        "cap-authorize-snapshot".to_string(),
        0,
        Some(5),
        50,
        Some(100),
        Some(500),
        Some("hold-authorize-snapshot-1".to_string()),
        Some("event-authorize-snapshot-later".to_string()),
        Some(leased.clone()),
    );
    assert!(store.authorize_budget_hold(later).unwrap().is_authorized());

    assert_eq!(store.authorize_budget_hold(request).unwrap(), first);
    let BudgetAuthorizeHoldDecision::Authorized(first) = first else {
        panic!("first authorization must be allowed");
    };
    assert_eq!(first.committed_cost_units_after, 100);
    assert_eq!(first.invocation_count_after, 1);
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));
    assert_eq!(
        first.metadata.event_id.as_deref(),
        Some("event-authorize-snapshot")
    );
    assert!(first.metadata.budget_commit_index.is_some());

    let zero_with_limit = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-authorize-zero-limit".to_string(),
            0,
            Some(1),
            0,
            Some(0),
            None,
            Some("hold-authorize-zero-limit".to_string()),
            Some("event-authorize-zero-limit".to_string()),
            None,
        ))
        .unwrap();
    let BudgetAuthorizeHoldDecision::Authorized(zero_with_limit) = zero_with_limit else {
        panic!("zero-exposure authorization with a monetary limit must be allowed");
    };
    assert_eq!(
        zero_with_limit.monetary_state,
        BudgetMonetaryHoldState::Exposed
    );

    let _ = fs::remove_file(path);
}

#[test]
fn denied_authorization_claim_survives_reopen_and_freezes_retry_snapshot() {
    let path = unique_db_path("chio-budget-authorize-denied-claim-reopen");
    let leased = authority("budget-primary", "lease-1", 1);
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-authorize-denied".to_string(),
        0,
        Some(5),
        100,
        Some(50),
        Some(500),
        Some("hold-authorize-denied".to_string()),
        Some("event-authorize-denied".to_string()),
        Some(leased.clone()),
    );
    let store = SqliteBudgetStore::open(&path).unwrap();
    let first = store.authorize_budget_hold(request.clone()).unwrap();
    assert!(matches!(first, BudgetAuthorizeHoldDecision::Denied(_)));
    drop(store);

    let store = SqliteBudgetStore::open(&path).unwrap();
    let events_before = store
        .list_mutation_events(10, Some("cap-authorize-denied"), Some(0))
        .unwrap();
    let collision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-authorize-denied".to_string(),
            0,
            Some(5),
            100,
            Some(50),
            Some(500),
            Some("hold-authorize-denied".to_string()),
            Some("event-authorize-denied-rebound".to_string()),
            Some(leased.clone()),
        ))
        .expect_err("a denied hold ID must not be rebound under a fresh event or maxima");
    assert!(matches!(collision, BudgetStoreError::Invariant(_)));
    assert!(store
        .get_usage("cap-authorize-denied", 0)
        .unwrap()
        .is_none());
    assert_eq!(
        store
            .list_mutation_events(10, Some("cap-authorize-denied"), Some(0))
            .unwrap(),
        events_before
    );
    let (claim_count, open_hold_count): (i64, i64) = store
        .connection()
        .unwrap()
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM budget_authorization_claims WHERE hold_id = 'hold-authorize-denied'),
                (SELECT COUNT(*) FROM budget_authorization_holds WHERE hold_id = 'hold-authorize-denied')
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((claim_count, open_hold_count), (1, 0));

    assert!(store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-authorize-denied".to_string(),
            0,
            Some(5),
            40,
            Some(50),
            Some(500),
            Some("hold-authorize-denied-later".to_string()),
            Some("event-authorize-denied-later".to_string()),
            Some(leased.clone()),
        ))
        .unwrap()
        .is_authorized());
    assert_eq!(store.authorize_budget_hold(request).unwrap(), first);
    let BudgetAuthorizeHoldDecision::Denied(first) = first else {
        panic!("first authorization must remain denied");
    };
    assert_eq!(first.committed_cost_units_after, 0);
    assert_eq!(first.invocation_count_after, 0);
    assert_eq!(
        first.invocation_state,
        BudgetInvocationReservationState::Denied
    );
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));

    let _ = fs::remove_file(path);
}

#[test]
fn imported_denied_authorization_claim_rejects_rebind_atomically() {
    let leader_path = unique_db_path("chio-budget-import-denied-claim-leader");
    let follower_path = unique_db_path("chio-budget-import-denied-claim-follower");
    let leader = SqliteBudgetStore::open(&leader_path).unwrap();
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-import-denied-claim".to_string(),
        0,
        Some(5),
        40,
        Some(20),
        Some(100),
        Some("hold-import-denied-claim".to_string()),
        Some("event-import-denied-claim".to_string()),
        None,
    );
    assert!(matches!(
        leader.authorize_budget_hold(request).unwrap(),
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    let event = leader
        .list_mutation_events(10, Some("cap-import-denied-claim"), Some(0))
        .unwrap()
        .pop()
        .expect("denied authorization event");

    let follower = SqliteBudgetStore::open(&follower_path).unwrap();
    import_events_with_quota_authority(&follower, &[event]).unwrap();
    let events_before = follower
        .list_mutation_events(10, Some("cap-import-denied-claim"), Some(0))
        .unwrap();
    let error = follower
        .try_charge_cost_with_ids(
            "cap-import-denied-claim",
            0,
            Some(5),
            40,
            Some(20),
            Some(100),
            Some("hold-import-denied-claim"),
            Some("event-import-denied-claim-rebound"),
        )
        .expect_err("an imported denied claim must permanently bind its hold ID");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));
    assert!(follower
        .get_usage("cap-import-denied-claim", 0)
        .unwrap()
        .is_none());
    assert_eq!(
        follower
            .list_mutation_events(10, Some("cap-import-denied-claim"), Some(0))
            .unwrap(),
        events_before
    );

    let _ = fs::remove_file(leader_path);
    let _ = fs::remove_file(follower_path);
}

#[test]
fn authorization_claim_migration_backfills_existing_authorization_event() {
    let path = unique_db_path("chio-budget-authorization-claim-migration");
    let store = SqliteBudgetStore::open(&path).unwrap();
    assert!(store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-claim-migration".to_string(),
            0,
            Some(2),
            10,
            Some(10),
            Some(20),
            Some("hold-claim-migration".to_string()),
            Some("event-claim-migration".to_string()),
            None,
        ))
        .unwrap()
        .is_authorized());
    store
        .connection()
        .unwrap()
        .execute("DROP TABLE budget_authorization_claims", [])
        .unwrap();
    drop(store);

    let store = SqliteBudgetStore::open(&path).unwrap();
    let claim_count: i64 = store
        .connection()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM budget_authorization_claims WHERE hold_id = 'hold-claim-migration'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(claim_count, 1);
    let error = store
        .try_charge_cost_with_ids(
            "cap-claim-migration",
            0,
            Some(2),
            10,
            Some(10),
            Some(20),
            Some("hold-claim-migration"),
            Some("event-claim-migration-rebound"),
        )
        .expect_err("migration-backfilled claim must close the fresh-event bypass");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));

    let _ = fs::remove_file(path);
}

#[test]
fn allowed_authorization_claim_rejects_fresh_event_and_maximum_bypass() {
    let path = unique_db_path("chio-budget-authorize-allowed-claim-rebind");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let request = BudgetAuthorizeHoldRequest::legacy(
        "cap-authorize-claimed".to_string(),
        0,
        Some(1),
        25,
        Some(25),
        Some(25),
        Some("hold-authorize-claimed".to_string()),
        Some("event-authorize-claimed".to_string()),
        None,
    );
    let first = store.authorize_budget_hold(request.clone()).unwrap();
    assert!(first.is_authorized());
    let usage_before = store
        .get_usage("cap-authorize-claimed", 0)
        .unwrap()
        .unwrap();
    let events_before = store
        .list_mutation_events(10, Some("cap-authorize-claimed"), Some(0))
        .unwrap();

    for max_invocations in [Some(1), None] {
        let error = store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                "cap-authorize-claimed".to_string(),
                0,
                max_invocations,
                25,
                Some(25),
                Some(25),
                Some("hold-authorize-claimed".to_string()),
                Some(format!(
                    "event-authorize-claimed-rebound-{max_invocations:?}"
                )),
                None,
            ))
            .expect_err("a claimed allowed hold must reject every fresh event");
        assert!(matches!(error, BudgetStoreError::Invariant(_)));
    }
    assert_eq!(
        store
            .get_usage("cap-authorize-claimed", 0)
            .unwrap()
            .unwrap(),
        usage_before
    );
    assert_eq!(
        store
            .list_mutation_events(10, Some("cap-authorize-claimed"), Some(0))
            .unwrap(),
        events_before
    );
    assert_eq!(store.authorize_budget_hold(request).unwrap(), first);

    let _ = fs::remove_file(path);
}

#[test]
fn high_level_reverse_retry_returns_original_persisted_snapshot_after_later_write() {
    let path = unique_db_path("chio-budget-reverse-snapshot-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let leased = authority("budget-primary", "lease-1", 1);
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-reverse-snapshot",
            0,
            Some(5),
            100,
            Some(100),
            Some(500),
            Some("hold-reverse-snapshot-0"),
            Some("event-reverse-snapshot-authorize"),
            Some(&leased),
        )
        .unwrap());
    let request = BudgetReverseHoldRequest {
        capability_id: "cap-reverse-snapshot".to_string(),
        grant_index: 0,
        reversed_exposure_units: 100,
        hold_id: Some("hold-reverse-snapshot-0".to_string()),
        event_id: Some("event-reverse-snapshot".to_string()),
        authority: Some(leased.clone()),
        admission_operation: None,
    };
    let first = store.reverse_budget_hold(request.clone()).unwrap();
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-reverse-snapshot",
            0,
            Some(5),
            50,
            Some(100),
            Some(500),
            Some("hold-reverse-snapshot-1"),
            Some("event-reverse-snapshot-later"),
            Some(&leased),
        )
        .unwrap());

    assert_eq!(store.reverse_budget_hold(request).unwrap(), first);
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));
    assert_eq!(
        first.metadata.event_id.as_deref(),
        Some("event-reverse-snapshot")
    );
    assert_eq!(first.monetary_state, BudgetMonetaryHoldState::Reversed);
    assert!(first.metadata.budget_commit_index.is_some());

    let _ = fs::remove_file(path);
}

#[test]
fn high_level_release_retry_returns_original_persisted_snapshot_after_later_write() {
    let path = unique_db_path("chio-budget-release-snapshot-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let leased = authority("budget-primary", "lease-1", 1);
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-release-snapshot",
            0,
            Some(5),
            100,
            Some(100),
            Some(500),
            Some("hold-release-snapshot-0"),
            Some("event-release-snapshot-authorize"),
            Some(&leased),
        )
        .unwrap());
    let request = BudgetReleaseHoldRequest {
        capability_id: "cap-release-snapshot".to_string(),
        grant_index: 0,
        released_exposure_units: 100,
        hold_id: Some("hold-release-snapshot-0".to_string()),
        event_id: Some("event-release-snapshot".to_string()),
        authority: Some(leased.clone()),
        admission_operation: None,
    };
    let first = store.release_budget_hold(request.clone()).unwrap();
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-release-snapshot",
            0,
            Some(5),
            50,
            Some(100),
            Some(500),
            Some("hold-release-snapshot-1"),
            Some("event-release-snapshot-later"),
            Some(&leased),
        )
        .unwrap());

    assert_eq!(store.release_budget_hold(request).unwrap(), first);
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));
    assert_eq!(
        first.metadata.event_id.as_deref(),
        Some("event-release-snapshot")
    );
    assert_eq!(first.monetary_state, BudgetMonetaryHoldState::Released);
    assert!(first.metadata.budget_commit_index.is_some());

    let _ = fs::remove_file(path);
}

#[test]
fn high_level_reconcile_retry_returns_original_persisted_snapshot_after_later_write() {
    let path = unique_db_path("chio-budget-reconcile-snapshot-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let leased = authority("budget-primary", "lease-1", 1);
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-reconcile-snapshot",
            0,
            Some(5),
            100,
            Some(100),
            Some(500),
            Some("hold-reconcile-snapshot-0"),
            Some("event-reconcile-snapshot-authorize"),
            Some(&leased),
        )
        .unwrap());
    let request = BudgetReconcileHoldRequest {
        capability_id: "cap-reconcile-snapshot".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 70,
        hold_id: Some("hold-reconcile-snapshot-0".to_string()),
        event_id: Some("event-reconcile-snapshot".to_string()),
        authority: Some(leased.clone()),
        admission_operation: None,
    };
    let first = store.reconcile_budget_hold(request.clone()).unwrap();
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-reconcile-snapshot",
            0,
            Some(5),
            50,
            Some(100),
            Some(500),
            Some("hold-reconcile-snapshot-1"),
            Some("event-reconcile-snapshot-later"),
            Some(&leased),
        )
        .unwrap());

    assert_eq!(store.reconcile_budget_hold(request).unwrap(), first);
    assert_eq!(first.metadata.authority.as_ref(), Some(&leased));
    assert_eq!(
        first.metadata.event_id.as_deref(),
        Some("event-reconcile-snapshot")
    );
    assert_eq!(first.monetary_state, BudgetMonetaryHoldState::Reconciled);
    assert!(first.metadata.budget_commit_index.is_some());

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_reduce_charge_cost_allows_zero_invocation_release_sqlite() {
    let path = unique_db_path("chio-reduce-charge-zero-invocations");
    let store = SqliteBudgetStore::open(&path).unwrap();
    store
        .upsert_usage(&usage_record("cap-zero", 0, 0, 10, 10, 40, 0))
        .unwrap();

    store.reduce_charge_cost("cap-zero", 0, 25).unwrap();

    let usage = store.get_usage("cap-zero", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_usage_totals(&usage, 15, 0);

    let events = store
        .list_mutation_events(10, Some("cap-zero"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, BudgetMutationKind::ReleaseExposure);
    assert_eq!(events[0].invocation_count_after, 0);
    assert_eq!(events[0].total_cost_exposed_after, 15);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_list_mutation_events_preserves_append_order_sqlite() {
    let path = unique_db_path("chio-budget-event-order");
    let store = SqliteBudgetStore::open(&path).unwrap();

    assert!(store
        .try_charge_cost_with_ids(
            "cap-order",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some("hold-cap-order-0"),
            Some("z-authorize"),
        )
        .unwrap());
    store
        .reduce_charge_cost_with_ids(
            "cap-order",
            0,
            25,
            Some("hold-cap-order-0"),
            Some("a-release"),
        )
        .unwrap();

    let events = store
        .list_mutation_events(10, Some("cap-order"), Some(0))
        .unwrap();
    let event_ids = events
        .iter()
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(event_ids, vec!["z-authorize", "a-release"]);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_hold_authority_requires_exact_lease_inmemory() {
    let store = InMemoryBudgetStore::new();
    let hold_id = "hold-cap-lease-0";
    let authorize_event_id = "hold-cap-lease-0:authorize";
    let release_event_id = "hold-cap-lease-0:release";
    let reconcile_event_id = "hold-cap-lease-0:reconcile";
    let initial = authority("budget-primary", "lease-7", 7);
    let advanced = authority("budget-primary", "lease-7", 8);
    let stale = authority("budget-primary", "lease-7", 6);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(authorize_event_id),
            Some(&initial),
        )
        .unwrap());

    let missing = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some("hold-cap-lease-0:release-missing"),
            None,
        )
        .expect_err("missing lease metadata should fail closed");
    assert!(missing
        .to_string()
        .contains("requires authority lease metadata"));

    let stale_error = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some("hold-cap-lease-0:release-stale"),
            Some(&stale),
        )
        .expect_err("stale lease epoch should fail closed");
    assert!(stale_error.to_string().contains("lease epoch regressed"));

    let advanced_error = store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some(release_event_id),
            Some(&advanced),
        )
        .expect_err("advanced lease epoch should fail closed");
    assert!(advanced_error
        .to_string()
        .contains("advanced beyond the open lease"));

    store
        .reduce_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            25,
            Some(hold_id),
            Some(release_event_id),
            Some(&initial),
        )
        .unwrap();
    store
        .settle_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            75,
            75,
            Some(hold_id),
            Some(reconcile_event_id),
            Some(&initial),
        )
        .unwrap();

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 75);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].authority.as_ref(), Some(&initial));
    assert_eq!(events[1].authority.as_ref(), Some(&initial));
    assert_eq!(events[2].authority.as_ref(), Some(&initial));
}

#[test]
fn budget_store_event_id_retry_rejects_authority_rollover_sqlite() {
    let path = unique_db_path("chio-hold-authority-event-reuse");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());

    let authority_error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("reused event id under a different authority should fail closed");
    assert!(matches!(authority_error, BudgetStoreError::Invariant(_)));

    let error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            101,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("reused event id with a different mutation should fail closed");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].authority.as_ref(), Some(&initial));

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_deleted_provisional_event_allows_retry_after_compensation_sqlite() {
    let path = unique_db_path("chio-hold-authority-compensation");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            100,
            Some(hold_id),
            Some("hold-cap-lease-0:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();
    store.delete_hold(hold_id).unwrap();
    store.delete_mutation_event(event_id).unwrap();

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    let event_ids = events
        .iter()
        .map(|record| record.event_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        event_ids,
        vec![
            "hold-cap-lease-0:authorize:rollback:1",
            "hold-cap-lease-0:authorize"
        ]
    );

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_rollback_artifact_allows_retry_with_new_authority_sqlite() {
    let path = unique_db_path("chio-hold-authority-rollback-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-lease-0";
    let event_id = "hold-cap-lease-0:authorize";
    let rollback_event_id = "hold-cap-lease-0:authorize:rollback:2";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            100,
            Some(hold_id),
            Some(rollback_event_id),
            Some(&initial),
        )
        .unwrap();

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-lease",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-lease", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let events = store
        .list_mutation_events(10, Some("cap-lease"), Some(0))
        .unwrap();
    let authorize = events
        .iter()
        .find(|record| record.event_id == event_id)
        .expect("replacement authorize event");
    assert_eq!(authorize.authority.as_ref(), Some(&changed));

    let _ = fs::remove_file(path);
}

#[test]
fn unrelated_typed_reverse_with_rollback_prefix_cannot_rebind_authorization_claim() {
    let path = unique_db_path("chio-hold-forged-rollback-prefix");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-target-0";
    let event_id = "hold-target-0:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-target",
            0,
            Some(10),
            100,
            Some(200),
            Some(1_000),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-unrelated",
            0,
            Some(10),
            1,
            Some(10),
            Some(100),
            Some("hold-unrelated-0"),
            Some("hold-unrelated-0:authorize"),
            Some(&changed),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-unrelated",
            0,
            1,
            Some("hold-unrelated-0"),
            Some("hold-target-0:authorize:rollback:forged"),
            Some(&changed),
        )
        .unwrap();

    let error = store
        .try_charge_cost_with_ids_and_authority(
            "cap-target",
            0,
            Some(10),
            100,
            Some(200),
            Some(1_000),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("an unrelated prefixed reverse must not unlock authority rebinding");
    assert!(matches!(error, BudgetStoreError::Invariant(_)));

    let target_events = store
        .list_mutation_events(10, Some("cap-target"), Some(0))
        .unwrap();
    assert_eq!(target_events.len(), 1);
    assert_eq!(target_events[0].event_id, event_id);
    assert_eq!(target_events[0].authority.as_ref(), Some(&initial));
    let usage = store.get_usage("cap-target", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 100, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn compensated_authorization_resolves_current_authority_but_exact_retry_stays_frozen() {
    let path = unique_db_path("chio-hold-authority-source-after-compensation");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-authority-source";
    let event_id = "hold-authority-source:authorize";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-authority-source",
            0,
            Some(10),
            50,
            Some(100),
            Some(500),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    let persisted_hint = store
        .authorization_authority_source(Some(hold_id), event_id)
        .unwrap();
    assert_eq!(
        persisted_hint,
        SqliteBudgetAuthorizationAuthority::Persisted(Some(initial.clone()))
    );

    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-authority-source",
            0,
            50,
            Some(hold_id),
            Some("hold-authority-source:authorize:rollback:1"),
            Some(&initial),
        )
        .unwrap();
    assert_eq!(
        store
            .authorization_authority_source(Some(hold_id), event_id)
            .unwrap(),
        SqliteBudgetAuthorizationAuthority::Current
    );

    let stale_candidate = match persisted_hint {
        SqliteBudgetAuthorizationAuthority::Persisted(_) => {
            SqliteBudgetCurrentAuthority::Unavailable
        }
        SqliteBudgetAuthorizationAuthority::Current => {
            panic!("pre-compensation source unexpectedly required current authority")
        }
    };
    let unavailable_error = store
        .try_charge_cost_with_ids_and_current_authority_outcome(
            "cap-authority-source",
            0,
            Some(10),
            50,
            Some(100),
            Some(500),
            Some(hold_id),
            Some(event_id),
            stale_candidate,
        )
        .expect_err("a stale persisted-authority hint must not survive compensation");
    assert!(matches!(unavailable_error, BudgetStoreError::Invariant(_)));

    let downgrade_error = store
        .try_charge_cost_with_ids_and_current_authority_outcome(
            "cap-authority-source",
            0,
            Some(10),
            50,
            Some(100),
            Some(500),
            Some(hold_id),
            Some(event_id),
            SqliteBudgetCurrentAuthority::Resolved(None),
        )
        .expect_err("a compensated HA claim must not downgrade to detached authority");
    assert!(matches!(downgrade_error, BudgetStoreError::Invariant(_)));

    let replacement = store
        .try_charge_cost_with_ids_and_current_authority_outcome(
            "cap-authority-source",
            0,
            Some(10),
            50,
            Some(100),
            Some(500),
            Some(hold_id),
            Some(event_id),
            SqliteBudgetCurrentAuthority::Resolved(Some(changed.clone())),
        )
        .unwrap();
    assert!(replacement.allowed);
    assert!(replacement.event_created);
    assert_eq!(replacement.authority.as_ref(), Some(&changed));

    let events = store
        .list_mutation_events(10, Some("cap-authority-source"), Some(0))
        .unwrap();
    let authorize = events
        .iter()
        .find(|event| event.event_id == event_id)
        .expect("replacement authorization event");
    assert_eq!(authorize.authority.as_ref(), Some(&changed));

    let _ = fs::remove_file(path);
}

#[test]
fn authorization_write_outcome_marks_only_the_transaction_that_created_the_event() {
    let path = unique_db_path("chio-hold-created-outcome");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let authority = authority("budget-primary", "lease-7", 7);

    let first = store
        .try_charge_cost_with_ids_and_authority_outcome(
            "cap-created-outcome",
            0,
            Some(10),
            25,
            Some(50),
            Some(500),
            Some("hold-created-outcome"),
            Some("hold-created-outcome:authorize"),
            Some(&authority),
        )
        .unwrap();
    assert!(first.allowed);
    assert!(first.event_created);

    let retry = store
        .try_charge_cost_with_ids_and_authority_outcome(
            "cap-created-outcome",
            0,
            Some(10),
            25,
            Some(50),
            Some(500),
            Some("hold-created-outcome"),
            Some("hold-created-outcome:authorize"),
            Some(&authority),
        )
        .unwrap();
    assert!(retry.allowed);
    assert!(!retry.event_created);

    let usage = store.get_usage("cap-created-outcome", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 25, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn budget_store_retry_after_rollback_replaces_orphaned_open_hold_once_sqlite() {
    let path = unique_db_path("chio-hold-rollback-orphan-retry");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-orphan-0";
    let event_id = "hold-cap-orphan-0:authorize";
    let rollback_event_id = "hold-cap-orphan-0:authorize:rollback:5";
    let initial = authority("budget-primary", "lease-7", 7);
    let changed = authority("budget-primary", "lease-8", 8);

    for _ in 0..3 {
        assert!(store
            .try_increment_with_event_id("cap-orphan", 0, Some(10), None)
            .unwrap());
    }
    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&initial),
        )
        .unwrap());
    store
        .reverse_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            75,
            Some(hold_id),
            Some(rollback_event_id),
            Some(&initial),
        )
        .unwrap();

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )
            .unwrap();
        SqliteBudgetStore::upsert_hold(
            &transaction,
            hold_id,
            "cap-orphan",
            0,
            75,
            75,
            HoldDisposition::Open,
            Some(&initial),
        )
        .unwrap();
        transaction.commit().unwrap();
    }

    assert!(store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .unwrap());

    let usage = store.get_usage("cap-orphan", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 4);
    assert_usage_totals(&usage, 75, 0);

    let events = store
        .list_mutation_events(20, Some("cap-orphan"), Some(0))
        .unwrap();
    let rollback = events
        .iter()
        .find(|record| record.event_id == rollback_event_id)
        .expect("rollback event");
    let retry = events
        .iter()
        .find(|record| record.event_id == event_id)
        .expect("retry authorize event");
    assert!(retry.event_seq > rollback.event_seq);
    assert_eq!(retry.authority.as_ref(), Some(&changed));

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("retry open hold");
        assert_eq!(hold.remaining_exposure_units, 75);
        assert_eq!(hold.disposition, HoldDisposition::Open);
    }

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute(
                "DELETE FROM budget_mutation_events WHERE event_id = ?1",
                params![event_id],
            )
            .unwrap();
        transaction.commit().unwrap();
    }

    let missing_replacement = store
        .try_charge_cost_with_ids_and_authority(
            "cap-orphan",
            0,
            Some(10),
            75,
            Some(100),
            Some(400),
            Some(hold_id),
            Some(event_id),
            Some(&changed),
        )
        .expect_err("a replacement authorization event cannot be recreated without compensation");
    assert!(matches!(
        missing_replacement,
        BudgetStoreError::Invariant(_)
    ));
    let events = store
        .list_mutation_events(20, Some("cap-orphan"), Some(0))
        .unwrap();
    assert!(events.iter().all(|record| record.event_id != event_id));
    let unchanged = store.get_usage("cap-orphan", 0).unwrap().unwrap();
    assert_eq!(unchanged, usage);

    let _ = fs::remove_file(path);
}

#[test]
fn import_mutation_record_keeps_duplicate_release_events_idempotent_sqlite() {
    let path = unique_db_path("chio-budget-import-release-idempotent");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let hold_id = "hold-cap-import-0";
    let authorize_event_id = "hold-cap-import-0:authorize";
    let release_event_id = "hold-cap-import-0:release";

    assert!(store
        .try_charge_cost_with_ids(
            "cap-import",
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
        .reduce_charge_cost_with_ids("cap-import", 0, 100, Some(hold_id), Some(release_event_id))
        .unwrap();

    let release_record = store
        .list_mutation_events(10, Some("cap-import"), Some(0))
        .unwrap()
        .into_iter()
        .find(|record| record.event_id == release_event_id)
        .expect("release event record");

    store.import_mutation_record(&release_record).unwrap();

    let usage = store.get_usage("cap-import", 0).unwrap().unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_usage_totals(&usage, 0, 0);

    {
        let mut connection = store.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("released hold state");
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(hold.disposition, HoldDisposition::Released);
    }

    let events = store
        .list_mutation_events(10, Some("cap-import"), Some(0))
        .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[1].event_id, release_event_id);

    let _ = fs::remove_file(path);
}

#[test]
fn import_mutation_record_preserves_captured_hold_state_sqlite() {
    let source_path = unique_db_path("chio-budget-import-capture-source");
    let target_path = unique_db_path("chio-budget-import-capture-target");
    let source = SqliteBudgetStore::open(&source_path).unwrap();
    let hold_id = "hold-cap-import-capture-0";

    assert!(source
        .try_charge_cost_with_ids(
            "cap-import-capture",
            0,
            Some(10),
            100,
            Some(200),
            Some(1000),
            Some(hold_id),
            Some("hold-cap-import-capture-0:authorize"),
        )
        .unwrap());
    source
        .capture_budget_hold(BudgetCaptureHoldRequest {
            capability_id: "cap-import-capture".to_string(),
            grant_index: 0,
            exposed_cost_units: 100,
            realized_spend_units: 60,
            hold_id: Some(hold_id.to_string()),
            event_id: Some("hold-cap-import-capture-0:capture".to_string()),
            authority: None,
            admission_operation: None,
        })
        .unwrap();
    let records = source
        .list_mutation_events(10, Some("cap-import-capture"), Some(0))
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].kind, BudgetMutationKind::CaptureExposure);
    assert_eq!(records[1].monetary_state, BudgetMonetaryHoldState::Captured);

    let target = SqliteBudgetStore::open(&target_path).unwrap();
    import_events_with_quota_authority(&target, &records).unwrap();
    target.import_mutation_record(&records[1]).unwrap();

    {
        let mut connection = target.connection().unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .unwrap();
        let hold = SqliteBudgetStore::load_hold(&transaction, hold_id)
            .unwrap()
            .expect("imported captured hold state");
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(hold.disposition, HoldDisposition::Captured);
    }
    let imported = target
        .list_mutation_events(10, Some("cap-import-capture"), Some(0))
        .unwrap();
    assert_eq!(imported.len(), 2);
    assert_eq!(imported[1].kind, BudgetMutationKind::CaptureExposure);
    assert_eq!(
        imported[1].monetary_state,
        BudgetMonetaryHoldState::Captured
    );

    let _ = fs::remove_file(source_path);
    let _ = fs::remove_file(target_path);
}

#[test]
fn import_mutation_record_rejects_out_of_range_sqlite_integers_before_floor_raise() {
    let mut candidates = Vec::new();

    let mut record = import_integrity_record("overflow-event-seq", 2);
    record.event_seq = u64::MAX;
    candidates.push(("event_seq", record));

    let mut record = import_integrity_record("overflow-usage-seq", 2);
    record.usage_seq = Some(u64::MAX);
    candidates.push(("usage_seq", record));

    let mut record = import_integrity_record("overflow-exposure", 2);
    record.exposure_units = u64::MAX;
    candidates.push(("exposure_units", record));

    let mut record = import_integrity_record("overflow-realized", 2);
    record.realized_spend_units = u64::MAX;
    candidates.push(("realized_spend_units", record));

    let mut record = import_integrity_record("overflow-max-per", 2);
    record.max_cost_per_invocation = Some(u64::MAX);
    candidates.push(("max_cost_per_invocation", record));

    let mut record = import_integrity_record("overflow-max-total", 2);
    record.max_total_cost_units = Some(u64::MAX);
    candidates.push(("max_total_cost_units", record));

    let mut record = import_integrity_record("overflow-exposed-total", 2);
    record.total_cost_exposed_after = u64::MAX;
    candidates.push(("total_cost_exposed_after", record));

    let mut record = import_integrity_record("overflow-realized-total", 2);
    record.total_cost_realized_spend_after = u64::MAX;
    candidates.push(("total_cost_realized_spend_after", record));

    let mut record = import_integrity_record("overflow-lease-epoch", 2);
    record.authority.as_mut().unwrap().lease_epoch = u64::MAX;
    candidates.push(("lease_epoch", record));

    for (field, record) in candidates {
        let path = unique_db_path(&format!("chio-budget-import-overflow-{field}"));
        let store = SqliteBudgetStore::open(&path).unwrap();
        import_events_with_quota_authority(&store, &[import_integrity_record("baseline", 1)])
            .unwrap();

        let error = import_events_with_quota_authority(&store, std::slice::from_ref(&record))
            .expect_err("out-of-range imported integer must fail closed");
        assert!(
            matches!(error, BudgetStoreError::Overflow(_)),
            "{field} returned the wrong error: {error}"
        );
        assert_eq!(
            replication_floor(&store),
            1,
            "{field} advanced the replication floor before rejection"
        );
        assert_eq!(
            store.max_mutation_event_seq().unwrap(),
            1,
            "{field} persisted a rejected mutation"
        );

        let _ = fs::remove_file(path);
    }
}

#[test]
fn imported_usage_rejects_out_of_range_sqlite_integers_before_floor_raise() {
    let mut records = Vec::new();

    let mut record = usage_record("cap-overflow-seq", 0, 1, 100, 1, 0, 0);
    record.seq = u64::MAX;
    records.push(("seq", record));

    let mut record = usage_record("cap-overflow-exposed", 0, 1, 100, 1, 0, 0);
    record.total_cost_exposed = u64::MAX;
    records.push(("total_cost_exposed", record));

    let mut record = usage_record("cap-overflow-realized", 0, 1, 100, 1, 0, 0);
    record.total_cost_realized_spend = u64::MAX;
    records.push(("total_cost_realized_spend", record));

    for (field, record) in records {
        let path = unique_db_path(&format!("chio-budget-usage-overflow-{field}"));
        let store = SqliteBudgetStore::open(&path).unwrap();

        let error = store
            .upsert_usage(&record)
            .expect_err("out-of-range imported usage must fail closed");
        assert!(
            matches!(error, BudgetStoreError::Overflow(_)),
            "{field} returned the wrong error: {error}"
        );
        assert_eq!(replication_floor(&store), 0, "{field} advanced the floor");
        assert!(store.list_all_usages().unwrap().is_empty());

        let _ = fs::remove_file(path);
    }
}

#[test]
fn imported_duplicate_identity_binds_sequences_time_states_and_authority() {
    let path = unique_db_path("chio-budget-import-exact-identity");
    let store = SqliteBudgetStore::open(&path).unwrap();
    let original = import_integrity_record("exact-event", 1);
    import_events_with_quota_authority(&store, std::slice::from_ref(&original)).unwrap();
    import_events_with_quota_authority(&store, std::slice::from_ref(&original)).unwrap();

    let mut variants = Vec::new();

    let mut record = original.clone();
    record.event_seq = 2;
    record.usage_seq = Some(2);
    variants.push(("event_seq", record));

    let mut record = original.clone();
    record.usage_seq = Some(2);
    variants.push(("usage_seq", record));

    let mut record = original.clone();
    record.recorded_at += 1;
    variants.push(("recorded_at", record));

    let mut record = original.clone();
    record.invocation_state = BudgetInvocationReservationState::Denied;
    variants.push(("invocation_state", record));

    let mut record = original.clone();
    record.monetary_state = BudgetMonetaryHoldState::Captured;
    variants.push(("monetary_state", record));

    let mut record = original.clone();
    record.authority.as_mut().unwrap().lease_epoch += 1;
    variants.push(("authority", record));

    for (field, record) in variants {
        let error = import_events_with_quota_authority(&store, std::slice::from_ref(&record))
            .expect_err("changed duplicate identity must fail closed");
        assert!(
            matches!(error, BudgetStoreError::Invariant(_)),
            "{field} returned the wrong error: {error}"
        );
        assert_eq!(
            replication_floor(&store),
            1,
            "{field} advanced the floor before duplicate rejection"
        );
        assert_eq!(
            store
                .mutation_event_seq_for_event_id("exact-event")
                .unwrap(),
            Some(1)
        );
    }

    let _ = fs::remove_file(path);
}
