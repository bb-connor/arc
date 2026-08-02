#[test]
fn sqlite_store_reports_truthful_single_node_guarantee_level() {
    use chio_kernel::budget_store::{BudgetGuaranteeLevel, BudgetStore};

    let dir = std::env::temp_dir().join(format!("chio-glevel-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap();
    assert_eq!(
        store.budget_guarantee_level(),
        BudgetGuaranteeLevel::SingleNodeAtomic
    );
}

#[test]
fn reap_orphaned_holds_is_reachable_through_budget_store_trait() {
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };
    use std::collections::HashMap;
    use std::sync::Arc;

    let dir = std::env::temp_dir().join(format!("chio-reap-trait-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store = SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap();

    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-reap-trait".to_string(),
            0,
            Some(5),
            100,
            Some(100),
            Some(500),
            Some("hold-orphan-trait".to_string()),
            Some("hold-orphan-trait:authorize".to_string()),
            None,
        ))
        .unwrap();
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    let dyn_store: Arc<dyn BudgetStore> = Arc::new(store);
    let (reconciled, reversed) = dyn_store.reap_orphaned_holds(&HashMap::new()).unwrap();
    assert_eq!(reconciled, 0, "no holds in the realized map to reconcile");
    assert_eq!(reversed, 1, "the open orphaned hold must be reversed");

    let usage = dyn_store.get_usage("cap-reap-trait", 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        0,
        "reversed hold must leave committed cost at zero"
    );
}

#[test]
fn open_hold_stays_reserved_without_reap() {
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };
    use std::sync::Arc;

    let dir = std::env::temp_dir().join(format!("chio-noreap-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let store: Arc<dyn BudgetStore> =
        Arc::new(SqliteBudgetStore::open(dir.join("budget.sqlite")).unwrap());

    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap-noreap".to_string(),
            0,
            Some(5),
            100,
            Some(100),
            Some(500),
            Some("hold-noreap".to_string()),
            Some("hold-noreap:authorize".to_string()),
            None,
        ))
        .unwrap();
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    assert_eq!(store.count_open_holds().unwrap(), 1);
    let usage = store.get_usage("cap-noreap", 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "open hold must remain reserved when startup does not call reap_orphaned_holds"
    );
}

#[test]
fn unstamped_caller_reservation_recovery_is_exact_atomic_and_restart_durable() {
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetHoldDispositionView,
        BudgetMutationKind, BudgetStore, ReservedHoldEnvelope,
        CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX,
        CALLER_NO_PAYMENT_RESERVATION_RECOVERY_EVENT_SUFFIX,
    };

    let path = unique_db_path("caller-reservation-crash-recovery");
    let request_id = "retry-after-caller-reservation-crash";
    let marked_hold = format!("budget-hold:{request_id}:cap-marked:0");
    let ordinary_hold = "budget-hold:ordinary-request:cap-ordinary:0";
    let stamped_hold = "budget-hold:stamped-request:cap-stamped:0";
    let composite_hold = "budget-hold:composite-request:leaf:0";
    let caller_event =
        |hold_id: &str| format!("{hold_id}{CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX}");
    let legacy_request =
        |capability_id: &str, hold_id: &str, event_id: String, authority: &BudgetEventAuthority| {
            BudgetAuthorizeHoldRequest::legacy(
                capability_id.to_string(),
                0,
                Some(1),
                100,
                Some(100),
                Some(100),
                Some(hold_id.to_string()),
                Some(event_id),
                Some(authority.clone()),
            )
        };
    let budget_authority = authority("budget-primary", "lease-recovery", 17);

    {
        let store = SqliteBudgetStore::open(&path).expect("open initial budget store");
        for request in [
            legacy_request(
                "cap-marked",
                &marked_hold,
                caller_event(&marked_hold),
                &budget_authority,
            ),
            legacy_request(
                "cap-ordinary",
                ordinary_hold,
                format!("{ordinary_hold}:authorize"),
                &budget_authority,
            ),
            legacy_request(
                "cap-stamped",
                stamped_hold,
                caller_event(stamped_hold),
                &budget_authority,
            ),
        ] {
            assert!(matches!(
                store.authorize_budget_hold(request),
                Ok(BudgetAuthorizeHoldDecision::Authorized(_))
            ));
        }
        store
            .mark_hold_reserved(
                stamped_hold,
                9_000,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .expect("stamp caller reservation");

        let mut composite =
            composite_authorize_input(composite_hold, &caller_event(composite_hold), 2);
        composite.authority = Some(budget_authority.clone());
        assert!(matches!(
            store
                .authorize_composite_hold(composite)
                .expect("authorize composite hold"),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));

        let marked_usage = store
            .get_usage("cap-marked", 0)
            .expect("read marked usage")
            .expect("marked usage exists");
        assert_eq!(marked_usage.invocation_count, 1);
        assert_eq!(marked_usage.total_cost_exposed, 100);
        assert_eq!(
            store
                .request_id_has_reserved_hold(request_id)
                .expect("probe request id before recovery"),
            Some(true)
        );
    }

    {
        let store = SqliteBudgetStore::open(&path).expect("reopen budget store");
        assert_eq!(
            store
                .recover_unstamped_caller_reservations()
                .expect("recover interrupted caller reservation"),
            1
        );
        assert_eq!(
            store
                .recover_unstamped_caller_reservations()
                .expect("repeat recovery"),
            0,
            "recovery must be idempotent"
        );

        let marked_usage = store
            .get_usage("cap-marked", 0)
            .expect("read recovered usage")
            .expect("recovered usage exists");
        assert_eq!(marked_usage.invocation_count, 0);
        assert_eq!(marked_usage.total_cost_exposed, 0);
        assert_eq!(marked_usage.total_cost_realized_spend, 0);
        let marked = store
            .get_budget_hold(&marked_hold)
            .expect("read recovered hold")
            .expect("recovered hold exists");
        assert_eq!(marked.disposition, BudgetHoldDispositionView::Reversed);
        assert_eq!(marked.remaining_exposure_units, 0);

        let recovery_event_prefix =
            format!("{marked_hold}{CALLER_NO_PAYMENT_RESERVATION_RECOVERY_EVENT_SUFFIX}");
        let recovery_event = store
            .list_mutation_events(32, Some("cap-marked"), Some(0))
            .expect("read recovery events")
            .into_iter()
            .find(|event| event.event_id.starts_with(&recovery_event_prefix))
            .expect("recovery event exists");
        assert_eq!(recovery_event.kind, BudgetMutationKind::ReverseExposure);
        assert_eq!(recovery_event.authority.as_ref(), Some(&budget_authority));
        assert_eq!(recovery_event.usage_seq, Some(recovery_event.event_seq));
        assert_eq!(recovery_event.invocation_count_after, 0);
        assert_eq!(recovery_event.total_cost_exposed_after, 0);
        assert_eq!(
            store
                .request_id_has_reserved_hold(request_id)
                .expect("probe recovered request id"),
            Some(false),
            "the exact recovered request id must become retryable"
        );

        let ordinary = store
            .get_budget_hold(ordinary_hold)
            .expect("read ordinary hold")
            .expect("ordinary hold exists");
        assert_eq!(ordinary.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(ordinary.reserved_until, None);
        assert_eq!(ordinary.remaining_exposure_units, 100);
        let ordinary_usage = store
            .get_usage("cap-ordinary", 0)
            .expect("read ordinary usage")
            .expect("ordinary usage exists");
        assert_eq!(ordinary_usage.invocation_count, 1);
        assert_eq!(ordinary_usage.total_cost_exposed, 100);

        let stamped = store
            .get_budget_hold(stamped_hold)
            .expect("read stamped hold")
            .expect("stamped hold exists");
        assert_eq!(stamped.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(stamped.reserved_until, Some(9_000));
        assert_eq!(stamped.remaining_exposure_units, 100);
        let stamped_usage = store
            .get_usage("cap-stamped", 0)
            .expect("read stamped usage")
            .expect("stamped usage exists");
        assert_eq!(stamped_usage.invocation_count, 1);
        assert_eq!(stamped_usage.total_cost_exposed, 100);

        let composite = store
            .get_budget_hold(composite_hold)
            .expect("read composite hold")
            .expect("composite hold exists");
        assert_eq!(composite.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(composite.reserved_until, None);
        assert_eq!(composite.remaining_exposure_units, 100);
        let composite_binding = composite_admission_binding(composite_hold);
        let persisted_composite_binding: (Option<String>, Option<String>) = store
            .connection()
            .expect("open composite ownership query")
            .query_row(
                "SELECT operation_id, request_binding_hash \
                 FROM budget_authorization_holds WHERE hold_id = ?1",
                params![composite_hold],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read composite ownership");
        assert_eq!(
            persisted_composite_binding,
            (
                Some(composite_binding.operation_id().to_string()),
                Some(composite_binding.request_binding_hash().to_string()),
            )
        );

        assert!(matches!(
            store
                .authorize_budget_hold(legacy_request(
                    "cap-marked",
                    &marked_hold,
                    caller_event(&marked_hold),
                    &budget_authority,
                ))
                .expect("reauthorize exact recovered request"),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        let retried_usage = store
            .get_usage("cap-marked", 0)
            .expect("read retried usage")
            .expect("retried usage exists");
        assert_eq!(retried_usage.invocation_count, 1);
        assert_eq!(retried_usage.total_cost_exposed, 100);
        let retried = store
            .get_budget_hold(&marked_hold)
            .expect("read retried hold")
            .expect("retried hold exists");
        assert_eq!(retried.disposition, BudgetHoldDispositionView::Open);
        assert_eq!(retried.remaining_exposure_units, 100);
        assert_eq!(
            store
                .request_id_has_reserved_hold(request_id)
                .expect("probe request id after reauthorization"),
            Some(true),
            "a live reauthorization after recovery must make the request id taken again"
        );
        store
            .mark_hold_reserved(
                &marked_hold,
                12_000,
                "USD",
                None,
                &ReservedHoldEnvelope::default(),
            )
            .expect("stamp reauthorized caller reservation");
        assert_eq!(
            store
                .get_budget_hold(&marked_hold)
                .expect("read stamped retry")
                .expect("stamped retry exists")
                .reserved_until,
            Some(12_000)
        );
        assert_eq!(
            store
                .recover_unstamped_caller_reservations()
                .expect("recovery after retry stamp"),
            0,
            "a stamped retry must not be recovered"
        );
    }

    let _ = std::fs::remove_file(path);
}

#[test]
fn unstamped_invocation_only_caller_reservation_recovers_its_atomic_zero_exposure_hold() {
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetHoldDispositionView,
        BudgetStore, CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX,
    };

    let path = unique_db_path("invocation-only-caller-reservation-crash-recovery");
    let capability_id = "cap-invocation-only-reservation";
    let hold_id = "budget-hold:invocation-only-crash:cap-invocation-only-reservation:0";
    let authority = authority("budget-primary", "lease-invocation-only", 23);
    let request = || {
        BudgetAuthorizeHoldRequest::legacy(
            capability_id.to_string(),
            0,
            Some(1),
            0,
            None,
            None,
            Some(hold_id.to_string()),
            Some(format!(
                "{hold_id}{CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX}"
            )),
            Some(authority.clone()),
        )
    };

    {
        let store = SqliteBudgetStore::open(&path).expect("open initial budget store");
        assert!(matches!(
            store
                .authorize_budget_hold(request())
                .expect("authorize invocation-only hold"),
            BudgetAuthorizeHoldDecision::Authorized(_)
        ));
        let usage = store
            .get_usage(capability_id, 0)
            .expect("read invocation-only usage")
            .expect("invocation-only usage exists");
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.total_cost_exposed, 0);
    }

    {
        let store = SqliteBudgetStore::open(&path).expect("reopen budget store");
        assert_eq!(
            store
                .recover_unstamped_caller_reservations()
                .expect("recover invocation-only reservation"),
            1
        );
        let usage = store
            .get_usage(capability_id, 0)
            .expect("read recovered invocation-only usage")
            .expect("recovered invocation-only usage exists");
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.total_cost_exposed, 0);
        let hold = store
            .get_budget_hold(hold_id)
            .expect("read recovered invocation-only hold")
            .expect("recovered invocation-only hold exists");
        assert_eq!(hold.disposition, BudgetHoldDispositionView::Reversed);
        assert_eq!(hold.remaining_exposure_units, 0);
        assert_eq!(
            store
                .recover_unstamped_caller_reservations()
                .expect("repeat invocation-only recovery"),
            0
        );
    }

    let _ = std::fs::remove_file(path);
}

#[test]
fn atomic_invocation_only_caller_reservation_stamps_existing_hold_without_money_fields() {
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore, ReservedHoldEnvelope,
        CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX,
    };

    let path = unique_db_path("atomic-invocation-only-reservation-stamp");
    let capability_id = "cap-atomic-invocation-stamp";
    let hold_id = "budget-hold:atomic-invocation-stamp:cap-atomic-invocation-stamp:0";
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    assert!(matches!(
        store
            .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
                capability_id.to_string(),
                0,
                Some(2),
                0,
                None,
                None,
                Some(hold_id.to_string()),
                Some(format!(
                    "{hold_id}{CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX}"
                )),
                Some(authority("budget-primary", "lease-invocation-stamp", 29)),
            ))
            .expect("authorize invocation-only hold"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let envelope = ReservedHoldEnvelope {
        budget_total: None,
        delegation_depth: 2,
        root_budget_holder: "root-invocation-stamp".to_string(),
    };
    store
        .mark_invocation_hold_reserved(hold_id, capability_id, 0, 17_000, &envelope)
        .expect("stamp atomic invocation-only hold");
    store
        .mark_invocation_hold_reserved(hold_id, capability_id, 0, 17_000, &envelope)
        .expect("retry exact invocation-only stamp");

    let snapshot = store
        .get_budget_hold(hold_id)
        .expect("read stamped invocation-only hold")
        .expect("stamped invocation-only hold exists");
    assert_eq!(snapshot.authorized_exposure_units, 0);
    assert_eq!(snapshot.remaining_exposure_units, 0);
    assert_eq!(snapshot.reserved_until, Some(17_000));
    assert_eq!(snapshot.reserved_currency, None);
    assert_eq!(snapshot.reserved_payment_reference, None);
    assert_eq!(snapshot.reserved_budget_total, None);
    assert_eq!(snapshot.reserved_delegation_depth, Some(2));
    assert_eq!(
        snapshot.reserved_root_budget_holder.as_deref(),
        Some("root-invocation-stamp")
    );
    assert_eq!(
        store
            .recover_unstamped_caller_reservations()
            .expect("stamped hold is not crash-recovered"),
        0
    );
    assert!(store
        .mark_invocation_hold_reserved(hold_id, capability_id, 0, 17_001, &envelope)
        .is_err());

    let _ = std::fs::remove_file(path);
}

#[test]
fn payment_journal_insert_advance_close_and_conflict() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{
        PaymentJournalRecord, PaymentJournalState, PaymentSettleAction, PaymentSettleIntent,
    };

    let path = unique_db_path("payment-journal");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    let record = PaymentJournalRecord {
        request_id: "req-J".to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        admission_operation: None,
        authority: None,
        hold_id: Some("hold-1".to_string()),
        rail: "x402".to_string(),
        authorization_id: None,
        transaction_id: None,
        budget_exposure_units: 100,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 1_000,
        tenant_id: Some("tenant-J".to_string()),
    };
    store.record_payment_journal(&record).expect("insert");
    assert!(
        store.record_payment_journal(&record).is_err(),
        "reused request_id must conflict"
    );

    store
        .advance_payment_journal(
            "req-J",
            PaymentJournalState::HoldPlaced,
            PaymentJournalState::Authorized,
            Some("auth-9"),
            None,
            None,
        )
        .expect("advance to Authorized");
    assert!(
        store
            .advance_payment_journal(
                "req-J",
                PaymentJournalState::HoldPlaced,
                PaymentJournalState::Settling,
                None,
                None,
                Some(PaymentSettleIntent {
                    action: PaymentSettleAction::Capture,
                    amount_units: Some(80),
                }),
            )
            .is_err(),
        "wrong expected state must fail closed"
    );
    assert!(
        store
            .advance_payment_journal(
                "req-J",
                PaymentJournalState::Authorized,
                PaymentJournalState::Settling,
                None,
                None,
                None,
            )
            .is_err(),
        "Settling advance must carry the committed settle intent"
    );

    store
        .advance_payment_journal(
            "req-J",
            PaymentJournalState::Authorized,
            PaymentJournalState::Settling,
            None,
            None,
            Some(PaymentSettleIntent {
                action: PaymentSettleAction::Capture,
                amount_units: Some(80),
            }),
        )
        .expect("advance to Settling with settle intent");
    store
        .advance_payment_journal(
            "req-J",
            PaymentJournalState::Settling,
            PaymentJournalState::Settled,
            None,
            Some("txn-7"),
            None,
        )
        .expect("advance to Settled");

    let incomplete = store
        .list_incomplete_payment_journal(u64::MAX)
        .expect("list");
    let row = incomplete
        .iter()
        .find(|row| row.request_id == "req-J")
        .expect("row present");
    assert_eq!(row.authorization_id.as_deref(), Some("auth-9"));
    assert_eq!(row.transaction_id.as_deref(), Some("txn-7"));
    assert_eq!(row.settle_action, Some(PaymentSettleAction::Capture));
    assert_eq!(row.settle_amount_units, Some(80));
    assert_eq!(row.state, PaymentJournalState::Settled);
    assert_eq!(row.tenant_id.as_deref(), Some("tenant-J"));

    assert!(store.close_payment_journal("req-J").expect("close"));
    assert!(!store
        .close_payment_journal("req-J")
        .expect("close again returns false"));
    assert!(store
        .list_incomplete_payment_journal(u64::MAX)
        .expect("list after close")
        .iter()
        .all(|row| row.request_id != "req-J"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn payment_journal_capture_intent_can_be_restaged_after_exact_rail_recovery() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{
        PaymentJournalRecord, PaymentJournalState, PaymentSettleAction, PaymentSettleIntent,
    };

    let path = unique_db_path("payment-journal-capture-restage");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    for request_id in ["req-release", "req-refund"] {
        store
            .record_payment_journal(&PaymentJournalRecord {
                request_id: request_id.to_string(),
                capability_id: "cap".to_string(),
                grant_index: 0,
                admission_operation: None,
                authority: None,
                hold_id: Some(format!("hold-{request_id}")),
                rail: "test".to_string(),
                authorization_id: None,
                transaction_id: None,
                budget_exposure_units: 100,
                amount_units: 100,
                settle_action: None,
                settle_amount_units: None,
                currency: "USD".to_string(),
                state: PaymentJournalState::HoldPlaced,
                created_at_unix_ms: 1_000,
                tenant_id: None,
            })
            .expect("insert payment journal");
        store
            .advance_payment_journal(
                request_id,
                PaymentJournalState::HoldPlaced,
                PaymentJournalState::Authorized,
                Some("auth-1"),
                None,
                None,
            )
            .expect("record authorization");
        store
            .advance_payment_journal(
                request_id,
                PaymentJournalState::Authorized,
                PaymentJournalState::Settling,
                None,
                None,
                Some(PaymentSettleIntent {
                    action: PaymentSettleAction::Capture,
                    amount_units: Some(100),
                }),
            )
            .expect("stage capture intent");
    }

    store
        .advance_payment_journal(
            "req-release",
            PaymentJournalState::Settling,
            PaymentJournalState::Settling,
            None,
            None,
            Some(PaymentSettleIntent {
                action: PaymentSettleAction::Release,
                amount_units: None,
            }),
        )
        .expect("restage held authorization for release");
    store
        .advance_payment_journal(
            "req-refund",
            PaymentJournalState::Settling,
            PaymentJournalState::Settling,
            None,
            Some("txn-captured"),
            Some(PaymentSettleIntent {
                action: PaymentSettleAction::Refund,
                amount_units: Some(100),
            }),
        )
        .expect("restage settled capture for refund");

    let release = store
        .get_payment_journal("req-release")
        .expect("read release journal")
        .expect("release journal exists");
    assert_eq!(release.state, PaymentJournalState::Settling);
    assert_eq!(release.authorization_id.as_deref(), Some("auth-1"));
    assert_eq!(release.transaction_id, None);
    assert_eq!(release.settle_action, Some(PaymentSettleAction::Release));
    assert_eq!(release.settle_amount_units, None);

    let refund = store
        .get_payment_journal("req-refund")
        .expect("read refund journal")
        .expect("refund journal exists");
    assert_eq!(refund.state, PaymentJournalState::Settling);
    assert_eq!(refund.authorization_id.as_deref(), Some("auth-1"));
    assert_eq!(refund.transaction_id.as_deref(), Some("txn-captured"));
    assert_eq!(refund.settle_action, Some(PaymentSettleAction::Refund));
    assert_eq!(refund.settle_amount_units, Some(100));

    let _ = std::fs::remove_file(path);
}

#[test]
fn get_payment_journal_is_scoped_identically_to_the_incomplete_listing() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("payment-journal-keyed-lookup");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    assert!(store
        .get_payment_journal("req-missing")
        .expect("lookup an absent row")
        .is_none());
    assert!(store
        .get_payment_journal_for_audit("req-missing")
        .expect("audit lookup of an absent row")
        .is_none());

    let record = PaymentJournalRecord {
        request_id: "req-K".to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        admission_operation: None,
        authority: None,
        hold_id: Some("hold-1".to_string()),
        rail: "x402".to_string(),
        authorization_id: Some("auth-K".to_string()),
        transaction_id: None,
        budget_exposure_units: 100,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        tenant_id: Some("tenant-K".to_string()),
        created_at_unix_ms: 1_000,
    };
    store.record_payment_journal(&record).expect("insert");

    let found = store
        .get_payment_journal("req-K")
        .expect("lookup a present row")
        .expect("row present");
    assert_eq!(found, record);
    assert_eq!(
        store
            .get_payment_journal_for_audit("req-K")
            .expect("audit lookup of a present row")
            .expect("audit row present"),
        record
    );

    assert!(store.close_payment_journal("req-K").expect("close"));
    assert!(store
        .get_payment_journal("req-K")
        .expect("lookup a closed row")
        .is_none());
    let closed = store
        .get_payment_journal_for_audit("req-K")
        .expect("audit lookup of a closed row")
        .expect("closed journal remains available for evidence");
    assert_eq!(closed.request_id, record.request_id);
    assert_eq!(closed.authorization_id, record.authorization_id);
    assert_eq!(closed.state, PaymentJournalState::Closed);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn payment_journal_reconcile_failed_rail_finds_only_reconcile_failed_rows() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("payment-journal-reconcile-failed-rail");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    assert!(store
        .payment_journal_reconcile_failed_rail("req-missing")
        .expect("lookup an absent row")
        .is_none());

    let record = PaymentJournalRecord {
        request_id: "req-L".to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        admission_operation: None,
        authority: None,
        hold_id: Some("hold-1".to_string()),
        rail: "x402".to_string(),
        authorization_id: Some("auth-L".to_string()),
        transaction_id: None,
        budget_exposure_units: 100,
        amount_units: 100,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 1_000,
        tenant_id: None,
    };
    store.record_payment_journal(&record).expect("insert");
    assert!(store
        .payment_journal_reconcile_failed_rail("req-L")
        .expect("lookup an open row")
        .is_none());

    store
        .advance_payment_journal(
            "req-L",
            PaymentJournalState::HoldPlaced,
            PaymentJournalState::ReconcileFailed,
            None,
            None,
            None,
        )
        .expect("advance to ReconcileFailed");
    assert_eq!(
        store
            .payment_journal_reconcile_failed_rail("req-L")
            .expect("lookup a reconcile-failed row"),
        Some("x402".to_string())
    );
    assert!(store
        .get_payment_journal("req-L")
        .expect("lookup a reconcile-failed row via get_payment_journal")
        .is_none());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn composite_payment_journal_persists_exact_operation_binding_and_rejects_rebinding() {
    use chio_kernel::budget_store::{BudgetAdmissionOperationBinding, BudgetStore};
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("composite-payment-journal-binding");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    let input = composite_authorize_input(
        "hold-composite-journal",
        "hold-composite-journal:authorize",
        8,
    );
    let binding = BudgetAdmissionOperationBinding::new(
        input.operation_id.clone(),
        input.request_binding_hash.clone(),
    )
    .expect("valid operation binding");
    let journal = PaymentJournalRecord {
        request_id: "req-composite-journal".to_string(),
        capability_id: input.capability_id.clone(),
        grant_index: input.grant_index as u32,
        admission_operation: Some(binding.clone()),
        authority: input.authority.clone(),
        hold_id: Some(input.hold_id.clone()),
        rail: "operation-only".to_string(),
        authorization_id: None,
        transaction_id: None,
        budget_exposure_units: input.requested_exposure_units,
        amount_units: input.requested_exposure_units,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 10,
        tenant_id: None,
    };

    store
        .authorize_composite_hold_with_journal(input.clone(), None, Some(&journal))
        .expect("authorize composite hold and journal atomically");
    store
        .authorize_composite_hold_with_journal(input.clone(), None, Some(&journal))
        .expect("exact authorization retry is idempotent");

    let persisted = store
        .get_payment_journal(&journal.request_id)
        .expect("read journal")
        .expect("journal row exists");
    assert_eq!(persisted.admission_operation.as_ref(), Some(&binding));
    assert_eq!(persisted.authority, input.authority);

    let mut rebound = journal.clone();
    rebound.admission_operation = Some(
        BudgetAdmissionOperationBinding::new(
            "different-operation".to_string(),
            input.request_binding_hash.clone(),
        )
        .expect("valid mismatched binding"),
    );
    let error = store
        .authorize_composite_hold_with_journal(input, None, Some(&rebound))
        .expect_err("operation rebinding must fail closed");
    assert!(error
        .to_string()
        .contains("does not match its budget authorization"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn payment_journal_reopen_rejects_an_incomplete_operation_binding() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("payment-journal-incomplete-binding");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    store
        .record_payment_journal(&PaymentJournalRecord {
            request_id: "req-incomplete-binding".to_string(),
            capability_id: "cap".to_string(),
            grant_index: 0,
            admission_operation: None,
            authority: None,
            hold_id: Some("hold-incomplete-binding".to_string()),
            rail: "x402".to_string(),
            authorization_id: None,
            transaction_id: None,
            budget_exposure_units: 1,
            amount_units: 1,
            settle_action: None,
            settle_amount_units: None,
            currency: "USD".to_string(),
            state: PaymentJournalState::HoldPlaced,
            created_at_unix_ms: 1,
            tenant_id: None,
        })
        .expect("record legacy journal row");
    {
        let connection = store.connection().expect("open direct connection");
        connection
            .execute_batch(
                r#"
                DROP TRIGGER payment_journal_recovery_binding_immutable;
                PRAGMA ignore_check_constraints = ON;
                UPDATE payment_journal
                SET operation_id = 'partial-operation'
                WHERE request_id = 'req-incomplete-binding';
                "#,
            )
            .expect("simulate a partially migrated operation binding");
    }
    drop(store);

    let error = match SqliteBudgetStore::open(&path) {
        Ok(_) => panic!("an incomplete durable operation binding must reject reopen"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("incomplete or invalid operation binding"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn legacy_payment_journal_rows_migrate_amount_into_budget_exposure() {
    let connection = Connection::open_in_memory().expect("open legacy payment journal database");
    connection
        .execute_batch(
            r#"
            CREATE TABLE payment_journal (
                request_id TEXT PRIMARY KEY,
                amount_units INTEGER NOT NULL
            );
            INSERT INTO payment_journal (request_id, amount_units)
            VALUES ('legacy-request', 37);
            "#,
        )
        .expect("create legacy payment journal row");

    ensure_payment_journal_operation_columns(&connection)
        .expect("migrate legacy recovery binding columns");

    let budget_exposure_units = connection
        .query_row(
            "SELECT budget_exposure_units FROM payment_journal WHERE request_id = ?1",
            ["legacy-request"],
            |row| row.get::<_, i64>(0),
        )
        .expect("read migrated budget exposure");
    assert_eq!(budget_exposure_units, 37);
}

#[test]
fn payment_journal_commits_refund_intent_with_captured_transaction() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{
        PaymentJournalRecord, PaymentJournalState, PaymentSettleAction, PaymentSettleIntent,
    };

    let path = unique_db_path("payment-journal-refund-intent");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    store
        .record_payment_journal(&PaymentJournalRecord {
            request_id: "req-refund-intent".to_string(),
            capability_id: "cap".to_string(),
            grant_index: 0,
            admission_operation: None,
            authority: None,
            hold_id: Some("hold-refund-intent".to_string()),
            rail: "x402".to_string(),
            authorization_id: None,
            transaction_id: None,
            budget_exposure_units: 25,
            amount_units: 25,
            settle_action: None,
            settle_amount_units: None,
            currency: "USD".to_string(),
            state: PaymentJournalState::HoldPlaced,
            created_at_unix_ms: 1,
            tenant_id: None,
        })
        .expect("record HoldPlaced row");

    let intent = PaymentSettleIntent {
        action: PaymentSettleAction::Refund,
        amount_units: Some(25),
    };
    assert!(store
        .advance_payment_journal(
            "req-refund-intent",
            PaymentJournalState::HoldPlaced,
            PaymentJournalState::Settling,
            Some("auth-refund-intent"),
            None,
            Some(intent),
        )
        .is_err());
    store
        .advance_payment_journal(
            "req-refund-intent",
            PaymentJournalState::HoldPlaced,
            PaymentJournalState::Settling,
            Some("auth-refund-intent"),
            Some("captured-refund-intent"),
            Some(intent),
        )
        .expect("commit exact refund recovery intent");

    let row = store
        .get_payment_journal("req-refund-intent")
        .expect("read refund row")
        .expect("refund row remains open");
    assert_eq!(row.state, PaymentJournalState::Settling);
    assert_eq!(row.authorization_id.as_deref(), Some("auth-refund-intent"));
    assert_eq!(
        row.transaction_id.as_deref(),
        Some("captured-refund-intent")
    );
    assert_eq!(row.settle_action, Some(PaymentSettleAction::Refund));
    assert_eq!(row.settle_amount_units, Some(25));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn authorize_budget_hold_writes_journal_atomically() {
    use chio_kernel::budget_store::{BudgetAuthorizeHoldRequest, BudgetStore};
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("hold-journal-atomic");
    let store = SqliteBudgetStore::open(&path).expect("open");
    assert!(store.supports_durable_atomic_payment_journal());
    let journal = PaymentJournalRecord {
        request_id: "req-H".to_string(),
        capability_id: "cap".to_string(),
        grant_index: 0,
        admission_operation: None,
        authority: None,
        hold_id: Some("hold-req-H".to_string()),
        rail: "x402".to_string(),
        authorization_id: None,
        transaction_id: None,
        budget_exposure_units: 50,
        amount_units: 50,
        settle_action: None,
        settle_amount_units: None,
        currency: "USD".to_string(),
        state: PaymentJournalState::HoldPlaced,
        created_at_unix_ms: 2_000,
        tenant_id: None,
    };
    let mut authorize_request = BudgetAuthorizeHoldRequest::legacy(
        "cap".to_string(),
        0,
        Some(10),
        50,
        Some(50),
        Some(500),
        Some("hold-req-H".to_string()),
        Some("hold-req-H:authorize".to_string()),
        None,
    );
    authorize_request.payment_journal = Some(journal);
    store
        .authorize_budget_hold(authorize_request)
        .expect("authorize hold with journal");
    let rows = store
        .list_incomplete_payment_journal(u64::MAX)
        .expect("list");
    assert!(rows
        .iter()
        .any(|row| row.request_id == "req-H" && row.state == PaymentJournalState::HoldPlaced));

    let denied_journal = PaymentJournalRecord {
        request_id: "req-D".to_string(),
        hold_id: Some("hold-req-D".to_string()),
        budget_exposure_units: 10_000,
        amount_units: 10_000,
        ..rows[0].clone()
    };
    let mut denied_request = BudgetAuthorizeHoldRequest::legacy(
        "cap".to_string(),
        0,
        Some(10),
        10_000,
        Some(50),
        Some(500),
        Some("hold-req-D".to_string()),
        Some("hold-req-D:authorize".to_string()),
        None,
    );
    denied_request.payment_journal = Some(denied_journal);
    let decision = store
        .authorize_budget_hold(denied_request)
        .expect("denied authorize still returns a decision");
    assert!(matches!(
        decision,
        chio_kernel::budget_store::BudgetAuthorizeHoldDecision::Denied(_)
    ));
    assert!(store
        .list_incomplete_payment_journal(u64::MAX)
        .expect("list after deny")
        .iter()
        .all(|row| row.request_id != "req-D"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn expire_open_hold_releases_exposure_without_recording_spend() {
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldRequest, BudgetInvocationReservationState, BudgetMonetaryHoldState,
        BudgetMutationKind, BudgetStore,
    };

    let path = unique_db_path("hold-sweep");
    let store = SqliteBudgetStore::open(&path).expect("open");
    store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest::legacy(
            "cap".to_string(),
            0,
            Some(10),
            70,
            Some(70),
            Some(500),
            Some("hold-sweep-1".to_string()),
            Some("hold-sweep-1:authorize".to_string()),
            None,
        ))
        .expect("authorize hold");

    let exposed_before = store
        .get_usage("cap", 0)
        .expect("usage")
        .expect("record")
        .total_cost_exposed;
    assert_eq!(exposed_before, 70);
    assert_eq!(store.open_hold_count().expect("count"), 1);

    let open = store
        .list_open_holds_older_than(u64::MAX, 100)
        .expect("list open");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].hold_id, "hold-sweep-1");
    assert_eq!(open[0].capability_id, "cap");
    assert_eq!(open[0].remaining_exposure_units, 70);
    assert!(store
        .list_open_holds_older_than(0, 100)
        .expect("list young")
        .is_empty());

    assert!(store.expire_open_hold("hold-sweep-1").expect("expire"));
    assert!(!store
        .expire_open_hold("hold-sweep-1")
        .expect("expire again"));

    let usage = store.get_usage("cap", 0).expect("usage").expect("record");
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.total_cost_realized_spend, 0);
    assert_eq!(usage.invocation_count, 0);

    let events = store
        .list_mutation_events(10, Some("cap"), Some(0))
        .expect("events");
    let expire = events
        .iter()
        .find(|event| event.kind == BudgetMutationKind::ExpireHold)
        .expect("expire mutation event");
    assert_eq!(
        expire.invocation_state,
        BudgetInvocationReservationState::Absent
    );
    assert_eq!(expire.monetary_state, BudgetMonetaryHoldState::Released);
    assert_eq!(store.open_hold_count().expect("count after"), 0);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn expire_open_hold_returns_the_invocation_slot() {
    use chio_kernel::budget_store::{
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
    };

    let path = unique_db_path("hold-sweep-invocation");
    let store = SqliteBudgetStore::open(&path).expect("open");
    let authorize = |hold: &str| {
        BudgetAuthorizeHoldRequest::legacy(
            "cap".to_string(),
            0,
            Some(1),
            70,
            Some(70),
            Some(500),
            Some(hold.to_string()),
            Some(format!("{hold}:authorize")),
            None,
        )
    };

    assert!(matches!(
        store
            .authorize_budget_hold(authorize("hold-inv-1"))
            .expect("authorize"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    let usage = store.get_usage("cap", 0).expect("usage").expect("record");
    assert_eq!(usage.invocation_count, 1);

    assert!(store.expire_open_hold("hold-inv-1").expect("expire"));
    let usage = store.get_usage("cap", 0).expect("usage").expect("record");
    assert_eq!(
        usage.invocation_count, 0,
        "expiry must reverse the invocation debit exactly like the normal reverse path"
    );
    assert_eq!(usage.total_cost_exposed, 0);

    assert!(matches!(
        store
            .authorize_budget_hold(authorize("hold-inv-2"))
            .expect("authorize retry"),
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));

    let _ = std::fs::remove_file(&path);
}

type QuotaAuthorityRow = (String, String, i64, u32, u32, u32, i64, u64);

fn quota_authority_rows(
    store: &SqliteBudgetStore,
) -> Result<Vec<QuotaAuthorityRow>, Box<dyn std::error::Error>> {
    let connection = store.connection()?;
    let mut statement = connection.prepare(
        r#"
            SELECT profile, owner_id, grant_index_key, max_invocations,
                   reserved_invocations, captured_invocations, updated_at, seq
            FROM budget_invocation_quota_usage
            ORDER BY profile, owner_id, grant_index_key
            "#,
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                test_row_u64(row, 7)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

fn grant_quota_authority_row(
    store: &SqliteBudgetStore,
    owner_id: &str,
) -> Result<QuotaAuthorityRow, Box<dyn std::error::Error>> {
    quota_authority_rows(store)?
        .into_iter()
        .find(|row| {
            row.0 == BudgetQuotaProfile::GrantInvocation.as_str() && row.1 == owner_id && row.2 == 0
        })
        .ok_or_else(|| format!("grant quota row for `{owner_id}` is missing").into())
}

#[test]
fn mixed_monetary_denial_preserves_primary_and_pins_missing_quota_rows_at_zero(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("quota-authority-mixed-monetary-denial");
    {
        let store = SqliteBudgetStore::open(&path)?;
        assert!(store.try_increment_with_event_id(
            "leaf",
            0,
            Some(2),
            Some("event-quota-authority-primary-capture"),
        )?);

        let quota_count = store.connection()?.query_row(
            "SELECT COUNT(*) FROM budget_invocation_quota_usage",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        assert_eq!(
            quota_count, 1,
            "only the primary quota may exist before admission"
        );

        let primary_before = grant_quota_authority_row(&store, "leaf")?;
        assert_eq!((primary_before.4, primary_before.5), (0, 1));

        let mut request = composite_authorize_input(
            "hold-quota-authority-mixed-denial",
            "event-quota-authority-mixed-denial",
            2,
        );
        request.requested_exposure_units = 101;
        request.max_cost_per_invocation = Some(100);
        let decision = store.authorize_composite_hold(request.clone())?;
        let BudgetAuthorizeHoldDecision::Denied(denied) = &decision else {
            return Err("monetary overspend did not deny the composite authorization".into());
        };
        let denial_seq = denied
            .metadata
            .budget_commit_index
            .ok_or("durable denial did not expose its event sequence")?;
        assert_eq!(denied.invocation_count_after, 1);
        assert!(denied
            .invocation_counts_after
            .iter()
            .any(
                |usage| usage.quota.key().profile() == BudgetQuotaProfile::GrantInvocation
                    && usage.captured_invocations_after == 1
                    && usage.reserved_invocations_after == 0
            ));

        let primary_after = grant_quota_authority_row(&store, "leaf")?;
        assert_eq!(
            primary_after, primary_before,
            "denial must not rewrite the existing primary authority row"
        );

        let pinned = quota_authority_rows(&store)?
            .into_iter()
            .filter(|row| {
                !(row.0 == BudgetQuotaProfile::GrantInvocation.as_str()
                    && row.1 == "leaf"
                    && row.2 == 0)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            pinned.len(),
            2,
            "aggregate and broker authority must be pinned"
        );
        assert!(pinned.iter().all(|row| row.4 == 0 && row.5 == 0));
        assert!(pinned.iter().any(|row| {
            row.0 == BudgetQuotaProfile::AggregateCapabilityInvocation.as_str()
                && row.1 == "leaf"
                && row.2 == -1
        }));
        let broker_owner_id = "22".repeat(32);
        assert!(pinned.iter().any(|row| {
            row.0 == BudgetQuotaProfile::SupplementalBrokerExecution.as_str()
                && row.1 == broker_owner_id.as_str()
                && row.2 == -1
        }));

        let persisted: (i64, u64, Option<u64>) = store.connection()?.query_row(
            r#"
                SELECT authorization.allowed, event.event_seq, event.usage_seq
                FROM budget_composite_authorizations AS authorization
                JOIN budget_mutation_events AS event
                  ON event.event_id = authorization.event_id
                WHERE authorization.event_id = 'event-quota-authority-mixed-denial'
                "#,
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    test_row_u64(row, 1)?,
                    test_row_optional_u64(row, 2)?,
                ))
            },
        )?;
        assert_eq!(persisted, (0, denial_seq, None));
        assert_eq!(
            store.get_budget_hold("hold-quota-authority-mixed-denial")?,
            None,
            "denial must not synthesize a hold"
        );
        drop(store);

        let reopened = SqliteBudgetStore::open(&path)?;
        assert_eq!(
            reopened.authorize_composite_hold(request.clone())?,
            decision
        );
        let mut changed = request.clone();
        changed.requested_exposure_units = 99;
        assert!(matches!(
            reopened.authorize_composite_hold(changed),
            Err(BudgetStoreError::Conflict(_))
        ));
    }
    let _ = std::fs::remove_file(path);
    Ok(())
}

#[test]
fn composite_replay_after_capture_and_later_reserve_keeps_live_quota_state(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("quota-authority-composite-replay-live-state");
    let first_request = composite_authorize_input(
        "hold-quota-authority-replay-first",
        "event-quota-authority-replay-first",
        4,
    );

    let store = SqliteBudgetStore::open(&path)?;
    let original = store.authorize_composite_hold(first_request.clone())?;
    let BudgetAuthorizeHoldDecision::Authorized(original_snapshot) = &original else {
        return Err("first composite hold was not authorized".into());
    };
    let original_seq = original_snapshot
        .metadata
        .budget_commit_index
        .ok_or("authorization did not expose its event sequence")?;
    assert!(original_snapshot
        .invocation_counts_after
        .iter()
        .all(
            |usage| usage.reserved_invocations_after == 1 && usage.captured_invocations_after == 0
        ));

    let captured = store.capture_invocation_reservations(BudgetCaptureInvocationRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        hold_id: Some("hold-quota-authority-replay-first".to_string()),
        event_id: Some("event-quota-authority-replay-first:capture".to_string()),
        authority: None,
        admission_operation: Some(composite_admission_binding(
            "hold-quota-authority-replay-first",
        )),
    })?;
    assert_eq!(
        captured.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert!(store
        .authorize_composite_hold(composite_authorize_input(
            "hold-quota-authority-replay-later",
            "event-quota-authority-replay-later",
            4,
        ))?
        .is_authorized());

    let live_before_replay = quota_authority_rows(&store)?;
    assert_eq!(live_before_replay.len(), 3);
    assert!(live_before_replay
        .iter()
        .all(|row| row.4 == 1 && row.5 == 1 && row.7 > original_seq));
    let event_count_before = store.connection()?.query_row(
        "SELECT COUNT(*) FROM budget_mutation_events",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    drop(store);

    let reopened = SqliteBudgetStore::open(&path)?;
    assert_eq!(
        reopened.authorize_composite_hold(first_request)?,
        original,
        "authorization replay must return its original frozen decision"
    );
    assert_eq!(
        quota_authority_rows(&reopened)?,
        live_before_replay,
        "authorization replay must not rewind later live quota counters or sequence"
    );
    let event_count_after = reopened.connection()?.query_row(
        "SELECT COUNT(*) FROM budget_mutation_events",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    assert_eq!(event_count_after, event_count_before);

    let _ = std::fs::remove_file(path);
    Ok(())
}

#[test]
fn reserve_and_compatibility_capture_race_consume_one_shared_grant_unit(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("quota-authority-reserve-capture-race");
    let seed = SqliteBudgetStore::open(&path)?;
    drop(seed);

    let increment_store = SqliteBudgetStore::open(&path)?;
    let composite_store = SqliteBudgetStore::open(&path)?;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let increment_barrier = std::sync::Arc::clone(&barrier);
    let increment = std::thread::spawn(move || {
        increment_barrier.wait();
        increment_store.try_increment_with_event_id(
            "leaf",
            0,
            Some(1),
            Some("event-quota-authority-race-capture"),
        )
    });

    let mut composite_request = composite_authorize_input(
        "hold-quota-authority-race-reserve",
        "event-quota-authority-race-reserve",
        1,
    );
    composite_request.invocation_quotas = vec![persisted_quota(
        BudgetQuotaProfile::GrantInvocation,
        "leaf",
        Some(0),
        1,
    )];
    composite_request.requested_exposure_units = 0;
    composite_request.max_cost_per_invocation = None;
    composite_request.max_total_cost_units = None;
    let composite_barrier = std::sync::Arc::clone(&barrier);
    let composite = std::thread::spawn(move || {
        composite_barrier.wait();
        composite_store.authorize_composite_hold(composite_request)
    });

    let increment_result = increment.join().map_err(|_| "increment racer panicked")?;
    let composite_result = composite.join().map_err(|_| "composite racer panicked")?;
    let increment_allowed = match &increment_result {
        Ok(allowed) => *allowed,
        Err(error) if error.to_string().contains("composite invocation admission") => false,
        Err(error) => return Err(format!("unexpected compatibility racer error: {error}").into()),
    };
    let composite_authorized = match &composite_result {
        Ok(decision) => decision.is_authorized(),
        Err(error) => return Err(format!("unexpected composite racer error: {error}").into()),
    };
    assert_eq!(
        usize::from(increment_allowed) + usize::from(composite_authorized),
        1,
        "exactly one mutation mode may consume the shared last unit"
    );
    if increment_allowed {
        assert!(matches!(
            &composite_result,
            Ok(BudgetAuthorizeHoldDecision::Denied(_))
        ));
    } else {
        assert!(composite_authorized);
        assert!(
            matches!(&increment_result, Ok(false))
                || matches!(&increment_result, Err(error) if error.to_string().contains("composite invocation admission")),
            "the compatibility loser must be a durable denial or managed-grant conflict"
        );
    }

    let store = SqliteBudgetStore::open(&path)?;
    let (row_count, maximum, reserved, captured, quota_seq): (i64, u32, u32, u32, u64) =
        store.connection()?.query_row(
            r#"
                SELECT
                    (SELECT COUNT(*) FROM budget_invocation_quota_usage),
                    max_invocations,
                    reserved_invocations,
                    captured_invocations,
                    seq
                FROM budget_invocation_quota_usage
                WHERE profile = 'chio.grant-invocation.v1'
                  AND owner_id = 'leaf'
                  AND grant_index_key = 0
                "#,
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    test_row_u64(row, 4)?,
                ))
            },
        )?;
    assert_eq!(row_count, 1);
    assert_eq!(maximum, 1);
    assert_eq!(reserved + captured, 1);
    assert_eq!(usize::from(reserved == 1) + usize::from(captured == 1), 1);
    assert_eq!(
        store
            .get_usage("leaf", 0)?
            .ok_or("legacy race usage is missing")?
            .invocation_count,
        1
    );

    let events = {
        let connection = store.connection()?;
        let mut statement = connection.prepare(
            r#"
                SELECT event_id, allowed, event_seq, usage_seq
                FROM budget_mutation_events
                WHERE event_id IN (
                    'event-quota-authority-race-capture',
                    'event-quota-authority-race-reserve'
                )
                ORDER BY event_seq
                "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    test_row_u64(row, 2)?,
                    test_row_optional_u64(row, 3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows
    };
    assert!((1..=2).contains(&events.len()));
    let allowed_events = events
        .iter()
        .filter(|event| event.1 == Some(1))
        .collect::<Vec<_>>();
    assert_eq!(allowed_events.len(), 1);
    assert_eq!(allowed_events[0].3, Some(allowed_events[0].2));
    assert_eq!(quota_seq, allowed_events[0].2);
    assert!(events
        .iter()
        .filter(|event| event.1 == Some(0))
        .all(|event| event.3.is_none()));
    let hold_count = store
        .connection()?
        .query_row(
            "SELECT COUNT(*) FROM budget_authorization_holds WHERE hold_id = 'hold-quota-authority-race-reserve'",
            [],
            |row| row.get::<_, i64>(0),
        )?;
    assert_eq!(hold_count, i64::from(composite_authorized));

    let _ = std::fs::remove_file(path);
    Ok(())
}

#[test]
fn compatibility_increment_replay_after_reverse_and_live_mutations_is_read_only(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("quota-authority-compatibility-replay-live-state");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_increment_with_event_id(
        "cap-quota-authority-replay",
        0,
        Some(2),
        Some("event-quota-authority-replay-original"),
    )?);
    let original_event_seq = store
        .list_mutation_events(10, Some("cap-quota-authority-replay"), Some(0))?
        .into_iter()
        .find(|event| event.event_id == "event-quota-authority-replay-original")
        .ok_or("original compatibility event is missing")?
        .event_seq;
    store.reverse_charge_cost_with_ids(
        "cap-quota-authority-replay",
        0,
        0,
        None,
        Some("event-quota-authority-replay-reverse"),
    )?;
    assert!(store.try_increment_with_event_id(
        "cap-quota-authority-replay",
        0,
        Some(2),
        Some("event-quota-authority-replay-live-one"),
    )?);
    assert!(store.try_increment_with_event_id(
        "cap-quota-authority-replay",
        0,
        Some(2),
        Some("event-quota-authority-replay-live-two"),
    )?);

    let row_before = grant_quota_authority_row(&store, "cap-quota-authority-replay")?;
    assert_eq!((row_before.3, row_before.4, row_before.5), (2, 0, 2));
    assert!(row_before.7 > original_event_seq);
    let event_count_before = store
        .connection()?
        .query_row(
            "SELECT COUNT(*) FROM budget_mutation_events WHERE capability_id = 'cap-quota-authority-replay' AND grant_index = 0",
            [],
            |row| row.get::<_, i64>(0),
        )?;
    drop(store);

    let reopened = SqliteBudgetStore::open(&path)?;
    assert!(reopened.try_increment_with_event_id(
        "cap-quota-authority-replay",
        0,
        Some(2),
        Some("event-quota-authority-replay-original"),
    )?);
    let row_after = grant_quota_authority_row(&reopened, "cap-quota-authority-replay")?;
    assert_eq!(row_after, row_before);
    let event_count_after = reopened
        .connection()?
        .query_row(
            "SELECT COUNT(*) FROM budget_mutation_events WHERE capability_id = 'cap-quota-authority-replay' AND grant_index = 0",
            [],
            |row| row.get::<_, i64>(0),
        )?;
    assert_eq!(event_count_after, event_count_before);
    assert!(matches!(
        reopened.try_increment_with_event_id(
            "cap-quota-authority-replay",
            0,
            Some(3),
            Some("event-quota-authority-replay-original"),
        ),
        Err(BudgetStoreError::Conflict(_))
    ));
    let unchanged = grant_quota_authority_row(&reopened, "cap-quota-authority-replay")?;
    assert_eq!(unchanged, row_before);

    let _ = std::fs::remove_file(path);
    Ok(())
}

#[test]
fn budget_schema_v0_removes_self_asserted_partition_escrow_authority() {
    let path = unique_db_path("partition-escrow-schema-v0-upgrade");
    drop(SqliteBudgetStore::open(&path).expect("create current budget database"));

    let legacy = Connection::open(&path).expect("open prior budget database");
    legacy
        .execute(
            "UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'budget'",
            [],
        )
        .expect("mark prior budget schema");
    legacy
        .execute_batch(
            r#"
            DROP TRIGGER budget_partition_escrow_evidence_insert_guard;
            CREATE TABLE partition_escrow_budget_store_config (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                store_identity_digest TEXT NOT NULL UNIQUE,
                counter_namespace_digest TEXT NOT NULL UNIQUE,
                fencing_token INTEGER NOT NULL CHECK (fencing_token > 0)
            );
            CREATE TRIGGER partition_escrow_budget_store_config_update_forbidden
            BEFORE UPDATE ON partition_escrow_budget_store_config
            BEGIN
                SELECT RAISE(ABORT, 'immutable partition escrow budget store configuration');
            END;
            CREATE TRIGGER partition_escrow_budget_store_config_delete_forbidden
            BEFORE DELETE ON partition_escrow_budget_store_config
            BEGIN
                SELECT RAISE(ABORT, 'immutable partition escrow budget store configuration');
            END;
            CREATE TRIGGER budget_partition_escrow_evidence_insert_guard
            BEFORE INSERT ON budget_composite_partition_escrow_evidence
            WHEN NOT EXISTS (
                SELECT 1 FROM partition_escrow_budget_store_config WHERE singleton = 1
            )
            BEGIN
                SELECT RAISE(ABORT, 'partition escrow evidence lacks configured authorization binding');
            END;
            "#,
        )
        .expect("install prior self-asserted partition escrow schema");
    drop(legacy);

    drop(SqliteBudgetStore::open(&path).expect("upgrade prior budget schema"));
    let upgraded = Connection::open(&path).expect("inspect upgraded budget database");
    let version = upgraded
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'budget'",
            [],
            |row| row.get::<_, i32>(0),
        )
        .expect("budget schema version");
    assert_eq!(version, 1);
    let obsolete_table_exists = upgraded
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'partition_escrow_budget_store_config')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .expect("obsolete config table query");
    assert!(!obsolete_table_exists);
    let trigger_sql = upgraded
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'budget_partition_escrow_evidence_insert_guard'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("partition escrow evidence trigger");
    assert!(!trigger_sql.contains("partition_escrow_budget_store_config"));
    assert!(trigger_sql.contains("budget_composite_authorizations"));
    assert!(trigger_sql.contains("budget_composite_authorization_artifacts"));
    assert!(crate::check_schema_version(
        &upgraded,
        super::store::BUDGET_STORE_SCHEMA_KEY,
        0,
        super::store::BUDGET_STORE_LEGACY_ANCHOR_TABLES,
    )
    .is_err());

    drop(upgraded);
    let _ = std::fs::remove_file(path);
}
