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
    let caller_event = |hold_id: &str| {
        format!("{hold_id}{CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX}")
    };
    let legacy_request = |capability_id: &str,
                          hold_id: &str,
                          event_id: String,
                          authority: &BudgetEventAuthority| {
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
                store.authorize_budget_hold(request).expect("authorize hold"),
                BudgetAuthorizeHoldDecision::Authorized(_)
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

        let mut composite = composite_authorize_input(
            composite_hold,
            &caller_event(composite_hold),
            2,
        );
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
        BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest, BudgetStore,
        ReservedHoldEnvelope, CALLER_NO_PAYMENT_RESERVATION_AUTHORIZE_EVENT_SUFFIX,
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
fn get_payment_journal_is_scoped_identically_to_the_incomplete_listing() {
    use chio_kernel::budget_store::BudgetStore;
    use chio_kernel::payment::{PaymentJournalRecord, PaymentJournalState};

    let path = unique_db_path("payment-journal-keyed-lookup");
    let store = SqliteBudgetStore::open(&path).expect("open budget store");
    assert!(store
        .get_payment_journal("req-missing")
        .expect("lookup an absent row")
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

    assert!(store.close_payment_journal("req-K").expect("close"));
    assert!(store
        .get_payment_journal("req-K")
        .expect("lookup a closed row")
        .is_none());

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
