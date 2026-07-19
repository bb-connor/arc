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
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-reap-trait".to_string(),
            grant_index: 0,
            max_invocations: Some(5),
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-orphan-trait".to_string()),
            event_id: Some("hold-orphan-trait:authorize".to_string()),
            authority: None,
            payment_journal: None,
        })
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
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap-noreap".to_string(),
            grant_index: 0,
            max_invocations: Some(5),
            requested_exposure_units: 100,
            max_cost_per_invocation: Some(100),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-noreap".to_string()),
            event_id: Some("hold-noreap:authorize".to_string()),
            authority: None,
            payment_journal: None,
        })
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
    store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            requested_exposure_units: 50,
            max_cost_per_invocation: Some(50),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-req-H".to_string()),
            event_id: Some("hold-req-H:authorize".to_string()),
            authority: None,
            payment_journal: Some(journal),
        })
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
    let decision = store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            requested_exposure_units: 10_000,
            max_cost_per_invocation: Some(50),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-req-D".to_string()),
            event_id: Some("hold-req-D:authorize".to_string()),
            authority: None,
            payment_journal: Some(denied_journal),
        })
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
    use chio_kernel::budget_store::{BudgetAuthorizeHoldRequest, BudgetMutationKind, BudgetStore};

    let path = unique_db_path("hold-sweep");
    let store = SqliteBudgetStore::open(&path).expect("open");
    store
        .authorize_budget_hold(BudgetAuthorizeHoldRequest {
            capability_id: "cap".to_string(),
            grant_index: 0,
            max_invocations: Some(10),
            requested_exposure_units: 70,
            max_cost_per_invocation: Some(70),
            max_total_cost_units: Some(500),
            hold_id: Some("hold-sweep-1".to_string()),
            event_id: Some("hold-sweep-1:authorize".to_string()),
            authority: None,
            payment_journal: None,
        })
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
    assert!(events
        .iter()
        .any(|event| event.kind == BudgetMutationKind::ExpireHold));
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
    let authorize = |hold: &str| BudgetAuthorizeHoldRequest {
        capability_id: "cap".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        requested_exposure_units: 70,
        max_cost_per_invocation: Some(70),
        max_total_cost_units: Some(500),
        hold_id: Some(hold.to_string()),
        event_id: Some(format!("{hold}:authorize")),
        authority: None,
        payment_journal: None,
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
