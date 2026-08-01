#[test]
fn admission_authority_commits_and_state_writes_recover_exactly() {
    let directory =
        chio_test_support::private_fs::private_tempdir("chio-t2-admission-").test_unwrap();
    let directory_path = std::fs::canonicalize(directory.path()).test_unwrap();
    let operation_path = directory_path.join("admission.sqlite3");
    let budget_path = directory_path.join("budget.sqlite3");
    let approval_path = directory_path.join("approval.sqlite3");
    let nonce_path = directory_path.join("nonce.sqlite3");
    let attempt_path = directory_path.join("attempt.sqlite3");
    let revocation_path = directory_path.join("revocation.sqlite3");
    let reverse_budget_path = directory_path.join("reverse-budget.sqlite3");
    let release_budget_path = directory_path.join("release-budget.sqlite3");
    let terminal_receipt_path = directory_path.join("terminal-receipt.sqlite3");
    let receipt_path = directory_path.join("receipt.sqlite3");
    let mut registration = broker_registration(
        "invocation-crash",
        "11".repeat(32),
        "proof-nonce-crash-matrix",
    );
    let terminal_signer = Keypair::from_seed(&[79; 32]);
    let prepared = tool_admission_operation(
        &registration.ids.attempt_id,
        format!("kernel:{}", terminal_signer.public_key().to_hex()),
    );
    let operation_id = prepared.operation_id().to_string();
    let request_binding_hash = prepared.request_binding_hash().to_string();
    registration.ids.operation_id.clone_from(&operation_id);
    let mut inventory = AuthorityCrashBoundaryInventory::default();

    let before_create = SqliteSecurityAdmissionOperationStore::open(&operation_path).test_unwrap();
    assert_eq!(before_create.load(&operation_id).test_unwrap(), None);
    inventory.before("operation.create_prepared", || {
        before_create.create_prepared(prepared.clone())
    });
    drop(before_create);

    let create_store = SqliteSecurityAdmissionOperationStore::open(&operation_path).test_unwrap();
    let lost_create = lose_response_after_commit(
        || create_store.create_prepared(prepared.clone()),
        AdmissionOperationError::Unavailable(
            "injected operation creation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_create,
        Err(AdmissionOperationError::Unavailable(_))
    ));
    drop(create_store);
    inventory.response_lost("operation.create_prepared");

    let reopened_create = SqliteSecurityAdmissionOperationStore::open(&operation_path).test_unwrap();
    let created = reopened_create
        .load(&operation_id)
        .test_unwrap()
        .test_unwrap();
    assert!(matches!(
        reopened_create.create_prepared(prepared).test_unwrap(),
        AdmissionOperationCreateOutcome::Existing(existing) if existing == created
    ));
    drop(reopened_create);
    inventory.recovered("operation.create_prepared");

    let before_attempt = SqliteAttemptStore::open(&attempt_path).test_unwrap();
    assert_eq!(
        before_attempt
            .load_attempt(&registration.ids.attempt_id)
            .test_unwrap(),
        None
    );
    inventory.before("attempt.register", || {
        before_attempt.register_intent(&registration, 100)
    });
    drop(before_attempt);
    let attempt_store = SqliteAttemptStore::open(&attempt_path).test_unwrap();
    let lost_attempt = lose_response_after_commit(
        || attempt_store.register_intent(&registration, 100),
        BrokerError::AuthorityUnavailable(
            "injected broker registration acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_attempt,
        Err(BrokerError::AuthorityUnavailable(_))
    ));
    drop(attempt_store);
    inventory.response_lost("attempt.register");
    let reopened_attempt = SqliteAttemptStore::open(&attempt_path).test_unwrap();
    let inserted_attempt = reopened_attempt
        .load_attempt(&registration.ids.attempt_id)
        .test_unwrap()
        .test_unwrap();
    assert!(matches!(
        reopened_attempt
            .register_intent(&registration, 101)
            .test_unwrap(),
        RegisterAttemptOutcome::ExactRetry(exact) if exact == inserted_attempt
    ));
    inventory.recovered("attempt.register");

    let mut durable_operation = recover_operation_state_after_lost_response(
        &operation_path,
        &created,
        AdmissionOperationState::BrokerAttemptRegistered,
        AdmissionDispatchState::NotStarted,
        "operation.cas.broker_attempt_registered",
        &mut inventory,
    );

    let authorize_request = authorize_input_with_binding(
        "leaf",
        "hold-1",
        "authorize-1",
        &operation_id,
        &request_binding_hash,
    );
    let before_authorize = SqliteBudgetStore::open(&budget_path).test_unwrap();
    assert_eq!(
        before_authorize
            .query_composite_authorization("authorize-1")
            .test_unwrap(),
        None
    );
    assert_eq!(
        before_authorize
            .query_composite_authorization_input("authorize-1")
            .test_unwrap(),
        None
    );
    inventory.before("budget.authorize_composite_hold", || {
        before_authorize.authorize_composite_hold(authorize_request.clone())
    });
    drop(before_authorize);
    let authorize_store = SqliteBudgetStore::open(&budget_path).test_unwrap();
    let lost_authorize = lose_response_after_commit(
        || authorize_store.authorize_composite_hold(authorize_request.clone()),
        BudgetStoreError::Invariant(
            "injected budget authorization acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_authorize,
        Err(BudgetStoreError::Invariant(_))
    ));
    drop(authorize_store);
    inventory.response_lost("budget.authorize_composite_hold");
    let reopened_authorize = SqliteBudgetStore::open(&budget_path).test_unwrap();
    let recovered_authorize = reopened_authorize
        .query_composite_authorization("authorize-1")
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        reopened_authorize
            .authorize_composite_hold(authorize_request)
            .test_unwrap(),
        recovered_authorize
    );
    assert_eq!(quota_counts(&budget_path), (1, 0));
    inventory.recovered("budget.authorize_composite_hold");

    durable_operation = recover_operation_state_after_lost_response(
        &operation_path,
        &durable_operation,
        AdmissionOperationState::BudgetAuthorized,
        AdmissionDispatchState::NotStarted,
        "operation.cas.budget_authorized",
        &mut inventory,
    );
    durable_operation = recover_operation_state_after_lost_response(
        &operation_path,
        &durable_operation,
        AdmissionOperationState::DelegatedBudgetReserved,
        AdmissionDispatchState::NotStarted,
        "operation.cas.delegated_budget_reserved",
        &mut inventory,
    );

    let payment_request = PaymentAuthorizeRequest {
        operation_id: Some(operation_id.clone()),
        request_binding_hash: Some(request_binding_hash.clone()),
        amount_units: 100,
        currency: "USD".to_string(),
        payer: "payer-crash-matrix".to_string(),
        payee: "payee-crash-matrix".to_string(),
        reference: "request-admission".to_string(),
        governed: None,
        commerce: None,
    };
    let payment = SimPaymentAdapter::new();
    assert_eq!(
        payment
            .lookup_authorization_for_operation(&operation_id, &request_binding_hash)
            .test_unwrap(),
        None
    );
    inventory.before("payment.authorize_for_operation", || {
        payment.authorize_for_operation(&operation_id, &request_binding_hash, &payment_request)
    });
    let payment_recovery = payment.clone();
    let lost_payment_authorize = lose_response_after_commit(
        || payment.authorize_for_operation(&operation_id, &request_binding_hash, &payment_request),
        PaymentError::Unavailable(
            "injected payment authorization acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_payment_authorize,
        Err(PaymentError::Unavailable(_))
    ));
    drop(payment);
    inventory.response_lost("payment.authorize_for_operation");
    let recovered_payment_authorization = payment_recovery
        .lookup_authorization_for_operation(&operation_id, &request_binding_hash)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        payment_recovery
            .authorize_for_operation(&operation_id, &request_binding_hash, &payment_request)
            .test_unwrap(),
        recovered_payment_authorization
    );
    assert_eq!(
        payment_recovery
            .settlement_state_for_operation(
                &operation_id,
                &request_binding_hash,
                &payment_request.reference,
                Some(&recovered_payment_authorization.authorization_id),
            )
            .test_unwrap(),
        RailSettlementState::Held {
            authorization_id: recovered_payment_authorization.authorization_id.clone(),
        }
    );
    inventory.recovered("payment.authorize_for_operation");

    durable_operation = recover_operation_state_after_lost_response(
        &operation_path,
        &durable_operation,
        AdmissionOperationState::PaymentAuthorized,
        AdmissionDispatchState::NotStarted,
        "operation.cas.payment_authorized",
        &mut inventory,
    );

    let approval_set = ApprovalSetReservationInput::new(
        "44".repeat(32),
        vec![
            ApprovalReservationMember::new("threshold-token-crash".to_string(), "66".repeat(32))
                .test_unwrap(),
        ],
        unix_now().saturating_add(1_000),
    )
    .test_unwrap();
    let before_approval = SqliteApprovalStore::open(&approval_path).test_unwrap();
    assert_eq!(
        before_approval
            .get_approval_reservation(&operation_id)
            .test_unwrap(),
        None
    );
    inventory.before("approval.reserve_approval_set", || {
        before_approval.reserve_approval_set(&operation_id, &approval_set)
    });
    drop(before_approval);
    let approval_store = SqliteApprovalStore::open(&approval_path).test_unwrap();
    let lost_approval = lose_response_after_commit(
        || approval_store.reserve_approval_set(&operation_id, &approval_set),
        ApprovalStoreError::Backend(
            "injected approval reservation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(lost_approval, Err(ApprovalStoreError::Backend(_))));
    drop(approval_store);
    inventory.response_lost("approval.reserve_approval_set");
    let reopened_approval = SqliteApprovalStore::open(&approval_path).test_unwrap();
    let recovered_approval = reopened_approval
        .get_approval_reservation(&operation_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(recovered_approval.state(), ReplayReservationState::Reserved);
    assert_eq!(
        reopened_approval
            .reserve_approval_set(&operation_id, &approval_set)
            .test_unwrap(),
        recovered_approval
    );
    inventory.recovered("approval.reserve_approval_set");

    durable_operation = recover_operation_state_after_lost_response(
        &operation_path,
        &durable_operation,
        AdmissionOperationState::ApprovalReserved,
        AdmissionDispatchState::NotStarted,
        "operation.cas.approval_reserved",
        &mut inventory,
    );

    let nonce_expires_at = i64::try_from(unix_now().saturating_add(1_000)).test_unwrap();
    let before_nonce = SqliteExecutionNonceStore::open(&nonce_path).test_unwrap();
    assert_eq!(
        before_nonce
            .get_nonce_reservation(&operation_id)
            .test_unwrap(),
        None
    );
    inventory.before("nonce.reserve_nonce_for_operation", || {
        before_nonce.reserve_nonce_for_operation(&operation_id, "nonce-1", nonce_expires_at)
    });
    drop(before_nonce);
    let nonce_store = SqliteExecutionNonceStore::open(&nonce_path).test_unwrap();
    let lost_nonce = lose_response_after_commit(
        || nonce_store.reserve_nonce_for_operation(&operation_id, "nonce-1", nonce_expires_at),
        ExecutionNonceReservationError::Store(
            "injected nonce reservation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_nonce,
        Err(ExecutionNonceReservationError::Store(_))
    ));
    drop(nonce_store);
    inventory.response_lost("nonce.reserve_nonce_for_operation");
    let reopened_nonce = SqliteExecutionNonceStore::open(&nonce_path).test_unwrap();
    let recovered_nonce = reopened_nonce
        .get_nonce_reservation(&operation_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(recovered_nonce.state(), ReplayReservationState::Reserved);
    assert_eq!(
        reopened_nonce
            .reserve_nonce_for_operation(&operation_id, "nonce-1", nonce_expires_at)
            .test_unwrap(),
        recovered_nonce
    );
    inventory.recovered("nonce.reserve_nonce_for_operation");

    durable_operation = recover_operation_state_after_lost_response(
        &operation_path,
        &durable_operation,
        AdmissionOperationState::ReadyToDispatch,
        AdmissionDispatchState::NotStarted,
        "operation.cas.ready_to_dispatch",
        &mut inventory,
    );
    durable_operation = recover_operation_state_after_lost_response(
        &operation_path,
        &durable_operation,
        AdmissionOperationState::CapturePending,
        AdmissionDispatchState::NotStarted,
        "operation.cas.capture_pending",
        &mut inventory,
    );

    let approval_commit_store = SqliteApprovalStore::open(&approval_path).test_unwrap();
    assert_eq!(
        approval_commit_store
            .get_approval_reservation(&operation_id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        ReplayReservationState::Reserved
    );
    inventory.before("approval.commit_approval_reservation", || {
        approval_commit_store.commit_approval_reservation(&operation_id)
    });
    let lost_approval_commit = lose_response_after_commit(
        || approval_commit_store.commit_approval_reservation(&operation_id),
        ApprovalStoreError::Backend("injected approval commit acknowledgement loss".to_string()),
    );
    assert!(matches!(
        lost_approval_commit,
        Err(ApprovalStoreError::Backend(_))
    ));
    drop(approval_commit_store);
    inventory.response_lost("approval.commit_approval_reservation");
    let reopened_approval_commit = SqliteApprovalStore::open(&approval_path).test_unwrap();
    let recovered_approval_commit = reopened_approval_commit
        .get_approval_reservation(&operation_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        recovered_approval_commit.state(),
        ReplayReservationState::Committed
    );
    assert_eq!(
        reopened_approval_commit
            .commit_approval_reservation(&operation_id)
            .test_unwrap(),
        recovered_approval_commit
    );
    inventory.recovered("approval.commit_approval_reservation");

    let nonce_commit_store = SqliteExecutionNonceStore::open(&nonce_path).test_unwrap();
    assert_eq!(
        nonce_commit_store
            .get_nonce_reservation(&operation_id)
            .test_unwrap()
            .test_unwrap()
            .state(),
        ReplayReservationState::Reserved
    );
    inventory.before("nonce.commit_nonce_reservation", || {
        nonce_commit_store.commit_nonce_reservation(&operation_id)
    });
    let lost_nonce_commit = lose_response_after_commit(
        || nonce_commit_store.commit_nonce_reservation(&operation_id),
        ExecutionNonceReservationError::Store(
            "injected nonce commit acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_nonce_commit,
        Err(ExecutionNonceReservationError::Store(_))
    ));
    drop(nonce_commit_store);
    inventory.response_lost("nonce.commit_nonce_reservation");
    let reopened_nonce_commit = SqliteExecutionNonceStore::open(&nonce_path).test_unwrap();
    let recovered_nonce_commit = reopened_nonce_commit
        .get_nonce_reservation(&operation_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        recovered_nonce_commit.state(),
        ReplayReservationState::Committed
    );
    assert_eq!(
        reopened_nonce_commit
            .commit_nonce_reservation(&operation_id)
            .test_unwrap(),
        recovered_nonce_commit
    );
    inventory.recovered("nonce.commit_nonce_reservation");

    let capture_request = admission_capture_request(&operation_id, &request_binding_hash, None);
    let before_capture = SqliteAdmissionCaptureAuthority::open(&budget_path).test_unwrap();
    assert_eq!(
        before_capture
            .query_admission_capture(&capture_request)
            .test_unwrap(),
        None
    );
    inventory.before("combined.capture_admission", || {
        before_capture.capture_admission(capture_request.clone())
    });
    drop(before_capture);
    let capture_authority = SqliteAdmissionCaptureAuthority::open(&budget_path).test_unwrap();
    let lost_capture = lose_response_after_commit(
        || capture_authority.capture_admission(capture_request.clone()),
        AdmissionCaptureError::Unavailable(
            "injected combined capture acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_capture,
        Err(AdmissionCaptureError::Unavailable(_))
    ));
    drop(capture_authority);
    inventory.response_lost("combined.capture_admission");
    let reopened_capture = SqliteAdmissionCaptureAuthority::open(&budget_path).test_unwrap();
    let recovered_capture = reopened_capture
        .query_admission_capture(&capture_request)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        reopened_capture
            .capture_admission(capture_request)
            .test_unwrap(),
        recovered_capture
    );
    let AdmissionCaptureDecision::Captured { budget, .. } = recovered_capture else {
        panic!("combined admission capture must survive acknowledgement loss");
    };
    assert_eq!(
        budget.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    assert_eq!(quota_counts(&budget_path), (0, 1));
    inventory.recovered("combined.capture_admission");

    durable_operation = recover_operation_state_after_lost_response(
        &operation_path,
        &durable_operation,
        AdmissionOperationState::DispatchCommitted,
        AdmissionDispatchState::Committed,
        "operation.cas.dispatch_committed",
        &mut inventory,
    );

    let payment_capture_request = || OperationPaymentCaptureRequest {
        operation_id: &operation_id,
        request_binding_hash: &request_binding_hash,
        authorization_id: &recovered_payment_authorization.authorization_id,
        amount_units: 25,
        currency: &payment_request.currency,
        reference: &payment_request.reference,
    };
    inventory.before("payment.capture_for_operation", || {
        payment_recovery.capture_for_operation(payment_capture_request())
    });
    let payment_after_client_restart = payment_recovery.clone();
    let lost_payment_capture = lose_response_after_commit(
        || payment_recovery.capture_for_operation(payment_capture_request()),
        PaymentError::Unavailable("injected payment capture acknowledgement loss".to_string()),
    );
    assert!(matches!(
        lost_payment_capture,
        Err(PaymentError::Unavailable(_))
    ));
    drop(payment_recovery);
    inventory.response_lost("payment.capture_for_operation");
    let recovered_payment_capture = payment_after_client_restart
        .capture_for_operation(payment_capture_request())
        .test_unwrap();
    assert!(matches!(
        payment_after_client_restart
            .settlement_state_for_operation(
                &operation_id,
                &request_binding_hash,
                &payment_request.reference,
                Some(&recovered_payment_authorization.authorization_id),
            )
            .test_unwrap(),
        RailSettlementState::Settled { ref authorization_id, ref result }
            if authorization_id == &recovered_payment_authorization.authorization_id
                && result == &recovered_payment_capture
    ));
    inventory.recovered("payment.capture_for_operation");

    let admission_binding =
        BudgetAdmissionOperationBinding::new(operation_id.clone(), request_binding_hash.clone())
            .test_unwrap();
    let reconcile_request = BudgetReconcileHoldRequest {
        capability_id: "leaf".to_string(),
        grant_index: 0,
        exposed_cost_units: 100,
        realized_spend_units: 25,
        hold_id: Some("hold-1".to_string()),
        event_id: Some("reconcile-crash-matrix".to_string()),
        authority: None,
        admission_operation: Some(admission_binding),
    };
    let reconcile_store = SqliteBudgetStore::open(&budget_path).test_unwrap();
    inventory.before("budget.reconcile_budget_hold", || {
        reconcile_store.reconcile_budget_hold(reconcile_request.clone())
    });
    let lost_reconcile = lose_response_after_commit(
        || reconcile_store.reconcile_budget_hold(reconcile_request.clone()),
        BudgetStoreError::Invariant(
            "injected budget reconciliation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_reconcile,
        Err(BudgetStoreError::Invariant(_))
    ));
    drop(reconcile_store);
    inventory.response_lost("budget.reconcile_budget_hold");
    let reopened_reconcile = SqliteBudgetStore::open(&budget_path).test_unwrap();
    let recovered_reconcile = reopened_reconcile
        .reconcile_budget_hold(reconcile_request.clone())
        .test_unwrap();
    assert_eq!(
        reopened_reconcile
            .reconcile_budget_hold(reconcile_request)
            .test_unwrap(),
        recovered_reconcile
    );
    assert_eq!(
        recovered_reconcile.invocation_state,
        BudgetInvocationReservationState::Captured
    );
    inventory.recovered("budget.reconcile_budget_hold");

    durable_operation = recover_terminal_operation_after_lost_response(
        &operation_path,
        &terminal_receipt_path,
        &durable_operation,
        &terminal_signer,
        &mut inventory,
    );
    assert_eq!(
        durable_operation.state(),
        AdmissionOperationState::Completed
    );

    let cancel_operation_id = "77".repeat(32);
    let cancel_nonce_id = "nonce-cancel-crash";
    let cancel_nonce_store = SqliteExecutionNonceStore::open(&nonce_path).test_unwrap();
    assert_eq!(
        cancel_nonce_store
            .get_nonce_reservation(&cancel_operation_id)
            .test_unwrap(),
        None
    );
    inventory.before("nonce.reserve_cancel_path", || {
        cancel_nonce_store.reserve_nonce_for_operation(
            &cancel_operation_id,
            cancel_nonce_id,
            nonce_expires_at,
        )
    });
    let lost_cancel_reserve = lose_response_after_commit(
        || {
            cancel_nonce_store.reserve_nonce_for_operation(
                &cancel_operation_id,
                cancel_nonce_id,
                nonce_expires_at,
            )
        },
        ExecutionNonceReservationError::Store(
            "injected cancel-path nonce reservation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_cancel_reserve,
        Err(ExecutionNonceReservationError::Store(_))
    ));
    drop(cancel_nonce_store);
    inventory.response_lost("nonce.reserve_cancel_path");
    let reopened_cancel_nonce = SqliteExecutionNonceStore::open(&nonce_path).test_unwrap();
    let recovered_cancel_reserve = reopened_cancel_nonce
        .get_nonce_reservation(&cancel_operation_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        reopened_cancel_nonce
            .reserve_nonce_for_operation(&cancel_operation_id, cancel_nonce_id, nonce_expires_at,)
            .test_unwrap(),
        recovered_cancel_reserve
    );
    inventory.recovered("nonce.reserve_cancel_path");

    inventory.before("nonce.cancel_nonce_reservation", || {
        reopened_cancel_nonce.cancel_nonce_reservation(&cancel_operation_id)
    });
    let lost_cancel = lose_response_after_commit(
        || reopened_cancel_nonce.cancel_nonce_reservation(&cancel_operation_id),
        ExecutionNonceReservationError::Store(
            "injected nonce cancellation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_cancel,
        Err(ExecutionNonceReservationError::Store(_))
    ));
    drop(reopened_cancel_nonce);
    inventory.response_lost("nonce.cancel_nonce_reservation");
    let reopened_cancelled_nonce = SqliteExecutionNonceStore::open(&nonce_path).test_unwrap();
    let recovered_cancel = reopened_cancelled_nonce
        .get_nonce_reservation(&cancel_operation_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(recovered_cancel.state(), ReplayReservationState::Cancelled);
    assert_eq!(
        reopened_cancelled_nonce
            .cancel_nonce_reservation(&cancel_operation_id)
            .test_unwrap(),
        recovered_cancel
    );
    inventory.recovered("nonce.cancel_nonce_reservation");

    let cancel_approval_operation_id = "78".repeat(32);
    let cancel_approval_set = ApprovalSetReservationInput::new(
        "aa".repeat(32),
        vec![ApprovalReservationMember::new(
            "threshold-token-cancel-crash".to_string(),
            "bb".repeat(32),
        )
        .test_unwrap()],
        unix_now().saturating_add(1_000),
    )
    .test_unwrap();
    let before_cancel_approval = SqliteApprovalStore::open(&approval_path).test_unwrap();
    assert_eq!(
        before_cancel_approval
            .get_approval_reservation(&cancel_approval_operation_id)
            .test_unwrap(),
        None
    );
    inventory.before("approval.reserve_cancel_path", || {
        before_cancel_approval
            .reserve_approval_set(&cancel_approval_operation_id, &cancel_approval_set)
    });
    drop(before_cancel_approval);
    let cancel_approval_store = SqliteApprovalStore::open(&approval_path).test_unwrap();
    let lost_cancel_approval_reserve = lose_response_after_commit(
        || {
            cancel_approval_store
                .reserve_approval_set(&cancel_approval_operation_id, &cancel_approval_set)
        },
        ApprovalStoreError::Backend(
            "injected cancel-path approval reservation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_cancel_approval_reserve,
        Err(ApprovalStoreError::Backend(_))
    ));
    drop(cancel_approval_store);
    inventory.response_lost("approval.reserve_cancel_path");
    let reopened_cancel_approval = SqliteApprovalStore::open(&approval_path).test_unwrap();
    let recovered_cancel_approval_reserve = reopened_cancel_approval
        .get_approval_reservation(&cancel_approval_operation_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        recovered_cancel_approval_reserve.state(),
        ReplayReservationState::Reserved
    );
    assert_eq!(
        reopened_cancel_approval
            .reserve_approval_set(&cancel_approval_operation_id, &cancel_approval_set)
            .test_unwrap(),
        recovered_cancel_approval_reserve
    );
    inventory.recovered("approval.reserve_cancel_path");

    inventory.before("approval.cancel_approval_reservation", || {
        reopened_cancel_approval.cancel_approval_reservation(&cancel_approval_operation_id)
    });
    let lost_cancel_approval = lose_response_after_commit(
        || reopened_cancel_approval.cancel_approval_reservation(&cancel_approval_operation_id),
        ApprovalStoreError::Backend(
            "injected approval cancellation acknowledgement loss".to_string(),
        ),
    );
    assert!(matches!(
        lost_cancel_approval,
        Err(ApprovalStoreError::Backend(_))
    ));
    drop(reopened_cancel_approval);
    inventory.response_lost("approval.cancel_approval_reservation");
    let reopened_cancelled_approval = SqliteApprovalStore::open(&approval_path).test_unwrap();
    let recovered_cancel_approval = reopened_cancelled_approval
        .get_approval_reservation(&cancel_approval_operation_id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        recovered_cancel_approval.state(),
        ReplayReservationState::Cancelled
    );
    assert_eq!(
        reopened_cancelled_approval
            .cancel_approval_reservation(&cancel_approval_operation_id)
            .test_unwrap(),
        recovered_cancel_approval
    );
    inventory.recovered("approval.cancel_approval_reservation");

    let revocation_record = RevocationRecord {
        capability_id: "crash-matrix-revocation".to_string(),
        revoked_at: 100,
    };
    let before_revocation = SqliteAdmissionCaptureAuthority::open(&revocation_path).test_unwrap();
    assert_eq!(before_revocation.revocation_head().test_unwrap(), 0);
    assert!(before_revocation
        .broker_revocation_snapshot(&[revocation_record.capability_id.clone()])
        .test_unwrap()
        .revoked_ids()
        .is_empty());
    drop(before_revocation);
    let revocation_authority =
        SqliteAdmissionCaptureAuthority::open(&revocation_path).test_unwrap();
    inventory.before("combined.upsert_revocation", || {
        revocation_authority.upsert_revocation(&revocation_record)
    });
    let lost_revocation = lose_response_after_commit(
        || revocation_authority.upsert_revocation(&revocation_record),
        RevocationStoreError::Sync("injected revocation acknowledgement loss".to_string()),
    );
    assert!(matches!(
        lost_revocation,
        Err(RevocationStoreError::Sync(_))
    ));
    drop(revocation_authority);
    inventory.response_lost("combined.upsert_revocation");
    let reopened_revocation = SqliteAdmissionCaptureAuthority::open(&revocation_path).test_unwrap();
    assert_eq!(reopened_revocation.revocation_head().test_unwrap(), 1);
    assert_eq!(
        reopened_revocation
            .broker_revocation_snapshot(&[revocation_record.capability_id.clone()])
            .test_unwrap()
            .revoked_ids(),
        &[revocation_record.capability_id.clone()]
    );
    let recovered_revocation = reopened_revocation
        .upsert_revocation(&revocation_record)
        .test_unwrap();
    assert!(recovered_revocation.changed());
    assert_eq!(recovered_revocation.revocation_commit_index(), 1);
    assert_eq!(reopened_revocation.revocation_head().test_unwrap(), 1);
    inventory.recovered("combined.upsert_revocation");

    let reverse_operation_id = "89".repeat(32);
    let reverse_binding_hash = "9a".repeat(32);
    let reverse_authorize = authorize_input_with_binding(
        "reverse-leaf",
        "reverse-hold",
        "reverse-authorize",
        &reverse_operation_id,
        &reverse_binding_hash,
    );
    let reverse_setup = SqliteBudgetStore::open(&reverse_budget_path).test_unwrap();
    assert!(reverse_setup
        .authorize_composite_hold(reverse_authorize)
        .test_unwrap()
        .is_authorized());
    assert_eq!(
        quota_counts_for_owner(&reverse_budget_path, "reverse-leaf"),
        (1, 0)
    );
    drop(reverse_setup);
    let reverse_request = BudgetReverseHoldRequest {
        capability_id: "reverse-leaf".to_string(),
        grant_index: 0,
        reversed_exposure_units: 100,
        hold_id: Some("reverse-hold".to_string()),
        event_id: Some("reverse-crash-matrix".to_string()),
        authority: None,
        admission_operation: Some(
            BudgetAdmissionOperationBinding::new(
                reverse_operation_id.clone(),
                reverse_binding_hash.clone(),
            )
            .test_unwrap(),
        ),
    };
    let reverse_store = SqliteBudgetStore::open(&reverse_budget_path).test_unwrap();
    inventory.before("budget.reverse_budget_hold", || {
        reverse_store.reverse_budget_hold(reverse_request.clone())
    });
    let lost_budget_reverse = lose_response_after_commit(
        || reverse_store.reverse_budget_hold(reverse_request.clone()),
        BudgetStoreError::Invariant("injected budget reverse acknowledgement loss".to_string()),
    );
    assert!(matches!(
        lost_budget_reverse,
        Err(BudgetStoreError::Invariant(_))
    ));
    drop(reverse_store);
    inventory.response_lost("budget.reverse_budget_hold");
    let reopened_reverse = SqliteBudgetStore::open(&reverse_budget_path).test_unwrap();
    let recovered_budget_reverse = reopened_reverse
        .reverse_budget_hold(reverse_request.clone())
        .test_unwrap();
    assert_eq!(
        reopened_reverse
            .reverse_budget_hold(reverse_request)
            .test_unwrap(),
        recovered_budget_reverse
    );
    assert_eq!(
        recovered_budget_reverse.invocation_state,
        BudgetInvocationReservationState::Reversed
    );
    assert_eq!(
        quota_counts_for_owner(&reverse_budget_path, "reverse-leaf"),
        (0, 0)
    );
    inventory.recovered("budget.reverse_budget_hold");

    let release_operation_id = "88".repeat(32);
    let release_binding_hash = "99".repeat(32);
    let release_authorize = authorize_input_with_binding(
        "release-leaf",
        "release-hold",
        "release-authorize",
        &release_operation_id,
        &release_binding_hash,
    );
    let release_setup = SqliteBudgetStore::open(&release_budget_path).test_unwrap();
    assert!(release_setup
        .authorize_composite_hold(release_authorize)
        .test_unwrap()
        .is_authorized());
    drop(release_setup);
    let release_request = BudgetReleaseHoldRequest {
        capability_id: "release-leaf".to_string(),
        grant_index: 0,
        released_exposure_units: 100,
        hold_id: Some("release-hold".to_string()),
        event_id: Some("release-crash-matrix".to_string()),
        authority: None,
        admission_operation: Some(
            BudgetAdmissionOperationBinding::new(
                release_operation_id.clone(),
                release_binding_hash.clone(),
            )
            .test_unwrap(),
        ),
    };
    let release_store = SqliteBudgetStore::open(&release_budget_path).test_unwrap();
    inventory.before("budget.release_budget_hold", || {
        release_store.release_budget_hold(release_request.clone())
    });
    let lost_budget_release = lose_response_after_commit(
        || release_store.release_budget_hold(release_request.clone()),
        BudgetStoreError::Invariant("injected budget release acknowledgement loss".to_string()),
    );
    assert!(matches!(
        lost_budget_release,
        Err(BudgetStoreError::Invariant(_))
    ));
    drop(release_store);
    inventory.response_lost("budget.release_budget_hold");
    let reopened_release = SqliteBudgetStore::open(&release_budget_path).test_unwrap();
    let recovered_budget_release = reopened_release
        .release_budget_hold(release_request.clone())
        .test_unwrap();
    assert_eq!(
        reopened_release
            .release_budget_hold(release_request)
            .test_unwrap(),
        recovered_budget_release
    );
    inventory.recovered("budget.release_budget_hold");

    let rail_release_operation_id = "aa".repeat(32);
    let rail_release_binding_hash = "bb".repeat(32);
    let rail_release_request = PaymentAuthorizeRequest {
        operation_id: Some(rail_release_operation_id.clone()),
        request_binding_hash: Some(rail_release_binding_hash.clone()),
        amount_units: 50,
        currency: "USD".to_string(),
        payer: "payer-release".to_string(),
        payee: "payee-release".to_string(),
        reference: "release-reference".to_string(),
        governed: None,
        commerce: None,
    };
    let release_payment = SimPaymentAdapter::new();
    let release_authorization = release_payment
        .authorize_for_operation(
            &rail_release_operation_id,
            &rail_release_binding_hash,
            &rail_release_request,
        )
        .test_unwrap();
    assert!(matches!(
        release_payment
            .settlement_state_for_operation(
                &rail_release_operation_id,
                &rail_release_binding_hash,
                &rail_release_request.reference,
                Some(&release_authorization.authorization_id),
            )
            .test_unwrap(),
        RailSettlementState::Held { .. }
    ));
    let release_payment_recovery = release_payment.clone();
    inventory.before("payment.release_for_operation", || {
        release_payment.release_for_operation(
            &rail_release_operation_id,
            &rail_release_binding_hash,
            &release_authorization.authorization_id,
            &rail_release_request.reference,
        )
    });
    let lost_payment_release = lose_response_after_commit(
        || {
            release_payment.release_for_operation(
                &rail_release_operation_id,
                &rail_release_binding_hash,
                &release_authorization.authorization_id,
                &rail_release_request.reference,
            )
        },
        PaymentError::Unavailable("injected payment release acknowledgement loss".to_string()),
    );
    assert!(matches!(
        lost_payment_release,
        Err(PaymentError::Unavailable(_))
    ));
    drop(release_payment);
    inventory.response_lost("payment.release_for_operation");
    let recovered_payment_release = release_payment_recovery
        .release_for_operation(
            &rail_release_operation_id,
            &rail_release_binding_hash,
            &release_authorization.authorization_id,
            &rail_release_request.reference,
        )
        .test_unwrap();
    assert_eq!(
        release_payment_recovery
            .release_for_operation(
                &rail_release_operation_id,
                &rail_release_binding_hash,
                &release_authorization.authorization_id,
                &rail_release_request.reference,
            )
            .test_unwrap(),
        recovered_payment_release
    );
    assert_eq!(
        release_payment_recovery
            .settlement_state_for_operation(
                &rail_release_operation_id,
                &rail_release_binding_hash,
                &rail_release_request.reference,
                Some(&release_authorization.authorization_id),
            )
            .test_unwrap(),
        RailSettlementState::NoAuthorization
    );
    inventory.recovered("payment.release_for_operation");

    let receipt = standalone_crash_matrix_receipt();
    let before_receipt = SqliteReceiptStore::open(&receipt_path).test_unwrap();
    assert_eq!(before_receipt.tool_receipt_count().test_unwrap(), 0);
    assert!(
        before_receipt
            .load_chio_receipt(&receipt.id)
            .test_unwrap()
            .is_none()
    );
    drop(before_receipt);
    let receipt_store = SqliteReceiptStore::open(&receipt_path).test_unwrap();
    inventory.before("receipt.append_chio_receipt", || {
        ReceiptStore::append_chio_receipt_with_timeout(
            &receipt_store,
            &receipt,
            std::time::Duration::from_secs(5),
        )
    });
    let lost_receipt = lose_response_after_commit(
        || {
            ReceiptStore::append_chio_receipt_with_timeout(
                &receipt_store,
                &receipt,
                std::time::Duration::from_secs(5),
            )
        },
        ReceiptStoreError::Timeout {
            operation: "append_chio_receipt".to_string(),
            timeout_ms: 5_000,
        },
    );
    assert!(matches!(
        lost_receipt,
        Err(ReceiptStoreError::Timeout { .. })
    ));
    drop(receipt_store);
    inventory.response_lost("receipt.append_chio_receipt");
    let reopened_receipt = SqliteReceiptStore::open(&receipt_path).test_unwrap();
    let recovered_receipt = reopened_receipt
        .load_chio_receipt(&receipt.id)
        .test_unwrap()
        .test_unwrap();
    assert_eq!(
        chio_core::canonical::canonical_json_bytes(&recovered_receipt).test_unwrap(),
        chio_core::canonical::canonical_json_bytes(&receipt).test_unwrap()
    );
    let committed_receipt_seq = ReceiptStore::append_chio_receipt_with_timeout(
        &reopened_receipt,
        &receipt,
        std::time::Duration::from_secs(5),
    )
    .test_unwrap()
    .test_unwrap();
    assert!(committed_receipt_seq > 0);
    assert_eq!(reopened_receipt.tool_receipt_count().test_unwrap(), 1);
    inventory.recovered("receipt.append_chio_receipt");

    inventory.assert_complete();
}

fn broker_registration(
    invocation_id: &str,
    request_digest: String,
    proof_nonce: &str,
) -> AttemptRegistration {
    AttemptRegistration {
        ids: derive_attempt_ids(
            "broker-capability",
            invocation_id,
            proof_nonce,
            &request_digest,
        )
        .test_unwrap(),
        invocation_id: invocation_id.to_string(),
        parent_capability_id: "leaf".to_string(),
        broker_capability_id: "broker-capability".to_string(),
        request_canonical_digest: request_digest.clone(),
        request_digest,
        proof_digest: "22".repeat(32),
        proof_key_id: "proof-key-1".to_string(),
        proof_nonce: proof_nonce.to_string(),
        nonce_expires_at_unix_seconds: 200,
        quotas: vec![ExecutionQuota {
            key_id: "broker-quota-1".to_string(),
            maximum_executions: 2,
        }],
        authority_metadata_digest: "33".repeat(32),
        revocation_authority_domain: "combined-authority".to_string(),
    }
}

#[test]
fn broker_attempt_ack_recovery_consumes_nonce_before_budget_authority() {
    let directory = tempfile::tempdir().test_unwrap();
    let directory_path = std::fs::canonicalize(directory.path()).test_unwrap();
    let attempt_path = directory_path.join("attempts.sqlite3");
    let budget_path = directory_path.join("budget.sqlite3");
    let registration =
        broker_registration("invocation-1", "11".repeat(32), "proof-nonce-abcdefghijkl");

    let before_registration = SqliteAttemptStore::open(&attempt_path).test_unwrap();
    assert_eq!(
        before_registration
            .load_attempt(&registration.ids.attempt_id)
            .test_unwrap(),
        None
    );
    drop(before_registration);

    let registration_store = SqliteAttemptStore::open(&attempt_path).test_unwrap();
    let RegisterAttemptOutcome::Inserted(inserted) = registration_store
        .register_attempt(&registration, 100)
        .test_unwrap()
    else {
        panic!("the first broker attempt registration must insert durable state");
    };
    drop(registration_store);
    let reopened = SqliteAttemptStore::open(&attempt_path).test_unwrap();
    assert_eq!(
        reopened
            .load_attempt(&registration.ids.attempt_id)
            .test_unwrap(),
        Some(inserted.clone())
    );
    assert!(matches!(
        reopened.register_attempt(&registration, 101).test_unwrap(),
        RegisterAttemptOutcome::ExactRetry(exact_retry) if exact_retry == inserted
    ));

    let replay = broker_registration("invocation-2", "44".repeat(32), "proof-nonce-abcdefghijkl");
    assert!(matches!(
        reopened.register_attempt(&replay, 101),
        Err(BrokerError::AuthorizationDenied(_))
    ));

    let budget = SqliteBudgetStore::open(&budget_path).test_unwrap();
    assert!(budget
        .list_mutation_events(10, None, None)
        .test_unwrap()
        .is_empty());
    assert!(budget
        .authorize_composite_hold(authorize_input(
            "leaf",
            &registration.ids.hold_id,
            &registration.ids.authorize_event_id,
        ))
        .test_unwrap()
        .is_authorized());
    assert_eq!(
        budget
            .list_mutation_events(10, None, None)
            .test_unwrap()
            .len(),
        1
    );
}

fn active_response_intent_body() -> GovernedResponsePlanIntentBody {
    let canonical_plan_body = json!({
        "actionId": "action-1",
        "affectedSetHash": "a".repeat(64),
        "createdAt": 1_000,
        "expiresAt": 1_200,
        "policyVersion": "policy-7",
        "tenant": "tenant-1"
    });
    let plan_body_hash =
        GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body).test_unwrap();
    GovernedResponsePlanIntentBody::new(
        CHIO_RESPONSE_PLAN_SCHEMA,
        "action-1",
        "operator-capability-1",
        "b".repeat(64),
        1_300,
        Keypair::from_seed(&[21; 32]).public_key(),
        canonical_plan_body,
        plan_body_hash,
        json!({"affectedSetHash": "a".repeat(64), "tenant": "tenant-1"}),
        vec![GovernedResponseEffect::RestrictEgress],
        1_200,
        json!({"contributionId": "action-1", "mode": "remove_contribution"}),
    )
    .test_unwrap()
}

#[test]
fn active_response_intent_rejects_body_hash_mismatch_and_raw_hash_substitution() {
    let body = active_response_intent_body();
    let intent = GovernedTransactionIntent::active_response_plan(body.clone());
    assert_ne!(intent.binding_hash().test_unwrap(), body.plan_body_hash());

    let mut raw_hash = serde_json::to_value(&body).test_unwrap();
    raw_hash["canonicalPlanBody"] = json!("a".repeat(64));
    raw_hash["planBodyHash"] = json!("a".repeat(64));
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(raw_hash).is_err());

    let mut mismatched = serde_json::to_value(&body).test_unwrap();
    mismatched["canonicalPlanBody"]["tenant"] = json!("tenant-2");
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(mismatched).is_err());

    let mut embedded_hash = serde_json::to_value(&body).test_unwrap();
    embedded_hash["canonicalPlanBody"] = json!({"planHash": "a".repeat(64)});
    embedded_hash["planBodyHash"] = json!("a".repeat(64));
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(embedded_hash).is_err());

    let mut expired_binding = serde_json::to_value(&body).test_unwrap();
    expired_binding["expiresAt"] = json!(1_301);
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(expired_binding).is_err());
}

struct TestToolServer {
    server_id: String,
    tool_name: String,
    reported_cost: Option<ToolInvocationCost>,
    invocations: Option<Arc<AtomicUsize>>,
}

#[async_trait::async_trait]
impl ToolServerConnection for TestToolServer {
    fn server_id(&self) -> &str {
        &self.server_id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![self.tool_name.clone()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        if let Some(invocations) = self.invocations.as_ref() {
            invocations.fetch_add(1, Ordering::SeqCst);
        }
        Ok(json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, self.reported_cost.clone()))
    }
}

fn invoke_request(
    request_id: &str,
    capability: &CapabilityToken,
    tool: &str,
    server: &str,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

fn active_response_grant() -> ToolGrant {
    ToolGrant {
        server_id: CHIO_ACTIVE_RESPONSE_SERVER_ID.to_string(),
        tool_name: GovernedResponseEffect::RestrictEgress
            .tool_name()
            .to_string(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_secs()
}

#[test]
fn operator_scoped_capability_rejects_mutation_expiry_and_revocation() {
    let authority = Keypair::from_seed(&[31; 32]);
    let subject = Keypair::from_seed(&[32; 32]);
    let tool = GovernedResponseEffect::RestrictEgress.tool_name();
    let mut kernel = make_kernel(authority.clone());
    kernel.register_tool_server(Box::new(TestToolServer {
        server_id: CHIO_ACTIVE_RESPONSE_SERVER_ID.to_string(),
        tool_name: tool.to_string(),
        reported_cost: None,
        invocations: None,
    }));
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants: vec![active_response_grant()],
                ..ChioScope::default()
            },
            300,
        )
        .test_unwrap();

    let mut mutated = capability.clone();
    mutated.id.push_str("-mutated");
    let mutated_response = kernel
        .evaluate_tool_call_blocking(&invoke_request(
            "operator-mutated",
            &mutated,
            tool,
            CHIO_ACTIVE_RESPONSE_SERVER_ID,
        ))
        .test_unwrap();
    assert_eq!(mutated_response.verdict, Verdict::Deny);

    kernel.revoke_capability(&capability.id).test_unwrap();
    let revoked_response = kernel
        .evaluate_tool_call_blocking(&invoke_request(
            "operator-revoked",
            &capability,
            tool,
            CHIO_ACTIVE_RESPONSE_SERVER_ID,
        ))
        .test_unwrap();
    assert_eq!(revoked_response.verdict, Verdict::Deny);
    assert!(revoked_response
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("revoked"));

    let now = unix_now();
    let expired = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "expired-operator-capability".to_string(),
            issuer: authority.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![active_response_grant()],
                ..ChioScope::default()
            },
            issued_at: now.saturating_sub(2),
            expires_at: now.saturating_sub(1),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &authority,
    )
    .test_unwrap();
    let expired_response = kernel
        .evaluate_tool_call_blocking(&invoke_request(
            "operator-expired",
            &expired,
            tool,
            CHIO_ACTIVE_RESPONSE_SERVER_ID,
        ))
        .test_unwrap();
    assert_eq!(expired_response.verdict, Verdict::Deny);
    assert!(expired_response
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("expired"));
}

fn active_response_operation() -> AdmissionOperation {
    AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::GovernedActiveResponse,
        coordinator_authority_id: "response-executor-1".to_string(),
        request_id: "active-response-1".to_string(),
        capability_id: "operator-capability-1".to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: "22".repeat(32),
        policy_hash: "33".repeat(32),
        broker_attempt_id: None,
        budget_hold_id: None,
        approval_set_hash: Some("44".repeat(32)),
        execution_nonce_id: None,
        coordinator_lease_epoch: 9,
    })
    .test_unwrap()
}

#[test]
fn approval_only_admission_recovers_without_budget_or_nonce_participants() {
    let directory = tempfile::tempdir().test_unwrap();
    let operation_path = directory.path().join("response-admission.sqlite3");
    let budget_path = directory.path().join("unused-budget.sqlite3");
    let prepared = active_response_operation();
    assert!(prepared.budget_hold_id().is_none());
    assert!(prepared.execution_nonce_id().is_none());
    let operation_id = prepared.operation_id().to_string();
    let store = SqliteSecurityAdmissionOperationStore::open(&operation_path).test_unwrap();
    store.create_prepared(prepared).test_unwrap();
    let AdmissionOperationCasOutcome::Applied(reserved) = store
        .compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: &operation_id,
            expected_version: 0,
            coordinator_lease_epoch: 9,
            next_state: AdmissionOperationState::ApprovalReserved,
            next_dispatch_state: AdmissionDispatchState::NotStarted,
            next_coordinator_lease_epoch: 9,
            last_error: None,
        })
        .test_unwrap()
    else {
        panic!("approval reservation must persist");
    };
    drop(store);

    let reopened = SqliteSecurityAdmissionOperationStore::open(&operation_path).test_unwrap();
    assert_eq!(
        reopened.load(&operation_id).test_unwrap(),
        Some(reserved.clone())
    );
    let AdmissionOperationCasOutcome::Applied(committed) = reopened
        .compare_and_swap(AdmissionOperationCompareAndSwap {
            operation_id: &operation_id,
            expected_version: reserved.version(),
            coordinator_lease_epoch: 9,
            next_state: AdmissionOperationState::DispatchCommitted,
            next_dispatch_state: AdmissionDispatchState::Committed,
            next_coordinator_lease_epoch: 9,
            last_error: None,
        })
        .test_unwrap()
    else {
        panic!("response dispatch must commit once");
    };
    drop(reopened);

    let reopened = SqliteSecurityAdmissionOperationStore::open(&operation_path).test_unwrap();
    assert!(matches!(
        reopened
            .compare_and_swap(AdmissionOperationCompareAndSwap {
                operation_id: &operation_id,
                expected_version: reserved.version(),
                coordinator_lease_epoch: 9,
                next_state: AdmissionOperationState::DispatchCommitted,
                next_dispatch_state: AdmissionDispatchState::Committed,
                next_coordinator_lease_epoch: 9,
                last_error: None,
            })
            .test_unwrap(),
        AdmissionOperationCasOutcome::Conflict(current) if current == committed
    ));
    let terminal_request = || AdmissionOperationCompareAndSwap {
        operation_id: &operation_id,
        expected_version: committed.version(),
        coordinator_lease_epoch: 9,
        next_state: AdmissionOperationState::Completed,
        next_dispatch_state: AdmissionDispatchState::EffectCompleted,
        next_coordinator_lease_epoch: 9,
        last_error: None,
    };
    assert!(matches!(
        reopened.compare_and_swap(terminal_request()),
        Err(error) if error
            .to_string()
            .contains("terminal admission transitions require an atomic forward action")
    ));
    let terminal_action = AdmissionCleanupAction::pending(
        &committed,
        AdmissionCleanupActionKind::TerminalReceipt,
        &json!({"terminal": AdmissionOperationState::Completed.as_str()}),
    )
    .test_unwrap();
    let AdmissionOperationCasOutcome::Applied(completed) = reopened
        .compare_and_swap_with_cleanup_action(terminal_request(), terminal_action.clone())
        .test_unwrap()
    else {
        panic!("completion and terminal receipt outbox insert must apply atomically");
    };
    drop(reopened);
    let reopened = SqliteSecurityAdmissionOperationStore::open(&operation_path).test_unwrap();
    assert_eq!(reopened.load(&operation_id).test_unwrap(), Some(completed));
    assert_eq!(
        reopened.load_cleanup_actions(&operation_id).test_unwrap(),
        vec![terminal_action]
    );
    assert!(SqliteBudgetStore::open(&budget_path)
        .test_unwrap()
        .list_mutation_events(10, None, None)
        .test_unwrap()
        .is_empty());
}

#[test]
fn aggregate_authority_is_denied_when_the_feature_is_unnegotiated() {
    let issuer = Keypair::from_seed(&[41; 32]);
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "aggregate-unnegotiated".to_string(),
            issuer: issuer.public_key(),
            subject: Keypair::from_seed(&[42; 32]).public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: Some(AggregateInvocationBudget {
                scope: AggregateInvocationScope::Capability,
                max_invocations: 2,
                root_binding: None,
            }),
        },
        &issuer,
    )
    .test_unwrap();
    let peer = CapabilityNegotiation::t1_default();
    assert!(!peer.supports(AGGREGATE_INVOCATION_BUDGET));
    let trust_roots = |_issuer: &chio_core::PublicKey| None;
    let mut budgets = InMemoryBudgetRegistry::new();
    let error = verify_capability_full(
        &token,
        &[issuer.public_key()],
        &FixedClock::new(150),
        CapabilityCryptoFloor::AllowClassical,
        &peer,
        &trust_roots,
        &mut budgets,
    )
    .test_unwrap_err();
    assert_eq!(
        error,
        CapabilityError::AttenuationViolation(
            "aggregate invocation budget is not negotiated".to_string()
        )
    );
}

#[test]
fn verified_ca_root_family_budget_is_shared_across_distinct_kernels() {
    let directory =
        chio_test_support::private_fs::private_tempdir("chio-t2-family-").test_unwrap();
    let directory_path = std::fs::canonicalize(directory.path()).test_unwrap();
    let budget_path = directory_path.join("multi-kernel-budget.sqlite3");
    let operation_path = directory_path.join("multi-kernel-operations.sqlite3");
    let receipt_path = directory_path.join("multi-kernel-receipts.sqlite3");
    let fixture = LiveAggregateFamilyFixture::new("verified-family-root", 1, 71);
    let sibling_a = fixture.descendant("verified-family-sibling-a");
    let sibling_b = fixture.descendant("verified-family-sibling-b");
    let seed_receipts = SqliteReceiptStore::open(&receipt_path).test_unwrap();
    seed_receipts
        .record_capability_snapshot(&fixture.root_token, None)
        .test_unwrap();
    drop(seed_receipts);
    let external_invocations = Arc::new(AtomicUsize::new(0));
    let resolver_a_calls = Arc::new(AtomicUsize::new(0));
    let resolver_b_calls = Arc::new(AtomicUsize::new(0));
    let kernel_a = live_aggregate_kernel(
        Keypair::from_seed(&[74; 32]),
        &fixture,
        &budget_path,
        &operation_path,
        &receipt_path,
        Arc::clone(&external_invocations),
        Arc::clone(&resolver_a_calls),
    );
    let kernel_b = live_aggregate_kernel(
        Keypair::from_seed(&[75; 32]),
        &fixture,
        &budget_path,
        &operation_path,
        &receipt_path,
        Arc::clone(&external_invocations),
        Arc::clone(&resolver_b_calls),
    );

    let allowed = kernel_a
        .evaluate_tool_call_blocking(&invoke_request(
            "verified-family-request-a",
            &sibling_a,
            "execute",
            "aggregate-server",
        ))
        .test_unwrap();
    assert_eq!(allowed.verdict, Verdict::Allow);
    let denied = kernel_b
        .evaluate_tool_call_blocking(&invoke_request(
            "verified-family-request-b",
            &sibling_b,
            "execute",
            "aggregate-server",
        ))
        .test_unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .contains("budget"));
    assert_eq!(external_invocations.load(Ordering::SeqCst), 1);
    assert!(resolver_a_calls.load(Ordering::SeqCst) > 0);
    assert!(resolver_b_calls.load(Ordering::SeqCst) > 0);

    let connection = Connection::open(&budget_path).test_unwrap();
    let quota_row: (i64, i64, i64) = connection
        .query_row(
            r#"
            SELECT max_invocations, reserved_invocations, captured_invocations
            FROM budget_invocation_quota_usage
            WHERE profile = 'chio.aggregate-family-invocation.v1'
              AND owner_id = ?1
              AND grant_index_key = -1
            "#,
            [fixture.verified_root.family_owner()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .test_unwrap();
    assert_eq!(quota_row, (1, 0, 1));
    let stored_root: (String, String) = connection
        .query_row(
            r#"
            SELECT aggregate_root_capability_id, aggregate_root_binding_digest
            FROM budget_composite_authorizations
            WHERE allowed = 1
            "#,
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .test_unwrap();
    assert_eq!(stored_root.0, fixture.verified_root.root_capability_id());
    assert_eq!(stored_root.1, fixture.verified_root.root_binding_digest());
}

struct LiveAggregateFamilyFixture {
    root_issuer: Keypair,
    root_subject: Keypair,
    child_subject: Keypair,
    root_token: CapabilityToken,
    verified_root: VerifiedAggregateFamilyRoot,
}

impl LiveAggregateFamilyFixture {
    fn new(id: &str, maximum: u32, seed_offset: u8) -> Self {
        let root_issuer = Keypair::from_seed(&[seed_offset; 32]);
        let root_subject = Keypair::from_seed(&[seed_offset.saturating_add(1); 32]);
        let child_subject = Keypair::from_seed(&[seed_offset.saturating_add(2); 32]);
        let now = unix_now();
        let root_token = issue_aggregate_family_root(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: root_issuer.public_key(),
                subject: root_subject.public_key(),
                scope: aggregate_family_scope(),
                issued_at: now.saturating_sub(10),
                expires_at: now.saturating_add(300),
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            maximum,
            &root_issuer,
        )
        .test_unwrap();
        let verified_root = verify_direct_aggregate_family_root(
            &root_token,
            std::slice::from_ref(&root_issuer.public_key()),
        )
        .test_unwrap();
        Self {
            root_issuer,
            root_subject,
            child_subject,
            root_token,
            verified_root,
        }
    }

    fn delegation_marker(&self) -> AggregateBudgetDelegationMarker {
        let evidence = self.verified_root.preservation_evidence();
        AggregateBudgetDelegationMarker {
            root_binding_digest: evidence.root_binding_digest,
            max_invocations: evidence.max_invocations,
        }
    }

    fn descendant(&self, id: &str) -> CapabilityToken {
        let now = unix_now();
        let child_scope = aggregate_child_scope();
        let root_scope_hash = scope_hash(&self.root_token.scope).test_unwrap();
        let mut normalized_subset_proof =
            compute_attenuation_witness(&self.root_token.scope, &child_scope).test_unwrap();
        normalized_subset_proof.aggregate_budget = Some(self.delegation_marker());
        let link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: self.root_token.id.clone(),
                delegator: self.root_subject.public_key(),
                delegatee: self.child_subject.public_key(),
                attenuations: Vec::new(),
                timestamp: now.saturating_sub(5),
                scope_hash: Some(root_scope_hash.clone()),
                aggregate_budget: Some(self.delegation_marker()),
                cumulative_approval: None,
                aggregate_family_preservation: Some(self.verified_root.preservation_evidence()),
            },
            &self.root_subject,
        )
        .test_unwrap();
        CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: id.to_string(),
                    issuer: self.root_subject.public_key(),
                    subject: self.child_subject.public_key(),
                    scope: child_scope.clone(),
                    issued_at: now.saturating_sub(5),
                    expires_at: now.saturating_add(200),
                    delegation_chain: vec![link],
                    aggregate_invocation_budget: self
                        .root_token
                        .aggregate_invocation_budget
                        .clone(),
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: AttenuationProof {
                    parent_scope_hash: root_scope_hash,
                    child_scope_hash: scope_hash(&child_scope).test_unwrap(),
                    normalized_subset_proof,
                    aggregate_family_preservation: Some(self.verified_root.preservation_evidence()),
                },
                budget_share_bps: None,
            },
            &self.root_subject,
        )
        .test_unwrap()
    }
}

fn aggregate_family_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "aggregate-server".to_string(),
            tool_name: "execute".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn aggregate_child_scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "aggregate-server".to_string(),
            tool_name: "execute".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn live_aggregate_kernel(
    signer: Keypair,
    fixture: &LiveAggregateFamilyFixture,
    budget_path: &std::path::Path,
    operation_path: &std::path::Path,
    receipt_path: &std::path::Path,
    external_invocations: Arc<AtomicUsize>,
    resolver_calls: Arc<AtomicUsize>,
) -> ChioKernel {
    let mut config = kernel_config(signer);
    config.ca_public_keys = vec![
        fixture.root_issuer.public_key(),
        fixture.root_subject.public_key(),
    ];
    let mut kernel = ChioKernel::new(config);
    kernel.set_capability_trust_root(
        fixture.root_subject.public_key(),
        scope_hash(&fixture.root_token.scope).test_unwrap(),
    );
    let root_id = fixture.root_token.id.clone();
    let verified_root = fixture.verified_root.clone();
    kernel.set_aggregate_family_root_resolver(Arc::new(move |requested_id: &str| {
        resolver_calls.fetch_add(1, Ordering::SeqCst);
        if requested_id == root_id {
            Ok(AggregateFamilyRootResolution::FamilyBound(
                verified_root.clone(),
            ))
        } else {
            Err(chio_core::capability::aggregate_budget::AggregateFamilyRootResolutionError::Missing)
        }
    }));
    kernel
        .set_budget_store_handle(Arc::new(SqliteBudgetStore::open(budget_path).test_unwrap()))
        .test_unwrap();
    kernel
        .set_admission_operation_store_handle(Arc::new(
            SqliteSecurityAdmissionOperationStore::open(operation_path).test_unwrap(),
        ))
        .test_unwrap();
    kernel
        .set_receipt_store(Box::new(
            SqliteReceiptStore::open(receipt_path).test_unwrap(),
        ))
        .test_unwrap();
    kernel
        .register_budget_parent(fixture.root_token.id.clone(), 10_000)
        .test_unwrap();
    kernel.enable_aggregate_invocation_admission().test_unwrap();
    kernel.register_tool_server(Box::new(TestToolServer {
        server_id: "aggregate-server".to_string(),
        tool_name: "execute".to_string(),
        reported_cost: None,
        invocations: Some(external_invocations),
    }));
    kernel
}

fn monetary_grant() -> ToolGrant {
    ToolGrant {
        server_id: "cost-server".to_string(),
        tool_name: "compute".to_string(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: Some(2),
        max_cost_per_invocation: Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: 1_000,
            currency: "USD".to_string(),
        }),
        dpop_required: None,
    }
}

#[test]
fn signed_receipt_budget_metadata_matches_durable_store_events() {
    let directory = tempfile::tempdir().test_unwrap();
    let budget_path = directory.path().join("receipt-budget.sqlite3");
    let operation_path = directory.path().join("receipt-operation.sqlite3");
    let budget_store = Arc::new(SqliteBudgetStore::open(&budget_path).test_unwrap());
    let mut kernel = make_kernel(Keypair::from_seed(&[51; 32]));
    kernel
        .set_admission_operation_store_handle(Arc::new(
            SqliteSecurityAdmissionOperationStore::open(&operation_path).test_unwrap(),
        ))
        .test_unwrap();
    kernel
        .set_budget_store_handle(budget_store.clone())
        .test_unwrap();
    kernel.register_tool_server(Box::new(TestToolServer {
        server_id: "cost-server".to_string(),
        tool_name: "compute".to_string(),
        reported_cost: Some(ToolInvocationCost {
            units: 75,
            currency: "USD".to_string(),
            breakdown: None,
        }),
        invocations: None,
    }));
    let subject = Keypair::from_seed(&[52; 32]);
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants: vec![monetary_grant()],
                ..ChioScope::default()
            },
            300,
        )
        .test_unwrap();
    let response = kernel
        .evaluate_tool_call_blocking(&invoke_request(
            "receipt-store-parity",
            &capability,
            "compute",
            "cost-server",
        ))
        .test_unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "unexpected denial: {:?}",
        response.reason
    );
    assert!(response.receipt.verify_signature().test_unwrap());

    let events = budget_store
        .list_mutation_events(10, Some(&capability.id), Some(0))
        .test_unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, BudgetMutationKind::ReserveInvocations);
    assert_eq!(events[1].kind, BudgetMutationKind::CaptureInvocations);
    assert_eq!(events[2].kind, BudgetMutationKind::ReconcileSpend);
    let receipt_metadata = response.receipt.metadata.as_ref().test_unwrap();
    let budget_metadata = &receipt_metadata["budget_authority"];
    assert_eq!(
        budget_metadata["authorize"]["event_id"].as_str(),
        Some(events[0].event_id.as_str())
    );
    assert_eq!(
        budget_metadata["authorize"]["budget_commit_index"].as_u64(),
        events[0].usage_seq
    );
    assert_eq!(
        budget_metadata["authorize"]["exposure_units"].as_u64(),
        Some(events[0].exposure_units)
    );
    assert_eq!(
        receipt_metadata["protocol_admission"]["invocation_capture"]["eventId"].as_str(),
        Some(events[1].event_id.as_str())
    );
    assert_eq!(
        receipt_metadata["protocol_admission"]["invocation_capture"]["budgetCommitIndex"].as_u64(),
        events[1].usage_seq
    );
    assert_eq!(
        budget_metadata["terminal"]["event_id"].as_str(),
        Some(events[2].event_id.as_str())
    );
    assert_eq!(
        budget_metadata["terminal"]["budget_commit_index"].as_u64(),
        events[2].usage_seq
    );
    assert_eq!(
        budget_metadata["terminal"]["realized_spend_units"].as_u64(),
        Some(events[2].realized_spend_units)
    );
}
