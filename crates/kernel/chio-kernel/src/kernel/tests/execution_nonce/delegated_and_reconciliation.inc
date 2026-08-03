use crate::budget_store::{
    BudgetAuthorityProfile, BudgetGuaranteeLevel, BudgetMeteringProfile,
};

fn delegated_reserve_request(
    request_id: &str,
    child: &CapabilityToken,
    child_kp: &Keypair,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: child.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

fn install_strict_nonce_store(kernel: &mut ChioKernel) {
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
}

#[test]
fn delegated_reserving_child_holds_sibling_share_until_reconciled() {
    // Parent share 5000 bps, child A and child B each 4000 bps: either child
    // fits alone, but A+B (8000) over-subscribes the parent. While child A's
    // reservation hold is open, child A's admitted share must still count so a
    // second delegated child under the same parent is denied.
    let fixture = make_sibling_sum_monetary_fixture("delegated-reserve-reconcile");
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_reserve_request("req-a-reserve", &fixture.child_a, &fixture.child_a_kp);
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A reservation should be admitted: {:?}",
        reserved_a.reason
    );
    let nonce = *reserved_a
        .execution_nonce
        .clone()
        .expect("child A reservation mints a nonce");

    let second = delegated_reserve_request("req-b-reserve", &fixture.child_b, &fixture.child_b_kp);
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied while child A's reservation is open: {:?}",
        denied_b.reason
    );
    assert!(
        denied_b.reason.as_deref().is_some_and(|reason| {
            reason.contains("sibling-sum") || reason.contains("sibling sum")
        }),
        "child B denial must cite sibling-sum over-subscription: {:?}",
        denied_b.reason
    );

    // Reconcile child A's hold: closing it releases child A's sibling share.
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    let third =
        delegated_reserve_request("req-b-reserve-2", &fixture.child_b, &fixture.child_b_kp);
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's reservation is reconciled: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn delegated_reserving_child_sibling_share_freed_after_ttl_reap() {
    let fixture = make_sibling_sum_monetary_fixture("delegated-reserve-reap");
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_reserve_request("req-a-reserve", &fixture.child_a, &fixture.child_a_kp);
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A reservation should be admitted: {:?}",
        reserved_a.reason
    );

    let second = delegated_reserve_request("req-b-reserve", &fixture.child_b, &fixture.child_b_kp);
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied while child A's reservation is open: {:?}",
        denied_b.reason
    );

    // The TTL reaper forfeits child A's abandoned reservation, closing the hold
    // and freeing child A's sibling-sum share back to the parent.
    assert_eq!(
        kernel.reap_expired_reserved_budget_holds(i64::MAX).unwrap(),
        1,
        "the reaper settles child A's expired reserved hold"
    );

    let third =
        delegated_reserve_request("req-b-reserve-2", &fixture.child_b, &fixture.child_b_kp);
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's reservation is reaped: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

// ---------------------------------------------------------------------------
// Restart durability: a delegated reserve-for-caller hold left open in the
// durable budget store keeps its child's sibling-sum share admitted against the
// parent. That admission is in-memory only, so a mediation kernel built fresh
// over the same store (a process restart) loses it. The kernel must not admit a
// second delegated child against the parent as if the still-open reservation
// consumed nothing; it denies delegated admission fail-closed until the prior
// process's hold is reconciled or reaped, then resumes.
// ---------------------------------------------------------------------------

#[test]
fn restart_gate_blocks_sibling_over_subscription_against_open_delegated_reserve() {
    let receipt_path = unique_receipt_db_path("restart-reserved-sibling-gate");

    // One shared, durable-style budget store both kernels reserve holds against,
    // exactly as the sidecar shares a single budget store across a restart.
    let budget: Arc<dyn BudgetStore> =
        durable_atomic_test_budget_store("restart-reserved-sibling-budget");
    let operations =
        durable_test_admission_operation_store("restart-reserved-sibling-operations");

    // The sidecar reloads its persistent signing key on restart, so both kernels
    // issue and trust the same capability tokens.
    let config_before = make_monetary_config();
    let signer = config_before.keypair.clone();

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_monetary_grant(
        "cost-srv", "compute", 100, 1_000, "USD",
    )]);

    // Kernel before the restart: reserve child A, opening a delegated hold that
    // consumes 4000 bps of the parent's 5000 bps sibling budget.
    let mut kernel_before = make_kernel(config_before);
    kernel_before.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    kernel_before
        .set_admission_operation_store_handle(operations.clone())
        .expect("install admission operation store");
    kernel_before
        .set_budget_store_handle(Arc::clone(&budget))
        .expect("install budget store");
    let parent = make_capability(&kernel_before, &parent_kp, parent_scope.clone(), 300);
    {
        let seed_store = SqliteReceiptStore::open(&receipt_path).unwrap();
        seed_store.record_capability_snapshot(&parent, None).unwrap();
    }
    kernel_before
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&receipt_path).unwrap()))
        .unwrap();
    kernel_before
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    kernel_before.set_capability_trust_root(
        signer.public_key(),
        scope_hash(&parent_scope).unwrap(),
    );
    install_strict_nonce_store(&mut kernel_before);

    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: "cap-restart-child-a",
        share_bps: 4_000,
    });
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_b_kp,
        parent_scope: &parent_scope,
        child_scope,
        id: "cap-restart-child-b",
        share_bps: 4_000,
    });

    let reserve_a = delegated_reserve_request("req-a-reserve", &child_a, &child_a_kp);
    let reserved_a = kernel_before
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_a, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A reservation should be admitted before the restart: {:?}",
        reserved_a.reason
    );
    drop(kernel_before);

    // Kernel after the restart: fresh in-memory sibling-sum map and registry over
    // the SAME durable budget store, which still carries child A's open hold.
    let mut config_after = make_monetary_config();
    config_after.keypair = signer.clone();
    let mut kernel_after = make_kernel(config_after);
    kernel_after.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    kernel_after
        .set_admission_operation_store_handle(operations)
        .expect("restore admission operation store");
    kernel_after
        .set_budget_store_handle(Arc::clone(&budget))
        .expect("install budget store");
    kernel_after
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&receipt_path).unwrap()))
        .unwrap();
    kernel_after
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    kernel_after.set_capability_trust_root(
        signer.public_key(),
        scope_hash(&parent_scope).unwrap(),
    );
    install_strict_nonce_store(&mut kernel_after);
    kernel_after.arm_restart_reserved_hold_gate().unwrap();

    // Child B's 4000 bps would over-subscribe the parent's 5000 bps because child
    // A's reservation still holds 4000 bps. Without the restart gate the fresh
    // registry admits it; the gate denies fail-closed instead.
    let reserve_b = delegated_reserve_request("req-b-reserve", &child_b, &child_b_kp);
    let denied_b = kernel_after
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_b, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied fail-closed while child A's restart-carried reservation is open: {:?}",
        denied_b.reason
    );
    assert!(
        denied_b
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("prior process")),
        "child B denial must cite the unaccounted prior-process reservation: {:?}",
        denied_b.reason
    );

    // Settle child A's abandoned reservation in the shared store. Closing it drops
    // the last unaccounted delegated reserve hold, so the gate clears.
    assert_eq!(
        kernel_after.reap_expired_reserved_budget_holds(i64::MAX).unwrap(),
        1,
        "the reaper settles child A's expired restart-carried hold"
    );

    let reserve_b_again = delegated_reserve_request("req-b-reserve-2", &child_b, &child_b_kp);
    let admitted_b = kernel_after
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_b_again, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted once child A's restart-carried reservation is settled: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(receipt_path);
}

fn delegated_invocation_reserve_request(
    request_id: &str,
    child: &CapabilityToken,
    child_kp: &Keypair,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: child.clone(),
        tool_name: "compute".to_string(),
        server_id: "limited-srv".to_string(),
        agent_id: child_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

#[test]
fn delegated_reserving_child_with_non_monetary_grant_holds_sibling_share_until_reconciled() {
    // A non-monetary grant (max_invocations only, no cost ceiling) adopts its
    // debited invocation into a durable zero-exposure reserved hold on the
    // reserve-for-caller path. That hold is real and stays open until the caller
    // executes downstream, so child A's admitted sibling-sum share must be
    // RETAINED and recorded against the hold, exactly as a monetary reserve does.
    // A second delegated child under the same parent must be denied while child
    // A's invocation hold is open, or the parent's sibling budget is
    // over-subscribed. The share is freed only when the hold closes.
    let fixture = make_sibling_sum_invocation_fixture("delegated-reserve-invocation-reconcile");
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_invocation_reserve_request(
        "req-a-reserve",
        &fixture.child_a,
        &fixture.child_a_kp,
    );
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A non-monetary reservation should be admitted: {:?}",
        reserved_a.reason
    );
    let nonce = *reserved_a
        .execution_nonce
        .clone()
        .expect("child A invocation reservation mints a nonce");
    let invocation_hold_id = format!("budget-hold:req-a-reserve:{}:0", fixture.child_a.id);
    let invocation_hold = kernel
        .budget_store
        .get_budget_hold(&invocation_hold_id)
        .unwrap()
        .expect("atomic invocation-only reservation hold exists");
    assert!(invocation_hold.reserved_until.is_some());
    assert_eq!(invocation_hold.authorized_exposure_units, 0);
    assert_eq!(invocation_hold.remaining_exposure_units, 0);
    assert_eq!(invocation_hold.reserved_currency, None);
    assert_eq!(invocation_hold.reserved_payment_reference, None);
    assert_eq!(invocation_hold.reserved_budget_total, None);
    let receipt_metadata = reserved_a
        .receipt
        .metadata
        .as_ref()
        .expect("invocation reservation receipt metadata");
    assert_eq!(
        receipt_metadata["budget_authority"]["hold_id"],
        invocation_hold_id
    );
    assert_eq!(
        receipt_metadata["budget_authority"]["authorize"]["exposure_units"],
        0
    );
    assert!(receipt_metadata.get("financial").is_none());

    let second = delegated_invocation_reserve_request(
        "req-b-reserve",
        &fixture.child_b,
        &fixture.child_b_kp,
    );
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied while child A's invocation reservation is open: {:?}",
        denied_b.reason
    );
    assert!(
        denied_b.reason.as_deref().is_some_and(|reason| {
            reason.contains("sibling-sum") || reason.contains("sibling sum")
        }),
        "child B denial must cite sibling-sum over-subscription: {:?}",
        denied_b.reason
    );

    // Reconcile child A's zero-exposure invocation hold at zero realized cost:
    // closing it releases child A's retained sibling share.
    let realized = ToolInvocationCost {
        units: 0,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    let third = delegated_invocation_reserve_request(
        "req-b-reserve-2",
        &fixture.child_b,
        &fixture.child_b_kp,
    );
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's invocation reservation is reconciled: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn delegated_reserving_child_with_non_monetary_grant_sibling_share_freed_after_ttl_reap() {
    // The invocation-only reserve-for-caller hold retains child A's sibling share
    // for the life of the hold. If the caller never executes, the TTL reaper
    // forfeits the expired hold and releases the share back to the parent, so a
    // sibling can then be admitted. Confirms the reaper's per-hold-id share
    // release covers the zero-exposure invocation hold.
    let fixture = make_sibling_sum_invocation_fixture("delegated-reserve-invocation-reap");
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_invocation_reserve_request(
        "req-a-reserve",
        &fixture.child_a,
        &fixture.child_a_kp,
    );
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A non-monetary reservation should be admitted: {:?}",
        reserved_a.reason
    );

    let second = delegated_invocation_reserve_request(
        "req-b-reserve",
        &fixture.child_b,
        &fixture.child_b_kp,
    );
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied while child A's invocation reservation is open: {:?}",
        denied_b.reason
    );

    // The TTL reaper forfeits child A's abandoned invocation reservation, closing
    // the zero-exposure hold and freeing child A's retained sibling share.
    assert_eq!(
        kernel.reap_expired_reserved_budget_holds(i64::MAX).unwrap(),
        1,
        "the reaper settles child A's expired invocation reserved hold"
    );

    let third = delegated_invocation_reserve_request(
        "req-b-reserve-2",
        &fixture.child_b,
        &fixture.child_b_kp,
    );
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's invocation reservation is reaped: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

// ---------------------------------------------------------------------------
// A failed reservation stamp must reverse the authorized hold, not strand it
// open-and-unstamped where the TTL reaper (which only settles stamped holds)
// would never reclaim it.
// ---------------------------------------------------------------------------

struct StampFailingBudgetStore {
    inner: Box<dyn BudgetStore>,
    fail_mark: std::sync::Arc<AtomicBool>,
}

impl BudgetStore for StampFailingBudgetStore {
    fn authority_profile(&self) -> crate::budget_store::BudgetStoreProfile {
        self.inner.authority_profile()
    }

    fn budget_guarantee_level(&self) -> crate::budget_store::BudgetGuaranteeLevel {
        self.inner.budget_guarantee_level()
    }

    fn supports_durable_atomic_payment_journal(&self) -> bool {
        self.inner.supports_durable_atomic_payment_journal()
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.get_usage(capability_id, grant_index)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<crate::budget_store::BudgetMutationRecord>, BudgetStoreError> {
        self.inner
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn get_mutation_event_by_id(
        &self,
        event_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetMutationRecord>, BudgetStoreError> {
        self.inner.get_mutation_event_by_id(event_id)
    }

    fn record_payment_journal(
        &self,
        entry: &crate::payment::PaymentJournalRecord,
    ) -> Result<(), BudgetStoreError> {
        self.inner.record_payment_journal(entry)
    }

    fn advance_payment_journal(
        &self,
        request_id: &str,
        expected: crate::payment::PaymentJournalState,
        next: crate::payment::PaymentJournalState,
        authorization_id: Option<&str>,
        transaction_id: Option<&str>,
        settle: Option<crate::payment::PaymentSettleIntent>,
    ) -> Result<(), BudgetStoreError> {
        self.inner.advance_payment_journal(
            request_id,
            expected,
            next,
            authorization_id,
            transaction_id,
            settle,
        )
    }

    fn close_payment_journal(&self, request_id: &str) -> Result<bool, BudgetStoreError> {
        self.inner.close_payment_journal(request_id)
    }

    fn list_incomplete_payment_journal(
        &self,
        older_than_unix_ms: u64,
    ) -> Result<Vec<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        self.inner
            .list_incomplete_payment_journal(older_than_unix_ms)
    }

    fn get_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, BudgetStoreError> {
        self.inner.get_payment_journal(request_id)
    }

    fn payment_journal_reconcile_failed_rail(
        &self,
        request_id: &str,
    ) -> Result<Option<String>, BudgetStoreError> {
        self.inner
            .payment_journal_reconcile_failed_rail(request_id)
    }

    fn authorize_budget_hold(
        &self,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.inner.authorize_budget_hold(request)
    }

    fn replay_budget_authorization(
        &self,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.inner.replay_budget_authorization(request)
    }

    fn reverse_budget_hold(
        &self,
        request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, BudgetStoreError> {
        self.inner.reverse_budget_hold(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: crate::budget_store::BudgetReconcileHoldRequest,
    ) -> Result<crate::budget_store::BudgetReconcileHoldDecision, BudgetStoreError> {
        self.inner.reconcile_budget_hold(request)
    }

    fn release_budget_hold(
        &self,
        request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReleaseHoldDecision, BudgetStoreError> {
        self.inner.release_budget_hold(request)
    }

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<crate::budget_store::BudgetHoldMutationDecision, BudgetStoreError> {
        self.inner.capture_invocation_reservations(request)
    }

    fn query_invocation_capture(
        &self,
        request: &crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<Option<crate::budget_store::BudgetHoldMutationDecision>, BudgetStoreError> {
        self.inner.query_invocation_capture(request)
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        self.inner.get_budget_hold(hold_id)
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        if self.fail_mark.load(Ordering::SeqCst) {
            return Err(BudgetStoreError::Invariant(
                "reservation stamp write failed (test double)".to_string(),
            ));
        }
        self.inner.mark_hold_reserved(
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn mark_invocation_hold_reserved(
        &self,
        hold_id: &str,
        capability_id: &str,
        grant_index: usize,
        reserved_until_unix_secs: i64,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        if self.fail_mark.load(Ordering::SeqCst) {
            return Err(BudgetStoreError::Invariant(
                "invocation reservation stamp write failed (test double)".to_string(),
            ));
        }
        self.inner.mark_invocation_hold_reserved(
            hold_id,
            capability_id,
            grant_index,
            reserved_until_unix_secs,
            envelope,
        )
    }

    fn mark_admission_operation_hold_reserved(
        &self,
        hold_id: &str,
        admission_operation: &crate::budget_store::BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        if self.fail_mark.load(Ordering::SeqCst) {
            return Err(BudgetStoreError::Invariant(
                "reservation stamp write failed (test double)".to_string(),
            ));
        }
        self.inner.mark_admission_operation_hold_reserved(
            hold_id,
            admission_operation,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        self.inner.reap_expired_reserved_holds(now_unix_secs)
    }
}

#[test]
fn reserving_stamp_failure_reverses_authorized_hold() {
    let mut kernel = make_kernel(make_monetary_config());
    install_durable_test_receipt_store(&mut kernel, "stamp-failure-receipts");
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(
            "stamp-failure-operations",
        ))
        .expect("install admission operation store");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_budget_store(Box::new(StampFailingBudgetStore {
        inner: Box::new(DurableAtomicTestBudgetStore::new()),
        fail_mark: std::sync::Arc::clone(&fail_mark),
    }))
    .expect("install budget store");
    install_strict_nonce_store(&mut kernel);

    // The whole grant is reservable by one authorization, so a stranded hold
    // would block every later reservation on the grant.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = reserve_request("req-stamp-fail", &cap, &agent_kp);
    let err = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap_err();
    assert!(
        err.to_string().contains("stamp") || err.to_string().contains("reservation"),
        "the reservation stamp failure must surface: {err}"
    );

    // The authorized hold was reversed, not left open-and-unstamped.
    let hold_id = format!("budget-hold:req-stamp-fail:{}:0", cap.id);
    let hold = kernel
        .budget_store
        .get_budget_hold(&hold_id)
        .unwrap()
        .expect("the authorized hold is recorded");
    assert_eq!(
        hold.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reversed,
        "a failed reservation stamp must reverse the hold, not strand it open: {err}"
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        0,
        "the reversed hold leaves no committed exposure"
    );

    // Once the stamp write recovers, a later reservation on the same fully-bounded
    // grant succeeds: nothing was stranded by the failed stamp.
    fail_mark.store(false, Ordering::SeqCst);
    let retry = reserve_request("req-stamp-recover", &cap, &agent_kp);
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&retry, None)
        .unwrap();
    assert_eq!(
        reserved.verdict,
        Verdict::Allow,
        "a later reservation must succeed after the failed stamp was unwound: {:?}",
        reserved.reason
    );
}

#[test]
fn invocation_only_stamp_failure_reverses_exact_atomic_hold() {
    let fixture = make_sibling_sum_invocation_fixture("invocation-stamp-failure");
    let path = fixture.path.clone();
    let mut kernel = fixture.kernel;
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel
        .set_budget_store(Box::new(StampFailingBudgetStore {
            inner: Box::new(DurableAtomicTestBudgetStore::new()),
            fail_mark: std::sync::Arc::clone(&fail_mark),
        }))
        .expect("install budget store");
    install_strict_nonce_store(&mut kernel);

    let failed = delegated_invocation_reserve_request(
        "req-invocation-stamp-fail",
        &fixture.child_a,
        &fixture.child_a_kp,
    );
    let error = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&failed, None)
        .expect_err("invocation-only reservation stamp must fail");
    assert!(error.to_string().contains("stamp"));
    let failed_hold_id = format!(
        "budget-hold:req-invocation-stamp-fail:{}:0",
        fixture.child_a.id
    );
    let failed_hold = kernel
        .budget_store
        .get_budget_hold(&failed_hold_id)
        .unwrap()
        .expect("atomic invocation hold remains auditable");
    assert_eq!(
        failed_hold.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reversed
    );
    assert_eq!(
        kernel
            .budget_store
            .get_usage(&fixture.child_a.id, 0)
            .unwrap()
            .unwrap()
            .invocation_count,
        0
    );

    fail_mark.store(false, Ordering::SeqCst);
    let retry = delegated_invocation_reserve_request(
        "req-invocation-stamp-retry",
        &fixture.child_a,
        &fixture.child_a_kp,
    );
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&retry, None)
        .expect("retry after exact hold reversal");
    assert_eq!(reserved.verdict, Verdict::Allow);
    let retry_hold_id = format!(
        "budget-hold:req-invocation-stamp-retry:{}:0",
        fixture.child_a.id
    );
    let retry_hold = kernel
        .budget_store
        .get_budget_hold(&retry_hold_id)
        .unwrap()
        .expect("retry invocation hold exists");
    assert!(retry_hold.reserved_until.is_some());
    assert_eq!(retry_hold.reserved_currency, None);
    assert_eq!(retry_hold.reserved_budget_total, None);

    let _ = std::fs::remove_file(path);
}

// A failed reservation stamp reverses the hold, so the reserved preflight receipt
// must not have been persisted first: a `hold_disposition: reserved` receipt with
// no terminal event standing over a reversed hold is a corrupted audit view. The
// receipt is persisted only after the hold is successfully stamped.
#[test]
fn reserving_stamp_failure_persists_terminal_compensation_receipt() {
    let mut kernel = make_kernel(make_monetary_config());
    install_durable_test_receipt_store(&mut kernel, "stamp-receipt-failure-receipts");
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(
            "stamp-receipt-failure-operations",
        ))
        .expect("install admission operation store");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_budget_store(Box::new(StampFailingBudgetStore {
        inner: Box::new(DurableAtomicTestBudgetStore::new()),
        fail_mark: std::sync::Arc::clone(&fail_mark),
    }))
    .expect("install budget store");
    install_strict_nonce_store(&mut kernel);

    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = reserve_request("req-stamp-no-receipt", &cap, &agent_kp);
    let err = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap_err();
    assert!(
        err.to_string().contains("stamp") || err.to_string().contains("reservation"),
        "the reservation stamp failure must surface: {err}"
    );

    // The failed stamp reverses the hold and commits one signed terminal
    // compensation receipt. It must not leave an orphaned reserved receipt.
    assert_eq!(
        kernel.receipt_log().len(),
        1,
        "a failed reservation stamp must commit one terminal compensation receipt"
    );
    assert!(matches!(
        kernel.receipt_log().receipts()[0].decision,
        Some(Decision::Deny { .. })
    ));

    // Once the stamp write recovers, the success path adds exactly one reserved
    // receipt after the earlier terminal compensation receipt.
    fail_mark.store(false, Ordering::SeqCst);
    let retry = reserve_request("req-stamp-receipt-ok", &cap, &agent_kp);
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&retry, None)
        .unwrap();
    assert_eq!(reserved.verdict, Verdict::Allow);
    assert_eq!(
        kernel.receipt_log().len(),
        2,
        "a successful reservation adds exactly one reserved receipt"
    );
}

include!("delegated_and_reconciliation_tail.inc");
