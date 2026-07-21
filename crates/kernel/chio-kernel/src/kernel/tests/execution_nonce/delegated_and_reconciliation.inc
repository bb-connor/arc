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
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());

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
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_budget_store(Box::new(StampFailingBudgetStore {
        inner: Box::new(InMemoryBudgetStore::new()),
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
        "a failed reservation stamp must reverse the hold, not strand it open"
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
            inner: Box::new(InMemoryBudgetStore::new()),
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
fn reserving_stamp_failure_persists_no_reserved_receipt() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_budget_store(Box::new(StampFailingBudgetStore {
        inner: Box::new(InMemoryBudgetStore::new()),
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

    // No orphaned reserved receipt: the stamp failed and reversed the hold, so the
    // preflight receipt must never have been persisted.
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a failed reservation stamp must leave no persisted reserved receipt"
    );

    // Once the stamp write recovers, the success path persists exactly one reserved
    // receipt: the persist follows a successfully stamped hold.
    fail_mark.store(false, Ordering::SeqCst);
    let retry = reserve_request("req-stamp-receipt-ok", &cap, &agent_kp);
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&retry, None)
        .unwrap();
    assert_eq!(reserved.verdict, Verdict::Allow);
    assert_eq!(
        kernel.receipt_log().len(),
        1,
        "a successful reservation persists exactly one reserved receipt"
    );
}

// ---------------------------------------------------------------------------
// A durable receipt persist failure AFTER a successful reservation stamp must
// reverse the stamped hold and release the sibling-sum share, mirroring the
// stamp-failure cleanup. Otherwise the open, stamped hold burns budget for an
// authorization the caller never received until the TTL reaper forfeits it.
// ---------------------------------------------------------------------------

/// A receipt store whose `append` fails on demand, so a reservation stamp lands
/// but the durable receipt persist that follows it fails.
struct TogglingAppendReceiptStore {
    fail: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for TogglingAppendReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ReceiptStoreError::Conflict(
                "receipt append failed (test double)".to_string(),
            ));
        }
        Ok(())
    }

    fn append_child_receipt(&self, _receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

/// A receipt store that forwards capability-snapshot reads to a real store (so
/// delegation validation still resolves ancestors) but fails receipt `append` on
/// demand, so a delegated reservation stamp lands and its durable persist fails.
struct TogglingSnapshotReceiptStore {
    inner: SqliteReceiptStore,
    fail: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for TogglingSnapshotReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ReceiptStoreError::Conflict(
                "receipt append failed (test double)".to_string(),
            ));
        }
        self.inner.append_chio_receipt(receipt)
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        self.inner.append_child_receipt(receipt)
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.inner
            .record_capability_snapshot(token, parent_capability_id)
    }

    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
        self.inner.get_capability_snapshot(capability_id)
    }
}

#[test]
fn reserving_receipt_persist_failure_is_nonfatal_and_reservation_reconcilable() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    kernel
        .set_receipt_store(Box::new(TogglingAppendReceiptStore {
            fail: std::sync::Arc::clone(&fail),
        }))
        .unwrap();
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

    let grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // The reserve preflight's durable receipt persist fails. The reservation is
    // already durable in the budget store and the caller receives the minted nonce
    // to reconcile downstream, so a persistence-log failure must NOT void the
    // reservation: the response is a normal Allow carrying the nonce.
    let request = reserve_request("req-persist-fail", &cap, &agent_kp);
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .expect("a reserve receipt persist failure must not void the durable reservation");
    assert_eq!(reserved.verdict, Verdict::Allow);
    let nonce = *reserved
        .execution_nonce
        .clone()
        .expect("the caller receives the minted nonce to reconcile the durable reservation");

    // The stamped hold stays OPEN (reserved), never reversed: it is reconcilable
    // and its worst-case exposure stays committed against the grant.
    let hold_id = format!("budget-hold:req-persist-fail:{}:0", cap.id);
    let hold = kernel
        .budget_store
        .get_budget_hold(&hold_id)
        .unwrap()
        .expect("the reserved hold is recorded");
    assert_eq!(
        hold.disposition,
        crate::budget_store::BudgetHoldDispositionView::Open,
        "a receipt persist failure must NOT reverse the durable reservation"
    );
    assert!(
        hold.reserved_until.is_some(),
        "the hold stays stamped/reserved so the TTL reaper can settle it if abandoned"
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "the reserved worst-case exposure stays committed"
    );

    // The caller reconciles the durable reservation with the returned nonce once
    // the receipt store recovers, proving the reservation was never lost.
    fail.store(false, Ordering::SeqCst);
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &request.arguments, &realized)
        .expect("the durable reservation must be reconcilable by the returned nonce");
    assert_eq!(reconciled.verdict, Verdict::Allow);
}

#[test]
fn reserving_receipt_persist_failure_keeps_delegated_reservation_and_share() {
    let fixture = make_sibling_sum_monetary_fixture("reserve-persist-sibling");
    let path = fixture.path.clone();
    let mut kernel = fixture.kernel;
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    kernel
        .set_receipt_store(Box::new(TogglingSnapshotReceiptStore {
            inner: SqliteReceiptStore::open(&path).unwrap(),
            fail: std::sync::Arc::clone(&fail),
        }))
        .unwrap();
    install_strict_nonce_store(&mut kernel);

    // Child A's reserve stamps a monetary hold and records its sibling-sum share,
    // then the durable receipt persist fails. That persistence-log failure is
    // NON-FATAL: child A's reservation is durable in the budget store and child A
    // receives the nonce to reconcile, so the hold is NOT reversed and its share
    // stays held.
    let first = delegated_reserve_request("req-a-reserve", &fixture.child_a, &fixture.child_a_kp);
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .expect("a reserve receipt persist failure must not void child A's reservation");
    assert_eq!(reserved_a.verdict, Verdict::Allow);
    let nonce_a = *reserved_a
        .execution_nonce
        .clone()
        .expect("child A receives its reconcile nonce");

    // The receipt store recovers, but child B stays denied: child A's share is
    // still held by its durable reservation, not released by the failed persist.
    fail.store(false, Ordering::SeqCst);
    let second = delegated_reserve_request("req-b-reserve", &fixture.child_b, &fixture.child_b_kp);
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must stay denied while child A's persisted-but-unreceipted reservation holds its share: {:?}",
        denied_b.reason
    );

    // Reconciling child A's reservation by its nonce closes the hold and releases
    // the share, after which child B is admitted: the reservation lifecycle is
    // intact, the persist failure neither lost it nor leaked its share.
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce_a, &first.arguments, &realized)
        .expect("child A's durable reservation must reconcile by its nonce");
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

    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Reconcile-by-nonce stamps the GRANT budget and delegation lineage recorded on
// the reserved hold, not the reservation exposure and a lost lineage.
// ---------------------------------------------------------------------------

#[test]
fn reconcile_by_nonce_stamps_grant_budget_not_reservation_exposure() {
    // Grant: max_cost_per_invocation 100, max_total 150. One reserve exposes 100
    // but the grant ceiling is 150. Reconcile at realized 30 must stamp
    // budget_total == 150 (grant ceiling) and budget_remaining == 150 - 30.
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-grant-total", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();

    let financial = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("reconciled receipt carries financial metadata")
        .clone();
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial).unwrap();
    assert_eq!(
        parsed.budget_total, 150,
        "budget_total must reflect the grant ceiling, not the reservation exposure"
    );
    assert_eq!(
        parsed.budget_remaining, 120,
        "budget_remaining must be the grant ceiling minus the grant's committed spend \
         after settle (a single reservation settled at 30 leaves 150 - 30)"
    );
    assert_eq!(parsed.cost_charged, 30);
    // A root reservation carries no delegation: depth 0, root is the grant holder.
    assert_eq!(parsed.delegation_depth, 0);
    assert_eq!(parsed.root_budget_holder, cap.issuer.to_hex());
}

#[test]
fn reconcile_by_nonce_budget_remaining_accounts_for_other_committed_spend() {
    // Grant: max_cost_per_invocation 40, max_total 150. Two reservations coexist
    // (40 + 40 = 80 <= 150). Reconciling the first at realized 10 must report
    // budget_remaining against the grant's TOTAL committed spend after settle
    // (150 - (80 - 40 + 10) = 100), NOT the grant ceiling minus this reconcile's
    // realized cost (150 - 10 = 140), which would ignore reservation B's held 40.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
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
    let grant = make_monetary_grant("cost-srv", "compute", 40, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let reserve_a = reserve_request("req-recon-a", &cap, &agent_kp);
    let authorized_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_a, None)
        .unwrap();
    let nonce_a = *authorized_a.execution_nonce.clone().unwrap();

    // Reservation B stays open, committing another 40 against the grant.
    let reserve_b = reserve_request("req-recon-b", &cap, &agent_kp);
    let authorized_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_b, None)
        .unwrap();
    assert_eq!(authorized_b.verdict, Verdict::Allow);

    let realized = ToolInvocationCost {
        units: 10,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce_a, &reserve_a.arguments, &realized)
        .unwrap();
    let financial = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("reconciled receipt carries financial metadata")
        .clone();
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial).unwrap();
    assert_eq!(parsed.budget_total, 150);
    assert_eq!(
        parsed.budget_remaining, 100,
        "budget_remaining must subtract the grant's total committed spend after \
         settle (50), not just this reconcile's realized cost (10)"
    );
    assert_eq!(parsed.cost_charged, 10);
}

#[test]
fn reconcile_by_nonce_no_total_cap_grant_does_not_stamp_sentinel() {
    // A grant with a per-invocation cap but NO max_total_cost carries no monetary
    // ceiling; the budget layer records u64::MAX as its sentinel ceiling. That
    // sentinel must never surface on a signed authoritative receipt as
    // budget_total / budget_remaining.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
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
    let grant = {
        use chio_core::capability::scope::MonetaryAmount;
        let mut grant = make_monetary_grant("cost-srv", "compute", 100, 999, "USD");
        grant.max_cost_per_invocation = Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        });
        grant.max_total_cost = None;
        grant
    };
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let reserve = reserve_request("req-recon-no-cap", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &reserve.arguments, &realized)
        .unwrap();
    let financial = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("reconciled receipt carries financial metadata")
        .clone();
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial).unwrap();
    assert_ne!(
        parsed.budget_total,
        u64::MAX,
        "a no-total-cap grant must not stamp the u64::MAX sentinel as budget_total"
    );
    assert_ne!(
        parsed.budget_remaining,
        u64::MAX,
        "budget_remaining must not carry the u64::MAX sentinel"
    );
    // With no real ceiling the receipt falls back to this reservation's bounded
    // exposure (100), settled at realized 30.
    assert_eq!(parsed.budget_total, 100);
    assert_eq!(parsed.budget_remaining, 70);
    assert_eq!(parsed.cost_charged, 30);
}

#[test]
fn reconcile_by_nonce_stamps_delegated_lineage() {
    // A delegated reservation must stamp its true delegation depth and root
    // budget holder, not depth 0 with the nonce subject as root.
    let fixture = make_sibling_sum_monetary_fixture("reconcile-lineage");
    let path = fixture.path.clone();
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_reserve_request("req-a-reserve", &fixture.child_a, &fixture.child_a_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();

    let financial = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("reconciled receipt carries financial metadata")
        .clone();
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial).unwrap();
    let expected_depth = fixture.child_a.delegation_chain.len() as u32;
    assert!(
        expected_depth > 0,
        "the fixture child must actually be delegated"
    );
    assert_eq!(
        parsed.delegation_depth, expected_depth,
        "a delegated reservation must stamp its true delegation depth, not zero"
    );
    assert_eq!(
        parsed.root_budget_holder,
        fixture.child_a.issuer.to_hex(),
        "a delegated reservation must stamp the true root budget holder"
    );

    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// A durable receipt persist failure AFTER an irreversible reconcile settlement
// must still return the signed authoritative receipt (the nonce is already
// consumed and the hold closed, so a retry cannot recreate it), while a
// forged/replayed nonce still fails closed BEFORE settlement.
// ---------------------------------------------------------------------------

#[test]
fn reconcile_by_nonce_receipt_persist_failure_still_returns_authoritative_receipt() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let fail = std::sync::Arc::new(AtomicBool::new(false));
    kernel
        .set_receipt_store(Box::new(TogglingAppendReceiptStore {
            fail: std::sync::Arc::clone(&fail),
        }))
        .unwrap();
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
    let grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // Reserve succeeds (persist not failing yet), minting a nonce bound to the hold.
    let first = reserve_request("req-recon-persist-fail", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // The durable receipt persist fails during reconcile, AFTER the nonce is
    // consumed and the hold settled (irreversible). The signed authoritative
    // receipt must still be returned rather than surfacing only the persist error.
    fail.store(true, Ordering::SeqCst);
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .expect("a persist failure after settlement must still return the signed receipt");
    assert_eq!(reconciled.verdict, Verdict::Allow);
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(()),
        "the returned receipt must be an authoritative spend receipt"
    );

    // The settlement is irreversible: a second reconcile of the same nonce is a
    // replay and still fails closed.
    fail.store(false, Ordering::SeqCst);
    let replay = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        replay.to_string().contains("nonce"),
        "a second reconcile of the settled nonce must fail closed as replay: {replay}"
    );
}

// ---------------------------------------------------------------------------
// The TTL reaper must release the sibling-sum share for holds the store closed
// before it errored partway through the sweep, then propagate the store error.
// A closed hold that keeps its share admitted would leak headroom and wrongly
// deny valid sibling reservations until restart; a still-open hold keeps its
// share because the store did not settle it.
// ---------------------------------------------------------------------------

/// A budget store whose reaper closes exactly one named hold and then fails, so
/// the sweep settles some holds before erroring. `get_budget_hold` reflects the
/// post-reap disposition so the reaper can re-query which holds actually closed.
struct PartialReapBudgetStore {
    holds: std::sync::Mutex<
        std::collections::HashMap<String, crate::budget_store::BudgetHoldDispositionView>,
    >,
    close_on_reap: String,
}

impl PartialReapBudgetStore {
    fn new(close_on_reap: &str) -> Self {
        let mut holds = std::collections::HashMap::new();
        holds.insert(
            "h1".to_string(),
            crate::budget_store::BudgetHoldDispositionView::Open,
        );
        holds.insert(
            "h2".to_string(),
            crate::budget_store::BudgetHoldDispositionView::Open,
        );
        Self {
            holds: std::sync::Mutex::new(holds),
            close_on_reap: close_on_reap.to_string(),
        }
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        std::collections::HashMap<String, crate::budget_store::BudgetHoldDispositionView>,
    > {
        match self.holds.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl BudgetStore for PartialReapBudgetStore {
    fn try_increment(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        Ok(true)
    }

    fn try_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _max_invocations: Option<u32>,
        _cost_units: u64,
        _max_cost_per_invocation: Option<u64>,
        _max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        Ok(true)
    }

    fn reverse_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _exposed_cost_units: u64,
        _realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        Ok(())
    }

    fn list_usages(
        &self,
        _limit: usize,
        _capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        Ok(Vec::new())
    }

    fn get_usage(
        &self,
        _capability_id: &str,
        _grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        Ok(None)
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        Ok(self
            .lock()
            .get(hold_id)
            .map(|disposition| crate::budget_store::BudgetHoldSnapshot {
                hold_id: hold_id.to_string(),
                capability_id: "cap".to_string(),
                grant_index: 0,
                authorized_exposure_units: 100,
                remaining_exposure_units: 100,
                disposition: *disposition,
                reserved_until: Some(0),
                reserved_currency: Some("USD".to_string()),
                reserved_payment_reference: None,
                reserved_budget_total: Some(100),
                reserved_delegation_depth: Some(1),
                reserved_root_budget_holder: Some("root".to_string()),
                authority: None,
            }))
    }

    fn reap_expired_reserved_holds(&self, _now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        // Close exactly one hold, then fail: models a store that settled some
        // holds before erroring partway through the sweep.
        if let Some(disposition) = self.lock().get_mut(&self.close_on_reap) {
            *disposition = crate::budget_store::BudgetHoldDispositionView::Expired;
        }
        Err(BudgetStoreError::Invariant(
            "reap failed after settling one hold (test double)".to_string(),
        ))
    }
}

#[test]
fn reaper_releases_shares_for_holds_closed_before_a_store_error() {
    let mut kernel = make_kernel(make_config());
    kernel
        .set_budget_store(Box::new(PartialReapBudgetStore::new("h1")))
        .expect("install budget store");
    {
        let mut shares = match kernel.reserved_sibling_shares.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        shares.insert(
            "h1".to_string(),
            ReservedSiblingShare {
                parent_token_id: "parent".to_string(),
                child_token_id: "child-1".to_string(),
                share_bps: 4000,
            },
        );
        shares.insert(
            "h2".to_string(),
            ReservedSiblingShare {
                parent_token_id: "parent".to_string(),
                child_token_id: "child-2".to_string(),
                share_bps: 4000,
            },
        );
    }

    // The store closes h1 then errors on the rest of the sweep. h1's sibling
    // share must be released (its hold is now closed) while h2's is retained
    // (its hold is still open), and the store error must still propagate.
    let result = kernel.reap_expired_reserved_budget_holds(1_000);
    assert!(result.is_err(), "the store reap error must still propagate");

    let mut remaining = kernel.tracked_reserved_sibling_hold_ids();
    remaining.sort();
    assert_eq!(
        remaining,
        vec!["h2".to_string()],
        "only the still-open hold retains its share; the closed hold's share is released"
    );
}

// ---------------------------------------------------------------------------
// A transient store error while settling a reconcile must NOT consume the
// nonce. The single-use mark lands only after settlement, so a trusted caller
// that hit a transient error can re-present the same signed nonce and settle at
// realized cost instead of forfeiting the reservation.
// ---------------------------------------------------------------------------

/// A budget store that fails `reconcile_budget_hold` while a flag is armed,
/// simulating a transient settle error, and otherwise delegates to a real store.
struct TransientReconcileFailBudgetStore {
    inner: InMemoryBudgetStore,
    fail_reconcile: std::sync::Arc<AtomicBool>,
}

impl BudgetStore for TransientReconcileFailBudgetStore {
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

    fn authorize_budget_hold(
        &self,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.inner.authorize_budget_hold(request)
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
        // A transient settle failure: the nonce must survive it so the caller can
        // retry the same reconcile once the store recovers.
        if self.fail_reconcile.load(Ordering::SeqCst) {
            return Err(BudgetStoreError::Invariant(
                "reconcile settle failed (test double)".to_string(),
            ));
        }
        self.inner.reconcile_budget_hold(request)
    }

    fn release_budget_hold(
        &self,
        request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReleaseHoldDecision, BudgetStoreError> {
        self.inner.release_budget_hold(request)
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
        self.inner.mark_hold_reserved(
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
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
fn reconcile_by_nonce_transient_settle_error_preserves_nonce_for_retry() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
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
    let fail_reconcile = std::sync::Arc::new(AtomicBool::new(false));
    kernel.set_budget_store(Box::new(TransientReconcileFailBudgetStore {
        inner: InMemoryBudgetStore::new(),
        fail_reconcile: std::sync::Arc::clone(&fail_reconcile),
    }))
    .expect("install budget store");
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let first = reserve_request("req-recon-transient", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized
        .execution_nonce
        .clone()
        .expect("reserving authorization mints a nonce");
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };

    // Arm a transient settle failure: the nonce is verified but the hold settle
    // errors, so the nonce must NOT be consumed and the reserved hold stays open.
    fail_reconcile.store(true, Ordering::SeqCst);
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        err.to_string().contains("test double"),
        "the transient settle error must surface: {err}"
    );

    // Clear the failure and re-present the SAME signed nonce: it settles now,
    // proving the failed attempt did not burn the nonce.
    fail_reconcile.store(false, Ordering::SeqCst);
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .expect("the same nonce must reconcile after the transient error clears");
    assert_eq!(reconciled.verdict, Verdict::Allow);
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["budget_authority"]["terminal"]["realized_spend_units"], 30,
        "the retry settles at the realized cost"
    );
}
