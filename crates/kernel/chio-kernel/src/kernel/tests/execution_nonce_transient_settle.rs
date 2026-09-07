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

    delegate_authority_fenced_budget_methods!(inner);

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

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<crate::budget_store::BudgetInvocationCaptureDecision, BudgetStoreError> {
        self.inner.capture_invocation_reservations(request)
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
    );
    let fail_reconcile = std::sync::Arc::new(AtomicBool::new(false));
    kernel.set_budget_store(Box::new(TransientReconcileFailBudgetStore {
        inner: InMemoryBudgetStore::new(),
        fail_reconcile: std::sync::Arc::clone(&fail_reconcile),
    }));
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
