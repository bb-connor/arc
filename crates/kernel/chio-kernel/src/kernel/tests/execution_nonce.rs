use super::*;

#[path = "execution_nonce/delegated_shares.rs"]
mod delegated_shares;
#[path = "execution_nonce/receipt_and_reaper.rs"]
mod receipt_and_reaper;
#[path = "execution_nonce/reservations.rs"]
mod reservations;
#[path = "execution_nonce/verification.rs"]
mod verification;

// ---------------------------------------------------------------------------
// Reconcile-by-nonce: mediated spend becomes authoritative at the realized cost.
// ---------------------------------------------------------------------------

fn reconcile_kernel_and_cap() -> (ChioKernel, Keypair, CapabilityToken, ExecutionNonceConfig) {
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
    // max_cost_per_invocation 100, max_total 150: one authorization reserves the
    // worst-case 100; a second (needing 100 more -> 200 > 150) is blocked until
    // the first frees its unspent slack.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    (kernel, agent_kp, cap, cfg)
}

pub(super) fn reserve_request(
    request_id: &str,
    cap: &CapabilityToken,
    agent_kp: &Keypair,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

// ---------------------------------------------------------------------------
// Preflight terminal-state reasons stay consistent with their receipt decision.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Delegated reserve-for-caller: an outstanding reservation keeps its child's
// sibling-sum share admitted, so a sibling cannot over-subscribe the parent
// while the reservation is open. The share is freed only when the hold closes
// (reconcile-by-nonce or TTL reap).
// ---------------------------------------------------------------------------

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
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

pub(super) fn install_strict_nonce_store(kernel: &mut ChioKernel) {
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
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
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

// ---------------------------------------------------------------------------
// A failed reservation stamp must reverse the authorized hold, not strand it
// open-and-unstamped where the TTL reaper (which only settles stamped holds)
// would never reclaim it.
// ---------------------------------------------------------------------------

pub(super) struct StampFailingBudgetStore {
    pub(super) inner: InMemoryBudgetStore,
    pub(super) fail_mark: std::sync::Arc<AtomicBool>,
}

impl BudgetStore for StampFailingBudgetStore {
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

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        self.inner.reap_expired_reserved_holds(now_unix_secs)
    }
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

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
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

// ---------------------------------------------------------------------------
// Reconcile-by-nonce stamps the GRANT budget and delegation lineage recorded on
// the reserved hold, not the reservation exposure and a lost lineage.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A durable receipt persist failure AFTER an irreversible reconcile settlement
// must still return the signed authoritative receipt (the nonce is already
// consumed and the hold closed, so a retry cannot recreate it), while a
// forged/replayed nonce still fails closed BEFORE settlement.
// ---------------------------------------------------------------------------

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
    fail_next_closed_lookup: AtomicBool,
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
            fail_next_closed_lookup: AtomicBool::new(false),
        }
    }

    fn with_post_reap_read_failure(close_on_reap: &str) -> Self {
        let store = Self::new(close_on_reap);
        store.fail_next_closed_lookup.store(true, Ordering::SeqCst);
        store
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

    reject_authority_fenced_budget_methods!(
        "partial reaper store does not support authority-fenced budget mutations"
    );

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
        let disposition = self.lock().get(hold_id).copied();
        if disposition.is_some_and(|value| !value.is_open())
            && self.fail_next_closed_lookup.swap(false, Ordering::SeqCst)
        {
            return Err(BudgetStoreError::Invariant(
                "transient post-reap read failure".to_string(),
            ));
        }
        Ok(
            disposition.map(|disposition| crate::budget_store::BudgetHoldSnapshot {
                hold_id: hold_id.to_string(),
                capability_id: "cap".to_string(),
                grant_index: 0,
                authorized_exposure_units: 100,
                remaining_exposure_units: 100,
                disposition,
                reserved_until: Some(0),
                reserved_currency: Some("USD".to_string()),
                reserved_payment_reference: None,
                reserved_budget_total: Some(100),
                reserved_delegation_depth: Some(1),
                reserved_root_budget_holder: Some("root".to_string()),
                authority: None,
            }),
        )
    }

    fn reap_expired_reserved_holds(&self, _now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        // Close exactly one hold, then fail: models a store that settled some
        // holds before erroring partway through the sweep.
        if let Some(disposition) = self.lock().get_mut(&self.close_on_reap) {
            *disposition = crate::budget_store::BudgetHoldDispositionView::Reconciled;
        }
        Err(BudgetStoreError::Invariant(
            "reap failed after settling one hold (test double)".to_string(),
        ))
    }
}
