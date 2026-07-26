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
    install_fixture_budget_admission_authorities(&mut kernel, "reserve-receipt-persist-failure");
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
    install_fixture_budget_admission_authorities(&mut kernel, "reconcile-remaining-spend");
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
    install_fixture_budget_admission_authorities(&mut kernel, "reconcile-no-total-cap");
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
    let caller_attribution = serde_json::json!({
        "attribution": {
            "subject_key": "caller-controlled-subject",
            "issuer_key": "caller-controlled-issuer",
            "delegation_depth": 4_294_967_295_u32,
            "grant_index": 4_294_967_295_u32,
            "caller_extension": "must-not-survive",
        }
    });
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, Some(caller_attribution))
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
    let attribution = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("attribution"))
        .expect("reconciled receipt carries trusted attribution")
        .clone();
    assert!(
        attribution.get("caller_extension").is_none(),
        "caller-controlled attribution extensions must not survive typed projection"
    );
    let attribution: crate::ReceiptAttributionMetadata =
        serde_json::from_value(attribution).unwrap();
    assert_eq!(attribution.subject_key, fixture.child_a.subject.to_hex());
    assert_eq!(attribution.issuer_key, fixture.child_a.issuer.to_hex());
    assert_eq!(attribution.delegation_depth, expected_depth);
    assert_eq!(attribution.grant_index, Some(0));

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
    install_fixture_budget_admission_authorities(&mut kernel, "reconcile-receipt-persist-failure");
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
                authorization_metadata: BudgetCommitMetadata {
                    authority: None,
                    guarantee_level: BudgetGuaranteeLevel::SingleNodeAtomic,
                    budget_profile: BudgetAuthorityProfile::AuthoritativeHoldEvent,
                    metering_profile:
                        BudgetMeteringProfile::MaxCostPreauthorizeThenReconcileActual,
                    budget_commit_index: Some(1),
                    event_id: Some(format!("{hold_id}:authorize")),
                    partition_escrow_evidence: None,
                },
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
    inner: DurableAtomicTestBudgetStore,
    fail_reconcile: std::sync::Arc<AtomicBool>,
}

impl BudgetStore for TransientReconcileFailBudgetStore {
    fn authority_profile(&self) -> crate::budget_store::BudgetStoreProfile {
        self.inner.authority_profile()
    }

    fn supports_durable_atomic_payment_journal(&self) -> bool {
        self.inner.supports_durable_atomic_payment_journal()
    }

    fn budget_guarantee_level(&self) -> crate::budget_store::BudgetGuaranteeLevel {
        self.inner.budget_guarantee_level()
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
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(
            "transient-reconcile-failure-operations",
        ))
        .expect("install admission operation store");
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
        inner: DurableAtomicTestBudgetStore::new(),
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
