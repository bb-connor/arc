use super::*;

#[test]
fn reserving_stamp_failure_reverses_authorized_hold() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_budget_store(Box::new(StampFailingBudgetStore {
        inner: InMemoryBudgetStore::new(),
        fail_mark: std::sync::Arc::clone(&fail_mark),
    }));
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
    let hold_id = format!("nonce-preflight-budget-hold:req-stamp-fail:{}:0", cap.id);
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
        inner: InMemoryBudgetStore::new(),
        fail_mark: std::sync::Arc::clone(&fail_mark),
    }));
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
    );

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
    let hold_id = nonce
        .reserved_hold_id()
        .expect("the reconcile nonce names the durable reservation")
        .to_string();
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

    let third = delegated_reserve_request("req-b-reserve-2", &fixture.child_b, &fixture.child_b_kp);
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
        parsed.budget_total,
        Some(150),
        "budget_total must reflect the grant ceiling, not the reservation exposure"
    );
    assert_eq!(
        parsed.budget_remaining,
        Some(120),
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
    );
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
    assert_eq!(parsed.budget_total, Some(150));
    assert_eq!(
        parsed.budget_remaining,
        Some(100),
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
    );
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
    // No grant ceiling exists. Invocation exposure cannot stand in for one.
    assert_eq!(parsed.budget_total, None);
    assert_eq!(parsed.budget_remaining, None);
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
    );
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

#[test]
fn reaper_releases_shares_for_holds_closed_before_a_store_error() {
    let mut kernel = make_kernel(make_config());
    kernel.set_budget_store(Box::new(
        PartialReapBudgetStore::with_post_reap_read_failure("h1"),
    ));
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

    // The store closes h1, errors on the sweep, then transiently fails the
    // post-reap read. The share stays held fail-closed on that first pass.
    let result = kernel.reap_expired_reserved_budget_holds(1_000);
    assert!(result.is_err(), "the store reap error must still propagate");
    let mut remaining = kernel.tracked_reserved_sibling_hold_ids();
    remaining.sort();
    assert_eq!(remaining, vec!["h1".to_string(), "h2".to_string()]);

    // The next sweep notices h1 is already closed and releases its share.
    assert!(kernel.reap_expired_reserved_budget_holds(1_000).is_err());
    let mut remaining = kernel.tracked_reserved_sibling_hold_ids();
    remaining.sort();
    assert_eq!(
        remaining,
        vec!["h2".to_string()],
        "only the still-open hold retains its share; the closed hold's share is released"
    );
}
