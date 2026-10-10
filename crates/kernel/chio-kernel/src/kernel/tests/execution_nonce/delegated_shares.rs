use super::*;

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

    let third = delegated_reserve_request("req-b-reserve-2", &fixture.child_b, &fixture.child_b_kp);
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
    kernel_before.set_budget_store_handle(Arc::clone(&budget));
    let parent = make_capability(&kernel_before, &parent_kp, parent_scope.clone(), 300);
    {
        let seed_store = SqliteReceiptStore::open(&receipt_path).unwrap();
        seed_store
            .record_capability_snapshot(&parent, None)
            .unwrap();
    }
    kernel_before
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&receipt_path).unwrap()))
        .unwrap();
    kernel_before
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    kernel_before
        .set_capability_trust_root(signer.public_key(), scope_hash(&parent_scope).unwrap());
    install_strict_nonce_store(&mut kernel_before);

    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        kernel: &kernel_before,
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: "cap-restart-child-a",
        share_bps: 4_000,
    });
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        kernel: &kernel_before,
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
    kernel_after.set_budget_store_handle(Arc::clone(&budget));
    kernel_after
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&receipt_path).unwrap()))
        .unwrap();
    kernel_after
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    kernel_after.set_capability_trust_root(signer.public_key(), scope_hash(&parent_scope).unwrap());
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
        kernel_after
            .reap_expired_reserved_budget_holds(i64::MAX)
            .unwrap(),
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
