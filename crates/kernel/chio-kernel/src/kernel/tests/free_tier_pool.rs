// Free-tier aggregate-pool tests (code-review C1 + PR957 codex P2).
//
// These tests live alongside the budget suite (`include!`d into the kernel test
// module) and exercise the aggregate Chio Pass pool co-debit: post-execution
// reconciliation of the worst-case hold down to realized cost (C1), and the
// no-pool admission boundary that keeps unrelated custom private-unit budgets on
// the normal path while still failing closed for genuine XCC Pass charges (P2).

/// The current UTC calendar-month attestation window, computed dynamically so
/// these tests are not wall-clock time bombs.
fn current_month_window() -> chio_core::capability::token::AttestationWindowId {
    use chio_core::capability::token::AttestationWindowId;
    use chrono::{DateTime, Datelike, Months, TimeZone, Utc};

    let now = current_unix_timestamp();
    let dt = DateTime::from_timestamp(now as i64, 0).expect("representable timestamp");
    let month_start_naive = dt
        .date_naive()
        .with_day(1)
        .and_then(|day| day.and_hms_opt(0, 0, 0))
        .expect("month start");
    let month_start = Utc.from_utc_datetime(&month_start_naive);
    let next_month = month_start
        .checked_add_months(Months::new(1))
        .expect("next month");
    AttestationWindowId {
        window_ym: month_start.format("%Y-%m").to_string(),
        since: month_start.timestamp() as u64,
        until: next_month.timestamp() as u64,
    }
}

/// Build a free-tier XCC Pass capability for `subject`, signed by `issuer` (the
/// kernel signing keypair). The single metered grant pins the canonical
/// `chio.pass.compute` XCC compute tool with the supplied per-invocation ceiling
/// `max_per_invocation` (the worst-case pre-execution hold) and total ceiling
/// `max_total`, plus the baseline gifted-stream resource grants.
fn make_free_tier_pass_cap(
    issuer: &Keypair,
    subject: &Keypair,
    window: &chio_core::capability::token::AttestationWindowId,
    max_per_invocation: u64,
    max_total: u64,
) -> CapabilityToken {
    use chio_core::capability::token::window_scoped_capability_id;

    let subject_did = format!("did:chio:{}", subject.public_key().to_hex());
    let metered = ToolGrant {
        server_id: "chio.pass.compute".to_string(),
        tool_name: "*".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_per_invocation,
            currency: "XCC".to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_total,
            currency: "XCC".to_string(),
        }),
        dpop_required: None,
    };
    let scope = ChioScope {
        grants: vec![metered],
        resource_grants: crate::pass_gating::pass_baseline_resource_grants(&subject_did)
            .expect("baseline resource grants"),
        prompt_grants: vec![],
    };
    let id = window_scoped_capability_id(&subject_did, window).expect("window-scoped id");
    CapabilityToken::sign(
        CapabilityTokenBody {
            id,
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope,
            issued_at: window.since,
            expires_at: window.until,
            delegation_chain: vec![],
        },
        issuer,
    )
    .expect("sign pass capability")
}

#[test]
fn free_tier_pool_reconciles_pass_charge_to_realized_cost_and_frees_room() {
    // code-review C1: a free-tier XCC Pass charged with max_cost_per_invocation = N
    // but realizing a lower cost M < N must reconcile the aggregate pool co-debit DOWN
    // to M (freeing N - M), so committed_units(term) == M and a second Pass can consume
    // the freed room. The pool (150) is deliberately smaller than 2*N (200): without
    // the reconcile the second Pass's worst-case hold would exhaust the pool and deny,
    // so an Allow on the second charge proves the room was actually freed.
    const N: u64 = 100; // max_cost_per_invocation (worst-case pre-execution hold)
    const M: u64 = 10; // realized cost the tool reports (M < N)
    const POOL: u64 = 150; // monthly pool: N + M fits, 2*N does not

    let window = current_month_window();
    let pool = FreeTierPoolConfig {
        monthly_pool_units: POOL,
        allotment_unit: "XCC".to_string(),
        board_approval_ref: "board-approval-test".to_string(),
    };
    let mut kernel = make_kernel(make_monetary_config())
        .with_free_tier_pool(pool)
        .unwrap();
    // The tool reports a realized cost of M XCC, below the N pre-execution hold.
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("chio.pass.compute", M, "XCC")));

    // Build both Passes up front (different subjects, same window/pool term) so no
    // immutable borrow of the kernel signing keypair is held across evaluation.
    let subject_a = make_keypair();
    let subject_b = make_keypair();
    let cap_a = make_free_tier_pass_cap(&kernel.config.keypair, &subject_a, &window, N, 1000);
    let cap_b = make_free_tier_pass_cap(&kernel.config.keypair, &subject_b, &window, N, 1000);

    let resp_a = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "pass-reconcile-a",
            &cap_a,
            "compute",
            "chio.pass.compute",
            serde_json::json!({}),
        ))
        .unwrap();
    assert_eq!(
        resp_a.verdict,
        Verdict::Allow,
        "the first free-tier Pass charge must be allowed"
    );

    // The aggregate pool committed exactly the realized M: held N, reconciled to M,
    // freeing N - M back into the shared monthly term.
    let term_id = FreeTierPoolConfig::window_ym_from_issued_at(cap_a.issued_at).unwrap();
    let usage_after_a = kernel
        .budget_store
        .get_usage(&term_id, super::FREETIER_GLOBAL_GRANT_INDEX)
        .unwrap()
        .expect("pool term usage row after first charge");
    assert_eq!(
        usage_after_a.committed_cost_units().unwrap(),
        M,
        "the pool must reconcile to the realized cost M (freed by N - M)"
    );

    // A SECOND Pass consumes the freed room. M (committed) + N (its worst-case hold)
    // = 110 <= POOL = 150, whereas an un-reconciled N + N = 200 would exceed POOL and
    // deny, so this Allow depends on the freed N - M units.
    let resp_b = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "pass-reconcile-b",
            &cap_b,
            "compute",
            "chio.pass.compute",
            serde_json::json!({}),
        ))
        .unwrap();
    assert_eq!(
        resp_b.verdict,
        Verdict::Allow,
        "a second Pass must consume the room freed by reconciling the first charge"
    );

    // Both charges reconciled to M, so the shared pool term committed 2*M total.
    let usage_after_b = kernel
        .budget_store
        .get_usage(&term_id, super::FREETIER_GLOBAL_GRANT_INDEX)
        .unwrap()
        .expect("pool term usage row after second charge");
    assert_eq!(
        usage_after_b.committed_cost_units().unwrap(),
        2 * M,
        "the pool tracks realized free-tier spend across both Passes"
    );
}

#[test]
fn non_pass_private_unit_allowed_when_no_pool_configured() {
    // PR957 codex P2: with NO free-tier pool installed, a capability budgeted in a
    // custom private-use unit ("ABC", which is not the Pass XCC allotment unit) must
    // stay on the normal budget path and be allowed. Before the fix the no-pool branch
    // reversed and denied EVERY unpinned three-letter unit, breaking unrelated
    // private-unit budgets merely because the Pass pool was absent.
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let agent_kp = make_keypair();
    let grant = make_monetary_grant("cost-srv", "compute", 5, 100, "ABC");
    let cap = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);

    let resp = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "abc-no-pool-1",
            &cap,
            "compute",
            "cost-srv",
            serde_json::json!({}),
        ))
        .unwrap();
    assert_eq!(
        resp.verdict,
        Verdict::Allow,
        "a non-Pass private-use unit must not be denied merely because no Pass pool is configured"
    );
}

#[test]
fn genuine_pass_xcc_denied_when_no_pool_configured() {
    // PR957 codex P2 (DO-NOT-WEAKEN guard): the no-pool fix above must NOT widen the
    // XCC-must-co-debit invariant. A genuine Pass XCC charge cannot co-debit an absent
    // aggregate ceiling, so with NO pool configured it MUST still fail closed.
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let agent_kp = make_keypair();
    let grant = make_monetary_grant("cost-srv", "compute", 5, 100, "XCC");
    let cap = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);

    let resp = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "xcc-no-pool-1",
            &cap,
            "compute",
            "cost-srv",
            serde_json::json!({}),
        ))
        .unwrap();
    assert_eq!(
        resp.verdict,
        Verdict::Deny,
        "a genuine XCC Pass charge must fail closed when no aggregate pool is configured"
    );
}
