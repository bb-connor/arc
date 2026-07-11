// Section 8.2 kernel free-tier pool suite + Gate 1 exhaustion evidence (M1-10).
//
// These tests exercise the CONTROL-1 per-Pass + aggregate-pool co-debit in
// `check_and_increment_budget` (validation.rs) and its symmetric reversal in
// `reverse_budget_charge`. They prove the free-tier gift bounds aggregate
// liability to a hard monthly ceiling and degrades to read-only (fail-closed)
// the instant the pool is insolvent, so the treasury never overspends.
//
// The mechanism is tested directly at the budget-charge boundary (the unit under
// test) rather than through `evaluate_tool_call_blocking`: a naive XCC-bearing
// capability is rejected at admission by the B7 deterministic-id gate, so driving
// the full pipeline would require minting canonical window-scoped Passes and
// exercise unrelated surface. `KernelError::BudgetExhausted` is exactly the
// pre-execution deny signal the evaluation pipeline renders as `Verdict::Deny`
// with `cost_charged == 0` (evaluation.rs builds the monetary deny receipt from
// this error), so the Gate-1 assertions below are the faithful kernel-level form
// of the spec's "the 4th is Verdict::Deny".

const FT_SERVER: &str = "chio.pass.compute";
const FT_TOOL: &str = "compute";
const FT_UNIT: &str = "XCC";
const FT_BOARD_REF: &str = "board-2026-06-freetier";

// 2026-06-15 and 2026-07-15 UTC. Pinning issued_at keeps the derived pool window
// deterministic and independent of the wall clock (no month-boundary flake).
const WINDOW_JUNE_ISSUED_AT: u64 = 1_781_481_600;
const WINDOW_JULY_ISSUED_AT: u64 = 1_784_073_600;

fn make_grant_in(per_invocation: u64, total: u64, currency: &str) -> ToolGrant {
    ToolGrant {
        server_id: FT_SERVER.to_string(),
        tool_name: FT_TOOL.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: per_invocation,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: total,
            currency: currency.to_string(),
        }),
        dpop_required: None,
    }
}

/// Build a self-signed capability with full control over id, issued_at, and
/// scope. `check_and_increment_budget` never verifies the signature, so a fresh
/// keypair (distinct subject) per call is sufficient and keeps each Pass distinct.
fn make_freetier_cap(id: &str, issued_at: u64, grant: ToolGrant) -> CapabilityToken {
    let kp = make_keypair();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: id.to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: make_scope(vec![grant]),
            issued_at,
            expires_at: issued_at.saturating_add(30 * 24 * 3600),
            delegation_chain: Vec::new(),
        },
        &kp,
    )
    .expect("sign free-tier capability")
}

fn one_grant(cap: &CapabilityToken) -> Vec<MatchingGrant<'_>> {
    vec![MatchingGrant {
        index: 0,
        grant: &cap.scope.grants[0],
        specificity: (1, 1, 0),
    }]
}

fn pool_kernel(monthly_pool_units: u64) -> ChioKernel {
    make_kernel(make_config())
        .with_free_tier_pool(FreeTierPoolConfig {
            monthly_pool_units,
            allotment_unit: FT_UNIT.to_string(),
            board_approval_ref: FT_BOARD_REF.to_string(),
        })
        .expect("install board-approved free-tier pool")
}

fn no_pool_kernel() -> ChioKernel {
    make_kernel(make_config())
}

/// Committed (held) cost units for `(capability_id, grant_index 0)`. Both the
/// per-Pass row and the aggregate pool row key off grant index 0, so this helper
/// serves both. A missing row reads as zero.
fn committed_units(kernel: &ChioKernel, capability_id: &str) -> u64 {
    kernel
        .budget_store
        .get_usage(capability_id, FREETIER_GLOBAL_GRANT_INDEX)
        .expect("budget usage lookup")
        .map(|record| record.committed_cost_units().expect("committed cost units"))
        .unwrap_or(0)
}

/// Count of budget rows whose id is a `freetier:global:<window>` pool term.
fn freetier_row_count(kernel: &ChioKernel) -> usize {
    kernel
        .budget_store
        .list_usages(1024, None)
        .expect("list budget usages")
        .into_iter()
        .filter(|record| record.capability_id.starts_with("freetier:global:"))
        .count()
}

/// Assert a charge fail-closed denies and return the error. Used instead of
/// `Result::expect_err` because the `Ok` payload (`PreExecutionBudgetMutation`)
/// is not `Debug`.
fn expect_denied(
    result: Result<(usize, PreExecutionBudgetMutation), KernelError>,
    context: &str,
) -> KernelError {
    match result {
        Ok(_) => panic!("expected a fail-closed deny ({context}), got an admitted charge"),
        Err(err) => err,
    }
}

// 1. Pool-disabled additive no-op: with no pool installed the existing monetary
//    path is byte-identical to before the mechanism (Allow then exhaustion Deny)
//    and NO freetier:global row is ever written.
#[test]
fn pool_disabled_is_additive_noop_and_writes_no_freetier_row() {
    let kernel = no_pool_kernel();
    let cap = make_freetier_cap(
        "cap-noop-usd",
        WINDOW_JUNE_ISSUED_AT,
        make_grant_in(100, 100, "USD"),
    );
    let grants = one_grant(&cap);

    let (idx, mutation) = kernel
        .check_and_increment_budget("req-noop-1", &cap, &grants)
        .expect("first USD charge is admitted");
    assert_eq!(idx, 0);
    match &mutation {
        PreExecutionBudgetMutation::Charge(charge) => {
            assert_eq!(charge.cost_charged, 100);
            assert!(
                charge.free_tier_pool_hold.is_none(),
                "a pinned (USD) currency must take the unchanged non-pool path"
            );
        }
        _ => panic!("expected a monetary charge"),
    }

    let err = expect_denied(
        kernel.check_and_increment_budget("req-noop-2", &cap, &grants),
        "second USD charge denies on per-Pass exhaustion",
    );
    assert!(matches!(err, KernelError::BudgetExhausted(_)));

    assert_eq!(
        freetier_row_count(&kernel),
        0,
        "a disabled pool must never write a freetier:global row"
    );
}

// 2. Currency scoping: an installed pool governs ONLY its allotment unit. A USD
//    charge (pinned, carries a money leg) is unaffected and writes no pool row.
#[test]
fn configured_pool_leaves_non_allotment_currency_unaffected() {
    let kernel = pool_kernel(1_000_000);
    let cap = make_freetier_cap(
        "cap-scope-usd",
        WINDOW_JUNE_ISSUED_AT,
        make_grant_in(100, 1_000, "USD"),
    );
    let grants = one_grant(&cap);

    let (_idx, mutation) = kernel
        .check_and_increment_budget("req-scope-usd", &cap, &grants)
        .expect("USD charge is admitted under an installed pool");
    match &mutation {
        PreExecutionBudgetMutation::Charge(charge) => {
            assert_eq!(charge.cost_charged, 100);
            assert!(
                charge.free_tier_pool_hold.is_none(),
                "USD must not debit the XCC pool"
            );
        }
        _ => panic!("expected a monetary charge"),
    }
    assert_eq!(
        freetier_row_count(&kernel),
        0,
        "a non-allotment currency must not touch the pool"
    );
    assert_eq!(
        committed_units(&kernel, &cap.id),
        100,
        "the per-Pass USD row charged normally"
    );
}

// 3. Pool-bypass-closed: a free-tier (XCC) charge of cost_units == 0 must DENY.
//    The gift cannot be drawn for free; the per-Pass hold is reversed and no pool
//    row is written.
#[test]
fn zero_cost_freetier_charge_denies_and_cannot_bypass_meter() {
    let kernel = pool_kernel(1_000_000);
    let cap = make_freetier_cap(
        "cap-zero",
        WINDOW_JUNE_ISSUED_AT,
        make_grant_in(0, 100, FT_UNIT),
    );
    let grants = one_grant(&cap);

    let err = expect_denied(
        kernel.check_and_increment_budget("req-zero", &cap, &grants),
        "a zero-cost free-tier charge must deny",
    );
    assert!(matches!(err, KernelError::BudgetExhausted(_)));
    assert_eq!(
        committed_units(&kernel, &cap.id),
        0,
        "the per-Pass hold is reversed"
    );
    assert_eq!(
        freetier_row_count(&kernel),
        0,
        "a denied zero-cost charge never authorizes a pool hold"
    );
}

// 4. B5: with NO pool installed a free-tier (XCC) charge denies fail-closed AND
//    the per-Pass hold is reversed (no stranded exposure).
#[test]
fn b5_freetier_pool_none_denies_xcc_and_reverses_per_pass_hold() {
    let kernel = no_pool_kernel();
    let cap = make_freetier_cap(
        "cap-b5",
        WINDOW_JUNE_ISSUED_AT,
        make_grant_in(50, 1_000, FT_UNIT),
    );
    let grants = one_grant(&cap);
    let committed_before = committed_units(&kernel, &cap.id);

    let err = expect_denied(
        kernel.check_and_increment_budget("req-b5", &cap, &grants),
        "XCC with no pool installed must deny",
    );
    assert!(matches!(err, KernelError::BudgetExhausted(_)));
    assert_eq!(
        committed_units(&kernel, &cap.id),
        committed_before,
        "the per-Pass hold is reversed to its pre-charge committed value"
    );
    assert_eq!(committed_units(&kernel, &cap.id), 0);
    assert_eq!(freetier_row_count(&kernel), 0);
}

// 5. Monthly roll: charging in window M then window M+1 debits DISTINCT,
//    independently zeroed pool rows (the term id is window-scoped).
#[test]
fn pool_window_rolls_monthly_with_fresh_row() {
    let kernel = pool_kernel(1_000_000);
    let term_june = FreeTierPoolConfig::window_ym_from_issued_at(WINDOW_JUNE_ISSUED_AT)
        .expect("june window term");
    let term_july = FreeTierPoolConfig::window_ym_from_issued_at(WINDOW_JULY_ISSUED_AT)
        .expect("july window term");
    assert_ne!(
        term_june, term_july,
        "the windows must differ across the month boundary"
    );

    let cap_june = make_freetier_cap(
        "cap-june",
        WINDOW_JUNE_ISSUED_AT,
        make_grant_in(40, 1_000, FT_UNIT),
    );
    let grants_june = one_grant(&cap_june);
    kernel
        .check_and_increment_budget("req-june", &cap_june, &grants_june)
        .expect("june charge admitted");
    assert_eq!(committed_units(&kernel, &term_june), 40);
    assert_eq!(
        committed_units(&kernel, &term_july),
        0,
        "the july row is not yet materialized"
    );

    let cap_july = make_freetier_cap(
        "cap-july",
        WINDOW_JULY_ISSUED_AT,
        make_grant_in(40, 1_000, FT_UNIT),
    );
    let grants_july = one_grant(&cap_july);
    kernel
        .check_and_increment_budget("req-july", &cap_july, &grants_july)
        .expect("july charge admitted");
    assert_eq!(
        committed_units(&kernel, &term_july),
        40,
        "the fresh july row starts at zero and now holds exactly one allotment"
    );
    assert_eq!(
        committed_units(&kernel, &term_june),
        40,
        "the june row is unchanged by the july charge"
    );
}

// 6. Deterministic two-thread atomicity: the per-Pass hold, the pool hold, and
//    the compensating reversal run under ONE budget-store lock. With a ceiling of
//    exactly one allotment, two racing charges produce a deterministic result:
//    exactly one Allow, and a committed pool total of exactly one allotment (the
//    ceiling is never overrun / double-credited).
#[test]
fn concurrent_free_tier_charges_are_atomic_against_the_pool_ceiling() {
    use std::sync::{Arc, Barrier};

    const ALLOT: u64 = 70;
    let kernel = Arc::new(pool_kernel(ALLOT));
    let term =
        FreeTierPoolConfig::window_ym_from_issued_at(WINDOW_JUNE_ISSUED_AT).expect("window term");
    let barrier = Arc::new(Barrier::new(2));

    let mut handles = Vec::new();
    for i in 0..2 {
        let kernel = kernel.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let cap = make_freetier_cap(
                &format!("cap-race-{i}"),
                WINDOW_JUNE_ISSUED_AT,
                make_grant_in(ALLOT, ALLOT, FT_UNIT),
            );
            let grants = one_grant(&cap);
            barrier.wait();
            kernel
                .check_and_increment_budget(&format!("req-race-{i}"), &cap, &grants)
                .is_ok()
        }));
    }

    let admitted = handles
        .into_iter()
        .map(|handle| handle.join().expect("race thread joins"))
        .filter(|ok| *ok)
        .count();
    assert_eq!(
        admitted, 1,
        "exactly one of the two racing charges is admitted"
    );
    assert_eq!(
        committed_units(&kernel, &term),
        ALLOT,
        "the pool committed total never exceeds the one-allotment ceiling"
    );
}

// 7. Symmetric reversal: cancelling a free-tier charge releases BOTH the per-Pass
//    hold AND the aggregate pool hold (no stale pool exposure).
#[test]
fn cancelling_a_charge_reverses_both_per_pass_and_pool_holds() {
    let kernel = pool_kernel(1_000_000);
    let term =
        FreeTierPoolConfig::window_ym_from_issued_at(WINDOW_JUNE_ISSUED_AT).expect("window term");
    let cap = make_freetier_cap(
        "cap-reverse",
        WINDOW_JUNE_ISSUED_AT,
        make_grant_in(60, 1_000, FT_UNIT),
    );
    let grants = one_grant(&cap);

    let (_idx, mutation) = kernel
        .check_and_increment_budget("req-reverse", &cap, &grants)
        .expect("free-tier charge admitted");
    let charge = match mutation {
        PreExecutionBudgetMutation::Charge(charge) => charge,
        _ => panic!("expected a free-tier monetary charge"),
    };
    assert!(
        charge.free_tier_pool_hold.is_some(),
        "a free-tier charge must carry a pool hold"
    );
    assert_eq!(committed_units(&kernel, &cap.id), 60, "per-Pass hold present");
    assert_eq!(committed_units(&kernel, &term), 60, "pool hold present");

    kernel
        .reverse_budget_charge(&cap.id, &charge)
        .expect("reversal succeeds");
    assert_eq!(
        committed_units(&kernel, &cap.id),
        0,
        "the per-Pass hold is released"
    );
    assert_eq!(
        committed_units(&kernel, &term),
        0,
        "the pool hold is released symmetrically"
    );
}

// 8. GATE 1 (headline evidence): a board-approved pool of exactly three
//    allotments. Four DISTINCT-subject Passes in the SAME window each draw one
//    XCC allotment. The first three are admitted; the fourth is denied
//    fail-closed with nothing charged, the pool sits at EXACTLY its ceiling, and
//    the denied Pass keeps a zero committed balance. Generosity-insolvency
//    degrades the gift to read-only; the treasury never overspends.
#[test]
fn gate_1_pool_exhaustion_fails_closed_treasury_never_overspends() {
    const ALLOT: u64 = 100;
    const POOL: u64 = 3 * ALLOT;
    let kernel = pool_kernel(POOL);
    let term =
        FreeTierPoolConfig::window_ym_from_issued_at(WINDOW_JUNE_ISSUED_AT).expect("window term");

    for i in 0..3 {
        let cap = make_freetier_cap(
            &format!("cap-gate1-{i}"),
            WINDOW_JUNE_ISSUED_AT,
            make_grant_in(ALLOT, ALLOT, FT_UNIT),
        );
        let grants = one_grant(&cap);
        let (_idx, mutation) = kernel
            .check_and_increment_budget(&format!("req-gate1-{i}"), &cap, &grants)
            .unwrap_or_else(|e| panic!("pass {i} must be admitted, got {e}"));
        match &mutation {
            PreExecutionBudgetMutation::Charge(charge) => {
                assert_eq!(
                    charge.cost_charged, ALLOT,
                    "pass {i} charges exactly one allotment"
                );
                let hold = charge
                    .free_tier_pool_hold
                    .as_ref()
                    .expect("each admitted Pass debits the shared pool");
                assert_eq!(
                    hold.term_id, term,
                    "every Pass in the window debits the same pool row"
                );
                assert_eq!(hold.units, ALLOT);
            }
            _ => panic!("pass {i} expected a free-tier monetary charge"),
        }
    }
    assert_eq!(
        committed_units(&kernel, &term),
        POOL,
        "the pool is now exactly full (three allotments held)"
    );

    // The fourth distinct Pass: the gift is insolvent for this window.
    let cap4 = make_freetier_cap(
        "cap-gate1-3",
        WINDOW_JUNE_ISSUED_AT,
        make_grant_in(ALLOT, ALLOT, FT_UNIT),
    );
    let grants4 = one_grant(&cap4);
    let committed_before = committed_units(&kernel, &cap4.id);

    let err = expect_denied(
        kernel.check_and_increment_budget("req-gate1-3", &cap4, &grants4),
        "the fourth Pass must be denied (Verdict::Deny at the pipeline)",
    );
    // BudgetExhausted is the pre-execution deny the pipeline renders as
    // Verdict::Deny with cost_charged == 0.
    assert!(
        matches!(&err, KernelError::BudgetExhausted(id) if *id == cap4.id),
        "the deny is scoped to the fourth Pass, got {err}"
    );

    // cost_charged == 0: nothing stuck to the denied Pass. Its committed row is
    // unchanged at zero (the per-Pass hold was authorized then reversed).
    assert_eq!(
        committed_units(&kernel, &cap4.id),
        committed_before,
        "the denying (cap.id, grant_index 0) row is unchanged"
    );
    assert_eq!(
        committed_units(&kernel, &cap4.id),
        0,
        "the denied Pass keeps a zero committed balance"
    );

    // The pool row is UNCHANGED by the denied charge: committed == ceiling.
    assert_eq!(
        committed_units(&kernel, &term),
        POOL,
        "pool committed == monthly_pool_units exactly; the treasury never overspends"
    );

    // budget_remaining == 0: the pool is fully drawn and admits nothing further.
    let remaining = POOL - committed_units(&kernel, &term);
    assert_eq!(remaining, 0, "the pool budget_remaining is 0");
}

#[test]
fn gate_1_pipeline_renders_pool_exhaustion_as_verdict_deny() {
    // Full-pipeline form of the Gate-1 ceiling proof: three canonical Passes
    // fill the pool through evaluate_tool_call_blocking, then the fourth
    // distinct holder's charge renders as Verdict::Deny with the pool row
    // unchanged at the ceiling and nothing stuck to the denied Pass.
    use chio_core::capability::scope::{MonetaryAmount, Operation};
    use chio_core::capability::token::{window_scoped_capability_id, AttestationWindowId};
    use chrono::{DateTime, Datelike, Months, TimeZone, Utc};

    const ALLOT: u64 = 100;
    const POOL: u64 = 3 * ALLOT;

    // Current calendar-month window, computed dynamically so the test is not a
    // wall-clock time bomb.
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
    let window = AttestationWindowId {
        window_ym: month_start.format("%Y-%m").to_string(),
        since: month_start.timestamp() as u64,
        until: next_month.timestamp() as u64,
    };
    let term = FreeTierPoolConfig::window_ym_from_issued_at(window.since).expect("window term");

    let pool = FreeTierPoolConfig {
        monthly_pool_units: POOL,
        allotment_unit: FT_UNIT.to_string(),
        board_approval_ref: FT_BOARD_REF.to_string(),
    };
    let mut kernel = make_kernel(make_monetary_config())
        .with_free_tier_pool(pool)
        .expect("pool installs");
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost(FT_SERVER)));

    let mint_pass = |kernel: &ChioKernel, tag: &str| {
        let subject = make_keypair();
        let subject_did = format!("did:chio:{}", subject.public_key().to_hex());
        let metered = ToolGrant {
            server_id: FT_SERVER.to_string(),
            tool_name: "*".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: Some(MonetaryAmount {
                units: ALLOT,
                currency: FT_UNIT.to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: ALLOT,
                currency: FT_UNIT.to_string(),
            }),
            dpop_required: None,
        };
        let scope = ChioScope {
            grants: vec![metered],
            resource_grants: crate::pass_gating::pass_baseline_resource_grants(&subject_did)
                .expect("baseline resource grants"),
            prompt_grants: vec![],
        };
        let id = window_scoped_capability_id(&subject_did, &window).expect("window-scoped id");
        let cap = CapabilityToken::sign(
            CapabilityTokenBody {
                id,
                issuer: kernel.config.keypair.public_key(),
                subject: subject.public_key(),
                scope,
                issued_at: window.since,
                expires_at: window.until,
                delegation_chain: vec![],
            },
            &kernel.config.keypair,
        )
        .unwrap_or_else(|error| panic!("sign pass capability {tag}: {error}"));
        (subject, cap)
    };

    for i in 0..3 {
        let (_subject, cap) = mint_pass(&kernel, &format!("holder-{i}"));
        let resp = kernel
            .evaluate_tool_call_blocking(&make_request_with_arguments(
                &format!("pipeline-gate1-{i}"),
                &cap,
                "compute",
                FT_SERVER,
                serde_json::json!({}),
            ))
            .expect("pipeline evaluates");
        assert_eq!(
            resp.verdict,
            Verdict::Allow,
            "holder {i} fits inside the pool"
        );
    }
    assert_eq!(
        committed_units(&kernel, &term),
        POOL,
        "three allotments fill the pool exactly"
    );

    // The fourth distinct holder: the gift is insolvent for this window and the
    // FULL pipeline must render the exhaustion as a deny.
    let (_subject4, cap4) = mint_pass(&kernel, "holder-3");
    let resp = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "pipeline-gate1-3",
            &cap4,
            "compute",
            FT_SERVER,
            serde_json::json!({}),
        ))
        .expect("pipeline evaluates the denied charge");
    assert_eq!(
        resp.verdict,
        Verdict::Deny,
        "the fourth Pass must render as Verdict::Deny"
    );
    let metadata = resp.receipt.metadata.as_ref().expect("deny receipt metadata");
    let financial = metadata.get("financial").expect("financial metadata");
    assert_eq!(financial["settlement_status"], "not_applicable");

    // Nothing stuck: the denied Pass keeps a zero committed row and the pool is
    // unchanged at exactly the ceiling.
    assert_eq!(committed_units(&kernel, &cap4.id), 0);
    assert_eq!(
        committed_units(&kernel, &term),
        POOL,
        "the pool never overspends through the pipeline"
    );
}

// ---------------------------------------------------------------------------
// Code-review C1 + PR957 codex P2: post-execution pool reconciliation (worst-
// case hold down to realized cost) and the no-pool admission boundary that keeps
// unrelated custom private-unit budgets on the normal path while still failing
// closed for genuine XCC Pass charges. (Helpers here are independent of the
// M1-10 suite above; folded in during the m0 -> m1 flow-up merge.)
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

