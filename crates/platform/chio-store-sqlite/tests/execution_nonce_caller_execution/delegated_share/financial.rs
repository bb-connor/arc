use super::*;
use chio_core::capability::scope::MonetaryAmount;
use chio_kernel::{BudgetStore, FinancialReceiptMetadata, SettlementStatus, ToolInvocationCost};

fn monetary_siblings(fixture: &Fixture, runtime: &mut Runtime) -> TestResult<Siblings> {
    let parent_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: SERVER_ID.into(),
            tool_name: TOOL_NAME.into(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: Vec::new(),
            max_invocations: Some(4),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 40,
                currency: "USD".into(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 150,
                currency: "USD".into(),
            }),
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let parent =
        runtime
            .kernel
            .issue_capability(&fixture.agent.public_key(), parent_scope.clone(), 600)?;
    let mut child_scope = parent_scope;
    child_scope.grants[0].operations = vec![Operation::Invoke];
    let child = |id: &str| -> TestResult<CapabilityToken> {
        let agent = Keypair::generate();
        let parent_scope_hash = scope_hash(&parent.scope)?;
        let link = DelegationLink::sign(
            DelegationLinkBody {
                capability_id: parent.id.clone(),
                delegator: fixture.agent.public_key(),
                delegatee: agent.public_key(),
                attenuations: Vec::new(),
                timestamp: parent.issued_at,
                scope_hash: Some(parent_scope_hash.clone()),
                aggregate_budget: None,
                cumulative_approval: None,
            },
            &fixture.agent,
        )?;
        Ok(CapabilityToken::sign_attenuated(
            CapabilityTokenAttenuationBody {
                body: CapabilityTokenBody {
                    id: format!("{}:{id}", parent.id),
                    issuer: fixture.signer.public_key(),
                    subject: agent.public_key(),
                    scope: child_scope.clone(),
                    issued_at: parent.issued_at,
                    expires_at: parent.expires_at,
                    delegation_chain: vec![link],
                    aggregate_invocation_budget: None,
                },
                caveats: Vec::new(),
                scope_attenuations: Vec::new(),
                attenuation_proof: AttenuationProof {
                    parent_scope_hash,
                    child_scope_hash: scope_hash(&child_scope)?,
                    normalized_subset_proof: compute_attenuation_witness(
                        &parent.scope,
                        &child_scope,
                    )?,
                },
                budget_share_bps: Some(4_000),
            },
            &fixture.signer,
        )?)
    };
    let first = child("monetary-child-a")?;
    let second = child("monetary-child-b")?;
    let siblings = Siblings {
        parent,
        first,
        second,
    };
    siblings.configure(fixture, runtime)?;
    Ok(siblings)
}

fn assert_usage(runtime: &Runtime, request: &ToolCallRequest, expected: (u64, u64)) -> TestResult {
    let usage = runtime
        .authority
        .budget_store()
        .get_usage(&request.capability.id, 0)?
        .ok_or("monetary grant usage")?;
    assert_eq!(
        (usage.total_cost_exposed, usage.total_cost_realized_spend),
        expected
    );
    Ok(())
}

fn assert_sibling_blocked(runtime: &Runtime, siblings: &Siblings, request_id: &str) -> TestResult {
    let blocked = runtime
        .kernel
        .reserve_caller_execution_blocking(&request(&siblings.second, request_id)?)?;
    assert_eq!(blocked.verdict, Verdict::Deny, "{:?}", blocked.reason);
    assert_eq!(
        blocked.reason,
        Some(format!(
            "sibling-sum budget admission failed: child {} share 4000 bps + sibling sum 4000 bps > parent share 5000 bps",
            siblings.second.id
        ))
    );
    Ok(())
}

fn assert_payment(fixture: &Fixture, expected_state: &str) -> TestResult {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.directory.path().join("local-payments.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let payment: (u64, String, u64) = connection.query_row(
        "SELECT count(*), min(state), sum(amount_units) FROM chio_finding_operator_payments",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(payment, (1, expected_state.into(), 40));
    Ok(())
}

#[test]
fn monetary_delegated_reservation_retains_share_until_signed_settlement_after_restart() -> TestResult
{
    let (mut fixture, key) = crate::authenticated::fixture()?;
    fixture.local_payment_rail = true;
    let (siblings, first) = {
        let mut runtime = fixture.open()?;
        let siblings = monetary_siblings(&fixture, &mut runtime)?;
        let first = reserve_child(&runtime, &request(&siblings.first, "monetary-share-first")?)?;
        assert_usage(&runtime, &first, (40, 0))?;
        assert_eq!(grant_quota(&runtime, &first)?, (1, 0));
        assert_sibling_blocked(&runtime, &siblings, "monetary-share-before-restart")?;
        (siblings, first)
    };
    let mut runtime = fixture.open_with_reconcile(false)?;
    siblings.configure(&fixture, &mut runtime)?;
    runtime.kernel.reconcile_durable_admission_startup()?;
    assert_state(&fixture, &first, "ready_to_dispatch")?;
    assert_usage(&runtime, &first, (40, 0))?;
    assert_eq!(grant_quota(&runtime, &first)?, (1, 0));
    assert_sibling_blocked(&runtime, &siblings, "monetary-share-after-restart")?;

    let authorization = crate::authenticated::start(&runtime, &first)?;
    assert_payment(&fixture, "held")?;
    assert_usage(&runtime, &first, (40, 0))?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    let ledger = crate::authenticated::ledger(&fixture)?;
    let effects = std::sync::atomic::AtomicUsize::new(0);
    let report = ledger.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        &key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(CallerExecutionReport {
                output: serde_json::json!({"external": true}),
                realized_cost: Some(ToolInvocationCost {
                    units: 40,
                    currency: "USD".into(),
                    breakdown: None,
                }),
            })
        },
    )?;
    let settled = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(settled.verdict, Verdict::Allow, "{:?}", settled.reason);
    assert!(settled.receipt.verify_signature()?);
    assert_state(&fixture, &first, "completed")?;
    let financial: FinancialReceiptMetadata = serde_json::from_value(
        settled
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("financial"))
            .ok_or("signed financial metadata")?
            .clone(),
    )?;
    assert_eq!(financial.grant_index, 0);
    assert_eq!(financial.cost_charged, 40);
    assert_eq!(financial.currency, "USD");
    assert_eq!(financial.budget_total, Some(150));
    assert_eq!(financial.budget_remaining, Some(110));
    assert_eq!(first.capability.delegation_chain.len(), 1);
    assert_eq!(financial.delegation_depth, 1);
    assert_eq!(
        financial.root_budget_holder,
        fixture.signer.public_key().to_hex()
    );
    assert_ne!(
        financial.root_budget_holder,
        first.capability.subject.to_hex()
    );
    assert_eq!(financial.settlement_status, SettlementStatus::Settled);
    assert_usage(&runtime, &first, (0, 40))?;
    assert_payment(&fixture, "captured")?;

    let replay = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(canonical(&settled.receipt)?, canonical(&replay.receipt)?);
    assert_usage(&runtime, &first, (0, 40))?;
    assert_eq!(grant_quota(&runtime, &first)?, (0, 1));
    let second = reserve_child(
        &runtime,
        &request(&siblings.second, "monetary-share-after-settlement")?,
    )?;
    assert_usage(&runtime, &second, (40, 0))?;
    assert_payment(&fixture, "captured")?;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
