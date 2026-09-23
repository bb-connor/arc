use super::*;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationId, AdmissionOperationStore,
    QualifiedAdmissionOperationStoreExt,
};
use chio_kernel::{ToolCallOutput, Verdict};

#[allow(dead_code)]
mod support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/threshold_kernel_lifecycle/support.rs"
    ));
}

#[test]
fn approved_caller_replay_refuses_expired_lease_without_new_hold_or_event() -> support::TestResult {
    let mut fixture = support::Fixture::new()?;
    fixture.nonce_ttl_secs = Some(300);
    fixture.caller_executor = Some(chio_kernel::caller_delivery::CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "approved-replay-executor")?,
        public_key: chio_core::crypto::Keypair::generate().public_key(),
        key_epoch: 9,
    });
    let runtime = fixture.open()?;
    let mut request = fixture.request(&runtime, "approved-replay-expiry")?;
    let preflight = runtime.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
    request.execution_nonce = Some(*preflight.execution_nonce.ok_or("preflight nonce")?);
    let parked = runtime.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(parked.verdict, Verdict::PendingApproval);
    let Some(ToolCallOutput::Value(value)) = parked.output else {
        return Err("proposal".into());
    };
    let proposal: chio_core::capability::governance::ThresholdApprovalProposal =
        serde_json::from_value(value)?;
    let collector = fixture.collector(&runtime, true)?;
    collector.create_proposal(proposal.clone(), support::now())?;
    collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(&proposal, &fixture.reviewer)?,
        support::now(),
    )?;
    let delivered = collector.deliver(&proposal.body.proposal_id, support::now())?;
    request.threshold_approval_proposal = Some(delivered.proposal);
    request.approval_tokens = delivered.tokens;
    let reserved = runtime.kernel.reserve_caller_execution_blocking(&request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let connection = Connection::open(fixture.database())?;
    let (id, claimant): (String, String) = connection.query_row("SELECT operation_id,recovery_claimant_id FROM admission_operations WHERE state='ready_to_dispatch'", [], |row| Ok((row.get(0)?, row.get(1)?)))?;
    let store = runtime.authority.admission_operation_store();
    let operation = store
        .load_by_operation_id(&AdmissionOperationId::from_persisted(id)?)?
        .ok_or("operation")?;
    assert!(operation
        .provider_attempt()
        .is_some_and(|attempt| attempt.is_caller_report()));
    assert!(operation.approval_set_hash().is_some());
    let hold = operation.budget_hold_id().ok_or("hold")?;
    let event_id: String = connection.query_row("SELECT event_id FROM budget_mutation_events WHERE hold_id=?1 AND kind IN ('reserve_invocation','authorize_exposure') ORDER BY event_seq DESC LIMIT 1", [hold.as_str()], |row| row.get(0))?;
    let event = SqliteBudgetStore::load_mutation_event(&connection, &event_id)?.ok_or("event")?;
    let original = load_authorization_request(&connection, &event)?;
    let fence = runtime.authority.mutation_fence();
    let at = support::now() * 1000 + 1000;
    let claimant = AdmissionIdentifier::try_new("claimant_id", claimant)?;
    let lease = store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &claimant,
        at,
        at + 60_000,
        &fence,
    )?;
    let before = crate::tests::authority_snapshot(&connection)?;
    let anchor = runtime.authority.anchor_generation()?;
    let (decision, replayed) = store.authorize_budget_and_commit_admission(
        &operation,
        &lease,
        original.clone(),
        None,
        None,
        &fence,
        at,
    )?;
    assert!(matches!(
        decision,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert_eq!(replayed, operation);
    assert_eq!(crate::tests::authority_snapshot(&connection)?, before);
    assert_eq!(runtime.authority.anchor_generation()?, anchor);
    let _expired = chio_kernel::scope_fixed_runtime_for_current_thread(
        lease.expires_at_unix_ms() / 1000 + 1,
        [],
    );
    let refused = store.authorize_budget_and_commit_admission(
        &operation, &lease, original, None, None, &fence, at,
    );
    assert!(
        refused.is_err(),
        "expired approved-caller replay was authorized"
    );
    assert!(refused
        .err()
        .is_some_and(|error| error.to_string().contains("expired")));
    assert_eq!(crate::tests::authority_snapshot(&connection)?, before);
    assert_eq!(runtime.authority.anchor_generation()?, anchor);
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    Ok(())
}
