//! Real kernel collection and execution with separate durable collector/admission stores.
#[path = "threshold_kernel_lifecycle/support.rs"]
mod support;

use chio_kernel::admission_operation::{AdmissionIdentifier, AdmissionOperationStore};
use chio_kernel::threshold_approval::ThresholdApprovalCollectionPolicy;
use chio_kernel::{ThresholdApprovalCollectorState, Verdict};
use std::sync::atomic::Ordering;
use support::*;

#[test]
fn original_request_collects_after_reopen_and_execution_replays_once() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture
        .open()
        .map_err(|error| format!("initial runtime: {error}"))?;
    let mut request = fixture.request(&runtime, "restart-request")?;
    let proposal = pending(&runtime, &request)?;
    let collector = fixture.collector(&runtime, true)?;
    let registered = collector.create_proposal(proposal.clone(), now())?;
    assert_eq!(registered.submitter, Some(fixture.agent.public_key()));
    assert!(registered.require_submitter_separation);
    collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(&proposal, &fixture.reviewer)?,
        now(),
    )?;
    let before_restart = collector_bytes(&fixture)?;
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    drop(collector);
    drop(runtime);

    let runtime = fixture
        .open()
        .map_err(|error| format!("reopened runtime: {error}"))?;
    let collector = fixture.collector(&runtime, true)?;
    let retained = collector
        .get_proposal(&proposal.body.proposal_id, now())?
        .ok_or("proposal missing after restart")?;
    assert_eq!(retained.state, ThresholdApprovalCollectorState::Ready);
    assert_eq!(collector_bytes(&fixture)?, before_restart);
    let delivered = collector.deliver(&proposal.body.proposal_id, now())?;
    assert_eq!(canonical(&delivered.proposal)?, canonical(&proposal)?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    request.threshold_approval_proposal = Some(delivered.proposal);
    request.approval_tokens = delivered.tokens;
    let first = runtime
        .kernel
        .evaluate_tool_call_blocking(&request)
        .map_err(|error| {
            format!(
                "first approved execution ({} invocations): {error}",
                fixture.invocations.load(Ordering::SeqCst)
            )
        })?;
    assert_eq!(first.verdict, Verdict::Allow, "{:?}", first.reason);
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking(&request)
        .map_err(|error| format!("approved execution replay: {error}"))?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(canonical(&first.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert!(
        collector
            .deliver(&proposal.body.proposal_id, now())
            .is_err(),
        "completed operations cannot reopen collection"
    );
    drop(collector);
    drop(runtime);
    let runtime = fixture.open()?;
    let replay = runtime.kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(canonical(&first.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn collector_rechecks_revocation_after_voting_without_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "revoked-request")?;
    let proposal = pending(&runtime, &request)?;
    let collector = fixture.collector(&runtime, true)?;
    collector.create_proposal(proposal.clone(), now())?;
    collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(&proposal, &fixture.reviewer)?,
        now(),
    )?;
    let before = collector_bytes(&fixture)?;
    runtime.kernel.revoke_capability(&request.capability.id)?;
    assert!(collector
        .deliver(&proposal.body.proposal_id, now())
        .is_err());
    assert_eq!(collector_bytes(&fixture)?, before);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn collector_rechecks_current_directory_and_original_submitter() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "directory-request")?;
    let proposal = pending(&runtime, &request)?;
    let collector = fixture.collector(&runtime, true)?;
    collector.create_proposal(proposal.clone(), now())?;
    let before = collector_bytes(&fixture)?;
    let error = match collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(&proposal, &fixture.agent)?,
        now(),
    ) {
        Ok(_) => return Err("submitter was allowed to approve their own request".into()),
        Err(error) => error,
    };
    assert!(error.to_string().contains("submitter"), "{error}");
    assert_eq!(collector_bytes(&fixture)?, before);
    collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(&proposal, &fixture.reviewer)?,
        now(),
    )?;
    let mut current = fixture
        .requirement
        .write()
        .map_err(|_| "directory poisoned")?;
    *current = chio_core::capability::threshold_approval::ThresholdApprovalRequirement::new(
        current.policy_hash.clone(),
        current.threshold,
        current.eligible_approvers.clone(),
        "directory-v2".into(),
        current.timeout_seconds,
    )?;
    drop(current);
    let before = collector_bytes(&fixture)?;
    assert!(collector
        .deliver(&proposal.body.proposal_id, now())
        .is_err());
    assert_eq!(collector_bytes(&fixture)?, before);
    Ok(())
}

#[test]
fn original_context_requires_startup_and_policy_binding() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open_with_policy(&fixture.policy_hash, false)?;
    assert!(fixture.collector(&runtime, true).is_err());
    runtime.kernel.reconcile_durable_admission_startup()?;
    assert!(fixture.collector(&runtime, true).is_ok());
    assert!(runtime
        .kernel
        .create_threshold_approval_collector(
            runtime.approvals.clone(),
            ThresholdApprovalCollectionPolicy::new("f".repeat(64), true)?
        )
        .is_err());
    Ok(())
}

#[test]
fn invalid_capability_has_no_original_context_to_collect() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let mut request = fixture.request(&runtime, "invalid-request")?;
    request.capability.id.push_str("-forged");
    assert_eq!(
        runtime
            .kernel
            .evaluate_tool_call_blocking(&request)?
            .verdict,
        Verdict::Deny
    );
    assert!(runtime
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &runtime.authority.mutation_fence(),
            now() * 1000,
        )?
        .is_none());
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn collector_requires_original_admission_even_for_a_trusted_signed_proposal() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "missing-source")?;
    let proposal = pending(&runtime, &request)?;
    let mut other = Fixture::new()?;
    other.signer = fixture.signer.clone();
    other.requirement = fixture.requirement.clone();
    let empty_runtime = other.open()?;
    let collector = other.collector(&empty_runtime, true)?;
    let error = match collector.create_proposal(proposal, now()) {
        Ok(_) => return Err("a signed proposal supplied its own admission authority".into()),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("original request material is unavailable"),
        "{error}"
    );
    let count: i64 = rusqlite::Connection::open(other.directory.path().join("approvals.db"))?
        .query_row(
            "SELECT COUNT(*) FROM chio_threshold_approval_collectors",
            [],
            |row| row.get(0),
        )?;
    assert_eq!(count, 0);
    assert_eq!(other.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn collector_rejects_changed_policy_after_restart_without_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "changed-policy")?;
    let proposal = pending(&runtime, &request)?;
    let collector = fixture.collector(&runtime, true)?;
    collector.create_proposal(proposal.clone(), now())?;
    collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(&proposal, &fixture.reviewer)?,
        now(),
    )?;
    let before = collector_bytes(&fixture)?;
    drop(collector);
    drop(runtime);
    let new_policy = chio_core::sha256_hex(b"replacement policy");
    let runtime = fixture.open_with_policy(&new_policy, true)?;
    let collector = runtime.kernel.create_threshold_approval_collector(
        runtime.approvals.clone(),
        ThresholdApprovalCollectionPolicy::new(new_policy, true)?,
    )?;
    let error = match collector.deliver(&proposal.body.proposal_id, now()) {
        Ok(_) => return Err("a changed kernel policy reused original admission authority".into()),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("stale for the active policy"),
        "{error}"
    );
    assert_eq!(collector_bytes(&fixture)?, before);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn collector_checks_operator_separation_rules_and_expiry_without_mutation() -> TestResult {
    let fixture = Fixture::new()?;
    let runtime = fixture.open()?;
    let request = fixture.request(&runtime, "operator-separation")?;
    let proposal = pending(&runtime, &request)?;
    let collector = fixture.collector(&runtime, false)?;
    let record = collector.create_proposal(proposal.clone(), now())?;
    assert_eq!(record.submitter, Some(fixture.agent.public_key()));
    assert!(!record.require_submitter_separation);
    collector.submit_token(
        &proposal.body.proposal_id,
        fixture.vote(&proposal, &fixture.agent)?,
        now(),
    )?;
    let before = collector_bytes(&fixture)?;
    // Only the operator's composition policy can disable this rule. A stricter
    // current policy cannot inherit votes qualified under the weaker one.
    let stricter = fixture.collector(&runtime, true)?;
    assert!(stricter.deliver(&proposal.body.proposal_id, now()).is_err());
    assert_eq!(collector_bytes(&fixture)?, before);
    collector.deliver(&proposal.body.proposal_id, now())?;
    let before = collector_bytes(&fixture)?;
    assert!(collector
        .deliver(&proposal.body.proposal_id, proposal.body.proposal_deadline)
        .is_err());
    assert_eq!(collector_bytes(&fixture)?, before);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn collector_rejects_policy_changes_during_original_context_resolution() -> TestResult {
    let fixture = Fixture::new()?;
    let mut runtime = fixture.open()?;
    let request = fixture.request(&runtime, "racing-directory")?;
    let proposal = pending(&runtime, &request)?;
    let original = fixture
        .requirement
        .read()
        .map_err(|_| "directory poisoned")?
        .clone();
    let changed = chio_core::capability::threshold_approval::ThresholdApprovalRequirement::new(
        original.policy_hash.clone(),
        original.threshold,
        original.eligible_approvers.clone(),
        "directory-v2".into(),
        original.timeout_seconds,
    )?;
    let calls = std::sync::atomic::AtomicUsize::new(0);
    std::sync::Arc::get_mut(&mut runtime.kernel)
        .ok_or("kernel unexpectedly shared")?
        .set_threshold_approval_requirement_resolver(std::sync::Arc::new(
            move |_: &str, _: &str, _: &str| {
                Ok(Some(if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    original.clone()
                } else {
                    changed.clone()
                }))
            },
        ));
    let collector = fixture.collector(&runtime, true)?;
    let error = match collector.create_proposal(proposal, now()) {
        Ok(_) => return Err("a changed directory survived original-context validation".into()),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("threshold policy changed during collection validation"),
        "{error}"
    );
    let count: i64 = rusqlite::Connection::open(fixture.directory.path().join("approvals.db"))?
        .query_row(
            "SELECT COUNT(*) FROM chio_threshold_approval_collectors",
            [],
            |row| row.get(0),
        )?;
    assert_eq!(count, 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
