//! Public consumer execution with signed capabilities and real SQLite custody.

#[path = "consumer_boundary/support.rs"]
mod support;

use chio_kernel::{budget_store::BudgetQuotaKey, BudgetStore};
use std::sync::atomic::Ordering;
use support::*;

fn aggregate_restart(protocol: Protocol) -> TestResult {
    let fixture = Fixture::new()?;
    let request = fixture.request("aggregate-first")?;
    let mut consumer = fixture.open(protocol)?;
    let first = consumer.invoke(&request)?;
    assert_eq!(first.decision, "allow", "{:?}", first.receipt);
    assert_eq!(first.receipt.kernel_key, fixture.signer.public_key());
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert!(!first.output.is_null());
    let quota = consumer
        .authority
        .budget_store()
        .get_invocation_quota_usage(&BudgetQuotaKey::grant(request.capability.id.clone(), 0))?
        .ok_or("grant usage")?;
    assert_eq!(quota.captured_invocations, 1);
    drop(consumer);
    let mut consumer = fixture.open(protocol)?;
    let replay = consumer.invoke(&request)?;
    assert_eq!(replay.decision, "allow");
    assert_eq!(
        chio_core::canonical_json_bytes(&first.receipt)?,
        chio_core::canonical_json_bytes(&replay.receipt)?
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    let second = consumer.invoke(&fixture.request("aggregate-exhausted")?)?;
    assert_eq!(second.decision, "deny");
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

fn threshold_restart(protocol: Protocol) -> TestResult {
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        ThresholdApprovalProposal,
    };
    let fixture = Fixture::new()?.with_threshold_approval()?;
    let mut request = fixture.request("threshold-operation")?;
    request.governed_intent = Some(serde_json::from_value(serde_json::json!({
        "id":"threshold-intent", "server_id":SERVER, "tool_name":TOOL,
        "purpose":"authorize one counted consumer invocation", "max_amount":{"units":100,"currency":"USD"}
    }))?);
    let mut consumer = fixture.open(protocol)?;
    let pending = consumer.invoke(&request)?;
    assert_eq!(
        pending.decision, "pending_approval",
        "{:?}",
        pending.receipt
    );
    assert_eq!(pending.output["status"], "pending_approval");
    let proposal: ThresholdApprovalProposal =
        serde_json::from_value(pending.output["proposal"].clone())?;
    assert!(proposal.verify_signature()?);
    assert_eq!(proposal.body.policy_authority, fixture.signer.public_key());
    assert_eq!(proposal.body.request_id, request.request_id);
    assert_eq!(proposal.body.threshold, 2);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
    let proposal_hash = proposal.artifact_digest()?;
    let intent_hash = request
        .governed_intent
        .as_ref()
        .ok_or("intent")?
        .binding_hash()?;
    request.approval_tokens = fixture
        .approvers
        .iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("consumer-approval-{index}"),
                    approver: approver.public_key(),
                    subject: fixture.agent.public_key(),
                    governed_intent_hash: intent_hash.clone(),
                    request_id: request.request_id.clone(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    issued_at: proposal.body.proposal_created_at,
                    expires_at: proposal.body.proposal_deadline,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    request.threshold_approval_proposal = Some(proposal);
    let completed = consumer.invoke(&request)?;
    assert_eq!(completed.decision, "allow", "{:?}", completed.receipt);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    drop(consumer);
    let mut consumer = fixture.open(protocol)?;
    let replay = consumer.invoke(&request)?;
    assert_eq!(replay.decision, "allow", "{:?}", replay.receipt);
    assert_eq!(
        chio_core::canonical_json_bytes(&completed.receipt)?,
        chio_core::canonical_json_bytes(&replay.receipt)?
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn native_aggregate_capture_survives_consumer_restart() -> TestResult {
    aggregate_restart(Protocol::Native)
}
#[test]
fn mcp_aggregate_capture_survives_consumer_restart() -> TestResult {
    aggregate_restart(Protocol::Mcp)
}
#[test]
fn a2a_aggregate_capture_survives_consumer_restart() -> TestResult {
    aggregate_restart(Protocol::A2a)
}
#[test]
fn acp_aggregate_capture_survives_consumer_restart() -> TestResult {
    aggregate_restart(Protocol::Acp)
}

#[test]
fn native_threshold_proposal_approval_and_restart_preserve_one_capture() -> TestResult {
    threshold_restart(Protocol::Native)
}
#[test]
fn mcp_threshold_proposal_approval_and_restart_preserve_one_capture() -> TestResult {
    threshold_restart(Protocol::Mcp)
}
#[test]
fn a2a_threshold_proposal_approval_and_restart_preserve_one_capture() -> TestResult {
    threshold_restart(Protocol::A2a)
}
#[test]
fn acp_threshold_proposal_approval_and_restart_preserve_one_capture() -> TestResult {
    threshold_restart(Protocol::Acp)
}
