//! Owning-kernel eligibility checks, independent of process binding conflicts.
//! Fresh-process crash tests separately prove retained operation/hold behavior.
mod support;

use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, ThresholdApprovalProposal, ThresholdApprovalProposalBody,
    THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core_types::capability::scope::{
    Constraint, FindingRecoveryMarkerV1, MonetaryAmount, Operation,
};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_core_types::message::{ExecutionNonce, NonceBinding, SignedExecutionNonce};
use chio_kernel::{KernelError, NestedFlowBridge, ToolServerConnection};
use chio_process::ProcessRuntime;
use serde_json::{json, Value};
use support::Result;

struct ReadServer;
#[async_trait::async_trait]
impl ToolServerConnection for ReadServer {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["read".into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        tool == "read"
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Ok(arguments)
    }
}

#[test]
fn matching_stateful_grants_exclude_retry_but_unrelated_grants_do_not() -> Result {
    let dir = tempfile::tempdir()?;
    let kernel = support::kernel(dir.path(), Box::new(ReadServer))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    support::root(&runtime, &kernel, 1)?;
    let original = runtime.tool_request(
        "root",
        "read",
        "tools",
        "read",
        json!({"path": "/public/a", "finding_id": "b".repeat(64)}),
    )?;
    assert!(kernel.can_redispatch_unknown_read(&original));
    let mut aggregate = original.clone();
    aggregate.capability.aggregate_invocation_budget = Some(chio_core_types::capability::aggregate_invocation::AggregateInvocationBudget {
        scope: chio_core_types::capability::aggregate_invocation::AggregateInvocationScope::Capability,
        max_invocations: 3, root_binding: None,
    });
    assert!(!kernel.can_redispatch_unknown_read(&aggregate));
    for authority in [
        "invocations",
        "per_call_cost",
        "total_cost",
        "cumulative",
        "finding_recovery",
        "dpop",
        "matcher_error",
    ] {
        let mut request = original.clone();
        let mut constrained = request.capability.scope.grants[1].clone();
        match authority {
            "invocations" => constrained.max_invocations = Some(3),
            "per_call_cost" => {
                constrained.max_cost_per_invocation = Some(MonetaryAmount {
                    units: 3,
                    currency: "USD".into(),
                })
            }
            "total_cost" => {
                constrained.max_total_cost = Some(MonetaryAmount {
                    units: 30,
                    currency: "USD".into(),
                })
            }
            "cumulative" => {
                constrained
                    .constraints
                    .push(Constraint::RequireCumulativeApprovalAbove {
                        threshold: MonetaryAmount {
                            units: 3,
                            currency: "USD".into(),
                        },
                        approval_budget_id: "approval-budget".into(),
                        approval_budget_epoch: 1,
                        cumulative_approval_root_binding: None,
                    })
            }
            "finding_recovery" => constrained
                .constraints
                .push(Constraint::RequireFindingRecovery(Box::new(
                    FindingRecoveryMarkerV1 {
                        recovery_id: "a".repeat(64),
                        finding_id: "b".repeat(64),
                        listing_id: "listing".into(),
                        original_capability_id: request.capability.id.clone(),
                        original_delivery_receipt_id: "c".repeat(64),
                        purchase_key: "d".repeat(64),
                        max_recoveries: 3,
                    },
                ))),
            "dpop" => constrained.dpop_required = Some(true),
            _ => constrained
                .constraints
                .push(Constraint::RegexMatch("[".into())),
        }
        request.capability.scope.grants.push(constrained.clone());
        assert!(!kernel.can_redispatch_unknown_read(&request), "{authority}");
        for unrelated in ["name", "permission", "path"] {
            let mut request = original.clone();
            let mut grant = constrained.clone();
            match unrelated {
                "name" => grant.tool_name = "other-tool".into(),
                "permission" => grant.operations = vec![Operation::ReadResult],
                _ => grant
                    .constraints
                    .insert(0, Constraint::PathPrefix("/private".into())),
            }
            request.capability.scope.grants.push(grant);
            assert!(
                kernel.can_redispatch_unknown_read(&request),
                "{authority}, unrelated {unrelated}"
            );
        }
    }
    let mut delivery = original;
    delivery.arguments["finding_delivery_receipt_id"] = json!("retained-delivery");
    assert!(!kernel.can_redispatch_unknown_read(&delivery));
    Ok(())
}

#[test]
fn original_request_bound_artifacts_individually_exclude_new_id_eligibility() -> Result {
    let dir = tempfile::tempdir()?;
    let kernel = support::kernel(dir.path(), Box::new(ReadServer))?;
    let runtime = ProcessRuntime::open(dir.path().join("process.db"), kernel.clone())?;
    support::root(&runtime, &kernel, 1)?;
    let original = runtime.tool_request("root", "read", "tools", "read", json!({}))?;
    assert!(kernel.can_redispatch_unknown_read(&original));
    let key = support::parent_key();
    let intent: GovernedTransactionIntent = serde_json::from_value(
        json!({"id": "intent", "server_id": "tools", "tool_name": "read", "purpose": "read once"}),
    )?;
    let approval = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval".into(),
            approver: key.public_key(),
            subject: original.capability.subject.clone(),
            governed_intent_hash: intent.binding_hash()?,
            request_id: original.request_id.clone(),
            threshold_proposal_hash: None,
            issued_at: original.capability.issued_at,
            expires_at: original.capability.expires_at,
            decision: GovernedApprovalDecision::Approved,
        },
        &key,
    )?;
    let proposal = ThresholdApprovalProposal::sign(
        ThresholdApprovalProposalBody {
            schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.into(),
            proposal_id: "proposal".into(),
            request_id: original.request_id.clone(),
            governed_intent_hash: intent.binding_hash()?,
            subject: original.capability.subject.clone(),
            authorizing_capability_digest: sha256_hex(&canonical_json_bytes(&original.capability)?),
            policy_hash: "a".repeat(64),
            threshold: 1,
            eligible_set_digest: "b".repeat(64),
            proposal_created_at: original.capability.issued_at,
            proposal_deadline: original.capability.expires_at,
            policy_authority: key.public_key(),
        },
        &key,
    )?;
    for artifact in [
        "dpop",
        "execution_nonce",
        "intent",
        "approval",
        "approval_set",
        "proposal",
        "supplemental",
    ] {
        let mut request = original.clone();
        match artifact {
            "dpop" => request.dpop_proof = Some(chio_kernel::dpop::DpopProof::sign(chio_kernel::dpop::DpopProofBody {
                schema: chio_kernel::dpop::DPOP_SCHEMA.into(), replay_authority: None,
                capability_id: request.capability.id.clone(), tool_server: request.server_id.clone(), tool_name: request.tool_name.clone(),
                action_hash: sha256_hex(&canonical_json_bytes(&request.arguments)?), nonce: request.request_id.clone(),
                issued_at: request.capability.issued_at, agent_key: key.public_key(),
            }, &key)?),
            "execution_nonce" => {
                let nonce = ExecutionNonce { schema: "chio.execution-nonce.v1".into(), nonce_id: "nonce".into(), issued_at: i64::try_from(request.capability.issued_at)?, expires_at: i64::try_from(request.capability.expires_at)?,
                    bound_to: NonceBinding { subject_id: request.agent_id.clone(), request_id: request.request_id.clone(), capability_id: request.capability.id.clone(), tool_server: request.server_id.clone(), tool_name: request.tool_name.clone(), parameter_hash: sha256_hex(&canonical_json_bytes(&request.arguments)?) }, reserved_hold_id: None, reserving_request_id: None };
                let signature = support::issuer().sign_canonical(&nonce)?.0;
                request.execution_nonce = Some(SignedExecutionNonce { nonce, signature });
            }
            "intent" => request.governed_intent = Some(intent.clone()),
            "approval" => request.approval_token = Some(approval.clone()),
            "approval_set" => request.approval_tokens = vec![approval.clone()],
            "proposal" => request.threshold_approval_proposal = Some(proposal.clone()),
            _ => request.supplemental_authorization = Some(chio_core_types::capability::supplemental_authorization::OpaqueSupplementalAuthorization { signed_extension: "original-request-bound-extension".into() }),
        }
        // Classify the artifact-bearing original request itself. No second
        // process admission or changed-binding Conflict can satisfy this check.
        assert_eq!(request.request_id, runtime.request_id("root", "read")?);
        assert!(!kernel.can_redispatch_unknown_read(&request), "{artifact}");
    }
    Ok(())
}
