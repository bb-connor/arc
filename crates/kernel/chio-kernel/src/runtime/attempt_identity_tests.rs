use super::ToolCallRequest;
use crate::admission_operation::RetainedToolAdmissionRequestV1;
use crate::dpop::{DpopProof, DpopProofBody, DPOP_SCHEMA};
use crate::execution_nonce::{mint_execution_nonce, ExecutionNonceConfig, NonceBinding};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core_types::capability::scope::ChioScope;
use chio_core_types::capability::supplemental_authorization::OpaqueSupplementalAuthorization;
use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core_types::crypto::Keypair;
use chio_core_types::SignedDeclassificationGrant;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn digest(label: &str) -> String {
    chio_core_types::sha256_hex(label.as_bytes())
}

fn fully_populated_request() -> Result<ToolCallRequest, Box<dyn std::error::Error>> {
    let issuer = Keypair::generate();
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability-identity".into(),
            issuer: issuer.public_key(),
            subject: issuer.public_key(),
            scope: ChioScope::default(),
            issued_at: 1,
            expires_at: 2,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )?;
    let token = GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: "approval-identity".into(),
            approver: issuer.public_key(),
            subject: issuer.public_key(),
            governed_intent_hash: digest("intent"),
            request_id: "request-identity".into(),
            threshold_proposal_hash: None,
            issued_at: 1,
            expires_at: 2,
            decision: GovernedApprovalDecision::Approved,
        },
        &issuer,
    )?;
    let declassification_body = serde_json::from_value(json!({
        "domain_version": 1, "grant_id": "grant-identity",
        "capability_id": "capability-identity", "tenant_id": "tenant-identity",
        "subject_id": "subject-identity", "agent_id": "agent-identity",
        "session_id": "session-identity", "source_label_hash": vec![1; 32],
        "target_label": {"kind": "known", "owners": {}, "compartments": []},
        "destination_id": "server-identity", "tool_name": "tool-identity",
        "purpose": "identity", "request_hash": vec![2; 32],
        "issued_at_unix_seconds": 100, "expires_at_unix_seconds": 200,
        "authority_key_id": "authority-identity"
    }))?;
    Ok(ToolCallRequest {
        request_id: "request-identity".into(),
        agent_id: issuer.public_key().to_hex(),
        tool_name: "tool-identity".into(),
        server_id: "server-identity".into(),
        arguments: json!({"record": "identity"}),
        dpop_proof: Some(DpopProof::sign(
            DpopProofBody {
                schema: DPOP_SCHEMA.into(),
                replay_authority: crate::dpop::test_authority(),
                capability_id: "capability-identity".into(),
                tool_server: "server-identity".into(),
                tool_name: "tool-identity".into(),
                action_hash: digest("arguments"),
                nonce: "proof-nonce".into(),
                issued_at: 1,
                agent_key: issuer.public_key(),
            },
            &issuer,
        )?),
        execution_nonce: Some(mint_execution_nonce(
            &chio_core::crypto::Ed25519Backend::new(issuer.clone()),
            NonceBinding {
                subject_id: issuer.public_key().to_hex(),
                request_id: "request-identity".into(),
                capability_id: "capability-identity".into(),
                tool_server: "server-identity".into(),
                tool_name: "tool-identity".into(),
                parameter_hash: digest("arguments"),
            },
            &ExecutionNonceConfig::default(),
            1,
        )?),
        governed_intent: None,
        approval_token: Some(token.clone()),
        approval_tokens: vec![token],
        threshold_approval_proposal: Some(ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.into(),
                proposal_id: "proposal-identity".into(),
                request_id: "request-identity".into(),
                governed_intent_hash: digest("intent"),
                subject: issuer.public_key(),
                authorizing_capability_digest: digest("capability"),
                policy_hash: digest("policy"),
                threshold: 1,
                eligible_set_digest: digest("eligible"),
                proposal_created_at: 1,
                proposal_deadline: 2,
                policy_authority: issuer.public_key(),
            },
            &issuer,
        )?),
        supplemental_authorization: Some(OpaqueSupplementalAuthorization {
            signed_extension: "b3BhcXVl".into(),
        }),
        model_metadata: None,
        federated_origin_kernel_id: Some("origin-identity".into()),
        declassification_grant: Some(SignedDeclassificationGrant::sign(
            declassification_body,
            &issuer,
        )?),
        capability,
    })
}

#[test]
fn attempt_identity_clears_exactly_the_attempt_scoped_credentials() -> TestResult {
    let request = fully_populated_request()?;
    let identity = request.attempt_identity();
    // Exhaustive: a new request field fails to compile until it is classified.
    let ToolCallRequest {
        request_id,
        capability,
        tool_name,
        server_id,
        agent_id,
        arguments,
        dpop_proof,
        execution_nonce,
        governed_intent,
        approval_token,
        approval_tokens,
        threshold_approval_proposal,
        supplemental_authorization,
        model_metadata,
        federated_origin_kernel_id,
        declassification_grant,
    } = identity.clone();
    assert!(dpop_proof.is_none());
    assert!(execution_nonce.is_none());
    assert!(approval_token.is_none());
    assert!(approval_tokens.is_empty());
    assert!(threshold_approval_proposal.is_none());
    assert_eq!(request_id, request.request_id);
    assert_eq!(
        canonical_json_bytes(&capability)?,
        canonical_json_bytes(&request.capability)?
    );
    assert_eq!(tool_name, request.tool_name);
    assert_eq!(server_id, request.server_id);
    assert_eq!(agent_id, request.agent_id);
    assert_eq!(arguments, request.arguments);
    assert_eq!(
        canonical_json_bytes(&governed_intent)?,
        canonical_json_bytes(&request.governed_intent)?
    );
    assert_eq!(
        supplemental_authorization,
        request.supplemental_authorization
    );
    assert!(supplemental_authorization.is_some());
    assert_eq!(
        canonical_json_bytes(&model_metadata)?,
        canonical_json_bytes(&request.model_metadata)?
    );
    assert_eq!(
        federated_origin_kernel_id,
        request.federated_origin_kernel_id
    );
    assert_eq!(declassification_grant, request.declassification_grant);
    assert!(declassification_grant.is_some());

    let mut expected = request.clone();
    expected.dpop_proof = None;
    expected.execution_nonce = None;
    expected.approval_token = None;
    expected.approval_tokens = Vec::new();
    expected.threshold_approval_proposal = None;
    assert_eq!(
        canonical_json_bytes(&identity)?,
        canonical_json_bytes(&expected)?
    );
    Ok(())
}

#[test]
fn retention_omits_the_attempt_identity_and_its_non_retained_grants() -> TestResult {
    let request = fully_populated_request()?;
    let mut expected = request.attempt_identity();
    expected.supplemental_authorization = None;
    expected.declassification_grant = None;
    assert_eq!(
        canonical_json_bytes(
            &RetainedToolAdmissionRequestV1::request_without_transient_credentials(&request)
        )?,
        canonical_json_bytes(&expected)?
    );
    Ok(())
}
