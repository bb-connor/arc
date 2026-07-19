use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::aggregate_budget::{
    AggregateBudgetRootBinding, AggregateFamilyPreservationEvidence, AggregateInvocationBudget,
};
use chio_core::capability::governance::GovernedApprovalToken;
use chio_core::capability::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, VerifiedApprovalSetBody,
};
use chio_kernel::admission_operation::{
    AdmissionOperationError, AdmissionRequestBindingInput, AdmissionRequestBindingParts,
};
use chio_kernel::budget_store::{BudgetCaptureInvocationRequest, BudgetEventAuthority};
use chio_kernel::supplemental_quota::CanonicalRevocationSet;
use chio_kernel::{
    AdmissionCaptureDecision, AdmissionCaptureError, AdmissionCaptureRequest,
    AdmissionCaptureRequestInput,
};
use chio_test_support::prelude::*;
use serde::Deserialize;
use serde_json::Value;

use super::super::super::*;
use super::super::budget::{
    build_remote_admission_capture_authority, validate_composite_authorize_response,
};
use super::support::{ScriptedResponse, ScriptedResponseServer};

const EXPECTED_SCHEMA_VALID_CASES: [&str; 13] = [
    "admission_evidence_revocation_digest_tampered",
    "admission_evidence_supplemental_binding_rebound",
    "admission_request_approval_digests_not_sorted",
    "aggregate_binding_noncanonical_trailing_newline",
    "aggregate_binding_signature_tampered",
    "aggregate_budget_maximum_rebound",
    "aggregate_preservation_digest_rebound",
    "capture_checked_revocation_digest_tampered",
    "governed_token_proposal_rebound",
    "threshold_proposal_lifetime_exceeds_protocol_maximum",
    "threshold_proposal_signature_tampered",
    "verified_approval_set_not_canonically_sorted",
    "verified_approval_set_proposal_rebound",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationCorpus {
    schema: String,
    operation_format: String,
    cases: Vec<MutationCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationCase {
    id: String,
    base: String,
    mutation: Mutation,
    expected: MutationExpectation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Mutation {
    op: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    hex: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationExpectation {
    json_parse_valid: bool,
    json_schema_valid: bool,
    semantic_valid: bool,
    failure: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionRequestBindingVector {
    action_hash: String,
    policy_hash: String,
    governed_intent_hash: Option<String>,
    threshold_proposal_hash: Option<String>,
    verified_approval_set_hash: Option<String>,
    approval_token_digests: Vec<String>,
    budget_hold_reference: Option<String>,
    supplemental_authorization_reference: Option<String>,
    supplemental_authorization_digest: Option<String>,
    execution_nonce_reference: Option<String>,
}

impl AdmissionRequestBindingVector {
    fn into_native(self) -> Result<AdmissionRequestBindingInput, AdmissionOperationError> {
        AdmissionRequestBindingInput::new(AdmissionRequestBindingParts {
            action_hash: self.action_hash,
            policy_hash: self.policy_hash,
            governed_intent_hash: self.governed_intent_hash,
            threshold_proposal_hash: self.threshold_proposal_hash,
            verified_approval_set_hash: self.verified_approval_set_hash,
            approval_token_digests: self.approval_token_digests,
            budget_hold_reference: self.budget_hold_reference,
            supplemental_authorization_reference: self.supplemental_authorization_reference,
            supplemental_authorization_digest: self.supplemental_authorization_digest,
            execution_nonce_reference: self.execution_nonce_reference,
        })
    }
}

#[test]
fn schema_valid_protocol_primitive_mutations_are_rejected_by_native_semantics() {
    let corpus: MutationCorpus =
        serde_json::from_slice(&read_vector("mutations-v1.json")).test_unwrap();
    assert_eq!(
        corpus.schema,
        "chio.test-vector.protocol-primitives.mutations.v1"
    );
    assert_eq!(
        corpus.operation_format,
        "RFC 6902 single-operation subset plus append_bytes"
    );

    let expected_ids = EXPECTED_SCHEMA_VALID_CASES
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual_ids = corpus
        .cases
        .iter()
        .filter(|case| case.expected.json_schema_valid)
        .map(|case| case.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_ids, expected_ids);

    let mut rejected_ids = BTreeSet::new();
    for case in corpus
        .cases
        .iter()
        .filter(|case| case.expected.json_schema_valid)
    {
        assert!(case.expected.json_parse_valid, "case {}", case.id);
        assert!(!case.expected.semantic_valid, "case {}", case.id);
        assert!(rejected_ids.insert(case.id.as_str()), "case {}", case.id);
        let mutated = apply_mutation(case);
        assert!(
            serde_json::from_slice::<Value>(&mutated).is_ok(),
            "schema-valid case {} stopped being JSON-parseable",
            case.id
        );

        match case.id.as_str() {
            "aggregate_binding_noncanonical_trailing_newline" => {
                assert_case_contract(
                    case,
                    "positive/aggregate-budget-root-binding-v1.json",
                    "noncanonical_binding_bytes",
                );
                let positive = read_vector(&case.base);
                AggregateBudgetRootBinding::from_canonical_bytes(&positive).test_unwrap();
                assert!(AggregateBudgetRootBinding::from_canonical_bytes(&mutated).is_err());
            }
            "aggregate_binding_signature_tampered" => {
                assert_case_contract(
                    case,
                    "positive/aggregate-budget-root-binding-v1.json",
                    "invalid_root_binding_signature",
                );
                let positive = read_vector(&case.base);
                AggregateBudgetRootBinding::from_canonical_bytes(&positive).test_unwrap();
                assert!(AggregateBudgetRootBinding::from_canonical_bytes(&mutated).is_err());
            }
            "aggregate_budget_maximum_rebound" => {
                assert_case_contract(
                    case,
                    "positive/aggregate-invocation-budget-v1.json",
                    "root_maximum_mismatch",
                );
                let positive: AggregateInvocationBudget = load_vector(&case.base);
                positive.validate_root_binding().test_unwrap();
                let candidate: AggregateInvocationBudget =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(candidate.validate_root_binding().is_err());
            }
            "aggregate_preservation_digest_rebound" => {
                assert_case_contract(
                    case,
                    "positive/aggregate-family-preservation-evidence-v1.json",
                    "family_binding_digest_mismatch",
                );
                let budget: AggregateInvocationBudget =
                    load_vector("positive/aggregate-invocation-budget-v1.json");
                budget.validate_root_binding().test_unwrap();
                let positive: AggregateFamilyPreservationEvidence = load_vector(&case.base);
                positive.validate_against_budget(&budget).test_unwrap();
                let candidate: AggregateFamilyPreservationEvidence =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(candidate.validate_against_budget(&budget).is_err());
            }
            "threshold_proposal_lifetime_exceeds_protocol_maximum" => {
                assert_case_contract(
                    case,
                    "positive/threshold-approval-proposal-body-v1.json",
                    "proposal_window_exceeds_3600_seconds",
                );
                let positive: ThresholdApprovalProposalBody = load_vector(&case.base);
                positive.validate().test_unwrap();
                let candidate: ThresholdApprovalProposalBody =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(candidate.validate().is_err());
            }
            "threshold_proposal_signature_tampered" => {
                assert_case_contract(
                    case,
                    "positive/threshold-approval-proposal-v1.json",
                    "invalid_policy_authority_signature",
                );
                let positive: ThresholdApprovalProposal = load_vector(&case.base);
                assert!(positive.verify_signature().test_unwrap());
                let candidate: ThresholdApprovalProposal =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(!candidate.verify_signature().test_unwrap());
            }
            "governed_token_proposal_rebound" => {
                assert_case_contract(
                    case,
                    "positive/governed-approval-token-alice-v1.json",
                    "approval_proposal_binding_or_signature",
                );
                let proposal: ThresholdApprovalProposal =
                    load_vector("positive/threshold-approval-proposal-v1.json");
                assert!(proposal.verify_signature().test_unwrap());
                let proposal_hash = proposal.proposal_hash().test_unwrap();
                let positive: GovernedApprovalToken = load_vector(&case.base);
                assert_eq!(
                    positive.threshold_proposal_hash.as_deref(),
                    Some(proposal_hash.as_str())
                );
                assert!(positive.verify_signature().test_unwrap());
                let candidate: GovernedApprovalToken =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(!candidate.verify_signature().test_unwrap());
            }
            "verified_approval_set_not_canonically_sorted" => {
                assert_case_contract(
                    case,
                    "positive/verified-approval-set-v1.json",
                    "noncanonical_approval_set_order",
                );
                let positive: VerifiedApprovalSetBody = load_vector(&case.base);
                positive.validate().test_unwrap();
                let candidate: VerifiedApprovalSetBody =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(candidate.validate().is_err());
            }
            "verified_approval_set_proposal_rebound" => {
                assert_case_contract(
                    case,
                    "positive/verified-approval-set-v1.json",
                    "verified_set_proposal_mismatch",
                );
                let proposal: ThresholdApprovalProposal =
                    load_vector("positive/threshold-approval-proposal-v1.json");
                let positive: VerifiedApprovalSetBody = load_vector(&case.base);
                positive.validate_against_proposal(&proposal).test_unwrap();
                let candidate: VerifiedApprovalSetBody =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(candidate.validate_against_proposal(&proposal).is_err());
            }
            "admission_request_approval_digests_not_sorted" => {
                assert_case_contract(
                    case,
                    "positive/admission-request-binding-v1.json",
                    "noncanonical_approval_digest_order",
                );
                let positive: AdmissionRequestBindingVector = load_vector(&case.base);
                let positive = positive.into_native().test_unwrap();
                let evidence: BudgetInvocationAdmissionEvidenceView =
                    load_vector("positive/budget-invocation-admission-evidence-v1.json");
                assert_eq!(
                    positive.derive_hash().test_unwrap(),
                    evidence
                        .supplemental_binding
                        .as_ref()
                        .test_unwrap()
                        .request_binding_hash
                );
                let candidate: AdmissionRequestBindingVector =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(candidate.into_native().is_err());
            }
            "admission_evidence_revocation_digest_tampered" => {
                assert_case_contract(
                    case,
                    "positive/budget-invocation-admission-evidence-v1.json",
                    "revocation_set_digest_mismatch",
                );
                let positive: BudgetInvocationAdmissionEvidenceView = load_vector(&case.base);
                CanonicalRevocationSet::from_persisted_parts(
                    positive.revocation_set.ids,
                    positive.revocation_set.digest,
                )
                .test_unwrap();
                let candidate: BudgetInvocationAdmissionEvidenceView =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(CanonicalRevocationSet::from_persisted_parts(
                    candidate.revocation_set.ids,
                    candidate.revocation_set.digest,
                )
                .is_err());
            }
            "admission_evidence_supplemental_binding_rebound" => {
                assert_case_contract(
                    case,
                    "positive/budget-invocation-admission-evidence-v1.json",
                    "supplemental_request_binding_mismatch",
                );
                let positive: BudgetInvocationAdmissionEvidenceView = load_vector(&case.base);
                let request = composite_authorize_request(positive.clone());
                validate_composite_authorize_response(
                    &request,
                    composite_authorize_response(positive),
                )
                .test_unwrap();
                let candidate: BudgetInvocationAdmissionEvidenceView =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(validate_composite_authorize_response(
                    &request,
                    composite_authorize_response(candidate),
                )
                .is_err());
            }
            "capture_checked_revocation_digest_tampered" => {
                assert_case_contract(
                    case,
                    "positive/admission-capture-metadata-v1.json",
                    "capture_revocation_binding_mismatch",
                );
                let positive: AdmissionCaptureMetadataView = load_vector(&case.base);
                assert!(matches!(
                    execute_remote_capture(positive),
                    Ok(AdmissionCaptureDecision::Denied(_))
                ));
                let candidate: AdmissionCaptureMetadataView =
                    serde_json::from_slice(&mutated).test_unwrap();
                assert!(matches!(
                    execute_remote_capture(candidate),
                    Err(AdmissionCaptureError::InvalidRequest(reason))
                        if reason.contains("changed its bound identity or authority evidence")
                ));
            }
            unexpected => {
                panic!("unmapped schema-valid protocol-primitives mutation case: {unexpected}")
            }
        }
    }
    assert_eq!(rejected_ids, expected_ids);
}

fn composite_authorize_request(
    admission_evidence: BudgetInvocationAdmissionEvidenceView,
) -> CompositeBudgetAuthorizeRequest {
    CompositeBudgetAuthorizeRequest {
        operation_id: "admission-operation-vector-1".to_string(),
        request_binding_hash: "44".repeat(32),
        capability_id: "aggregate-root-vector-1".to_string(),
        grant_index: 0,
        requested_exposure_units: 1,
        max_exposure_per_invocation: Some(1),
        max_total_exposure_units: Some(10),
        hold_id: "budget-hold-vector-1".to_string(),
        event_id: "budget-authorize-vector-1".to_string(),
        admission_evidence,
    }
}

fn composite_authorize_response(
    admission_evidence: BudgetInvocationAdmissionEvidenceView,
) -> CompositeBudgetAuthorizeResponse {
    let invocation_counts_after = admission_evidence
        .invocation_quotas
        .iter()
        .cloned()
        .map(|quota| BudgetInvocationQuotaUsageView {
            quota,
            reserved_invocations_after: 1,
            captured_invocations_after: 0,
        })
        .collect();
    CompositeBudgetAuthorizeResponse {
        operation_id: "admission-operation-vector-1".to_string(),
        request_binding_hash: "44".repeat(32),
        capability_id: "aggregate-root-vector-1".to_string(),
        grant_index: 0,
        hold_id: "budget-hold-vector-1".to_string(),
        event_id: "budget-authorize-vector-1".to_string(),
        allowed: true,
        authorized_exposure_units: Some(1),
        attempted_exposure_units: None,
        committed_cost_units_after: 1,
        invocation_count_after: 1,
        invocation_counts_after,
        invocation_state: BudgetInvocationReservationStateView::Authorized,
        monetary_state: BudgetMonetaryHoldStateView::Exposed,
        admission_evidence,
        budget_authority: Some(budget_authority_view(41)),
        budget_commit: Some(budget_commit_view(41)),
    }
}

fn budget_authority_view(sequence: u64) -> BudgetAuthorityMetadataView {
    BudgetAuthorityMetadataView {
        authority_id: "budget-primary".to_string(),
        leader_url: "http://leader-a".to_string(),
        budget_term: 7,
        lease_id: "lease-7".to_string(),
        lease_epoch: 7,
        lease_expires_at: 5_000,
        lease_ttl_ms: 750,
        guarantee_level: "ha_linearizable".to_string(),
        budget_commit_index: Some(sequence),
    }
}

fn budget_commit_view(sequence: u64) -> BudgetWriteCommitView {
    BudgetWriteCommitView {
        budget_seq: sequence,
        commit_index: sequence,
        quorum_committed: true,
        quorum_size: 2,
        committed_nodes: 2,
        witness_urls: vec![
            "http://leader-a".to_string(),
            "http://follower-b".to_string(),
        ],
        authority_id: "budget-primary".to_string(),
        budget_term: 7,
        lease_id: "lease-7".to_string(),
        lease_epoch: 7,
    }
}

fn execute_remote_capture(
    metadata: AdmissionCaptureMetadataView,
) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
    let evidence: BudgetInvocationAdmissionEvidenceView =
        load_vector("positive/budget-invocation-admission-evidence-v1.json");
    let revocation_set = CanonicalRevocationSet::from_persisted_parts(
        evidence.revocation_set.ids.clone(),
        evidence.revocation_set.digest.clone(),
    )
    .test_unwrap();
    let authority = metadata.authority.as_ref().test_unwrap();
    let request = AdmissionCaptureRequest::new(AdmissionCaptureRequestInput {
        operation_id: metadata.operation_id.clone(),
        budget: BudgetCaptureInvocationRequest {
            admission_operation: Some(
                BudgetAdmissionOperationBinding::new(
                    metadata.operation_id.clone(),
                    "44".repeat(32),
                )
                .test_unwrap(),
            ),
            capability_id: "aggregate-root-vector-1".to_string(),
            grant_index: 0,
            hold_id: Some(metadata.hold_id.clone()),
            event_id: Some(metadata.event_id.clone()),
            authority: Some(BudgetEventAuthority {
                authority_id: authority.authority_id.clone(),
                lease_id: authority.lease_id.clone(),
                lease_epoch: authority.lease_epoch,
            }),
        },
        revocation_set,
        bound_revocation_set_digest: evidence.revocation_set.digest.clone(),
        authorization_artifact_digests: metadata.authorization_artifact_digests.clone(),
        aggregate_root_capability_id: metadata.aggregate_root_capability_id.clone(),
        aggregate_root_binding_digest: metadata.aggregate_root_binding_digest.clone(),
        last_observed_revocation_index: None,
    })
    .test_unwrap();
    let response = CombinedAdmissionCaptureResponse {
        operation_id: metadata.operation_id.clone(),
        request_binding_hash: "44".repeat(32),
        capability_id: "aggregate-root-vector-1".to_string(),
        grant_index: 0,
        hold_id: metadata.hold_id.clone(),
        event_id: metadata.event_id.clone(),
        outcome: AdmissionCaptureOutcomeView::DeniedRevoked,
        budget: None,
        revocation_set: evidence.revocation_set,
        revoked_capability_ids: vec!["aggregate-root-vector-1".to_string()],
        metadata,
    };
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: serde_json::to_string(&response).test_unwrap(),
        content_type: "application/json",
    }]);
    let remote = build_remote_admission_capture_authority(&server.url, "secret").test_unwrap();
    remote.capture_admission(request)
}

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/bindings/vectors/security/protocol-primitives")
}

fn read_vector(relative: &str) -> Vec<u8> {
    std::fs::read(vector_root().join(relative)).test_unwrap()
}

fn load_vector<T>(relative: &str) -> T
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_slice(&read_vector(relative)).test_unwrap()
}

fn assert_case_contract(case: &MutationCase, base: &str, failure: &str) {
    assert_eq!(case.base, base, "case {} changed base", case.id);
    assert_eq!(
        case.expected.failure, failure,
        "case {} changed expected semantic boundary",
        case.id
    );
}

fn apply_mutation(case: &MutationCase) -> Vec<u8> {
    let mut bytes = read_vector(&case.base);
    match case.mutation.op.as_str() {
        "append_bytes" => {
            assert!(case.mutation.path.is_none(), "case {}", case.id);
            assert!(case.mutation.value.is_none(), "case {}", case.id);
            bytes.extend(decode_hex(
                case.mutation.hex.as_deref().test_expect("append_bytes hex"),
            ));
            bytes
        }
        "replace" => {
            assert!(case.mutation.hex.is_none(), "case {}", case.id);
            let mut document: Value = serde_json::from_slice(&bytes).test_unwrap();
            let path = case.mutation.path.as_deref().test_expect("replace path");
            let target = document
                .pointer_mut(path)
                .unwrap_or_else(|| panic!("case {} has missing path {path}", case.id));
            *target = case.mutation.value.clone().test_expect("replace value");
            canonical_json_bytes(&document).test_unwrap()
        }
        unsupported => panic!(
            "schema-valid case {} uses unsupported mutation operation {unsupported}",
            case.id
        ),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "odd-length hex mutation");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex mutation byte"),
    }
}
