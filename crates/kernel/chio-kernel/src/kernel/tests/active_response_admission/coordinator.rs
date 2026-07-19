use super::*;

use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
};

use crate::admission_operation::{
    AdmissionCleanupActionKind, AdmissionCleanupActionState, AdmissionDispatchState,
    AdmissionOperationKind, AdmissionOperationState, AdmissionOperationStore,
    ReplayReservationState,
};
use crate::approval::ApprovalStore;
use crate::kernel::{
    ActiveResponseAdmissionRequest, ActiveResponsePolicyResolutionError, ActiveResponseRequirement,
    PreparedActiveResponseAdmission,
};
use crate::threshold_approval::{
    ThresholdApprovalProposal, ThresholdApprovalProposalBody, ThresholdApprovalRequirement,
};

use super::super::{
    DurableThresholdApprovalStore, DurableThresholdBudgetStore, RecordingThresholdOperationStore,
};

const ACTIVE_RESPONSE_POLICY_HASH_BYTE: &str = "33";

struct GovernedCoordinatorFixture {
    fixture: ActiveResponseFixture,
    request: ActiveResponseAdmissionRequest,
    operations: Arc<RecordingThresholdOperationStore>,
    approvals: Arc<DurableThresholdApprovalStore>,
    executor_authority: Arc<RecordingActiveResponseExecutor>,
}

struct ThresholdArtifacts {
    proposal: ThresholdApprovalProposal,
    tokens: Vec<GovernedApprovalToken>,
    requirement: ThresholdApprovalRequirement,
    policy_authority: Keypair,
}

fn race_expired_termination_against_inflight_dispatch(
    kernel: Arc<ChioKernel>,
    request: ActiveResponseAdmissionRequest,
    prepared: PreparedActiveResponseAdmission,
    response_plan: ResponsePlan,
    binding: chio_security_types::ports::PreparedActiveResponseDispatchBinding,
    executor: Arc<RecordingActiveResponseExecutor>,
) -> (
    Result<ActiveResponseExecutionEvidence, KernelError>,
    Result<(), KernelError>,
    bool,
) {
    let execution_barrier = Arc::new(Barrier::new(2));
    executor.set_execution_barrier(execution_barrier.clone());
    let valid_unix_secs = request.authorization().operator_capability().issued_at;
    let expired_unix_secs = response_plan
        .expires_at_unix_ms
        .checked_div(1_000)
        .unwrap_or(0)
        .saturating_add(1);
    let execution_kernel = kernel.clone();
    let execution_request = request.clone();
    let execution_prepared = prepared.clone();
    let execution = std::thread::spawn(move || {
        let _runtime = crate::scope_fixed_runtime_for_current_thread(valid_unix_secs, Vec::new());
        execution_kernel.execute_prepared_active_response(&execution_request, &execution_prepared)
    });
    execution_barrier.wait();

    let termination_start = Arc::new(Barrier::new(2));
    let termination_worker_start = termination_start.clone();
    let termination_kernel = kernel.clone();
    let (termination_sender, termination_receiver) = mpsc::sync_channel(1);
    let termination = std::thread::spawn(move || {
        let _runtime = crate::scope_fixed_runtime_for_current_thread(expired_unix_secs, Vec::new());
        termination_worker_start.wait();
        let result = termination_kernel.terminate_never_committed_active_response(
            &response_plan,
            &binding,
            None,
        );
        termination_sender
            .send(result)
            .expect("termination result receiver");
    });
    termination_start.wait();
    let early_termination = termination_receiver.recv_timeout(Duration::from_millis(100));
    execution_barrier.wait();
    let execution_result = execution.join().expect("execution worker");
    let (termination_result, returned_before_dispatch) = match early_termination {
        Ok(result) => (result, true),
        Err(mpsc::RecvTimeoutError::Timeout) => (
            termination_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("termination must finish after dispatch"),
            false,
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("termination worker disconnected")
        }
    };
    termination.join().expect("termination worker");
    (
        execution_result,
        termination_result,
        returned_before_dispatch,
    )
}

fn active_response_policy_hash() -> String {
    ACTIVE_RESPONSE_POLICY_HASH_BYTE.repeat(32)
}

fn governed_coordinator_fixture() -> ActiveResponseFixture {
    active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    )
}

fn automatic_coordinator_fixture() -> ActiveResponseFixture {
    active_response_fixture_with_grants_and_approval(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        vec![active_response_grant(
            GovernedResponseEffect::RestrictEgress,
        )],
        ResponseApprovalRequirement::Automatic,
    )
}

#[test]
fn admission_artifact_digest_is_domain_bound_order_invariant_and_mutation_sensitive() {
    let fixture = governed_coordinator_fixture();
    let artifacts =
        build_threshold_artifacts(&fixture, vec![Keypair::generate(), Keypair::generate()]);
    let forward = crate::kernel::active_response_admission_artifact_payload_digest(
        fixture.request.plan_body(),
        fixture.request.operator_capability(),
        fixture.request.governed_intent(),
        fixture.request.submission_proof(),
        &Some(artifacts.proposal.clone()),
        &artifacts.tokens,
    )
    .expect("forward artifact digest");
    let mut reversed = artifacts.tokens.clone();
    reversed.reverse();
    let reordered = crate::kernel::active_response_admission_artifact_payload_digest(
        fixture.request.plan_body(),
        fixture.request.operator_capability(),
        fixture.request.governed_intent(),
        fixture.request.submission_proof(),
        &Some(artifacts.proposal),
        &reversed,
    )
    .expect("reordered artifact digest");
    assert_eq!(forward, reordered);

    let mut mutated_plan = fixture.request.plan_body().clone();
    mutated_plan.reason_hash = Digest32::new([0x91; 32]);
    let mutated = crate::kernel::active_response_admission_artifact_payload_digest(
        &mutated_plan,
        fixture.request.operator_capability(),
        fixture.request.governed_intent(),
        fixture.request.submission_proof(),
        &None,
        &[],
    )
    .expect("mutated artifact digest");
    let unmutated = crate::kernel::active_response_admission_artifact_payload_digest(
        fixture.request.plan_body(),
        fixture.request.operator_capability(),
        fixture.request.governed_intent(),
        fixture.request.submission_proof(),
        &None,
        &[],
    )
    .expect("unmutated artifact digest");
    assert_ne!(mutated, unmutated);

    let proof_digest =
        crate::kernel::active_response_submission_proof_digest(fixture.request.submission_proof())
            .expect("domain-separated proof digest");
    let canonical = canonical_json_bytes(fixture.request.submission_proof())
        .expect("canonical submission proof");
    assert_ne!(proof_digest.as_bytes(), sha256(&canonical).as_bytes());
}

#[test]
fn kernel_admission_rejects_ephemeral_or_same_submitter_artifact_authority() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    fixture
        .kernel
        .set_admission_operation_store_handle(Arc::new(RecordingThresholdOperationStore::new()))
        .expect("operation store");
    let executor_signer = fixture.executor.clone();
    install_active_response_policy(&mut fixture, executor_signer);
    let valid = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    let base = valid.artifact_authority_attestation();

    let canonical = canonical_json_bytes(&base.body).expect("canonical authority attestation");
    let mut wrong_domain = base.clone();
    wrong_domain.signature = fixture.submission_authority.sign(&canonical);
    assert!(!wrong_domain
        .verify_signature()
        .expect("wrong-domain authority signature verification"));

    let body = &base.body;
    assert!(
        crate::kernel::ActiveResponseArtifactAuthorityAttestationBody::new(
            crate::kernel::ActiveResponseArtifactAuthorityAttestationInput {
                artifact_ref: body.artifact_ref.clone(),
                action_id: body.action_id.clone(),
                tenant_id: body.tenant_id.clone(),
                artifact_payload_digest: body.artifact_payload_digest,
                submission_proof_digest: body.submission_proof_digest,
                plan_body_hash: body.plan_body_hash,
                governed_intent_hash: body.governed_intent_hash,
                submitter: body.submitter.clone(),
                authority: body.submitter.clone(),
                issued_at_unix_ms: body.issued_at_unix_ms,
                expires_at_unix_ms: body.expires_at_unix_ms,
            },
        )
        .is_err()
    );

    let ephemeral_authority = Keypair::generate();
    let mut ephemeral_body = body.clone();
    ephemeral_body.authority = ephemeral_authority.public_key();
    let ephemeral = crate::kernel::ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
        ephemeral_body,
        &Ed25519Backend::new(ephemeral_authority),
    )
    .expect("ephemeral authority attestation");
    let ephemeral_request = ActiveResponseAdmissionRequest::new(
        fixture.response_plan.clone(),
        fixture.request.clone(),
        body.artifact_ref.clone(),
        ephemeral,
        None,
        Vec::new(),
    )
    .expect("ephemeral authority request");
    assert!(fixture
        .kernel
        .prepare_active_response_admission(&ephemeral_request)
        .is_err());

    let mut rebound_body = body.clone();
    rebound_body.submitter = Keypair::generate().public_key();
    let rebound = crate::kernel::ActiveResponseArtifactAuthorityAttestation::sign_with_backend(
        rebound_body,
        &Ed25519Backend::new(fixture.submission_authority.clone()),
    )
    .expect("rebound submitter attestation");
    let rebound_request = ActiveResponseAdmissionRequest::new(
        fixture.response_plan.clone(),
        fixture.request.clone(),
        body.artifact_ref.clone(),
        rebound,
        None,
        Vec::new(),
    )
    .expect("rebound submitter request");
    assert!(fixture
        .kernel
        .prepare_active_response_admission(&rebound_request)
        .is_err());
}

fn install_active_response_policy(
    fixture: &mut ActiveResponseFixture,
    executor_signer: Keypair,
) -> Arc<RecordingActiveResponseExecutor> {
    let policy_hash = fixture.kernel.config.policy_hash.clone();
    let policy_version = fixture.request.plan_body().policy_version.clone();
    let approval_requirement = fixture.request.plan_body().approval_requirement.clone();
    let ttl_ms = fixture.request.plan_body().ttl_ms;
    let expected_hash = policy_hash.clone();
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            move |_: &crate::kernel::ActiveResponsePolicyRequest, received: &str| {
                if received != expected_hash {
                    return Err(ActiveResponsePolicyResolutionError::StalePolicy {
                        expected: expected_hash.clone(),
                        received: received.to_string(),
                    });
                }
                Ok(match &approval_requirement {
                    ResponseApprovalRequirement::Automatic => ActiveResponseRequirement::automatic(
                        expected_hash.clone(),
                        policy_version.clone(),
                        ttl_ms,
                        1_000,
                    ),
                    ResponseApprovalRequirement::Governed { policy_id } => {
                        ActiveResponseRequirement::governed(
                            expected_hash.clone(),
                            policy_version.clone(),
                            policy_id.clone(),
                            1_000,
                        )
                    }
                })
            },
        ))
        .expect("active-response requirement resolver");
    let executor_authority = Arc::new(RecordingActiveResponseExecutor::new(executor_signer, 1));
    fixture
        .kernel
        .set_active_response_executor_authority(executor_authority.clone())
        .expect("active-response executor authority");
    if fixture.kernel.admission_operation_store.is_none() {
        fixture
            .kernel
            .set_admission_operation_store_handle(Arc::new(RecordingThresholdOperationStore::new()))
            .expect("active-response operation store");
    }
    fixture
        .kernel
        .enable_governed_active_response_plans()
        .expect("active-response plan activation");
    executor_authority
}

fn build_threshold_artifacts(
    fixture: &ActiveResponseFixture,
    approvers: Vec<Keypair>,
) -> ThresholdArtifacts {
    build_threshold_artifacts_with_timeout(fixture, approvers, 900)
}

fn build_threshold_artifacts_with_timeout(
    fixture: &ActiveResponseFixture,
    approvers: Vec<Keypair>,
    proposal_timeout_seconds: u64,
) -> ThresholdArtifacts {
    build_threshold_artifacts_with_token_timeout(
        fixture,
        &approvers,
        proposal_timeout_seconds,
        proposal_timeout_seconds,
    )
}

fn build_threshold_artifacts_with_token_timeout(
    fixture: &ActiveResponseFixture,
    approvers: &[Keypair],
    proposal_timeout_seconds: u64,
    token_timeout_seconds: u64,
) -> ThresholdArtifacts {
    let eligible = approvers
        .iter()
        .enumerate()
        .map(|(index, approver)| {
            (
                format!("active-response-approver-{index}"),
                approver.public_key(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let requirement = ThresholdApprovalRequirement::new(
        u32::try_from(approvers.len()).expect("approver count fits u32"),
        eligible,
        proposal_timeout_seconds,
        fixture.kernel.config.policy_hash.clone(),
        1,
    )
    .expect("active-response threshold requirement");
    let policy_authority = Keypair::generate();
    let intent_hash = fixture
        .request
        .governed_intent()
        .binding_hash()
        .expect("active-response intent hash");
    let capability = fixture.request.operator_capability();
    let capability_hash = crate::threshold_approval::authorization_capability_hash(capability)
        .expect("operator capability hash");
    let now = current_unix_timestamp();
    let governed_expires_at = fixture
        .request
        .governed_intent()
        .as_active_response_plan()
        .expect("active-response intent")
        .expires_at();
    let proposal_body = ThresholdApprovalProposalBody::new(
        format!("proposal-{}", fixture.request.plan_body().action_id),
        fixture.request.plan_body().action_id.as_str(),
        intent_hash.clone(),
        capability.subject.clone(),
        capability_hash,
        fixture.kernel.config.policy_hash.clone(),
        requirement.required(),
        requirement.eligible_set_digest(),
        now,
        requirement.proposal_timeout_seconds(),
        capability.expires_at,
        governed_expires_at,
    )
    .expect("active-response threshold proposal body");
    let proposal = ThresholdApprovalProposal::sign(proposal_body, &policy_authority)
        .expect("active-response threshold proposal");
    let proposal_hash = proposal.proposal_hash().expect("threshold proposal hash");
    let deadline = proposal.body().proposal_deadline();
    let token_expires_at = now
        .checked_add(token_timeout_seconds)
        .expect("approval token expiry")
        .min(deadline);
    let tokens = approvers
        .iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("approval-{}-{index}", fixture.request.plan_body().action_id),
                    approver: approver.public_key(),
                    subject: capability.subject.clone(),
                    governed_intent_hash: intent_hash.clone(),
                    threshold_proposal_hash: Some(proposal_hash.clone()),
                    request_id: fixture.request.plan_body().action_id.as_str().to_string(),
                    issued_at: now,
                    expires_at: token_expires_at,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .expect("active-response approval token")
        })
        .collect();
    ThresholdArtifacts {
        proposal,
        tokens,
        requirement,
        policy_authority,
    }
}

fn install_threshold_authorities(
    fixture: &mut ActiveResponseFixture,
    artifacts: &ThresholdArtifacts,
    operations: Arc<RecordingThresholdOperationStore>,
    approvals: Arc<DurableThresholdApprovalStore>,
) {
    let requirement = artifacts.requirement.clone();
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(Arc::new(
            move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                Ok(requirement.clone())
            },
        ))
        .expect("threshold requirement resolver");
    fixture
        .kernel
        .set_threshold_approval_policy_authority(artifacts.policy_authority.public_key())
        .expect("threshold proposal authority");
    fixture
        .kernel
        .set_admission_operation_store_handle(operations)
        .expect("active-response operation store");
    fixture
        .kernel
        .set_approval_store_handle(approvals)
        .expect("active-response approval store");
    fixture
        .kernel
        .set_budget_store_handle(Arc::new(DurableThresholdBudgetStore::new()))
        .expect("threshold feature budget authority");
    fixture
        .kernel
        .enable_threshold_governed_approvals()
        .expect("threshold governed approval activation");
}

fn setup_governed_with_stores(
    operations: Arc<RecordingThresholdOperationStore>,
    approvals: Arc<DurableThresholdApprovalStore>,
    approvers: Vec<Keypair>,
) -> GovernedCoordinatorFixture {
    setup_governed_with_stores_and_timeout(operations, approvals, approvers, 900)
}

fn setup_governed_with_stores_and_timeout(
    operations: Arc<RecordingThresholdOperationStore>,
    approvals: Arc<DurableThresholdApprovalStore>,
    approvers: Vec<Keypair>,
    proposal_timeout_seconds: u64,
) -> GovernedCoordinatorFixture {
    setup_governed_with_stores_and_token_timeout(
        operations,
        approvals,
        approvers,
        proposal_timeout_seconds,
        proposal_timeout_seconds,
    )
}

fn setup_governed_with_stores_and_token_timeout(
    operations: Arc<RecordingThresholdOperationStore>,
    approvals: Arc<DurableThresholdApprovalStore>,
    approvers: Vec<Keypair>,
    proposal_timeout_seconds: u64,
    token_timeout_seconds: u64,
) -> GovernedCoordinatorFixture {
    let mut fixture = governed_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let artifacts = build_threshold_artifacts_with_token_timeout(
        &fixture,
        &approvers,
        proposal_timeout_seconds,
        token_timeout_seconds,
    );
    install_threshold_authorities(
        &mut fixture,
        &artifacts,
        Arc::clone(&operations),
        Arc::clone(&approvals),
    );
    let executor_signer = fixture.executor.clone();
    let executor_authority = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        Some(artifacts.proposal),
        artifacts.tokens,
    );
    GovernedCoordinatorFixture {
        fixture,
        request,
        operations,
        approvals,
        executor_authority,
    }
}

fn setup_governed() -> GovernedCoordinatorFixture {
    setup_governed_with_stores(
        Arc::new(RecordingThresholdOperationStore::new()),
        Arc::new(DurableThresholdApprovalStore::new()),
        vec![Keypair::generate(), Keypair::generate()],
    )
}

#[test]
fn automatic_admission_verifies_executor_without_operation_or_approval_mutation() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let operations = Arc::new(RecordingThresholdOperationStore::new());
    let approvals = Arc::new(DurableThresholdApprovalStore::new());
    fixture
        .kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    fixture
        .kernel
        .set_approval_store_handle(approvals)
        .expect("approval store");
    let executor_signer = fixture.executor.clone();
    let executor_authority = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );

    let PreparedActiveResponseAdmission::Automatic(permit) = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("automatic active-response admission")
    else {
        panic!("automatic policy must return an automatic permit");
    };

    assert_eq!(
        permit.request_id(),
        fixture.request.plan_body().action_id.as_str()
    );
    assert_eq!(permit.plan_body_hash(), fixture.plan_hash);
    assert_eq!(
        permit.authorization_capability_hash(),
        fixture.capability_hash
    );
    fixture
        .kernel
        .execute_prepared_active_response(
            &request,
            &PreparedActiveResponseAdmission::Automatic(permit),
        )
        .expect("automatic active-response execution");
    let expected_policy_hash = fixture.response_plan.policy_hash;
    assert_eq!(request.response_plan().policy_hash, expected_policy_hash);
    assert_eq!(
        executor_authority.last_policy_hash(),
        Some(expected_policy_hash)
    );
    assert_ne!(
        expected_policy_hash.as_bytes(),
        sha256(active_response_policy_hash().as_bytes()).as_bytes(),
        "dispatch must preserve decoded policy bytes rather than hash their hex text"
    );
    assert_eq!(executor_authority.calls(), 1);
    assert!(operations.states().is_empty());
}

#[test]
fn public_prepared_commit_rejects_automatic_admission_without_mutation() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let operations = Arc::new(RecordingThresholdOperationStore::new());
    fixture
        .kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    fixture
        .kernel
        .set_approval_store_handle(Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    let executor_signer = fixture.executor.clone();
    let executor_authority = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    let prepared = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("automatic active-response admission");

    let error = fixture
        .kernel
        .commit_prepared_active_response_admission(&request, &prepared)
        .expect_err("approval-only commit must reject automatic admission");

    assert!(error.to_string().contains("governed preparation"));
    assert!(operations.states().is_empty());
    assert_eq!(executor_authority.calls(), 0);
}

#[test]
fn exact_committed_recovery_survives_capability_revocation_and_resolver_rotation() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let executor_signer = fixture.executor.clone();
    let executor_authority = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    let prepared = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("initial automatic preparation");
    let dispatch_id = prepared.dispatch_id().clone();
    let first = fixture
        .kernel
        .execute_prepared_active_response(&request, &prepared)
        .expect("initial automatic execution");

    fixture
        .kernel
        .revoke_capability(&fixture.request.operator_capability().id)
        .expect("post-commit capability revocation");
    fixture.kernel.deactivate_governed_active_response_plans();
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            |_: &crate::kernel::ActiveResponsePolicyRequest, _: &str| {
                Err(ActiveResponsePolicyResolutionError::Invalid(
                    "rotated resolver rejects the historical request".to_string(),
                ))
            },
        ))
        .expect("rotate active-response resolver");
    fixture.finding_authority.set_ready(false);

    let recovered = fixture
        .kernel
        .recover_committed_active_response(&fixture.response_plan, &dispatch_id)
        .expect("exact committed recovery must remain available")
        .expect("durable dispatch must be present");
    assert_eq!(recovered.dispatch_id(), &dispatch_id);
    assert_eq!(recovered.proof_evidence_id(), first.proof_evidence_id());
    assert_eq!(recovered.proof_body_hash(), first.proof_body_hash());
    assert_eq!(executor_authority.calls(), 2);
}

#[test]
fn missing_committed_dispatch_does_not_bypass_current_authorization() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let executor_signer = fixture.executor.clone();
    let executor_authority = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    let prepared = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("initial automatic preparation");
    let dispatch_id = prepared.dispatch_id().clone();
    fixture
        .kernel
        .revoke_capability(&fixture.request.operator_capability().id)
        .expect("capability revocation");

    assert!(fixture
        .kernel
        .recover_committed_active_response(&fixture.response_plan, &dispatch_id)
        .expect("missing dispatch lookup")
        .is_none());
    assert!(fixture
        .kernel
        .execute_prepared_active_response(&request, &prepared)
        .is_err());
    assert_eq!(executor_authority.calls(), 0);
}

#[test]
fn committed_recovery_rejects_rehashed_malformed_applying_history() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let executor_signer = fixture.executor.clone();
    let executor_authority = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    let prepared = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("initial automatic preparation");
    let dispatch_id = prepared.dispatch_id().clone();
    fixture
        .kernel
        .execute_prepared_active_response(&request, &prepared)
        .expect("initial automatic execution");
    executor_authority.corrupt_committed_applying_history(&dispatch_id);

    assert!(fixture
        .kernel
        .recover_committed_active_response(&fixture.response_plan, &dispatch_id)
        .is_err());
    assert_eq!(executor_authority.calls(), 1);
}

#[test]
fn exact_never_committed_automatic_cleanup_survives_authorization_rotation() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let executor_signer = fixture.executor.clone();
    let executor_authority = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    let prepared = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("initial automatic preparation");
    let binding = prepared
        .durable_dispatch_binding(&fixture.response_plan)
        .expect("durable prepared dispatch binding");
    assert!(fixture
        .kernel
        .recover_committed_active_response(&fixture.response_plan, &binding.dispatch_id)
        .expect("exact committed readback")
        .is_none());
    assert!(
        fixture
            .kernel
            .terminate_never_committed_active_response(
                &fixture.response_plan,
                &binding,
                Some(&request),
            )
            .is_err()
    );

    fixture
        .kernel
        .revoke_capability(&fixture.request.operator_capability().id)
        .expect("capability revocation");
    fixture.kernel.deactivate_governed_active_response_plans();
    fixture
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            |_: &crate::kernel::ActiveResponsePolicyRequest, _: &str| {
                Err(ActiveResponsePolicyResolutionError::Invalid(
                    "rotated resolver rejects the prepared request".to_string(),
                ))
            },
        ))
        .expect("rotate active-response resolver");
    fixture.finding_authority.set_ready(false);
    fixture
        .kernel
        .terminate_never_committed_active_response(&fixture.response_plan, &binding, Some(&request))
        .expect("revocation is a definitive pre-expiry denial");
    let _expired_runtime = crate::scope_fixed_runtime_for_current_thread(
        fixture
            .request
            .operator_capability()
            .expires_at
            .saturating_add(1),
        Vec::new(),
    );

    fixture
        .kernel
        .terminate_never_committed_active_response(&fixture.response_plan, &binding, None)
        .expect("expired exact missing termination needs no admission artifacts");
    fixture
        .kernel
        .terminate_never_committed_active_response(&fixture.response_plan, &binding, None)
        .expect("exact missing automatic termination is idempotent");
    assert!(fixture
        .kernel
        .prepare_active_response_admission(&request)
        .is_err());
    assert_eq!(executor_authority.calls(), 0);
}

#[test]
fn automatic_dispatch_gate_serializes_expired_termination_after_durable_commit() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let executor_signer = fixture.executor.clone();
    let executor_authority = install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        None,
        Vec::new(),
    );
    let prepared = fixture
        .kernel
        .prepare_active_response_admission(&request)
        .expect("automatic preparation");
    let binding = prepared
        .durable_dispatch_binding(&fixture.response_plan)
        .expect("durable automatic binding");
    let response_plan = fixture.response_plan.clone();
    let kernel = Arc::new(fixture.kernel);

    let (execution, termination, returned_before_dispatch) =
        race_expired_termination_against_inflight_dispatch(
            kernel,
            request,
            prepared,
            response_plan,
            binding,
            executor_authority.clone(),
        );
    assert!(!returned_before_dispatch);
    assert!(execution.is_ok());
    assert!(termination.is_err());
    assert_eq!(executor_authority.calls(), 1);
}

#[test]
fn active_response_executor_authority_is_required_and_must_match_capability() {
    let mut missing = automatic_coordinator_fixture();
    missing.kernel.config.policy_hash = active_response_policy_hash();
    let policy_hash = missing.kernel.config.policy_hash.clone();
    let policy_version = missing.request.plan_body().policy_version.clone();
    let ttl_ms = missing.request.plan_body().ttl_ms;
    missing
        .kernel
        .set_active_response_requirement_resolver(Arc::new(
            move |_: &crate::kernel::ActiveResponsePolicyRequest, _: &str| {
                Ok(ActiveResponseRequirement::automatic(
                    policy_hash.clone(),
                    policy_version.clone(),
                    ttl_ms,
                    1_000,
                ))
            },
        ))
        .expect("active-response policy resolver");
    assert!(missing
        .kernel
        .enable_governed_active_response_plans()
        .is_err());

    let mut mismatched = automatic_coordinator_fixture();
    mismatched.kernel.config.policy_hash = active_response_policy_hash();
    install_active_response_policy(&mut mismatched, Keypair::generate());
    let request = signed_active_response_admission_request(
        &mismatched,
        mismatched.response_plan.clone(),
        mismatched.request.clone(),
        None,
        Vec::new(),
    );
    assert!(mismatched
        .kernel
        .prepare_active_response_admission(&request)
        .is_err());
}

#[test]
fn automatic_admission_rejects_threshold_artifacts_before_mutation() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let operations = Arc::new(RecordingThresholdOperationStore::new());
    fixture
        .kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    let artifacts =
        build_threshold_artifacts(&fixture, vec![Keypair::generate(), Keypair::generate()]);
    let executor_signer = fixture.executor.clone();
    install_active_response_policy(&mut fixture, executor_signer);
    let request = signed_active_response_admission_request(
        &fixture,
        fixture.response_plan.clone(),
        fixture.request.clone(),
        Some(artifacts.proposal),
        artifacts.tokens,
    );

    assert!(fixture
        .kernel
        .prepare_active_response_admission(&request)
        .is_err());
    assert!(operations.states().is_empty());
}

#[test]
fn active_response_admission_revalidates_the_full_executable_plan() {
    let mut fixture = automatic_coordinator_fixture();
    fixture.kernel.config.policy_hash = active_response_policy_hash();
    let operations = Arc::new(RecordingThresholdOperationStore::new());
    fixture
        .kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    let executor_signer = fixture.executor.clone();
    install_active_response_policy(&mut fixture, executor_signer);

    let mut response_plan = fixture.response_plan.clone();
    let mut effects = response_plan.effects.clone().into_vec();
    effects[0].canonical_contribution = CanonicalBody::new(
        canonical_json_bytes(&serde_json::json!({"mutated": true}))
            .expect("canonical mutated contribution"),
    )
    .expect("bounded mutated contribution");
    response_plan.effects = PlannedResponseEffects::new(effects).expect("bounded effects");
    let request = signed_active_response_admission_request(
        &fixture,
        response_plan,
        fixture.request.clone(),
        None,
        Vec::new(),
    );

    assert!(fixture
        .kernel
        .prepare_active_response_admission(&request)
        .is_err());
    assert!(operations.states().is_empty());
}

#[test]
fn governed_admission_orders_operation_reservation_dispatch_and_completion() {
    let coordinator = setup_governed();

    let PreparedActiveResponseAdmission::Governed(reservation) = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation")
    else {
        panic!("governed policy must return a governed reservation");
    };
    let prepared = PreparedActiveResponseAdmission::Governed(reservation.clone());
    assert_eq!(
        coordinator.operations.states(),
        vec![
            AdmissionOperationState::Prepared,
            AdmissionOperationState::ApprovalReserved,
        ]
    );
    let operation = coordinator
        .operations
        .load(reservation.operation_id())
        .expect("operation lookup")
        .expect("persisted operation");
    assert_eq!(
        operation.kind(),
        AdmissionOperationKind::GovernedActiveResponse
    );
    let executor_authority_id = coordinator
        .executor_authority
        .identity()
        .authority_id()
        .to_string();
    assert_eq!(operation.coordinator_authority_id(), executor_authority_id);
    assert_eq!(
        operation.request_id(),
        coordinator.fixture.request.plan_body().action_id.as_str()
    );
    assert_eq!(
        operation.capability_id(),
        coordinator.fixture.request.operator_capability().id
    );
    assert_eq!(
        operation.authorization_capability_hash(),
        coordinator.fixture.capability_hash
    );
    assert_eq!(
        operation.approval_set_hash(),
        Some(reservation.approval_set_hash())
    );
    assert!(operation.budget_hold_id().is_none());
    assert!(operation.execution_nonce_id().is_none());
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("approval reservation")
            .state(),
        ReplayReservationState::Reserved
    );

    let permit = coordinator
        .fixture
        .kernel
        .commit_active_response_dispatch(&coordinator.request, &reservation)
        .expect("active-response dispatch commitment");
    assert_eq!(
        permit.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert!(!permit.is_recovery());
    assert_eq!(
        coordinator.operations.states(),
        vec![
            AdmissionOperationState::Prepared,
            AdmissionOperationState::ApprovalReserved,
            AdmissionOperationState::DispatchCommitted,
        ]
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("committed approval reservation")
            .state(),
        ReplayReservationState::Committed
    );

    coordinator
        .fixture
        .kernel
        .execute_prepared_active_response(&coordinator.request, &prepared)
        .expect("active-response execution and admission completion");
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
    assert_eq!(coordinator.executor_authority.calls(), 1);
}

#[test]
fn public_prepared_commit_is_idempotent_for_governed_admission() {
    let coordinator = setup_governed();
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    let PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed policy must return a governed reservation");
    };

    coordinator
        .fixture
        .kernel
        .commit_prepared_active_response_admission(&coordinator.request, &prepared)
        .expect("initial public dispatch commitment");
    coordinator
        .fixture
        .kernel
        .commit_prepared_active_response_admission(&coordinator.request, &prepared)
        .expect("idempotent public dispatch commitment");

    assert_eq!(
        coordinator
            .operations
            .states()
            .iter()
            .filter(|state| **state == AdmissionOperationState::DispatchCommitted)
            .count(),
        1
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("approval reservation")
            .state(),
        ReplayReservationState::Committed
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn public_prepared_cancel_compensates_exact_governed_admission() {
    let coordinator = setup_governed();
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    let PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed policy must return a governed reservation");
    };

    coordinator
        .fixture
        .kernel
        .cancel_prepared_active_response_admission(&prepared, "outbox persistence failed")
        .expect("cancel exact governed preparation");
    coordinator
        .fixture
        .kernel
        .cancel_prepared_active_response_admission(&prepared, "idempotent retry")
        .expect("repeat exact cancellation");

    assert_eq!(
        coordinator
            .operations
            .load(reservation.operation_id())
            .expect("operation lookup")
            .expect("compensated operation")
            .state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        coordinator
            .approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("cancelled approval")
            .state(),
        ReplayReservationState::Cancelled
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn concurrent_public_commit_and_cancel_choose_one_safe_terminal_branch() {
    let coordinator = setup_governed();
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    let PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed policy must return a governed reservation");
    };
    let operation_id = reservation.operation_id().to_string();
    let binding = prepared
        .durable_dispatch_binding(&coordinator.fixture.response_plan)
        .expect("durable governed binding");
    let request = coordinator.request.clone();
    let recovery_request = coordinator.request.clone();
    let executor = coordinator.executor_authority.clone();
    let operations = coordinator.operations.clone();
    let approvals = coordinator.approvals.clone();
    let kernel = Arc::new(coordinator.fixture.kernel);
    let start = Arc::new(Barrier::new(3));

    let (commit_result, cancel_result) = std::thread::scope(|scope| {
        let commit_kernel = kernel.clone();
        let commit_start = start.clone();
        let commit_prepared = prepared.clone();
        let commit = scope.spawn(move || {
            commit_start.wait();
            commit_kernel.commit_prepared_active_response_admission(&request, &commit_prepared)
        });
        let cancel_kernel = kernel.clone();
        let cancel_start = start.clone();
        let cancel_prepared = prepared.clone();
        let cancel = scope.spawn(move || {
            cancel_start.wait();
            cancel_kernel.cancel_prepared_active_response_admission(
                &cancel_prepared,
                "concurrent cancellation",
            )
        });
        start.wait();
        (
            commit.join().expect("commit worker"),
            cancel.join().expect("cancel worker"),
        )
    });
    assert_ne!(commit_result.is_ok(), cancel_result.is_ok());

    let operation = operations
        .load(&operation_id)
        .expect("operation lookup")
        .expect("terminal operation branch");
    let approval = approvals
        .get_approval_reservation(&operation_id)
        .expect("approval lookup")
        .expect("approval tombstone");
    match operation.state() {
        AdmissionOperationState::DispatchCommitted => {
            assert!(commit_result.is_ok());
            assert!(cancel_result.is_err());
            assert_eq!(
                operation.dispatch_state(),
                AdmissionDispatchState::Committed
            );
            assert_eq!(approval.state(), ReplayReservationState::Committed);
            assert!(matches!(
                kernel.reconstruct_pre_dispatch_active_response_admission(
                    &recovery_request,
                    &binding,
                ),
                Ok(crate::kernel::PreDispatchActiveResponseReconstruction::NotPrepared)
            ));
        }
        AdmissionOperationState::CompensatedBeforeDispatch => {
            assert!(commit_result.is_err());
            assert!(cancel_result.is_ok());
            assert_eq!(
                operation.dispatch_state(),
                AdmissionDispatchState::NotStarted
            );
            assert!(matches!(
                approval.state(),
                ReplayReservationState::Cancelled | ReplayReservationState::Committed
            ));
        }
        state => panic!("commit-cancel race ended in unsafe state {state:?}"),
    }
    assert_eq!(executor.calls(), 0);
}

#[test]
fn approval_replay_commit_precedes_dispatch_committed_cas() {
    let operations = Arc::new(RecordingThresholdOperationStore::new());
    let approvals = Arc::new(DurableThresholdApprovalStore::with_commit_failure_before_write());
    let coordinator = setup_governed_with_stores(
        Arc::clone(&operations),
        Arc::clone(&approvals),
        vec![Keypair::generate(), Keypair::generate()],
    );
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    let PreparedActiveResponseAdmission::Governed(reservation) = &prepared else {
        panic!("governed policy must return a governed reservation");
    };

    let error = coordinator
        .fixture
        .kernel
        .commit_prepared_active_response_admission(&coordinator.request, &prepared)
        .expect_err("approval commit failure must prevent dispatch commitment");
    assert!(error
        .to_string()
        .contains("injected approval commit failure before write"));
    assert_eq!(
        operations
            .load(reservation.operation_id())
            .expect("operation lookup")
            .expect("persisted operation")
            .state(),
        AdmissionOperationState::ApprovalReserved
    );
    assert_eq!(
        approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("approval reservation")
            .state(),
        ReplayReservationState::Reserved
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);

    coordinator
        .fixture
        .kernel
        .commit_prepared_active_response_admission(&coordinator.request, &prepared)
        .expect("retry commits approval replay before dispatch commitment");

    assert_eq!(
        approvals
            .get_approval_reservation(reservation.operation_id())
            .expect("approval lookup")
            .expect("approval reservation")
            .state(),
        ReplayReservationState::Committed
    );
    assert_eq!(
        operations
            .load(reservation.operation_id())
            .expect("operation lookup")
            .expect("persisted operation")
            .state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(
        operations
            .states()
            .iter()
            .filter(|state| **state == AdmissionOperationState::DispatchCommitted)
            .count(),
        1
    );
    assert_eq!(coordinator.executor_authority.calls(), 0);
}

#[test]
fn governed_completion_requires_exact_durable_effect_evidence() {
    let coordinator = setup_governed();
    coordinator
        .executor_authority
        .set_outcome(TestActiveResponseExecutionOutcome::MissingEffectEvidence);
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");

    let error = coordinator
        .fixture
        .kernel
        .execute_prepared_active_response(&coordinator.request, &prepared)
        .expect_err("missing effect evidence must not complete admission");

    assert!(error.to_string().contains("effect evidence"));
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::DispatchCommitted)
    );
    assert_eq!(coordinator.executor_authority.calls(), 1);
}

#[test]
fn governed_completion_rejects_every_mutated_or_cross_dispatch_proof() {
    for outcome in [
        TestActiveResponseExecutionOutcome::MutatedResponseBodyHash,
        TestActiveResponseExecutionOutcome::MutatedResponseTransitionId,
        TestActiveResponseExecutionOutcome::MutatedEffectResultHash,
        TestActiveResponseExecutionOutcome::MutatedEffectGeneration,
        TestActiveResponseExecutionOutcome::MutatedCompletionReceipt,
        TestActiveResponseExecutionOutcome::SpuriousFailureEvidence,
        TestActiveResponseExecutionOutcome::WrongDispatchProof,
    ] {
        let coordinator = setup_governed();
        coordinator.executor_authority.set_outcome(outcome);
        let prepared = coordinator
            .fixture
            .kernel
            .prepare_active_response_admission(&coordinator.request)
            .expect("governed active-response reservation");

        assert!(coordinator
            .fixture
            .kernel
            .execute_prepared_active_response(&coordinator.request, &prepared)
            .is_err());
        assert_eq!(
            coordinator.operations.states().last(),
            Some(&AdmissionOperationState::DispatchCommitted),
            "mutated proof {outcome:?} must not complete admission"
        );
    }
}

#[test]
fn kernel_rejects_resigned_response_lifecycle_and_lineage_forgery() {
    for outcome in [
        TestActiveResponseExecutionOutcome::MissingEffectRequestedLifecycle,
        TestActiveResponseExecutionOutcome::ReversedMutationTimestampLifecycle,
        TestActiveResponseExecutionOutcome::BrokenPriorReceiptLifecycle,
    ] {
        let coordinator = setup_governed();
        coordinator.executor_authority.set_outcome(outcome);
        let prepared = coordinator
            .fixture
            .kernel
            .prepare_active_response_admission(&coordinator.request)
            .expect("governed active-response reservation");

        let error = coordinator
            .fixture
            .kernel
            .execute_prepared_active_response(&coordinator.request, &prepared)
            .expect_err("resigned illegal response lifecycle must be rejected");
        assert!(error.to_string().contains("durable lifecycle"));
        assert_eq!(
            coordinator.operations.states().last(),
            Some(&AdmissionOperationState::DispatchCommitted),
            "illegal lifecycle {outcome:?} must not complete admission"
        );
    }
}

#[test]
fn uncertain_executor_outcome_stays_dispatch_committed_and_retries_idempotently() {
    let coordinator = setup_governed();
    coordinator
        .executor_authority
        .set_outcome(TestActiveResponseExecutionOutcome::OutcomeUnknown);
    let prepared = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");

    assert!(coordinator
        .fixture
        .kernel
        .execute_prepared_active_response(&coordinator.request, &prepared)
        .is_err());
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::DispatchCommitted)
    );

    coordinator
        .executor_authority
        .set_outcome(TestActiveResponseExecutionOutcome::Success);
    coordinator
        .fixture
        .kernel
        .execute_prepared_active_response(&coordinator.request, &prepared)
        .expect("same dispatch recovers after acknowledgement loss");
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );
    assert_eq!(coordinator.executor_authority.calls(), 2);
}

#[test]
fn governed_dispatch_committed_and_completed_recovery_survives_expired_proof_windows() {
    let mut coordinator = setup_governed();
    coordinator
        .executor_authority
        .set_outcome(TestActiveResponseExecutionOutcome::OutcomeUnknown);
    let first = coordinator
        .fixture
        .kernel
        .prepare_active_response_admission(&coordinator.request)
        .expect("governed active-response reservation");
    let stable_dispatch_id = first.dispatch_id().clone();
    let durable_binding = first
        .durable_dispatch_binding(&coordinator.fixture.response_plan)
        .expect("durable governed dispatch binding");
    assert!(coordinator
        .fixture
        .kernel
        .execute_prepared_active_response(&coordinator.request, &first)
        .is_err());
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::DispatchCommitted)
    );

    coordinator
        .fixture
        .kernel
        .revoke_capability(&coordinator.fixture.request.operator_capability().id)
        .expect("post-commit capability revocation");
    coordinator
        .fixture
        .kernel
        .deactivate_governed_active_response_plans();
    coordinator.fixture.finding_authority.set_ready(false);
    let _expired_runtime = crate::scope_fixed_runtime_for_current_thread(
        coordinator
            .fixture
            .request
            .operator_capability()
            .expires_at
            .saturating_add(1),
        Vec::new(),
    );
    coordinator
        .executor_authority
        .set_outcome(TestActiveResponseExecutionOutcome::Success);
    let completed = coordinator
        .fixture
        .kernel
        .recover_committed_active_response(
            &coordinator.fixture.response_plan,
            &durable_binding.dispatch_id,
        )
        .expect("expired dispatch commitment must reconcile")
        .expect("durable committed dispatch must exist");
    assert_eq!(completed.dispatch_id(), &stable_dispatch_id);
    assert_eq!(
        coordinator.operations.states().last(),
        Some(&AdmissionOperationState::Completed)
    );

    let replay = coordinator
        .fixture
        .kernel
        .recover_committed_active_response(&coordinator.fixture.response_plan, &stable_dispatch_id)
        .expect("completed expired dispatch must return exact evidence")
        .expect("completed durable dispatch must remain present");
    assert_eq!(completed.outcome(), replay.outcome());
    assert_eq!(completed.proof_evidence_id(), replay.proof_evidence_id());
    assert_eq!(completed.proof_body_hash(), replay.proof_body_hash());
}

include!("coordinator_expiry_and_recovery.inc");
