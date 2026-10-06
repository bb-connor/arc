//! Legacy retirement against a genuinely published runtime and real V1 store.
use super::*;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
    GovernedTransactionIntentBody, ThresholdApprovalProposal, ThresholdApprovalProposalBody,
    ACTIVE_RESPONSE_PLAN_TOOL_NAME, ACTIVE_RESPONSE_SERVER_ID, GOVERNED_RESPONSE_PLAN_SCHEMA,
    THRESHOLD_APPROVAL_PROPOSAL_SCHEMA,
};
use chio_core::{canonical_json_bytes, sha256_hex};
use chio_kernel::admission_operation::{
    AdmissionOperationState, AdmissionOperationStore as LegacyOperationStore,
};
use chio_kernel::governed_active_response::GovernedActiveResponseRequest;
use chio_kernel::KernelError;

fn legacy_grant(server: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server.to_owned(),
        tool_name: tool.to_owned(),
        operations: vec![Operation::Invoke],
        constraints: Vec::new(),
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

struct LegacyResponseFixture<'a> {
    issuer: &'a Keypair,
    requirement: &'a ThresholdApprovalRequirement,
    policy_authority: &'a Keypair,
    approvers: [&'a Keypair; 2],
    executor: &'a Keypair,
    now: u64,
}

impl LegacyResponseFixture<'_> {
    fn request(
        &self,
        request_id: &str,
        effects: Vec<GovernedResponseEffect>,
        grants: Vec<ToolGrant>,
    ) -> GovernedActiveResponseRequest {
        let capability = CapabilityToken::sign(
            CapabilityTokenBody {
                id: format!("legacy-capability-{request_id}"),
                issuer: self.issuer.public_key(),
                subject: self.executor.public_key(),
                scope: ChioScope {
                    grants,
                    ..ChioScope::default()
                },
                issued_at: self.now.saturating_sub(1),
                expires_at: self.now.saturating_add(600),
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            self.issuer,
        )
        .unwrap();
        let canonical_plan_body = serde_json::json!({
            "actionId": request_id,
            "effects": effects,
            "target": {"sessionId": "session-active-1"}
        });
        let plan_body_hash =
            GovernedResponsePlanIntentBody::plan_body_hash(&canonical_plan_body).unwrap();
        let expires_at = self.now + 240;
        let intent = GovernedTransactionIntent {
            id: request_id.to_owned(),
            server_id: ACTIVE_RESPONSE_SERVER_ID.to_owned(),
            tool_name: ACTIVE_RESPONSE_PLAN_TOOL_NAME.to_owned(),
            purpose: "contain compromised session".to_owned(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
            body: GovernedTransactionIntentBody::ActiveResponsePlan(Box::new(
                GovernedResponsePlanIntentBody {
                    plan_schema: GOVERNED_RESPONSE_PLAN_SCHEMA.to_owned(),
                    plan_id: request_id.to_owned(),
                    operator_capability_id: capability.id.clone(),
                    operator_capability_hash: sha256_hex(
                        &canonical_json_bytes(&capability).unwrap(),
                    ),
                    operator_capability_expires_at: capability.expires_at,
                    executor_subject: capability.subject.clone(),
                    canonical_plan_body,
                    plan_body_hash,
                    target_binding: serde_json::json!({"sessionId": "session-active-1"}),
                    ordered_effects: effects,
                    expires_at,
                    rollback_binding: serde_json::json!({"mode": "remove_contributions"}),
                },
            )),
        };
        let governed_intent_hash = intent.binding_hash().unwrap();
        let proposal_created_at = self.now;
        let proposal_deadline = ThresholdApprovalProposalBody::proposal_deadline(
            proposal_created_at,
            self.requirement.timeout_seconds,
            capability.expires_at,
            Some(expires_at),
        )
        .unwrap();
        let proposal = ThresholdApprovalProposal::sign(
            ThresholdApprovalProposalBody {
                schema: THRESHOLD_APPROVAL_PROPOSAL_SCHEMA.to_string(),
                proposal_id: format!("proposal-{request_id}"),
                request_id: request_id.to_owned(),
                governed_intent_hash: governed_intent_hash.clone(),
                subject: capability.subject.clone(),
                authorizing_capability_digest: sha256_hex(
                    &canonical_json_bytes(&capability).unwrap(),
                ),
                policy_hash: self.requirement.policy_hash.clone(),
                threshold: self.requirement.threshold,
                eligible_set_digest: self.requirement.eligible_set_digest.clone(),
                proposal_created_at,
                proposal_deadline,
                policy_authority: self.policy_authority.public_key(),
            },
            self.policy_authority,
        )
        .unwrap();
        let proposal_hash = proposal.artifact_digest().unwrap();
        let approval_tokens = self
            .approvers
            .into_iter()
            .enumerate()
            .map(|(index, approver)| {
                GovernedApprovalToken::sign(
                    GovernedApprovalTokenBody {
                        id: format!("token-{request_id}-{index}"),
                        approver: approver.public_key(),
                        subject: capability.subject.clone(),
                        governed_intent_hash: governed_intent_hash.clone(),
                        request_id: request_id.to_owned(),
                        threshold_proposal_hash: Some(proposal_hash.clone()),
                        issued_at: self.now,
                        expires_at: proposal_deadline,
                        decision: GovernedApprovalDecision::Approved,
                    },
                    approver,
                )
                .unwrap()
            })
            .collect();
        GovernedActiveResponseRequest {
            request_id: request_id.to_owned(),
            operator_capability: capability,
            governed_intent: intent,
            approval_tokens,
            threshold_approval_proposal: proposal,
            federated_origin_kernel_id: None,
        }
    }
}

#[test]
fn legacy_active_response_commit_refuses_without_consuming_approval() {
    let base = real_adapter_fixture();
    let response_plan = base.native_request().response_plan().clone();
    let RealAdapterFixture {
        _directory,
        paths,
        operator_authority,
        executor_signer,
        submission_authority,
        threshold_policy_authority: policy_authority,
        finding,
        clock,
        runtime: original_runtime,
        ..
    } = base;
    // Retire the first handle before reconstructing its real durable stores.
    drop(original_runtime);
    let approver_a = Keypair::generate();
    let approver_b = Keypair::generate();
    let requirement = ThresholdApprovalRequirement::new(
        hex::encode(response_plan.policy_hash.as_bytes()),
        2,
        vec![
            ThresholdApproverIdentity {
                identifier: "alice".into(),
                public_key: approver_a.public_key(),
            },
            ThresholdApproverIdentity {
                identifier: "bob".into(),
                public_key: approver_b.public_key(),
            },
        ],
        "legacy-retirement-directory".into(),
        300,
    )
    .unwrap();
    let runtime = build_real_adapter_runtime(
        &paths,
        &operator_authority,
        &executor_signer,
        &submission_authority,
        &policy_authority,
        &requirement,
        &finding,
        &response_plan,
        clock,
        false,
    );
    let RealAdapterRuntime {
        mut kernel,
        coordinator,
        executor: executor_authority,
        effects: effects_authority,
        ..
    } = runtime;
    drop(coordinator);
    let kernel = Arc::get_mut(&mut kernel).expect("sole published kernel handle");
    assert!(
        kernel
            .governed_security_runtime_status()
            .active_response_enabled
    );
    let database = _directory.path().join("legacy-v1.db");
    let locks = _directory.path().join("legacy-v1-locks");
    crate::create_private_directory(&locks).unwrap();
    chio_store_sqlite::SqliteAuthorityStore::provision(&database, &locks).unwrap();
    let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving_with_clock(
        database,
        locks,
        kernel.authority_clock(),
    )
    .unwrap();
    let store = authority.admission_operation_store();
    kernel
        .set_durable_admission_store(
            Arc::new(store.clone()),
            Arc::new(authority.tool_outcome_store()),
            authority.mutation_fence(),
        )
        .unwrap();
    kernel.set_revocation_store_handle(Arc::new(authority.revocation_store()));
    let now = kernel
        .authority_clock_reading()
        .unwrap()
        .unix_millis()
        .as_secs();
    let executor = Keypair::generate();
    let effects = vec![
        GovernedResponseEffect::RestrictEgress,
        GovernedResponseEffect::SuspendSession,
    ];
    let grants = effects
        .iter()
        .map(|effect| legacy_grant(ACTIVE_RESPONSE_SERVER_ID, effect.tool_name()))
        .collect();
    let fixture = LegacyResponseFixture {
        issuer: &operator_authority,
        requirement: &requirement,
        // The legacy verifier trusts its actual kernel signing root. The
        // published modern policy authority remains installed and unchanged.
        policy_authority: &operator_authority,
        approvers: [&approver_a, &approver_b],
        executor: &executor,
        now,
    };
    let request = fixture.request("active-response-1", effects.clone(), grants);

    let mut mismatched = request.clone();
    let GovernedTransactionIntentBody::ActiveResponsePlan(plan) =
        &mut mismatched.governed_intent.body
    else {
        panic!("active-response body");
    };
    plan.canonical_plan_body["actionId"] = serde_json::json!("substituted-response");
    assert!(kernel
        .admit_governed_active_response(&mismatched)
        .unwrap_err()
        .to_string()
        .contains("body hash"));

    let mut mismatched_effects = fixture.request(
        "active-response-mismatched-effects",
        vec![GovernedResponseEffect::RestrictEgress],
        vec![legacy_grant(
            ACTIVE_RESPONSE_SERVER_ID,
            GovernedResponseEffect::RestrictEgress.tool_name(),
        )],
    );
    let GovernedTransactionIntentBody::ActiveResponsePlan(plan) =
        &mut mismatched_effects.governed_intent.body
    else {
        panic!("active-response body");
    };
    plan.canonical_plan_body["effects"] = serde_json::json!([
        GovernedResponseEffect::RestrictEgress,
        GovernedResponseEffect::SuspendSession
    ]);
    plan.plan_body_hash =
        GovernedResponsePlanIntentBody::plan_body_hash(&plan.canonical_plan_body).unwrap();
    assert!(kernel
        .admit_governed_active_response(&mismatched_effects)
        .unwrap_err()
        .to_string()
        .contains("effects do not match"));

    let mut raw_plan_hash = request.clone();
    let GovernedTransactionIntentBody::ActiveResponsePlan(plan) =
        &raw_plan_hash.governed_intent.body
    else {
        panic!("active-response body");
    };
    let substituted_hash = plan.plan_body_hash.clone();
    let mut substituted_proposal = raw_plan_hash.threshold_approval_proposal.body.clone();
    substituted_proposal.governed_intent_hash = substituted_hash.clone();
    raw_plan_hash.threshold_approval_proposal =
        ThresholdApprovalProposal::sign(substituted_proposal, &operator_authority).unwrap();
    let substituted_proposal_hash = raw_plan_hash
        .threshold_approval_proposal
        .artifact_digest()
        .unwrap();
    raw_plan_hash.approval_tokens = [&approver_a, &approver_b]
        .into_iter()
        .enumerate()
        .map(|(index, approver)| {
            GovernedApprovalToken::sign(
                GovernedApprovalTokenBody {
                    id: format!("raw-plan-token-{index}"),
                    approver: approver.public_key(),
                    subject: raw_plan_hash.operator_capability.subject.clone(),
                    governed_intent_hash: substituted_hash.clone(),
                    request_id: raw_plan_hash.request_id.clone(),
                    threshold_proposal_hash: Some(substituted_proposal_hash.clone()),
                    issued_at: now,
                    expires_at: raw_plan_hash
                        .threshold_approval_proposal
                        .body
                        .proposal_deadline,
                    decision: GovernedApprovalDecision::Approved,
                },
                approver,
            )
            .unwrap()
        })
        .collect();
    let raw_plan_error = kernel
        .admit_governed_active_response(&raw_plan_hash)
        .unwrap_err();
    assert!(
        matches!(&raw_plan_error, KernelError::GovernedTransactionDenied(_)),
        "raw plan substitution returned a different typed family: {raw_plan_error:?}"
    );
    assert!(
        raw_plan_error
            .to_string()
            .contains("proposal does not match"),
        "raw plan substitution rejected before its intended binding check: {raw_plan_error:?}"
    );

    let missing_grant = fixture.request(
        "active-response-missing-grant",
        effects,
        vec![legacy_grant(
            ACTIVE_RESPONSE_SERVER_ID,
            GovernedResponseEffect::RestrictEgress.tool_name(),
        )],
    );
    assert!(kernel
        .admit_governed_active_response(&missing_grant)
        .unwrap_err()
        .to_string()
        .contains("suspend_session"));

    let revoked = fixture.request(
        "active-response-revoked",
        vec![GovernedResponseEffect::RestrictEgress],
        vec![legacy_grant(
            ACTIVE_RESPONSE_SERVER_ID,
            GovernedResponseEffect::RestrictEgress.tool_name(),
        )],
    );
    kernel
        .revoke_capability(&revoked.operator_capability.id)
        .unwrap();
    assert!(matches!(
        kernel.admit_governed_active_response(&revoked),
        Err(KernelError::CapabilityRevoked(id)) if id == revoked.operator_capability.id
    ));

    let admitted = kernel.admit_governed_active_response(&request).unwrap();
    assert_eq!(admitted.state(), AdmissionOperationState::ApprovalReserved);
    assert_eq!(admitted.requirement(), &requirement);
    assert_eq!(
        admitted.operator_capability().capability_id(),
        request.operator_capability.id
    );
    assert_eq!(
        admitted.operation().binding().kind(),
        chio_kernel::admission_operation::AdmissionOperationKind::GovernedActiveResponse
    );
    assert_eq!(
        admitted.operation().binding().participant_requirements(),
        chio_kernel::admission_operation::AdmissionParticipantRequirements {
            approval: true,
            ..chio_kernel::admission_operation::AdmissionParticipantRequirements::NONE
        }
    );
    assert_eq!(
        admitted.approval_set().approval_set_hash().unwrap(),
        admitted.approval_set_hash()
    );
    let operation_id = admitted.operation_id().to_owned();
    let typed_operation_id = admitted.operation().binding().operation_id().clone();
    let mut mismatched_approval_set = request.clone();
    mismatched_approval_set.approval_tokens = mismatched_approval_set
        .approval_tokens
        .iter()
        .zip([&approver_a, &approver_b])
        .enumerate()
        .map(|(index, (token, approver))| {
            let mut body = token.body();
            let replacement_token_id = format!("replacement-active-response-token-{index}");
            body.id = replacement_token_id;
            GovernedApprovalToken::sign(body, approver).unwrap()
        })
        .collect();
    assert!(kernel
        .admit_governed_active_response(&mismatched_approval_set)
        .unwrap_err()
        .to_string()
        .contains("retained approval reservation"));
    let mut admitted = kernel
        .admit_governed_active_response(&request)
        .expect("mismatched replay must not compensate retained admission");
    assert_eq!(admitted.state(), AdmissionOperationState::ApprovalReserved);
    assert!(matches!(
        kernel.commit_governed_active_response_dispatch(&mut admitted),
        Err(KernelError::GovernedTransactionDenied(_))
    ));
    assert_eq!(admitted.state(), AdmissionOperationState::ApprovalReserved);
    assert_eq!(
        store
            .load_by_operation_id(&typed_operation_id)
            .unwrap()
            .unwrap()
            .state(),
        AdmissionOperationState::ApprovalReserved
    );

    let mut recovered = kernel.admit_governed_active_response(&request).unwrap();
    assert_eq!(recovered.operation_id(), operation_id);
    assert_eq!(recovered.state(), AdmissionOperationState::ApprovalReserved);
    assert!(matches!(
        kernel.commit_governed_active_response_dispatch(&mut recovered),
        Err(KernelError::GovernedTransactionDenied(_))
    ));
    assert_eq!(
        store
            .load_by_operation_id(&typed_operation_id)
            .unwrap()
            .unwrap()
            .state(),
        AdmissionOperationState::ApprovalReserved
    );
    kernel.cancel_governed_active_response(&recovered).unwrap();
    assert_eq!(executor_authority.calls(), 0);
    assert_eq!(effects_authority.executions(), 0);
    assert_eq!(
        store
            .load_by_operation_id(&typed_operation_id)
            .unwrap()
            .unwrap()
            .state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
}
