#[test]
fn active_response_authorization_binds_compact_plan_and_logical_projection() {
    let fixture = active_response_fixture(
        &[
            ResponseEffectKind::EscalateAlert,
            ResponseEffectKind::RestrictEgress,
            ResponseEffectKind::RestrictEgress,
            ResponseEffectKind::ThrottleSession,
        ],
        vec![
            GovernedResponseEffect::RestrictEgress,
            GovernedResponseEffect::ThrottleSession,
        ],
        &[
            GovernedResponseEffect::RestrictEgress,
            GovernedResponseEffect::ThrottleSession,
        ],
    );

    let compact = canonical_json_bytes(&fixture.compact_plan_body).expect("compact plan body");
    assert!(compact.len() < 64 * 1024);
    assert!(!String::from_utf8_lossy(&compact).contains("canonical_contribution"));

    let verified = fixture
        .kernel
        .verify_active_response_authorization(&fixture.request)
        .expect("valid active response authorization");
    assert_eq!(verified.request_id(), "action-active-response");
    assert_eq!(
        verified.authorization_capability_id(),
        fixture.request.operator_capability().id
    );
    assert_eq!(
        verified.authorization_capability_hash(),
        fixture.capability_hash
    );
    assert_eq!(
        verified.governed_intent_hash(),
        fixture
            .request
            .governed_intent()
            .binding_hash()
            .expect("governed intent hash")
    );
    assert_eq!(verified.plan_body_hash(), fixture.plan_hash);
    assert_eq!(
        verified.executor_subject(),
        &fixture.request.operator_capability().subject
    );
    assert_eq!(
        verified.authenticated_submitter(),
        fixture.request.authenticated_submitter()
    );
    assert_eq!(
        verified.operator_capability_expires_at(),
        fixture.request.operator_capability().expires_at
    );
    assert_eq!(
        verified.governed_operation_expires_at(),
        fixture.request.plan_body().expires_at_unix_ms / 1_000
    );
    assert_eq!(
        verified.policy_id().map(RecordId::as_str),
        Some("governed-active-response-policy")
    );
    assert_eq!(
        verified.ordered_effects(),
        &[
            GovernedResponseEffect::RestrictEgress,
            GovernedResponseEffect::ThrottleSession,
        ]
    );
}

#[test]
fn active_response_authorization_requires_a_ready_exact_signed_finding_authority() {
    let mut missing = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );
    missing.kernel.clear_active_response_finding_authority();
    assert!(missing
        .kernel
        .verify_active_response_authorization(&missing.request)
        .is_err());

    let unavailable = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );
    unavailable.finding_authority.set_ready(false);
    assert!(unavailable
        .kernel
        .verify_active_response_authorization(&unavailable.request)
        .is_err());

    let rebound = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );
    let replacement = correlated_finding_evidence(
        rebound.request.plan_body().created_at_unix_ms,
        Digest32::new([0x48; 32]),
        1,
    );
    rebound.finding_authority.replace(replacement);
    assert!(rebound
        .kernel
        .verify_active_response_authorization(&rebound.request)
        .is_err());
}

#[test]
fn active_response_authorization_rejects_a_plan_policy_hash_outside_kernel_authority() {
    let mut fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );
    fixture.kernel.config.policy_hash = "44".repeat(32);
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&fixture.request)
        .is_err());
}

#[test]
fn active_response_authorization_rejects_governed_alert_only_plan() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::EscalateAlert],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );

    assert!(fixture
        .kernel
        .verify_active_response_authorization(&fixture.request)
        .is_err());
}

#[test]
fn active_response_authorization_rejects_missing_exact_grant() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[],
    );

    assert!(fixture
        .kernel
        .verify_active_response_authorization(&fixture.request)
        .is_err());
}

#[test]
fn active_response_authorization_preserves_lightweight_automatic_declaration_as_binding() {
    let fixture = active_response_fixture_with_grants_and_approval(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        vec![active_response_grant(
            GovernedResponseEffect::RestrictEgress,
        )],
        ResponseApprovalRequirement::Automatic,
    );

    let verified = fixture
        .kernel
        .verify_active_response_authorization(&fixture.request)
        .expect("lightweight automatic declaration must pass immutable binding verification");
    assert_eq!(
        verified.declared_approval_requirement(),
        &ResponseApprovalRequirement::Automatic
    );
    assert!(verified.policy_id().is_none());
}

#[test]
fn active_response_authorization_rejects_heavy_automatic_declaration() {
    let fixture = active_response_fixture_with_grants_and_approval(
        &[ResponseEffectKind::SuspendSession],
        vec![GovernedResponseEffect::SuspendSession],
        vec![active_response_grant(
            GovernedResponseEffect::SuspendSession,
        )],
        ResponseApprovalRequirement::Automatic,
    );

    let error = fixture
        .kernel
        .verify_active_response_authorization(&fixture.request)
        .expect_err("heavy containment must never accept automatic approval");
    assert!(error
        .to_string()
        .contains("automatic approval cannot be declared for a heavy containment effect"));
}

#[test]
fn active_response_authorization_preserves_typed_revocation_denial() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );
    let capability_id = fixture.request.operator_capability().id.clone();
    fixture
        .kernel
        .revoke_capability(&capability_id)
        .expect("revoke operator capability");

    assert!(matches!(
        fixture
            .kernel
            .verify_active_response_authorization(&fixture.request),
        Err(KernelError::CapabilityRevoked(revoked)) if revoked == capability_id
    ));
}

#[test]
fn active_response_authorization_rejects_authenticated_submitter_mismatch() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );

    let different_submitter = make_keypair();
    let mismatched_proof = signed_submission_proof(
        fixture.request.plan_body(),
        fixture.request.governed_intent(),
        &different_submitter,
    );
    let request = ActiveResponseAuthorizationRequest::new(
        fixture.request.operator_capability().clone(),
        fixture.request.plan_body().clone(),
        fixture.request.governed_intent().clone(),
        mismatched_proof,
    )
    .expect("signed but mismatched submitter request");
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&request)
        .is_err());
}

#[test]
fn active_response_authorization_rejects_tampered_or_expired_submission_proof() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );

    let mut tampered = fixture.request.submission_proof().clone();
    tampered.body.plan_body_hash = "00".repeat(32);
    assert!(ActiveResponseAuthorizationRequest::new(
        fixture.request.operator_capability().clone(),
        fixture.request.plan_body().clone(),
        fixture.request.governed_intent().clone(),
        tampered,
    )
    .is_err());

    let plan = fixture.request.plan_body();
    let governed_intent_hash = fixture
        .request
        .governed_intent()
        .binding_hash()
        .expect("governed intent hash");
    let expiry = plan
        .created_at_unix_ms
        .checked_add(1)
        .expect("proof expiry");
    let body = ActiveResponseSubmissionProofBody::new(
        plan.action_id.clone(),
        plan.tenant_id.clone(),
        fixture.plan_hash.clone(),
        governed_intent_hash,
        fixture.submitter.public_key(),
        plan.created_at_unix_ms,
        expiry,
    )
    .expect("short-lived proof body");
    let proof = ActiveResponseSubmissionProof::sign_with_backend(
        body,
        &Ed25519Backend::new(fixture.submitter.clone()),
    )
    .expect("short-lived proof");
    let request = ActiveResponseAuthorizationRequest::new(
        fixture.request.operator_capability().clone(),
        plan.clone(),
        fixture.request.governed_intent().clone(),
        proof,
    )
    .expect("signed short-lived request");
    assert!(fixture
        .kernel
        .verify_active_response_authorization_at(&request, expiry)
        .is_err());
}

#[test]
fn active_response_submission_signature_is_domain_separated_and_identity_bound() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );
    let original = fixture.request.submission_proof();
    let canonical = canonical_json_bytes(&original.body).expect("canonical submission proof body");

    let mut wrong_domain = original.clone();
    wrong_domain.signature = fixture.submitter.sign(&canonical);
    assert!(!wrong_domain
        .verify_signature()
        .expect("wrong-domain signature verification"));

    let mut signing_bytes = b"chio.active-response-submission.v1\0".to_vec();
    signing_bytes.extend_from_slice(&canonical);
    let mut wrong_identity = original.clone();
    wrong_identity.signature = Keypair::generate().sign(&signing_bytes);
    assert!(!wrong_identity
        .verify_signature()
        .expect("wrong-identity signature verification"));
}

#[test]
fn active_response_submission_authority_pin_is_required_and_install_once() {
    let missing = make_kernel(make_config());
    let expected = Keypair::generate().public_key();
    assert!(missing
        .ensure_active_response_submission_authority_matches(&expected)
        .is_err());

    let mut fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );
    let installed = fixture.submission_authority.public_key();
    assert!(fixture
        .kernel
        .ensure_active_response_submission_authority_matches(&installed)
        .is_ok());
    assert!(fixture
        .kernel
        .set_active_response_submission_authority(installed.clone())
        .is_ok());

    let wrong = Keypair::generate().public_key();
    assert!(fixture
        .kernel
        .set_active_response_submission_authority(wrong.clone())
        .is_err());
    assert!(fixture
        .kernel
        .ensure_active_response_submission_authority_matches(&wrong)
        .is_err());
    assert!(fixture
        .kernel
        .ensure_active_response_submission_authority_matches(&installed)
        .is_ok());

    fixture.kernel.governed_security_runtime_generation = 1;
    assert!(fixture
        .kernel
        .set_active_response_submission_authority(wrong)
        .is_err());
    assert!(fixture
        .kernel
        .ensure_active_response_submission_authority_matches(&installed)
        .is_ok());
}

#[test]
fn active_response_authorization_rejects_plan_and_capability_binding_mutations() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );

    let mut changed_body = fixture.request.plan_body().clone();
    changed_body.reason_hash = Digest32::new([0x99; 32]);
    let changed_request = ActiveResponseAuthorizationRequest::new(
        fixture.request.operator_capability().clone(),
        changed_body,
        fixture.request.governed_intent().clone(),
        fixture.request.submission_proof().clone(),
    )
    .expect("structurally valid changed request");
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&changed_request)
        .is_err());

    let mut changed_digest = fixture.request.plan_body().clone();
    changed_digest.operator_capability.capability_digest = Digest32::new([0xaa; 32]);
    let changed_request = ActiveResponseAuthorizationRequest::new(
        fixture.request.operator_capability().clone(),
        changed_digest,
        fixture.request.governed_intent().clone(),
        fixture.request.submission_proof().clone(),
    )
    .expect("structurally valid digest mutation");
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&changed_request)
        .is_err());

    let mut changed_subject = fixture.request.plan_body().clone();
    changed_subject.operator_capability.executor_subject =
        RecordId::new(make_keypair().public_key().to_hex()).expect("changed executor subject");
    let changed_request = ActiveResponseAuthorizationRequest::new(
        fixture.request.operator_capability().clone(),
        changed_subject,
        fixture.request.governed_intent().clone(),
        fixture.request.submission_proof().clone(),
    )
    .expect("structurally valid executor mutation");
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&changed_request)
        .is_err());
}

#[test]
fn active_response_authorization_rejects_future_or_expired_plan() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );

    let now = fixture.request.operator_capability().issued_at;
    for (created_at_unix_ms, expires_at_unix_ms) in [
        ((now + 1) * 1_000, (now + 2) * 1_000),
        ((now - 2) * 1_000, (now - 1) * 1_000),
    ] {
        let mut plan = fixture.request.plan_body().clone();
        plan.created_at_unix_ms = created_at_unix_ms;
        plan.expires_at_unix_ms = expires_at_unix_ms;
        plan.ttl_ms = expires_at_unix_ms - created_at_unix_ms;
        let request = ActiveResponseAuthorizationRequest::new(
            fixture.request.operator_capability().clone(),
            plan,
            fixture.request.governed_intent().clone(),
            fixture.request.submission_proof().clone(),
        )
        .expect("structurally valid time mutation");
        assert!(fixture
            .kernel
            .verify_active_response_authorization(&request)
            .is_err());
    }
}

#[test]
fn active_response_authorization_rejects_unsupported_grant_semantics() {
    let exact = active_response_grant(GovernedResponseEffect::RestrictEgress);
    let mut wildcard_server = exact.clone();
    wildcard_server.server_id = "*".to_string();
    let mut wildcard_tool = exact.clone();
    wildcard_tool.tool_name = "*".to_string();
    let mut constrained = exact.clone();
    constrained.constraints = vec![Constraint::MaxArgsSize(1_024)];
    let mut quota_limited = exact.clone();
    quota_limited.max_invocations = Some(1);
    let mut monetary = exact.clone();
    monetary.max_cost_per_invocation = Some(MonetaryAmount {
        units: 1,
        currency: "USD".to_string(),
    });
    let mut dpop = exact.clone();
    dpop.dpop_required = Some(false);
    let mut wrong_operation = exact;
    wrong_operation.operations = vec![Operation::ReadResult];

    for grant in [
        wildcard_server,
        wildcard_tool,
        constrained,
        quota_limited,
        monetary,
        dpop,
        wrong_operation,
    ] {
        let fixture = active_response_fixture_with_grants_and_approval(
            &[ResponseEffectKind::RestrictEgress],
            vec![GovernedResponseEffect::RestrictEgress],
            vec![grant],
            ResponseApprovalRequirement::Automatic,
        );
        assert!(fixture
            .kernel
            .verify_active_response_authorization(&fixture.request)
            .is_err());
    }
}

#[test]
fn active_response_authorization_rejects_unadmitted_capability_quotas() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );

    let shared = attenuated_operator_capability(&fixture, Some(5_000), None);
    let shared_request = rebuild_request_for_capability(&fixture, shared);
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&shared_request)
        .is_err());

    let aggregate = attenuated_operator_capability(
        &fixture,
        None,
        Some(
            chio_core::capability::aggregate_budget::AggregateInvocationBudget {
                scope:
                    chio_core::capability::aggregate_budget::AggregateInvocationScope::Capability,
                max_invocations: 1,
                root_binding: None,
            },
        ),
    );
    let aggregate_request = rebuild_request_for_capability(&fixture, aggregate);
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&aggregate_request)
        .is_err());
}

#[test]
fn active_response_authorization_rejects_delegated_capability_without_explicit_share() {
    let mut parent_grant = active_response_grant(GovernedResponseEffect::RestrictEgress);
    parent_grant.operations.push(Operation::Delegate);
    let mut fixture = active_response_fixture_with_grants_and_approval(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        vec![parent_grant],
        ResponseApprovalRequirement::Automatic,
    );
    let parent = fixture.request.operator_capability().clone();
    let child_subject = make_keypair();
    let child_scope = make_scope(vec![active_response_grant(
        GovernedResponseEffect::RestrictEgress,
    )]);
    let parent_scope_hash = scope_hash(&parent.scope).expect("parent scope hash");
    let child_scope_hash = scope_hash(&child_scope).expect("child scope hash");
    let link = make_chain_bound_delegation_link(
        &parent.id,
        &fixture.executor,
        &child_subject.public_key(),
        &parent.scope,
        parent.issued_at,
    );
    let child = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "active-response-delegated-no-share".to_string(),
                issuer: fixture.executor.public_key(),
                subject: child_subject.public_key(),
                scope: child_scope.clone(),
                issued_at: parent.issued_at,
                expires_at: parent.expires_at.saturating_sub(1),
                delegation_chain: vec![link],
                aggregate_invocation_budget: None,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash,
                child_scope_hash,
                normalized_subset_proof: compute_attenuation_witness(&parent.scope, &child_scope)
                    .expect("attenuation witness"),
                aggregate_family_preservation: None,
            },
            budget_share_bps: None,
        },
        &fixture.executor,
    )
    .expect("delegated operator capability");

    let receipt_path = unique_receipt_db_path("active-response-delegated-no-share");
    let seed_store = SqliteReceiptStore::open(&receipt_path).expect("seed receipt store");
    seed_store
        .record_capability_snapshot(&parent, None)
        .expect("record parent capability snapshot");
    drop(seed_store);
    fixture
        .kernel
        .set_receipt_store(Box::new(
            SqliteReceiptStore::open(&receipt_path).expect("active response receipt store"),
        ))
        .expect("install active response receipt store");
    trust_delegated_leaf_signer_for_scope(&mut fixture.kernel, &fixture.executor, &parent.scope);

    let request = rebuild_request_for_capability(&fixture, child);
    let error = fixture
        .kernel
        .verify_active_response_authorization(&request)
        .expect_err("delegated operator capability must require a budget participant");
    assert!(error
        .to_string()
        .contains("delegated operator capabilities are unsupported"));

    let _ = std::fs::remove_file(receipt_path);
}

#[test]
fn active_response_authorization_rejects_false_target_and_rollback_bindings() {
    let fixture = active_response_fixture(
        &[ResponseEffectKind::RestrictEgress],
        vec![GovernedResponseEffect::RestrictEgress],
        &[GovernedResponseEffect::RestrictEgress],
    );
    let original = fixture
        .request
        .governed_intent()
        .as_active_response_plan()
        .expect("active-response plan");

    let wrong_target = rebuild_request_with_bindings(
        &fixture,
        serde_json::json!({"affectedSetHash": "00".repeat(32)}),
        original.rollback_binding().clone(),
    );
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&wrong_target)
        .is_err());

    let wrong_rollback = rebuild_request_with_bindings(
        &fixture,
        original.target_binding().clone(),
        serde_json::json!({"responsePlanHash": "11".repeat(32)}),
    );
    assert!(fixture
        .kernel
        .verify_active_response_authorization(&wrong_rollback)
        .is_err());
}
