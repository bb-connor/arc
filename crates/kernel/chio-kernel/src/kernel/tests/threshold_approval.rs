fn threshold_test_fixture() -> (
    ChioKernel,
    CapabilityToken,
    ToolGrant,
    chio_core::capability::governance::GovernedTransactionIntent,
    ToolCallRequest,
    u64,
) {
    let mut config = make_config();
    config.policy_hash = "33".repeat(32);
    let kernel = make_kernel(config);
    let subject = Keypair::generate();
    let grant = make_governed_monetary_grant("payments", "transfer", 100, 1_000, "USD", 50);
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            make_scope(vec![grant.clone()]),
            3_600,
        )
        .expect("capability");
    let intent = make_governed_intent(
        "threshold-intent",
        "payments",
        "transfer",
        "approved transfer",
        100,
        "USD",
    );
    let now = current_unix_timestamp();
    let request = ToolCallRequest {
        request_id: "threshold-request".to_string(),
        capability: capability.clone(),
        tool_name: "transfer".to_string(),
        server_id: "payments".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: Some(intent.clone()),
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    (kernel, capability, grant, intent, request, now)
}

fn legacy_threshold_test_token(
    kernel: &ChioKernel,
    capability: &CapabilityToken,
    intent: &chio_core::capability::governance::GovernedTransactionIntent,
    request_id: &str,
    token_id: &str,
    now: u64,
) -> GovernedApprovalToken {
    GovernedApprovalToken::sign(
        chio_core::capability::governance::GovernedApprovalTokenBody {
            id: token_id.to_string(),
            approver: kernel.config.keypair.public_key(),
            subject: capability.subject.clone(),
            governed_intent_hash: intent.binding_hash().expect("intent hash"),
            threshold_proposal_hash: None,
            request_id: request_id.to_string(),
            issued_at: now.saturating_sub(1),
            expires_at: now + 300,
            decision: GovernedApprovalDecision::Approved,
        },
        &kernel.config.keypair,
    )
    .expect("legacy approval")
}

#[test]
fn approval_token_input_rejects_singular_list_ambiguity() {
    let (kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    let token = legacy_threshold_test_token(
        &kernel,
        &capability,
        &intent,
        &request.request_id,
        "legacy-a",
        now,
    );
    request.approval_token = Some(token.clone());
    request.approval_tokens = vec![token];
    let error = request
        .normalized_approval_tokens()
        .expect_err("ambiguous token forms must deny");
    assert!(error.to_string().contains("must not both"));
}

#[test]
fn threshold_policy_authority_roots_are_bounded_and_deduplicated() {
    let mut kernel = make_kernel(make_config());
    let authority = Keypair::generate().public_key();
    kernel
        .set_threshold_approval_policy_authorities(vec![authority.clone(), authority.clone()])
        .expect("deduplicated trust roots");
    assert_eq!(kernel.threshold_approval_policy_authorities(), &[authority]);

    let oversized = (0..=chio_core::capability::threshold_approval::MAX_THRESHOLD_APPROVAL_TOKENS)
        .map(|_| Keypair::generate().public_key())
        .collect();
    assert!(kernel
        .set_threshold_approval_policy_authorities(oversized)
        .is_err());
}

#[test]
fn one_element_list_preserves_legacy_semantics_without_threshold_policy() {
    let (kernel, capability, grant, intent, mut request, now) = threshold_test_fixture();
    request.approval_tokens = vec![legacy_threshold_test_token(
        &kernel,
        &capability,
        &intent,
        &request.request_id,
        "legacy-list",
        now,
    )];
    assert!(kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .is_ok());
}

#[test]
fn multiple_legacy_list_tokens_cannot_bypass_threshold_proposal() {
    let (kernel, capability, grant, intent, mut request, now) = threshold_test_fixture();
    request.approval_tokens = vec![
        legacy_threshold_test_token(
            &kernel,
            &capability,
            &intent,
            &request.request_id,
            "legacy-a",
            now,
        ),
        legacy_threshold_test_token(
            &kernel,
            &capability,
            &intent,
            &request.request_id,
            "legacy-b",
            now,
        ),
    ];
    let error = kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .expect_err("multiple legacy tokens must deny");
    assert!(error.to_string().contains("were not negotiated"));
}

#[test]
fn configured_threshold_policy_cannot_downgrade_after_resolver_loss() {
    let (mut kernel, capability, grant, _intent, request, now) = threshold_test_fixture();
    let approver = Keypair::generate().public_key();
    let requirement = crate::threshold_approval::ThresholdApprovalRequirement::new(
        1,
        std::collections::BTreeMap::from([("approver".to_string(), approver)]),
        900,
        kernel.config.policy_hash.clone(),
        1,
    )
    .expect("requirement");
    kernel.set_threshold_approval_requirement_resolver(std::sync::Arc::new(
        move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
            Ok(requirement.clone())
        },
    ));
    kernel.clear_threshold_approval_requirement_resolver();
    let error = kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .expect_err("missing configured resolver must deny");
    assert!(error.to_string().contains("resolver is unavailable"));
}

#[test]
fn stale_threshold_policy_denies_before_legacy_fallback() {
    let (mut kernel, capability, grant, _intent, request, now) = threshold_test_fixture();
    kernel.set_threshold_approval_requirement_resolver(std::sync::Arc::new(
        move |_: &crate::threshold_approval::ThresholdApprovalRequest, received: &str| {
            Err(
                crate::threshold_approval::ThresholdApprovalResolutionError::StalePolicy {
                    expected: "44".repeat(32),
                    received: received.to_string(),
                },
            )
        },
    ));
    let error = kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .expect_err("stale threshold policy must deny");
    assert!(error.to_string().contains("stale"));
}

#[test]
fn policy_approver_directory_does_not_create_an_approval_trigger() {
    let (mut kernel, capability, mut grant, _intent, request, now) = threshold_test_fixture();
    grant
        .constraints
        .retain(|constraint| !matches!(constraint, Constraint::RequireApprovalAbove { .. }));
    let approver = Keypair::generate().public_key();
    let requirement = crate::threshold_approval::ThresholdApprovalRequirement::new(
        1,
        std::collections::BTreeMap::from([("approver".to_string(), approver)]),
        900,
        kernel.config.policy_hash.clone(),
        1,
    )
    .expect("requirement");
    kernel.set_threshold_approval_requirement_resolver(std::sync::Arc::new(
        move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
            Ok(requirement.clone())
        },
    ));
    assert!(kernel
        .validate_governed_transaction(&request, &capability, &grant, None, now)
        .is_ok());
}
