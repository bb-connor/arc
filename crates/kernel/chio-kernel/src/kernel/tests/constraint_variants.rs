use super::*;
// Constraint-variant tests.
//
// Shared fixtures are imported from the parent test module.

/// A grant with `MemoryStoreAllowlist` should deny a request whose
/// arguments carry a `store` value outside the allowlist, and allow
/// one whose `store` value is in the allowlist.
#[test]
fn kernel_denies_memory_write_to_disallowed_store() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("mem", vec!["memory_write"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "mem".to_string(),
            tool_name: "memory_write".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::MemoryStoreAllowlist(vec![
                "conversation".to_string(),
                "scratchpad".to_string(),
            ])],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let allowed = make_request_with_arguments(
        "req-mem-allow",
        &cap,
        "memory_write",
        "mem",
        serde_json::json!({"store": "conversation", "key": "k1", "value": "hello"}),
    );
    let denied = make_request_with_arguments(
        "req-mem-deny",
        &cap,
        "memory_write",
        "mem",
        serde_json::json!({"store": "privileged", "key": "k1", "value": "hello"}),
    );

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&allowed)
            .unwrap()
            .verdict,
        Verdict::Allow,
    );
    let denied_response = kernel.evaluate_tool_call_blocking(&denied).unwrap();
    assert_eq!(denied_response.verdict, Verdict::Deny);
    assert!(
        denied_response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("not in capability scope"),
        "unexpected deny reason: {:?}",
        denied_response.reason,
    );
}

/// `AudienceAllowlist` should not affect tool calls whose arguments do
/// not carry a recipient-style key.
#[test]
fn kernel_allows_action_when_unaffected_by_new_constraint() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["ping"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "ping".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::AudienceAllowlist(vec!["#ops".to_string()])],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // No recipient/audience/to/channel keys are present so the
    // AudienceAllowlist constraint is not activated.
    let request = make_request_with_arguments(
        "req-ping",
        &cap,
        "ping",
        "srv-a",
        serde_json::json!({"payload": "hello"}),
    );

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&request)
            .unwrap()
            .verdict,
        Verdict::Allow,
    );
}

// These domain constraints remain part of the protocol vocabulary, but the
// kernel cannot establish their grant-specific enforcement. A global guard
// configuration cannot discharge a narrower capability requirement.
fn unsupported_domain_constraints() -> [Constraint; 7] {
    use chio_core::capability::scope::{ContentReviewTier, SqlOperationClass};
    [
        Constraint::TableAllowlist(vec!["orders".to_string()]),
        Constraint::ColumnDenylist(vec!["users.ssn".to_string()]),
        Constraint::MaxRowsReturned(1),
        Constraint::OperationClass(SqlOperationClass::ReadOnly),
        Constraint::ContentReviewTier(ContentReviewTier::Strict),
        Constraint::MaxTransactionAmountUsd("1.00".to_string()),
        Constraint::RequireDualApproval(true),
    ]
}

fn externally_signed_domain_capability(
    issuer: &Keypair,
    subject: &PublicKey,
    grants: Vec<ToolGrant>,
) -> CapabilityToken {
    let now = current_unix_timestamp();
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: uuid::Uuid::new_v4().to_string(),
            issuer: issuer.public_key(),
            subject: subject.clone(),
            scope: make_scope(grants),
            issued_at: now.saturating_sub(60),
            expires_at: now.saturating_add(300),
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .unwrap()
}

#[test]
fn kg4_issuance_rejects_each_unenforced_domain_constraint() {
    let kernel = make_kernel(make_config());
    let subject = make_keypair().public_key();
    let mut accepted = Vec::new();
    for constraint in unsupported_domain_constraints() {
        let mut grant = make_grant("db", "sql_query");
        grant.constraints.push(constraint.clone());
        let result = kernel.issue_capability(&subject, make_scope(vec![grant]), 300);
        if !matches!(result, Err(KernelError::InvalidConstraint(_))) {
            accepted.push((constraint, result.err().map(|error| error.to_string())));
        }
    }
    assert!(
        accepted.is_empty(),
        "unsupported issuance results: {accepted:?}"
    );
}

#[test]
fn kg4_external_tokens_deny_before_sibling_fallback_without_tool_effects() {
    let issuer = make_keypair();
    let subject = make_keypair().public_key();
    let mut config = make_config();
    config.ca_public_keys.push(issuer.public_key());
    let mut kernel = make_kernel(config);
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "db",
        vec!["sql_query"],
        Arc::clone(&invocations),
    )));
    let mut unexpected = Vec::new();
    for constraint in unsupported_domain_constraints() {
        // Cover the lone grant, a matching sibling, and an unrelated grant.
        // Even the unrelated grant must not conceal unsupported authority.
        for sibling_kind in 0..3 {
            let mut constrained = make_grant("db", "sql_query");
            constrained.constraints.push(constraint.clone());
            let mut grants = Vec::new();
            if sibling_kind > 0 {
                grants.push(make_grant("db", "sql_query"));
            }
            if sibling_kind == 2 {
                constrained.server_id = "other-db".to_string();
            }
            grants.push(constrained);
            let cap = externally_signed_domain_capability(&issuer, &subject, grants);
            let request = make_request_with_arguments(
                &cap.id,
                &cap,
                "sql_query",
                "db",
                serde_json::json!({"query": "SELECT * FROM users", "amount_usd": "2.00"}),
            );
            let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
            if response.verdict != Verdict::Deny
                || !response
                    .reason
                    .as_deref()
                    .unwrap_or_default()
                    .contains("unsupported capability constraint")
            {
                unexpected.push((
                    constraint.clone(),
                    sibling_kind,
                    response.verdict,
                    response.reason,
                ));
            }
        }
    }
    assert!(
        unexpected.is_empty(),
        "unsupported admission results: {unexpected:?}"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn kg4_request_matching_rejects_unsupported_grants_before_route_filtering() {
    let issuer = make_keypair();
    for constraint in unsupported_domain_constraints() {
        let mut unsupported = make_grant("other-db", "other-tool");
        unsupported.constraints.push(constraint.clone());
        let cap = externally_signed_domain_capability(
            &issuer,
            &issuer.public_key(),
            vec![make_grant("db", "sql_query"), unsupported],
        );
        assert!(
            matches!(
                crate::capability_matches_request(&cap, "sql_query", "db", &serde_json::json!({})),
                Err(KernelError::InvalidConstraint(_))
            ),
            "matching silently skipped {constraint:?}"
        );
    }
}

#[test]
fn kg4_non_tool_admission_rejects_external_unsupported_scope() {
    let issuer = make_keypair();
    let mut config = make_config();
    config.ca_public_keys.push(issuer.public_key());
    let kernel = make_kernel(config);
    let mut grant = make_grant("db", "sql_query");
    grant
        .constraints
        .push(Constraint::TableAllowlist(vec!["orders".to_string()]));
    let cap = externally_signed_domain_capability(&issuer, &issuer.public_key(), vec![grant]);
    let error = kernel
        .validate_non_tool_capability(&cap, &cap.subject.to_hex())
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("unsupported capability constraint"));
}

// ---- ModelConstraint evaluation -----------------------------------------

/// A model listed in `allowed_model_ids` is admitted.
#[test]
fn kernel_allows_tool_call_when_model_is_in_allowlist() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["invoke"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "invoke".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::ModelConstraint {
                allowed_model_ids: vec!["claude-opus-4".to_string(), "gpt-5".to_string()],
                min_safety_tier: None,
            }],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let mut request = make_request_with_arguments(
        "req-model-allow",
        &cap,
        "invoke",
        "srv",
        serde_json::json!({"payload": "hello"}),
    );
    request.model_metadata = Some(chio_core::capability::scope::ModelMetadata {
        model_id: "claude-opus-4".to_string(),
        safety_tier: Some(chio_core::capability::scope::ModelSafetyTier::High),
        provider: Some("anthropic".to_string()),
        provenance_class: chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
    });

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&request)
            .unwrap()
            .verdict,
        Verdict::Allow,
    );
}

/// A model not in `allowed_model_ids` is denied.
#[test]
fn kernel_denies_tool_call_when_model_is_not_in_allowlist() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["invoke"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "invoke".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::ModelConstraint {
                allowed_model_ids: vec!["claude-opus-4".to_string()],
                min_safety_tier: None,
            }],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let mut request = make_request_with_arguments(
        "req-model-deny",
        &cap,
        "invoke",
        "srv",
        serde_json::json!({"payload": "hello"}),
    );
    request.model_metadata = Some(chio_core::capability::scope::ModelMetadata {
        model_id: "small-uncensored".to_string(),
        safety_tier: Some(chio_core::capability::scope::ModelSafetyTier::Low),
        provider: None,
        provenance_class: chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
    });

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("not in capability scope"),
        "unexpected deny reason: {:?}",
        response.reason,
    );
}

/// A model whose declared safety tier is below `min_safety_tier` is
/// denied.
#[test]
fn kernel_denies_tool_call_when_model_safety_tier_is_below_minimum() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["invoke"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "invoke".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::ModelConstraint {
                allowed_model_ids: Vec::new(),
                min_safety_tier: Some(chio_core::capability::scope::ModelSafetyTier::Standard),
            }],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let mut request = make_request_with_arguments(
        "req-model-low-tier",
        &cap,
        "invoke",
        "srv",
        serde_json::json!({"payload": "hello"}),
    );
    request.model_metadata = Some(chio_core::capability::scope::ModelMetadata {
        model_id: "small-uncensored".to_string(),
        safety_tier: Some(chio_core::capability::scope::ModelSafetyTier::Low),
        provider: None,
        provenance_class: chio_core::capability::governance::ProvenanceEvidenceClass::Asserted,
    });

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
}

/// When the grant carries a `ModelConstraint` with any requirement and
/// the request omits `model_metadata`, the kernel must deny. This
/// protects against a caller forgetting to declare their model.
#[test]
fn kernel_denies_tool_call_when_model_metadata_is_missing_but_required() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["invoke"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "invoke".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::ModelConstraint {
                allowed_model_ids: vec!["claude-opus-4".to_string()],
                min_safety_tier: Some(chio_core::capability::scope::ModelSafetyTier::Standard),
            }],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = make_request_with_arguments(
        "req-model-missing",
        &cap,
        "invoke",
        "srv",
        serde_json::json!({"payload": "hello"}),
    );
    // model_metadata remains None.

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
}

/// Wire back-compat: when the grant has no `ModelConstraint`, a
/// request that omits `model_metadata` must still be accepted. This
/// preserves the existing invocation shape used by every current call
/// site.
#[test]
fn kernel_allows_tool_call_without_model_metadata_when_grant_has_no_model_constraint() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["invoke"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv".to_string(),
            tool_name: "invoke".to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = make_request_with_arguments(
        "req-no-model-metadata",
        &cap,
        "invoke",
        "srv",
        serde_json::json!({"payload": "hello"}),
    );
    // model_metadata remains None.

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&request)
            .unwrap()
            .verdict,
        Verdict::Allow,
    );
}

/// `MemoryWriteDenyPatterns` should deny a write whose arguments
/// contain a string matching any supplied regex pattern.
#[test]
fn kernel_denies_memory_write_matching_deny_pattern() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("mem", vec!["memory_write"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "mem".to_string(),
            tool_name: "memory_write".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::MemoryWriteDenyPatterns(vec![
                r"AKIA[0-9A-Z]{16}".to_string(),
            ])],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let benign = make_request_with_arguments(
        "req-benign",
        &cap,
        "memory_write",
        "mem",
        serde_json::json!({"key": "k1", "value": "hello world"}),
    );
    let secret = make_request_with_arguments(
        "req-secret",
        &cap,
        "memory_write",
        "mem",
        serde_json::json!({
            "key": "k1",
            "value": "token=AKIAIOSFODNN7EXAMPLE",
        }),
    );

    assert_eq!(
        kernel.evaluate_tool_call_blocking(&benign).unwrap().verdict,
        Verdict::Allow,
    );
    assert_eq!(
        kernel.evaluate_tool_call_blocking(&secret).unwrap().verdict,
        Verdict::Deny,
    );
}
