
use super::*;

#[test]
fn cli_mcp_manifest_uses_local_wrapped_process_topology() {
    let signer = chio_core::Keypair::from_seed(&[92; 32]);
    let manifest = chio_manifest::ToolManifest {
        schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "cli-remote-flow".to_string(),
        name: "CLI remote flow".to_string(),
        description: None,
        version: "1".to_string(),
        tools: vec![chio_manifest::ToolDefinition {
            name: "read".to_string(),
            description: "Read".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("sign CLI remote manifest: {error}"));
    let path = std::env::temp_dir().join(format!(
        "chio-cli-remote-flow-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("system clock: {error}"))
            .as_nanos()
    ));
    std::fs::write(
        &path,
        serde_json::to_vec(&signed)
            .unwrap_or_else(|error| panic!("encode CLI remote manifest: {error}")),
    )
    .unwrap_or_else(|error| panic!("write CLI remote manifest: {error}"));

    let registry =
        load_manifest_for_mcp_kernel(&path, &signer.public_key().to_hex(), "cli-remote-flow")
            .unwrap_or_else(|error| panic!("load remote CLI manifest: {error}"));
    chio_control_plane::security::reject_unprotected_flow_manifest(&registry)
        .unwrap_or_else(|error| panic!("local wrapped process must remain compatible: {error}"));
    std::fs::remove_file(path)
        .unwrap_or_else(|error| panic!("remove CLI remote manifest: {error}"));
}

#[test]
fn cli_mcp_teardown_reports_operation_and_shutdown_failures() {
    let operation = Err(CliError::cli_other_error(
        "stdio transport failed".to_string(),
    ));
    let shutdown = Err(CliError::cli_other_error(
        "overlay inventory remained active".to_string(),
    ));

    let error = merge_cli_active_defense_results(operation, shutdown)
        .expect_err("both failures must produce a nonzero CLI result");
    let rendered = error.to_string();
    assert!(rendered.contains("stdio transport failed"));
    assert!(rendered.contains("overlay inventory remained active"));
    assert!(rendered.contains("explicit active-defense shutdown also failed"));
}

#[test]
fn cli_mcp_teardown_failure_overrides_successful_stdio_completion() {
    let shutdown = Err(CliError::cli_other_error(
        "response worker refused shutdown".to_string(),
    ));

    let error = merge_cli_active_defense_results(Ok(()), shutdown)
        .expect_err("teardown refusal must fail the CLI command");
    assert!(error
        .to_string()
        .contains("response worker refused shutdown"));
}

#[test]
fn cli_mcp_startup_error_still_executes_explicit_shutdown() {
    let shutdown_called = std::cell::Cell::new(false);
    let startup = Err(CliError::cli_other_error(
        "bootstrap readiness failed".to_string(),
    ));

    let error = finish_cli_active_defense_with_shutdown(startup, || {
        shutdown_called.set(true);
        Ok(())
    })
    .expect_err("startup failure must remain visible after teardown");
    assert!(shutdown_called.get());
    assert!(error.to_string().contains("bootstrap readiness failed"));
}

fn aggregate_request(
    request_id: &str,
    capability: chio_core::capability::token::CapabilityToken,
) -> KernelToolCallRequest {
    KernelToolCallRequest {
        request_id: request_id.to_string(),
        agent_id: capability.subject.to_hex(),
        capability,
        tool_name: "custom_tool".to_string(),
        server_id: "aggregate-server".to_string(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

fn must_err<T: std::fmt::Debug>(result: Result<T, CliError>, context: &str) -> CliError {
    match result {
        Ok(value) => panic!("{context}: expected error, got {value:?}"),
        Err(error) => error,
    }
}

fn assert_registry_error(err: &CliError, expected_code: &str, expected_domain: &str) {
    match err {
        CliError::Chio(chio) => {
            assert_eq!(chio.code().as_str(), expected_code);
            assert_eq!(chio.domain().as_str(), expected_domain);
        }
        other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
    }
}

#[test]
fn missing_local_receipt_db_uses_cli_domain() {
    let error = must_err(
        require_receipt_db_path(None),
        "missing receipt db should fail closed",
    );

    assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
}

#[test]
fn partial_credit_loss_lifecycle_amount_uses_cli_domain() {
    let error = must_err(
        crate::runtime_trust_reports::build_credit_loss_lifecycle_query(
            "bond-1",
            "delinquency",
            Some(100),
            None,
        ),
        "partial amount flags should fail closed",
    );

    assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
}

#[test]
fn tenant_read_token_mapping_rejects_surrounding_whitespace() {
    for spec in [" tenant-a=read-token", "tenant-a=read-token "] {
        let error = must_err(
            parse_tenant_read_tokens(&[spec.to_string()]),
            "tenant token mapping with surrounding whitespace should fail closed",
        );

        let message = error.to_string();
        assert!(
            message.contains("surrounding whitespace"),
            "unexpected tenant token validation error for {spec}: {message}"
        );
    }
}

#[test]
fn tenant_read_token_mapping_rejects_control_characters() {
    for spec in ["tenant-\na=read-token", "tenant-a=read\u{7f}token"] {
        let error = must_err(
            parse_tenant_read_tokens(&[spec.to_string()]),
            "tenant token mapping with control characters should fail closed",
        );

        let message = error.to_string();
        assert!(
            message.contains("control characters"),
            "unexpected tenant token validation error for {spec:?}: {message}"
        );
    }
}

#[test]
fn cluster_member_mapping_parses_ed25519_pin() {
    let key = Keypair::from_seed(&[0x42; 32]).public_key();
    let members = parse_cluster_members(&[format!(
        "https://node-a.example={}",
        key.to_hex()
    )])
    .expect("parse cluster member pin");

    assert_eq!(members.len(), 1);
    assert_eq!(members[0].node_url, "https://node-a.example");
    assert_eq!(members[0].public_key, key);
}

#[test]
fn cluster_member_mapping_rejects_missing_or_invalid_pin() {
    for spec in ["https://node-a.example", "https://node-a.example=deadbeef"] {
        let error = must_err(
            parse_cluster_members(&[spec.to_string()]),
            "invalid cluster member pin should fail closed",
        );
        assert!(error.to_string().contains("--cluster-member"));
    }
}

#[test]
fn remote_mcp_auth_contract_is_derived_from_external_auth_urls() {
    let contract = remote_mcp_auth_egress_contract(
        "edge-a",
        Some("https://id.example.com/.well-known/openid-configuration"),
        Some("https://auth.example.com/oauth2/introspect"),
        None,
        Some("https://issuer.example.com/oauth2/default"),
        Some("https://keys.example.com/jwks.json"),
    )
    .expect("contract builds")
    .expect("external auth creates contract");

    assert_eq!(contract.tenant_egress_namespace, "remote-mcp-auth:edge-a");
    assert!(contract.allowed_schemes.contains("https"));
    assert!(contract.allowed_authority_set.contains("id.example.com"));
    assert!(contract.allowed_authority_set.contains("auth.example.com"));
    assert!(contract
        .allowed_authority_set
        .contains("issuer.example.com"));
    assert!(contract.allowed_authority_set.contains("keys.example.com"));
    assert!(contract.deny_loopback);
}

#[test]
fn remote_mcp_auth_contract_permits_explicit_loopback_auth_url() {
    let contract = remote_mcp_auth_egress_contract(
        "edge-local",
        None,
        Some("http://127.0.0.1:18080/introspect"),
        None,
        None,
        None,
    )
    .expect("contract builds")
    .expect("loopback auth creates contract");

    assert!(contract.allowed_schemes.contains("http"));
    assert!(contract.allowed_authority_set.contains("127.0.0.1:18080"));
    assert!(!contract.deny_loopback);
}

#[test]
fn cli_product_constructor_preserves_aggregate_exhaustion_across_restart_without_broker() {
    use chio_core::capability::aggregate_budget::{
        AggregateInvocationBudget, AggregateInvocationScope,
    };
    use chio_core::capability::scope::{Operation, ToolGrant};
    use chio_core::capability::token::CapabilityToken;

    let temp = tempfile::tempdir().expect("temporary aggregate product directory");
    let policy_path = temp.path().join("policy.yaml");
    let operation_path = temp.path().join("admission-operations.sqlite3");
    let budget_path = temp.path().join("budgets.sqlite3");
    std::fs::write(
        &policy_path,
        "kernel:\n  allow_ephemeral_receipt_log: true\n",
    )
    .expect("write aggregate policy");
    let kernel_authority = Keypair::from_seed(&[73_u8; 32]);
    let subject = Keypair::from_seed(&[74_u8; 32]);

    let loaded = policy::load_policy_for_runtime(&policy_path, None, None)
        .expect("load aggregate runtime policy");
    let kernel = build_kernel(loaded, &kernel_authority).expect("build aggregate kernel");
    let mut kernel = compose_cli_ordinary_runtime_kernel(
        kernel,
        true,
        Some(&operation_path),
        None,
        Some(&budget_path),
        None,
        None,
    )
    .expect("compose aggregate product kernel");
    kernel.register_tool_server(Box::new(CheckToolServer {
        id: "aggregate-server".to_string(),
        output: None,
    }));

    let ordinary = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "aggregate-server".to_string(),
                    tool_name: "custom_tool".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            3_600,
        )
        .expect("issue aggregate test capability");
    let mut body = ordinary.body();
    body.aggregate_invocation_budget = Some(AggregateInvocationBudget {
        scope: AggregateInvocationScope::Capability,
        max_invocations: 1,
        root_binding: None,
    });
    let capability =
        CapabilityToken::sign(body, &kernel_authority).expect("sign aggregate test capability");
    let allowed = kernel
        .evaluate_tool_call_blocking(&aggregate_request(
            "aggregate-before-restart",
            capability.clone(),
        ))
        .expect("first aggregate evaluation");
    assert_eq!(
        allowed.verdict,
        chio_kernel::Verdict::Allow,
        "unexpected aggregate denial: {:?}",
        allowed.reason
    );
    drop(kernel);

    let loaded = policy::load_policy_for_runtime(&policy_path, None, None)
        .expect("reload aggregate runtime policy");
    let kernel = build_kernel(loaded, &kernel_authority).expect("rebuild aggregate kernel");
    let mut restarted = compose_cli_ordinary_runtime_kernel(
        kernel,
        true,
        Some(&operation_path),
        None,
        Some(&budget_path),
        None,
        None,
    )
    .expect("recompose aggregate product kernel");
    restarted.register_tool_server(Box::new(CheckToolServer {
        id: "aggregate-server".to_string(),
        output: None,
    }));

    let denied = restarted
        .evaluate_tool_call_blocking(&aggregate_request("aggregate-after-restart", capability))
        .expect("post-restart aggregate evaluation");
    assert_eq!(denied.verdict, chio_kernel::Verdict::Deny);
    assert!(denied
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("budget")));
}
