// Phase 2.2 constraint-variant tests.
//
// Included by `src/kernel/tests.rs`, so this file inherits the outer
// `use super::*;` environment along with the helpers defined at the
// top of `tests/all.rs` (make_config, make_capability, EchoServer, etc.).

/// A grant with `MemoryStoreAllowlist` should deny a request whose
/// arguments carry a `store` value outside the allowlist, and allow
/// one whose `store` value is in the allowlist.
#[test]
fn kernel_denies_memory_write_to_disallowed_store() {
    let mut kernel = ArcKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("mem", vec!["memory_write"])));

    let agent_kp = make_keypair();
    let scope = ArcScope {
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
        ..ArcScope::default()
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
/// not carry a recipient-style key, demonstrating the additive and
/// non-regressing nature of the new variant.
#[test]
fn kernel_allows_action_when_unaffected_by_new_constraint() {
    let mut kernel = ArcKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["ping"])));

    let agent_kp = make_keypair();
    let scope = ArcScope {
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
        ..ArcScope::default()
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

/// Document that `TableAllowlist` is accepted at the request-matching
/// stage and enforcement is deferred to `arc-data-guards`. A request
/// that ships SQL text is admitted regardless of the SQL's tables
/// because the kernel delegates parsing.
#[test]
fn kernel_records_constraint_and_defers_to_data_guard() {
    let mut kernel = ArcKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("db", vec!["sql_query"])));

    let agent_kp = make_keypair();
    let scope = ArcScope {
        grants: vec![ToolGrant {
            server_id: "db".to_string(),
            tool_name: "sql_query".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::TableAllowlist(vec![
                "users".to_string(),
                "orders".to_string(),
            ])],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ArcScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // SQL text references a forbidden table. The kernel does not yet
    // parse SQL at this layer, so the request is admitted and a
    // downstream data guard enforces the TableAllowlist. This test
    // documents the v1 deferral behavior.
    let request = make_request_with_arguments(
        "req-sql",
        &cap,
        "sql_query",
        "db",
        serde_json::json!({"query": "SELECT * FROM payroll WHERE id = 1"}),
    );

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
    let mut kernel = ArcKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("mem", vec!["memory_write"])));

    let agent_kp = make_keypair();
    let scope = ArcScope {
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
        ..ArcScope::default()
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
