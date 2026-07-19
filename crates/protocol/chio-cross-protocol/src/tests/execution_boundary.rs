fn semantic_tool(
    name: &str,
    latency_hint: Option<LatencyHint>,
    input_schema: Value,
    output_schema: Option<Value>,
) -> ToolDefinition {
    ToolDefinition {
        name: name.to_string(),
        description: format!("semantic tool {name}"),
        input_schema,
        output_schema,
        pricing: None,
        annotations: chio_manifest::ToolAnnotations {
            read_only: true,
            destructive: false,
            idempotent: false,
            requires_approval: false,
        },
        latency_hint,
        flow: None,
    }
}
fn explicit_local_bridge_security(server_id: &str, tool_name: &str) -> BridgeSecurityMetadata {
    explicit_local_manifest_registry(server_id, tool_name)
        .bridge_security(server_id, tool_name)
        .unwrap()
}

fn explicit_local_manifest_registry(server_id: &str, tool_name: &str) -> VerifiedManifestRegistry {
    admitted_manifest_registry(server_id, tool_name, None, RuntimeToolTopology::local())
}

fn explicit_egress_manifest_registry(server_id: &str, tool_name: &str) -> VerifiedManifestRegistry {
    admitted_manifest_registry(
        server_id,
        tool_name,
        Some(ToolFlowDeclaration::public_egress()),
        RuntimeToolTopology::remote(),
    )
}

fn nontrivial_registry_flow() -> ToolFlowDeclaration {
    serde_json::from_value(json!({
        "output_label": {
            "kind": "known",
            "owners": {},
            "compartments": ["audit", "pii"]
        },
        "input_clearance": {
            "kind": "known",
            "owners": {},
            "compartments": ["customer", "restricted"]
        },
        "egress": true,
        "declassification_purposes": ["audit", "support"]
    }))
    .unwrap()
}

fn explicit_nontrivial_bridge_security(server_id: &str, tool_name: &str) -> BridgeSecurityMetadata {
    explicit_nontrivial_manifest_registry(server_id, tool_name)
        .bridge_security(server_id, tool_name)
        .unwrap()
}

fn explicit_nontrivial_manifest_registry(
    server_id: &str,
    tool_name: &str,
) -> VerifiedManifestRegistry {
    admitted_manifest_registry(
        server_id,
        tool_name,
        Some(nontrivial_registry_flow()),
        RuntimeToolTopology::remote(),
    )
}

fn admitted_manifest_registry(
    server_id: &str,
    tool_name: &str,
    flow: Option<ToolFlowDeclaration>,
    topology: RuntimeToolTopology,
) -> VerifiedManifestRegistry {
    admitted_manifest_registry_with_schema(
        server_id,
        tool_name,
        flow,
        topology,
        json!({"type": "object"}),
    )
}

fn admitted_manifest_registry_with_schema(
    server_id: &str,
    tool_name: &str,
    flow: Option<ToolFlowDeclaration>,
    topology: RuntimeToolTopology,
    input_schema: Value,
) -> VerifiedManifestRegistry {
    let signer = Keypair::from_seed(&[41u8; 32]);
    let policy = match flow.as_ref() {
        Some(flow) => match (&flow.input_clearance, &flow.output_label) {
            (Some(input_clearance), Some(output_label)) => {
                chio_manifest::AuthoritativeToolPolicy::new(
                    vec![input_clearance.clone()],
                    output_label.clone(),
                    flow.declassification_purposes.clone(),
                )
                .unwrap()
            }
            _ => chio_manifest::AuthoritativeToolPolicy::public_only(),
        },
        _ => chio_manifest::AuthoritativeToolPolicy::public_only(),
    };
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: server_id.to_string(),
        name: format!("Cross-protocol {server_id}"),
        description: None,
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: tool_name.to_string(),
            description: format!("Cross-protocol test tool {tool_name}"),
            input_schema,
            output_schema: Some(json!({"type": "object"})),
            pricing: None,
            annotations: chio_manifest::ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: Some(LatencyHint::Fast),
            flow,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = sign_manifest(&manifest, &signer).unwrap();
    let policies = BTreeMap::from([(tool_name.to_string(), policy)]);
    let topologies = BTreeMap::from([(tool_name.to_string(), topology)]);
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(signed, &signer.public_key(), &policies, &topologies)
        .unwrap();
    registry
}

fn boundary_request(bridge_security: BridgeSecurityMetadata) -> CrossProtocolExecutionRequest {
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    CrossProtocolExecutionRequest {
        origin_request_id: "cross-protocol-security-origin".to_string(),
        kernel_request_id: "cross-protocol-security-kernel".to_string(),
        target_protocol: DiscoveryProtocol::Native,
        target_server_id: "test-srv".to_string(),
        target_tool_name: "echo".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: json!({"message": "security boundary"}),
        capability: capability_for_tool(&issuer, &subject, "test-srv", "echo"),
        source_envelope: json!({"message": {"role": "user"}}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        authenticated_session_id: None,
        security_context: None,
        bridge_security,
    }
}

#[test]
fn execution_boundary_accepts_exact_registry_admitted_bridge_security() {
    let registry = explicit_nontrivial_manifest_registry("test-srv", "echo");
    let request = boundary_request(registry.bridge_security("test-srv", "echo").unwrap());
    validate_execution_request_boundary(&request, &registry).unwrap();
}

#[test]
fn execution_boundary_rejects_unadmitted_bridge_security() {
    let registry = explicit_nontrivial_manifest_registry("test-srv", "echo");
    let request = boundary_request(BridgeSecurityMetadata::unconstrained());
    let error = validate_execution_request_boundary(&request, &registry).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid request envelope: bridge security does not match live registry entry for test-srv/echo"
    );
}

#[test]
fn execution_boundary_rejects_bridge_security_server_mismatch() {
    let registry = explicit_nontrivial_manifest_registry("test-srv", "echo");
    let request = boundary_request(explicit_nontrivial_bridge_security("other-srv", "echo"));
    let error = validate_execution_request_boundary(&request, &registry).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid request envelope: bridge security does not match live registry entry for test-srv/echo"
    );
}

#[test]
fn execution_boundary_rejects_bridge_security_tool_mismatch() {
    let registry = explicit_nontrivial_manifest_registry("test-srv", "echo");
    let request = boundary_request(explicit_nontrivial_bridge_security(
        "test-srv",
        "other-tool",
    ));
    let error = validate_execution_request_boundary(&request, &registry).unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid request envelope: bridge security does not match live registry entry for test-srv/echo"
    );
}

#[test]
fn execution_boundary_rejects_forged_digest_flow_and_topology_fields() {
    let registry = explicit_nontrivial_manifest_registry("test-srv", "echo");
    let exact = registry.bridge_security("test-srv", "echo").unwrap();
    let exact_value = serde_json::to_value(exact).unwrap();

    let mut forged_cases = Vec::new();
    let mut forged_digest = exact_value.clone();
    forged_digest["manifest_digest"] = Value::String("00".repeat(32));
    forged_cases.push(("manifest digest", forged_digest));

    let mut forged_topology = exact_value.clone();
    forged_topology["effective_egress"] = Value::Bool(false);
    forged_cases.push(("effective topology", forged_topology));

    let mut forged_flow = exact_value.clone();
    forged_flow["flow"]["egress"] = Value::Bool(false);
    forged_cases.push(("flow egress", forged_flow));

    let mut forged_purposes = exact_value;
    forged_purposes["flow"]["declassification_purposes"] = json!(["audit"]);
    forged_cases.push(("flow declassification purposes", forged_purposes));

    for (field, value) in forged_cases {
        let forged: BridgeSecurityMetadata = serde_json::from_value(value).unwrap();
        let request = boundary_request(forged);
        let error = validate_execution_request_boundary(&request, &registry).unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid request envelope: bridge security does not match live registry entry for test-srv/echo",
            "forged {field} must fail closed"
        );
    }
}

#[test]
fn execution_boundary_rejects_sidecar_from_different_live_registry_before_dispatch() {
    let registry_a = explicit_nontrivial_manifest_registry("test-srv", "echo");
    let registry_b = explicit_local_manifest_registry("test-srv", "echo");
    let dispatches = AtomicUsize::new(0);
    let executor = CountingMcpExecutor {
        dispatches: &dispatches,
    };
    let (_, kernel) = test_kernel();
    let orchestrator =
        CrossProtocolOrchestrator::new(&kernel, &registry_b).with_executor(&executor);
    let mut request = boundary_request(registry_a.bridge_security("test-srv", "echo").unwrap());
    request.target_protocol = DiscoveryProtocol::Mcp;

    let error = orchestrator.execute(&MockBridge, request).unwrap_err();

    assert_eq!(
        error.to_string(),
        "invalid request envelope: bridge security does not match live registry entry for test-srv/echo"
    );
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
}

#[test]
fn cross_protocol_routing_preserves_registry_admitted_flow_canonical_bytes() {
    let (_, mut kernel) = test_kernel();
    let _runtime_directory = install_test_flow_runtime(&mut kernel);
    let subject = Keypair::generate();
    let security_context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("tenant-cross-protocol-flow").unwrap(),
        SessionId::new("session-cross-protocol-flow").unwrap(),
        PrincipalId::new(subject.public_key().to_hex()).unwrap(),
        IsolationEpochId::new("epoch-cross-protocol-flow").unwrap(),
        LineageId::new("lineage-cross-protocol-flow").unwrap(),
        1,
    ));
    let capability = kernel
        .issue_capability_with_security_context(
            &subject.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "test-srv".to_string(),
                    tool_name: "echo".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: Vec::new(),
                prompt_grants: Vec::new(),
            },
            300,
            &security_context,
        )
        .unwrap();
    let expected_flow = nontrivial_registry_flow();
    let manifest_registry = explicit_nontrivial_manifest_registry("test-srv", "echo");
    let bridge_security = manifest_registry
        .bridge_security("test-srv", "echo")
        .unwrap();
    let source_flow = bridge_security
        .flow()
        .expect("registry-admitted cross-protocol sidecar must retain flow");
    let expected_flow_bytes = chio_core::canonical_json_bytes(&expected_flow).unwrap();
    assert_eq!(
        chio_core::canonical_json_bytes(source_flow).unwrap(),
        expected_flow_bytes
    );

    let result = CrossProtocolOrchestrator::new(&kernel, &manifest_registry)
        .execute(
            &MockBridge,
            CrossProtocolExecutionRequest {
                origin_request_id: "cross-protocol-flow-origin".to_string(),
                kernel_request_id: "cross-protocol-flow-kernel".to_string(),
                target_protocol: DiscoveryProtocol::Native,
                target_server_id: "test-srv".to_string(),
                target_tool_name: "echo".to_string(),
                agent_id: subject.public_key().to_hex(),
                arguments: json!({"message": "preserve flow"}),
                capability,
                source_envelope: json!({
                    "message": {"role": "user"},
                    "metadata": {"chio": {"targetSkillId": "echo"}}
                }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                approval_tokens: Vec::new(),
                threshold_approval_proposal: None,
                model_metadata: None,
                supplemental_authorization: None,
                authenticated_session_id: None,
                security_context: Some(security_context),
                bridge_security: bridge_security.clone(),
            },
        )
        .unwrap();
    let metadata = result.metadata();
    let routed_sidecar = metadata
        .pointer("/chio/receipt/metadata/chio_manifest_security_v1")
        .expect("routed receipt metadata must retain the complete admitted sidecar");
    assert_eq!(
        chio_core::canonical_json_bytes(routed_sidecar).unwrap(),
        chio_core::canonical_json_bytes(&serde_json::to_value(&bridge_security).unwrap()).unwrap()
    );
    let routed_flow = metadata
        .pointer("/chio/receipt/metadata/chio_manifest_security_v1/flow")
        .expect("routed receipt metadata must retain admitted flow");

    assert_eq!(
        chio_core::canonical_json_bytes(routed_flow).unwrap(),
        expected_flow_bytes
    );
    assert_eq!(
        routed_flow["declassification_purposes"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(routed_flow["egress"].as_bool(), Some(true));
}
