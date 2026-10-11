// Shared wire-preservation cases. These schema fixtures are deliberately not
// execution authority; live admission tests must mint their own valid artifacts.

pub struct CountedToolServer {
    pub server: String,
    pub tool: String,
    pub calls: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for CountedToolServer {
    fn server_id(&self) -> &str {
        &self.server
    }
    fn tool_names(&self) -> Vec<String> {
        vec![self.tool.clone()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: serde_json::Value,
        _: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(arguments)
    }
}

pub fn primitive<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/protocol-primitives-v1.json"))
            .unwrap_or_else(|error| panic!("protocol primitive corpus: {error}"));
    let case = corpus["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["name"] == name))
        .unwrap_or_else(|| panic!("missing protocol primitive {name}"));
    let mut instance = case["instance"].clone();
    // The schema corpus uses arbitrary hex strings. Rust also validates curve
    // points during decoding, so use deterministic real keys in typed tests.
    for (field, seed) in [
        ("issuer", 80),
        ("subject", 81),
        ("approver", 82),
        ("policy_authority", 83),
        ("executor_subject", 84),
    ] {
        if instance.get(field).is_some() {
            instance[field] = serde_json::json!(chio_core::crypto::Keypair::from_seed(&[seed; 32])
                .public_key()
                .to_hex());
        }
    }
    serde_json::from_value(instance)
        .unwrap_or_else(|error| panic!("protocol primitive {name}: {error}"))
}

pub fn complete_wire_request() -> chio_kernel::ToolCallRequest {
    let mut capability: chio_core::capability::token::CapabilityToken =
        primitive("capability-with-direct-cumulative-approval");
    let aggregate: chio_core::capability::token::CapabilityToken =
        primitive("capability-with-aggregate-budget");
    capability.aggregate_invocation_budget = aggregate.aggregate_invocation_budget;
    let approval: chio_core::capability::governance::GovernedApprovalToken =
        primitive("governed-approval-token");
    let mut second_approval = approval.clone();
    second_approval.id = "approval-2".to_string();
    let plan = primitive::<serde_json::Value>("active-response-intent");
    let intent = serde_json::json!({
        "id": "request-1", "server_id": "server-1", "tool_name": "tool-1",
        "purpose": "consumer projection contract",
        "body": { "kind": "active_response_plan", "value":plan }
    });
    let key = chio_core::crypto::Keypair::from_seed(&[82; 32]);
    let proof = chio_kernel::dpop::DpopProof::sign(
        chio_kernel::dpop::DpopProofBody {
            schema: chio_kernel::dpop::DPOP_SCHEMA.to_string(),
            replay_authority: None,
            capability_id: capability.id.clone(),
            tool_server: "server-1".to_string(),
            tool_name: "tool-1".to_string(),
            action_hash: "a".repeat(64),
            nonce: "consumer-projection-dpop".to_string(),
            issued_at: 100,
            agent_key: key.public_key(),
        },
        &key,
    )
    .unwrap_or_else(|error| panic!("projection proof: {error}"));
    serde_json::from_value(serde_json::json!({
        "request_id": "request-1", "capability": capability,
        "agent_id": capability.subject.to_hex(), "server_id": "server-1",
        "tool_name": "tool-1", "arguments": {"value": 7},
        "dpop_proof": proof,
        "execution_nonce": primitive::<serde_json::Value>("operation-execution-nonce"),
        "governed_intent": intent,
        "approval_tokens": [approval, second_approval],
        "threshold_approval_proposal": primitive::<serde_json::Value>("threshold-proposal"),
        "supplemental_authorization": primitive::<serde_json::Value>("opaque-supplemental-authorization"),
        "model_metadata": {"model_id":"consumer-test", "provider":"local", "safety_tier":"standard"}
    })).unwrap_or_else(|error| panic!("complete authorization wire fixture: {error}"))
}

pub fn assert_authorization_preserved(
    expected: &chio_kernel::ToolCallRequest,
    actual: &chio_kernel::ToolCallRequest,
) {
    let value = |request: &chio_kernel::ToolCallRequest| {
        serde_json::to_value(request).unwrap_or_else(|error| panic!("serialize request: {error}"))
    };
    let expected = value(expected);
    let actual = value(actual);
    for field in [
        "capability",
        "dpop_proof",
        "execution_nonce",
        "governed_intent",
        "approval_token",
        "approval_tokens",
        "threshold_approval_proposal",
        "supplemental_authorization",
        "model_metadata",
    ] {
        assert_eq!(actual[field], expected[field], "projection changed {field}");
    }
    assert_eq!(actual["approval_tokens"].as_array().map(Vec::len), Some(2));
}

pub fn extension_cases(
    baseline: &chio_kernel::ToolCallRequest,
) -> Vec<(&'static str, chio_kernel::ToolCallRequest)> {
    use chio_core::capability::features::*;
    let wire = complete_wire_request();
    [
        AGGREGATE_INVOCATION_BUDGET,
        CUMULATIVE_APPROVAL_BUDGET,
        THRESHOLD_GOVERNED_APPROVALS,
        GOVERNED_ACTIVE_RESPONSE_PLAN,
        OPAQUE_SUPPLEMENTAL_AUTHORIZATION,
    ]
    .into_iter()
    .map(|feature| {
        let mut request = baseline.clone();
        request.request_id = format!("not-negotiated-{feature}");
        match feature {
            AGGREGATE_INVOCATION_BUDGET => {
                request.capability.aggregate_invocation_budget =
                    wire.capability.aggregate_invocation_budget.clone()
            }
            CUMULATIVE_APPROVAL_BUDGET => request.capability.scope.grants[0]
                .constraints
                .extend(wire.capability.scope.grants[0].constraints.clone()),
            THRESHOLD_GOVERNED_APPROVALS => {
                request.approval_tokens = wire.approval_tokens.clone();
                request.threshold_approval_proposal = wire.threshold_approval_proposal.clone();
            }
            GOVERNED_ACTIVE_RESPONSE_PLAN => request.governed_intent = wire.governed_intent.clone(),
            OPAQUE_SUPPLEMENTAL_AUTHORIZATION => {
                request.supplemental_authorization = wire.supplemental_authorization.clone()
            }
            _ => unreachable!(),
        }
        (feature, request)
    })
    .collect()
}
