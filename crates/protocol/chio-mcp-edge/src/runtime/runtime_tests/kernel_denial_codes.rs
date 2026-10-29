use super::*;

const PRIVATE_DETAIL: &str = "/srv/chio/tenant-7/private-key.json Bearer secret-token";

fn denial_result(code: &str, text: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"code": code},
        "isError": true,
    })
}

fn kernel_error_families() -> Vec<(KernelError, &'static str, &'static str)> {
    let capability_invalid = (
        "capability_invalid",
        "Capability is not valid for this request",
    );
    let capability_revoked = ("capability_revoked", "Capability has been revoked");
    let scope_denied = ("scope_denied", "Request is outside the capability scope");
    let tool_unavailable = ("tool_unavailable", "Tool is not available");
    let guard_denied = ("guard_denied", "Request denied by policy guard");
    let governed = ("governed_transaction_denied", "Governed transaction denied");
    let budget_exhausted = ("budget_exhausted", "Budget does not cover this request");
    let payment_unavailable = ("payment_unavailable", "Payment could not be authorized");
    let replay_denied = (
        "replay_denied",
        "Request was already executed or its nonce is invalid",
    );
    let runtime_admission_denied = ("runtime_admission_denied", "Runtime admission denied");
    let overloaded = ("overloaded", "Kernel is over capacity");
    let kernel_unavailable = ("kernel_unavailable", "Kernel could not complete admission");
    let session_unsupported = (
        "session_unsupported",
        "Request is not supported in this session",
    );
    let detail = || PRIVATE_DETAIL.to_string();
    [
        (KernelError::CapabilityExpired, capability_invalid),
        (KernelError::DelegationInvalid(detail()), capability_invalid),
        (KernelError::InvalidConstraint(detail()), capability_invalid),
        (
            KernelError::SubjectMismatch {
                expected: detail(),
                actual: detail(),
            },
            capability_invalid,
        ),
        (KernelError::CapabilityRevoked(detail()), capability_revoked),
        (
            KernelError::DelegationChainRevoked(detail()),
            capability_revoked,
        ),
        (
            KernelError::OutOfScope {
                tool: detail(),
                server: detail(),
            },
            scope_denied,
        ),
        (
            KernelError::OutOfScopeResource { uri: detail() },
            scope_denied,
        ),
        (KernelError::ToolNotRegistered(detail()), tool_unavailable),
        (KernelError::ToolServerError(detail()), tool_unavailable),
        (KernelError::GuardDenied(detail()), guard_denied),
        (KernelError::GovernedTransactionDenied(detail()), governed),
        (KernelError::ApprovalRejected(detail()), governed),
        (KernelError::BudgetExhausted(detail()), budget_exhausted),
        (
            KernelError::FinancialBudgetExceeded {
                total: 7,
                committed: 9,
            },
            budget_exhausted,
        ),
        (
            KernelError::CrossCurrencyOracle(detail()),
            payment_unavailable,
        ),
        (
            KernelError::Web3EvidenceUnavailable(detail()),
            payment_unavailable,
        ),
        (KernelError::CapturedBudgetReplay(detail()), replay_denied),
        (
            KernelError::RuntimeAdmissionReadinessTimeout { timeout_ms: 5 },
            runtime_admission_denied,
        ),
        (KernelError::ExecutionNonceCapacity, overloaded),
        (KernelError::Internal(detail()), kernel_unavailable),
        (KernelError::DurableAdmission(detail()), kernel_unavailable),
        (
            KernelError::ReceiptSigningFailed(detail()),
            kernel_unavailable,
        ),
        (
            KernelError::ReceiptWriterUnavailable(detail()),
            kernel_unavailable,
        ),
        (KernelError::SamplingNotNegotiated, session_unsupported),
        (
            KernelError::RequestIncomplete(detail()),
            session_unsupported,
        ),
    ]
    .into_iter()
    .map(|(error, (code, text))| (error, code, text))
    .collect()
}

#[test]
fn kernel_errors_project_only_their_family_code_and_text() {
    let _metrics_guard = metrics_test_guard();
    let mut edge = make_edge(10);
    for (error, code, text) in kernel_error_families() {
        let variant = format!("{error:?}");
        let outcome =
            edge.tool_call_error_outcome(&SessionId::new("kernel-denial-codes"), error, None);
        let ToolCallEdgeOutcome::Result(result) = outcome else {
            panic!("{variant} did not produce a tool result");
        };
        assert_eq!(result, denial_result(code, text), "{variant}");
    }
}

struct DetailGuard {
    fail: bool,
}

impl chio_kernel::Guard for DetailGuard {
    fn name(&self) -> &str {
        "detail-guard"
    }

    fn evidence_declaration(&self) -> chio_kernel::GuardEvidenceDeclaration {
        chio_kernel::GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(
        &self,
        _ctx: &chio_kernel::GuardContext,
    ) -> Result<chio_kernel::GuardDecision, KernelError> {
        if self.fail {
            Err(KernelError::Internal(PRIVATE_DETAIL.to_string()))
        } else {
            Err(KernelError::GuardDenied(PRIVATE_DETAIL.to_string()))
        }
    }
}

fn denied_tool_call(edge: &mut ChioMcpEdge) -> Value {
    initialize_edge(edge);
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/tmp/demo.txt" }
            }
        }))
        .unwrap();
    response["result"].clone()
}

fn assert_signed_denial(result: &Value, code: &str, text: &str, detail: &str) {
    assert_eq!(result["isError"], true, "result: {result}");
    assert_eq!(result["content"], json!([{"type": "text", "text": text}]));
    assert_eq!(result["structuredContent"], json!({"code": code}));
    let decision = &result["_meta"]["chio"]["receipt"]["decision"];
    assert_eq!(decision["verdict"], "deny", "result: {result}");
    let reason = decision["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains(detail),
        "receipt lost the denial detail: {decision}"
    );
    let client_text = result["content"].to_string();
    assert!(
        !client_text.contains(detail),
        "denial detail reached the client text: {client_text}"
    );
}

fn edge_over(
    kernel: ChioKernel,
    caller: &Keypair,
    capabilities: Vec<CapabilityToken>,
) -> ChioMcpEdge {
    ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        caller.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

#[test]
fn subject_mismatch_denial_projects_capability_invalid() {
    let _metrics_guard = metrics_test_guard();
    let (kernel, _) = make_kernel();
    let caller = Keypair::generate();
    let subject = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &subject);
    let mut edge = edge_over(kernel, &caller, capabilities);
    let result = denied_tool_call(&mut edge);
    assert_signed_denial(
        &result,
        "capability_invalid",
        "Capability is not valid for this request",
        &subject.public_key().to_hex(),
    );
}

#[test]
fn revoked_capability_denial_projects_capability_revoked() {
    let _metrics_guard = metrics_test_guard();
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    let revoked = capabilities[0].id.clone();
    kernel.revoke_capability(&revoked).unwrap();
    let mut edge = edge_over(kernel, &agent, capabilities);
    let result = denied_tool_call(&mut edge);
    assert_signed_denial(
        &result,
        "capability_revoked",
        "Capability has been revoked",
        &revoked,
    );
}

#[test]
fn emergency_stop_denial_projects_emergency_stop() {
    let _metrics_guard = metrics_test_guard();
    let (kernel, _) = make_kernel();
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    kernel.emergency_stop(PRIVATE_DETAIL).unwrap();
    let mut edge = edge_over(kernel, &agent, capabilities);
    let result = denied_tool_call(&mut edge);
    assert_eq!(result["isError"], true, "result: {result}");
    assert_eq!(
        result["content"],
        json!([{"type": "text", "text": "Kernel emergency stop is active"}])
    );
    assert_eq!(
        result["structuredContent"],
        json!({"code": "emergency_stop"})
    );
}

#[test]
fn guard_denial_projects_guard_denied_and_keeps_receipt_detail() {
    for fail in [false, true] {
        let _metrics_guard = metrics_test_guard();
        let (mut kernel, _) = make_kernel();
        kernel.add_guard(Box::new(DetailGuard { fail }));
        let agent = Keypair::generate();
        let capabilities = issue_capabilities(&kernel, &agent);
        let mut edge = edge_over(kernel, &agent, capabilities);
        let result = denied_tool_call(&mut edge);
        assert_signed_denial(
            &result,
            "guard_denied",
            "Request denied by policy guard",
            PRIVATE_DETAIL,
        );
    }
}
