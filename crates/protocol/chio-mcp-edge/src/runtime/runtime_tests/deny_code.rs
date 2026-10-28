use super::*;

const PRIVATE_DETAIL: &str = "open /srv/chio/private-key.json failed for tenant secret-tenant";

struct FailingGuard;

impl chio_kernel::Guard for FailingGuard {
    fn name(&self) -> &str {
        "failing-guard"
    }

    fn evidence_declaration(&self) -> chio_kernel::GuardEvidenceDeclaration {
        chio_kernel::GuardEvidenceDeclaration::SAFE
    }

    fn evaluate(
        &self,
        _ctx: &chio_kernel::GuardContext,
    ) -> Result<chio_kernel::GuardDecision, KernelError> {
        Err(KernelError::Internal(PRIVATE_DETAIL.to_string()))
    }
}

fn make_failing_guard_edge() -> ChioMcpEdge {
    let (mut kernel, _) = make_kernel();
    kernel.add_guard(Box::new(FailingGuard));
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap()
}

#[test]
fn tools_call_denial_renders_the_signed_denial_code() {
    let mut edge = make_failing_guard_edge();
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }));
    let _ = edge.handle_jsonrpc(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    }));

    let denied = edge
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
    let rendered = denied.to_string();
    assert!(
        !rendered.contains("private-key.json"),
        "denial detail reached the client: {rendered}"
    );

    let result = &denied["result"];
    assert_eq!(result["isError"], true, "result: {result}");
    let decision = &result["_meta"]["chio"]["receipt"]["decision"];
    assert_eq!(decision["verdict"], "deny", "result: {result}");
    let code = decision["code"]
        .as_str()
        .unwrap_or_else(|| panic!("deny decision carries no code: {decision}"));
    let commitment = decision["detail_commitment"]
        .as_str()
        .unwrap_or_else(|| panic!("deny decision carries no detail_commitment: {decision}"));
    assert_eq!(commitment.len(), 64);
    assert!(commitment
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));

    assert_eq!(result["structuredContent"]["code"], code);
    assert_eq!(result["content"][0]["text"], decision["reason"]);
}
