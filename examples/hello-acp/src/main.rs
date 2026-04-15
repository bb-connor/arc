use std::error::Error;
use std::io::{self, BufRead, Write};

use arc_acp_edge::{AcpEdgeConfig, AcpKernelExecutionContext, ArcAcpEdge};
use arc_core::capability::{ArcScope, Operation, ToolGrant};
use arc_core::crypto::Keypair;
use arc_kernel::{
    ArcKernel, KernelError, KernelConfig, NestedFlowBridge, ToolCallChunk, ToolCallStream,
    ToolServerConnection, ToolServerStreamResult, DEFAULT_CHECKPOINT_BATCH_SIZE,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use arc_manifest::{ToolDefinition, ToolManifest};
use serde_json::{json, Value};

struct HelloToolServer;

impl ToolServerConnection for HelloToolServer {
    fn server_id(&self) -> &str {
        "hello-acp-srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["hello_tool".to_string()]
    }

    fn invoke(
        &self,
        _tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        Ok(json!({
            "message": "hello from acp",
            "arguments": arguments,
        }))
    }

    fn invoke_stream(
        &self,
        _tool_name: &str,
        arguments: Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        let name = arguments
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("world");
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: vec![
                ToolCallChunk {
                    data: json!({"content": [{"type": "text", "text": format!("hello from acp, {name}")}]}),
                },
                ToolCallChunk {
                    data: json!({"content": [{"type": "text", "text": "resume complete"}]}),
                },
            ],
        })))
    }
}

fn kernel_config() -> KernelConfig {
    let keypair = Keypair::generate();
    KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 8,
        policy_hash: "hello-acp-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    }
}

fn demo_manifest() -> ToolManifest {
    ToolManifest {
        schema: "arc.manifest.v1".to_string(),
        server_id: "hello-acp-srv".to_string(),
        name: "Hello ACP Server".to_string(),
        description: Some("A tiny receipt-bearing ACP hello surface".to_string()),
        version: "0.1.0".to_string(),
        tools: vec![ToolDefinition {
            name: "hello_tool".to_string(),
            description: "Return a greeting payload".to_string(),
            input_schema: json!({
                "type": "object",
                "x-arc-streaming": true,
                "x-arc-partial-output": true,
                "x-arc-cancellation": true
            }),
            output_schema: None,
            pricing: None,
            has_side_effects: false,
            latency_hint: None,
        }],
        required_permissions: None,
        public_key: "hello-acp-manifest".to_string(),
    }
}

fn build_demo_state() -> (ArcAcpEdge, ArcKernel, AcpKernelExecutionContext) {
    let mut kernel = ArcKernel::new(kernel_config());
    kernel.register_tool_server(Box::new(HelloToolServer));

    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            ArcScope {
                grants: vec![ToolGrant {
                    server_id: "hello-acp-srv".to_string(),
                    tool_name: "hello_tool".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ArcScope::default()
            },
            300,
        )
        .expect("issue capability");

    let execution = AcpKernelExecutionContext {
        capability,
        agent_id: agent.public_key().to_hex(),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
    };

    (
        ArcAcpEdge::new(AcpEdgeConfig::default(), vec![demo_manifest()]).expect("create edge"),
        kernel,
        execution,
    )
}

fn serve() -> Result<(), Box<dyn Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let (edge, kernel, execution) = build_demo_state();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let message: Value = serde_json::from_str(&line)?;
        let response = edge.handle_jsonrpc(message, &kernel, &execution);
        serde_json::to_writer(&mut stdout, &response)?;
        writeln!(&mut stdout)?;
        stdout.flush()?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "serve".to_string());
    match mode.as_str() {
        "serve" => serve(),
        other => Err(format!("unknown mode: {other}").into()),
    }
}

