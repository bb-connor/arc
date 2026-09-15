//! The production A2A client discovers and calls the production kernel-backed edge.
//! Loopback HTTP with a test credential resolver; no independent-company claim.
use chio_a2a_adapter::{A2aAdapter, A2aAdapterConfig};
use chio_a2a_edge::{A2aEdgeConfig, A2aKernelExecutionContext, ChioA2aEdge};
use chio_core::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityTokenBody,
};
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::decision::Decision;
use chio_egress_contract::HttpEgressContract;
use chio_kernel::{
    ChioKernel, KernelConfig, KernelError, NestedFlowBridge, ToolServerConnection,
    DEFAULT_CHECKPOINT_BATCH_SIZE, DEFAULT_MAX_STREAM_DURATION_SECS,
    DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_manifest::{ToolDefinition, ToolManifest};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Response, Server};

fn manifest_public_key(seed: u8) -> String {
    Keypair::from_seed(&[seed; 32]).public_key().to_hex()
}

struct ReviewTool(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for ReviewTool {
    fn server_id(&self) -> &str {
        "test-srv"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["echo".into(), "write".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"reviewed": arguments}))
    }
}

struct Host {
    url: String,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    kernel_key: chio_core::crypto::PublicKey,
    client_state: tempfile::TempDir,
}
impl Drop for Host {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.take() {
            assert!(handle.join().is_ok());
        }
    }
}
impl Host {
    fn start() -> Self {
        let server = Server::http("127.0.0.1:0").unwrap_or_else(|error| panic!("{error:?}"));
        let address = server
            .server_addr()
            .to_ip()
            .unwrap_or_else(|| panic!("missing fixture value"));
        let url = format!("http://{address}");
        let mut edge = ChioA2aEdge::new(
            A2aEdgeConfig {
                endpoint_url: format!("{url}/rpc"),
                ..Default::default()
            },
            vec![test_manifest()],
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
        let config = test_kernel_config();
        let issuer = config.keypair.clone();
        let kernel_key = issuer.public_key();
        let mut kernel = ChioKernel::new(config);
        let calls = Arc::new(AtomicUsize::new(0));
        kernel.register_tool_server(Box::new(ReviewTool(calls.clone())));
        let contexts: Vec<_> = ["buyer", "other-buyer", "denied"]
            .into_iter()
            .map(|label| {
                let subject = Keypair::generate();
                let capability = capability_for_tool(
                    &issuer,
                    &subject,
                    "test-srv",
                    if label == "denied" { "write" } else { "echo" },
                );
                (
                    format!("Bearer {label}"),
                    A2aKernelExecutionContext {
                        capability,
                        agent_id: subject.public_key().to_hex(),
                        dpop_proof: None,
                        execution_nonce: None,
                        governed_intent: None,
                        approval_token: None,
                        approval_tokens: vec![],
                        threshold_approval_proposal: None,
                        supplemental_authorization: None,
                        model_metadata: None,
                    },
                )
            })
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                let Some(mut request) = server
                    .recv_timeout(Duration::from_millis(100))
                    .unwrap_or_else(|error| panic!("{error:?}"))
                else {
                    continue;
                };
                let content = if request.url() == "/.well-known/agent-card.json" {
                    edge.agent_card_json()
                        .unwrap_or_else(|error| panic!("{error:?}"))
                } else {
                    let context = contexts.iter().find(|(auth, _)| {
                        request
                            .headers()
                            .iter()
                            .any(|h| h.field.equiv("Authorization") && h.value.as_str() == auth)
                    });
                    let Some((_, execution)) = context else {
                        request
                            .respond(Response::empty(401))
                            .unwrap_or_else(|error| panic!("{error:?}"));
                        continue;
                    };
                    let value: Value = serde_json::from_reader(request.as_reader())
                        .unwrap_or_else(|error| panic!("{error:?}"));
                    let response = edge
                        .handle_jsonrpc(value, &kernel, execution)
                        .into_value()
                        .unwrap_or_else(|| panic!("missing fixture value"));
                    serde_json::to_string(&response).unwrap_or_else(|error| panic!("{error:?}"))
                };
                request
                    .respond(
                        Response::from_string(content).with_header(
                            Header::from_bytes("Content-Type", "application/json")
                                .unwrap_or_else(|error| panic!("{error:?}")),
                        ),
                    )
                    .unwrap_or_else(|error| panic!("{error:?}"));
            }
        });
        Self {
            url,
            calls,
            stop,
            thread: Some(handle),
            kernel_key,
            client_state: tempfile::tempdir().unwrap_or_else(|error| panic!("{error:?}")),
        }
    }
    fn client(&self, credential: &str) -> A2aAdapter {
        A2aAdapter::discover(
            A2aAdapterConfig::new(&self.url, manifest_public_key(23))
                .with_task_registry_file(
                    self.client_state.path().join(format!("{credential}.json")),
                )
                .with_bearer_token(credential)
                .with_timeout(Duration::from_secs(5))
                .with_egress_contract(HttpEgressContract::permissive_for_tests(
                    self.url
                        .strip_prefix("http://")
                        .unwrap_or_else(|| panic!("missing fixture value")),
                )),
        )
        .unwrap_or_else(|error| panic!("{error:?}"))
    }
}

#[tokio::test]
async fn a2a_client_calls_kernel_edge_and_reads_bound_task() {
    let host = Host::start();
    let client = host.client("buyer");
    let output = client
        .invoke("echo", json!({"data": {"target": "payments-api"}}), None)
        .await
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(output["task"]["status"]["state"], "TASK_STATE_COMPLETED");
    assert_eq!(
        output["task"]["artifacts"][0]["parts"][0]["data"]["reviewed"]["target"],
        "payments-api"
    );
    let receipt: ChioReceipt =
        serde_json::from_value(output["task"]["metadata"]["chio"]["receipt"].clone())
            .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(receipt.kernel_key, host.kernel_key);
    assert!(receipt
        .verify_signature()
        .unwrap_or_else(|error| panic!("{error:?}")));
    assert_eq!(receipt.decision, Some(Decision::Allow));
    assert_eq!(receipt.action.parameters, json!({"target": "payments-api"}));
    assert!(receipt
        .action
        .verify_hash()
        .unwrap_or_else(|error| panic!("{error:?}")));
    let task_id = output["task"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("missing fixture value"));
    // A new client instance resolves the task through its durable local registry.
    let reconnected = host.client("buyer");
    let polled = reconnected
        .invoke("echo", json!({"get_task": {"id": task_id}}), None)
        .await
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(polled["task"], output["task"]);
    assert_eq!(host.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a2a_client_receives_signed_kernel_denial_without_tool_dispatch() {
    let host = Host::start();
    let client = host.client("denied");
    let output = client
        .invoke("echo", json!({"message": "review payments"}), None)
        .await
        .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(output["task"]["status"]["state"], "TASK_STATE_FAILED");
    let receipt: ChioReceipt =
        serde_json::from_value(output["task"]["metadata"]["chio"]["receipt"].clone())
            .unwrap_or_else(|error| panic!("{error:?}"));
    assert_eq!(receipt.kernel_key, host.kernel_key);
    assert!(receipt
        .verify_signature()
        .unwrap_or_else(|error| panic!("{error:?}")));
    assert!(matches!(receipt.decision, Some(Decision::Deny { .. })));
    assert_eq!(host.calls.load(Ordering::SeqCst), 0);
}

fn test_kernel_config() -> KernelConfig {
    let keypair = Keypair::generate();
    KernelConfig {
        ca_public_keys: vec![keypair.public_key()],
        keypair,
        max_delegation_depth: 8,
        policy_hash: "policy-a2a-test".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    }
}

fn capability_for_tool(
    issuer: &Keypair,
    subject: &Keypair,
    server_id: &str,
    tool_name: &str,
) -> chio_core::capability::token::CapabilityToken {
    let now = unix_now();
    chio_core::capability::token::CapabilityToken::sign(
        CapabilityTokenBody {
            id: format!("cap-{server_id}-{tool_name}"),
            issuer: issuer.public_key(),
            subject: subject.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: server_id.to_string(),
                    tool_name: tool_name.to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                resource_grants: vec![],
                prompt_grants: vec![],
            },
            issued_at: now.saturating_sub(30),
            expires_at: now + 300,
            delegation_chain: vec![],
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .unwrap_or_else(|error| panic!("capability should sign: {error:?}"))
}

fn test_manifest() -> ToolManifest {
    ToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: "test-srv".to_string(),
        name: "Test Server".to_string(),
        description: Some("Test".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![
            ToolDefinition {
                name: "echo".to_string(),
                description: "Echo input".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            },
            ToolDefinition {
                name: "write".to_string(),
                description: "Write data".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: true,
                latency_hint: None,
            },
        ],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: manifest_public_key(1),
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("system time should be after unix epoch: {error:?}"))
        .as_secs()
}
