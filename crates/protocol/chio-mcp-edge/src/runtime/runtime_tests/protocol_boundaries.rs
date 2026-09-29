use super::*;

struct ProtocolClock(
    std::sync::Mutex<
        Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>,
    >,
);
impl ProtocolClock {
    fn new() -> Self {
        Self(std::sync::Mutex::new(Ok(Self::at(0))))
    }
    fn at(elapsed: u64) -> chio_security_types::clock::ClockReading {
        use chio_security_types::clock::*;
        ClockReading::new(
            UnixMillis::new(1_700_000_000_000 + elapsed),
            MonotonicInstant::from_nanos(elapsed * 1_000_000),
        )
    }
    fn advance(&self, elapsed: u64) {
        *self.0.lock().unwrap() = Ok(Self::at(elapsed));
    }
    fn fail(&self) {
        *self.0.lock().unwrap() = Err(chio_security_types::clock::ClockError::Unavailable);
    }
}
impl chio_security_types::clock::Clock for ProtocolClock {
    fn read(
        &self,
    ) -> Result<chio_security_types::clock::ClockReading, chio_security_types::clock::ClockError>
    {
        *self.0.lock().unwrap()
    }
}

fn edge_with_clock(clock: Arc<ProtocolClock>) -> ChioMcpEdge {
    let (kernel, _) = make_kernel_with_clock(clock);
    let agent = Keypair::generate();
    let capabilities = issue_capabilities(&kernel, &agent);
    let mut edge = ChioMcpEdge::new(
        McpEdgeConfig::default(),
        kernel,
        agent.public_key().to_hex(),
        capabilities,
        vec![sample_manifest()],
    )
    .unwrap();
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}));
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}));
    edge
}

fn queue_task(edge: &mut ChioMcpEdge) -> String {
    let (session, context, operation) = edge
        .prepare_tool_call_request(
            &json!(2),
            &json!({"name":"read_file", "arguments":{"path":"/tmp/data"}}),
        )
        .unwrap();
    let result = edge.create_tool_call_task(
        json!(2),
        session,
        context,
        operation,
        RequestedTask { ttl: Some(10) },
        true,
    );
    result["result"]["task"]["taskId"]
        .as_str()
        .expect("task created")
        .into()
}

#[test]
fn protocol_boundary_background_expiry_prevents_both_dispatch_paths() {
    for channel in [false, true] {
        let clock = Arc::new(ProtocolClock::new());
        let mut edge = edge_with_clock(clock.clone());
        let task = queue_task(&mut edge);
        clock.advance(10);
        let processed = if channel {
            let (_tx, mut rx) = mpsc::channel();
            let (_cancel_tx, mut cancel_rx) = mpsc::channel();
            edge.process_background_tasks_with_channel(&mut rx, &mut cancel_rx, &mut Vec::new())
                .unwrap()
        } else {
            edge.process_background_tasks().unwrap()
        };
        assert!(!processed, "expired work reached the evaluator");
        assert!(!edge.tasks.contains_key(&task));
        assert!(edge.pending_background_tasks.is_empty());
    }
}

#[test]
fn protocol_boundary_clock_fault_keeps_pending_work_unexecuted() {
    let clock = Arc::new(ProtocolClock::new());
    let mut edge = edge_with_clock(clock.clone());
    let task = queue_task(&mut edge);
    clock.fail();
    assert!(matches!(
        edge.process_background_tasks(),
        Err(AdapterError::Clock(
            chio_security_types::clock::ClockError::Unavailable
        ))
    ));
    assert_eq!(edge.pending_background_tasks, vec![task.clone()]);
    assert!(!edge.tasks[&task].is_terminal());
    let response = edge.handle_tasks_get(json!(3), json!({"taskId":task}));
    assert_eq!(
        response["error"]["data"]["chioError"],
        "urn:chio:error:kernel:clock-unavailable"
    );
}

#[test]
fn protocol_boundary_sequence_exhaustion_and_pagination_cannot_wrap() {
    let clock = Arc::new(ProtocolClock::new());
    let mut edge = edge_with_clock(clock);
    edge.task_counter = u64::MAX;
    assert_eq!(
        edge.next_task_id().unwrap_err(),
        chio_security_types::clock::ClockError::Overflow
    );
    assert_eq!(edge.task_counter, u64::MAX);
    let response =
        paginate_named_response(json!(4), 1, usize::MAX, "items", vec![json!(1), json!(2)]);
    assert_eq!(response["result"]["items"], json!([2]));
}

#[test]
fn review_regression_edge_capacity_preserves_uncollected_results_until_expiry() {
    let clock = Arc::new(ProtocolClock::new());
    let mut edge = edge_with_clock(clock.clone());
    let first_id = queue_task(&mut edge);
    edge.tasks
        .get_mut(&first_id)
        .unwrap()
        .mark_completed(json!({"content": []}), ProtocolClock::at(0));
    for _ in 1..MAX_DEFERRED_MCP_TASKS {
        queue_task(&mut edge);
    }
    let error = edge.ensure_deferred_task_capacity(&json!(9)).unwrap_err();
    assert_eq!(
        error["error"]["message"],
        "urn:chio:error:transport:task-capacity-exceeded"
    );
    let response = edge.handle_tasks_result(json!(10), json!({"taskId":first_id}));
    assert_eq!(response["result"]["content"], json!([]));
    clock.advance(10);
    edge.ensure_deferred_task_capacity(&json!(11)).unwrap();
    assert!(edge.tasks.is_empty());
}

#[test]
fn review_regression_channel_preserves_original_decoder_cause() {
    use std::error::Error;
    let (tx, mut rx) = mpsc::channel();
    let (cancel_tx, _cancel_rx) = mpsc::channel();
    let bytes = b"{\"authority\":\"secret-first\",\"authority\":\"secret-second\"}\n";
    pump_client_messages(&bytes[..], tx, cancel_tx);
    let error = next_client_message(&mut rx).unwrap_err();
    assert!(matches!(
        error,
        AdapterError::UntrustedInput(chio_core::canonical::UntrustedJsonError::SignedInput(_))
    ));
    assert!(error.source().is_some());
    assert_eq!(
        error.to_string(),
        "urn:chio:error:attest:signed-json-invalid-input"
    );
    assert!(!format!("{error:?}").contains("secret"));
}

pub(super) fn make_kernel_with_clock(
    clock: Arc<dyn chio_security_types::clock::Clock>,
) -> (ChioKernel, Keypair) {
    let keypair = Keypair::generate();
    let config = KernelConfig {
        keypair: keypair.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "edge-policy".to_string(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    };
    let mut kernel = ChioKernel::new_with_clock(config, clock);
    kernel.register_tool_server(Box::new(EchoServer));
    kernel.register_resource_provider(Box::new(DocsResourceProvider));
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));
    (kernel, keypair)
}
