// Hot-path deadline and writer-watchdog behavior: a hung guard or tool server
// fails closed within budget without pinning a worker, a dispatch deadline runs
// the full cancellation unwind, and a wedged writer denies before any tool side
// effect.

/// A guard whose `evaluate` blocks well past any budget, modeling a guard doing
/// synchronous blocking I/O.
struct SleepingGuard {
    label: String,
}

impl Guard for SleepingGuard {
    fn name(&self) -> &str {
        &self.label
    }
    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        // Well past any test budget, but bounded so the detached blocking thread
        // does not stall tokio runtime teardown after the deadline has fired.
        std::thread::sleep(Duration::from_secs(2));
        Ok(GuardDecision {
            verdict: Verdict::Allow,
            evidence: Vec::new(),
        })
    }
}

/// A guard that records it ran and always allows, to prove non-targeted guards
/// still execute under per-guard budgeting.
struct RecordingGuard {
    label: String,
    ran: Arc<AtomicU64>,
}

impl Guard for RecordingGuard {
    fn name(&self) -> &str {
        &self.label
    }
    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        self.ran.fetch_add(1, Ordering::SeqCst);
        Ok(GuardDecision {
            verdict: Verdict::Allow,
            evidence: Vec::new(),
        })
    }
}

/// A tool server whose `invoke` never returns, modeling a wedged tool server.
struct HangingToolServer {
    id: String,
    tools: Vec<String>,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for HangingToolServer {
    fn server_id(&self) -> &str {
        &self.id
    }
    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }
    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<()>().await;
        unreachable!("hanging tool server never returns")
    }
}

/// A store double that reports a wedged writer, to drive the pre-dispatch gate
/// without a real stuck sqlite writer.
struct WedgedLivenessStore;

impl ReceiptStore for WedgedLivenessStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn writer_liveness(&self, _stall_threshold: std::time::Duration) -> ReceiptWriterLiveness {
        ReceiptWriterLiveness::Wedged
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_pipeline_budget_denies_hung_guard_and_frees_worker(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = make_config();
    config.deadlines.guard_pipeline_budget_ms = 200;
    let mut kernel = make_kernel(config);
    kernel.add_guard(Box::new(SleepingGuard {
        label: "sleeping".to_string(),
    }));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-hpd", vec!["noop"])));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-hpd", "noop")]),
        300,
    );
    let request = make_request("req-hpd-guard", &cap, "noop", "srv-hpd");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    let elapsed = start.elapsed();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        elapsed < Duration::from_secs(1),
        "deadline should fire near 200ms, well before the 2s guard sleep, took {elapsed:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_guard_budget_bounds_single_guard_not_pipeline(
) -> Result<(), Box<dyn std::error::Error>> {
    let fast_ran = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    // No pipeline budget; only the slow guard gets a 200ms override.
    config
        .deadlines
        .per_guard_budget_ms
        .insert("slow".to_string(), 200);
    let mut kernel = make_kernel(config);
    kernel.add_guard(Box::new(RecordingGuard {
        label: "fast".to_string(),
        ran: Arc::clone(&fast_ran),
    }));
    kernel.add_guard(Box::new(SleepingGuard {
        label: "slow".to_string(),
    }));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-pg", vec!["noop"])));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-pg", "noop")]),
        300,
    );
    let request = make_request("req-pg", &cap, "noop", "srv-pg");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(start.elapsed() < Duration::from_secs(1));
    // The fast guard ran before the slow guard tripped its override.
    assert_eq!(fast_ran.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatch_budget_expiry_runs_full_unwind_and_emits_cancelled_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let invocations = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.deadlines.dispatch_budget_ms = 200;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(HangingToolServer {
        id: "srv-hang".to_string(),
        tools: vec!["noop".to_string()],
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-hang", "noop")]),
        300,
    );
    let request = make_request("req-dispatch-deadline", &cap, "noop", "srv-hang");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "deadline must fire near 200ms"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1, "dispatch did start");
    assert_eq!(response.verdict, Verdict::Deny);

    // Exactly one signed Cancelled receipt was persisted, via the same path as a
    // cancellation.
    assert_eq!(
        kernel.receipt_log().len(),
        1,
        "one Cancelled receipt persisted"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedged_writer_watchdog_denies_before_side_effect(
) -> Result<(), Box<dyn std::error::Error>> {
    let invocations = Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(WedgedLivenessStore))?;
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-wedged",
        vec!["noop"],
        Arc::clone(&invocations),
    )));
    kernel.refresh_receipt_writer_liveness_for_test();
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-wedged", "noop")]),
        300,
    );
    let request = make_request("req-wedged", &cap, "noop", "srv-wedged");
    let kernel = Arc::new(kernel);

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "no tool side effect may occur while the writer is wedged"
    );
    Ok(())
}

/// A wedged store that also counts capability-snapshot writes, to prove the
/// snapshot path denies before entering the (unbounded) writer-backed write.
struct SnapshotCountingWedgedStore {
    snapshot_writes: Arc<AtomicU64>,
}

impl ReceiptStore for SnapshotCountingWedgedStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn record_capability_snapshot(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.snapshot_writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn writer_liveness(&self, _stall_threshold: std::time::Duration) -> ReceiptWriterLiveness {
        ReceiptWriterLiveness::Wedged
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedged_writer_denies_before_evaluation_capability_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    // The observed-capability snapshot in the evaluation hot path is a
    // writer-backed write with an unbounded wait. A wedged writer must be denied
    // before that write is entered, not after it has already hung the request.
    let invocations = Arc::new(AtomicU64::new(0));
    let snapshot_writes = Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(SnapshotCountingWedgedStore {
        snapshot_writes: Arc::clone(&snapshot_writes),
    }))?;
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-snapshot",
        vec!["noop"],
        Arc::clone(&invocations),
    )));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-snapshot", "noop")]),
        300,
    );
    // Publish the wedged verdict only now, so the snapshot that capability
    // issuance above records is not what this test measures.
    kernel.refresh_receipt_writer_liveness_for_test();
    let snapshots_before_dispatch = snapshot_writes.load(Ordering::SeqCst);
    let request = make_request("req-snapshot", &cap, "noop", "srv-snapshot");
    let kernel = Arc::new(kernel);

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        snapshot_writes.load(Ordering::SeqCst),
        snapshots_before_dispatch,
        "evaluation must deny before entering the capability snapshot write"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "no tool side effect may occur while the writer is wedged"
    );
    Ok(())
}
