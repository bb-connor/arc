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
async fn pipeline_budget_bounds_the_per_guard_loop(
) -> Result<(), Box<dyn std::error::Error>> {
    // With per-guard budgets configured, the whole guard loop must still honor
    // the pipeline budget. A single guard whose own budget is generous but whose
    // work exceeds the pipeline budget must trip the pipeline deadline rather
    // than running to completion.
    let mut config = make_config();
    config.deadlines.guard_pipeline_budget_ms = 300;
    // A generous per-guard override forces the per-guard offloaded path yet never
    // fires on its own, so only the pipeline deadline can stop the slow guard.
    config
        .deadlines
        .per_guard_budget_ms
        .insert("slow".to_string(), 5_000);
    let mut kernel = make_kernel(config);
    kernel.add_guard(Box::new(SleepingGuard {
        label: "slow".to_string(),
    }));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-pipeline", vec!["noop"])));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-pipeline", "noop")]),
        300,
    );
    let request = make_request("req-pipeline", &cap, "noop", "srv-pipeline");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    let elapsed = start.elapsed();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        elapsed < Duration::from_secs(1),
        "the pipeline deadline must fire near 300ms, well before the 2s guard sleep, took {elapsed:?}"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedged_writer_denies_before_dispatch_without_a_running_watchdog(
) -> Result<(), Box<dyn std::error::Error>> {
    // No watchdog is started and no test refresh is published, mirroring a
    // freshly attached durable store on an edge that never calls
    // `spawn_receipt_writer_watchdog`. The gate must still sample the writer's
    // liveness directly and fail closed on a wedged writer, rather than admitting
    // on the not-yet-probed `Unknown` verdict and reaching a tool side effect.
    let invocations = Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(WedgedLivenessStore))?;
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-no-watchdog",
        vec!["noop"],
        Arc::clone(&invocations),
    )));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-no-watchdog", "noop")]),
        300,
    );
    let request = make_request("req-no-watchdog", &cap, "noop", "srv-no-watchdog");
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

/// A healthy store that records how the evaluation hot path invokes the
/// observed-capability snapshot: the budget passed to the bounded writer path,
/// and any use of the unbounded path.
struct SnapshotBudgetStore {
    bounded_budget_ms: Arc<AtomicU64>,
    unbounded_calls: Arc<AtomicU64>,
}

impl ReceiptStore for SnapshotBudgetStore {
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
        self.unbounded_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn record_capability_snapshot_with_timeout(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
        budget: std::time::Duration,
    ) -> Result<(), ReceiptStoreError> {
        self.bounded_budget_ms
            .store(budget.as_millis() as u64, Ordering::SeqCst);
        Ok(())
    }
    fn writer_liveness(&self, _stall_threshold: std::time::Duration) -> ReceiptWriterLiveness {
        ReceiptWriterLiveness::Healthy
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthy_writer_records_capability_snapshot_through_the_bounded_path(
) -> Result<(), Box<dyn std::error::Error>> {
    // A writer that is healthy at the pre-dispatch gate can still stall on the
    // observed-capability snapshot, which commits through the receipt writer.
    // The hot path must take that write through the bounded writer path with the
    // append budget, not the unbounded one, so it fails closed rather than hangs.
    let bounded_budget_ms = Arc::new(AtomicU64::new(0));
    let unbounded_calls = Arc::new(AtomicU64::new(0));
    let config = make_config();
    let expected_budget_ms =
        u64::try_from(config.deadlines.receipt_append_budget().as_millis()).unwrap_or(u64::MAX);
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(SnapshotBudgetStore {
        bounded_budget_ms: Arc::clone(&bounded_budget_ms),
        unbounded_calls: Arc::clone(&unbounded_calls),
    }))?;
    kernel.register_tool_server(Box::new(EchoServer::new("srv-snap-budget", vec!["noop"])));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-snap-budget", "noop")]),
        300,
    );
    // Isolate the dispatch-time snapshot from the issuance-time snapshot above.
    bounded_budget_ms.store(0, Ordering::SeqCst);
    unbounded_calls.store(0, Ordering::SeqCst);
    let request = make_request("req-snap-budget", &cap, "noop", "srv-snap-budget");
    let kernel = Arc::new(kernel);

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        bounded_budget_ms.load(Ordering::SeqCst),
        expected_budget_ms,
        "the observed-capability snapshot must use the bounded writer path with the append budget"
    );
    assert_eq!(
        unbounded_calls.load(Ordering::SeqCst),
        0,
        "the hot-path snapshot must not use the unbounded writer path"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase_dispatch_honors_the_configured_dispatch_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    // The `ToolEvaluator::dispatch` phase entry point is reachable by custom
    // evaluators independently of the full evaluate path. With a dispatch budget
    // configured it must enforce the deadline too, so a wedged tool server fails
    // closed within budget rather than hanging the caller indefinitely.
    use crate::kernel::evaluator::{BlockingToolEvaluator, ToolEvaluator};

    let invocations = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.deadlines.dispatch_budget_ms = 200;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(HangingToolServer {
        id: "srv-phase-hang".to_string(),
        tools: vec!["noop".to_string()],
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-phase-hang", "noop")]),
        300,
    );
    let request = make_request("req-phase-dispatch", &cap, "noop", "srv-phase-hang");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let result = BlockingToolEvaluator
        .dispatch(&kernel, &request, false)
        .await;
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "the phase dispatch deadline must fire near 200ms, well before a hung server"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1, "dispatch did start");
    match result {
        Err(KernelError::HotPathDeadlineExceeded { stage, .. }) => {
            assert_eq!(stage, HotPathStage::Dispatch);
        }
        other => panic!("expected a dispatch deadline error, got {other:?}"),
    }
    Ok(())
}
