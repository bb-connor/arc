use super::*;
use crate::receipt_store::RetainedReceiptCommitment;
use std::num::NonZeroUsize;
use tokio::sync::Semaphore;

fn capacity(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("nonzero capacity")
}

struct PendingServer {
    started: Arc<Semaphore>,
    release: Arc<Semaphore>,
    invocations: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl ToolServerConnection for PendingServer {
    fn server_id(&self) -> &str {
        "ordinary-pending-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["pending".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.started.add_permits(1);
        self.release
            .acquire()
            .await
            .map_err(|_| KernelError::Internal("pending fixture closed".into()))?
            .forget();
        Ok(serde_json::json!({"complete": true}))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn defaults_admit_more_than_256_real_pending_nondurable_calls() {
    const CALLS: usize = 320;
    let mut kernel = make_kernel(make_config());
    let started = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(PendingServer {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
        invocations: Arc::clone(&invocations),
    }));
    let capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("ordinary-pending-server", "pending")]),
        300,
    );
    let kernel = Arc::new(kernel);
    let mut calls = tokio::task::JoinSet::new();
    for index in 0..CALLS {
        let kernel = Arc::clone(&kernel);
        let request = make_request(
            &format!("ordinary-pending-{index}"),
            &capability,
            "pending",
            "ordinary-pending-server",
        );
        calls.spawn(async move { kernel.evaluate_tool_call(&request).await });
    }
    let admitted = tokio::time::timeout(
        Duration::from_secs(10),
        Arc::clone(&started).acquire_many_owned(u32::try_from(CALLS).expect("call count")),
    )
    .await;
    let concurrently_pending = invocations.load(Ordering::SeqCst);
    release.add_permits(CALLS);
    let mut allowed = 0;
    while let Some(response) = calls.join_next().await {
        if response
            .expect("evaluator task")
            .is_ok_and(|response| response.verdict == Verdict::Allow)
        {
            allowed += 1;
        }
    }
    assert!(
        admitted.is_ok_and(|result| result.is_ok()),
        "default evidence budget stopped at {concurrently_pending} of {CALLS} real calls"
    );
    assert_eq!(concurrently_pending, CALLS);
    assert_eq!(allowed, CALLS);
    assert_eq!(kernel.receipt_log().len(), CALLS);
}

#[test]
fn default_host_bytes_support_more_than_1024_ordinary_reservations() {
    const RESERVATIONS: usize = 1_025;
    let mut config = make_config();
    config.memory_budget.post_effect_evidence_slots = 2_048;
    config.memory_budget.post_effect_evidence_bytes = 256 * 1024 * 1024;
    let mut kernel = make_kernel(config);
    kernel
        .set_post_effect_evidence_budget(Arc::new(
            PostEffectEvidenceBudget::new(capacity(4_096)).expect("default host budget"),
        ))
        .expect("host budget install");
    let mut held = Vec::new();
    for _ in 0..RESERVATIONS {
        match kernel.acquire_post_effect_evidence_slot(capacity(128 * 1024)) {
            Ok(slot) => held.push(slot),
            Err(_) => break,
        }
    }
    let admitted = held.len();
    drop(held);
    assert_eq!(
        admitted, RESERVATIONS,
        "host bytes must cover its advertised ordinary slots"
    );
}

#[test]
fn custom_slot_count_scales_ordinary_byte_capacity() {
    let mut kernel = make_kernel(make_config());
    kernel
        .set_post_effect_evidence_budget(Arc::new(
            PostEffectEvidenceBudget::new(capacity(1)).expect("one-slot host budget"),
        ))
        .expect("host budget install");
    let mut slot = kernel
        .acquire_post_effect_evidence_slot(capacity(128 * 1024))
        .expect("ordinary reservation");
    assert!(matches!(
        slot.reserve_bytes(1),
        Err(KernelError::PostEffectEvidenceCapacity)
    ));
}

#[test]
fn overflowing_default_byte_scaling_is_refused_without_allocation() {
    assert!(matches!(
        PostEffectEvidenceBudget::new(capacity(Semaphore::MAX_PERMITS)),
        Err(KernelError::PostEffectEvidenceCapacity)
    ));
}

#[test]
fn explicit_byte_limit_remains_independent_of_slot_count() {
    let mut kernel = make_kernel(make_config());
    kernel
        .set_post_effect_evidence_budget(Arc::new(
            PostEffectEvidenceBudget::with_byte_limit(capacity(2), capacity(8))
                .expect("explicit bounded host budget"),
        ))
        .expect("host budget install");
    let held = kernel
        .acquire_post_effect_evidence_slot(capacity(8))
        .expect("first slot");
    assert!(matches!(
        kernel.acquire_post_effect_evidence_slot(capacity(1)),
        Err(KernelError::PostEffectEvidenceCapacity)
    ));
    drop(held);
    assert!(kernel
        .acquire_post_effect_evidence_slot(capacity(8))
        .is_ok());
}

#[derive(Default)]
struct ReceiptState {
    open: AtomicBool,
    receipts: Mutex<Vec<ChioReceipt>>,
    children: Mutex<Vec<ChildRequestReceipt>>,
}

struct LatchingStore(Arc<ReceiptState>);

impl ReceiptStore for LatchingStore {
    fn opening_status(
        &self,
        _receipt_id: &str,
    ) -> Result<crate::receipt_store::OpeningStatus, crate::receipt_store::ReceiptStoreError> {
        Ok(crate::receipt_store::OpeningStatus::Unknown)
    }
    fn read_openings(
        &self,
        _receipt_id: &str,
        _scope: &crate::receipt_store::OpeningReadScope,
    ) -> Result<crate::receipt_store::OpeningState, crate::receipt_store::ReceiptStoreError> {
        Ok(crate::receipt_store::OpeningState::Unknown)
    }
    fn erase_openings(
        &self,
        _receipt_id: &str,
        _erased_at: u64,
    ) -> Result<(), crate::receipt_store::ReceiptStoreError> {
        Err(crate::receipt_store::ReceiptStoreError::Unsupported(
            "test double holds no receipt openings".to_string(),
        ))
    }
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        let mut receipts = self.0.receipts.lock().expect("stored receipts");
        if !receipts.iter().any(|stored| stored.id == receipt.id) {
            receipts.push(receipt.clone());
        }
        if self.0.open.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ReceiptStoreError::Timeout {
                operation: "controlled receipt acknowledgement".into(),
                timeout_ms: 1,
            })
        }
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        let mut children = self.0.children.lock().expect("stored children");
        if !children.iter().any(|stored| stored.id == receipt.id) {
            children.push(receipt.clone());
        }
        if self.0.open.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ReceiptStoreError::Timeout {
                operation: "controlled child acknowledgement".into(),
                timeout_ms: 1,
            })
        }
    }

    fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        if self.0.open.load(Ordering::SeqCst) {
            Ok(ReceiptFlushReport::default())
        } else {
            Err(ReceiptStoreError::Timeout {
                operation: "controlled writer barrier".into(),
                timeout_ms: 1,
            })
        }
    }

    fn load_chio_receipt(&self, id: &str) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .0
            .receipts
            .lock()
            .expect("stored receipts")
            .iter()
            .find(|receipt| receipt.id == id)
            .cloned())
    }

    fn load_retained_chio_receipt_commitment(
        &self,
        id: &str,
    ) -> Result<Option<RetainedReceiptCommitment>, ReceiptStoreError> {
        self.load_chio_receipt(id)?
            .map(|receipt| {
                Ok(RetainedReceiptCommitment {
                    entry_seq: 1,
                    receipt_id: receipt.id.clone(),
                    receipt_sha256: chio_core::crypto::sha256_hex(
                        &chio_core::canonical::canonical_json_bytes(&receipt)
                            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?,
                    ),
                    kernel_key: receipt.kernel_key,
                })
            })
            .transpose()
    }

    fn load_retained_child_receipt(
        &self,
        id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        Ok(self
            .0
            .children
            .lock()
            .expect("stored children")
            .iter()
            .find(|receipt| receipt.id == id)
            .cloned())
    }
}

struct ReadOnlyServer(Arc<AtomicU64>);

#[async_trait::async_trait]
impl ToolServerConnection for ReadOnlyServer {
    fn server_id(&self) -> &str {
        "latching-read-only"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["read".into()]
    }
    fn tool_is_read_only(&self, tool: &str) -> bool {
        tool == "read"
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({"read": true}))
    }
}

struct DurableParentServer {
    store: Arc<super::durable_admission::TestAdmissionOperationStore>,
    started: std::sync::mpsc::Sender<()>,
    continue_child: Arc<Semaphore>,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableParentServer {
    fn server_id(&self) -> &str {
        "durable-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted
        );
        self.invocations.fetch_add(1, Ordering::SeqCst);
        self.started
            .send(())
            .map_err(|_| KernelError::Internal("parent started receiver closed".into()))?;
        self.continue_child
            .acquire()
            .await
            .map_err(|_| KernelError::Internal("child gate closed".into()))?
            .forget();
        let roots = bridge
            .ok_or_else(|| KernelError::Internal("child bridge missing".into()))?
            .list_roots()?;
        Ok(serde_json::json!({"roots": roots}))
    }
}

struct RootsClient(Arc<AtomicU64>);

impl NestedFlowClient for RootsClient {
    fn list_roots(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
    fn create_message(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        unreachable!("roots-only fixture")
    }
    fn create_elicitation(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        unreachable!("roots-only fixture")
    }
    fn notify_elicitation_completed(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }
    fn notify_resource_updated(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }
    fn notify_resources_list_changed(&mut self, _: &OperationContext) -> Result<(), KernelError> {
        Ok(())
    }
}

fn durable_child_after_latch(host_slots: usize, expected_children: u64) {
    let (mut kernel, request, store, parent_invocations) =
        super::durable_admission::durable_admission_fixture("child-after-unrelated-latch");
    let receipt_state = Arc::new(ReceiptState::default());
    kernel
        .set_receipt_store(Box::new(LatchingStore(Arc::clone(&receipt_state))))
        .expect("latching store");
    kernel
        .set_post_effect_evidence_budget(Arc::new(
            PostEffectEvidenceBudget::new(capacity(host_slots)).expect("shared host slots"),
        ))
        .expect("host budget install");
    let (started, receiver) = std::sync::mpsc::channel();
    let continue_child = Arc::new(Semaphore::new(0));
    kernel.register_tool_server(Box::new(DurableParentServer {
        store: Arc::clone(&store),
        started,
        continue_child: Arc::clone(&continue_child),
        invocations: Arc::clone(&parent_invocations),
    }));
    let read_invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(ReadOnlyServer(Arc::clone(&read_invocations))));
    let agent_id = request.capability.subject.to_hex();
    let session = kernel
        .open_session(agent_id.clone(), vec![request.capability.clone()])
        .expect("parent session");
    kernel
        .activate_session(&session)
        .expect("active parent session");
    kernel
        .set_session_peer_capabilities(
            &session,
            PeerCapabilities {
                authorization: None,
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: true,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .expect("root capability negotiation");
    let parent = make_operation_context(&session, &request.request_id, &agent_id);
    kernel
        .begin_session_request(&parent, OperationKind::ToolCall, true)
        .expect("parent request");
    let read_capability = make_capability(
        &kernel,
        &make_keypair(),
        make_scope(vec![make_grant("latching-read-only", "read")]),
        300,
    );
    let read_request = make_request(
        "unrelated-latching-call",
        &read_capability,
        "read",
        "latching-read-only",
    );
    let kernel = Arc::new(kernel);
    let child_invocations = Arc::new(AtomicU64::new(0));
    let parent_kernel = Arc::clone(&kernel);
    let children = Arc::clone(&child_invocations);
    let call = std::thread::spawn(move || {
        let mut client = RootsClient(children);
        parent_kernel.evaluate_tool_call_with_nested_flow_client(
            &parent,
            &request,
            &mut client,
            None,
        )
    });
    receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("actual durable parent dispatch");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    let unrelated = kernel
        .evaluate_tool_call_blocking(&read_request)
        .expect_err("receipt acknowledgement remains unresolved");
    let KernelError::ReceiptAppendOutcomeUnknown { receipt_id, source } = unrelated else {
        panic!("expected the original receipt's unresolved append: {unrelated:?}");
    };
    assert!(matches!(
        *source,
        KernelError::ReceiptPersistence(ReceiptStoreError::Timeout {
            operation,
            timeout_ms: 1,
        }) if operation == "controlled receipt acknowledgement"
    ));
    {
        let receipts = receipt_state.receipts.lock().expect("stored receipts");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].id, receipt_id);
        assert_eq!(
            receipts[0]
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/receipt_context/request_id"))
                .and_then(serde_json::Value::as_str),
            Some(read_request.request_id.as_str())
        );
    }
    assert_eq!(read_invocations.load(Ordering::SeqCst), 1);
    assert!(matches!(
        kernel.ensure_post_effect_evidence_latch_clear(),
        Err(KernelError::PostEffectEvidencePending { buffered: 1 })
    ));
    continue_child.add_permits(1);
    let parent_result = call.join().expect("durable parent thread");
    receipt_state.open.store(true, Ordering::SeqCst);
    super::evidence_recovery::wait_for_post_effect_evidence(&kernel);
    assert_eq!(parent_invocations.load(Ordering::SeqCst), 1);
    assert_eq!(child_invocations.load(Ordering::SeqCst), expected_children, "already-dispatched child capacity is independent of the new-dispatch latch: {parent_result:?}");
    assert_eq!(
        receipt_state
            .children
            .lock()
            .expect("stored children")
            .len(),
        usize::try_from(expected_children).expect("child count")
    );
}

#[test]
fn dispatched_durable_parent_can_begin_child_while_another_call_latches_dispatch() {
    durable_child_after_latch(2, 1);
}

#[test]
fn dispatched_durable_child_still_respects_actual_host_slot_capacity() {
    durable_child_after_latch(1, 0);
}
