#![allow(clippy::expect_used, clippy::unwrap_used)]
use super::*;
use chio_core::capability::scope::{ChioScope, ToolGrant};
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::kinds::{BoundaryClass, ReceiptKind};
use chio_core::receipt::lineage::ChildRequestReceipt;
use chio_kernel::{KernelConfig, KernelError, ReceiptStore, ReceiptStoreError};
use chio_security_types::clock::{AuthorityDeadline, Clock, ClockError, ClockReading};
use chio_security_types::clock::{MonotonicInstant, UnixMillis};
use std::fs::{File, OpenOptions};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const WALL_START: u64 = 1_700_000_000_000;
// A finite producer is the independent stop for the original unbounded poll.
// It replenishes during each append, so the old code cannot observe an empty
// channel until it has consumed every command.
const PRODUCER_COMMANDS: usize = 64;

struct PollClock(Mutex<ClockReading>);
impl PollClock {
    fn new() -> Self {
        Self(Mutex::new(ClockReading::new(
            UnixMillis::new(WALL_START),
            MonotonicInstant::from_nanos(0),
        )))
    }
    fn advance(&self, wall_ms: u64, monotonic_ms: u64) {
        *self.0.lock().unwrap() = ClockReading::new(
            UnixMillis::new(WALL_START + wall_ms),
            MonotonicInstant::from_nanos(monotonic_ms * 1_000_000),
        );
    }
}
impl Clock for PollClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        Ok(*self.0.lock().unwrap())
    }
}

enum AppendEvent {
    Committed(usize),
    Stop,
}
struct ReplenishedReceiptStore {
    file: Mutex<File>,
    receipts: Mutex<Vec<ChioReceipt>>,
    events: mpsc::Sender<AppendEvent>,
    replenished: Mutex<mpsc::Receiver<()>>,
}
impl ReceiptStore for ReplenishedReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        let bytes = canonical_json_bytes(receipt)
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        let mut file = self.file.lock().unwrap();
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        drop(file);
        let mut receipts = self.receipts.lock().unwrap();
        receipts.push(receipt.clone());
        let count = receipts.len();
        drop(receipts);
        self.events
            .send(AppendEvent::Committed(count))
            .map_err(|_| ReceiptStoreError::Conflict("resupply producer stopped".into()))?;
        self.replenished
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| ReceiptStoreError::Conflict("resupply barrier timed out".into()))?;
        Ok(())
    }
    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Unsupported(
            "refusal polling cannot write a child terminal".into(),
        ))
    }
}

struct CountedTool(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for CountedTool {
    fn server_id(&self) -> &str {
        "poll-srv"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        _: Value,
        _: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<Value, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"unexpected_dispatch": true}))
    }
}

#[derive(Clone, Copy)]
enum PollCase {
    Yield,
    CapabilityWall,
    CapabilityMonotonic,
    TaskMonotonic,
    Cancel,
}

fn queue_refusal(
    sender: &crate::ingress::McpInboxSender,
    sequence: usize,
) -> crate::ingress::ProtocolRefusalAcknowledgement {
    let wire = format!(
        r#"{{"jsonrpc":"2.0","id":{sequence},"method":"tools/call","params":{{"name":"read_file","arguments":{{"secret":"raw-refusal-secret"}}}}}}"#
    );
    let message = sender.decode(wire.as_bytes(), 4096).unwrap();
    let summary = chio_kernel::ProtocolRefusalSummary::new(
        chio_kernel::ProtocolRefusalReason::SessionCredentialToolRestricted,
        "tools/call",
        Some("read_file"),
        message.request_digest().unwrap().clone(),
    );
    sender.record_protocol_refusal(message, summary).unwrap()
}

fn exercise_replenished_poll(case: PollCase) {
    let clock = Arc::new(PollClock::new());
    let signer = Keypair::generate();
    let config = KernelConfig {
        keypair: signer.clone(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "refusal-poll-policy".into(),
        allow_sampling: true,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: 0,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    };
    let mut kernel = ChioKernel::new_with_clock(config, clock.clone());
    let calls = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountedTool(calls.clone())));
    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "poll-srv".into(),
                    tool_name: "read_file".into(),
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
            1,
        )
        .unwrap();
    let expires_at = UnixMillis::from_secs(capability.expires_at).unwrap();
    let session_id = kernel
        .open_session(agent.public_key().to_hex(), vec![capability])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let parent_context = OperationContext::new(
        session_id.clone(),
        RequestId::new("poll-parent"),
        agent.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let path = std::env::temp_dir().join(format!("chio-refusal-poll-{}.jsonl", Uuid::new_v4()));
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&path)
        .unwrap();
    let (events, event_rx) = mpsc::channel();
    let (replenished, replenished_rx) = mpsc::channel();
    let store = Arc::new(ReplenishedReceiptStore {
        file: Mutex::new(file),
        receipts: Mutex::new(Vec::new()),
        events: events.clone(),
        replenished: Mutex::new(replenished_rx),
    });
    kernel.try_set_receipt_store_handle(store.clone()).unwrap();
    let (sender, mut receiver) = mcp_inbox();
    let (cancel_tx, mut cancel_rx) = mpsc::channel();
    let first_acknowledgement = queue_refusal(&sender, 1);
    let resupply_sender = sender.clone();
    let producer_clock = clock.clone();
    let producer = std::thread::spawn(move || {
        let mut acknowledgements = vec![first_acknowledgement];
        while let Ok(event) = event_rx.recv_timeout(Duration::from_secs(5)) {
            let AppendEvent::Committed(count) = event else {
                break;
            };
            assert_ne!(resupply_sender.usage().unwrap().wire_bytes, 0);
            match case {
                PollCase::Yield => producer_clock.advance(count as u64, count as u64),
                PollCase::CapabilityWall => producer_clock.advance(1000, 1000),
                PollCase::CapabilityMonotonic => producer_clock.advance(0, 1000),
                PollCase::TaskMonotonic => producer_clock.advance(0, 1),
                PollCase::Cancel if count == 1 => cancel_tx
                    .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
                        "params":{"requestId":"outer-parent","reason":"stop parent"}}))
                    .unwrap(),
                PollCase::Cancel => {}
            }
            if count < PRODUCER_COMMANDS {
                acknowledgements.push(queue_refusal(&resupply_sender, count + 1));
            }
            replenished.send(()).unwrap();
            if count == PRODUCER_COMMANDS {
                break;
            }
        }
        acknowledgements
    });
    let task_deadline = matches!(case, PollCase::TaskMonotonic)
        .then(|| AuthorityDeadline::for_timeout_ms(clock.read().unwrap(), 1).unwrap());
    let mut counter = 0;
    let mut progress = 0;
    let parent_client_id = json!("outer-parent");
    let mut pending = Vec::new();
    let mut deferred = VecDeque::new();
    let mut accepted = Vec::new();
    let mut output = Vec::new();
    let mut client = QueuedEdgeNestedFlowClient {
        refusal_kernel: &kernel,
        refusal_context: &parent_context,
        held_reply_reservations: Vec::new(),
        request_counter: &mut counter,
        parent_progress_step: &mut progress,
        parent_client_request_id: &parent_client_id,
        parent_kernel_request_id: &parent_context.request_id,
        pending_notifications: &mut pending,
        deferred_client_messages: &mut deferred,
        accepted_url_elicitations: &mut accepted,
        logging_enabled: false,
        minimum_log_level: LogLevel::Info,
        related_task_id: None,
        admission: receiver.admission.clone(),
        clock: clock.clone(),
        expires_at,
        capability_deadline: AuthorityDeadline::new(
            UnixMillis::new(WALL_START),
            expires_at,
            clock.read().unwrap(),
        ),
        task_deadline,
        client_rx: &mut receiver.receiver,
        cancel_rx: &mut cancel_rx,
        writer: &mut output,
    };
    let outcome = client.poll_parent_cancellation(&parent_context);
    drop(client);
    let _ = events.send(AppendEvent::Stop);
    let acknowledgements = producer.join().unwrap();
    let receipts = store.receipts.lock().unwrap().clone();
    let durable = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let reopened: Vec<ChioReceipt> = durable
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(reopened.len(), receipts.len());
    for (receipt, acknowledgement) in reopened.iter().zip(&acknowledgements) {
        let acknowledged = acknowledgement.try_recv().unwrap().unwrap();
        assert_eq!(receipt.id, acknowledged.id);
        assert!(receipt.verify_signature().unwrap());
        assert_eq!(receipt.kernel_key, signer.public_key());
        assert_eq!(receipt.receipt_kind, ReceiptKind::TraceObservation);
        assert_eq!(receipt.boundary_class, BoundaryClass::DetectOnly);
        assert!(receipt.decision.is_none());
        assert!(receipt.capability_id.is_empty());
        assert!(!receipt.is_allowed());
        assert!(receipt.financial_budget_authority_metadata().is_none());
    }
    assert!(!durable.contains("raw-refusal-secret"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(counter, 0);
    assert_eq!(progress, 0);
    assert!(pending.is_empty());
    assert!(deferred.is_empty());
    assert!(accepted.is_empty());
    assert!(output.is_empty());
    assert_eq!(kernel.session(&session_id).unwrap().inflight().len(), 1);
    assert!(kernel
        .session(&session_id)
        .unwrap()
        .request_lineage(&RequestId::new("protocol-refusal"))
        .is_none());

    match case {
        PollCase::Yield => {
            assert!(
                outcome.is_ok(),
                "poll failed instead of yielding: {outcome:?}"
            );
            assert!(
                receipts.len() <= 16,
                "one callback drained all {} continuously replenished refusals",
                receipts.len()
            );
        }
        PollCase::CapabilityWall | PollCase::CapabilityMonotonic | PollCase::TaskMonotonic => {
            assert!(matches!(
                outcome,
                Err(KernelError::Clock(ClockError::Expired))
            ));
            assert_eq!(
                receipts.len(),
                1,
                "expired polling persisted additional commands"
            );
        }
        PollCase::Cancel => {
            assert!(
                matches!(outcome, Err(KernelError::RequestCancelled { request_id, reason })
                if request_id == parent_context.request_id && reason == "cancelled by client: stop parent")
            );
            assert_eq!(
                receipts.len(),
                1,
                "parent cancellation lost priority during resupply"
            );
        }
    }
    assert_eq!(acknowledgements.len(), receipts.len() + 1);
    assert!(matches!(
        acknowledgements.last().unwrap().try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert_ne!(sender.usage().unwrap().wire_bytes, 0);
    drop(receiver);
    assert_eq!(
        sender.usage().unwrap(),
        crate::ingress::IngressUsage::default()
    );
}

#[test]
fn replenished_host_refusals_yield_to_upstream_before_queue_drains() {
    exercise_replenished_poll(PollCase::Yield);
}

#[test]
fn replenished_host_refusals_observe_original_capability_wall_expiry() {
    exercise_replenished_poll(PollCase::CapabilityWall);
}

#[test]
fn replenished_host_refusals_observe_original_capability_monotonic_expiry() {
    exercise_replenished_poll(PollCase::CapabilityMonotonic);
}

#[test]
fn replenished_host_refusals_observe_original_task_monotonic_expiry() {
    exercise_replenished_poll(PollCase::TaskMonotonic);
}

#[test]
fn replenished_host_refusals_preserve_parent_cancellation_priority() {
    exercise_replenished_poll(PollCase::Cancel);
}
