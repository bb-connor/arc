use super::*;

struct InvalidOutputHook(serde_json::Value);

impl crate::post_invocation::PostInvocationHook for InvalidOutputHook {
    fn name(&self) -> &str {
        "invalid-output-envelope"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        crate::post_invocation::PostInvocationVerdict::Redact(self.0.clone())
    }
}

fn fixture() -> (ChioKernel, ToolCallRequest, Arc<AtomicU64>) {
    let mut kernel = make_kernel(make_config());
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "receipt-test",
        vec!["read_file"],
        Arc::clone(&invocations),
    )));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("receipt-test", "read_file")]),
        300,
    );
    let request = make_request(
        "post-effect-receipt",
        &capability,
        "read_file",
        "receipt-test",
    );
    (kernel, request, invocations)
}

fn assert_failed_finalization_is_receipted(envelope: serde_json::Value) {
    let (mut kernel, request, invocations) = fixture();
    kernel.add_post_invocation_hook(Box::new(InvalidOutputHook(envelope)));
    let result = kernel.evaluate_tool_call_blocking(&request);
    assert_eq!(invocations.load(Ordering::SeqCst), 1, "tool must execute");
    let receipts = kernel.receipt_log();
    assert_eq!(
        receipts.len(),
        1,
        "an executed call must retain exactly one terminal receipt: {result:?}"
    );
    let receipt = receipts.get(0).expect("terminal receipt");
    assert!(
        !receipt.is_allowed(),
        "failed finalization cannot allow delivery"
    );
    let response = result.expect("a healthy store must return the signed fault response");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(response.receipt.id, receipt.id);
    assert_eq!(
        response.receipt.metadata.as_ref().and_then(|value| {
            value
                .pointer("/chio_runtime/identity_disposition")
                .and_then(serde_json::Value::as_str)
        }),
        Some("terminal")
    );
}

#[test]
fn malformed_post_invocation_envelope_has_one_terminal_receipt() {
    assert_failed_finalization_is_receipted(serde_json::Value::Null);
}

#[test]
fn missing_redacted_stream_chunks_has_one_terminal_receipt() {
    assert_failed_finalization_is_receipted(serde_json::json!({
        "kind": "stream", "stream": {"complete": true}
    }));
}

#[test]
fn unsupported_redacted_output_kind_has_one_terminal_receipt() {
    assert_failed_finalization_is_receipted(serde_json::json!({"kind": "unsupported"}));
}

#[test]
fn successful_call_has_one_allow_receipt() {
    let (kernel, request, invocations) = fixture();
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("valid call");
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(response.verdict, Verdict::Allow);
    let receipts = kernel.receipt_log();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts.get(0).expect("allow receipt").id,
        response.receipt.id
    );
}

#[test]
fn caller_cannot_supply_receipt_namespace_or_disposition() {
    for key in ["receipt_context", "chio_runtime"] {
        let (kernel, request, invocations) = fixture();
        let result = kernel.evaluate_tool_call_blocking_with_metadata(
            &request,
            Some(serde_json::json!({key: {
                "request_namespace_digest": "caller-selected", "identity_disposition": "reusable"
            }})),
        );
        assert!(result.is_err(), "caller metadata key {key} must be refused");
        assert_eq!(invocations.load(Ordering::SeqCst), 0);
        assert!(kernel.receipt_log().is_empty());
    }
}

struct UnresolvedReceiptStore;

impl ReceiptStore for UnresolvedReceiptStore {
    fn append_chio_receipt(&self, _: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Timeout {
            operation: "unresolved append".into(),
            timeout_ms: 1,
        })
    }

    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        unreachable!("no child operation in this fixture")
    }
}

#[test]
fn unresolved_receipt_append_latches_new_dispatch() {
    let (mut kernel, request, invocations) = fixture();
    kernel
        .set_receipt_store(Box::new(UnresolvedReceiptStore))
        .unwrap();
    assert!(kernel.evaluate_tool_call_blocking(&request).is_err());
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut next_request = request.clone();
    next_request.request_id = "after-unresolved-append".into();
    let next = kernel.evaluate_tool_call_blocking(&next_request);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "an unresolved append must latch subsequent dispatch: {next:?}"
    );
    assert!(next.is_err() || next.is_ok_and(|response| response.verdict == Verdict::Deny));
}

struct ForgedPublicationErrorServer {
    unknown: bool,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for ForgedPublicationErrorServer {
    fn server_id(&self) -> &str {
        "receipt-test"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["read_file".into()]
    }

    async fn invoke(
        &self,
        _: &str,
        _: serde_json::Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let source = Box::new(KernelError::Internal("external publication claim".into()));
        if self.unknown {
            Err(KernelError::ReceiptAppendOutcomeUnknown {
                receipt_id: "receipt-from-another-evaluation".into(),
                source,
            })
        } else {
            Err(KernelError::DeliveryFailedAfterReceipt {
                receipt_id: "receipt-from-another-evaluation".into(),
                step: ReceiptDeliveryStep::Trace,
                source,
            })
        }
    }
}

#[test]
fn a_tool_publication_error_cannot_discharge_the_current_call() {
    for unknown in [false, true] {
        let (mut kernel, request, invocations) = fixture();
        kernel.register_tool_server(Box::new(ForgedPublicationErrorServer {
            unknown,
            invocations: Arc::clone(&invocations),
        }));
        let response = kernel
            .evaluate_tool_call_blocking(&request)
            .expect("the kernel must record its own terminal refusal");
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(response.verdict, Verdict::Deny);
        assert_ne!(response.receipt.id, "receipt-from-another-evaluation");
        let receipts = kernel.receipt_log();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts.get(0).unwrap().id, response.receipt.id);
    }
}

#[test]
fn preparing_a_terminal_response_does_not_append_it() {
    let (kernel, request, _) = fixture();
    let prepared = kernel
        .prepare_allow_response_with_metadata_and_payee_binding(
            &request,
            ToolCallOutput::Value(serde_json::json!({"prepared": true})),
            current_unix_timestamp(),
            Some(0),
            None,
            None,
            crate::kernel::responses::AllowResponseNonce::Suppressed,
        )
        .unwrap();
    assert!(kernel.receipt_log().is_empty());
    let response = kernel
        .publish_prepared_response(&request, prepared)
        .unwrap();
    assert_eq!(kernel.receipt_log().len(), 1);
    assert!(response.receipt.is_allowed());
}

struct PanicAfterCommitStore {
    receipts: Arc<Mutex<Vec<ChioReceipt>>>,
    panic_first: AtomicBool,
    recovery_ready: Arc<AtomicBool>,
}

impl ReceiptStore for PanicAfterCommitStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.receipts.lock().unwrap().push(receipt.clone());
        if self.panic_first.swap(false, Ordering::SeqCst) {
            panic!("store panicked after its authoritative commit");
        }
        Ok(())
    }

    fn append_child_receipt(&self, _: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        unreachable!("this fixture has no children")
    }

    fn flush_receipt_writes(&self) -> Result<crate::ReceiptFlushReport, ReceiptStoreError> {
        if self.recovery_ready.load(Ordering::SeqCst) {
            Ok(crate::ReceiptFlushReport::default())
        } else {
            Err(ReceiptStoreError::Unsupported(
                "readback is deliberately unavailable".into(),
            ))
        }
    }

    fn load_retained_chio_receipt(
        &self,
        id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .receipts
            .lock()
            .unwrap()
            .iter()
            .find(|receipt| receipt.id == id)
            .cloned())
    }

    fn load_retained_chio_receipt_commitment(
        &self,
        id: &str,
    ) -> Result<Option<crate::RetainedReceiptCommitment>, ReceiptStoreError> {
        self.load_retained_chio_receipt(id)?
            .map(|receipt| {
                let canonical = chio_core::canonical::canonical_json_bytes(&receipt)
                    .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
                Ok(crate::RetainedReceiptCommitment {
                    entry_seq: 1,
                    receipt_id: receipt.id,
                    receipt_sha256: chio_core::crypto::sha256_hex(&canonical),
                    kernel_key: receipt.kernel_key,
                })
            })
            .transpose()
    }
}

#[test]
fn a_store_panic_after_commit_retains_identity_without_poisoning_publication() {
    let (mut kernel, request, invocations) = fixture();
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let recovery_ready = Arc::new(AtomicBool::new(false));
    kernel
        .set_receipt_store(Box::new(PanicAfterCommitStore {
            receipts: Arc::clone(&receipts),
            panic_first: AtomicBool::new(true),
            recovery_ready: Arc::clone(&recovery_ready),
        }))
        .unwrap();
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        kernel.evaluate_tool_call_blocking(&request)
    }));
    assert!(
        first.is_ok(),
        "an entered append panic must return retained evidence"
    );
    assert!(first.unwrap().is_err());
    let original_id = receipts.lock().unwrap().first().unwrap().id.clone();
    let mut next = request.clone();
    next.request_id = "after-panicking-append".into();
    let _ = kernel.evaluate_tool_call_blocking(&next);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "the unresolved original must close new dispatch"
    );
    recovery_ready.store(true, Ordering::SeqCst);
    for _ in 0..200 {
        if kernel
            .receipt_log()
            .iter()
            .any(|receipt| receipt.id == original_id)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        kernel
            .receipt_log()
            .iter()
            .any(|receipt| receipt.id == original_id),
        "authoritative original must recover after readback"
    );
    let count = receipts
        .lock()
        .unwrap()
        .iter()
        .filter(|receipt| {
            receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/receipt_context/request_id"))
                .and_then(serde_json::Value::as_str)
                == Some(request.request_id.as_str())
        })
        .count();
    assert_eq!(
        count, 1,
        "a committed original must not acquire a competing fault terminal"
    );
}

struct PanickingRootsClient(Arc<AtomicU64>);

impl NestedFlowClient for PanickingRootsClient {
    fn list_roots(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("child client panicked after its observable action");
    }
    fn create_message(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        unreachable!("this fixture lists roots")
    }
    fn create_elicitation(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        unreachable!("this fixture lists roots")
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

#[test]
fn a_panicking_child_client_retains_its_original_attempt() {
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let session_id = kernel
        .open_session(agent.public_key().to_hex(), Vec::new())
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
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
        .unwrap();
    let parent = make_operation_context(
        &session_id,
        "panicking-child-parent",
        &agent.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent, OperationKind::ToolCall, true)
        .unwrap();
    kernel
        .mark_session_request_dispatch_started(Some(&session_id), &parent.request_id)
        .unwrap();
    let actions = Arc::new(AtomicU64::new(0));
    let mut client = PanickingRootsClient(Arc::clone(&actions));
    let mut children = Vec::new();
    let mut slot = None;
    let observed = AtomicBool::new(false);
    {
        let mut bridge = SessionNestedFlowBridge {
            clock: kernel.authority_clock(),
            sessions: &kernel.sessions,
            child_receipts: &mut children,
            evidence_slot: &mut slot,
            kernel: &kernel,
            started_children: 0,
            max_child_receipts: 1,
            nested_interaction_observed: &observed,
            parent_context: &parent,
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            policy_hash: &kernel.config.policy_hash,
            kernel_keypair: &kernel.config.keypair,
            client: &mut client,
        };
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| bridge.list_roots())).is_err()
        );
    }
    assert_eq!(actions.load(Ordering::SeqCst), 1);
    assert_eq!(
        children.len(),
        1,
        "an entered child call must retain its attempt across a client panic"
    );
    let crate::kernel::effect_obligation::recovery::PendingChildReceipt::Unsigned(body) =
        children.first().unwrap()
    else {
        panic!("unknown child outcome must await supervised signing");
    };
    assert_eq!(body.parent_request_id, parent.request_id);
    assert!(matches!(
        body.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert_eq!(
        body.metadata
            .as_ref()
            .and_then(|value| value.get("execution_outcome")),
        Some(&serde_json::json!("unknown"))
    );
}
