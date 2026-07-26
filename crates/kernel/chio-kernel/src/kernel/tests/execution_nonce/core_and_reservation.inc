// Execution-nonce integration tests.
//
// Included by `src/kernel/tests.rs`, which already imported `super::*`
// and all helper items from `tests/all.rs` (`make_config`, `make_scope`,
// `make_grant`, `make_keypair`, `make_capability`, `make_request`,
// `EchoServer`).
//
// The tests cover six behaviours:
//   (a) a fresh nonce on Allow verifies
//   (b) a stale nonce (>TTL) is rejected
//   (c) a replayed nonce is rejected
//   (d) mismatched binding is rejected
//   (e) tampered signature is rejected
//   (f) disabled mode lets tool calls through without a nonce (back-compat)

use crate::execution_nonce::{
    mint_execution_nonce, verify_execution_nonce, ExecutionNonceConfig, ExecutionNonceError,
    InMemoryExecutionNonceStore, NonceBinding,
};

fn install_fixture_budget_admission_authorities(kernel: &mut ChioKernel, prefix: &str) {
    kernel
        .set_admission_operation_store_handle(durable_test_admission_operation_store(&format!(
            "{prefix}-operations"
        )))
        .expect("install fixture admission operation store");
    kernel
        .set_budget_store_handle(durable_atomic_test_budget_store(&format!(
            "{prefix}-budget"
        )))
        .expect("install fixture budget store");
}

struct OperationDecliningNoncePaymentAdapter {
    operation_adapter: crate::payment::SimPaymentAdapter,
}

impl OperationDecliningNoncePaymentAdapter {
    fn new() -> Self {
        Self {
            operation_adapter: crate::payment::SimPaymentAdapter::new(),
        }
    }
}

impl PaymentAdapter for OperationDecliningNoncePaymentAdapter {
    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn supports_operation_payment_mutations(&self) -> bool {
        true
    }

    fn authorize(
        &self,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        PaymentAdapter::authorize(&DecliningPaymentAdapter, request)
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        PaymentAdapter::capture(
            &DecliningPaymentAdapter,
            authorization_id,
            amount_units,
            currency,
            reference,
        )
    }

    fn release(
        &self,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        PaymentAdapter::release(&DecliningPaymentAdapter, authorization_id, reference)
    }

    fn refund(
        &self,
        transaction_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        PaymentAdapter::refund(
            &DecliningPaymentAdapter,
            transaction_id,
            amount_units,
            currency,
            reference,
        )
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        let _ = self
            .operation_adapter
            .lookup_authorization_for_operation(operation_id, request_binding_hash)?;
        if request.operation_id.as_deref() != Some(operation_id)
            || request.request_binding_hash.as_deref() != Some(request_binding_hash)
        {
            return Err(PaymentError::RailError(
                "payment authorization request does not match its admission operation".to_string(),
            ));
        }
        Err(PaymentError::InsufficientFunds)
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        let _ = self
            .operation_adapter
            .lookup_authorization_for_operation(operation_id, request_binding_hash)?;
        Ok(None)
    }

    fn capture_for_operation(
        &self,
        request: crate::payment::OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.operation_adapter.capture_for_operation(request)
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        authorization_id: &str,
        reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.operation_adapter.release_for_operation(
            operation_id,
            request_binding_hash,
            authorization_id,
            reference,
        )
    }

    fn refund_for_operation(
        &self,
        request: crate::payment::OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        self.operation_adapter.refund_for_operation(request)
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<crate::payment::RailSettlementState, PaymentError> {
        self.operation_adapter.settlement_state_for_operation(
            operation_id,
            request_binding_hash,
            reference,
            authorization_id,
        )
    }
}

struct SelectiveAuthorityArtifactTrustResolver {
    key: PublicKey,
    denied_artifact: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

impl AuthorityArtifactTrustResolver for SelectiveAuthorityArtifactTrustResolver {
    fn trusted_issuer_for_artifact(
        &self,
        artifact: &[u8],
        claimed_issuer: &PublicKey,
        signature: &chio_core::Signature,
    ) -> Result<Option<PublicKey>, String> {
        if claimed_issuer != &self.key {
            return Ok(None);
        }
        if !claimed_issuer.verify(artifact, signature) {
            return Ok(None);
        }
        if self
            .denied_artifact
            .lock()
            .map_err(|_| "selective authority resolver lock poisoned".to_string())?
            .as_deref()
            == Some(artifact)
        {
            return Err("authority artifact denied by runtime migration binding".to_string());
        }
        Ok(Some(self.key.clone()))
    }
}

fn kernel_with_nonce() -> (ChioKernel, Keypair, ChioScope, ExecutionNonceConfig) {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let store = Box::new(InMemoryExecutionNonceStore::from_config(&cfg));
    kernel
        .set_execution_nonce_store(cfg.clone(), store)
        .expect("nonce store installation");
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    (kernel, agent_kp, scope, cfg)
}

fn binding_for_request(cap: &CapabilityToken, request: &ToolCallRequest) -> NonceBinding {
    let parameter_hash =
        chio_core::receipt::decision::ToolCallAction::from_parameters(request.arguments.clone())
            .unwrap()
            .parameter_hash;
    NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash,
    }
}

fn mint_nonce_for_request(
    kernel: &ChioKernel,
    cap: &CapabilityToken,
    request: &ToolCallRequest,
    cfg: &ExecutionNonceConfig,
) -> crate::execution_nonce::SignedExecutionNonce {
    let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
    mint_execution_nonce(
        &kernel.config.keypair,
        binding_for_request(cap, request),
        cfg,
        now,
    )
    .unwrap()
}

#[test]
fn allow_verdict_carries_signed_execution_nonce_and_verifies() {
    let (kernel, agent_kp, scope, _cfg) = kernel_with_nonce();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let signed = response
        .execution_nonce
        .expect("allow verdict must carry an execution nonce");

    let expected = NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash: response.receipt.action.parameter_hash.clone(),
    };
    kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap();
}

#[test]
fn resolver_denial_does_not_consume_a_presented_execution_nonce() {
    let (mut kernel, agent_kp, scope, _cfg) = kernel_with_nonce();
    let denied_artifact = std::sync::Arc::new(std::sync::Mutex::new(None));
    kernel
        .set_authority_artifact_trust_resolver(std::sync::Arc::new(
            SelectiveAuthorityArtifactTrustResolver {
                key: kernel.public_key(),
                denied_artifact: std::sync::Arc::clone(&denied_artifact),
            },
        ))
        .unwrap();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-resolver", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let signed = response.execution_nonce.unwrap();
    let expected = binding_for_request(&cap, &request);
    *denied_artifact.lock().unwrap() = Some(
        crate::execution_nonce::execution_nonce_signed_artifact(&signed).unwrap(),
    );

    let error = kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap_err();
    assert!(matches!(error, ExecutionNonceError::AuthorityTrust(_)));

    *denied_artifact.lock().unwrap() = None;
    kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap();
}

#[test]
fn stale_nonce_is_rejected_after_ttl() {
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let store = InMemoryExecutionNonceStore::from_config(&cfg);
    let kp = Keypair::generate();
    let binding = NonceBinding {
        subject_id: "s".into(),
        capability_id: "c".into(),
        tool_server: "t".into(),
        tool_name: "n".into(),
        parameter_hash: "h".into(),
    };
    let now = 1_000_000;
    let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();

    let err = verify_execution_nonce(
        &signed,
        &kp.public_key(),
        &binding,
        now + cfg.nonce_ttl_secs as i64 + 1,
        &store,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExecutionNonceError::Expired { .. }),
        "expected Expired, got {err:?}"
    );
}

#[test]
fn replayed_nonce_is_rejected_by_store() {
    let (kernel, agent_kp, scope, _cfg) = kernel_with_nonce();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-replay", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let signed = response
        .execution_nonce
        .expect("allow verdict must carry an execution nonce");
    let expected = NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash: response.receipt.action.parameter_hash.clone(),
    };

    // First verification consumes the nonce.
    kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap();
    // Second verification with the same nonce must be rejected as replay.
    let err = kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap_err();
    assert!(
        matches!(err, ExecutionNonceError::Replayed),
        "expected Replayed, got {err:?}"
    );
}

#[test]
fn mismatched_binding_is_rejected() {
    let (kernel, agent_kp, scope, _cfg) = kernel_with_nonce();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-bind", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let signed = response
        .execution_nonce
        .expect("allow verdict must carry an execution nonce");

    // Corrupt the expected tool name -- the kernel was bound to read_file
    // but the caller claims write_file.
    let expected = NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: "write_file".to_string(),
        parameter_hash: response.receipt.action.parameter_hash.clone(),
    };
    let err = kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap_err();
    assert!(
        matches!(err, ExecutionNonceError::BindingMismatch { .. }),
        "expected BindingMismatch, got {err:?}"
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let store = InMemoryExecutionNonceStore::from_config(&cfg);
    let kp = Keypair::generate();
    let binding = NonceBinding {
        subject_id: "s".into(),
        capability_id: "c".into(),
        tool_server: "t".into(),
        tool_name: "n".into(),
        parameter_hash: "h".into(),
    };
    let now = 1_000_000;
    let mut signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
    // Mutate a signed field after signing. Caller also mutates the
    // expected binding so the code path reaches signature verify.
    signed.nonce.bound_to.tool_name = "write_file".to_string();
    let expected = NonceBinding {
        tool_name: "write_file".to_string(),
        ..binding
    };
    let err =
        verify_execution_nonce(&signed, &kp.public_key(), &expected, now + 1, &store).unwrap_err();
    assert!(
        matches!(err, ExecutionNonceError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn disabled_mode_allows_tool_calls_without_nonce() {
    // A kernel with no execution_nonce_config installed: the allow
    // response must still succeed and the nonce slot must be absent.
    // This is the backward-compat guarantee for existing deployments.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-no-nonce-config", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(
        response.execution_nonce.is_none(),
        "legacy deployments should carry no execution nonce"
    );
}

#[test]
fn strict_nonce_mode_denies_dispatch_without_presented_nonce() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("nonce store installation");

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-required", &cap, "read_file", "srv-a");

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();

    assert!(
        err.to_string().contains("execution nonce"),
        "expected execution nonce denial, got: {err}"
    );
}

#[test]
fn strict_nonce_mode_denies_missing_nonce_before_server_lookup() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("nonce store installation");

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-nonce-before-lookup", &cap, "read_file", "missing-srv");
    request.server_id = "missing-srv".to_string();

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();

    assert!(
        err.to_string().contains("execution nonce"),
        "expected nonce denial before server lookup, got: {err}"
    );
}

#[test]
fn strict_nonce_mode_dispatches_once_with_presented_nonce() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("nonce store installation");

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-nonce-dispatch-once", &cap, "read_file", "srv-a");
    request.execution_nonce = Some(mint_nonce_for_request(&kernel, &cap, &request, &cfg));

    let (output, cost) =
        block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false)).unwrap();
    assert!(cost.is_none());
    let ToolServerOutput::Value(value) = output else {
        panic!("expected value output");
    };
    assert_eq!(value["tool"], "read_file");

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "expected replay denial, got: {err}"
    );
}

#[test]
fn strict_nonce_mode_nested_flow_operation_forwards_presented_nonce(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("nonce store installation");

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request_id = "req-nonce-nested-operation";
    let request = make_request(request_id, &cap, "read_file", "srv-a");
    let nonce = mint_nonce_for_request(&kernel, &cap, &request, &cfg);
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(&session_id, request_id, &agent_kp.public_key().to_hex());
    let operation = ToolCallOperation {
        capability: cap,
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: None,
        supplemental_authorization: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        execution_nonce: Some(serde_json::to_value(&nonce)?),
        model_metadata: None,
        extra_metadata: None,
        declassification_grant: None,
    };
    let mut client = NoopNestedFlowClient;

    let response = kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    )?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert!(
        response.output.is_some(),
        "valid nonce on nested-flow operation must reach dispatch"
    );
    Ok(())
}

#[test]
fn strict_nonce_mode_preflights_nonce_then_executes_once() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        invocations.clone(),
    )));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("nonce store installation");
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-preflight", &cap, "read_file", "srv-a");

    let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight.verdict, Verdict::Allow);
    assert!(
        preflight.output.is_none(),
        "strict preflight must not invoke the tool server"
    );
    assert!(matches!(
        &preflight.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(
        matches!(
            preflight.receipt.decision.as_ref(),
            Some(Decision::Incomplete { reason })
                if reason.contains("execution nonce preflight")
        ),
        "nonce preflight receipt must not claim executed Allow"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let nonce = *preflight
        .execution_nonce
        .expect("strict preflight must return an execution nonce");

    let mut execution_request = request.clone();
    execution_request.execution_nonce = Some(nonce);
    let executed = kernel
        .evaluate_tool_call_blocking(&execution_request)
        .unwrap();
    assert_eq!(executed.verdict, Verdict::Allow);
    assert!(
        executed.output.is_some(),
        "execution request must return tool output"
    );
    assert!(
        executed.execution_nonce.is_none(),
        "executed calls must not mint another nonce for the same request"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&execution_request)
        .unwrap();
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(
        replay
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("execution nonce")),
        "expected replay denial, got: {:?}",
        replay.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn strict_nonce_mode_ordinary_aggregate_admission_owns_replay_reservation() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        invocations.clone(),
    )));
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let nonce_store = DurableRecoveryNonceStore::new();
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .unwrap();
    kernel.set_budget_store_handle(budget).unwrap();
    kernel
        .set_execution_nonce_store(config.clone(), Box::new(nonce_store.clone()))
        .unwrap();
    kernel.enable_aggregate_invocation_admission().unwrap();

    let agent_kp = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(2);
    let capability = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let capability = aggregate_limited_capability(&kernel, &capability, 2);
    let mut request = make_request(
        "req-ordinary-operation-owned-nonce",
        &capability,
        "read_file",
        "srv-a",
    );
    request.execution_nonce = Some(mint_nonce_for_request(
        &kernel,
        &capability,
        &request,
        &config,
    ));
    let expected_nonce = request.execution_nonce.clone().unwrap();

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let operation_id = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.pointer("/protocol_admission/admission_operation/operation_id")
        })
        .and_then(serde_json::Value::as_str)
        .unwrap();
    let operation = operations.load(operation_id).unwrap().unwrap();
    assert_eq!(
        operation.execution_nonce_id(),
        Some(expected_nonce.nonce_id())
    );
    let reservation = nonce_store
        .get_nonce_reservation(operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(reservation.operation_id(), operation_id);
    assert_eq!(reservation.nonce_id(), expected_nonce.nonce_id());
    assert_eq!(reservation.signed_expires_at(), expected_nonce.expires_at());
    assert_eq!(reservation.state(), ReplayReservationState::Committed);
    let nonce_action = operations
        .load_cleanup_actions(operation_id)
        .unwrap()
        .into_iter()
        .find(|action| action.kind() == AdmissionCleanupActionKind::ExecutionNonce)
        .unwrap();
    assert_eq!(nonce_action.state(), AdmissionCleanupActionState::Completed);

    let mut replay = request;
    replay.request_id = "req-ordinary-operation-owned-nonce-replay".to_string();
    let replay = kernel.evaluate_tool_call_blocking(&replay).unwrap();
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("execution nonce reservation")));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn strict_nonce_mode_payment_denial_does_not_consume_nonce() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-payment-denial");
    kernel
        .set_payment_adapter(Box::new(OperationDecliningNoncePaymentAdapter::new()))
        .expect("install payment adapter");
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("nonce store installation");

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let mut request = ToolCallRequest {
        request_id: "req-nonce-payment-deny".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        supplemental_authorization: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight.verdict, Verdict::Allow);
    request.execution_nonce = Some(
        *preflight
            .execution_nonce
            .expect("strict preflight must return an execution nonce"),
    );

    let denied = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("payment authorization failed")),
        "expected payment denial, got: {:?}",
        denied.reason
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);

    kernel
        .set_payment_adapter(Box::new(crate::payment::SimPaymentAdapter::new()))
        .expect("install payment adapter");
    request.request_id = "req-nonce-payment-allow".to_string();
    let allowed = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(allowed.verdict, Verdict::Allow);
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn strict_nonce_mode_denies_dispatch_with_stale_nonce() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("nonce store installation");

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-nonce-stale-dispatch", &cap, "read_file", "srv-a");
    let stale_issued_at =
        i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX) - cfg.nonce_ttl_secs as i64 - 1;
    request.execution_nonce = Some(
        mint_execution_nonce(
            &kernel.config.keypair,
            binding_for_request(&cap, &request),
            &cfg,
            stale_issued_at,
        )
        .unwrap(),
    );

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "expected stale nonce denial, got: {err}"
    );
}

#[test]
fn strict_nonce_mode_denies_dispatch_with_mismatched_binding() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("nonce store installation");

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-nonce-binding-dispatch", &cap, "read_file", "srv-a");
    let mut wrong_binding = binding_for_request(&cap, &request);
    wrong_binding.tool_name = "write_file".to_string();
    let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
    request.execution_nonce =
        Some(mint_execution_nonce(&kernel.config.keypair, wrong_binding, &cfg, now).unwrap());

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "expected binding denial, got: {err}"
    );
}

#[test]
fn require_presented_nonce_denies_when_missing_in_strict_mode() {
    // Build a kernel in strict mode and then call the gate helper
    // directly to prove that missing nonces fail closed.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let store = Box::new(InMemoryExecutionNonceStore::from_config(&cfg));
    kernel
        .set_execution_nonce_store(cfg, store)
        .expect("nonce store installation");
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-strict-missing", &cap, "read_file", "srv-a");

    assert!(kernel.execution_nonce_required());
    let err = kernel
        .require_presented_execution_nonce(&request, &cap)
        .unwrap_err();
    assert!(matches!(err, KernelError::Internal(_)), "{err:?}");
}

#[test]
fn require_presented_nonce_passes_when_valid() {
    let (kernel, agent_kp, scope, cfg) = kernel_with_nonce();
    // Flip strict mode after initial construction via a fresh config.
    let _ = cfg; // cfg borrow -- silence unused warning
    let strict_cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let strict_store = Box::new(InMemoryExecutionNonceStore::from_config(&strict_cfg));
    // Rebuild kernel with strict mode set.
    let mut kernel = kernel;
    kernel
        .set_execution_nonce_store(strict_cfg.clone(), strict_store)
        .expect("nonce store installation");

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-strict-ok", &cap, "read_file", "srv-a");
    request.execution_nonce = Some(mint_nonce_for_request(&kernel, &cap, &request, &strict_cfg));

    kernel
        .require_presented_execution_nonce(&request, &cap)
        .unwrap();
}

#[test]
fn kernel_ttl_enforces_30s_default() {
    // A tool call presented >30s after evaluation is rejected. We
    // cannot "sleep 30s" in a unit test, so we mint a nonce at a
    // specific timestamp and re-verify with an explicit clock.
    let cfg = ExecutionNonceConfig::default();
    assert_eq!(cfg.nonce_ttl_secs, 30);
    let store = InMemoryExecutionNonceStore::from_config(&cfg);
    let kp = Keypair::generate();
    let binding = NonceBinding {
        subject_id: "s".into(),
        capability_id: "c".into(),
        tool_server: "t".into(),
        tool_name: "n".into(),
        parameter_hash: "h".into(),
    };
    let now = 1_000_000;
    let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
    // exactly on the boundary -> rejected (strict < check).
    let err =
        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 30, &store).unwrap_err();
    assert!(matches!(err, ExecutionNonceError::Expired { .. }));
}

#[test]
fn in_memory_store_ttl_grace_period_does_not_regress() {
    // Round-trip: a short TTL expires entries but the signed body still
    // blocks a real replay because expires_at was already checked.
    let store = InMemoryExecutionNonceStore::new(1024, std::time::Duration::from_millis(1));
    use crate::execution_nonce::ExecutionNonceStore;
    assert!(store.reserve("a").unwrap());
    std::thread::sleep(Duration::from_millis(5));
    // After TTL the slot is reclaimed; that is intentional. The signed
    // body's `expires_at` is what prevents the actual replay.
    assert!(store.reserve("a").unwrap());
}

#[test]
fn mediated_allow_receipt_records_bound_execution_nonce_id() {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-mediated-allow");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig { nonce_ttl_secs: 30, nonce_store_capacity: 1024, require_nonce: false };
    kernel
        .set_execution_nonce_store(
            cfg.clone(),
            Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
        )
        .expect("install execution nonce store");

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600).unwrap();
    let request = ToolCallRequest {
        request_id: "req-nonce-link".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let nonce = response.execution_nonce.as_ref().expect("mediated allow mints a nonce");
    let metadata = response.receipt.metadata.as_ref().expect("receipt metadata present");
    let recorded = metadata["budget_authority"]["execution_nonce_id"].as_str()
        .expect("execution_nonce_id recorded on budget_authority metadata");
    assert_eq!(recorded, nonce.nonce_id());
    assert_eq!(
        metadata["budget_authority"]["mediated_spend"]["profile"],
        "chio.mediated_spend.v1"
    );
}

#[test]
fn reserving_authorization_keeps_hold_open_and_blocks_oversubscription() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-reservation-oversubscription");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");

    // max_cost_per_invocation == max_total_cost == 100: one authorization
    // reserves the entire grant budget.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let first = ToolCallRequest {
        request_id: "req-reserve-1".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    // The reserving authorization returns an allow verdict, an incomplete
    // terminal (no dispatch), and a freshly minted execution nonce.
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    assert!(matches!(
        &authorized.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(
        authorized.output.is_none(),
        "an authorization gate must not dispatch the tool"
    );
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("authorization mints a nonce");

    // The receipt records the reserved hold's authorize block with no terminal
    // reconcile, so it is truthfully non-authoritative.
    let metadata = authorized
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    assert_eq!(
        metadata["budget_authority"]["authorize"]["exposure_units"], 100,
        "the reserved hold must record the authorized exposure"
    );
    assert!(
        metadata["budget_authority"].get("terminal").is_none(),
        "a reserved (not reconciled) hold must carry no terminal disposition"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert!(
        is_authoritative_spend_receipt(&authorized.receipt, &admitted, nonce.as_ref()).is_err(),
        "a reserved authorization receipt must not be an authoritative spend"
    );

    // The hold stayed reserved (not reversed), so a second
    // authorization for the same fully-reserved grant is denied. No
    // over-subscription past max_total_cost.
    let mut second = first.clone();
    second.request_id = "req-reserve-2".to_string();
    let denied = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied.verdict,
        Verdict::Deny,
        "the reserved hold must block a second authorization: {:?}",
        denied.reason
    );
}

#[test]
fn strict_retry_mediated_spend_receipt_names_presented_nonce() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-strict-retry-spend");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let mut request = ToolCallRequest {
        request_id: "req-strict-retry-nonce".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    // The strict retry presents a nonce from a prior allow (the nonce binds the
    // capability/server/tool/parameter-hash, not the request id), so no nonce is
    // preminted during this completion.
    let nonce = mint_nonce_for_request(&kernel, &cap, &request, &cfg);
    request.execution_nonce = Some(nonce.clone());
    let executed = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(executed.verdict, Verdict::Allow);
    assert!(
        executed.output.is_some(),
        "strict retry must return tool output"
    );
    assert!(
        executed.execution_nonce.is_none(),
        "strict retry must not mint another nonce"
    );

    // The completed receipt must name the presented nonce id, not drop it.
    let metadata = executed
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    assert_eq!(
        metadata["budget_authority"]["execution_nonce_id"]
            .as_str()
            .expect("execution_nonce_id recorded on budget_authority metadata"),
        nonce.nonce_id()
    );

    // The reconciled receipt is an authoritative mediated-spend receipt bound to
    // the presented nonce: no NonceLinkMissing.
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&executed.receipt, &admitted, &nonce),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Reconcile-by-nonce: mediated spend becomes authoritative at the realized cost.
// ---------------------------------------------------------------------------

fn reconcile_kernel_and_cap() -> (ChioKernel, Keypair, CapabilityToken, ExecutionNonceConfig) {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-reconcile");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
    // max_cost_per_invocation 100, max_total 150: one authorization reserves the
    // worst-case 100; a second (needing 100 more -> 200 > 150) is blocked until
    // the first frees its unspent slack.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    (kernel, agent_kp, cap, cfg)
}

fn reserve_request(request_id: &str, cap: &CapabilityToken, agent_kp: &Keypair) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    }
}

#[test]
fn reconcile_by_nonce_settles_reserved_hold_and_frees_difference() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-1", &cap, &agent_kp);

    // Reserving authorization: hold H stays open, a nonce bound to H is minted.
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized
        .execution_nonce
        .clone()
        .expect("reserving authorization mints a nonce");
    assert!(
        nonce.reserved_hold_id().is_some(),
        "the reserving nonce must name the reserved hold"
    );
    assert_eq!(nonce.reserving_request_id(), Some("req-recon-1"));

    // A second authorization is blocked while the slack is reserved.
    let second = reserve_request("req-recon-2", &cap, &agent_kp);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "reserved hold must block the second authorization: {:?}",
        blocked.reason
    );

    // Reconcile H at realized 30 (< reserved 100): settle down, free 70.
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    // The receipt is an authoritative mediated spend bound to the presented nonce.
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["budget_authority"]["terminal"]["disposition"], "reconciled",
        "the reserved hold must be reconciled, not released"
    );
    assert_eq!(meta["budget_authority"]["terminal"]["realized_spend_units"], 30);
    assert_eq!(meta["budget_authority"]["authorize"]["exposure_units"], 100);
    assert_eq!(
        meta["budget_authority"]["execution_nonce_id"]
            .as_str()
            .unwrap(),
        nonce.nonce_id()
    );

    // The freed difference admits a subsequent authorization that was blocked.
    let third = reserve_request("req-recon-3", &cap, &agent_kp);
    let now_allowed = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        now_allowed.verdict,
        Verdict::Allow,
        "the freed budget must admit a new authorization: {:?}",
        now_allowed.reason
    );
}

#[test]
fn reconcile_by_nonce_receipt_binds_reserved_hold_into_authoritative_predicate() {
    use chio_core_types::receipt::authoritative_spend::{
        is_authoritative_spend_receipt, BudgetAuthorityReceiptRef, PresentedNonceView,
    };

    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-bind", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();

    // The reconcile-by-nonce receipt commits the exact hold the nonce reserved,
    // so the nonce's signed reserved hold id equals the receipt's committed hold.
    let budget = BudgetAuthorityReceiptRef::from_receipt(&reconciled.receipt)
        .expect("reconciled receipt carries budget authority");
    assert_eq!(
        PresentedNonceView::bound_reserved_hold_id(&nonce),
        Some(budget.hold_id.as_str()),
        "the reconciled hold must equal the hold the nonce reserved"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
}

#[test]
fn reconcile_by_nonce_second_time_is_rejected_as_replay() {
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-replay", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };

    kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        err.to_string().contains("nonce"),
        "second reconcile of the same nonce must be rejected as replay, got: {err}"
    );
}

#[test]
fn reconcile_by_nonce_rejects_forged_nonce() {
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-forge", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Repoint the signed hold id at an attacker-chosen hold without re-signing.
    let mut forged = nonce.clone();
    forged.nonce.reserved_hold_id = Some("budget-hold:attacker:cap:0".to_string());
    let realized = ToolInvocationCost {
        units: 10,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&forged, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        err.to_string().contains("nonce"),
        "a tampered nonce must be rejected, got: {err}"
    );

    // The genuine hold is untouched: the real nonce still reconciles.
    let ok = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(ok.verdict, Verdict::Allow);
}

#[test]
fn reconcile_by_nonce_clamps_realized_above_reserved() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-reconcile-clamp");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
    // Reserve the whole grant (max_per == max_total == 100).
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let first = reserve_request("req-recon-clamp", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Realized cost 250 exceeds the reserved worst-case 100: clamp to 100.
    let realized = ToolInvocationCost {
        units: 250,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["budget_authority"]["terminal"]["realized_spend_units"], 100,
        "realized cost above the reserved worst-case must clamp to the reserved amount"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
}

#[test]
fn reserved_hold_ttl_reaper_settles_expired_authorization_at_worst_case() {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-reservation-reaper");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
    // Whole grant reserved by one authorization.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let first = reserve_request("req-reap-1", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized
        .execution_nonce
        .clone()
        .expect("reserving authorization mints a nonce");
    let hold_id = nonce
        .reserved_hold_id()
        .expect("reserving nonce names the reserved hold")
        .to_string();

    // Not yet expired: the reaper leaves the still-valid reserved hold in place.
    let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
    assert_eq!(kernel.reap_expired_reserved_budget_holds(now).unwrap(), 0);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(
            &reserve_request("req-reap-2", &cap, &agent_kp),
            None,
        )
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "a still-valid reserved hold must keep blocking: {:?}",
        blocked.reason
    );

    // Past expiry: the reaper SETTLES the abandoned reserved hold at its reserved
    // worst-case (forfeit). The only evidence a spend occurred is a reconcile the
    // caller never sent, so an expired-and-unreconciled hold is treated as fully
    // spent: realized spend advances by the reserved amount and the difference is
    // NOT refunded. This is fail-closed for a cumulative spend cap.
    assert_eq!(
        kernel.reap_expired_reserved_budget_holds(i64::MAX).unwrap(),
        1
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.total_cost_realized_spend, 100,
        "the forfeited reserved worst-case becomes realized spend"
    );
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "committed spend stays at the worst-case, not released back to 0"
    );
    let settled = kernel
        .budget_store
        .get_budget_hold(&hold_id)
        .unwrap()
        .expect("the reaped hold is still present");
    assert_eq!(
        settled.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reconciled,
        "an expired reserved hold is settled at worst-case, not released"
    );

    // The forfeited worst-case stays consumed: a new authorization is DENIED, not
    // admitted by the freed difference the old release behavior used to give back.
    let forfeited = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(
            &reserve_request("req-reap-3", &cap, &agent_kp),
            None,
        )
        .unwrap();
    assert_eq!(
        forfeited.verdict,
        Verdict::Deny,
        "the forfeited reserved worst-case must stay consumed after reaping: {:?}",
        forfeited.reason
    );
}

#[test]
fn reserved_hold_ttl_matches_minted_nonce_expiry() {
    // The reserved-hold TTL deadline must be derived from the exact
    // instant the nonce is minted (its signed `expires_at`), so a valid nonce can
    // never expire after its hold has already been reaped. Guarantees the caller
    // can always reconcile-before-reaper while the nonce is still valid.
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let request = reserve_request("req-ttl-match", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("reserving authorization mints a nonce");
    let hold_id = nonce
        .reserved_hold_id()
        .expect("reserving nonce names the reserved hold");
    let hold = kernel
        .budget_store
        .get_budget_hold(hold_id)
        .unwrap()
        .expect("reserved hold is present");
    assert_eq!(
        hold.reserved_until,
        Some(nonce.expires_at()),
        "the reserved-hold TTL deadline must equal the minted nonce's expiry, never earlier"
    );
}

#[test]
fn reconcile_by_nonce_rejects_mismatched_realized_currency() {
    // Reconcile must reject a realized cost whose currency differs from
    // the currency the hold/grant was authorized in, before settling or signing.
    // A caller-supplied currency is never stamped onto a signed authoritative
    // receipt unchecked.
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-currency", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Reconcile with a currency the grant was NOT authorized in (grant is USD).
    let mismatched = ToolInvocationCost {
        units: 30,
        currency: "EUR".to_string(),
        breakdown: None,
    };
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &mismatched)
        .unwrap_err();
    assert!(
        err.to_string().contains("currency"),
        "a realized currency that differs from the reserved grant currency must be rejected, got: {err}"
    );

    // Fail-closed: no settle occurred, so the reserved worst-case still blocks a
    // second authorization (the whole slack is still reserved, not consumed).
    let second = reserve_request("req-recon-currency-2", &cap, &agent_kp);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "a rejected reconcile must not settle the reserved hold: {:?}",
        blocked.reason
    );

    // The nonce was not burned by the rejected reconcile, so the matching-currency
    // reconcile still succeeds and frees the difference.
    let matching = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let ok = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &matching)
        .unwrap();
    assert_eq!(ok.verdict, Verdict::Allow);
}

#[test]
fn reconcile_by_nonce_normalizes_currency_for_zero_exposure_invocation() {
    // A non-monetary invocation reserve carries zero exposure and no reserved
    // currency, so its realized currency is never validated (step 3). The
    // unchecked, caller-supplied currency must not reach the signed receipt: it is
    // normalized to the canonical inert value instead.
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-zero-exposure-currency");
    let agent_kp = Keypair::generate();
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
    let grant = make_invocation_limited_grant("cost-srv", "compute", 1);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = reserve_request("req-recon-invocation-currency", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Reconcile with an arbitrary, attacker-controlled currency string. The
    // invocation reserve has zero exposure, so the currency is not validated and
    // the realized cost is clamped to zero.
    let realized = ToolInvocationCost {
        units: 0,
        currency: "ATTACKER-CONTROLLED".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &request.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    // The signed receipt carries the canonical inert currency, never the caller
    // string, on any field.
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["financial"]["currency"], "",
        "a zero-exposure invocation reconcile must normalize the receipt currency to the inert value"
    );
    let serialized = serde_json::to_string(&reconciled.receipt).unwrap();
    assert!(
        !serialized.contains("ATTACKER-CONTROLLED"),
        "the unchecked caller-supplied currency must never reach the signed receipt"
    );
}

#[test]
fn reserving_authorization_succeeds_for_unregistered_tool_server() {
    // The reserve-for-caller authorization path never dispatches a tool
    // on this kernel, so it must NOT require the caller's tool server to be
    // registered. This lets the sidecar stop registering caller-arbitrary server
    // ids (unbounded growth) into the kernel.
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-unregistered-reservation");
    let agent_kp = Keypair::generate();
    // Deliberately do NOT register "unreg-srv".
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
    let grant = make_monetary_grant("unreg-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-unreg-reserve".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "unreg-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(
        authorized.verdict,
        Verdict::Allow,
        "the reserve path must not require tool-server registration: {:?}",
        authorized.reason
    );
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("the reserve authorization mints a nonce even for an unregistered server");
    assert!(
        nonce.reserved_hold_id().is_some(),
        "the reserve path reserves a hold and binds it into the nonce"
    );
}

#[test]
fn dispatch_for_unregistered_tool_server_still_denies() {
    // The dispatch path (and every non-reserve disposition) must still require the
    // tool server to be registered: only the reserve-for-caller path is relaxed.
    let kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Non-strict kernel so the normal dispatch path (not the reserve preflight) runs.
    let grant = make_monetary_grant("unreg-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-unreg-dispatch".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "unreg-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        supplemental_authorization: None,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };

    let denied = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not registered")),
        "dispatch to an unregistered server must deny ToolNotRegistered, got: {:?}",
        denied.reason
    );
}

// ---------------------------------------------------------------------------
// Preflight terminal-state reasons stay consistent with their receipt decision.
// ---------------------------------------------------------------------------

#[test]
fn reserving_authorization_terminal_state_matches_receipt_decision_reason() {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-reservation-reason");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = reserve_request("req-reserve-reason", &cap, &agent_kp);

    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);

    let terminal_reason = match &authorized.terminal_state {
        OperationTerminalState::Incomplete { reason } => reason.clone(),
        other => panic!("reserving authorization must be incomplete, got {other:?}"),
    };
    let decision_reason = match authorized.receipt.decision.as_ref() {
        Some(Decision::Incomplete { reason }) => reason.clone(),
        other => panic!("reserving authorization receipt must be incomplete, got {other:?}"),
    };
    assert_eq!(
        terminal_reason, decision_reason,
        "the reserve path terminal_state reason must match its receipt decision reason"
    );
    assert!(
        decision_reason.contains("reserved")
            && decision_reason.contains("present the minted execution nonce"),
        "the reserve path must report the reservation reason, got: {decision_reason}"
    );
    assert!(
        !terminal_reason.contains("retry with presented nonce"),
        "the reserve path must not borrow the retry-path terminal reason"
    );
}

#[test]
fn preflight_retry_terminal_state_matches_receipt_decision_reason() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-preflight-reason", &cap, "read_file", "srv-a");

    let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight.verdict, Verdict::Allow);

    let terminal_reason = match &preflight.terminal_state {
        OperationTerminalState::Incomplete { reason } => reason.clone(),
        other => panic!("strict preflight must be incomplete, got {other:?}"),
    };
    let decision_reason = match preflight.receipt.decision.as_ref() {
        Some(Decision::Incomplete { reason }) => reason.clone(),
        other => panic!("strict preflight receipt must be incomplete, got {other:?}"),
    };
    assert_eq!(
        terminal_reason, decision_reason,
        "the retry path terminal_state reason must match its receipt decision reason"
    );
    assert_eq!(
        terminal_reason, "execution nonce preflight requires retry with presented nonce",
        "the reverse-for-retry preflight reason must be unchanged"
    );
}

#[test]
fn reserving_authorization_rejects_presented_execution_nonce() {
    let mut kernel = make_kernel(make_monetary_config());
    install_fixture_budget_admission_authorities(&mut kernel, "nonce-presented-reservation");
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    )
    .expect("install execution nonce store");
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // No presented nonce: the mint-only reserve entry point authorizes.
    let clean = reserve_request("req-reserve-clean", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&clean, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);

    // A presented nonce is a settlement artifact. The mint-only reserve entry
    // point must fail closed rather than silently skip the reserve path and fall
    // through to dispatch (the documented MUST-NOT invariant).
    let mut presented = reserve_request("req-reserve-presented", &cap, &agent_kp);
    presented.execution_nonce = Some(mint_nonce_for_request(&kernel, &cap, &presented, &cfg));
    let err = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&presented, None)
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "presenting a nonce at the reserve entry point must fail closed, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Delegated reserve-for-caller: an outstanding reservation keeps its child's
// sibling-sum share admitted, so a sibling cannot over-subscribe the parent
// while the reservation is open. The share is freed only when the hold closes
// (reconcile-by-nonce or TTL reap).
// ---------------------------------------------------------------------------
