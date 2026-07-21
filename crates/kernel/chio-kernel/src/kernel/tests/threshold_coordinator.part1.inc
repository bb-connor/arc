struct RecordingThresholdOperationStore {
    inner: InMemoryAdmissionOperationStore,
    states: std::sync::Mutex<Vec<AdmissionOperationState>>,
    lose_ack_for: std::sync::Mutex<Option<AdmissionOperationState>>,
    hide_cleanup_actions: std::sync::atomic::AtomicBool,
    fail_cleanup_creation: std::sync::atomic::AtomicBool,
    lose_cleanup_create_ack: std::sync::atomic::AtomicBool,
}

struct FailingThresholdMemoryProvenanceStore;

impl crate::memory_provenance::MemoryProvenanceStore
    for FailingThresholdMemoryProvenanceStore
{
    fn append(
        &self,
        _input: crate::memory_provenance::MemoryProvenanceAppend,
    ) -> Result<
        crate::memory_provenance::MemoryProvenanceEntry,
        crate::memory_provenance::MemoryProvenanceError,
    > {
        Err(crate::memory_provenance::MemoryProvenanceError::Backend(
            "injected post-receipt append failure".to_string(),
        ))
    }

    fn get_entry(
        &self,
        _entry_id: &str,
    ) -> Result<
        Option<crate::memory_provenance::MemoryProvenanceEntry>,
        crate::memory_provenance::MemoryProvenanceError,
    > {
        Err(crate::memory_provenance::MemoryProvenanceError::Backend(
            "injected provenance read failure".to_string(),
        ))
    }

    fn latest_for_key(
        &self,
        _store: &str,
        _key: &str,
    ) -> Result<
        Option<crate::memory_provenance::MemoryProvenanceEntry>,
        crate::memory_provenance::MemoryProvenanceError,
    > {
        Err(crate::memory_provenance::MemoryProvenanceError::Backend(
            "injected provenance read failure".to_string(),
        ))
    }

    fn verify_entry(
        &self,
        _entry_id: &str,
    ) -> Result<
        crate::memory_provenance::ProvenanceVerification,
        crate::memory_provenance::MemoryProvenanceError,
    > {
        Err(crate::memory_provenance::MemoryProvenanceError::Backend(
            "injected provenance verification failure".to_string(),
        ))
    }

    fn chain_digest(
        &self,
    ) -> Result<String, crate::memory_provenance::MemoryProvenanceError> {
        Err(crate::memory_provenance::MemoryProvenanceError::Backend(
            "injected provenance digest failure".to_string(),
        ))
    }
}

#[derive(Clone, Default)]
struct ReservingThresholdRuntimeHook {
    evaluations: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl ReservingThresholdRuntimeHook {
    fn evaluations(&self) -> u64 {
        self.evaluations.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl RuntimeAdmissionHook for ReservingThresholdRuntimeHook {
    fn name(&self) -> &str {
        "reserving-threshold-runtime-hook"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.evaluations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "reserved_destructive_lease_id": "unsafe-pre-persist-reservation"
            }
        }))))
    }
}

#[derive(Clone)]
struct OperationAwareThresholdRuntimeHook {
    allowed: bool,
    evaluations: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    releases: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl OperationAwareThresholdRuntimeHook {
    fn allowing() -> Self {
        Self {
            allowed: true,
            evaluations: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            releases: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn denying() -> Self {
        Self {
            allowed: false,
            evaluations: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            releases: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn evaluations(&self) -> Vec<(String, String)> {
        self.evaluations
            .lock()
            .expect("runtime evaluations")
            .clone()
    }

    fn releases(&self) -> Vec<(String, String)> {
        self.releases.lock().expect("runtime releases").clone()
    }
}

impl RuntimeAdmissionHook for OperationAwareThresholdRuntimeHook {
    fn name(&self) -> &str {
        "operation-aware-threshold-runtime-hook"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        Err(KernelError::Internal(
            "pure threshold runtime hook used through mutating evaluation boundary".to_string(),
        ))
    }

    fn evaluate_before_operation_persist(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let operation_id = context.admission_operation_id.ok_or_else(|| {
            KernelError::Internal("threshold runtime admission omitted operation_id".to_string())
        })?;
        let request_binding_hash = context.admission_request_binding_hash.ok_or_else(|| {
            KernelError::Internal(
                "threshold runtime admission omitted request_binding_hash".to_string(),
            )
        })?;
        self.evaluations
            .lock()
            .map_err(|_| KernelError::Internal("runtime evaluation trace poisoned".to_string()))?
            .push((operation_id.to_string(), request_binding_hash.to_string()));
        let metadata = Some(serde_json::json!({
            "chio_runtime": {
                "evaluation_mode": "pure_pre_persist"
            }
        }));
        if self.allowed {
            Ok(RuntimeAdmissionDecision::allow(metadata))
        } else {
            Ok(RuntimeAdmissionDecision::deny(
                "injected threshold runtime denial",
                metadata,
            ))
        }
    }

    fn release_reserved_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        _metadata: &serde_json::Value,
    ) -> Result<(), KernelError> {
        self.releases
            .lock()
            .map_err(|_| KernelError::Internal("runtime release trace poisoned".to_string()))?
            .push((operation_id.to_string(), request_binding_hash.to_string()));
        Ok(())
    }
}

#[derive(Clone)]
struct OperationAwareThresholdPaymentAdapter {
    calls: std::sync::Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    refunds: std::sync::Arc<std::sync::Mutex<Vec<(String, u64, String)>>>,
    lose_authorize_ack: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lose_capture_ack: std::sync::Arc<std::sync::atomic::AtomicBool>,
    lose_release_ack: std::sync::Arc<std::sync::atomic::AtomicBool>,
    authorization: std::sync::Arc<
        std::sync::Mutex<Option<(String, String, String, PaymentAuthorization)>>,
    >,
    authorization_mutations: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl OperationAwareThresholdPaymentAdapter {
    fn new() -> Self {
        Self {
            calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            refunds: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            lose_authorize_ack: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            lose_capture_ack: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            lose_release_ack: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            authorization: std::sync::Arc::new(std::sync::Mutex::new(None)),
            authorization_mutations: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    fn with_authorize_ack_loss() -> Self {
        let adapter = Self::new();
        adapter
            .lose_authorize_ack
            .store(true, std::sync::atomic::Ordering::SeqCst);
        adapter
    }

    fn with_capture_ack_loss() -> Self {
        let adapter = Self::new();
        adapter
            .lose_capture_ack
            .store(true, std::sync::atomic::Ordering::SeqCst);
        adapter
    }

    fn with_release_ack_loss() -> Self {
        let adapter = Self::new();
        adapter
            .lose_release_ack
            .store(true, std::sync::atomic::Ordering::SeqCst);
        adapter
    }

    fn calls(&self) -> Vec<(String, String, String)> {
        self.calls.lock().expect("payment calls").clone()
    }

    fn refunds(&self) -> Vec<(String, u64, String)> {
        self.refunds.lock().expect("payment refunds").clone()
    }

    fn record(&self, phase: &str, operation_id: &str, request_binding_hash: &str) {
        self.calls.lock().expect("payment calls").push((
            phase.to_string(),
            operation_id.to_string(),
            request_binding_hash.to_string(),
        ));
    }

    fn authorization_mutations(&self) -> u64 {
        self.authorization_mutations
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl PaymentAdapter for OperationAwareThresholdPaymentAdapter {
    fn supports_operation_authorization_recovery(&self) -> bool {
        true
    }

    fn supports_operation_payment_mutations(&self) -> bool {
        true
    }

    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Err(PaymentError::RailError(
            "threshold payment authorization omitted operation ownership".to_string(),
        ))
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "threshold payment capture omitted operation ownership".to_string(),
        ))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "threshold payment release omitted operation ownership".to_string(),
        ))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "threshold payment refund omitted operation ownership".to_string(),
        ))
    }

    fn authorize_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.record("authorize", operation_id, request_binding_hash);
        if request.operation_id.as_deref() != Some(operation_id)
            || request.request_binding_hash.as_deref() != Some(request_binding_hash)
        {
            return Err(PaymentError::RailError(
                "operation-owned payment request binding mismatch".to_string(),
            ));
        }
        let mut stored = self.authorization.lock().map_err(|_| {
            PaymentError::RailError("payment authorization state poisoned".to_string())
        })?;
        if let Some((stored_operation_id, stored_binding_hash, stored_reference, authorization)) =
            stored.as_ref()
        {
            if stored_operation_id != operation_id || stored_binding_hash != request_binding_hash {
                return Err(PaymentError::RailError(
                    "payment operation id reused with a different request binding".to_string(),
                ));
            }
            if stored_reference != &request.reference {
                return Err(PaymentError::RailError(
                    "payment operation retry changed its reference".to_string(),
                ));
            }
            return Ok(authorization.clone());
        }
        let authorization = PaymentAuthorization {
            authorization_id: format!("payment:{operation_id}"),
            settled: false,
            metadata: serde_json::json!({
                "operation_id": operation_id,
                "request_binding_hash": request_binding_hash
            }),
        };
        *stored = Some((
            operation_id.to_string(),
            request_binding_hash.to_string(),
            request.reference.clone(),
            authorization.clone(),
        ));
        self.authorization_mutations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        drop(stored);
        if self
            .lose_authorize_ack
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(PaymentError::Unavailable(
                "injected authorization acknowledgement loss".to_string(),
            ));
        }
        Ok(authorization)
    }

    fn lookup_authorization_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        self.record("lookup_authorization", operation_id, request_binding_hash);
        let stored = self.authorization.lock().map_err(|_| {
            PaymentError::RailError("payment authorization state poisoned".to_string())
        })?;
        match stored.as_ref() {
            Some((stored_operation_id, stored_binding_hash, _, authorization))
                if stored_operation_id == operation_id
                    && stored_binding_hash == request_binding_hash =>
            {
                Ok(Some(authorization.clone()))
            }
            Some(_) => Err(PaymentError::RailError(
                "payment operation id reused with a different request binding".to_string(),
            )),
            None => Ok(None),
        }
    }

    fn capture_for_operation(
        &self,
        request: OperationPaymentCaptureRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        let OperationPaymentCaptureRequest {
            operation_id,
            request_binding_hash,
            ..
        } = request;
        self.record("capture", operation_id, request_binding_hash);
        if self
            .lose_capture_ack
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(PaymentError::Unavailable(
                "injected capture acknowledgement loss".to_string(),
            ));
        }
        Ok(PaymentResult {
            transaction_id: format!("capture:{operation_id}"),
            settlement_status: RailSettlementStatus::Captured,
            metadata: serde_json::json!({}),
        })
    }

    fn release_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.record("release", operation_id, request_binding_hash);
        if self
            .lose_release_ack
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(PaymentError::Unavailable(
                "injected release acknowledgement loss".to_string(),
            ));
        }
        Ok(PaymentResult {
            transaction_id: format!("release:{operation_id}"),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund_for_operation(
        &self,
        request: OperationPaymentRefundRequest<'_>,
    ) -> Result<PaymentResult, PaymentError> {
        let OperationPaymentRefundRequest {
            operation_id,
            request_binding_hash,
            transaction_id,
            amount_units,
            currency,
            reference: _,
        } = request;
        self.record("refund", operation_id, request_binding_hash);
        self.refunds.lock().map_err(|_| {
            PaymentError::RailError("payment refund trace poisoned".to_string())
        })?.push((
            transaction_id.to_string(),
            amount_units,
            currency.to_string(),
        ));
        Ok(PaymentResult {
            transaction_id: format!("refund:{operation_id}"),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }

    fn settlement_state_for_operation(
        &self,
        operation_id: &str,
        request_binding_hash: &str,
        reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<crate::payment::RailSettlementState, PaymentError> {
        let stored = self.authorization.lock().map_err(|_| {
            PaymentError::RailError("payment authorization state poisoned".to_string())
        })?;
        let Some((stored_operation_id, stored_binding_hash, stored_reference, authorization)) =
            stored.as_ref()
        else {
            return Ok(crate::payment::RailSettlementState::NoAuthorization);
        };
        if stored_operation_id != operation_id
            || stored_binding_hash != request_binding_hash
            || stored_reference != reference
            || authorization_id
                .is_some_and(|expected| expected != authorization.authorization_id.as_str())
        {
            return Err(PaymentError::RailError(
                "payment settlement lookup changed its operation binding".to_string(),
            ));
        }
        let calls = self
            .calls
            .lock()
            .map_err(|_| PaymentError::RailError("payment call trace poisoned".to_string()))?;
        let has_phase = |phase: &str| {
            calls.iter().any(|(recorded_phase, recorded_operation, recorded_binding)| {
                recorded_phase == phase
                    && recorded_operation == operation_id
                    && recorded_binding == request_binding_hash
            })
        };
        if has_phase("refund") {
            return Ok(crate::payment::RailSettlementState::Settled {
                authorization_id: authorization.authorization_id.clone(),
                result: PaymentResult {
                    transaction_id: format!("refund:{operation_id}"),
                    settlement_status: RailSettlementStatus::Refunded,
                    metadata: serde_json::json!({}),
                },
            });
        }
        if has_phase("capture") {
            return Ok(crate::payment::RailSettlementState::Settled {
                authorization_id: authorization.authorization_id.clone(),
                result: PaymentResult {
                    transaction_id: format!("capture:{operation_id}"),
                    settlement_status: RailSettlementStatus::Captured,
                    metadata: serde_json::json!({}),
                },
            });
        }
        if has_phase("release") {
            return Ok(crate::payment::RailSettlementState::NoAuthorization);
        }
        Ok(crate::payment::RailSettlementState::Held {
            authorization_id: authorization.authorization_id.clone(),
        })
    }
}

#[derive(Clone, Default)]
struct LegacyThresholdPaymentAdapter {
    authorizations: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl LegacyThresholdPaymentAdapter {
    fn authorizations(&self) -> u64 {
        self.authorizations
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl PaymentAdapter for LegacyThresholdPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorizations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: "legacy-non-idempotent-authorization".to_string(),
            settled: false,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Captured,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }
}

impl RecordingThresholdOperationStore {
    fn new() -> Self {
        Self {
            inner: InMemoryAdmissionOperationStore::new(),
            states: std::sync::Mutex::new(Vec::new()),
            lose_ack_for: std::sync::Mutex::new(None),
            hide_cleanup_actions: std::sync::atomic::AtomicBool::new(false),
            fail_cleanup_creation: std::sync::atomic::AtomicBool::new(false),
            lose_cleanup_create_ack: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn with_ack_loss(state: AdmissionOperationState) -> Self {
        Self {
            inner: InMemoryAdmissionOperationStore::new(),
            states: std::sync::Mutex::new(Vec::new()),
            lose_ack_for: std::sync::Mutex::new(Some(state)),
            hide_cleanup_actions: std::sync::atomic::AtomicBool::new(false),
            fail_cleanup_creation: std::sync::atomic::AtomicBool::new(false),
            lose_cleanup_create_ack: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn states(&self) -> Vec<AdmissionOperationState> {
        self.states.lock().expect("state log").clone()
    }

    fn hide_cleanup_actions(&self) {
        self.hide_cleanup_actions
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn fail_next_cleanup_creation(&self) {
        self.fail_cleanup_creation
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn lose_next_cleanup_create_ack(&self) {
        self.lose_cleanup_create_ack
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn inject_legacy_operation_without_outbox(&self, operation: AdmissionOperation) {
        self.inner
            .inject_legacy_operation_without_outbox_for_test(operation)
            .expect("inject legacy operation");
    }
}

fn assert_signed_receipt_matches_terminal_operation(
    response: &ToolCallResponse,
    operations: &RecordingThresholdOperationStore,
    expected_state: AdmissionOperationState,
) {
    assert!(
        response.receipt.verify_signature().expect("receipt signature"),
        "terminal operation projection must be covered by a valid receipt signature"
    );
    let projection = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.pointer("/protocol_admission/admission_operation"))
        .unwrap_or_else(|| {
            panic!(
                "signed admission operation projection; metadata={:#?}",
                response.receipt.metadata
            )
        });
    let operation_id = projection["operation_id"]
        .as_str()
        .expect("projected operation_id");
    let operation = operations
        .load(operation_id)
        .expect("operation load")
        .expect("persisted operation");
    assert_eq!(
        operation.coordinator_authority_id(),
        format!("kernel:{}", response.receipt.kernel_key.to_hex())
    );
    assert_eq!(operation.state(), expected_state);
    assert_eq!(projection["state"], operation.state().as_str());
    assert_eq!(
        projection["dispatch_state"],
        operation.dispatch_state().as_str()
    );
    assert_eq!(projection["version"].as_u64(), Some(operation.version()));
    assert_eq!(projection["last_error"].as_str(), operation.last_error());
}

fn install_legacy_nonce_reservation_failure(
    kernel: &mut ChioKernel,
    capability: &CapabilityToken,
    intent: &chio_core::capability::governance::GovernedTransactionIntent,
    request: &mut ToolCallRequest,
    now: u64,
    token_id: &str,
) -> (
    std::sync::Arc<RecordingThresholdOperationStore>,
    std::sync::Arc<DurableThresholdApprovalStore>,
    std::sync::Arc<DurableThresholdBudgetStore>,
    std::sync::Arc<AtomicU64>,
) {
    let request_id = request.request_id.clone();
    request.approval_token = Some(legacy_threshold_test_token(
        kernel,
        capability,
        intent,
        &request_id,
        token_id,
        now,
    ));
    let nonce_config = ExecutionNonceConfig {
        require_nonce: true,
        ..ExecutionNonceConfig::default()
    };
    let execution_nonce = mint_nonce_for_request(kernel, capability, request, &nonce_config);
    request.execution_nonce = Some(execution_nonce);
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let approvals = std::sync::Arc::new(DurableThresholdApprovalStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        invocations.clone(),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(approvals.clone())
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .set_execution_nonce_store(nonce_config, Box::new(RejectingThresholdNonceStore))
        .expect("rejecting nonce store");
    (operations, approvals, budget, invocations)
}

fn assert_legacy_nonce_failure_compensation(
    response: &ToolCallResponse,
    capability: &CapabilityToken,
    expected_token: &GovernedApprovalToken,
    operations: &RecordingThresholdOperationStore,
    approvals: &DurableThresholdApprovalStore,
    budget: &DurableThresholdBudgetStore,
    invocations: &AtomicU64,
) {
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("threshold execution nonce reservation failed")
    }));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        operations.states(),
        vec![
            AdmissionOperationState::Prepared,
            AdmissionOperationState::BudgetAuthorized,
            AdmissionOperationState::DelegatedBudgetReserved,
            AdmissionOperationState::PaymentAuthorized,
            AdmissionOperationState::ApprovalReserved,
            AdmissionOperationState::CompensatedBeforeDispatch,
        ]
    );
    assert_signed_receipt_matches_terminal_operation(
        response,
        operations,
        AdmissionOperationState::CompensatedBeforeDispatch,
    );
    let operation_id = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| {
            metadata.pointer("/protocol_admission/admission_operation/operation_id")
        })
        .and_then(serde_json::Value::as_str)
        .expect("signed compensated operation id");
    let operation = operations
        .load(operation_id)
        .expect("operation load")
        .expect("compensated operation");
    assert_eq!(operation.dispatch_state(), AdmissionDispatchState::NotStarted);
    assert_eq!(response.reason.as_deref(), operation.last_error());
    let approval_tombstone = approvals
        .get_approval_reservation(operation_id)
        .expect("approval lookup")
        .expect("cancelled approval tombstone");
    assert_eq!(approval_tombstone.state(), ReplayReservationState::Cancelled);
    assert_eq!(approval_tombstone.approval_set().members().len(), 1);
    assert_eq!(
        approval_tombstone.approval_set().members()[0].token_id(),
        expected_token.id.as_str()
    );
    let expected_token_digest = expected_token
        .token_digest()
        .expect("legacy approval token digest");
    assert_eq!(
        approval_tombstone.approval_set().members()[0].token_digest(),
        expected_token_digest.as_str()
    );
    let usage = budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .expect("compensated budget usage");
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(usage.committed_cost_units().expect("committed cost"), 0);
}

impl AdmissionOperationStore for RecordingThresholdOperationStore {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        AdmissionOperationStoreProfile::SingleNodeDurable
    }

    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        Some(&self.inner)
    }

    fn load_cleanup_actions(
        &self,
        operation_id: &str,
    ) -> Result<Vec<AdmissionCleanupAction>, AdmissionOperationError> {
        if self
            .hide_cleanup_actions
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            Ok(Vec::new())
        } else {
            self.inner.load_cleanup_actions(operation_id)
        }
    }

    fn create_cleanup_action(
        &self,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionCleanupActionCreateOutcome, AdmissionOperationError> {
        if self
            .fail_cleanup_creation
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(AdmissionOperationError::Unavailable(
                "injected cleanup creation failure".to_string(),
            ));
        }
        let outcome = self.inner.create_cleanup_action(action)?;
        if self
            .lose_cleanup_create_ack
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(AdmissionOperationError::Unavailable(
                "injected cleanup creation acknowledgement loss".to_string(),
            ));
        }
        Ok(outcome)
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        let outcome = self.inner.create_prepared(operation)?;
        if matches!(outcome, AdmissionOperationCreateOutcome::Created(_)) {
            self.states
                .lock()
                .map_err(|_| AdmissionOperationError::Unavailable("state log poisoned".into()))?
                .push(AdmissionOperationState::Prepared);
        }
        Ok(outcome)
    }

    fn load(
        &self,
        operation_id: &str,
    ) -> Result<Option<AdmissionOperation>, AdmissionOperationError> {
        self.inner.load(operation_id)
    }

    fn count_unresolved_by_authority(
        &self,
        kind: AdmissionOperationKind,
        coordinator_authority_id: &str,
    ) -> Result<u64, AdmissionOperationError> {
        self.inner
            .count_unresolved_by_authority(kind, coordinator_authority_id)
    }

    fn compare_and_swap(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        let next_state = request.next_state;
        let outcome = self.inner.compare_and_swap(request)?;
        if matches!(outcome, AdmissionOperationCasOutcome::Applied(_)) {
            self.states
                .lock()
                .map_err(|_| AdmissionOperationError::Unavailable("state log poisoned".into()))?
                .push(next_state);
            let mut lose_ack_for = self.lose_ack_for.lock().map_err(|_| {
                AdmissionOperationError::Unavailable("ack-loss lock poisoned".into())
            })?;
            if lose_ack_for.as_ref() == Some(&next_state) {
                *lose_ack_for = None;
                return Err(AdmissionOperationError::Unavailable(
                    "injected transition acknowledgement loss".to_string(),
                ));
            }
        }
        Ok(outcome)
    }

    fn compare_and_swap_with_cleanup_action(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        let next_state = request.next_state;
        let outcome = self
            .inner
            .compare_and_swap_with_cleanup_action(request, action)?;
        if matches!(outcome, AdmissionOperationCasOutcome::Applied(_)) {
            self.states
                .lock()
                .map_err(|_| AdmissionOperationError::Unavailable("state log poisoned".into()))?
                .push(next_state);
            let mut lose_ack_for = self.lose_ack_for.lock().map_err(|_| {
                AdmissionOperationError::Unavailable("ack-loss lock poisoned".into())
            })?;
            if lose_ack_for.as_ref() == Some(&next_state) {
                *lose_ack_for = None;
                return Err(AdmissionOperationError::Unavailable(
                    "injected atomic transition acknowledgement loss".to_string(),
                ));
            }
        }
        Ok(outcome)
    }
}

struct DurableThresholdBudgetStore {
    inner: InMemoryBudgetStore,
    profile: crate::budget_store::BudgetStoreProfile,
    lose_capture_ack: std::sync::atomic::AtomicBool,
    forge_authorize_authority: bool,
    forge_capture_event_id: bool,
    reverse_authorities: std::sync::Mutex<Vec<Option<crate::budget_store::BudgetEventAuthority>>>,
}


struct DurableThresholdNonceStore {
    inner: InMemoryExecutionNonceStore,
    profile: ExecutionNonceStoreProfile,
}

struct RejectingThresholdNonceStore;

impl DurableThresholdNonceStore {
    fn new() -> Self {
        Self {
            inner: InMemoryExecutionNonceStore::default(),
            profile: ExecutionNonceStoreProfile::SingleNodeDurable,
        }
    }

    fn shared() -> Self {
        Self {
            inner: InMemoryExecutionNonceStore::default(),
            profile: ExecutionNonceStoreProfile::SharedLinearizable,
        }
    }
}

impl ExecutionNonceStore for DurableThresholdNonceStore {
    fn authority_profile(&self) -> ExecutionNonceStoreProfile {
        self.profile
    }

    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.inner.reserve(nonce_id)
    }

    fn reserve_until(&self, nonce_id: &str, expires_at: i64) -> Result<bool, KernelError> {
        self.inner.reserve_until(nonce_id, expires_at)
    }

    fn reserve_nonce_for_operation(
        &self,
        operation_id: &str,
        nonce_id: &str,
        signed_expires_at: i64,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.inner
            .reserve_nonce_for_operation(operation_id, nonce_id, signed_expires_at)
    }

    fn commit_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.inner.commit_nonce_reservation(operation_id)
    }

    fn cancel_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        self.inner.cancel_nonce_reservation(operation_id)
    }

    fn get_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<Option<ExecutionNonceReservation>, ExecutionNonceReservationError> {
        self.inner.get_nonce_reservation(operation_id)
    }
}

impl ExecutionNonceStore for RejectingThresholdNonceStore {
    fn authority_profile(&self) -> ExecutionNonceStoreProfile {
        ExecutionNonceStoreProfile::SingleNodeDurable
    }

    fn reserve(&self, _nonce_id: &str) -> Result<bool, KernelError> {
        Err(KernelError::Internal(
            "injected execution nonce reservation failure".to_string(),
        ))
    }

    fn reserve_until(&self, _nonce_id: &str, _expires_at: i64) -> Result<bool, KernelError> {
        Err(KernelError::Internal(
            "injected execution nonce reservation failure".to_string(),
        ))
    }

    fn reserve_nonce_for_operation(
        &self,
        _operation_id: &str,
        _nonce_id: &str,
        _signed_expires_at: i64,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        Err(ExecutionNonceReservationError::Store(
            "injected operation-owned nonce reservation failure".to_string(),
        ))
    }

    fn commit_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        Err(ExecutionNonceReservationError::NotFound(
            operation_id.to_string(),
        ))
    }

    fn cancel_nonce_reservation(
        &self,
        operation_id: &str,
    ) -> Result<ExecutionNonceReservation, ExecutionNonceReservationError> {
        Err(ExecutionNonceReservationError::NotFound(
            operation_id.to_string(),
        ))
    }

    fn get_nonce_reservation(
        &self,
        _operation_id: &str,
    ) -> Result<Option<ExecutionNonceReservation>, ExecutionNonceReservationError> {
        Ok(None)
    }
}

impl DurableThresholdBudgetStore {
    fn new() -> Self {
        Self {
            inner: InMemoryBudgetStore::new(),
            profile: crate::budget_store::BudgetStoreProfile::SingleNodeDurable,
            lose_capture_ack: std::sync::atomic::AtomicBool::new(false),
            forge_authorize_authority: false,
            forge_capture_event_id: false,
            reverse_authorities: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn shared() -> Self {
        Self {
            inner: InMemoryBudgetStore::new(),
            profile: crate::budget_store::BudgetStoreProfile::SharedLinearizable,
            lose_capture_ack: std::sync::atomic::AtomicBool::new(false),
            forge_authorize_authority: false,
            forge_capture_event_id: false,
            reverse_authorities: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn with_capture_ack_loss() -> Self {
        Self {
            inner: InMemoryBudgetStore::new(),
            profile: crate::budget_store::BudgetStoreProfile::SingleNodeDurable,
            lose_capture_ack: std::sync::atomic::AtomicBool::new(true),
            forge_authorize_authority: false,
            forge_capture_event_id: false,
            reverse_authorities: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn with_forged_authorize_authority() -> Self {
        Self {
            forge_authorize_authority: true,
            ..Self::new()
        }
    }

    fn with_invalid_capture_metadata() -> Self {
        Self {
            forge_capture_event_id: true,
            ..Self::new()
        }
    }

    fn reverse_authorities(&self) -> Vec<Option<crate::budget_store::BudgetEventAuthority>> {
        self.reverse_authorities
            .lock()
            .expect("reverse authority trace")
            .clone()
    }

    fn remote_authority() -> crate::budget_store::BudgetEventAuthority {
        crate::budget_store::BudgetEventAuthority {
            authority_id: "remote-linearizable-budget-authority".to_string(),
            lease_id: "remote-linearizable-budget-lease".to_string(),
            lease_epoch: 41,
        }
    }

    fn normalize_commit_metadata(&self, metadata: &mut crate::budget_store::BudgetCommitMetadata) {
        metadata.guarantee_level = self.budget_guarantee_level();
    }
}

impl BudgetStore for DurableThresholdBudgetStore {
    fn authority_profile(&self) -> crate::budget_store::BudgetStoreProfile {
        self.profile
    }

    fn budget_guarantee_level(&self) -> crate::budget_store::BudgetGuaranteeLevel {
        match self.profile {
            crate::budget_store::BudgetStoreProfile::SharedLinearizable => {
                crate::budget_store::BudgetGuaranteeLevel::HaLinearizable
            }
            crate::budget_store::BudgetStoreProfile::EphemeralLocal
            | crate::budget_store::BudgetStoreProfile::SingleNodeDurable => {
                crate::budget_store::BudgetGuaranteeLevel::SingleNodeAtomic
            }
        }
    }

    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<crate::BudgetUsageRecord>, BudgetStoreError> {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<crate::BudgetUsageRecord>, BudgetStoreError> {
        self.inner.get_usage(capability_id, grant_index)
    }

    fn authorize_budget_hold(
        &self,
        mut request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, BudgetStoreError> {
        if self.profile == crate::budget_store::BudgetStoreProfile::SharedLinearizable {
            request.authority = Some(Self::remote_authority());
        }
        let mut decision = self.inner.authorize_budget_hold(request)?;
        match &mut decision {
            crate::budget_store::BudgetAuthorizeHoldDecision::Authorized(authorized) => {
                self.normalize_commit_metadata(&mut authorized.metadata);
                if self.forge_authorize_authority {
                    authorized.metadata.authority =
                        Some(crate::budget_store::BudgetEventAuthority {
                            authority_id: "forged-returned-authority".to_string(),
                            lease_id: "forged-returned-lease".to_string(),
                            lease_epoch: 99,
                        });
                }
            }
            crate::budget_store::BudgetAuthorizeHoldDecision::Denied(denied) => {
                self.normalize_commit_metadata(&mut denied.metadata);
            }
        }
        Ok(decision)
    }

    fn reverse_budget_hold(
        &self,
        request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, BudgetStoreError> {
        self.reverse_authorities
            .lock()
            .map_err(|_| BudgetStoreError::Invariant("reverse authority trace poisoned".into()))?
            .push(request.authority.clone());
        let mut decision = self.inner.reverse_budget_hold(request)?;
        self.normalize_commit_metadata(&mut decision.metadata);
        Ok(decision)
    }

    fn release_budget_hold(
        &self,
        request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReleaseHoldDecision, BudgetStoreError> {
        self.inner.release_budget_hold(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: crate::budget_store::BudgetReconcileHoldRequest,
    ) -> Result<crate::budget_store::BudgetReconcileHoldDecision, BudgetStoreError> {
        self.inner.reconcile_budget_hold(request)
    }

    fn capture_budget_hold(
        &self,
        request: crate::budget_store::BudgetCaptureHoldRequest,
    ) -> Result<crate::budget_store::BudgetCaptureHoldDecision, BudgetStoreError> {
        self.inner.capture_budget_hold(request)
    }

    fn mark_admission_operation_hold_reserved(
        &self,
        hold_id: &str,
        admission_operation: &crate::budget_store::BudgetAdmissionOperationBinding,
        reserved_until_unix_secs: i64,
        currency: Option<&str>,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.inner.mark_admission_operation_hold_reserved(
            hold_id,
            admission_operation,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<crate::budget_store::BudgetHoldMutationDecision, BudgetStoreError> {
        let mut decision = self.inner.capture_invocation_reservations(request)?;
        self.normalize_commit_metadata(&mut decision.metadata);
        if self.forge_capture_event_id {
            decision.metadata.event_id = Some("forged-capture-event".to_string());
        }
        if self
            .lose_capture_ack
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(BudgetStoreError::Invariant(
                "injected capture acknowledgement loss".to_string(),
            ));
        }
        Ok(decision)
    }
}

fn prepared_threshold_coordinator_admission(
    request_id: &str,
    capability_id: &str,
    binding_byte: &str,
    set_byte: &str,
    members: &[(&str, &str)],
) -> crate::threshold_approval::PreparedGovernedToolAdmission {
    prepared_threshold_coordinator_admission_for_authority(
        "kernel:test",
        request_id,
        capability_id,
        binding_byte,
        set_byte,
        members,
    )
}

fn prepared_threshold_coordinator_admission_for_authority(
    coordinator_authority_id: &str,
    request_id: &str,
    capability_id: &str,
    binding_byte: &str,
    set_byte: &str,
    members: &[(&str, &str)],
) -> crate::threshold_approval::PreparedGovernedToolAdmission {
    let approval_set_hash = set_byte.repeat(32);
    let approval_set = ApprovalSetReservationInput::new(
        approval_set_hash.clone(),
        members
            .iter()
            .map(|(id, digest)| {
                ApprovalReservationMember::new((*id).to_string(), digest.repeat(32))
                    .expect("approval member")
            })
            .collect(),
        current_unix_timestamp().saturating_add(300),
    )
    .expect("approval set");
    let operation = AdmissionOperation::prepared(PreparedAdmissionOperation {
        kind: AdmissionOperationKind::ToolDispatch,
        coordinator_authority_id: coordinator_authority_id.to_string(),
        request_id: request_id.to_string(),
        capability_id: capability_id.to_string(),
        authorization_capability_hash: "11".repeat(32),
        request_binding_hash: binding_byte.repeat(32),
        policy_hash: "33".repeat(32),
        broker_attempt_id: None,
        budget_hold_id: Some(format!("budget-hold:{request_id}:{capability_id}:0")),
        approval_set_hash: Some(approval_set_hash),
        execution_nonce_id: None,
        coordinator_lease_epoch: 1,
    })
    .expect("prepared operation");
    crate::threshold_approval::PreparedGovernedToolAdmission::from_parts(operation, approval_set)
        .expect("prepared threshold admission")
}

struct ThresholdArtifactAuthority {
    policy_authority: Keypair,
    approvers: [Keypair; 2],
    requirement: crate::threshold_approval::ThresholdApprovalRequirement,
}

impl ThresholdArtifactAuthority {
    fn install(kernel: &mut ChioKernel) -> Self {
        let policy_authority = Keypair::generate();
        let approvers = [Keypair::generate(), Keypair::generate()];
        let requirement = crate::threshold_approval::ThresholdApprovalRequirement::new(
            2,
            std::collections::BTreeMap::from([
                ("approver-a".to_string(), approvers[0].public_key()),
                ("approver-b".to_string(), approvers[1].public_key()),
            ]),
            900,
            kernel.config.policy_hash.clone(),
            1,
        )
        .expect("threshold requirement");
        let resolved_requirement = requirement.clone();
        kernel
            .set_threshold_approval_requirement_resolver(std::sync::Arc::new(
                move |_: &crate::threshold_approval::ThresholdApprovalRequest, _: &str| {
                    Ok(resolved_requirement.clone())
                },
            ))
            .expect("threshold resolver");
        kernel
            .set_threshold_approval_policy_authority(policy_authority.public_key())
            .expect("threshold policy authority");
        Self {
            policy_authority,
            approvers,
            requirement,
        }
    }

    fn authorize_request(
        &self,
        capability: &CapabilityToken,
        intent: &chio_core::capability::governance::GovernedTransactionIntent,
        request: &mut ToolCallRequest,
        now: u64,
    ) {
        let intent_hash = intent.binding_hash().expect("intent hash");
        let capability_hash = crate::threshold_approval::authorization_capability_hash(capability)
            .expect("capability hash");
        let proposal_created_at = now.saturating_sub(10);
        let proposal_body = crate::threshold_approval::ThresholdApprovalProposalBody::new(
            format!("proposal-{}", request.request_id),
            request.request_id.clone(),
            intent_hash.clone(),
            capability.subject.clone(),
            capability_hash,
            self.requirement.policy_hash().to_string(),
            self.requirement.required(),
            self.requirement.eligible_set_digest(),
            proposal_created_at,
            self.requirement.proposal_timeout_seconds(),
            capability.expires_at,
            capability.expires_at,
        )
        .expect("proposal body");
        let proposal = crate::threshold_approval::ThresholdApprovalProposal::sign(
            proposal_body,
            &self.policy_authority,
        )
        .expect("proposal");
        let proposal_hash = proposal.proposal_hash().expect("proposal hash");
        let deadline = proposal.body().proposal_deadline();
        request.threshold_approval_proposal = Some(proposal);
        request.approval_tokens = self
            .approvers
            .iter()
            .enumerate()
            .map(|(index, approver)| {
                GovernedApprovalToken::sign(
                    GovernedApprovalTokenBody {
                        id: format!("approval-{}-{index}", request.request_id),
                        approver: approver.public_key(),
                        subject: capability.subject.clone(),
                        governed_intent_hash: intent_hash.clone(),
                        threshold_proposal_hash: Some(proposal_hash.clone()),
                        request_id: request.request_id.clone(),
                        issued_at: now.saturating_sub(1),
                        expires_at: deadline,
                        decision: GovernedApprovalDecision::Approved,
                    },
                    approver,
                )
                .expect("approval token")
            })
            .collect();
    }
}

fn install_valid_threshold_artifacts(
    kernel: &mut ChioKernel,
    capability: &CapabilityToken,
    intent: &chio_core::capability::governance::GovernedTransactionIntent,
    request: &mut ToolCallRequest,
    now: u64,
) {
    ThresholdArtifactAuthority::install(kernel).authorize_request(capability, intent, request, now);
}

fn aggregate_limited_capability(
    kernel: &ChioKernel,
    capability: &CapabilityToken,
    max_invocations: u32,
) -> CapabilityToken {
    let mut body = capability.body();
    body.aggregate_invocation_budget = Some(
        chio_core::capability::aggregate_budget::AggregateInvocationBudget {
            scope: chio_core::capability::aggregate_budget::AggregateInvocationScope::Capability,
            max_invocations,
            root_binding: None,
        },
    );
    CapabilityToken::sign(body, &kernel.config.keypair).expect("sign aggregate-limited capability")
}

fn assert_budget_exhausted_or_denied(result: Result<ToolCallResponse, KernelError>, label: &str) {
    match result {
        Err(KernelError::BudgetExhausted(_)) => {}
        Ok(response) => assert_eq!(
            response.verdict,
            Verdict::Deny,
            "{label} unexpectedly dispatched: {:?}",
            response.reason
        ),
        Err(error) => panic!("{label} failed for an unexpected reason: {error}"),
    }
}
