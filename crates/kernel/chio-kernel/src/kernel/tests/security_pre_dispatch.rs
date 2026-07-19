struct SecurityPreDispatchCapture {
    calls: std::sync::Arc<AtomicU64>,
    canonical_requests: std::sync::Arc<Mutex<Vec<Vec<u8>>>>,
    contexts: std::sync::Arc<Mutex<Vec<SecurityInvocationContext>>>,
    commitment_ids: std::sync::Arc<Mutex<Vec<String>>>,
    rejection: Option<&'static str>,
}

impl SecurityPreDispatchHook for SecurityPreDispatchCapture {
    fn name(&self) -> &str {
        "security-pre-dispatch-capture"
    }

    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.canonical_requests
            .lock()
            .unwrap()
            .push(context.canonical_request.to_vec());
        self.contexts
            .lock()
            .unwrap()
            .push(context.security_context.clone());
        self.commitment_ids
            .lock()
            .unwrap()
            .push(context.dispatch_commitment_id.as_str().to_string());
        match self.rejection {
            Some(reason) => Err(KernelError::Internal(reason.to_string())),
            None => Ok(None),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecordedSecurityDispatchOutcome {
    request_id: String,
    dispatch_commitment_id: String,
    outcome: SecurityDispatchOutcome,
}

struct RecordingSecurityDispatchOutcome {
    request_id: String,
    dispatch_commitment_id: String,
    outcomes: std::sync::Arc<Mutex<Vec<RecordedSecurityDispatchOutcome>>>,
}

impl SecurityDispatchOutcomeRecorder for RecordingSecurityDispatchOutcome {
    fn record(&mut self, outcome: SecurityDispatchOutcome) -> Result<(), KernelError> {
        self.outcomes
            .lock()
            .unwrap()
            .push(RecordedSecurityDispatchOutcome {
                request_id: self.request_id.clone(),
                dispatch_commitment_id: self.dispatch_commitment_id.clone(),
                outcome,
            });
        Ok(())
    }
}

struct SecurityDispatchOutcomeHook {
    outcomes: std::sync::Arc<Mutex<Vec<RecordedSecurityDispatchOutcome>>>,
}

impl SecurityPreDispatchHook for SecurityDispatchOutcomeHook {
    fn name(&self) -> &str {
        "security-dispatch-outcome-hook"
    }

    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(Some(SecurityDispatchOutcomeHandle::new(
            context,
            Box::new(RecordingSecurityDispatchOutcome {
                request_id: context.request.request_id.clone(),
                dispatch_commitment_id: context.dispatch_commitment_id.as_str().to_string(),
                outcomes: std::sync::Arc::clone(&self.outcomes),
            }),
        )))
    }
}

struct FailingSecurityDispatchOutcomeRecorder {
    attempts: std::sync::Arc<AtomicU64>,
}

impl SecurityDispatchOutcomeRecorder for FailingSecurityDispatchOutcomeRecorder {
    fn record(&mut self, _outcome: SecurityDispatchOutcome) -> Result<(), KernelError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(
            "injected authoritative security outcome persistence failure".to_string(),
        ))
    }
}

struct FailingSecurityDispatchOutcomeHook {
    attempts: std::sync::Arc<AtomicU64>,
}

impl SecurityPreDispatchHook for FailingSecurityDispatchOutcomeHook {
    fn name(&self) -> &str {
        "failing-security-dispatch-outcome-hook"
    }

    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(Some(SecurityDispatchOutcomeHandle::new(
            context,
            Box::new(FailingSecurityDispatchOutcomeRecorder {
                attempts: std::sync::Arc::clone(&self.attempts),
            }),
        )))
    }
}

struct RejectingOutcomeUnknownOperationStore {
    inner: RecordingThresholdOperationStore,
}

impl RejectingOutcomeUnknownOperationStore {
    fn new() -> Self {
        Self {
            inner: RecordingThresholdOperationStore::new(),
        }
    }

    fn states(&self) -> Vec<AdmissionOperationState> {
        self.inner.states()
    }
}

impl AdmissionOperationStore for RejectingOutcomeUnknownOperationStore {
    fn authority_profile(&self) -> AdmissionOperationStoreProfile {
        self.inner.authority_profile()
    }

    fn cleanup_journal_delegate(&self) -> Option<&dyn AdmissionOperationStore> {
        Some(&self.inner)
    }

    fn create_prepared(
        &self,
        operation: AdmissionOperation,
    ) -> Result<AdmissionOperationCreateOutcome, AdmissionOperationError> {
        self.inner.create_prepared(operation)
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
        if request.next_state == AdmissionOperationState::OutcomeUnknownAfterDispatch {
            return Err(AdmissionOperationError::Unavailable(
                "injected outcome-unknown persistence failure".to_string(),
            ));
        }
        self.inner.compare_and_swap(request)
    }

    fn compare_and_swap_with_cleanup_action(
        &self,
        request: AdmissionOperationCompareAndSwap<'_>,
        action: AdmissionCleanupAction,
    ) -> Result<AdmissionOperationCasOutcome, AdmissionOperationError> {
        if request.next_state == AdmissionOperationState::OutcomeUnknownAfterDispatch {
            return Err(AdmissionOperationError::Unavailable(
                "injected outcome-unknown persistence failure".to_string(),
            ));
        }
        self.inner
            .compare_and_swap_with_cleanup_action(request, action)
    }
}

struct RecordingRequestLifecyclePermit {
    ready: std::sync::Arc<AtomicBool>,
    final_releases: std::sync::Arc<AtomicU64>,
    abandoned: std::sync::Arc<AtomicU64>,
    completed: bool,
}

impl SecurityRequestLifecyclePermit for RecordingRequestLifecyclePermit {
    fn ensure_final_release(mut self: Box<Self>) -> Result<(), KernelError> {
        self.completed = true;
        self.final_releases.fetch_add(1, Ordering::SeqCst);
        if self.ready.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(KernelError::GuardDenied(
                "request lifecycle closed before final release".to_string(),
            ))
        }
    }
}

impl Drop for RecordingRequestLifecyclePermit {
    fn drop(&mut self) {
        if !self.completed {
            self.abandoned.fetch_add(1, Ordering::SeqCst);
        }
    }
}

struct LifecycleSecurityDispatchHook {
    outcomes: std::sync::Arc<Mutex<Vec<RecordedSecurityDispatchOutcome>>>,
    ready: std::sync::Arc<AtomicBool>,
    acquisitions: std::sync::Arc<AtomicU64>,
    final_releases: std::sync::Arc<AtomicU64>,
    abandoned: std::sync::Arc<AtomicU64>,
}

impl SecurityPreDispatchHook for LifecycleSecurityDispatchHook {
    fn name(&self) -> &str {
        "security-request-lifecycle-hook"
    }

    fn acquire_request_lifecycle(
        &self,
        _context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<Box<dyn SecurityRequestLifecyclePermit>>, KernelError> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        Ok(Some(Box::new(RecordingRequestLifecyclePermit {
            ready: std::sync::Arc::clone(&self.ready),
            final_releases: std::sync::Arc::clone(&self.final_releases),
            abandoned: std::sync::Arc::clone(&self.abandoned),
            completed: false,
        })))
    }

    fn commit(
        &self,
        context: &SecurityPreDispatchContext<'_>,
    ) -> Result<Option<SecurityDispatchOutcomeHandle>, KernelError> {
        Ok(Some(SecurityDispatchOutcomeHandle::new(
            context,
            Box::new(RecordingSecurityDispatchOutcome {
                request_id: context.request.request_id.clone(),
                dispatch_commitment_id: context.dispatch_commitment_id.as_str().to_string(),
                outcomes: std::sync::Arc::clone(&self.outcomes),
            }),
        )))
    }
}

struct CloseRequestLifecyclePostHook {
    ready: std::sync::Arc<AtomicBool>,
}

impl crate::post_invocation::PostInvocationHook for CloseRequestLifecyclePostHook {
    fn name(&self) -> &str {
        "close-request-lifecycle"
    }

    fn inspect(
        &self,
        _context: &crate::post_invocation::PostInvocationContext<'_>,
        _response: &serde_json::Value,
    ) -> crate::post_invocation::PostInvocationVerdict {
        self.ready.store(false, Ordering::SeqCst);
        crate::post_invocation::PostInvocationVerdict::Allow
    }
}

struct FailingSecurityDispatchServer;

#[async_trait::async_trait]
impl ToolServerConnection for FailingSecurityDispatchServer {
    fn server_id(&self) -> &str {
        "security-dispatch-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["security-dispatch-tool".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "injected security dispatch connector failure".to_string(),
        ))
    }
}

struct PendingSecurityDispatchServer {
    entered: std::sync::Arc<tokio::sync::Notify>,
}

struct IncompleteSecurityDispatchServer;

struct CancelledSecurityDispatchServer;

#[async_trait::async_trait]
impl ToolServerConnection for CancelledSecurityDispatchServer {
    fn server_id(&self) -> &str {
        "security-dispatch-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["security-dispatch-tool".to_string()]
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        Err(KernelError::RequestCancelled {
            request_id: "security-outcome-ordinary-cancelled".to_string().into(),
            reason: "cancelled after connector entry without delivery acknowledgement".to_string(),
        })
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "cancelled security dispatch unexpectedly used non-streaming invoke".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for IncompleteSecurityDispatchServer {
    fn server_id(&self) -> &str {
        "security-dispatch-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["security-dispatch-tool".to_string()]
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        Ok(Some(ToolServerStreamResult::Incomplete {
            stream: ToolCallStream { chunks: Vec::new() },
            reason: "connector stream ended without a terminal delivery acknowledgement"
                .to_string(),
        }))
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal(
            "incomplete security dispatch unexpectedly used non-streaming invoke".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for PendingSecurityDispatchServer {
    fn server_id(&self) -> &str {
        "security-dispatch-server"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["security-dispatch-tool".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.entered.notify_one();
        std::future::pending::<Result<serde_json::Value, KernelError>>().await
    }
}

fn install_security_dispatch_outcome_hook(
    kernel: &mut ChioKernel,
) -> std::sync::Arc<Mutex<Vec<RecordedSecurityDispatchOutcome>>> {
    let outcomes = std::sync::Arc::new(Mutex::new(Vec::new()));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(std::sync::Arc::new(SecurityDispatchOutcomeHook {
        outcomes: std::sync::Arc::clone(&outcomes),
    }));
    outcomes
}

fn install_failing_security_dispatch_outcome_hook(
    kernel: &mut ChioKernel,
) -> std::sync::Arc<AtomicU64> {
    let attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(std::sync::Arc::new(
        FailingSecurityDispatchOutcomeHook {
            attempts: std::sync::Arc::clone(&attempts),
        },
    ));
    attempts
}

fn assert_single_security_dispatch_outcome(
    outcomes: &std::sync::Arc<Mutex<Vec<RecordedSecurityDispatchOutcome>>>,
    request_id: &str,
    expected: SecurityDispatchOutcome,
) {
    let outcomes = outcomes.lock().unwrap();
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].request_id, request_id);
    assert!(outcomes[0]
        .dispatch_commitment_id
        .starts_with("dispatch-commitment:"));
    assert_eq!(outcomes[0].outcome, expected);
}

fn security_dispatch_nested_context(
    kernel: &mut ChioKernel,
    request: &ToolCallRequest,
) -> (SessionId, OperationContext) {
    let agent_id = request.agent_id.clone();
    let session_id = kernel
        .open_session(agent_id.clone(), vec![request.capability.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let parent_context = make_operation_context(&session_id, &request.request_id, &agent_id);
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    (session_id, parent_context)
}

fn security_dispatch_capture_failure_fixture(
    request_id: &str,
) -> (ChioKernel, ToolCallRequest, std::sync::Arc<AtomicUsize>) {
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_budget_store_handle(std::sync::Arc::new(FailingReleaseBudgetStore::new()))
        .unwrap();
    let invocations = std::sync::Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    let agent = make_keypair();
    let capability = kernel
        .issue_capability(
            &agent.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1_000, "USD",
            )]),
            300,
        )
        .unwrap();
    let request = make_request(request_id, &capability, "compute", "cost-srv");
    (kernel, request, invocations)
}

struct SecurityPreDispatchLateGuard {
    hook_calls: std::sync::Arc<AtomicU64>,
    guard_calls: std::sync::Arc<AtomicU64>,
    deny: bool,
}

impl Guard for SecurityPreDispatchLateGuard {
    fn name(&self) -> &str {
        "security-pre-dispatch-late-guard"
    }

    fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        assert_eq!(
            self.hook_calls.load(Ordering::SeqCst),
            0,
            "the pre-dispatch hook must run after the last guard"
        );
        self.guard_calls.fetch_add(1, Ordering::SeqCst);
        Ok(if self.deny {
            GuardDecision::deny(Vec::new())
        } else {
            GuardDecision::allow()
        })
    }
}

fn security_pre_dispatch_context_for(
    request: &ToolCallRequest,
    session_id: &str,
    context_generation: u64,
) -> SecurityInvocationContext {
    let lineage_root_id = request
        .capability
        .delegation_chain
        .first()
        .map_or(request.capability.id.as_str(), |link| {
            link.capability_id.as_str()
        });
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        chio_security_types::ports::TenantId::new("tenant-security-dispatch").unwrap(),
        chio_security_types::ports::SessionId::new(session_id).unwrap(),
        chio_security_types::PrincipalId::new(request.agent_id.clone()).unwrap(),
        chio_security_types::ports::IsolationEpochId::new("epoch-security-dispatch").unwrap(),
        chio_security_types::ports::LineageId::new(lineage_root_id).unwrap(),
        context_generation,
    ))
}

fn unbound_security_pre_dispatch_context_for(
    session_id: &str,
    context_generation: u64,
) -> SecurityInvocationContext {
    SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        chio_security_types::ports::TenantId::new("tenant-security-dispatch").unwrap(),
        chio_security_types::ports::SessionId::new(session_id).unwrap(),
        chio_security_types::PrincipalId::new("principal-security-dispatch").unwrap(),
        chio_security_types::ports::IsolationEpochId::new("epoch-security-dispatch").unwrap(),
        chio_security_types::ports::LineageId::new("lineage-security-dispatch").unwrap(),
        context_generation,
    ))
}

fn security_pre_dispatch_fixture(
    request_id: &str,
) -> (ChioKernel, ToolCallRequest, std::sync::Arc<AtomicU64>) {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "security-dispatch-server",
        vec!["security-dispatch-tool"],
        std::sync::Arc::clone(&invocations),
    )));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant(
            "security-dispatch-server",
            "security-dispatch-tool",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        request_id,
        &capability,
        "security-dispatch-tool",
        "security-dispatch-server",
        serde_json::json!({"alpha": 1, "nested": {"zeta": true}}),
    );
    (kernel, request, invocations)
}

#[test]
fn contextual_capability_issuance_denies_without_admission_authority() {
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let context = unbound_security_pre_dispatch_context_for("contextual-issuance-no-authority", 1);
    let error = kernel
        .issue_capability_with_security_context(
            &agent.public_key(),
            make_scope(vec![make_grant(
                "security-dispatch-server",
                "security-dispatch-tool",
            )]),
            300,
            &context,
        )
        .expect_err("governed contextual issuance requires an admission authority");

    assert!(matches!(
        error,
        KernelError::CapabilityIssuanceDenied(reason)
            if reason == "capability issuance admission authority is unavailable"
    ));
}

struct SecurityPreDispatchHarness {
    hook: std::sync::Arc<SecurityPreDispatchCapture>,
    canonical_requests: std::sync::Arc<Mutex<Vec<Vec<u8>>>>,
    contexts: std::sync::Arc<Mutex<Vec<SecurityInvocationContext>>>,
    commitment_ids: std::sync::Arc<Mutex<Vec<String>>>,
}

fn security_pre_dispatch_capture(
    calls: std::sync::Arc<AtomicU64>,
    rejection: Option<&'static str>,
) -> SecurityPreDispatchHarness {
    let canonical_requests = std::sync::Arc::new(Mutex::new(Vec::new()));
    let contexts = std::sync::Arc::new(Mutex::new(Vec::new()));
    let commitment_ids = std::sync::Arc::new(Mutex::new(Vec::new()));
    SecurityPreDispatchHarness {
        hook: std::sync::Arc::new(SecurityPreDispatchCapture {
            calls,
            canonical_requests: std::sync::Arc::clone(&canonical_requests),
            contexts: std::sync::Arc::clone(&contexts),
            commitment_ids: std::sync::Arc::clone(&commitment_ids),
            rejection,
        }),
        canonical_requests,
        contexts,
        commitment_ids,
    }
}

#[test]
fn standalone_security_pre_dispatch_enforcement_runs_without_issuance_authority() {
    let (mut kernel, request, invocations) =
        security_pre_dispatch_fixture("security-dispatch-normal");
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    let late_guard_calls = std::sync::Arc::new(AtomicU64::new(0));
    let capture = security_pre_dispatch_capture(std::sync::Arc::clone(&calls), None);
    kernel.add_guard(Box::new(SecurityPreDispatchLateGuard {
        hook_calls: std::sync::Arc::clone(&calls),
        guard_calls: std::sync::Arc::clone(&late_guard_calls),
        deny: false,
    }));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let hook: std::sync::Arc<dyn SecurityPreDispatchHook> = capture.hook.clone();
    kernel.set_security_pre_dispatch_hook(hook);
    let security_context =
        security_pre_dispatch_context_for(&request, "session-security-normal", 11);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(late_guard_calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        capture.canonical_requests.lock().unwrap().as_slice(),
        &[canonical_json_bytes(&request).unwrap()]
    );
    assert_eq!(
        capture.contexts.lock().unwrap().as_slice(),
        std::slice::from_ref(&security_context)
    );
    let ids = capture.commitment_ids.lock().unwrap();
    assert_eq!(ids.len(), 1);
    assert!(ids[0].starts_with("dispatch-commitment:"));
}

#[test]
fn direct_security_context_binding_rejects_principal_and_lineage_mismatches() {
    let (kernel, request, invocations) =
        security_pre_dispatch_fixture("security-context-direct-binding");
    let valid = security_pre_dispatch_context_for(&request, "direct-binding-session", 1);
    let valid_v1 = valid.as_v1();
    let principal_mismatch = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        valid_v1.tenant_id().clone(),
        valid_v1.session_id().clone(),
        chio_security_types::PrincipalId::new("different-principal").unwrap(),
        valid_v1.isolation_epoch_id().clone(),
        valid_v1.lineage_root_id().clone(),
        valid_v1.context_generation(),
    ));
    let principal_error = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &principal_mismatch)
        .unwrap_err();
    assert!(matches!(
        principal_error,
        KernelError::GuardDenied(reason)
            if reason == "authoritative security context principal does not match the request agent"
    ));

    let lineage_mismatch = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        valid_v1.tenant_id().clone(),
        valid_v1.session_id().clone(),
        valid_v1.principal_id().clone(),
        valid_v1.isolation_epoch_id().clone(),
        chio_security_types::ports::LineageId::new("different-lineage").unwrap(),
        valid_v1.context_generation(),
    ));
    let lineage_error = kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &lineage_mismatch)
        .unwrap_err();
    assert!(matches!(
        lineage_error,
        KernelError::GuardDenied(reason)
            if reason == "authoritative security context lineage root does not match the request capability"
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn nested_security_context_binding_rejects_lineage_before_session_tracking() {
    let (kernel, request, invocations) =
        security_pre_dispatch_fixture("security-context-nested-binding");
    let session_id = kernel
        .open_session(request.agent_id.clone(), vec![request.capability.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let parent_context =
        make_operation_context(&session_id, &request.request_id, &request.agent_id);
    let valid = security_pre_dispatch_context_for(&request, session_id.as_str(), 2);
    let valid_v1 = valid.as_v1();
    let lineage_mismatch = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        valid_v1.tenant_id().clone(),
        valid_v1.session_id().clone(),
        valid_v1.principal_id().clone(),
        valid_v1.isolation_epoch_id().clone(),
        chio_security_types::ports::LineageId::new("different-nested-lineage").unwrap(),
        valid_v1.context_generation(),
    ));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let error = runtime
        .block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                    &parent_context,
                    &request,
                    &mut client,
                    None,
                    &lineage_mismatch,
                )
                .await
        })
        .unwrap_err();
    assert!(matches!(
        error,
        KernelError::GuardDenied(reason)
            if reason == "authoritative security context lineage root does not match the request capability"
    ));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
}

#[test]
fn security_pre_dispatch_late_guard_denial_never_calls_hook_or_server() {
    let (mut kernel, request, invocations) =
        security_pre_dispatch_fixture("security-dispatch-late-deny");
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    let late_guard_calls = std::sync::Arc::new(AtomicU64::new(0));
    let capture = security_pre_dispatch_capture(std::sync::Arc::clone(&calls), None);
    kernel.add_guard(Box::new(SecurityPreDispatchLateGuard {
        hook_calls: std::sync::Arc::clone(&calls),
        guard_calls: std::sync::Arc::clone(&late_guard_calls),
        deny: true,
    }));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(capture.hook);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_pre_dispatch_context_for(&request, "session-security-late-deny", 12),
        )
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(late_guard_calls.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn security_pre_dispatch_enforce_requires_context_and_hook() {
    let (mut missing_hook_kernel, missing_hook_request, missing_hook_invocations) =
        security_pre_dispatch_fixture("security-dispatch-missing-hook");
    missing_hook_kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    let missing_hook_response = missing_hook_kernel
        .evaluate_tool_call_blocking_with_security_context(
            &missing_hook_request,
            &security_pre_dispatch_context_for(
                &missing_hook_request,
                "session-security-missing-hook",
                13,
            ),
        )
        .unwrap();
    assert_eq!(missing_hook_response.verdict, Verdict::Deny);
    assert_eq!(missing_hook_invocations.load(Ordering::SeqCst), 0);
    assert!(missing_hook_response
        .receipt
        .evidence
        .iter()
        .any(|evidence| {
            evidence.guard_name == "chio-security-pre-dispatch" && !evidence.verdict
        }));

    let (mut missing_context_kernel, missing_context_request, missing_context_invocations) =
        security_pre_dispatch_fixture("security-dispatch-missing-context");
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    let capture = security_pre_dispatch_capture(std::sync::Arc::clone(&calls), None);
    missing_context_kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    missing_context_kernel.set_security_pre_dispatch_hook(capture.hook);
    let missing_context_response = missing_context_kernel
        .evaluate_tool_call_blocking(&missing_context_request)
        .unwrap();
    assert_eq!(missing_context_response.verdict, Verdict::Deny);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(missing_context_invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn security_pre_dispatch_rejection_is_generic_signed_denial() {
    let (mut kernel, request, invocations) =
        security_pre_dispatch_fixture("security-dispatch-rejected");
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    let secret_internal_reason = "secret flow database endpoint and record id";
    let capture =
        security_pre_dispatch_capture(std::sync::Arc::clone(&calls), Some(secret_internal_reason));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(capture.hook);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_pre_dispatch_context_for(&request, "session-security-rejected", 14),
        )
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert!(!response
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains(secret_internal_reason));
    let evidence = response
        .receipt
        .evidence
        .iter()
        .find(|evidence| evidence.guard_name == "chio-security-pre-dispatch")
        .unwrap();
    assert!(!evidence
        .details
        .as_deref()
        .unwrap_or_default()
        .contains(secret_internal_reason));
}

#[test]
fn security_dispatch_commitment_binds_canonical_request_and_every_context_field() {
    let (_, mut request, _) = security_pre_dispatch_fixture("security-dispatch-binding");
    let base = security_pre_dispatch_context_for(&request, "session-security-binding", 15);
    let canonical = canonical_json_bytes(&request).unwrap();
    let first = super::dispatch::derive_security_dispatch_commitment_id(&canonical, &base).unwrap();
    let repeated =
        super::dispatch::derive_security_dispatch_commitment_id(&canonical, &base).unwrap();
    assert_eq!(first, repeated);

    let contexts = [
        SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("tenant-other").unwrap(),
            chio_security_types::ports::SessionId::new("session-security-binding").unwrap(),
            chio_security_types::PrincipalId::new("principal-security-dispatch").unwrap(),
            chio_security_types::ports::IsolationEpochId::new("epoch-security-dispatch").unwrap(),
            chio_security_types::ports::LineageId::new("lineage-security-dispatch").unwrap(),
            15,
        )),
        SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("tenant-security-dispatch").unwrap(),
            chio_security_types::ports::SessionId::new("session-other").unwrap(),
            chio_security_types::PrincipalId::new("principal-security-dispatch").unwrap(),
            chio_security_types::ports::IsolationEpochId::new("epoch-security-dispatch").unwrap(),
            chio_security_types::ports::LineageId::new("lineage-security-dispatch").unwrap(),
            15,
        )),
        SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("tenant-security-dispatch").unwrap(),
            chio_security_types::ports::SessionId::new("session-security-binding").unwrap(),
            chio_security_types::PrincipalId::new("principal-other").unwrap(),
            chio_security_types::ports::IsolationEpochId::new("epoch-security-dispatch").unwrap(),
            chio_security_types::ports::LineageId::new("lineage-security-dispatch").unwrap(),
            15,
        )),
        SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("tenant-security-dispatch").unwrap(),
            chio_security_types::ports::SessionId::new("session-security-binding").unwrap(),
            chio_security_types::PrincipalId::new("principal-security-dispatch").unwrap(),
            chio_security_types::ports::IsolationEpochId::new("epoch-other").unwrap(),
            chio_security_types::ports::LineageId::new("lineage-security-dispatch").unwrap(),
            15,
        )),
        SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
            chio_security_types::ports::TenantId::new("tenant-security-dispatch").unwrap(),
            chio_security_types::ports::SessionId::new("session-security-binding").unwrap(),
            chio_security_types::PrincipalId::new("principal-security-dispatch").unwrap(),
            chio_security_types::ports::IsolationEpochId::new("epoch-security-dispatch").unwrap(),
            chio_security_types::ports::LineageId::new("lineage-other").unwrap(),
            15,
        )),
        security_pre_dispatch_context_for(&request, "session-security-binding", 16),
        SecurityInvocationContext::v1(
            security_pre_dispatch_context_for(&request, "session-security-binding", 15)
                .as_v1()
                .clone()
                .with_flow_state_generation(2),
        ),
    ];
    for changed in contexts {
        assert_ne!(
            first,
            super::dispatch::derive_security_dispatch_commitment_id(&canonical, &changed).unwrap()
        );
    }

    request.arguments = serde_json::json!({"alpha": 2, "nested": {"zeta": true}});
    let changed_request = canonical_json_bytes(&request).unwrap();
    assert_ne!(
        first,
        super::dispatch::derive_security_dispatch_commitment_id(&changed_request, &base).unwrap()
    );
}

#[test]
fn security_pre_dispatch_runs_once_on_context_aware_nested_dispatch() {
    let (mut kernel, request, invocations) =
        security_pre_dispatch_fixture("security-dispatch-nested");
    let agent_id = request.agent_id.clone();
    let session_id = kernel
        .open_session(agent_id.clone(), vec![request.capability.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let parent_context = make_operation_context(&session_id, &request.request_id, &agent_id);
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    let security_context = security_pre_dispatch_context_for(&request, session_id.as_str(), 17);
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    let capture = security_pre_dispatch_capture(std::sync::Arc::clone(&calls), None);
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(capture.hook);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let response = runtime
        .block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                    &parent_context,
                    &request,
                    &mut client,
                    None,
                    &security_context,
                )
                .await
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn ordinary_dispatch_releases_consumed_security_outcome_only_after_connector_success() {
    let request_id = "security-outcome-ordinary-success";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_pre_dispatch_context_for(&request, "security-outcome-ordinary-success", 31),
        )
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::Released,
    );
}

#[test]
fn ordinary_final_release_rechecks_request_lifecycle_after_output_hooks() {
    let request_id = "security-request-lifecycle-ordinary";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    let outcomes = std::sync::Arc::new(Mutex::new(Vec::new()));
    let ready = std::sync::Arc::new(AtomicBool::new(true));
    let acquisitions = std::sync::Arc::new(AtomicU64::new(0));
    let final_releases = std::sync::Arc::new(AtomicU64::new(0));
    let abandoned = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(std::sync::Arc::new(LifecycleSecurityDispatchHook {
        outcomes: std::sync::Arc::clone(&outcomes),
        ready: std::sync::Arc::clone(&ready),
        acquisitions: std::sync::Arc::clone(&acquisitions),
        final_releases: std::sync::Arc::clone(&final_releases),
        abandoned: std::sync::Arc::clone(&abandoned),
    }));
    kernel.add_post_invocation_hook(Box::new(CloseRequestLifecyclePostHook { ready }));

    let result = kernel.evaluate_tool_call_blocking_with_security_context(
        &request,
        &security_pre_dispatch_context_for(&request, request_id, 35),
    );
    let Err(error) = result else {
        panic!("closed request lifecycle released an ordinary response");
    };
    assert!(matches!(error, KernelError::GuardDenied(_)));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(final_releases.load(Ordering::SeqCst), 1);
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::Released,
    );
}

#[test]
fn ordinary_connector_error_records_consumed_security_outcome_as_unknown() {
    let request_id = "security-outcome-ordinary-error";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    kernel.register_tool_server(Box::new(FailingSecurityDispatchServer));
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_pre_dispatch_context_for(&request, "security-outcome-ordinary-error", 32),
        )
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::OutcomeUnknownAfterDispatch,
    );
}

#[test]
fn ordinary_protocol_capture_failure_records_consumed_security_outcome_as_dispatch_failed() {
    let request_id = "security-outcome-ordinary-capture-failure";
    let (mut kernel, request, invocations) = security_dispatch_capture_failure_fixture(request_id);
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_pre_dispatch_context_for(
                &request,
                "security-outcome-ordinary-capture-failure",
                33,
            ),
        )
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::DispatchFailed,
    );
}

#[test]
fn security_dispatch_outcome_persistence_failure_before_connector_requires_reconciliation() {
    let request_id = "security-outcome-persistence-before-connector";
    let (mut kernel, request, invocations) =
        security_dispatch_capture_failure_fixture(request_id);
    let attempts = install_failing_security_dispatch_outcome_hook(&mut kernel);

    let error = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_pre_dispatch_context_for(&request, request_id, 38),
        )
        .expect_err("a failed DispatchFailed record must require reconciliation");

    assert_security_dispatch_outcome_recovery_required(&error);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let report = error.report();
    assert!(report.suggested_fix.contains("dispatch phase"));
    assert!(!report.suggested_fix.contains("external side-effect"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_ordinary_future_after_connector_entry_records_unknown_once() {
    let request_id = "security-outcome-ordinary-drop";
    let (mut kernel, request, _) = security_pre_dispatch_fixture(request_id);
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    kernel.register_tool_server(Box::new(PendingSecurityDispatchServer {
        entered: std::sync::Arc::clone(&entered),
    }));
    let outcomes = std::sync::Arc::new(Mutex::new(Vec::new()));
    let ready = std::sync::Arc::new(AtomicBool::new(true));
    let acquisitions = std::sync::Arc::new(AtomicU64::new(0));
    let final_releases = std::sync::Arc::new(AtomicU64::new(0));
    let abandoned = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(std::sync::Arc::new(LifecycleSecurityDispatchHook {
        outcomes: std::sync::Arc::clone(&outcomes),
        ready,
        acquisitions: std::sync::Arc::clone(&acquisitions),
        final_releases: std::sync::Arc::clone(&final_releases),
        abandoned: std::sync::Arc::clone(&abandoned),
    }));
    let security_context =
        security_pre_dispatch_context_for(&request, "security-outcome-ordinary-drop", 34);
    let kernel = std::sync::Arc::new(kernel);
    let evaluation = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move {
            kernel
                .evaluate_tool_call_with_security_context(&request, &security_context)
                .await
        })
    };

    tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    evaluation.abort();
    assert!(evaluation.await.unwrap_err().is_cancelled());
    assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(final_releases.load(Ordering::SeqCst), 0);
    assert_eq!(abandoned.load(Ordering::SeqCst), 1);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::OutcomeUnknownAfterDispatch,
    );
}

#[test]
fn ordinary_incomplete_stream_records_consumed_security_outcome_as_unknown() {
    let request_id = "security-outcome-ordinary-incomplete";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    kernel.register_tool_server(Box::new(IncompleteSecurityDispatchServer));
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_pre_dispatch_context_for(&request, request_id, 36),
        )
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.terminal_state.is_incomplete());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::OutcomeUnknownAfterDispatch,
    );
}

#[test]
fn ordinary_post_entry_cancellation_records_consumed_security_outcome_as_unknown() {
    let request_id = "security-outcome-ordinary-cancelled";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    kernel.register_tool_server(Box::new(CancelledSecurityDispatchServer));
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);

    let response = kernel
        .evaluate_tool_call_blocking_with_security_context(
            &request,
            &security_pre_dispatch_context_for(&request, request_id, 37),
        )
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.terminal_state.is_cancelled());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::OutcomeUnknownAfterDispatch,
    );
}

#[test]
fn nested_dispatch_releases_consumed_security_outcome_only_after_connector_success() {
    let request_id = "security-outcome-nested-success";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    let (session_id, parent_context) = security_dispatch_nested_context(&mut kernel, &request);
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(&request, session_id.as_str(), 41);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let response = runtime
        .block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                    &parent_context,
                    &request,
                    &mut client,
                    None,
                    &security_context,
                )
                .await
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::Released,
    );
}

#[test]
fn nested_final_release_rechecks_request_lifecycle_after_output_hooks() {
    let request_id = "security-request-lifecycle-nested";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    let (session_id, parent_context) = security_dispatch_nested_context(&mut kernel, &request);
    let outcomes = std::sync::Arc::new(Mutex::new(Vec::new()));
    let ready = std::sync::Arc::new(AtomicBool::new(true));
    let acquisitions = std::sync::Arc::new(AtomicU64::new(0));
    let final_releases = std::sync::Arc::new(AtomicU64::new(0));
    let abandoned = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_security_pre_dispatch_policy(SecurityPreDispatchPolicy::Enforce);
    kernel.set_security_pre_dispatch_hook(std::sync::Arc::new(LifecycleSecurityDispatchHook {
        outcomes: std::sync::Arc::clone(&outcomes),
        ready: std::sync::Arc::clone(&ready),
        acquisitions: std::sync::Arc::clone(&acquisitions),
        final_releases: std::sync::Arc::clone(&final_releases),
        abandoned: std::sync::Arc::clone(&abandoned),
    }));
    kernel.add_post_invocation_hook(Box::new(CloseRequestLifecyclePostHook { ready }));
    let security_context = security_pre_dispatch_context_for(&request, session_id.as_str(), 45);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("nested runtime: {error}"));

    let result = runtime.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                &parent_context,
                &request,
                &mut client,
                None,
                &security_context,
            )
            .await
    });
    let Err(error) = result else {
        panic!("closed request lifecycle released a nested response");
    };
    assert!(matches!(error, KernelError::GuardDenied(_)));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(final_releases.load(Ordering::SeqCst), 1);
    assert_eq!(abandoned.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::Released,
    );
}

#[test]
fn nested_connector_error_records_consumed_security_outcome_as_unknown() {
    let request_id = "security-outcome-nested-error";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    kernel.register_tool_server(Box::new(FailingSecurityDispatchServer));
    let (session_id, parent_context) = security_dispatch_nested_context(&mut kernel, &request);
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(&request, session_id.as_str(), 42);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let response = runtime
        .block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                    &parent_context,
                    &request,
                    &mut client,
                    None,
                    &security_context,
                )
                .await
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::OutcomeUnknownAfterDispatch,
    );
}

#[test]
fn nested_protocol_capture_failure_records_consumed_security_outcome_as_dispatch_failed() {
    let request_id = "security-outcome-nested-capture-failure";
    let (mut kernel, request, invocations) = security_dispatch_capture_failure_fixture(request_id);
    let (session_id, parent_context) = security_dispatch_nested_context(&mut kernel, &request);
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(&request, session_id.as_str(), 43);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let response = runtime
        .block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                    &parent_context,
                    &request,
                    &mut client,
                    None,
                    &security_context,
                )
                .await
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::DispatchFailed,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_nested_future_after_connector_entry_records_unknown_once() {
    let request_id = "security-outcome-nested-drop";
    let (mut kernel, request, _) = security_pre_dispatch_fixture(request_id);
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    kernel.register_tool_server(Box::new(PendingSecurityDispatchServer {
        entered: std::sync::Arc::clone(&entered),
    }));
    let (session_id, parent_context) = security_dispatch_nested_context(&mut kernel, &request);
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(&request, session_id.as_str(), 44);
    let kernel = std::sync::Arc::new(kernel);
    let evaluation = {
        let kernel = std::sync::Arc::clone(&kernel);
        tokio::spawn(async move {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                    &parent_context,
                    &request,
                    &mut client,
                    None,
                    &security_context,
                )
                .await
        })
    };

    tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    evaluation.abort();
    assert!(evaluation.await.unwrap_err().is_cancelled());
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::OutcomeUnknownAfterDispatch,
    );
}

#[test]
fn nested_incomplete_stream_records_consumed_security_outcome_as_unknown() {
    let request_id = "security-outcome-nested-incomplete";
    let (mut kernel, request, invocations) = security_pre_dispatch_fixture(request_id);
    kernel.register_tool_server(Box::new(IncompleteSecurityDispatchServer));
    let (session_id, parent_context) = security_dispatch_nested_context(&mut kernel, &request);
    let outcomes = install_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(&request, session_id.as_str(), 46);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let response = runtime
        .block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                    &parent_context,
                    &request,
                    &mut client,
                    None,
                    &security_context,
                )
                .await
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.terminal_state.is_incomplete());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_single_security_dispatch_outcome(
        &outcomes,
        request_id,
        SecurityDispatchOutcome::OutcomeUnknownAfterDispatch,
    );
}

fn assert_security_dispatch_outcome_recovery_required(error: &KernelError) {
    assert!(matches!(
        error,
        KernelError::SecurityDispatchOutcomeRecoveryRequired(_)
    ));
    assert!(!matches!(error, KernelError::GuardDenied(_)));
    let report = error.report();
    assert_eq!(
        report.code,
        "CHIO-KERNEL-SECURITY-DISPATCH-OUTCOME-RECOVERY-REQUIRED"
    );
    assert_eq!(report.context["retryable"], false);
    assert_eq!(report.context["redispatch_allowed"], false);
    assert_eq!(report.context["required_action"], "reconcile");
    assert!(report.suggested_fix.contains("Do not retry or redispatch"));
    assert!(report.suggested_fix.contains("Reconcile"));
}

#[tokio::test]
async fn security_dispatch_outcome_persistence_failure_marks_ordinary_async_admission_unknown() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    let subject = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(1);
    let ordinary = make_capability(&kernel, &subject, make_scope(vec![grant]), 300);
    let capability = aggregate_limited_capability(&kernel, &ordinary, 1);
    let request = make_request(
        "security-outcome-persistence-ordinary-async",
        &capability,
        "read_file",
        "srv-a",
    );
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel
        .enable_aggregate_invocation_admission()
        .expect("aggregate admission");
    let attempts = install_failing_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(
        &request,
        "security-outcome-persistence-ordinary-async",
        51,
    );

    let error = kernel
        .evaluate_tool_call_with_security_context(&request, &security_context)
        .await
        .expect_err("security outcome persistence failure must require reconciliation");

    assert_security_dispatch_outcome_recovery_required(&error);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let states = operations.states();
    assert_eq!(
        states.last(),
        Some(&AdmissionOperationState::OutcomeUnknownAfterDispatch)
    );
    assert!(!states.contains(&AdmissionOperationState::Completed));
}

#[tokio::test]
async fn security_dispatch_outcome_persistence_failure_marks_threshold_nested_admission_unknown() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "security-outcome-persistence-threshold-nested".to_string();
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let budget = std::sync::Arc::new(DurableThresholdBudgetStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        std::sync::Arc::clone(&invocations),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(budget.clone())
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");
    let attempts = install_failing_security_dispatch_outcome_hook(&mut kernel);
    let (session_id, parent_context) = security_dispatch_nested_context(&mut kernel, &request);
    let security_context = security_pre_dispatch_context_for(&request, session_id.as_str(), 52);
    let mut client = NoopNestedFlowClient;

    let error = kernel
        .evaluate_tool_call_with_nested_flow_client_async_and_security_context(
            &parent_context,
            &request,
            &mut client,
            None,
            &security_context,
        )
        .await
        .expect_err("nested security outcome persistence failure must require reconciliation");

    assert_security_dispatch_outcome_recovery_required(&error);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let states = operations.states();
    assert_eq!(
        states.last(),
        Some(&AdmissionOperationState::OutcomeUnknownAfterDispatch)
    );
    assert!(!states.contains(&AdmissionOperationState::Completed));
    let usage = budget
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .expect("captured threshold hold");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
}

#[tokio::test]
async fn security_dispatch_outcome_persistence_failure_keeps_incomplete_threshold_unknown() {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "security-outcome-persistence-threshold-incomplete".to_string();
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    let operations = std::sync::Arc::new(RecordingThresholdOperationStore::new());
    let side_effects = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(IncompleteStreamAfterSideEffectServer::new(
        "payments",
        vec!["transfer"],
        std::sync::Arc::clone(&side_effects),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");
    let attempts = install_failing_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(
        &request,
        "security-outcome-persistence-threshold-incomplete",
        53,
    );

    let error = kernel
        .evaluate_tool_call_with_security_context(&request, &security_context)
        .await
        .expect_err("incomplete security outcome persistence must require reconciliation");

    assert_security_dispatch_outcome_recovery_required(&error);
    assert_eq!(side_effects.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let states = operations.states();
    assert_eq!(
        states.last(),
        Some(&AdmissionOperationState::OutcomeUnknownAfterDispatch)
    );
    assert!(!states.contains(&AdmissionOperationState::Completed));
}

#[tokio::test]
async fn security_dispatch_outcome_persistence_failure_preserves_primary_when_terminalization_fails(
) {
    let (mut kernel, capability, _grant, intent, mut request, now) = threshold_test_fixture();
    request.request_id = "security-outcome-persistence-terminalization-failure".to_string();
    install_valid_threshold_artifacts(&mut kernel, &capability, &intent, &mut request, now);
    let operations = std::sync::Arc::new(RejectingOutcomeUnknownOperationStore::new());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "payments",
        vec!["transfer"],
        std::sync::Arc::clone(&invocations),
    )));
    kernel
        .set_admission_operation_store_handle(operations.clone())
        .expect("operation store");
    kernel
        .set_approval_store_handle(std::sync::Arc::new(DurableThresholdApprovalStore::new()))
        .expect("approval store");
    kernel
        .set_budget_store_handle(std::sync::Arc::new(DurableThresholdBudgetStore::new()))
        .expect("budget store");
    kernel
        .enable_threshold_governed_approvals()
        .expect("threshold activation");
    let attempts = install_failing_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(
        &request,
        "security-outcome-persistence-terminalization-failure",
        54,
    );

    let error = kernel
        .evaluate_tool_call_with_security_context(&request, &security_context)
        .await
        .expect_err("terminalization failure must not replace security recovery semantics");

    assert_security_dispatch_outcome_recovery_required(&error);
    let message = error.to_string();
    assert!(message.contains("injected authoritative security outcome persistence failure"));
    assert!(message.contains("secondary recovery faults"));
    assert!(message.contains("threshold admission outcome-unknown transition failed"));
    assert!(message.contains("injected outcome-unknown persistence failure"));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let states = operations.states();
    assert_eq!(
        states.last(),
        Some(&AdmissionOperationState::DispatchCommitted)
    );
    assert!(!states.contains(&AdmissionOperationState::Completed));
}

#[tokio::test]
async fn security_dispatch_outcome_persistence_failure_releases_ordinary_payment_and_budget() {
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_payment_adapter(Box::new(payment.clone()))
        .expect("install payment adapter");
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&invocations),
    )));
    let subject = make_keypair();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    grant.max_invocations = Some(1);
    let capability = kernel
        .issue_capability(&subject.public_key(), make_scope(vec![grant]), 3_600)
        .expect("capability");
    let request = make_request(
        "security-outcome-persistence-ordinary-monetary-cleanup",
        &capability,
        "compute",
        "cost-srv",
    );
    let attempts = install_failing_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(
        &request,
        "security-outcome-persistence-ordinary-monetary-cleanup",
        55,
    );

    let error = kernel
        .evaluate_tool_call_with_security_context(&request, &security_context)
        .await
        .expect_err("failed security outcome persistence must release ordinary monetary holds");

    assert_security_dispatch_outcome_recovery_required(&error);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let usage = kernel
        .budget_store
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .expect("budget usage");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 0);
    assert_eq!(payment.authorized.load(Ordering::SeqCst), 1);
    assert_eq!(payment.released.load(Ordering::SeqCst), 1);
    assert_eq!(payment.refunded.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn security_dispatch_outcome_persistence_failure_retains_runtime_and_delegation_reservations(
) {
    let SiblingSumMonetaryFixture {
        mut kernel,
        child_a,
        child_b,
        path,
        ..
    } = make_sibling_sum_monetary_fixture("security-outcome-persistence-retained-reservations");
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&invocations),
    )));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        ReleaseTrackingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
            releases: std::sync::Arc::clone(&releases),
            expected_request_id: "security-outcome-persistence-retained-reservations",
            admission_id: "adm-security-outcome-persistence-retained",
            lease_id: "lease-security-outcome-persistence-retained",
            continuation_id: Some("continuation-security-outcome-persistence-retained"),
        },
    ));
    let request = make_request(
        "security-outcome-persistence-retained-reservations",
        &child_a,
        "compute",
        "cost-srv",
    );
    let attempts = install_failing_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(
        &request,
        "security-outcome-persistence-retained-reservations",
        56,
    );

    let error = kernel
        .evaluate_tool_call_with_security_context(&request, &security_context)
        .await
        .expect_err("failed security outcome persistence must retain reservations");

    assert_security_dispatch_outcome_recovery_required(&error);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 0);
    let sibling_admission = kernel.admit_capability_budget(&child_b);
    assert!(
        sibling_admission.is_err(),
        "the retained child_a lease must continue to block its oversubscribing sibling"
    );
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn security_dispatch_outcome_persistence_failure_aggregates_monetary_cleanup_failure() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel
        .set_payment_adapter(Box::new(FailingReleasePaymentAdapter))
        .expect("install payment adapter");
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&invocations),
    )));
    let subject = make_keypair();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    grant.max_invocations = Some(1);
    let capability = kernel
        .issue_capability(&subject.public_key(), make_scope(vec![grant]), 3_600)
        .expect("capability");
    let request = make_request(
        "security-outcome-persistence-cleanup-failure",
        &capability,
        "compute",
        "cost-srv",
    );
    let attempts = install_failing_security_dispatch_outcome_hook(&mut kernel);
    let security_context = security_pre_dispatch_context_for(
        &request,
        "security-outcome-persistence-cleanup-failure",
        57,
    );

    let error = kernel
        .evaluate_tool_call_with_security_context(&request, &security_context)
        .await
        .expect_err("cleanup failure must preserve security recovery semantics");

    assert_security_dispatch_outcome_recovery_required(&error);
    let message = error.to_string();
    assert!(message.contains("secondary recovery faults"));
    assert!(message.contains("post-dispatch monetary cleanup failed"));
    assert!(message.contains("[REDACTED-API-KEY]"));
    assert!(!message.contains("sk_live_"));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let usage = kernel
        .budget_store
        .get_usage(&capability.id, 0)
        .expect("budget lookup")
        .expect("retained budget usage");
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.total_cost_exposed, 100);
}
