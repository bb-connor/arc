use crate::admission_operation::{
    AdmissionBeginResult, AdmissionCommandResult, AdmissionIdentifier, AdmissionOperationCommand,
    AdmissionOperationError, AdmissionOperationId, AdmissionOperationState,
    AdmissionOperationStore, AdmissionOperationStoreError, AdmissionOperationV1,
    AdmissionReplayClassification, AdmissionReplayKey, AdmissionTerminalReplay,
    QualifiedAdmissionOperationStore, StoreMutationFence, UntrustedAdmissionRecoveryClaim,
};

#[test]
fn durable_admission_runtime_defaults_closed_and_off_requires_explicit_unsafe_ephemeral_mode() {
    use crate::admission_operation::{AdmissionOperationError, DurableAdmissionMode};

    let mut kernel = make_kernel(make_config());
    assert_eq!(
        kernel.durable_admission_mode(),
        DurableAdmissionMode::SideEffecting
    );
    assert_eq!(
        kernel.configure_durable_admission(DurableAdmissionMode::Off, false),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
    kernel
        .configure_durable_admission(DurableAdmissionMode::Monetary, false)
        .expect("monetary qualification mode");
    assert_eq!(
        kernel.durable_admission_mode(),
        DurableAdmissionMode::Monetary
    );
    kernel
        .configure_durable_admission(DurableAdmissionMode::Off, true)
        .expect("explicit unsafe ephemeral mode");
    assert_eq!(kernel.durable_admission_mode(), DurableAdmissionMode::Off);

    let mut durable_config = make_config();
    durable_config.allow_ephemeral_receipt_log = false;
    let mut durable_kernel = make_kernel(durable_config);
    assert_eq!(
        durable_kernel.configure_durable_admission(DurableAdmissionMode::Off, true),
        Err(AdmissionOperationError::UnsafeDurableAdmissionOff)
    );
}

#[derive(Default)]
struct TestAdmissionState {
    operation: Option<AdmissionOperationV1>,
    claim: Option<UntrustedAdmissionRecoveryClaim>,
}

struct TestAdmissionOperationStore {
    fence: StoreMutationFence,
    state: std::sync::Mutex<TestAdmissionState>,
}

impl TestAdmissionOperationStore {
    fn new(fence: StoreMutationFence) -> Self {
        Self {
            fence,
            state: std::sync::Mutex::new(TestAdmissionState::default()),
        }
    }

    fn operation(&self) -> AdmissionOperationV1 {
        self.state
            .lock()
            .expect("test admission state lock")
            .operation
            .clone()
            .expect("retained operation")
    }

    fn require_fence(
        &self,
        fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        (fence == &self.fence)
            .then_some(())
            .ok_or(AdmissionOperationStoreError::Fenced)
    }
}

impl AdmissionOperationStore for TestAdmissionOperationStore {
    fn begin(
        &self,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        _trusted_now_unix_ms: u64,
    ) -> Result<AdmissionBeginResult, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        operation.validate()?;
        let mut state = self.state.lock().expect("test admission state lock");
        let Some(existing) = state.operation.as_ref() else {
            state.operation = Some(operation.clone());
            return Ok(AdmissionBeginResult::Created(operation.clone()));
        };
        Ok(match existing.classify_replay(operation) {
            AdmissionReplayClassification::Exact { terminal_replay } => {
                AdmissionBeginResult::ExactReplay {
                    operation: existing.clone(),
                    terminal_replay,
                }
            }
            AdmissionReplayClassification::Conflict => AdmissionBeginResult::Conflict {
                existing_operation_id: existing.binding().operation_id().clone(),
            },
        })
    }

    fn load_by_operation_id(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
            .cloned())
    }

    fn load_by_replay_key(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .as_ref()
            .filter(|operation| &operation.replay_key() == replay_key)
            .cloned())
    }

    fn compare_and_swap(
        &self,
        command: &AdmissionOperationCommand,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionCommandResult, AdmissionOperationStoreError> {
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == command.operation_id())
            .cloned()
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        let claim = state
            .claim
            .as_ref()
            .filter(|claim| claim.operation_id() == command.operation_id())
            .ok_or(AdmissionOperationStoreError::Fenced)?;
        let lease = command.recovery_lease();
        if claim.claimant_id() != lease.claimant_id()
            || claim.coordinator_lease_id() != lease.coordinator_lease_id()
            || claim.claimed_version() != lease.claimed_version()
            || claim.expires_at_unix_ms() != lease.expires_at_unix_ms()
            || claim.store_fence() != lease.store_fence()
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        let result = operation.apply_command(command, trusted_now_unix_ms)?;
        state.operation = Some(result.clone().into_operation());
        state.claim = None;
        Ok(result)
    }

    fn claim_recovery_untrusted(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        claimant_id: &AdmissionIdentifier,
        _trusted_now_unix_ms: u64,
        expires_at_unix_ms: u64,
        fence: &StoreMutationFence,
    ) -> Result<UntrustedAdmissionRecoveryClaim, AdmissionOperationStoreError> {
        self.require_fence(fence)?;
        let mut state = self.state.lock().expect("test admission state lock");
        let operation = state
            .operation
            .as_ref()
            .filter(|operation| operation.binding().operation_id() == operation_id)
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if operation.version() != expected_version {
            return Err(AdmissionOperationError::StaleVersion {
                expected: expected_version,
                actual: operation.version(),
            }
            .into());
        }
        let claim = UntrustedAdmissionRecoveryClaim::new(
            operation_id.clone(),
            claimant_id.clone(),
            AdmissionIdentifier::try_new("coordinator_lease_id", fence.lease_id.clone())?,
            operation.coordinator_lease_epoch(),
            expected_version,
            expires_at_unix_ms,
            fence.clone(),
        )?;
        state.claim = Some(claim.clone());
        Ok(claim)
    }

    fn revalidate_recovery_claim(
        &self,
        operation: &AdmissionOperationV1,
        claim: &UntrustedAdmissionRecoveryClaim,
        trusted_now_unix_ms: u64,
        current_store_fence: &StoreMutationFence,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.require_fence(current_store_fence)?;
        let state = self.state.lock().expect("test admission state lock");
        if state.operation.as_ref() != Some(operation)
            || state.claim.as_ref() != Some(claim)
            || trusted_now_unix_ms >= claim.expires_at_unix_ms()
        {
            return Err(AdmissionOperationStoreError::Fenced);
        }
        Ok(())
    }

    fn list_recoverable(
        &self,
        _not_after_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<AdmissionOperationV1>, AdmissionOperationStoreError> {
        Ok(self
            .state
            .lock()
            .expect("test admission state lock")
            .operation
            .iter()
            .filter(|operation| !operation.state().is_terminal())
            .take(limit)
            .cloned()
            .collect())
    }

    fn load_terminal_replay(
        &self,
        replay_key: &AdmissionReplayKey,
    ) -> Result<Option<AdmissionTerminalReplay>, AdmissionOperationStoreError> {
        Ok(self
            .load_by_replay_key(replay_key)?
            .and_then(|operation| operation.terminal_replay().cloned()))
    }
}

impl QualifiedAdmissionOperationStore for TestAdmissionOperationStore {}

fn admission_test_fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "test-admission-authority".to_string(),
        lease_id: "test-admission-lease".to_string(),
        owner_epoch: 1,
    }
}

struct DurableAdmissionCheckingServer {
    id: String,
    tools: Vec<String>,
    invocations: std::sync::Arc<AtomicU64>,
    store: std::sync::Arc<TestAdmissionOperationStore>,
}

#[async_trait::async_trait]
impl ToolServerConnection for DurableAdmissionCheckingServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        assert_eq!(
            self.store.operation().state(),
            AdmissionOperationState::DispatchCommitted,
            "dispatch must be durably committed before tool invocation"
        );
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

fn durable_admission_fixture(
    request_id: &str,
) -> (
    ChioKernel,
    ToolCallRequest,
    std::sync::Arc<TestAdmissionOperationStore>,
    std::sync::Arc<AtomicU64>,
) {
    let mut kernel = make_kernel(make_config());
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), fence)
        .expect("qualified admission store");
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_string(),
        tools: vec!["mutate".to_string()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("durable-server", "mutate")]),
        300,
    );
    let request = make_request_with_arguments(
        request_id,
        &capability,
        "mutate",
        "durable-server",
        serde_json::json!({"record": "ledger-7", "value": "settled"}),
    );
    (kernel, request, store, invocations)
}

#[test]
fn top_level_durable_admission_commits_before_dispatch_and_blocks_replay() {
    let (kernel, request, store, invocations) = durable_admission_fixture("durable-top-level");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("first durable dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("exact replay denial");
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let mut conflict = request.clone();
    conflict.arguments = serde_json::json!({"record": "ledger-7", "value": "reopened"});
    let conflict = kernel
        .evaluate_tool_call_blocking(&conflict)
        .expect("conflicting replay denial");
    assert_eq!(conflict.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_admission_binds_the_first_budget_eligible_matching_grant() {
    let mut kernel = make_kernel(make_config());
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), fence)
        .expect("qualified admission store");
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_string(),
        tools: vec!["mutate".to_string()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let mut exhausted = make_grant("durable-server", "mutate");
    exhausted.max_invocations = Some(1);
    let fallback = make_grant("durable-server", "mutate");
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![exhausted, fallback]),
        300,
    );
    assert!(kernel
        .with_budget_store(|budget| Ok(budget.try_increment(&capability.id, 0, Some(1))?))
        .expect("exhaust first matching grant"));
    let request = make_request("durable-grant-fallback", &capability, "mutate", "durable-server");

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("fallback grant dispatch");

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(store
        .operation()
        .budget_hold_id()
        .expect("bound budget hold")
        .as_str()
        .ends_with(":1"));
}

#[test]
fn nested_durable_admission_commits_before_dispatch_and_blocks_replay() {
    let (kernel, request, store, invocations) = durable_admission_fixture("durable-nested");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("nested test runtime");

    let evaluate = |request: &ToolCallRequest| {
        let session_id = kernel
            .open_session(request.agent_id.clone(), vec![request.capability.clone()])
            .expect("nested test session");
        kernel.activate_session(&session_id).expect("active session");
        let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
        kernel
            .begin_session_request(&context, OperationKind::ToolCall, true)
            .expect("active nested request");
        runtime.block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async(
                    &context,
                    request,
                    &mut client,
                    None,
                )
                .await
        })
    };

    let response = evaluate(&request).expect("first nested durable dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::DispatchCommitted
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = evaluate(&request).expect("nested replay denial");
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
