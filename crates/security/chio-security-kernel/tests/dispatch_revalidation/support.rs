use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RequestId, RootDefinition, ToolCallOperation,
};
use chio_core::Keypair;
use chio_kernel::*;
use chio_security_types::ports::*;
use chio_security_types::PrincipalId;
use chio_test_support::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    Clear,
    Active,
    Unavailable,
    Malformed,
}

pub(super) struct Authority {
    state: Mutex<State>,
    pub(super) queries: AtomicUsize,
}
impl Authority {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(State::Clear),
            queries: AtomicUsize::new(0),
        }
    }
    fn state(&self) -> State {
        self.queries.fetch_add(1, Ordering::SeqCst);
        *self.state.lock().test_unwrap()
    }
}
impl ContainmentOverlayStore for Authority {
    fn ensure_containment_overlays_ready(&self) -> PortResult<()> {
        Ok(())
    }
    fn apply_contribution(&self, _: &OverlayApplyRequest) -> PortResult<OverlaySnapshot> {
        Err(PortError::unavailable())
    }
    fn remove_contribution(&self, _: &OverlayRemoveRequest) -> PortResult<OverlaySnapshot> {
        Err(PortError::unavailable())
    }
    fn load_containment_overlay_result(
        &self,
        _: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        Err(PortError::unavailable())
    }
    fn load_effective(&self, target: &TenantScopedId) -> PortResult<Option<OverlaySnapshot>> {
        match self.state() {
            State::Clear => Ok(None),
            State::Unavailable => Err(PortError::unavailable()),
            state => Ok(Some(OverlaySnapshot {
                target: target.clone(),
                generation: 1,
                effective_posture_rank: 1,
                active_contributions: OverlayContributions::new(if state == State::Malformed {
                    Vec::new()
                } else {
                    vec![OverlayContribution {
                        effect_id: EffectId::new("overlay-effect").test_unwrap(),
                        posture_rank: 1,
                        contribution_hash: Digest32::new([1; 32]),
                        expires_at_unix_ms: None,
                    }]
                })
                .test_unwrap(),
                highest_fencing_token: 1,
            })),
        }
    }
}
impl CapabilitySetSuspensionStore for Authority {
    fn ensure_capability_set_suspensions_ready(&self) -> PortResult<()> {
        Ok(())
    }
    fn apply_capability_set_suspension(
        &self,
        _: &CapabilitySetSuspensionApplyRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        Err(PortError::unavailable())
    }
    fn remove_capability_set_suspension(
        &self,
        _: &CapabilitySetSuspensionRemoveRequest,
    ) -> PortResult<CapabilitySetSuspensionSnapshot> {
        Err(PortError::unavailable())
    }
    fn load_capability_set_suspensions(
        &self,
        _: &CapabilitySetSuspensionKey,
    ) -> PortResult<Option<CapabilitySetSuspensionSnapshot>> {
        Err(PortError::unavailable())
    }
    fn load_capability_set_suspension_result(
        &self,
        _: &EffectResultQuery,
    ) -> PortResult<EffectExecutionStatus> {
        Err(PortError::unavailable())
    }
    fn evaluate_capability_suspension(
        &self,
        query: &CapabilitySuspensionQuery,
    ) -> PortResult<CapabilitySuspensionDecision> {
        let state = self.state();
        if state == State::Unavailable {
            return Err(PortError::unavailable());
        }
        let denied = state == State::Active;
        Ok(CapabilitySuspensionDecision {
            tenant_id: if state == State::Malformed {
                TenantId::new("wrong-tenant").test_unwrap()
            } else {
                query.tenant_id.clone()
            },
            capability_id: query.capability_id.clone(),
            denied,
            active_matches: CapabilitySetSuspensionMatches::new(if denied {
                vec![CapabilitySetSuspensionMatch {
                    affected_set_hash: Digest32::new([1; 32]),
                    action_id: ActionId::new("suspension-action").test_unwrap(),
                    effect_id: EffectId::new("suspension-effect").test_unwrap(),
                    contribution_hash: Digest32::new([2; 32]),
                    expires_at_unix_ms: u64::MAX,
                }]
            } else {
                Vec::new()
            })
            .test_unwrap(),
        })
    }
}

struct ReadinessMutation {
    authority: Arc<Authority>,
    next: State,
    delayed: bool,
    polled: AtomicBool,
}
impl RuntimeAdmissionHook for ReadinessMutation {
    fn name(&self) -> &str {
        "overlay-readiness-mutation"
    }
    fn evaluate(
        &self,
        _: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        assert_eq!(*self.authority.state.lock().test_unwrap(), State::Clear);
        assert!(
            self.authority.queries.load(Ordering::SeqCst) > 0,
            "initial guard ran before readiness"
        );
        Ok(RuntimeAdmissionDecision::allow(None))
    }
    fn poll_ready_before_dispatch(&self, _: &ToolCallRequest, cx: &mut Context<'_>) -> Poll<()> {
        *self.authority.state.lock().test_unwrap() = self.next;
        if self.delayed && !self.polled.swap(true, Ordering::SeqCst) {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

struct Server(Arc<AtomicUsize>);
#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "overlay-server"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["read".into()]
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

struct SecurityContext(SecurityInvocationContext);
impl SecurityInvocationContextAuthority for SecurityContext {
    fn resolve_security_invocation_context(
        &self,
        _: &OperationContext,
        _: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        Ok(self.0.clone())
    }
}

struct NoChildren;
impl NestedFlowClient for NoChildren {
    fn list_roots(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Err(KernelError::Internal("unexpected child call".into()))
    }
    fn create_message(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(KernelError::Internal("unexpected child call".into()))
    }
    fn create_elicitation(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(KernelError::Internal("unexpected child call".into()))
    }
    fn notify_elicitation_completed(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected child notification".into(),
        ))
    }
    fn notify_resource_updated(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected child notification".into(),
        ))
    }
    fn notify_resources_list_changed(&mut self, _: &OperationContext) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected child notification".into(),
        ))
    }
}

pub(super) fn run(
    guard: Box<dyn Guard>,
    authority: Arc<Authority>,
    next: State,
    delayed: bool,
    nested: bool,
) -> ToolCallResponse {
    let clock = Arc::new(chio_security_types::clock::FixedClock::from_millis(
        1_800_000_000_000,
    ));
    let mut kernel = ChioKernel::new_with_clock(
        KernelConfig {
            keypair: Keypair::generate(),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: "overlay-revalidation-policy".into(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: HotPathDeadlineConfig::default(),
        },
        clock,
    );
    let invocations = Arc::new(AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(Server(invocations.clone())));
    kernel.add_guard(guard);
    kernel.set_runtime_admission_hook(Arc::new(ReadinessMutation {
        authority: authority.clone(),
        next,
        delayed,
        polled: AtomicBool::new(false),
    }));
    let subject = Keypair::generate();
    let capability = kernel
        .issue_capability(
            &subject.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "overlay-server".into(),
                    tool_name: "read".into(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: Some(1),
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            300,
        )
        .test_unwrap();
    let security = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("overlay-tenant").test_unwrap(),
        chio_security_types::ports::SessionId::new("overlay-session").test_unwrap(),
        PrincipalId::new(subject.public_key().to_hex()).test_unwrap(),
        IsolationEpochId::new("overlay-epoch").test_unwrap(),
        LineageId::new(capability.id.clone()).test_unwrap(),
        1,
    ));
    let request = ToolCallRequest {
        request_id: "overlay-request".into(),
        agent_id: subject.public_key().to_hex(),
        capability,
        tool_name: "read".into(),
        server_id: "overlay-server".into(),
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
    let response = if nested {
        let session_id = chio_core::session::SessionId::new("overlay-session");
        kernel
            .open_session_with_id(
                session_id.clone(),
                request.agent_id.clone(),
                vec![request.capability.clone()],
            )
            .test_unwrap();
        kernel.activate_session(&session_id).test_unwrap();
        kernel.set_security_invocation_context_authority(Arc::new(SecurityContext(security)));
        let context = OperationContext::new(
            session_id,
            RequestId::new("overlay-request"),
            request.agent_id.clone(),
        );
        let operation = ToolCallOperation {
            capability: request.capability,
            server_id: request.server_id,
            tool_name: request.tool_name,
            arguments: request.arguments,
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            model_metadata: None,
            supplemental_authorization: None,
            extra_metadata: None,
        };
        kernel
            .evaluate_tool_call_operation_with_nested_flow_client(
                &context,
                &operation,
                &mut NoChildren,
            )
            .test_unwrap()
    } else {
        kernel
            .evaluate_tool_call_blocking_with_security_context(&request, &security)
            .test_unwrap()
    };
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        usize::from(next == State::Clear),
        "late {next:?}, nested={nested}, delayed={delayed}"
    );
    response
}
