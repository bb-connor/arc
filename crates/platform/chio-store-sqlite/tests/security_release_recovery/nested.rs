//! The nested route must use the same durable release authority as ordinary calls.
use super::*;
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RequestId, RootDefinition, ToolCallOperation,
};
use chio_kernel::{NestedFlowClient, SecurityInvocationContextAuthority};

pub(super) struct ContextAuthority(pub(super) SecurityInvocationContext);
impl SecurityInvocationContextAuthority for ContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        _: &OperationContext,
        _: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        Ok(self.0.clone())
    }
}

pub(super) struct Client;
impl NestedFlowClient for Client {
    fn list_roots(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Ok(Vec::new())
    }
    fn create_message(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(KernelError::Internal("unexpected nested message".into()))
    }
    fn create_elicitation(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested elicitation".into(),
        ))
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

fn run(allowed: bool) -> TestResult {
    let mut fixture = Fixture::new()?;
    fixture.nonce_enabled = false;
    let hook = Arc::new(ReleaseHook {
        allowed,
        releases: Arc::new(AtomicUsize::new(0)),
    });
    let mut runtime = open(&fixture, hook.clone(), true)?;
    let request = fixture.request(&runtime, "nested-security-release")?;
    let session = runtime
        .kernel
        .open_session(request.agent_id.clone(), Vec::new())?;
    runtime.kernel.activate_session(&session)?;
    let parent = OperationContext::new(
        session.clone(),
        RequestId::new(request.request_id.clone()),
        request.agent_id.clone(),
    );
    let security_context = SecurityInvocationContext::v1(SecurityInvocationContextV1::new(
        TenantId::new("release-tenant")?,
        SessionId::new(session.as_str())?,
        PrincipalId::new(request.agent_id.clone())?,
        IsolationEpochId::new("release-epoch")?,
        LineageId::new(request.capability.id.clone())?,
        1,
    ));
    Arc::get_mut(&mut runtime.kernel)
        .ok_or("unique kernel")?
        .set_security_invocation_context_authority(Arc::new(ContextAuthority(
            security_context.clone(),
        )));
    let operation = ToolCallOperation {
        capability: request.capability.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };
    let evaluate = || {
        runtime
            .kernel
            .evaluate_tool_call_operation_with_nested_flow_client(&parent, &operation, &mut Client)
    };
    let first = evaluate();
    let replay = runtime
        .kernel
        .evaluate_tool_call_blocking_with_security_context(&request, &security_context);
    if allowed {
        let first = first?;
        let replay = replay?;
        assert_eq!(first.verdict, chio_kernel::Verdict::Allow);
        assert_eq!(replay.receipt.id, first.receipt.id);
    } else {
        assert_withheld(first);
        assert_withheld(replay);
    }
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(hook.releases.load(Ordering::SeqCst), 1);
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    Ok(())
}

#[test]
fn nested_release_failure_remains_withheld_on_retry() -> TestResult {
    run(false)
}

#[test]
fn nested_release_success_replays_the_same_terminal() -> TestResult {
    run(true)
}
