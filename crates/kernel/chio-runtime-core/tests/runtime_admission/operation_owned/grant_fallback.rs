use super::*;
use chio_core_types::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RequestId, RootDefinition, ToolCallOperation,
};
use chio_kernel::{KernelError, NestedFlowClient};

struct NoNestedRequests;

impl NestedFlowClient for NoNestedRequests {
    fn list_roots(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested roots request".into(),
        ))
    }
    fn create_message(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested sampling request".into(),
        ))
    }
    fn create_elicitation(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected nested elicitation request".into(),
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

#[test]
fn ordinary_and_nested_fallback_retire_the_denied_grants_runtime_episode() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    for nested in [false, true] {
        let mut fixture = Fixture::new(true)?;
        let mut body = fixture.request.capability.body();
        let fallback = body.scope.grants[0].clone();
        body.scope.grants[0].max_invocations = Some(0);
        body.scope.grants.push(fallback);
        let signer = Keypair::generate();
        body.issuer = signer.public_key();
        fixture.request.capability = CapabilityToken::sign(body, &signer)?;
        let kernel = fixture.kernel(fixture.hook()?, true, false)?;
        let response = if nested {
            let request = &fixture.request;
            let session =
                kernel.open_session(request.agent_id.clone(), vec![request.capability.clone()])?;
            kernel.activate_session(&session)?;
            let context = OperationContext::new(
                session,
                RequestId::new(request.request_id.clone()),
                request.agent_id.clone(),
            );
            let operation = ToolCallOperation {
                capability: request.capability.clone(),
                server_id: request.server_id.clone(),
                tool_name: request.tool_name.clone(),
                arguments: request.arguments.clone(),
                governed_intent: request.governed_intent.clone(),
                approval_token: None,
                approval_tokens: vec![],
                threshold_approval_proposal: None,
                supplemental_authorization: None,
                execution_nonce: None,
                model_metadata: None,
                extra_metadata: None,
            };
            kernel.evaluate_tool_call_operation_with_nested_flow_client(
                &context,
                &operation,
                &mut NoNestedRequests,
            )?
        } else {
            kernel.evaluate_tool_call_blocking(&fixture.request)?
        };
        assert_eq!(
            response.verdict,
            Verdict::Allow,
            "nested={nested}: {:?}",
            response.reason
        );
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .ok_or("fallback metadata")?;
        let reference: chio_kernel::admission_operation::runtime_participant::RuntimeParticipantClaimReferenceV1 =
            serde_json::from_value(metadata["chio_runtime"]["operation_owned_replay"]["reference"].clone())?;
        let (_, history) = fixture
            .authority
            .admission_operation_store()
            .load_runtime_participant_history(
                reference.operation_id(),
                &fixture.authority.mutation_fence(),
                NOW,
            )?
            .ok_or("fallback ownership")?;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].intent.grant_index(), 0);
        assert_eq!(
            history[0].disposition,
            RuntimeParticipantDisposition::ReleasedBeforeDispatch
        );
        assert_eq!(history[1].intent.grant_index(), 1);
        assert_eq!(
            history[1].disposition,
            RuntimeParticipantDisposition::RetainedAfterDispatchCommit
        );
        assert_ne!(history[0].reference, history[1].reference);
        assert_ne!(
            history[0].intent.plan_digest(),
            history[1].intent.plan_digest()
        );
        assert_eq!(history[0].intent.resources(), history[1].intent.resources());
    }
    Ok(())
}
