//! Public nested entrypoints must preserve proofs into physical replay custody.
use super::*;
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RequestId, RootDefinition, ToolCallOperation,
};
use chio_kernel::{NestedFlowClient, NestedToolCallProofs, ToolCallResponse};

struct NoChildRequests;

struct UnavailableContextAuthority;

impl chio_kernel::SecurityInvocationContextAuthority for UnavailableContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        _: &OperationContext,
        _: &ToolCallOperation,
    ) -> Result<chio_kernel::SecurityInvocationContext, KernelError> {
        Err(KernelError::GuardDenied(
            "context authority unavailable".into(),
        ))
    }
}

#[test]
fn public_nested_context_authority_error_clears_inflight_without_claims() -> AnchoredTestResult {
    for async_native in [false, true] {
        for explicit_proofs in [false, true] {
            let mut route = Route::new()?;
            route
                .kernel
                .set_security_invocation_context_authority(Arc::new(UnavailableContextAuthority));
            let request = route.request("nested-unavailable-context", &[1])?;
            let (context, operation) = session_call(&route, &request)?;
            let error = invoke(
                &route,
                &context,
                &operation,
                explicit_proofs.then(|| proofs(&request)),
                async_native,
            )
            .err()
            .ok_or("context resolution unexpectedly succeeded")?;
            assert!(matches!(error.downcast_ref::<KernelError>(),
                Some(KernelError::GuardDenied(reason)) if reason == "context authority unavailable"));
            let session = route
                .kernel
                .session(&context.session_id)
                .ok_or("session absent")?;
            assert!(
                session.inflight().is_empty(),
                "context failure leaked an inflight request"
            );
            assert!(session.terminal().get(&context.request_id).is_some());
            assert_eq!(route.calls.load(Ordering::SeqCst), 0);
            assert_eq!(route.counts()?, (0, 0));
        }
    }
    Ok(())
}

impl NestedFlowClient for NoChildRequests {
    fn list_roots(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Err(KernelError::Internal("unexpected roots request".into()))
    }

    fn create_message(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(KernelError::Internal("unexpected sampling request".into()))
    }

    fn create_elicitation(
        &mut self,
        _: &OperationContext,
        _: &OperationContext,
        _: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(KernelError::Internal(
            "unexpected elicitation request".into(),
        ))
    }

    fn notify_elicitation_completed(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected elicitation notification".into(),
        ))
    }

    fn notify_resource_updated(
        &mut self,
        _: &OperationContext,
        _: &str,
    ) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected resource notification".into(),
        ))
    }

    fn notify_resources_list_changed(&mut self, _: &OperationContext) -> Result<(), KernelError> {
        Err(KernelError::Internal(
            "unexpected resource list notification".into(),
        ))
    }
}

fn session_call(
    route: &Route,
    request: &ToolCallRequest,
) -> AnchoredTestResult<(OperationContext, ToolCallOperation)> {
    let session = route
        .kernel
        .open_session(request.agent_id.clone(), vec![request.capability.clone()])?;
    route.kernel.activate_session(&session)?;
    Ok((
        OperationContext::new(
            session,
            RequestId::new(&request.request_id),
            request.agent_id.clone(),
        ),
        serde_json::from_value(serde_json::to_value(request)?)?,
    ))
}

fn invoke(
    route: &Route,
    context: &OperationContext,
    operation: &ToolCallOperation,
    proofs: Option<NestedToolCallProofs>,
    async_native: bool,
) -> AnchoredTestResult<ToolCallResponse> {
    let mut client = NoChildRequests;
    let result =
        if async_native {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(async {
                    match proofs {
                        Some(proofs) => route
                            .kernel
                            .evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
                                context,
                                operation,
                                &mut client,
                                proofs,
                            )
                            .await,
                        None => {
                            route
                                .kernel
                                .evaluate_tool_call_operation_with_nested_flow_client_async(
                                    context,
                                    operation,
                                    &mut client,
                                )
                                .await
                        }
                    }
                })
        } else {
            match proofs {
                Some(proofs) => route
                    .kernel
                    .evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
                        context,
                        operation,
                        &mut client,
                        proofs,
                    ),
                None => route
                    .kernel
                    .evaluate_tool_call_operation_with_nested_flow_client(
                        context,
                        operation,
                        &mut client,
                    ),
            }
        };
    Ok(result?)
}

fn proofs(request: &ToolCallRequest) -> NestedToolCallProofs {
    NestedToolCallProofs {
        dpop_proof: request.dpop_proof.clone(),
        declassification_grant: request.declassification_grant.clone(),
    }
}

#[test]
fn public_nested_proofs_claim_exact_dpop_and_reject_cross_request_replay() -> AnchoredTestResult {
    for async_native in [false, true] {
        let route = Route::new()?;
        let mut request = route.request("nested-public-proof", &[2])?;
        let (mut context, operation) = session_call(&route, &request)?;
        let response = invoke(
            &route,
            &context,
            &operation,
            Some(proofs(&request)),
            async_native,
        )?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(route.calls.load(Ordering::SeqCst), 1);
        let (operation_record, history) = route.history(&request)?;
        assert!(operation_record.state().is_terminal());
        assert_eq!(history.len(), 1);
        assert_eq!(
            history[0].disposition,
            DpopReplayClaimDisposition::RetainedAfterDispatchCommit
        );
        assert_eq!(
            history[0].intent.credential().proof_digest().as_str(),
            sha256_hex(&canonical_json_bytes(
                request.dpop_proof.as_ref().ok_or("proof absent")?
            )?)
        );

        request.request_id = "nested-public-proof-replay".into();
        context.request_id = RequestId::new(&request.request_id);
        let response = invoke(
            &route,
            &context,
            &operation,
            Some(proofs(&request)),
            async_native,
        )?;
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert_eq!(route.calls.load(Ordering::SeqCst), 1);
        assert_eq!(route.counts()?, (1, 1));
    }
    Ok(())
}

#[test]
fn public_nested_missing_and_substituted_proofs_deny_before_claim_or_effect() -> AnchoredTestResult
{
    for async_native in [false, true] {
        for missing in [false, true] {
            let route = Route::new()?;
            let request = route.request("nested-public-invalid-proof", &[1])?;
            let (context, mut operation) = session_call(&route, &request)?;
            let mut supplied = proofs(&request);
            if missing {
                supplied.dpop_proof = None;
            } else {
                operation.arguments = serde_json::json!({"record": "substituted-action"});
            }
            let response = invoke(&route, &context, &operation, Some(supplied), async_native)?;
            assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
            assert_eq!(route.calls.load(Ordering::SeqCst), 0);
            assert_eq!(route.counts()?, (0, 0));
        }
    }
    Ok(())
}

#[test]
fn public_nested_compatibility_entrypoints_cannot_downgrade_required_dpop() -> AnchoredTestResult {
    for async_native in [false, true] {
        let route = Route::new()?;
        let request = route.request("nested-public-no-credentials", &[1])?;
        let (context, operation) = session_call(&route, &request)?;
        let response = invoke(&route, &context, &operation, None, async_native)?;
        assert_eq!(response.verdict, Verdict::Deny, "{:?}", response.reason);
        assert_eq!(route.calls.load(Ordering::SeqCst), 0);
        assert_eq!(route.counts()?, (0, 0));
    }
    Ok(())
}

#[test]
fn public_nested_nonce_retry_preserves_original_session_and_dpop_custody() -> AnchoredTestResult {
    for async_native in [false, true] {
        let mut route = Route::new()?;
        let config = chio_kernel::execution_nonce::ExecutionNonceConfig {
            nonce_ttl_secs: 60,
            nonce_store_capacity: 16,
            require_nonce: true,
        };
        route.kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(
                chio_kernel::execution_nonce::InMemoryExecutionNonceStore::from_config(&config),
            ),
        );
        let request = route.request("nested-public-nonce", &[1])?;
        let (context, mut operation) = session_call(&route, &request)?;
        let preflight = invoke(
            &route,
            &context,
            &operation,
            Some(proofs(&request)),
            async_native,
        )?;
        assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
        assert_eq!(route.calls.load(Ordering::SeqCst), 0);
        operation.execution_nonce = Some(serde_json::to_value(
            preflight.execution_nonce.ok_or("preflight nonce absent")?,
        )?);
        let response = invoke(
            &route,
            &context,
            &operation,
            Some(proofs(&request)),
            async_native,
        )?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert_eq!(route.calls.load(Ordering::SeqCst), 1);
        let (operation_record, history) = route.history(&request)?;
        assert!(operation_record.state().is_terminal());
        assert_eq!(history.len(), 2);
        assert_eq!(
            history[0].intent.phase(),
            DpopReplayClaimPhase::NoncePreflight
        );
        assert_eq!(
            history[0].disposition,
            DpopReplayClaimDisposition::ReleasedBeforeDispatch
        );
        assert_eq!(history[1].intent.phase(), DpopReplayClaimPhase::Dispatch);
        assert_eq!(
            history[1].disposition,
            DpopReplayClaimDisposition::RetainedAfterDispatchCommit
        );
        assert_eq!(
            history[0].intent.grant_index(),
            history[1].intent.grant_index()
        );
        assert!(invoke(
            &route,
            &context,
            &operation,
            Some(proofs(&request)),
            async_native
        )
        .is_err());
        assert_eq!(route.calls.load(Ordering::SeqCst), 1);
    }
    Ok(())
}
