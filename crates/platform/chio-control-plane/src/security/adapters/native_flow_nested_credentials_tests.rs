// Actual public nested operation, configured context and combined credential capture.
use super::*;
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RequestId, RootDefinition, ToolCallOperation,
};
use chio_kernel::{NestedFlowClient, NestedToolCallProofs, SecurityInvocationContextAuthority};

struct NoChildRequests;

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

struct BoundContextAuthority {
    operation_context: OperationContext,
    capability_id: String,
    security_context: SecurityInvocationContext,
}

impl SecurityInvocationContextAuthority for BoundContextAuthority {
    fn resolve_security_invocation_context(
        &self,
        context: &OperationContext,
        operation: &ToolCallOperation,
    ) -> Result<SecurityInvocationContext, KernelError> {
        if context != &self.operation_context || operation.capability.id != self.capability_id {
            return Err(KernelError::GuardDenied(
                "nested context substitution".into(),
            ));
        }
        Ok(self.security_context.clone())
    }
}

fn bind_session(fixture: &mut Fixture) -> TestResult<(OperationContext, ToolCallOperation)> {
    let session = fixture.kernel.open_session_with_id(
        chio_core::session::SessionId::new(fixture.context.as_v1().session_id().as_str()),
        fixture.request.agent_id.clone(),
        vec![fixture.request.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session)?;
    let context = OperationContext::new(
        session,
        RequestId::new(&fixture.request.request_id),
        fixture.request.agent_id.clone(),
    );
    fixture
        .kernel
        .set_security_invocation_context_authority(Arc::new(BoundContextAuthority {
            operation_context: context.clone(),
            capability_id: fixture.request.capability.id.clone(),
            security_context: fixture.context.clone(),
        }));
    let operation = serde_json::from_value(serde_json::to_value(&fixture.request)?)?;
    Ok((context, operation))
}

#[test]
fn native_declassification_supports_public_nested_sync_and_async_with_all_credentials() -> TestResult
{
    use super::super::super::{declassification, nonce::execution as nonce_execution};
    for combined in [false, true] {
        for nonce in [false, true] {
            for asynchronous in [false, true] {
                let (mut fixture, _) = declassification::profile(combined, 300)?;
                let legacy = if nonce {
                    let legacy = nonce_execution::install_nonce(&mut fixture, 120);
                    nonce_execution::issue(&mut fixture)?;
                    Some(legacy)
                } else {
                    None
                };
                let (context, operation) = bind_session(&mut fixture)?;
                let mut client = NoChildRequests;
                let proofs = NestedToolCallProofs {
                    dpop_proof: fixture.request.dpop_proof.clone(),
                    declassification_grant: fixture.request.declassification_grant.clone(),
                };
                let response = if asynchronous {
                    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(
                        fixture.kernel.evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
                            &context, &operation, &mut client, proofs,
                        ),
                    )?
                } else {
                    fixture
                        .kernel
                        .evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
                            &context,
                            &operation,
                            &mut client,
                            proofs,
                        )?
                };
                assert_eq!(
                    response.verdict,
                    Verdict::Allow,
                    "combined={combined} nonce={nonce} async={asynchronous}: {:?}",
                    response.reason
                );
                assert!(
                    matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
                );
                assert!(response.receipt.verify_signature()?);
                declassification::assert_completed(&fixture, combined, nonce)?;
                if let Some(legacy) = legacy {
                    assert_eq!(legacy.load(Ordering::SeqCst), 0);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn native_nonce_supports_public_nested_sync_and_async_dispatch() -> TestResult {
    use super::super::super::nonce::execution as nonce_execution;
    for combined in [false, true] {
        for asynchronous in [false, true] {
            for egress in [false, true] {
                let mut fixture = if combined {
                    Fixture::combined_native_credentials()?
                } else {
                    Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?
                };
                let legacy = nonce_execution::configure(&mut fixture, egress)?;
                let original_id = nonce_execution::issue(&mut fixture)?;
                let (context, operation) = bind_session(&mut fixture)?;
                let mut client = NoChildRequests;
                let proofs = NestedToolCallProofs {
                    dpop_proof: fixture.request.dpop_proof.clone(),
                    declassification_grant: None,
                };
                let response = if asynchronous {
                    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(
                        fixture.kernel.evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
                            &context, &operation, &mut client, proofs,
                        ),
                    )?
                } else {
                    fixture
                        .kernel
                        .evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
                            &context,
                            &operation,
                            &mut client,
                            proofs,
                        )?
                };
                assert_eq!(
                    response.verdict,
                    Verdict::Allow,
                    "combined={combined} async={asynchronous} egress={egress}: {:?}",
                    response.reason
                );
                assert!(
                    matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
                );
                assert!(response.receipt.verify_signature()?);
                assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
                assert_eq!(legacy.load(Ordering::SeqCst), 0);
                let store = fixture.authority.admission_operation_store();
                let (completed, _) = store
                    .load_retained_tool_request(
                        &original_id,
                        &fixture.authority.mutation_fence(),
                        now_ms()?,
                    )?
                    .ok_or("original completed nonce operation")?;
                assert_eq!(completed.state(), AdmissionOperationState::Completed);
                assert!(completed.execution_nonce_id().is_some());
                assert!(completed.native_dispatch_ledger_digest().is_some());
                if combined {
                    assert_combined_completion(&fixture, egress)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn public_nested_native_capture_retains_runtime_approval_and_dpop_for_local_and_egress(
) -> TestResult {
    for async_native in [false, true] {
        for egress in [false, true] {
            let mut fixture = Fixture::combined_native_credentials()?;
            let (context, operation) = bind_session(&mut fixture)?;
            let ledger = run_capture_through(&mut fixture, egress, |fixture| {
                let proofs = NestedToolCallProofs {
                    dpop_proof: fixture.request.dpop_proof.clone(),
                    declassification_grant: None,
                };
                let mut client = NoChildRequests;
                Ok(if async_native {
                    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(
                        fixture.kernel.evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
                            &context, &operation, &mut client, proofs,
                        ),
                    )?
                } else {
                    fixture
                        .kernel
                        .evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
                            &context,
                            &operation,
                            &mut client,
                            proofs,
                        )?
                })
            })?;
            assert_combined_capture(fixture, &ledger)?;
        }
    }
    Ok(())
}

#[test]
fn native_captured_lifecycle_supports_public_nested_sync_and_async_dispatch() -> TestResult {
    for combined in [false, true] {
        for async_native in [false, true] {
            for egress in [false, true] {
                let mut fixture = if combined {
                    Fixture::combined_native_credentials()?
                } else {
                    Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?
                };
                let (context, operation) = bind_session(&mut fixture)?;
                fixture.kernel.set_security_pre_dispatch_hook(Arc::new(
                    NativeFlowResolver::new(
                        fixture.binding.clone(),
                        super::super::super::super::registry(egress, InformationLabel::bottom())?,
                        Arc::new(CountingEmptyClassifier::new()),
                        Arc::new(Clock::default()),
                        flow_config(),
                    )?
                    .with_captured_lifecycle(),
                ));
                let mut client = NoChildRequests;
                let proofs = NestedToolCallProofs {
                    dpop_proof: fixture.request.dpop_proof.clone(),
                    declassification_grant: None,
                };
                let response = if async_native {
                    tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(
                        fixture
                            .kernel
                            .evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
                                &context,
                                &operation,
                                &mut client,
                                proofs,
                            ),
                    )?
                } else {
                    fixture
                        .kernel
                        .evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
                            &context,
                            &operation,
                            &mut client,
                            proofs,
                        )?
                };
                assert_eq!(
                    response.verdict,
                    Verdict::Allow,
                    "combined={combined} async={async_native} egress={egress}: {:?}",
                    response.reason
                );
                assert!(
                    matches!(&response.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &fixture.request.arguments)
                );
                assert!(response.receipt.verify_signature()?);
                assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
                assert_eq!(fixture.hook.legacy_dispatch.load(Ordering::SeqCst), 0);
                if combined {
                    assert_combined_completion(&fixture, egress)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn public_nested_declassification_proof_reaches_native_untrusted_issuer_denial() -> TestResult {
    for async_native in [false, true] {
        let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
        let (context, operation) = bind_session(&mut fixture)?;
        let grant = declassifying_flow_request(
            &Keypair::generate(),
            &DeclassificationPurpose::new("support")?,
        )
        .declassification_grant
        .ok_or("signed grant absent")?;
        assert!(grant.verify_signature()?);
        let classifier = Arc::new(CountingEmptyClassifier::new());
        fixture
            .kernel
            .set_security_pre_dispatch_hook(Arc::new(NativeFlowResolver::new(
                fixture.binding.clone(),
                super::super::super::super::registry(false, InformationLabel::bottom())?,
                classifier.clone(),
                Arc::new(Clock::default()),
                flow_config(),
            )?));
        let proofs = NestedToolCallProofs {
            dpop_proof: None,
            declassification_grant: Some(grant),
        };
        let mut client = NoChildRequests;
        let response = if async_native {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(
                    fixture
                        .kernel
                        .evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
                            &context,
                            &operation,
                            &mut client,
                            proofs,
                        ),
                )?
        } else {
            fixture
                .kernel
                .evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
                    &context,
                    &operation,
                    &mut client,
                    proofs,
                )?
        };
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(
            response.reason.as_deref().is_some_and(
                |reason| reason.contains("declassification authority is not currently trusted")
            ),
            "{:?}",
            response.reason
        );
        assert!(response.output.is_none());
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.hook.legacy_dispatch.load(Ordering::SeqCst), 0);
        assert_eq!(classifier.calls.load(Ordering::SeqCst), 0);
        if let Some(usage) = fixture
            .authority
            .budget_store()
            .get_invocation_quota_usage(&BudgetQuotaKey::grant(&fixture.request.capability.id, 0))?
        {
            assert_eq!(
                (usage.reserved_invocations, usage.captured_invocations),
                (0, 0)
            );
        }
    }
    Ok(())
}
