use super::*;
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RequestId, RootDefinition, SessionOperation,
    ToolCallOperation,
};
use chio_kernel::{NestedFlowClient, NestedToolCallProofs, SessionOperationResponse};

fn operation(route: &DpopRoute, proof: &DpopProof) -> Result<ToolCallOperation, serde_json::Error> {
    serde_json::from_value(serde_json::json!({
        "capability": route.capability,
        "server_id": SERVER,
        "tool_name": TOOL,
        "arguments": arguments(),
        "dpop_proof": proof
    }))
}

fn assert_replay_refused(
    response: &ToolCallResponse,
    route: &DpopRoute,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.output.is_none());
    assert_eq!(response.reason.as_deref(), Some(SPENT_PROOF_REASON));
    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.pointer("/chio_kernel/rejection_code"))
            .and_then(serde_json::Value::as_str),
        Some("CHIO-KERNEL-DURABLE-ADMISSION")
    );
    assert!(response.receipt.verify_integrity_embedded_key()?);
    assert_eq!(route.prepares.load(Ordering::SeqCst), 2);
    assert_eq!(route.invocations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn sqlite_session_preserves_proof_and_refuses_replay() -> Result<(), Box<dyn Error>> {
    let route = DpopRoute::new()?;
    route.prepares.store(1, Ordering::SeqCst);
    let subject = route.agent.public_key().to_hex();
    let session = route
        .kernel
        .open_session(subject.clone(), vec![route.capability.clone()])?;
    route.kernel.activate_session(&session)?;
    let proof = route.proof("session-proof-nonce")?;
    let operation = SessionOperation::ToolCall(Box::new(operation(&route, &proof)?));
    let first = route.kernel.evaluate_session_operation(
        &OperationContext::new(
            session.clone(),
            RequestId::new("session-first"),
            subject.clone(),
        ),
        &operation,
    )?;
    let SessionOperationResponse::ToolCall(first) = first else {
        return Err("tool response missing".into());
    };
    assert_eq!(first.verdict, Verdict::Allow, "{:?}", first.reason);
    assert!(first.output.is_some());
    assert_eq!(route.invocations.load(Ordering::SeqCst), 1);
    let replay = route.kernel.evaluate_session_operation(
        &OperationContext::new(session, RequestId::new("session-replay"), subject),
        &operation,
    )?;
    let SessionOperationResponse::ToolCall(replay) = replay else {
        return Err("tool response missing".into());
    };
    assert_replay_refused(&replay, &route)
}

#[test]
fn sqlite_nested_equal_proofs_coalesce_and_replays_never_dispatch() -> Result<(), Box<dyn Error>> {
    for asynchronous in [false, true] {
        let route = DpopRoute::new()?;
        route.prepares.store(1, Ordering::SeqCst);
        let subject = route.agent.public_key().to_hex();
        let session = route
            .kernel
            .open_session(subject.clone(), vec![route.capability.clone()])?;
        route.kernel.activate_session(&session)?;
        let proof = route.proof("nested-identical")?;
        let operation = operation(&route, &proof)?;
        let mut client = NoNestedCalls;
        for (request, explicit, expected) in [
            ("nested-conflict", route.proof("conflicting-proof")?, None),
            ("nested-honest", proof.clone(), Some(Verdict::Allow)),
            ("nested-replay", proof, Some(Verdict::Deny)),
        ] {
            let context =
                OperationContext::new(session.clone(), RequestId::new(request), subject.clone());
            let proofs = NestedToolCallProofs {
                dpop_proof: Some(explicit),
                declassification_grant: None,
            };
            let response = if asynchronous {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(
                        route
                            .kernel
                            .evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
                                &context,
                                &operation,
                                &mut client,
                                proofs,
                            ),
                    )
            } else {
                route
                    .kernel
                    .evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
                        &context,
                        &operation,
                        &mut client,
                        proofs,
                    )
            };
            match expected {
                None => {
                    assert!(matches!(response, Err(KernelError::InvalidConstraint(_))));
                    assert_eq!(route.invocations.load(Ordering::SeqCst), 0);
                }
                Some(Verdict::Allow) => {
                    let response = response?;
                    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
                    assert!(response.output.is_some());
                    assert_eq!(route.invocations.load(Ordering::SeqCst), 1);
                }
                _ => assert_replay_refused(&response?, &route)?,
            }
        }
    }
    Ok(())
}

struct NoNestedCalls;

impl NestedFlowClient for NoNestedCalls {
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
