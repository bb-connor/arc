use super::*;

#[test]
fn inbound_authority_session_preserves_proof_and_refuses_replay() {
    let agent = Keypair::generate();
    let (kernel, capability) = make_dpop_kernel_and_cap(&agent, "proof-srv", "read");
    let session_id = kernel
        .open_session(agent.public_key().to_hex(), vec![capability.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let arguments = serde_json::json!({"document": "notes"});
    let proof = make_dpop_proof(
        &agent,
        &capability,
        "proof-srv",
        "read",
        &arguments,
        "session-proof-nonce",
    );
    let operation: ToolCallOperation = serde_json::from_value(serde_json::json!({
        "capability": capability, "server_id": "proof-srv", "tool_name": "read",
        "arguments": arguments, "dpop_proof": proof
    }))
    .unwrap();
    let operation = SessionOperation::ToolCall(Box::new(operation));
    let first = kernel
        .evaluate_session_operation(
            &make_operation_context(&session_id, "proof-first", &agent.public_key().to_hex()),
            &operation,
        )
        .unwrap();
    let first = session_tool_call(first).unwrap();
    assert_eq!(first.verdict, Verdict::Allow, "{:?}", first.reason);
    assert!(first.output.is_some());
    let replay = kernel
        .evaluate_session_operation(
            &make_operation_context(&session_id, "proof-replay", &agent.public_key().to_hex()),
            &operation,
        )
        .unwrap();
    let replay = session_tool_call(replay).unwrap();
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(replay.output.is_none());
    assert!(
        replay.reason.as_deref().unwrap().contains("nonce"),
        "{:?}",
        replay.reason
    );
}

#[test]
fn inbound_authority_nested_equal_proofs_coalesce_and_conflicts_refuse() {
    for asynchronous in [false, true] {
        let agent = Keypair::generate();
        let (kernel, cap) = make_dpop_kernel_and_cap(&agent, "proof-srv", "read");
        let subject = agent.public_key().to_hex();
        let session = kernel
            .open_session(subject.clone(), vec![cap.clone()])
            .unwrap();
        kernel.activate_session(&session).unwrap();
        let arguments = serde_json::json!({"document":"notes"});
        let proof = make_dpop_proof(
            &agent,
            &cap,
            "proof-srv",
            "read",
            &arguments,
            "nested-identical",
        );
        let foreign = make_dpop_proof(
            &agent,
            &cap,
            "proof-srv",
            "read",
            &arguments,
            "nested-conflict",
        );
        let operation: ToolCallOperation = serde_json::from_value(serde_json::json!({
            "capability":cap,"server_id":"proof-srv","tool_name":"read","arguments":arguments,"dpop_proof":proof
        })).unwrap();
        let mut client = NoopNestedFlowClient;
        for (request, explicit, allowed) in [
            ("conflict", foreign, None),
            ("honest", proof.clone(), Some(true)),
            ("replay", proof, Some(false)),
        ] {
            let context = make_operation_context(&session, request, &subject);
            let proofs = crate::NestedToolCallProofs {
                dpop_proof: Some(explicit),
                declassification_grant: None,
            };
            let response = if asynchronous {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(
                        kernel
                            .evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async(
                                &context,
                                &operation,
                                &mut client,
                                proofs,
                            ),
                    )
            } else {
                kernel.evaluate_tool_call_operation_with_nested_flow_client_and_proofs(
                    &context,
                    &operation,
                    &mut client,
                    proofs,
                )
            };
            if let Some(allowed) = allowed {
                let response = response.unwrap();
                assert_eq!(
                    response.verdict,
                    if allowed {
                        Verdict::Allow
                    } else {
                        Verdict::Deny
                    },
                    "{:?}",
                    response.reason
                );
                assert_eq!(response.output.is_some(), allowed);
            } else {
                assert!(matches!(response, Err(KernelError::InvalidConstraint(_))));
            }
        }
    }
}
