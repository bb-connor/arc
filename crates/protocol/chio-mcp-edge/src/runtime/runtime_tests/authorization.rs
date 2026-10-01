use super::*;

#[cfg(test)]
mod authorization_projection {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/bindings/support/authorization_projection.rs"
    ));
}

#[test]
fn bridge_mcp_kernel_request_preserves_complete_authorization_context() {
    let expected = authorization_projection::complete_wire_request();
    let request = BridgeMcpToolCallRequest {
        request_id: expected.request_id.clone(),
        capability: expected.capability.clone(),
        server_id: expected.server_id.clone(),
        tool_name: expected.tool_name.clone(),
        arguments: expected.arguments.clone(),
        agent_id: expected.agent_id.clone(),
        dpop_proof: expected.dpop_proof.clone(),
        peer_capabilities: crate::authorization::authorization_capabilities(),
        execution_nonce: expected.execution_nonce.clone(),
        governed_intent: expected.governed_intent.clone(),
        approval_token: expected.approval_token.clone(),
        approval_tokens: expected.approval_tokens.clone(),
        threshold_approval_proposal: expected.threshold_approval_proposal.clone(),
        supplemental_authorization: expected.supplemental_authorization.clone(),
        model_metadata: expected.model_metadata.clone(),
        route_selection_metadata: None,
        peer_supports_chio_tool_streaming: false,
    };
    let actual = request.kernel_request();
    actual
        .validate_peer_capabilities(&request.peer_capabilities)
        .unwrap();
    authorization_projection::assert_authorization_preserved(&expected, &actual);
}

pub(super) fn initialize_authorization_edge(edge: &mut ChioMcpEdge, profile: Value) {
    let response = edge
        .handle_jsonrpc(json!({
            "jsonrpc":"2.0", "id":1, "method":"initialize", "params":{
                "capabilities":{"experimental":{"chioAuthorization":profile}}
            }
        }))
        .unwrap();
    assert!(response.get("error").is_none(), "{response}");
    edge.handle_jsonrpc(json!({"jsonrpc":"2.0", "method":"notifications/initialized"}));
}

#[test]
fn tools_call_meta_preserves_complete_authorization_context() {
    let mut edge = make_edge(10);
    let mut expected = authorization_projection::complete_wire_request();
    let aggregate = expected.capability.aggregate_invocation_budget.clone();
    let constraints = expected.capability.scope.grants[0].constraints.clone();
    expected.capability = edge.capabilities[0].clone();
    expected.capability.aggregate_invocation_budget = aggregate;
    expected.capability.scope.grants[0]
        .constraints
        .extend(constraints);
    edge.capabilities[0] = expected.capability.clone();
    // This session surface receives caller authentication from its host, not
    // from a DPoP value supplied in tools/call metadata.
    expected.dpop_proof = None;
    initialize_authorization_edge(
        &mut edge,
        json!(crate::authorization::authorization_capabilities()),
    );
    let params = json!({"name":"read_file", "arguments":{"path":"/tmp/readme"}, "_meta":{
        "chioRequestId":"request",
        "chioExecutionNonce":expected.execution_nonce,
        "chioGovernedIntent":expected.governed_intent,
        "chioApprovalTokens":expected.approval_tokens,
        "chioThresholdApprovalProposal":expected.threshold_approval_proposal,
        "chioSupplementalAuthorization":expected.supplemental_authorization,
        "chioModelMetadata":expected.model_metadata
    }});
    let (_, _, operation) = edge.prepare_tool_call_request(&json!(2), &params).unwrap();
    let actual = ToolCallRequest {
        request_id: expected.request_id.clone(),
        capability: operation.capability,
        server_id: operation.server_id,
        tool_name: operation.tool_name,
        agent_id: edge.agent_id.clone(),
        arguments: operation.arguments,
        dpop_proof: None,
        execution_nonce: operation
            .execution_nonce
            .map(|value| serde_json::from_value(value).unwrap()),
        governed_intent: operation.governed_intent,
        approval_token: operation.approval_token,
        approval_tokens: operation.approval_tokens,
        threshold_approval_proposal: operation.threshold_approval_proposal,
        supplemental_authorization: operation.supplemental_authorization,
        model_metadata: operation.model_metadata,
        federated_origin_kernel_id: None,
        declassification_grant: None,
    };
    authorization_projection::assert_authorization_preserved(&expected, &actual);
}

#[test]
fn mcp_unnegotiated_authorization_extensions_deny_before_receipt_or_dispatch() {
    let mut edge = make_edge(10);
    let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    edge.kernel
        .register_tool_server(Box::new(authorization_projection::CountedToolServer {
            server: "srv".to_string(),
            tool: "read_file".to_string(),
            calls: calls.clone(),
        }));
    initialize_edge(&mut edge);
    let positive = edge
        .handle_jsonrpc(json!({"jsonrpc":"2.0", "id":2, "method":"tools/call",
        "params":{"name":"read_file","arguments":{"path":"/tmp/readme"}}}))
        .unwrap();
    assert_eq!(positive["result"]["isError"], false, "{positive}");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let receipts = edge.kernel.receipt_log().receipts().len();
    let baseline: ToolCallRequest = serde_json::from_value(json!({
        "request_id":"baseline", "capability":edge.capabilities[0], "agent_id":edge.agent_id,
        "server_id":"srv", "tool_name":"read_file", "arguments":{}
    }))
    .unwrap();
    for (index, (feature, request)) in authorization_projection::extension_cases(&baseline)
        .into_iter()
        .enumerate()
    {
        edge.capabilities[0] = request.capability.clone();
        let wire = serde_json::to_value(request).unwrap();
        let mut meta = json!({});
        for (field, meta_field) in [
            ("approval_tokens", "chioApprovalTokens"),
            (
                "threshold_approval_proposal",
                "chioThresholdApprovalProposal",
            ),
            ("governed_intent", "chioGovernedIntent"),
            (
                "supplemental_authorization",
                "chioSupplementalAuthorization",
            ),
        ] {
            if let Some(value) = wire.get(field) {
                meta[meta_field] = value.clone();
            }
        }
        meta["chioRequestId"] = json!(format!("unnegotiated-{index}"));
        meta["chioAuthorization"] = json!(crate::authorization::authorization_capabilities());
        let result = edge
            .handle_jsonrpc(
                json!({"jsonrpc":"2.0", "id":10+index, "method":"tools/call",
            "params":{"name":"read_file","arguments":{},"_meta":meta}}),
            )
            .unwrap();
        assert_eq!(result["error"]["code"], JSONRPC_INVALID_PARAMS, "{result}");
        assert!(
            result["error"]["message"]
                .as_str()
                .unwrap()
                .contains(&format!("invocation feature {feature} was not negotiated")),
            "{result}"
        );
        assert_eq!(edge.kernel.receipt_log().receipts().len(), receipts);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}

#[test]
fn mcp_authorization_negotiation_rejects_malformed_profiles_before_session_acquisition() {
    for profile in [
        Value::Null,
        json!({"schema":"wrong"}),
        json!({"features":{"threshold_governed_approvals":1}}),
        json!({"features":{"bad key":true}}),
        json!({"unknown":true}),
    ] {
        let mut edge = make_edge(10);
        let response = edge
            .handle_jsonrpc(json!({"jsonrpc":"2.0", "id":1, "method":"initialize",
            "params":{"capabilities":{"experimental":{"chioAuthorization":profile}}}}))
            .unwrap();
        assert_eq!(
            response["error"]["code"], JSONRPC_INVALID_PARAMS,
            "{response}"
        );
        assert_eq!(edge.kernel.session_count(), 0);
        assert!(edge.kernel.receipt_log().receipts().is_empty());
    }
}

#[test]
fn restored_mcp_authorization_profile_is_exact_and_legacy_sessions_do_not_upgrade() {
    use chio_core::capability::features::{
        CapabilityNegotiation, OPAQUE_SUPPLEMENTAL_AUTHORIZATION,
    };
    let supported = crate::authorization::authorization_capabilities();
    let mut disabled = supported.clone();
    disabled
        .features
        .insert(OPAQUE_SUPPLEMENTAL_AUTHORIZATION.to_string(), false);
    for profile in [None, Some(supported), Some(disabled)] {
        let peer = PeerCapabilities {
            authorization: profile.clone(),
            ..PeerCapabilities::default()
        };
        let encoded = serde_json::to_value(&peer).unwrap();
        if profile.is_none() {
            assert!(encoded.get("authorization").is_none());
        }
        let retained: PeerCapabilities = serde_json::from_value(encoded).unwrap();
        assert_eq!(retained, peer);
        let mut restored = make_edge(10);
        let session_id = SessionId::new("restored-authorization-profile");
        restored
            .restore_ready_session(session_id.clone(), retained)
            .unwrap();
        assert_eq!(
            restored
                .kernel
                .session(&session_id)
                .unwrap()
                .peer_capabilities(),
            peer
        );
        let prepared = restored.prepare_tool_call_request(
            &json!(2),
            &json!({
                "name":"read_file", "arguments":{}, "_meta":{
                    "chioRequestId":"restored-feature-request",
                    "chioSupplementalAuthorization":{"signed_extension":"opaque"},
                    "chioAuthorization":crate::authorization::authorization_capabilities()
                }
            }),
        );
        if profile
            .as_ref()
            .is_some_and(|profile| profile.supports(OPAQUE_SUPPLEMENTAL_AUTHORIZATION))
        {
            assert!(prepared.is_ok(), "{prepared:?}");
        } else {
            let error = prepared.unwrap_err();
            assert!(error["error"]["message"].as_str().unwrap().contains(
                "invocation feature opaque_supplemental_authorization was not negotiated"
            ));
        }
        assert!(restored.kernel.receipt_log().receipts().is_empty());
    }

    for invalid in [
        CapabilityNegotiation {
            schema: "wrong".to_string(),
            features: Default::default(),
        },
        CapabilityNegotiation {
            schema: chio_core::capability::features::CHIO_CAPABILITIES_SCHEMA.to_string(),
            features: [("future_authority".to_string(), true)]
                .into_iter()
                .collect(),
        },
    ] {
        let mut edge = make_edge(10);
        assert!(edge
            .restore_ready_session(
                SessionId::new("invalid-profile"),
                PeerCapabilities {
                    authorization: Some(invalid),
                    ..PeerCapabilities::default()
                }
            )
            .is_err());
        assert_eq!(edge.kernel.session_count(), 0);
    }
}
