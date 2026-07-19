#[test]
fn plan_authoritative_route_prefers_registered_protocol_from_governed_intent() {
    let executor = MockMcpExecutor;
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
    let planning = plan_authoritative_route(
        "req-route-preferred",
        DiscoveryProtocol::A2a,
        DiscoveryProtocol::Native,
        Some(&governed_intent_with_control_plane(json!({
            "preferredTargetProtocol": "mcp",
            "allowNativeFallback": true
        }))),
        &registry,
        &BTreeMap::new(),
    )
    .unwrap();

    assert_eq!(
        planning.selected_target_protocol,
        Some(DiscoveryProtocol::Mcp)
    );
    assert_eq!(
        planning.evidence.decision,
        RouteSelectionDecision::Attenuate
    );
    assert_eq!(
        planning.evidence.selected_target_protocol,
        Some(DiscoveryProtocol::Mcp)
    );
}

#[test]
fn plan_authoritative_route_attentuates_to_native_fallback_when_requested_route_is_unavailable() {
    let mut availability = BTreeMap::new();
    availability.insert(
        DiscoveryProtocol::Mcp,
        RouteAvailabilityStatus::unavailable("mcp route unavailable"),
    );
    let executor = MockMcpExecutor;
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
    let planning = plan_authoritative_route(
        "req-route-fallback",
        DiscoveryProtocol::A2a,
        DiscoveryProtocol::Mcp,
        Some(&governed_intent_with_control_plane(json!({
            "allowNativeFallback": true
        }))),
        &registry,
        &availability,
    )
    .unwrap();

    assert_eq!(
        planning.selected_target_protocol,
        Some(DiscoveryProtocol::Native)
    );
    assert_eq!(
        planning.evidence.decision,
        RouteSelectionDecision::Attenuate
    );
    assert_eq!(
        planning.evidence.reason.as_deref(),
        Some("requested target protocol unavailable; attenuated to native fallback")
    );
}

#[test]
fn plan_authoritative_route_denies_when_projected_protocols_are_disallowed_without_native() {
    let executor = MockMcpExecutor;
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native).with_executor(&executor);
    let mut availability = BTreeMap::new();
    availability.insert(
        DiscoveryProtocol::Native,
        RouteAvailabilityStatus::unavailable("native route unavailable"),
    );

    let planning = plan_authoritative_route(
        "req-route-deny",
        DiscoveryProtocol::A2a,
        DiscoveryProtocol::Mcp,
        Some(&governed_intent_with_control_plane(json!({
            "disallowProjectedProtocols": true
        }))),
        &registry,
        &availability,
    )
    .unwrap();

    assert_eq!(planning.selected_target_protocol, None);
    assert_eq!(planning.evidence.decision, RouteSelectionDecision::Deny);
    assert_eq!(
        planning.evidence.reason.as_deref(),
        Some("governed intent disallowed projected protocols and no native route was available")
    );
}

#[test]
fn plan_authoritative_route_denies_unregistered_target_even_when_marked_available() {
    let registry = TargetProtocolRegistry::new(DiscoveryProtocol::Native);
    let mut availability = BTreeMap::new();
    availability.insert(DiscoveryProtocol::Mcp, RouteAvailabilityStatus::available());

    let planning = plan_authoritative_route(
        "req-route-unregistered-available",
        DiscoveryProtocol::A2a,
        DiscoveryProtocol::Mcp,
        None,
        &registry,
        &availability,
    )
    .unwrap();

    assert_eq!(planning.selected_target_protocol, None);
    assert_eq!(planning.evidence.decision, RouteSelectionDecision::Deny);
    assert_eq!(planning.evidence.selected_target_protocol, None);
    assert_eq!(planning.evidence.candidates.len(), 1);
    assert!(!planning.evidence.candidates[0].available);
    assert_eq!(
        planning.evidence.candidates[0]
            .availability_reason
            .as_deref(),
        Some("target protocol `mcp` is not registered")
    );
}

#[test]
fn schema_extension_returns_named_extension_only_for_object_schema() {
    let schema = json!({
        "type": "object",
        "x-chio-publish": false
    });

    assert_eq!(
        schema_extension(&schema, "x-chio-publish"),
        Some(&Value::Bool(false))
    );
    assert_eq!(schema_extension(&schema, "x-chio-missing"), None);
    assert_eq!(
        schema_extension(&Value::String("not-object".to_string()), "x"),
        None
    );
}

#[test]
fn semantic_hints_respect_extensions_and_defaults() {
    let explicit = semantic_tool(
        "explicit",
        Some(LatencyHint::Fast),
        json!({
            "type": "object",
            "x-chio-publish": false,
            "x-chio-approval-required": true,
            "x-chio-cancellation": true
        }),
        Some(json!({
            "type": "object",
            "x-chio-streaming": true,
            "x-chio-partial-output": true
        })),
    );
    let explicit_hints = semantic_hints_for_tool(&explicit);
    assert!(!explicit_hints.publish);
    assert!(explicit_hints.approval_required);
    assert!(explicit_hints.streams_output);
    assert!(explicit_hints.supports_cancellation);
    assert!(explicit_hints.partial_output);

    let fallback = semantic_tool(
        "fallback",
        Some(LatencyHint::Slow),
        json!({"type": "object"}),
        None,
    );
    let fallback_hints = semantic_hints_for_tool(&fallback);
    assert!(fallback_hints.publish);
    assert!(!fallback_hints.approval_required);
    assert!(fallback_hints.streams_output);
    assert!(fallback_hints.supports_cancellation);
    assert!(fallback_hints.partial_output);
}

#[test]
fn runtime_lifecycle_contract_serializes_shared_surface_metadata() {
    let lifecycle = runtime_lifecycle_contract(RuntimeLifecycleSurface::A2aAuthoritative);
    let json = serde_json::to_value(lifecycle).unwrap();
    assert_eq!(json["surface"], "a2a_authoritative");
    assert_eq!(json["blockingEntrypoint"], "message/send");
    assert_eq!(json["streamEntrypoint"], "message/stream");
    assert_eq!(json["followUpEntrypoint"], "task/get");
    assert_eq!(json["cancelEntrypoint"], "task/cancel");
    assert_eq!(json["claimEligible"], true);
    assert_eq!(json["compatibilityOnly"], false);
}

#[test]
fn bridge_fidelity_helpers_report_publication_state() {
    let lossless = BridgeFidelity::Lossless;
    assert!(lossless.published_by_default());
    assert!(lossless.caveats().is_empty());
    assert_eq!(lossless.unsupported_reason(), None);

    let adapted = BridgeFidelity::Adapted {
        caveats: vec!["partial output collated".to_string()],
    };
    assert!(adapted.published_by_default());
    assert_eq!(adapted.caveats(), ["partial output collated"]);
    assert_eq!(adapted.unsupported_reason(), None);

    let unsupported = BridgeFidelity::Unsupported {
        reason: "interactive permission prompt required".to_string(),
    };
    assert!(!unsupported.published_by_default());
    assert!(unsupported.caveats().is_empty());
    assert_eq!(
        unsupported.unsupported_reason(),
        Some("interactive permission prompt required")
    );
}
