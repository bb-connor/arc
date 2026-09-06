// ---- Deduplication tests ----

#[test]
fn duplicate_tools_across_manifests_deduplicated() {
    let m1 = test_manifest();
    let m2 = test_manifest();
    let edge = ChioAcpEdge::new(AcpEdgeConfig::default(), vec![m1, m2]).test_unwrap();
    assert_eq!(edge.capabilities().len(), 4);
}

#[test]
fn colliding_capability_ids_are_withheld_deterministically() {
    let edge = ChioAcpEdge::new(
        AcpEdgeConfig::default(),
        vec![test_manifest(), colliding_search_manifest()],
    )
    .test_unwrap();

    assert!(edge.capability("search").is_none());
    assert_eq!(edge.capabilities().len(), 3);

    let fidelity = edge
        .bridge_fidelity("search")
        .test_expect("collision should still have fidelity classification");
    let BridgeFidelity::Unsupported { reason } = fidelity else {
        panic!("colliding capability should be unsupported");
    };
    assert!(reason.contains("withheld from discovery"));
    assert!(reason.contains("other-srv/search"));
    assert!(reason.contains("test-srv/search"));
}

// ---- Error display tests ----

#[test]
fn error_display_tool_not_found() {
    let err = AcpEdgeError::ToolNotFound("x".into());
    assert!(format!("{err}").contains("x"));
}

#[test]
fn error_display_access_denied() {
    let err = AcpEdgeError::AccessDenied("no cap".into());
    assert!(format!("{err}").contains("no cap"));
}

#[test]
fn error_display_kernel() {
    let err = AcpEdgeError::Kernel("internal".into());
    assert!(format!("{err}").contains("internal"));
}

// ---- Serde tests ----

#[test]
fn bridge_fidelity_serializes() {
    assert_eq!(
        serde_json::to_value(BridgeFidelity::Lossless).test_unwrap(),
        json!({"kind": "lossless"})
    );
    assert_eq!(
        serde_json::to_value(BridgeFidelity::Adapted {
            caveats: vec!["preview only".to_string()]
        })
        .test_unwrap(),
        json!({"kind": "adapted", "caveats": ["preview only"]})
    );
    assert_eq!(
        serde_json::to_value(BridgeFidelity::Unsupported {
            reason: "not publishable".to_string()
        })
        .test_unwrap(),
        json!({"kind": "unsupported", "reason": "not publishable"})
    );
}

#[test]
fn acp_category_serializes() {
    assert_eq!(
        serde_json::to_value(AcpCategory::Tool).test_unwrap(),
        "tool"
    );
    assert_eq!(
        serde_json::to_value(AcpCategory::Filesystem).test_unwrap(),
        "filesystem"
    );
    assert_eq!(
        serde_json::to_value(AcpCategory::Terminal).test_unwrap(),
        "terminal"
    );
    assert_eq!(
        serde_json::to_value(AcpCategory::Browser).test_unwrap(),
        "browser"
    );
}

#[test]
fn permission_decision_serializes() {
    assert_eq!(
        serde_json::to_value(PermissionDecision::Allow).test_unwrap(),
        "allow"
    );
    assert_eq!(
        serde_json::to_value(PermissionDecision::Deny).test_unwrap(),
        "deny"
    );
}

// ---- Default config tests ----

#[test]
fn default_config_requires_permission() {
    let config = AcpEdgeConfig::default();
    assert!(config.require_permission);
    assert_eq!(config.default_category, AcpCategory::Tool);
}
