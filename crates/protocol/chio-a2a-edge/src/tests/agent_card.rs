// ---- Constructor and Agent Card tests ----

fn assert_invalid_agent_card_config_rejected(config: A2aEdgeConfig, expected: &str) {
    let error = match ChioA2aEdge::new(config, vec![test_manifest()]) {
        Ok(_) => panic!("A2A edge must reject invalid Agent Card config"),
        Err(error) => error,
    };

    let A2aEdgeError::InvalidRequest(message) = error else {
        panic!("expected invalid request error");
    };
    assert_eq!(message, expected);
}

#[test]
fn edge_rejects_manifest_with_unsupported_schema_version() {
    let mut manifest = test_manifest();
    manifest.schema = "chio.manifest.v0".to_string();
    manifest.public_key = manifest_public_key(99);

    let error = match ChioA2aEdge::new(A2aEdgeConfig::default(), vec![manifest]) {
        Ok(_) => panic!("A2A edge must reject unsupported manifest schema versions"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        A2aEdgeError::Manifest(chio_manifest::ManifestError::UnsupportedSchema(schema))
            if schema == "chio.manifest.v0"
    ));
}

#[test]
fn edge_rejects_blank_agent_card_name_before_publication() {
    let config = A2aEdgeConfig {
        agent_name: "  ".to_string(),
        ..A2aEdgeConfig::default()
    };

    assert_invalid_agent_card_config_rejected(config, "agent card name must not be empty");
}

#[test]
fn edge_rejects_blank_agent_card_version_before_publication() {
    let config = A2aEdgeConfig {
        agent_version: String::new(),
        ..A2aEdgeConfig::default()
    };

    assert_invalid_agent_card_config_rejected(config, "agent card version must not be empty");
}

#[test]
fn edge_rejects_blank_agent_card_endpoint_before_publication() {
    let config = A2aEdgeConfig {
        endpoint_url: "\t".to_string(),
        ..A2aEdgeConfig::default()
    };

    assert_invalid_agent_card_config_rejected(config, "agent card endpoint URL must not be empty");
}

#[test]
fn edge_rejects_padded_agent_card_endpoint_before_publication() {
    let config = A2aEdgeConfig {
        endpoint_url: " https://agent.example/a2a".to_string(),
        ..A2aEdgeConfig::default()
    };

    assert_invalid_agent_card_config_rejected(
        config,
        "agent card endpoint URL must not include leading or trailing whitespace",
    );
}

#[test]
fn edge_rejects_blank_agent_card_protocol_binding_before_publication() {
    let config = A2aEdgeConfig {
        protocol_binding: "\n".to_string(),
        ..A2aEdgeConfig::default()
    };

    assert_invalid_agent_card_config_rejected(
        config,
        "agent card protocol binding must not be empty",
    );
}

#[test]
fn edge_rejects_padded_agent_card_protocol_binding_before_publication() {
    let config = A2aEdgeConfig {
        protocol_binding: "JSONRPC ".to_string(),
        ..A2aEdgeConfig::default()
    };

    assert_invalid_agent_card_config_rejected(
        config,
        "agent card protocol binding must not include leading or trailing whitespace",
    );
}

#[test]
fn agent_card_default_config_fields_stay_stable() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let card = edge.agent_card();

    assert_eq!(card.name, "Chio A2A Edge");
    assert_eq!(
        card.description,
        "Chio-governed tools exposed as A2A skills"
    );
    assert_eq!(card.version, "0.1.0");
    assert_eq!(card.supported_interfaces.len(), 1);
    assert_eq!(card.supported_interfaces[0].url, "http://localhost:8080");
    assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
    assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
}

#[test]
fn agent_card_has_correct_name() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let card = edge.agent_card();
    assert_eq!(card.name, "Chio A2A Edge");
}

#[test]
fn agent_card_has_correct_version() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let card = edge.agent_card();
    assert_eq!(card.version, "0.1.0");
}

#[test]
fn agent_card_includes_all_skills() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let card = edge.agent_card();
    assert_eq!(card.skills.len(), 2);
    assert!(card.skills.iter().any(|s| s.id == "echo"));
    assert!(card.skills.iter().any(|s| s.id == "write"));
}

#[test]
fn agent_card_has_interface() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let card = edge.agent_card();
    assert_eq!(card.supported_interfaces.len(), 1);
    assert_eq!(card.supported_interfaces[0].protocol_binding, "JSONRPC");
    assert_eq!(card.supported_interfaces[0].protocol_version, "1.0");
}

#[test]
fn agent_card_json_serializes() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let json_str = edge.agent_card_json().test_unwrap();
    let parsed: Value = serde_json::from_str(&json_str).test_unwrap();
    assert_eq!(parsed["name"], "Chio A2A Edge");
}

#[test]
fn agent_card_custom_config() {
    let config = A2aEdgeConfig {
        agent_name: "My Agent".to_string(),
        agent_description: "Custom agent".to_string(),
        agent_version: "2.0.0".to_string(),
        endpoint_url: "https://myagent.com".to_string(),
        protocol_binding: "HTTP+JSON".to_string(),
    };
    let edge = ChioA2aEdge::new(config, vec![test_manifest()]).test_unwrap();
    let card = edge.agent_card();
    assert_eq!(card.name, "My Agent");
    assert_eq!(card.description, "Custom agent");
    assert!(card.capabilities.streaming);
    assert_eq!(card.supported_interfaces[0].url, "https://myagent.com");
    assert_eq!(card.supported_interfaces[0].protocol_binding, "HTTP+JSON");
}

// ---- BridgeFidelity tests ----

#[test]
fn read_only_tool_has_lossless_fidelity() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let skill = edge.skill("echo").test_unwrap();
    assert_eq!(skill.bridge_fidelity, BridgeFidelity::Lossless);
}

#[test]
fn side_effect_tool_has_adapted_fidelity_with_permission_caveat() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let skill = edge.skill("write").test_unwrap();
    let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
        panic!("expected adapted fidelity");
    };
    assert!(caveats
        .iter()
        .any(|c| c.contains("permission prompts") || c.contains("capability enforcement")));
}

#[test]
fn approval_required_tool_is_not_auto_published() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![approval_manifest()]).test_unwrap();
    assert!(edge.skill("approve").is_none());
    assert_eq!(
        edge.bridge_fidelity("approve"),
        Some(&BridgeFidelity::Unsupported {
            reason: "requires interactive approval semantics that the current A2A edge cannot truthfully project".to_string()
        })
    );
}

#[test]
fn cancellation_tool_is_adapted_with_truthful_caveats() {
    let edge =
        ChioA2aEdge::new(A2aEdgeConfig::default(), vec![cancellation_manifest()]).test_unwrap();
    let skill = edge.skill("cancel_me").test_unwrap();
    let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
        panic!("expected adapted fidelity");
    };
    assert!(caveats
        .iter()
        .any(|c| c.contains("cancellation is available only for deferred `message/stream` tasks")));
}

#[test]
fn hidden_tool_is_not_auto_published() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![hidden_manifest()]).test_unwrap();
    assert!(edge.skill("hidden").is_none());
    assert_eq!(
        edge.bridge_fidelity("hidden"),
        Some(&BridgeFidelity::Unsupported {
            reason: "publication disabled by x-chio-publish=false".to_string()
        })
    );
}

#[test]
fn streaming_tool_is_adapted_with_truthful_caveats() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![stream_manifest()]).test_unwrap();
    let skill = edge.skill("stream").test_unwrap();
    let BridgeFidelity::Adapted { caveats } = &skill.bridge_fidelity else {
        panic!("expected adapted fidelity");
    };
    assert!(caveats.iter().any(|c| c.contains("deferred tasks")));
    assert!(caveats.iter().any(|c| c.contains("terminal task payload")));
}

// ---- Skill lookup tests ----

#[test]
fn skill_ids_returns_all() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    let ids = edge.skill_ids();
    assert_eq!(ids.len(), 2);
}

#[test]
fn skill_returns_none_for_unknown() {
    let edge = ChioA2aEdge::new(A2aEdgeConfig::default(), vec![test_manifest()]).test_unwrap();
    assert!(edge.skill("nonexistent").is_none());
}
