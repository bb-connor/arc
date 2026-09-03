use chio_core::Keypair;
use chio_manifest::{
    sign_manifest, validate_manifest, verify_manifest, LatencyHint, ManifestError,
    RuntimeToolTopology, ServerTool, ToolAnnotations, ToolDefinition, ToolManifest,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use serde_json::json;

fn sample_manifest(server_tools: Vec<ServerTool>) -> ToolManifest {
    let keypair = Keypair::from_seed(&[9u8; 32]);
    ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "srv-anthropic".into(),
        name: "Anthropic tools".to_string(),
        description: Some("server tool gate".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "regular_tool".to_string(),
            description: "Regular client-hosted tool".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: Some(json!({"type": "object"})),
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
                estimated_duration_ms: None,
            },
            latency_hint: Some(LatencyHint::Fast),
            flow: None,
        }],
        server_tools,
        required_permissions: None,
        public_key: keypair.public_key().to_hex(),
    }
}

#[test]
fn server_tools_default_to_empty_allowlist() -> Result<(), Box<dyn std::error::Error>> {
    let public_key = Keypair::from_seed(&[12u8; 32]).public_key().to_hex();
    let json = json!({
        "schema": TOOL_MANIFEST_SCHEMA,
        "server_id": "srv-anthropic",
        "name": "Anthropic tools",
        "description": "server tool gate",
        "version": "1.0.0",
        "tools": [{
            "name": "regular_tool",
            "description": "Regular client-hosted tool",
            "input_schema": {"type": "object"},
            "output_schema": {"type": "object"},
            "annotations": {
                "read_only": true,
                "destructive": false,
                "idempotent": true,
                "requires_approval": false
            },
            "latency_hint": "fast"
        }],
        "public_key": public_key
    });
    let manifest: ToolManifest = serde_json::from_value(json)?;

    assert!(manifest.server_tools.is_empty());
    assert!(!manifest.allows_server_tool(ServerTool::ComputerUse));
    assert!(!manifest.allows_server_tool(ServerTool::Bash));
    assert!(!manifest.allows_server_tool(ServerTool::TextEditor));
    Ok(())
}

#[test]
fn server_tools_allowlist_round_trips_and_signs() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::from_seed(&[11u8; 32]);
    let mut manifest = sample_manifest(vec![ServerTool::ComputerUse, ServerTool::TextEditor]);
    manifest.public_key = keypair.public_key().to_hex();

    validate_manifest(&manifest)?;
    assert!(manifest.allows_server_tool(ServerTool::ComputerUse));
    assert!(!manifest.allows_server_tool(ServerTool::Bash));
    assert!(manifest.allows_server_tool(ServerTool::TextEditor));

    let encoded = serde_json::to_value(&manifest)?;
    assert_eq!(
        encoded.get("server_tools"),
        Some(&json!(["computer_use", "text_editor"]))
    );

    let signed = sign_manifest(&manifest, &keypair)?;
    verify_manifest(&signed, &keypair.public_key())?;
    Ok(())
}

#[test]
fn duplicate_server_tools_reject_at_validation() {
    let manifest = sample_manifest(vec![ServerTool::Bash, ServerTool::Bash]);

    assert!(matches!(
        validate_manifest(&manifest),
        Err(ManifestError::DuplicateServerTool(tool)) if tool == "bash"
    ));
}

#[test]
fn regular_tools_cannot_claim_reserved_anthropic_server_tool_wire_names() {
    for (wire_name, server_tool) in [
        ("computer_use", ServerTool::ComputerUse),
        ("computer_use_20241022", ServerTool::ComputerUse),
        ("bash", ServerTool::Bash),
        ("bash_20241022", ServerTool::Bash),
        ("text_editor", ServerTool::TextEditor),
        ("text_editor_20241022", ServerTool::TextEditor),
    ] {
        let mut manifest = sample_manifest(vec![server_tool]);
        manifest.tools[0].name = wire_name.to_string();

        assert!(
            validate_manifest(&manifest).is_err(),
            "regular tool must not claim reserved server-tool wire name {wire_name}"
        );
    }
}

#[test]
fn signed_manifest_admission_rejects_regular_server_tool_namespace_collision() {
    let signer = Keypair::from_seed(&[13u8; 32]);
    let mut manifest = sample_manifest(vec![ServerTool::Bash]);
    manifest.public_key = signer.public_key().to_hex();
    manifest.tools[0].name = "bash_20241022".to_string();
    let mut registry = VerifiedManifestRegistry::default();

    if let Ok(signed) = sign_manifest(&manifest, &signer) {
        let admission = registry.register_public_only(
            signed,
            &signer.public_key(),
            RuntimeToolTopology::remote(),
        );
        assert!(
            admission.is_err(),
            "verified registry must reject a regular tool that aliases admitted server tool bash"
        );
    }
    assert!(registry.verified_manifest("srv-anthropic").is_none());
}

#[test]
fn anthropic_wire_names_map_to_stable_allowlist_entries() {
    assert_eq!(
        ServerTool::from_anthropic_wire_name("computer_use_20241022"),
        Some(ServerTool::ComputerUse)
    );
    assert_eq!(
        ServerTool::from_anthropic_wire_name("bash_20241022"),
        Some(ServerTool::Bash)
    );
    assert_eq!(
        ServerTool::from_anthropic_wire_name("text_editor_20241022"),
        Some(ServerTool::TextEditor)
    );
    assert_eq!(ServerTool::from_anthropic_wire_name("custom_bash"), None);
}
