use chio_core::Keypair;
use chio_manifest::{
    sign_manifest, validate_manifest, verify_manifest, LatencyHint, ToolDefinition, ToolManifest,
};

#[test]
fn manifest_sign_and_verify_roundtrip_uses_public_api() {
    let keypair = Keypair::from_seed(&[5u8; 32]);
    let manifest = ToolManifest {
        schema: "chio.manifest.v1".to_string(),
        server_id: "srv-test".into(),
        name: "Test Server".to_string(),
        description: Some("integration smoke".to_string()),
        version: "1.0.0".to_string(),
        tools: vec![ToolDefinition {
            name: "echo".to_string(),
            description: "Echo input".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: Some(serde_json::json!({"type": "object"})),
            pricing: None,
            has_side_effects: false,
            latency_hint: Some(LatencyHint::Instant),
        }],
        required_permissions: None,
        public_key: keypair.public_key().to_hex(),
    };

    validate_manifest(&manifest).expect("manifest validates");
    let signed = sign_manifest(&manifest, &keypair).expect("manifest signs");
    verify_manifest(&signed, &keypair.public_key()).expect("manifest verifies");
}
