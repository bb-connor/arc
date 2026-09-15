use chio_core::Keypair;
use chio_manifest::{
    sign_manifest, RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolInputSchemaError,
    ToolManifest, VerifiedManifestAdmissionError, VerifiedManifestInvocationError,
    VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use serde_json::{json, Value};

fn signed_manifest(
    signer: &Keypair,
    input_schema: Value,
) -> Result<chio_manifest::SignedManifest, chio_manifest::ManifestError> {
    sign_manifest(
        &ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "schema-server".to_string(),
            name: "Schema server".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "echo".to_string(),
                description: "Echo".to_string(),
                input_schema,
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations::default(),
                latency_hint: None,
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        },
        signer,
    )
}

#[test]
fn verified_registry_rejects_local_recursive_ref() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::from_seed(&[31; 32]);
    let signed = signed_manifest(
        &signer,
        json!({
            "type": "object",
            "properties": {
                "child": {"$recursiveRef": "#"}
            }
        }),
    )?;
    let mut registry = VerifiedManifestRegistry::default();

    let error = match registry.register_public_only(
        signed,
        &signer.public_key(),
        RuntimeToolTopology::local(),
    ) {
        Ok(()) => panic!("Draft 2020-12 admission must reject $recursiveRef"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        VerifiedManifestAdmissionError::InputSchema(
            ToolInputSchemaError::RecursiveRef { tool_name }
        ) if tool_name == "echo"
    ));
    assert_eq!(registry.verified_manifests().len(), 0);
    Ok(())
}

#[test]
fn verified_registry_binds_arguments_to_signed_schema() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Keypair::from_seed(&[32; 32]);
    let signed = signed_manifest(
        &signer,
        json!({
            "type": "object",
            "properties": {
                "message": {"type": "string", "minLength": 1, "maxLength": 4}
            },
            "required": ["message"],
            "additionalProperties": false
        }),
    )?;
    let mut registry = VerifiedManifestRegistry::default();
    registry.register_public_only(signed, &signer.public_key(), RuntimeToolTopology::local())?;
    let security = match registry.bridge_security("schema-server", "echo") {
        Some(security) => security,
        None => panic!("registered tool must retain bridge security"),
    };

    assert!(matches!(
        registry.validate_invocation_arguments(
            "schema-server",
            "echo",
            &security,
            &json!({"message": true}),
        ),
        Err(VerifiedManifestInvocationError::SchemaMismatch {
            server_id,
            tool_name,
        }) if server_id == "schema-server" && tool_name == "echo"
    ));
    registry.validate_invocation_arguments(
        "schema-server",
        "echo",
        &security,
        &json!({"message": "🧪🧪🧪🧪"}),
    )?;
    Ok(())
}
