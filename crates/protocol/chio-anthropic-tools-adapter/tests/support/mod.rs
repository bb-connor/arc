use std::collections::BTreeMap;
use std::sync::Arc;

use chio_anthropic_tools_adapter::{AnthropicAdapter, AnthropicAdapterConfig, Transport};
use chio_core::Keypair;
use chio_manifest::{
    sign_manifest, RuntimeToolTopology, ServerTool, ToolAnnotations, ToolDefinition,
    ToolFlowDeclaration, ToolManifest, VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
};
use serde_json::json;

pub fn adapter(transport: Arc<dyn Transport>) -> AnthropicAdapter {
    adapter_with_manifest_options(
        transport,
        vec![
            ServerTool::ComputerUse,
            ServerTool::Bash,
            ServerTool::TextEditor,
        ],
        None,
    )
}

pub fn adapter_with_manifest_options(
    transport: Arc<dyn Transport>,
    server_tools: Vec<ServerTool>,
    regular_tool_flow: Option<ToolFlowDeclaration>,
) -> AnthropicAdapter {
    let signer = Keypair::from_seed(&[29; 32]);
    let public_key = signer.public_key().to_hex();
    let config = AnthropicAdapterConfig::new(
        "anthropic-1",
        "Anthropic Messages",
        "0.1.0",
        public_key.clone(),
        "wks_chio_demo",
    );
    let tools = [
        "get_weather",
        "search_web",
        "translate_text",
        "first",
        "second",
        "regular_tool",
    ]
    .into_iter()
    .map(|name| ToolDefinition {
        name: name.to_string(),
        description: format!("Explicit test tool {name}"),
        input_schema: json!({"type": "object"}),
        output_schema: None,
        pricing: None,
        annotations: ToolAnnotations {
            read_only: true,
            destructive: false,
            idempotent: false,
            requires_approval: false,
            estimated_duration_ms: None,
        },
        latency_hint: None,
        flow: if name == "regular_tool" {
            regular_tool_flow.clone()
        } else {
            None
        },
    })
    .collect();
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: config.server_id.clone(),
        name: config.server_name.clone(),
        description: Some("Explicit Anthropic test manifest".to_string()),
        version: config.server_version.clone(),
        tools,
        server_tools,
        required_permissions: None,
        public_key,
    };
    let signed = sign_manifest(&manifest, &signer)
        .unwrap_or_else(|error| panic!("failed to sign explicit Anthropic test manifest: {error}"));
    let policies = manifest
        .tools
        .iter()
        .map(|tool| {
            let policy = match &tool.flow {
                Some(flow) => match (&flow.input_clearance, &flow.output_label) {
                    (Some(input_clearance), Some(output_label)) => {
                        chio_manifest::AuthoritativeToolPolicy::new(
                            vec![input_clearance.clone()],
                            output_label.clone(),
                            flow.declassification_purposes.clone(),
                        )
                        .unwrap_or_else(|error| {
                            panic!("failed to build Anthropic flow policy: {error}")
                        })
                    }
                    _ => chio_manifest::AuthoritativeToolPolicy::public_only(),
                },
                None => chio_manifest::AuthoritativeToolPolicy::public_only(),
            };
            (tool.name.clone(), policy)
        })
        .chain(manifest.server_tools.iter().map(|tool| {
            (
                tool.as_str().to_string(),
                chio_manifest::AuthoritativeToolPolicy::public_only(),
            )
        }))
        .collect::<BTreeMap<_, _>>();
    let topologies = manifest
        .tools
        .iter()
        .map(|tool| (tool.name.clone(), RuntimeToolTopology::remote()))
        .chain(
            manifest
                .server_tools
                .iter()
                .map(|tool| (tool.as_str().to_string(), RuntimeToolTopology::remote())),
        )
        .collect::<BTreeMap<_, _>>();
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register(signed, &signer.public_key(), &policies, &topologies)
        .unwrap_or_else(|error| panic!("failed to admit Anthropic test manifest: {error}"));
    AnthropicAdapter::new_with_registry(config, transport, &registry)
        .unwrap_or_else(|error| panic!("failed to build Anthropic test adapter: {error}"))
}
