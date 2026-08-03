use std::collections::BTreeMap;

use chio_manifest::{LatencyHint, ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AdapterError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpExposedTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "outputSchema"
    )]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Value>,
}

#[derive(Debug, Clone)]
pub(super) struct ExposedToolBinding {
    pub(super) tool: McpExposedTool,
    pub(super) server_id: String,
    pub(super) tool_name: String,
    pub(super) input_validator: chio_manifest::ToolInputSchemaValidator,
}

pub(super) fn build_exposed_tool_bindings(
    manifests: Vec<ToolManifest>,
    registry: Option<&chio_manifest::VerifiedManifestRegistry>,
) -> Result<(Vec<ExposedToolBinding>, BTreeMap<String, usize>), AdapterError> {
    let mut tool_index = BTreeMap::new();
    let mut tools = Vec::new();

    for manifest in manifests {
        chio_manifest::validate_manifest(&manifest)?;

        for tool in manifest.tools {
            if tool_index.contains_key(&tool.name) {
                return Err(AdapterError::ManifestError(
                    chio_manifest::ManifestError::DuplicateToolName(tool.name),
                ));
            }

            let exposed_name = tool.name.clone();
            if let Some(registry) = registry {
                registry
                    .bridge_security(&manifest.server_id, &tool.name)
                    .ok_or_else(|| AdapterError::SecurityMetadataUnavailable {
                        server_id: manifest.server_id.clone(),
                        tool_name: tool.name.clone(),
                    })?;
            }
            let tool = manifest_tool_to_mcp_tool(tool)?;
            let input_validator = compile_input_validator(&exposed_name, &tool.input_schema)?;
            let binding = ExposedToolBinding {
                tool,
                server_id: manifest.server_id.clone(),
                tool_name: exposed_name.clone(),
                input_validator,
            };
            tool_index.insert(exposed_name, tools.len());
            tools.push(binding);
        }
    }

    Ok((tools, tool_index))
}

fn manifest_tool_to_mcp_tool(tool: ToolDefinition) -> Result<McpExposedTool, AdapterError> {
    validate_schema_object(&tool.name, "inputSchema", &tool.input_schema)?;
    if let Some(output_schema) = tool.output_schema.as_ref() {
        validate_schema_object(&tool.name, "outputSchema", output_schema)?;
    }

    let annotations = Some(json!({
        "readOnlyHint": tool.annotations.read_only,
        "destructiveHint": tool.annotations.destructive,
    }));

    let mut execution = serde_json::Map::new();
    execution.insert("taskSupport".to_string(), json!("optional"));
    if let Some(latency_hint) = tool.latency_hint {
        execution.insert(
            "suggestedLatency".to_string(),
            json!(latency_hint_to_label(latency_hint)),
        );
    }

    Ok(McpExposedTool {
        name: tool.name,
        title: None,
        description: tool.description,
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        annotations,
        execution: Some(Value::Object(execution)),
    })
}

fn validate_schema_object(
    tool_name: &str,
    field_name: &str,
    schema: &Value,
) -> Result<(), AdapterError> {
    if schema.is_object() {
        return Ok(());
    }

    Err(AdapterError::ParseError(format!(
        "MCP exposed tool `{tool_name}` {field_name} must be a JSON object"
    )))
}

fn compile_input_validator(
    tool_name: &str,
    schema: &Value,
) -> Result<chio_manifest::ToolInputSchemaValidator, AdapterError> {
    chio_manifest::ToolInputSchemaValidator::compile(tool_name, schema)
        .map_err(|error| AdapterError::ParseError(format!("MCP exposed {error}")))
}

fn latency_hint_to_label(latency_hint: LatencyHint) -> &'static str {
    match latency_hint {
        LatencyHint::Instant => "instant",
        LatencyHint::Fast => "fast",
        LatencyHint::Moderate => "moderate",
        LatencyHint::Slow => "slow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::Keypair;
    use chio_manifest::{
        BridgeSecurityMetadata, ToolAnnotations, ToolFlowDeclaration, TOOL_MANIFEST_SCHEMA,
    };

    #[test]
    fn constrained_tool_does_not_expose_internal_flow_sidecar() {
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: "flow-server".to_string(),
            name: "Flow server".to_string(),
            description: None,
            version: "2".to_string(),
            tools: vec![ToolDefinition {
                name: "send".to_string(),
                description: "Send".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations {
                    read_only: false,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: Some(LatencyHint::Moderate),
                flow: Some(ToolFlowDeclaration::public_egress()),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: Keypair::from_seed(&[4; 32]).public_key().to_hex(),
        };
        let security = BridgeSecurityMetadata::from_tool(&manifest.tools[0]);
        assert!(security.flow().is_some_and(|flow| flow.egress));
        let (bindings, _) = build_exposed_tool_bindings(vec![manifest], None)
            .unwrap_or_else(|error| panic!("build bindings: {error}"));
        let external = serde_json::to_value(&bindings[0].tool)
            .unwrap_or_else(|error| panic!("serialize MCP tool: {error}"));
        assert!(external.get("flow").is_none());
    }
}
