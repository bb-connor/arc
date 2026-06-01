use chio_manifest::{ToolDefinition, ToolManifest};
use serde_json::Value;

use crate::{AdapterError, McpAdapterConfig, McpToolInfo};

pub(crate) fn generate_manifest(
    config: &McpAdapterConfig,
    mcp_tools: Vec<McpToolInfo>,
) -> Result<ToolManifest, AdapterError> {
    let tools: Vec<ToolDefinition> = mcp_tools
        .into_iter()
        .map(tool_definition_from_mcp)
        .collect::<Result<_, _>>()?;

    let manifest = ToolManifest {
        schema: "chio.manifest.v1".into(),
        server_id: config.server_id.clone(),
        name: config.server_name.clone(),
        description: Some("MCP server adapted to Chio protocol".into()),
        version: config.server_version.clone(),
        tools,
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: config.public_key.clone(),
    };

    chio_manifest::validate_manifest(&manifest)?;
    Ok(manifest)
}

fn tool_definition_from_mcp(tool: McpToolInfo) -> Result<ToolDefinition, AdapterError> {
    validate_schema_object(&tool.name, "inputSchema", &tool.input_schema)?;
    if let Some(output_schema) = tool.output_schema.as_ref() {
        validate_schema_object(&tool.name, "outputSchema", output_schema)?;
    }

    Ok(ToolDefinition {
        name: tool.name,
        description: tool.description.unwrap_or_default(),
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        pricing: None,
        has_side_effects: infer_has_side_effects(tool.annotations.as_ref()),
        latency_hint: None,
    })
}

fn validate_schema_object(
    tool_name: &str,
    field: &str,
    schema: &Value,
) -> Result<(), AdapterError> {
    if schema.is_object() {
        return Ok(());
    }

    Err(AdapterError::ParseError(format!(
        "MCP tool `{tool_name}` {field} must be a JSON object"
    )))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct McpToolSafetyHints {
    read_only: Option<bool>,
    destructive: Option<bool>,
    malformed: bool,
}

impl McpToolSafetyHints {
    fn from_annotations(annotations: Option<&Value>) -> Self {
        let Some(annotations) = annotations else {
            return Self::default();
        };

        let (read_only, read_only_malformed) = read_bool_hint(annotations, "readOnlyHint");
        let (destructive, destructive_malformed) = read_bool_hint(annotations, "destructiveHint");

        Self {
            read_only,
            destructive,
            malformed: read_only_malformed || destructive_malformed,
        }
    }

    fn has_side_effects(self) -> bool {
        if self.malformed || self.destructive == Some(true) {
            return true;
        }
        !matches!(self.read_only, Some(true))
    }
}

fn read_bool_hint(annotations: &Value, key: &str) -> (Option<bool>, bool) {
    match annotations.get(key) {
        None | Some(Value::Null) => (None, false),
        Some(Value::Bool(value)) => (Some(*value), false),
        Some(_) => (None, true),
    }
}

pub(crate) fn infer_has_side_effects(annotations: Option<&Value>) -> bool {
    McpToolSafetyHints::from_annotations(annotations).has_side_effects()
}
