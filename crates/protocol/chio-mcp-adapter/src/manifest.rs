use chio_manifest::{ToolAnnotations, ToolDefinition, ToolManifest, TOOL_MANIFEST_SCHEMA};
use serde_json::Value;

use crate::adapter::McpAdapterConfig;
use crate::edge::{AdapterError, McpToolInfo};

/// Project a runtime-discovered MCP tool catalog into the exact Chio manifest
/// surface used by native MCP admission.
///
/// Callers that add signed platform-permission sidecars must preserve every
/// projected field. Runtime admission compares those fields against a fresh
/// discovery before registering the server with the kernel.
pub fn generate_manifest(
    config: &McpAdapterConfig,
    mcp_tools: Vec<McpToolInfo>,
) -> Result<ToolManifest, AdapterError> {
    let tools: Vec<ToolDefinition> = mcp_tools
        .into_iter()
        .map(tool_definition_from_mcp)
        .collect::<Result<_, _>>()?;

    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.into(),
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

/// Require the runtime-discovered MCP surface to match the publisher-signed
/// surface before the server is registered with the kernel.
pub fn verify_discovered_manifest_surface(
    discovered: &ToolManifest,
    admitted: &ToolManifest,
) -> Result<(), AdapterError> {
    require_surface_field(discovered.schema == admitted.schema, "schema")?;
    require_surface_field(discovered.server_id == admitted.server_id, "server_id")?;
    require_surface_field(discovered.name == admitted.name, "name")?;
    require_surface_field(
        discovered.description == admitted.description,
        "description",
    )?;
    require_surface_field(discovered.version == admitted.version, "version")?;
    require_surface_field(discovered.public_key == admitted.public_key, "public_key")?;
    require_surface_field(
        admitted.server_tools.is_empty(),
        "server_tools must be empty for an MCP subprocess",
    )?;
    require_surface_field(discovered.tools.len() == admitted.tools.len(), "tool count")?;

    for admitted_tool in &admitted.tools {
        let discovered_tool = discovered
            .tools
            .iter()
            .find(|tool| tool.name == admitted_tool.name)
            .ok_or_else(|| {
                AdapterError::ManifestSurfaceMismatch(format!(
                    "signed tool {} was not discovered",
                    admitted_tool.name
                ))
            })?;
        require_surface_field(
            discovered_tool.description == admitted_tool.description,
            &format!("tool {} description", admitted_tool.name),
        )?;
        require_surface_field(
            discovered_tool.input_schema == admitted_tool.input_schema,
            &format!("tool {} input schema", admitted_tool.name),
        )?;
        require_surface_field(
            discovered_tool.output_schema == admitted_tool.output_schema,
            &format!("tool {} output schema", admitted_tool.name),
        )?;
        require_surface_field(
            discovered_tool.annotations.read_only == admitted_tool.annotations.read_only
                && discovered_tool.annotations.destructive == admitted_tool.annotations.destructive
                && discovered_tool.annotations.idempotent == admitted_tool.annotations.idempotent
                && discovered_tool.annotations.requires_approval
                    == admitted_tool.annotations.requires_approval,
            &format!("tool {} annotations", admitted_tool.name),
        )?;
    }

    Ok(())
}

fn require_surface_field(matches: bool, field: &str) -> Result<(), AdapterError> {
    if matches {
        Ok(())
    } else {
        Err(AdapterError::ManifestSurfaceMismatch(field.to_string()))
    }
}

pub(crate) fn tool_definition_from_mcp(tool: McpToolInfo) -> Result<ToolDefinition, AdapterError> {
    let tool = ProjectedMcpTool::try_from(tool)?;

    Ok(ToolDefinition {
        name: tool.name,
        description: tool.description,
        input_schema: tool.input_schema,
        output_schema: tool.output_schema,
        pricing: None,
        annotations: ToolAnnotations {
            read_only: !tool.has_side_effects,
            destructive: tool.has_side_effects,
            idempotent: false,
            requires_approval: tool.has_side_effects,
        },
        latency_hint: None,
        flow: None,
    })
}

struct ProjectedMcpTool {
    name: String,
    description: String,
    input_schema: Value,
    output_schema: Option<Value>,
    has_side_effects: bool,
}

impl TryFrom<McpToolInfo> for ProjectedMcpTool {
    type Error = AdapterError;

    fn try_from(tool: McpToolInfo) -> Result<Self, Self::Error> {
        validate_schema_object(&tool.name, "inputSchema", &tool.input_schema)?;
        if let Some(output_schema) = tool.output_schema.as_ref() {
            validate_schema_object(&tool.name, "outputSchema", output_schema)?;
        }

        Ok(Self {
            name: tool.name,
            description: project_tool_description(
                tool.title.as_deref(),
                tool.description.as_deref(),
            ),
            input_schema: tool.input_schema,
            output_schema: tool.output_schema,
            has_side_effects: infer_has_side_effects(tool.annotations.as_ref()),
        })
    }
}

fn project_tool_description(title: Option<&str>, description: Option<&str>) -> String {
    let title = title.filter(|value| !value.is_empty());
    let description = description.filter(|value| !value.is_empty());
    match (title, description) {
        (Some(title), Some(description)) if title == description => description.to_string(),
        (Some(title), Some(description)) => format!("{title}\n\n{description}"),
        (Some(title), None) => title.to_string(),
        (None, Some(description)) => description.to_string(),
        (None, None) => String::new(),
    }
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
