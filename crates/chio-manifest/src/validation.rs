use std::collections::HashSet;

use crate::{
    ManifestError, RequiredPermissions, ToolDefinition, ToolManifest, TOOL_MANIFEST_SCHEMA,
};

/// Validate that a manifest is structurally well-formed.
///
/// This does not authenticate signer material. Use [`crate::sign_manifest`] or
/// [`crate::verify_manifest`] when the embedded public key must be parsed and
/// matched against a signer.
pub fn validate_manifest(manifest: &ToolManifest) -> Result<(), ManifestError> {
    if manifest.schema != TOOL_MANIFEST_SCHEMA {
        return Err(ManifestError::UnsupportedSchema(manifest.schema.clone()));
    }
    validate_manifest_identity(manifest)?;
    validate_tools(&manifest.tools)?;
    validate_server_tools(manifest)?;
    validate_required_permissions(manifest.required_permissions.as_ref())?;
    Ok(())
}

fn validate_manifest_identity(manifest: &ToolManifest) -> Result<(), ManifestError> {
    validate_manifest_text_field("server_id", &manifest.server_id)?;
    validate_manifest_text_field("name", &manifest.name)?;
    validate_manifest_text_field("version", &manifest.version)?;
    Ok(())
}

fn validate_manifest_text_field(field: &'static str, value: &str) -> Result<(), ManifestError> {
    if value.trim().is_empty() || value.trim() != value {
        Err(ManifestError::InvalidManifestField(field))
    } else {
        Ok(())
    }
}

fn validate_tools(tools: &[ToolDefinition]) -> Result<(), ManifestError> {
    if tools.is_empty() {
        return Err(ManifestError::EmptyManifest);
    }

    let mut seen = HashSet::new();
    for tool in tools {
        validate_tool(tool)?;
        if !seen.insert(&tool.name) {
            return Err(ManifestError::DuplicateToolName(tool.name.clone()));
        }
    }

    Ok(())
}

fn validate_tool(tool: &ToolDefinition) -> Result<(), ManifestError> {
    if tool.name.trim().is_empty() || tool.name.trim() != tool.name {
        return Err(ManifestError::InvalidToolName(tool.name.clone()));
    }
    if !tool.input_schema.is_object() {
        return Err(ManifestError::InvalidInputSchema(tool.name.clone()));
    }
    if tool
        .output_schema
        .as_ref()
        .is_some_and(|schema| !schema.is_object())
    {
        return Err(ManifestError::InvalidOutputSchema(tool.name.clone()));
    }
    Ok(())
}

fn validate_server_tools(manifest: &ToolManifest) -> Result<(), ManifestError> {
    let mut seen_server_tools = HashSet::new();
    for server_tool in &manifest.server_tools {
        if !seen_server_tools.insert(*server_tool) {
            return Err(ManifestError::DuplicateServerTool(
                server_tool.as_str().to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_required_permissions(
    permissions: Option<&RequiredPermissions>,
) -> Result<(), ManifestError> {
    let Some(permissions) = permissions else {
        return Ok(());
    };

    validate_permission_values(
        "required_permissions.read_paths",
        permissions.read_paths.as_deref(),
    )?;
    validate_permission_values(
        "required_permissions.write_paths",
        permissions.write_paths.as_deref(),
    )?;
    validate_permission_values(
        "required_permissions.network_hosts",
        permissions.network_hosts.as_deref(),
    )?;
    validate_permission_values(
        "required_permissions.environment_variables",
        permissions.environment_variables.as_deref(),
    )?;
    Ok(())
}

fn validate_permission_values(
    field: &'static str,
    values: Option<&[String]>,
) -> Result<(), ManifestError> {
    let Some(values) = values else {
        return Ok(());
    };

    let mut seen = HashSet::new();
    for value in values {
        if value.trim().is_empty() || value.trim() != value {
            return Err(ManifestError::InvalidRequiredPermission {
                field,
                value: value.clone(),
            });
        }
        if !seen.insert(value) {
            return Err(ManifestError::DuplicateRequiredPermission {
                field,
                value: value.clone(),
            });
        }
    }

    Ok(())
}
