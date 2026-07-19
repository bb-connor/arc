use serde_json::Value;

/// Version of Chio's trusted provider-native input-schema catalog.
pub const SERVER_TOOL_INPUT_SCHEMA_CATALOG_VERSION: &str =
    "chio.anthropic-server-tool-input-schemas.2024-10-22";

/// Draft 2020-12 validator compiled from one admitted tool input schema.
#[derive(Clone, Debug)]
pub struct ToolInputSchemaValidator {
    validator: jsonschema::Validator,
}

impl ToolInputSchemaValidator {
    /// Compile one tool input schema without permitting external retrieval.
    pub fn compile(tool_name: &str, schema: &Value) -> Result<Self, ToolInputSchemaError> {
        reject_unsupported_references(tool_name, schema)?;
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .with_retriever(RejectExternalSchemaRetrieval)
            .build(schema)
            .map_err(|error| ToolInputSchemaError::Invalid {
                tool_name: tool_name.to_string(),
                reason: error.to_string(),
            })?;
        Ok(Self { validator })
    }

    /// Return whether one invocation argument value satisfies the admitted schema.
    #[must_use]
    pub fn is_valid(&self, arguments: &Value) -> bool {
        self.validator.is_valid(arguments)
    }
}

/// Return the pinned input schema for one provider-native server-tool family.
#[must_use]
pub fn trusted_server_tool_input_schema(server_tool: crate::ServerTool) -> Value {
    match server_tool {
        crate::ServerTool::ComputerUse => serde_json::json!({
            "$id": "urn:chio:anthropic-server-tool:computer-use:2024-10-22",
            "$comment": SERVER_TOOL_INPUT_SCHEMA_CATALOG_VERSION,
            "type": "object",
            "properties": {
                "action": {
                    "enum": [
                        "key",
                        "type",
                        "mouse_move",
                        "left_click",
                        "left_click_drag",
                        "right_click",
                        "middle_click",
                        "double_click",
                        "screenshot",
                        "cursor_position"
                    ]
                },
                "text": {"type": "string"},
                "coordinate": {
                    "type": "array",
                    "prefixItems": [
                        {"type": "integer", "minimum": 0},
                        {"type": "integer", "minimum": 0}
                    ],
                    "items": false,
                    "minItems": 2,
                    "maxItems": 2
                }
            },
            "required": ["action"],
            "additionalProperties": false,
            "allOf": [
                {
                    "if": {"properties": {"action": {"enum": ["key", "type"]}}},
                    "then": {
                        "required": ["text"],
                        "not": {"required": ["coordinate"]}
                    }
                },
                {
                    "if": {
                        "properties": {
                            "action": {"enum": ["mouse_move", "left_click_drag"]}
                        }
                    },
                    "then": {
                        "required": ["coordinate"],
                        "not": {"required": ["text"]}
                    }
                },
                {
                    "if": {
                        "properties": {
                            "action": {
                                "enum": [
                                    "left_click",
                                    "right_click",
                                    "middle_click",
                                    "double_click",
                                    "screenshot",
                                    "cursor_position"
                                ]
                            }
                        }
                    },
                    "then": {
                        "not": {
                            "anyOf": [
                                {"required": ["text"]},
                                {"required": ["coordinate"]}
                            ]
                        }
                    }
                }
            ]
        }),
        crate::ServerTool::Bash => serde_json::json!({
            "$id": "urn:chio:anthropic-server-tool:bash:2024-10-22",
            "$comment": SERVER_TOOL_INPUT_SCHEMA_CATALOG_VERSION,
            "type": "object",
            "properties": {
                "command": {"type": "string", "minLength": 1},
                "restart": {"type": "boolean"}
            },
            "additionalProperties": false,
            "oneOf": [
                {
                    "required": ["command"],
                    "not": {"required": ["restart"]}
                },
                {
                    "properties": {"restart": {"const": true}},
                    "required": ["restart"],
                    "not": {"required": ["command"]}
                }
            ]
        }),
        crate::ServerTool::TextEditor => serde_json::json!({
            "$id": "urn:chio:anthropic-server-tool:text-editor:2024-10-22",
            "$comment": SERVER_TOOL_INPUT_SCHEMA_CATALOG_VERSION,
            "type": "object",
            "properties": {
                "command": {
                    "enum": ["view", "create", "str_replace", "insert", "undo_edit"]
                },
                "path": {"type": "string", "minLength": 1, "pattern": "^/"},
                "file_text": {"type": "string"},
                "view_range": {
                    "type": "array",
                    "prefixItems": [
                        {"type": "integer", "minimum": 1},
                        {"type": "integer", "minimum": -1}
                    ],
                    "items": false,
                    "minItems": 2,
                    "maxItems": 2
                },
                "old_str": {"type": "string"},
                "new_str": {"type": "string"},
                "insert_line": {"type": "integer", "minimum": 0}
            },
            "required": ["command", "path"],
            "additionalProperties": false,
            "allOf": [
                {
                    "if": {"properties": {"command": {"const": "view"}}},
                    "then": {
                        "not": {
                            "anyOf": [
                                {"required": ["file_text"]},
                                {"required": ["old_str"]},
                                {"required": ["new_str"]},
                                {"required": ["insert_line"]}
                            ]
                        }
                    }
                },
                {
                    "if": {"properties": {"command": {"const": "create"}}},
                    "then": {
                        "required": ["file_text"],
                        "not": {
                            "anyOf": [
                                {"required": ["view_range"]},
                                {"required": ["old_str"]},
                                {"required": ["new_str"]},
                                {"required": ["insert_line"]}
                            ]
                        }
                    }
                },
                {
                    "if": {"properties": {"command": {"const": "str_replace"}}},
                    "then": {
                        "required": ["old_str"],
                        "not": {
                            "anyOf": [
                                {"required": ["file_text"]},
                                {"required": ["view_range"]},
                                {"required": ["insert_line"]}
                            ]
                        }
                    }
                },
                {
                    "if": {"properties": {"command": {"const": "insert"}}},
                    "then": {
                        "required": ["insert_line", "new_str"],
                        "not": {
                            "anyOf": [
                                {"required": ["file_text"]},
                                {"required": ["view_range"]},
                                {"required": ["old_str"]}
                            ]
                        }
                    }
                },
                {
                    "if": {"properties": {"command": {"const": "undo_edit"}}},
                    "then": {
                        "not": {
                            "anyOf": [
                                {"required": ["file_text"]},
                                {"required": ["view_range"]},
                                {"required": ["old_str"]},
                                {"required": ["new_str"]},
                                {"required": ["insert_line"]}
                            ]
                        }
                    }
                }
            ]
        }),
    }
}

/// Input-schema compilation failure at a verified-registry trust boundary.
#[derive(Debug, thiserror::Error)]
pub enum ToolInputSchemaError {
    #[error("tool `{tool_name}` inputSchema is invalid: {reason}")]
    Invalid { tool_name: String, reason: String },
    #[error("tool `{tool_name}` inputSchema {keyword} must be a local fragment reference")]
    ExternalReference {
        tool_name: String,
        keyword: &'static str,
    },
    #[error("tool `{tool_name}` inputSchema uses unsupported $recursiveRef under Draft 2020-12")]
    RecursiveRef { tool_name: String },
}

/// Invocation failure against the exact schema retained by a verified registry.
#[derive(Debug, thiserror::Error)]
pub enum VerifiedManifestInvocationError {
    #[error(transparent)]
    Security(#[from] crate::VerifiedManifestAdmissionError),
    #[error("verified manifest registry has no input schema for {server_id}/{tool_name}")]
    SchemaUnavailable {
        server_id: String,
        tool_name: String,
    },
    #[error("tool arguments for {server_id}/{tool_name} must be a JSON object")]
    ArgumentsNotObject {
        server_id: String,
        tool_name: String,
    },
    #[error(
        "tool arguments for {server_id}/{tool_name} do not match the signed manifest input schema"
    )]
    SchemaMismatch {
        server_id: String,
        tool_name: String,
    },
    #[error(
        "tool arguments for {server_id}/{tool_name} do not match the trusted server-tool input schema"
    )]
    TrustedServerToolSchemaMismatch {
        server_id: String,
        tool_name: String,
    },
}

#[derive(Debug)]
struct RejectExternalSchemaRetrieval;

impl jsonschema::Retrieve for RejectExternalSchemaRetrieval {
    fn retrieve(
        &self,
        uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(format!(
            "external JSON Schema retrieval is disabled: {}",
            uri.as_str()
        )
        .into())
    }
}

fn reject_unsupported_references(
    tool_name: &str,
    schema: &Value,
) -> Result<(), ToolInputSchemaError> {
    let Value::Object(fields) = schema else {
        return Ok(());
    };

    if fields.contains_key("$recursiveRef") {
        return Err(ToolInputSchemaError::RecursiveRef {
            tool_name: tool_name.to_string(),
        });
    }
    for keyword in ["$ref", "$dynamicRef"] {
        if fields
            .get(keyword)
            .and_then(Value::as_str)
            .is_some_and(|reference| !reference.starts_with('#'))
        {
            return Err(ToolInputSchemaError::ExternalReference {
                tool_name: tool_name.to_string(),
                keyword,
            });
        }
    }

    for keyword in [
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    ] {
        if let Some(subschema) = fields.get(keyword) {
            reject_unsupported_references(tool_name, subschema)?;
        }
    }
    for keyword in ["allOf", "anyOf", "oneOf", "prefixItems"] {
        if let Some(subschemas) = fields.get(keyword).and_then(Value::as_array) {
            for subschema in subschemas {
                reject_unsupported_references(tool_name, subschema)?;
            }
        }
    }
    for keyword in [
        "$defs",
        "definitions",
        "dependencies",
        "dependentSchemas",
        "patternProperties",
        "properties",
    ] {
        if let Some(subschemas) = fields.get(keyword).and_then(Value::as_object) {
            for subschema in subschemas.values() {
                reject_unsupported_references(tool_name, subschema)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn draft_2020_12_rejects_local_recursive_ref() {
        let error = ToolInputSchemaValidator::compile(
            "walk",
            &json!({
                "type": "object",
                "properties": {
                    "child": {"$recursiveRef": "#"}
                }
            }),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ToolInputSchemaError::RecursiveRef { tool_name } if tool_name == "walk"
        ));
    }

    #[test]
    fn recursive_ref_property_name_is_not_treated_as_a_schema_keyword() {
        let validator = ToolInputSchemaValidator::compile(
            "literal",
            &json!({
                "type": "object",
                "properties": {
                    "$recursiveRef": {"type": "string"}
                },
                "required": ["$recursiveRef"]
            }),
        )
        .unwrap();

        assert!(validator.is_valid(&json!({"$recursiveRef": "literal"})));
    }

    #[test]
    fn local_ref_compiles_and_external_ref_fails_closed() {
        let local = ToolInputSchemaValidator::compile(
            "local",
            &json!({
                "$defs": {"name": {"type": "string"}},
                "type": "object",
                "properties": {"name": {"$ref": "#/$defs/name"}}
            }),
        )
        .unwrap();
        assert!(local.is_valid(&json!({"name": "Chio"})));

        assert!(matches!(
            ToolInputSchemaValidator::compile(
                "external",
                &json!({"$ref": "https://schemas.example/tool.json"})
            ),
            Err(ToolInputSchemaError::ExternalReference {
                tool_name,
                keyword: "$ref"
            }) if tool_name == "external"
        ));
    }

    #[test]
    fn trusted_anthropic_server_tool_catalog_is_strict_and_compilable() {
        let computer = ToolInputSchemaValidator::compile(
            "computer_use",
            &trusted_server_tool_input_schema(crate::ServerTool::ComputerUse),
        )
        .unwrap();
        assert!(computer.is_valid(&json!({"action": "screenshot"})));
        assert!(computer.is_valid(&json!({
            "action": "mouse_move",
            "coordinate": [20, 30]
        })));
        assert!(!computer.is_valid(&json!({
            "action": "screenshot",
            "text": "unexpected"
        })));
        assert!(!computer.is_valid(&json!({
            "action": "mouse_move",
            "coordinate": [20]
        })));

        let bash = ToolInputSchemaValidator::compile(
            "bash",
            &trusted_server_tool_input_schema(crate::ServerTool::Bash),
        )
        .unwrap();
        assert!(bash.is_valid(&json!({"command": "pwd"})));
        assert!(bash.is_valid(&json!({"restart": true})));
        assert!(!bash.is_valid(&json!({})));
        assert!(!bash.is_valid(&json!({"command": "pwd", "restart": true})));

        let editor = ToolInputSchemaValidator::compile(
            "text_editor",
            &trusted_server_tool_input_schema(crate::ServerTool::TextEditor),
        )
        .unwrap();
        assert!(editor.is_valid(&json!({"command": "view", "path": "/tmp/file"})));
        assert!(editor.is_valid(&json!({
            "command": "insert",
            "path": "/tmp/file",
            "insert_line": 1,
            "new_str": "line"
        })));
        assert!(!editor.is_valid(&json!({"command": "create", "path": "/tmp/file"})));
        assert!(!editor.is_valid(&json!({"command": "view", "path": "relative"})));
    }
}
