use chio_core_types::manifest::{
    LatencyHint, ToolAnnotations, ToolDefinition, ToolFlowDeclaration,
};

fn strict_tool() -> ToolDefinition {
    ToolDefinition {
        name: "lookup".to_string(),
        description: "Lookup a record".to_string(),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: Some(serde_json::json!({"type": "object"})),
        pricing: None,
        annotations: ToolAnnotations {
            read_only: true,
            destructive: false,
            idempotent: true,
            requires_approval: false,
        },
        latency_hint: Some(LatencyHint::Fast),
        flow: Some(ToolFlowDeclaration::public_egress()),
    }
}

#[test]
fn manifest_v2_nested_types_reject_unknown_fields() {
    let tool = strict_tool();
    let mut value = serde_json::to_value(&tool).unwrap_or_else(|error| panic!("encode: {error}"));
    value
        .as_object_mut()
        .unwrap_or_else(|| panic!("tool object"))
        .insert("unknown".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<ToolDefinition>(value).is_err());

    let mut value = serde_json::to_value(&tool).unwrap_or_else(|error| panic!("encode: {error}"));
    value["annotations"]["estimated_duration_ms"] = serde_json::json!(10);
    assert!(serde_json::from_value::<ToolDefinition>(value).is_err());

    let mut value = serde_json::to_value(&tool).unwrap_or_else(|error| panic!("encode: {error}"));
    value["flow"]["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ToolDefinition>(value).is_err());
}

#[test]
fn manifest_v2_latency_is_categorical_only() {
    let encoded =
        serde_json::to_value(strict_tool()).unwrap_or_else(|error| panic!("encode tool: {error}"));
    assert_eq!(encoded["latency_hint"], "fast");
    assert!(encoded["annotations"]
        .get("estimated_duration_ms")
        .is_none());
}
