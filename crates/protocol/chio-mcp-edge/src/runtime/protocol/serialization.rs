use super::*;

pub(in crate::runtime) fn serialize_resources(resources: Vec<ResourceDefinition>) -> Vec<Value> {
    resources
        .into_iter()
        .map(|resource| serde_json::to_value(resource).unwrap_or_else(|_| json!({})))
        .collect()
}

pub(in crate::runtime) fn serialize_resource_templates(
    templates: Vec<ResourceTemplateDefinition>,
) -> Vec<Value> {
    templates
        .into_iter()
        .map(|template| serde_json::to_value(template).unwrap_or_else(|_| json!({})))
        .collect()
}

pub(in crate::runtime) fn serialize_resource_contents(
    contents: Vec<ResourceContent>,
) -> Vec<Value> {
    contents
        .into_iter()
        .map(|content| serde_json::to_value(content).unwrap_or_else(|_| json!({})))
        .collect()
}

pub(in crate::runtime) fn serialize_prompts(prompts: Vec<PromptDefinition>) -> Vec<Value> {
    prompts
        .into_iter()
        .map(|prompt| serde_json::to_value(prompt).unwrap_or_else(|_| json!({})))
        .collect()
}
pub(in crate::runtime) fn paginate_response(
    id: Value,
    start: usize,
    page_size: usize,
    values: Vec<Value>,
) -> Value {
    paginate_named_response(id, start, page_size, "resources", values)
}

pub(in crate::runtime) fn paginate_named_response(
    id: Value,
    start: usize,
    page_size: usize,
    field_name: &str,
    values: Vec<Value>,
) -> Value {
    if start > values.len() {
        return jsonrpc_error(id, JSONRPC_INVALID_PARAMS, "cursor is out of range");
    }

    let page_size = page_size.max(1);
    let end = start.saturating_add(page_size).min(values.len());
    let next_cursor = (end < values.len()).then(|| end.to_string());

    let mut result = serde_json::Map::new();
    result.insert(
        field_name.to_string(),
        Value::Array(values[start..end].to_vec()),
    );
    // MCP's cursor is an optional string. A JSON null fails strict clients'
    // result schema even though permissive clients treat it as end-of-list.
    if let Some(cursor) = next_cursor {
        result.insert("nextCursor".to_string(), Value::String(cursor));
    }

    jsonrpc_result(id, Value::Object(result))
}
