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

/// Attach MCP's optional `nextCursor` to a paginated result object.
///
/// Every MCP `*Result` that paginates declares `nextCursor: CursorSchema.optional()`
/// where `CursorSchema = z.string()`. `optional()` admits `undefined`, never
/// `null`, so the last page of a listing MUST omit the key rather than send
/// JSON `null`: a null fails validation in every published
/// `@modelcontextprotocol/sdk` release (checked 1.17.0 through 1.30.0) and the
/// client rejects the entire response, not just the field.
///
/// This is the single place that knows the rule. Callers that build a listing
/// result route their `Option<String>` cursor through here instead of dropping
/// it into `json!({ "nextCursor": next_cursor })`, which serializes `None` as
/// `null`.
pub(in crate::runtime) fn insert_next_cursor(
    result: &mut serde_json::Map<String, Value>,
    next_cursor: Option<String>,
) {
    if let Some(next_cursor) = next_cursor {
        result.insert("nextCursor".to_string(), Value::String(next_cursor));
    }
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
    let end = (start + page_size).min(values.len());
    let next_cursor = (end < values.len()).then(|| end.to_string());

    let mut result = serde_json::Map::new();
    result.insert(
        field_name.to_string(),
        Value::Array(values[start..end].to_vec()),
    );
    insert_next_cursor(&mut result, next_cursor);

    jsonrpc_result(id, Value::Object(result))
}
