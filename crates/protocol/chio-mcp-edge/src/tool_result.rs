//! The shared MCP projection of a kernel output value.

use serde_json::{json, Value};

/// Project a value using the same content, structured-content and error rules
/// as the edge runtime. The caller supplies any verified execution metadata.
pub fn project_tool_result(value: Value) -> Value {
    if let Some(object) = value.as_object() {
        let has_mcp_shape = object.contains_key("content")
            || object.contains_key("structuredContent")
            || object.contains_key("isError");
        if has_mcp_shape {
            let mut object = object.clone();
            object
                .entry("isError".to_string())
                .or_insert_with(|| Value::Bool(false));
            if !object.contains_key("content") {
                if let Some(structured) = object.get("structuredContent") {
                    object.insert(
                        "content".to_string(),
                        json!([{"type": "text", "text": serde_json::to_string(structured).unwrap_or_default()}]),
                    );
                }
            }
            return Value::Object(object);
        }

        return json!({
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&value).unwrap_or_default(),
                }
            ],
            "structuredContent": value,
            "isError": false,
        });
    }

    match value {
        Value::String(text) => json!({
            "content": [{ "type": "text", "text": text }],
            "isError": false,
        }),
        other => json!({
            "content": [
                {
                    "type": "text",
                    "text": serde_json::to_string(&other).unwrap_or_default(),
                }
            ],
            "isError": false,
        }),
    }
}
