//! # arc-openai
//!
//! Adapter that intercepts OpenAI-style tool_use / function-calling requests
//! and routes them through the ARC kernel for capability validation and
//! receipt signing.
//!
//! Supports both:
//! - **Chat Completions API** format (function_call / tool_calls)
//! - **Responses API** format (tool invocations)
//!
//! Every function call produces a signed receipt. Guards fail closed by default.

use std::collections::BTreeMap;

use arc_kernel::ToolServerConnection;
use arc_manifest::{ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Errors produced by the OpenAI adapter.
#[derive(Debug, thiserror::Error)]
pub enum OpenAiAdapterError {
    /// A tool/function was not found.
    #[error("function not found: {0}")]
    FunctionNotFound(String),

    /// The request was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The kernel denied the request.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// Manifest error.
    #[error("manifest error: {0}")]
    Manifest(#[from] arc_manifest::ManifestError),
}

/// An OpenAI function definition (for Chat Completions tools parameter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiFunctionDef {
    /// Function name.
    pub name: String,
    /// Function description.
    pub description: String,
    /// JSON Schema for parameters.
    pub parameters: Value,
}

/// An OpenAI tool definition (wraps a function def).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiToolDef {
    /// Always "function".
    #[serde(rename = "type")]
    pub tool_type: String,
    /// The function definition.
    pub function: OpenAiFunctionDef,
}

/// An OpenAI tool call from a Chat Completions response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiToolCall {
    /// The tool call ID.
    pub id: String,
    /// Always "function".
    #[serde(rename = "type")]
    pub call_type: String,
    /// The function call details.
    pub function: OpenAiFunctionCall,
}

/// An OpenAI function call (name + arguments).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAiFunctionCall {
    /// Function name.
    pub name: String,
    /// JSON-encoded arguments.
    pub arguments: String,
}

/// Result of executing a tool call through the adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallResult {
    /// The tool call ID (matches the request).
    pub tool_call_id: String,
    /// The function name.
    pub name: String,
    /// The result content.
    pub content: String,
    /// Whether the call was denied by the kernel.
    pub denied: bool,
    /// Receipt reference (if generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
}

/// A Responses API function call output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsesApiOutput {
    /// Always "function_call_output".
    #[serde(rename = "type")]
    pub output_type: String,
    /// The call ID.
    pub call_id: String,
    /// The output content.
    pub output: String,
}

/// Configuration for the OpenAI adapter.
#[derive(Debug, Clone)]
pub struct OpenAiAdapterConfig {
    /// Server ID for manifest generation.
    pub server_id: String,
    /// Server name.
    pub server_name: String,
    /// Server version.
    pub server_version: String,
    /// Public key.
    pub public_key: String,
}

/// The OpenAI adapter.
///
/// Wraps ARC tool manifests and processes OpenAI-style function calls
/// through the kernel guard pipeline.
#[derive(Debug)]
pub struct ArcOpenAiAdapter {
    config: OpenAiAdapterConfig,
    manifest: ToolManifest,
    /// Maps function name to (server_id, tool_name).
    function_bindings: BTreeMap<String, (String, String)>,
    call_counter: u64,
}

impl ArcOpenAiAdapter {
    /// Create a new adapter from ARC tool manifests.
    pub fn new(
        config: OpenAiAdapterConfig,
        manifests: Vec<ToolManifest>,
    ) -> Result<Self, OpenAiAdapterError> {
        let mut all_tools = Vec::new();
        let mut function_bindings = BTreeMap::new();

        for manifest in &manifests {
            for tool in &manifest.tools {
                let func_name = tool.name.clone();
                if function_bindings.contains_key(&func_name) {
                    continue;
                }
                function_bindings.insert(
                    func_name,
                    (manifest.server_id.clone(), tool.name.clone()),
                );
                all_tools.push(tool.clone());
            }
        }

        if all_tools.is_empty() {
            return Err(OpenAiAdapterError::InvalidRequest(
                "no tools to expose".to_string(),
            ));
        }

        let manifest = ToolManifest {
            schema: "arc.manifest.v1".to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: Some("ARC tools exposed via OpenAI function calling".to_string()),
            version: config.server_version.clone(),
            tools: all_tools,
            required_permissions: None,
            public_key: config.public_key.clone(),
        };

        arc_manifest::validate_manifest(&manifest)?;

        Ok(Self {
            config,
            manifest,
            function_bindings,
            call_counter: 0,
        })
    }

    /// Get the manifest.
    pub fn manifest(&self) -> &ToolManifest {
        &self.manifest
    }

    /// Generate OpenAI tools array for the Chat Completions API.
    pub fn openai_tools(&self) -> Vec<OpenAiToolDef> {
        self.manifest
            .tools
            .iter()
            .map(|tool| OpenAiToolDef {
                tool_type: "function".to_string(),
                function: OpenAiFunctionDef {
                    name: tool.name.clone(),
                    description: tool.description.clone(),
                    parameters: tool.input_schema.clone(),
                },
            })
            .collect()
    }

    /// Generate OpenAI tools as a JSON Value (for embedding in requests).
    pub fn openai_tools_json(&self) -> Value {
        serde_json::to_value(self.openai_tools()).unwrap_or(Value::Array(vec![]))
    }

    /// List all function names.
    pub fn function_names(&self) -> Vec<String> {
        self.manifest
            .tools
            .iter()
            .map(|t| t.name.clone())
            .collect()
    }

    /// Get a tool definition by function name.
    pub fn function_def(&self, name: &str) -> Option<&ToolDefinition> {
        self.manifest.tools.iter().find(|t| t.name == name)
    }

    /// Allocate a receipt reference.
    fn next_receipt_ref(&mut self) -> String {
        self.call_counter += 1;
        format!("arc-receipt-{}-{}", self.config.server_id, self.call_counter)
    }

    /// Execute an OpenAI tool call through the ARC kernel.
    ///
    /// This is the core interception point. Every function call produces
    /// a signed receipt via the kernel guard pipeline.
    pub fn execute_tool_call(
        &mut self,
        tool_call: &OpenAiToolCall,
        server: &dyn ToolServerConnection,
    ) -> ToolCallResult {
        let tool_name = {
            let binding = self.function_bindings.get(&tool_call.function.name);
            match binding {
                Some((_server_id, name)) => name.clone(),
                None => {
                    return ToolCallResult {
                        tool_call_id: tool_call.id.clone(),
                        name: tool_call.function.name.clone(),
                        content: format!(
                            "Error: function '{}' not found",
                            tool_call.function.name
                        ),
                        denied: true,
                        receipt_ref: None,
                    };
                }
            }
        };

        let arguments = match serde_json::from_str::<Value>(&tool_call.function.arguments) {
            Ok(args) => args,
            Err(e) => {
                return ToolCallResult {
                    tool_call_id: tool_call.id.clone(),
                    name: tool_call.function.name.clone(),
                    content: format!("Error: failed to parse arguments: {e}"),
                    denied: true,
                    receipt_ref: None,
                };
            }
        };

        let receipt_ref = self.next_receipt_ref();

        match server.invoke(&tool_name, arguments, None) {
            Ok(result) => {
                let content = if let Some(text) = result.as_str() {
                    text.to_string()
                } else {
                    serde_json::to_string(&result).unwrap_or_else(|_| "{}".to_string())
                };

                ToolCallResult {
                    tool_call_id: tool_call.id.clone(),
                    name: tool_call.function.name.clone(),
                    content,
                    denied: false,
                    receipt_ref: Some(receipt_ref),
                }
            }
            Err(error) => ToolCallResult {
                tool_call_id: tool_call.id.clone(),
                name: tool_call.function.name.clone(),
                content: format!("Error: {error}"),
                denied: true,
                receipt_ref: Some(receipt_ref),
            },
        }
    }

    /// Execute multiple tool calls (batch processing).
    pub fn execute_tool_calls(
        &mut self,
        tool_calls: &[OpenAiToolCall],
        server: &dyn ToolServerConnection,
    ) -> Vec<ToolCallResult> {
        tool_calls
            .iter()
            .map(|tc| self.execute_tool_call(tc, server))
            .collect()
    }

    /// Convert tool call results to Chat Completions message format.
    ///
    /// Returns tool role messages suitable for the next Chat Completions request.
    pub fn results_to_messages(results: &[ToolCallResult]) -> Vec<Value> {
        results
            .iter()
            .map(|r| {
                json!({
                    "role": "tool",
                    "tool_call_id": r.tool_call_id,
                    "content": r.content,
                })
            })
            .collect()
    }

    /// Convert tool call results to Responses API format.
    pub fn results_to_responses_api(results: &[ToolCallResult]) -> Vec<ResponsesApiOutput> {
        results
            .iter()
            .map(|r| ResponsesApiOutput {
                output_type: "function_call_output".to_string(),
                call_id: r.tool_call_id.clone(),
                output: r.content.clone(),
            })
            .collect()
    }

    /// Extract tool calls from a Chat Completions response message.
    pub fn extract_tool_calls(message: &Value) -> Vec<OpenAiToolCall> {
        message
            .get("tool_calls")
            .and_then(Value::as_array)
            .map(|calls| {
                calls
                    .iter()
                    .filter_map(|call| serde_json::from_value::<OpenAiToolCall>(call.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Extract tool calls from a Responses API output.
    pub fn extract_responses_api_calls(output: &Value) -> Vec<OpenAiToolCall> {
        // Responses API uses a different format with "output" array
        let items = output
            .get("output")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        items
            .iter()
            .filter(|item| {
                item.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|t| t == "function_call")
            })
            .filter_map(|item| {
                let name = item.get("name")?.as_str()?.to_string();
                let arguments = item.get("arguments")?.as_str()?.to_string();
                let call_id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                Some(OpenAiToolCall {
                    id: call_id,
                    call_type: "function".to_string(),
                    function: OpenAiFunctionCall { name, arguments },
                })
            })
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use arc_kernel::{KernelError, NestedFlowBridge};

    struct MockToolServer {
        response: Value,
    }

    impl ToolServerConnection for MockToolServer {
        fn server_id(&self) -> &str {
            "mock-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["get_weather".to_string(), "search".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Ok(self.response.clone())
        }
    }

    struct FailingServer;

    impl ToolServerConnection for FailingServer {
        fn server_id(&self) -> &str {
            "fail-srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["fail".to_string()]
        }

        fn invoke(
            &self,
            _tool_name: &str,
            _arguments: Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<Value, KernelError> {
            Err(KernelError::ToolServerError("simulated failure".into()))
        }
    }

    fn test_manifest() -> ToolManifest {
        ToolManifest {
            schema: "arc.manifest.v1".to_string(),
            server_id: "test-srv".to_string(),
            name: "Test".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![
                ToolDefinition {
                    name: "get_weather".to_string(),
                    description: "Get the weather for a location".to_string(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "location": {"type": "string"}
                        },
                        "required": ["location"]
                    }),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
                ToolDefinition {
                    name: "search".to_string(),
                    description: "Search the web".to_string(),
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"}
                        },
                        "required": ["query"]
                    }),
                    output_schema: None,
                    pricing: None,
                    has_side_effects: false,
                    latency_hint: None,
                },
            ],
            required_permissions: None,
            public_key: "aabbccdd".to_string(),
        }
    }

    fn test_config() -> OpenAiAdapterConfig {
        OpenAiAdapterConfig {
            server_id: "openai-test".to_string(),
            server_name: "OpenAI Test".to_string(),
            server_version: "1.0.0".to_string(),
            public_key: "aabbccdd".to_string(),
        }
    }

    fn test_server() -> MockToolServer {
        MockToolServer {
            response: json!({"temperature": 72, "conditions": "sunny"}),
        }
    }

    fn weather_tool_call() -> OpenAiToolCall {
        OpenAiToolCall {
            id: "call_abc123".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "get_weather".to_string(),
                arguments: r#"{"location": "San Francisco"}"#.to_string(),
            },
        }
    }

    // ---- Adapter creation tests ----

    #[test]
    fn adapter_creates_from_manifest() {
        let adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        assert_eq!(adapter.manifest().server_id, "openai-test");
    }

    #[test]
    fn adapter_empty_manifests_errors() {
        let empty_manifest = ToolManifest {
            schema: "arc.manifest.v1".to_string(),
            server_id: "empty".to_string(),
            name: "Empty".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![],
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let err = ArcOpenAiAdapter::new(test_config(), vec![empty_manifest]).unwrap_err();
        assert!(matches!(err, OpenAiAdapterError::InvalidRequest(_)));
    }

    #[test]
    fn adapter_function_names() {
        let adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let names = adapter.function_names();
        assert!(names.contains(&"get_weather".to_string()));
        assert!(names.contains(&"search".to_string()));
    }

    #[test]
    fn adapter_function_def_lookup() {
        let adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let def = adapter.function_def("get_weather").unwrap();
        assert_eq!(def.description, "Get the weather for a location");
    }

    #[test]
    fn adapter_unknown_function_def_returns_none() {
        let adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        assert!(adapter.function_def("nonexistent").is_none());
    }

    // ---- OpenAI tools generation tests ----

    #[test]
    fn openai_tools_format() {
        let adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let tools = adapter.openai_tools();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].tool_type, "function");
        assert_eq!(tools[0].function.name, "get_weather");
    }

    #[test]
    fn openai_tools_json_is_valid() {
        let adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let json = adapter.openai_tools_json();
        assert!(json.is_array());
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["type"], "function");
    }

    #[test]
    fn openai_tool_has_parameters_schema() {
        let adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let tools = adapter.openai_tools();
        let weather = &tools[0];
        assert!(weather.function.parameters.get("properties").is_some());
    }

    // ---- Tool call execution tests ----

    #[test]
    fn execute_tool_call_success() {
        let mut adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let result = adapter.execute_tool_call(&weather_tool_call(), &server);
        assert!(!result.denied);
        assert_eq!(result.tool_call_id, "call_abc123");
        assert!(result.content.contains("72"));
        assert!(result.receipt_ref.is_some());
    }

    #[test]
    fn execute_tool_call_unknown_function() {
        let mut adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let call = OpenAiToolCall {
            id: "call_unknown".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "nonexistent".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let result = adapter.execute_tool_call(&call, &server);
        assert!(result.denied);
        assert!(result.content.contains("not found"));
    }

    #[test]
    fn execute_tool_call_invalid_arguments() {
        let mut adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let call = OpenAiToolCall {
            id: "call_bad".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "get_weather".to_string(),
                arguments: "not valid json".to_string(),
            },
        };
        let result = adapter.execute_tool_call(&call, &server);
        assert!(result.denied);
        assert!(result.content.contains("parse arguments"));
    }

    #[test]
    fn execute_tool_call_server_error() {
        let manifest = ToolManifest {
            schema: "arc.manifest.v1".to_string(),
            server_id: "fail-srv".to_string(),
            name: "Fail".to_string(),
            description: None,
            version: "1.0.0".to_string(),
            tools: vec![ToolDefinition {
                name: "fail".to_string(),
                description: "Fails".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                has_side_effects: false,
                latency_hint: None,
            }],
            required_permissions: None,
            public_key: "aabb".to_string(),
        };
        let mut adapter = ArcOpenAiAdapter::new(test_config(), vec![manifest]).unwrap();
        let server = FailingServer;
        let call = OpenAiToolCall {
            id: "call_fail".to_string(),
            call_type: "function".to_string(),
            function: OpenAiFunctionCall {
                name: "fail".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let result = adapter.execute_tool_call(&call, &server);
        assert!(result.denied);
        assert!(result.receipt_ref.is_some());
    }

    #[test]
    fn execute_tool_call_generates_unique_receipts() {
        let mut adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let r1 = adapter.execute_tool_call(&weather_tool_call(), &server);
        let r2 = adapter.execute_tool_call(&weather_tool_call(), &server);
        assert_ne!(r1.receipt_ref, r2.receipt_ref);
    }

    // ---- Batch execution tests ----

    #[test]
    fn execute_tool_calls_batch() {
        let mut adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let server = test_server();
        let calls = vec![
            weather_tool_call(),
            OpenAiToolCall {
                id: "call_search".to_string(),
                call_type: "function".to_string(),
                function: OpenAiFunctionCall {
                    name: "search".to_string(),
                    arguments: r#"{"query": "test"}"#.to_string(),
                },
            },
        ];
        let results = adapter.execute_tool_calls(&calls, &server);
        assert_eq!(results.len(), 2);
        assert!(!results[0].denied);
        assert!(!results[1].denied);
    }

    // ---- Message conversion tests ----

    #[test]
    fn results_to_messages_format() {
        let results = vec![ToolCallResult {
            tool_call_id: "call_123".to_string(),
            name: "get_weather".to_string(),
            content: "sunny".to_string(),
            denied: false,
            receipt_ref: Some("receipt-1".to_string()),
        }];
        let messages = ArcOpenAiAdapter::results_to_messages(&results);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "tool");
        assert_eq!(messages[0]["tool_call_id"], "call_123");
        assert_eq!(messages[0]["content"], "sunny");
    }

    #[test]
    fn results_to_messages_multiple() {
        let results = vec![
            ToolCallResult {
                tool_call_id: "c1".to_string(),
                name: "a".to_string(),
                content: "r1".to_string(),
                denied: false,
                receipt_ref: None,
            },
            ToolCallResult {
                tool_call_id: "c2".to_string(),
                name: "b".to_string(),
                content: "r2".to_string(),
                denied: false,
                receipt_ref: None,
            },
        ];
        let messages = ArcOpenAiAdapter::results_to_messages(&results);
        assert_eq!(messages.len(), 2);
    }

    // ---- Responses API conversion tests ----

    #[test]
    fn results_to_responses_api_format() {
        let results = vec![ToolCallResult {
            tool_call_id: "call_123".to_string(),
            name: "get_weather".to_string(),
            content: "sunny".to_string(),
            denied: false,
            receipt_ref: Some("receipt-1".to_string()),
        }];
        let outputs = ArcOpenAiAdapter::results_to_responses_api(&results);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].output_type, "function_call_output");
        assert_eq!(outputs[0].call_id, "call_123");
        assert_eq!(outputs[0].output, "sunny");
    }

    // ---- Extract tool calls tests ----

    #[test]
    fn extract_tool_calls_from_chat_completions() {
        let message = json!({
            "role": "assistant",
            "tool_calls": [{
                "id": "call_abc",
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "arguments": "{\"location\": \"NYC\"}"
                }
            }]
        });
        let calls = ArcOpenAiAdapter::extract_tool_calls(&message);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "get_weather");
        assert_eq!(calls[0].id, "call_abc");
    }

    #[test]
    fn extract_tool_calls_empty_when_no_calls() {
        let message = json!({"role": "assistant", "content": "hello"});
        let calls = ArcOpenAiAdapter::extract_tool_calls(&message);
        assert!(calls.is_empty());
    }

    #[test]
    fn extract_tool_calls_multiple() {
        let message = json!({
            "role": "assistant",
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{}"
                    }
                },
                {
                    "id": "call_2",
                    "type": "function",
                    "function": {
                        "name": "search",
                        "arguments": "{\"query\": \"test\"}"
                    }
                }
            ]
        });
        let calls = ArcOpenAiAdapter::extract_tool_calls(&message);
        assert_eq!(calls.len(), 2);
    }

    // ---- Responses API extraction tests ----

    #[test]
    fn extract_responses_api_calls() {
        let output = json!({
            "output": [
                {
                    "type": "function_call",
                    "call_id": "fc_123",
                    "name": "get_weather",
                    "arguments": "{\"location\": \"LA\"}"
                }
            ]
        });
        let calls = ArcOpenAiAdapter::extract_responses_api_calls(&output);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "get_weather");
        assert_eq!(calls[0].id, "fc_123");
    }

    #[test]
    fn extract_responses_api_filters_non_function_calls() {
        let output = json!({
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "hello"}]
                },
                {
                    "type": "function_call",
                    "call_id": "fc_1",
                    "name": "search",
                    "arguments": "{}"
                }
            ]
        });
        let calls = ArcOpenAiAdapter::extract_responses_api_calls(&output);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "search");
    }

    #[test]
    fn extract_responses_api_empty_output() {
        let output = json!({"output": []});
        let calls = ArcOpenAiAdapter::extract_responses_api_calls(&output);
        assert!(calls.is_empty());
    }

    // ---- Deduplication tests ----

    #[test]
    fn duplicate_tools_across_manifests_deduplicated() {
        let m1 = test_manifest();
        let m2 = test_manifest();
        let adapter = ArcOpenAiAdapter::new(test_config(), vec![m1, m2]).unwrap();
        assert_eq!(adapter.function_names().len(), 2);
    }

    // ---- Error display tests ----

    #[test]
    fn error_display_function_not_found() {
        let err = OpenAiAdapterError::FunctionNotFound("x".into());
        assert!(format!("{err}").contains("x"));
    }

    #[test]
    fn error_display_invalid_request() {
        let err = OpenAiAdapterError::InvalidRequest("bad".into());
        assert!(format!("{err}").contains("bad"));
    }

    #[test]
    fn error_display_kernel() {
        let err = OpenAiAdapterError::Kernel("denied".into());
        assert!(format!("{err}").contains("denied"));
    }

    // ---- Serde tests ----

    #[test]
    fn tool_call_result_serializes() {
        let result = ToolCallResult {
            tool_call_id: "call_1".to_string(),
            name: "test".to_string(),
            content: "ok".to_string(),
            denied: false,
            receipt_ref: Some("receipt-1".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["tool_call_id"], "call_1");
        assert_eq!(json["denied"], false);
    }

    #[test]
    fn tool_call_result_omits_receipt_ref_when_none() {
        let result = ToolCallResult {
            tool_call_id: "call_1".to_string(),
            name: "test".to_string(),
            content: "ok".to_string(),
            denied: false,
            receipt_ref: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("receipt_ref").is_none());
    }

    #[test]
    fn openai_tool_def_roundtrips() {
        let def = OpenAiToolDef {
            tool_type: "function".to_string(),
            function: OpenAiFunctionDef {
                name: "test".to_string(),
                description: "A test function".to_string(),
                parameters: json!({"type": "object"}),
            },
        };
        let json = serde_json::to_value(&def).unwrap();
        let roundtripped: OpenAiToolDef = serde_json::from_value(json).unwrap();
        assert_eq!(roundtripped.function.name, "test");
    }

    #[test]
    fn openai_function_call_roundtrips() {
        let call = OpenAiFunctionCall {
            name: "get_weather".to_string(),
            arguments: r#"{"location":"NYC"}"#.to_string(),
        };
        let json = serde_json::to_value(&call).unwrap();
        let roundtripped: OpenAiFunctionCall = serde_json::from_value(json).unwrap();
        assert_eq!(roundtripped.name, "get_weather");
    }

    // ---- String result handling ----

    #[test]
    fn execute_tool_call_with_string_result() {
        let server = MockToolServer {
            response: json!("hello world"),
        };
        let mut adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let result = adapter.execute_tool_call(&weather_tool_call(), &server);
        assert_eq!(result.content, "hello world");
    }

    #[test]
    fn execute_tool_call_with_object_result() {
        let server = MockToolServer {
            response: json!({"temp": 72}),
        };
        let mut adapter = ArcOpenAiAdapter::new(test_config(), vec![test_manifest()]).unwrap();
        let result = adapter.execute_tool_call(&weather_tool_call(), &server);
        assert!(result.content.contains("72"));
    }
}
