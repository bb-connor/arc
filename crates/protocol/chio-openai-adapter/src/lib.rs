//! # chio-openai
//!
//! Adapter that intercepts OpenAI-style tool_use / function-calling requests
//! and routes them through the Chio kernel for capability validation and
//! receipt signing.
//!
//! Supports both:
//! - **Chat Completions API** format (function_call / tool_calls)
//! - **Responses API** format (tool invocations)
//!
//! Every function call produces a signed receipt. Guards fail closed by default.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use chio_core::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent},
    scope::ModelMetadata,
    threshold_approval::ThresholdApprovalProposal,
    token::CapabilityToken,
};
use chio_core::message::OpaqueSupplementalAuthorization;
use chio_core::receipt::body::ChioReceipt;
use chio_core::session::{
    OperationContext, OperationTerminalState, RequestId, SessionId, ToolCallOperation,
};
use chio_cross_protocol::discovery::{DiscoveryProtocol, TargetProtocolRegistry};
use chio_cross_protocol::routing::{plan_authoritative_route, route_selection_metadata};
use chio_kernel::{
    dpop, ChioKernel, SecurityInvocationContext, SecurityInvocationContextAuthority,
    SignedExecutionNonce, ToolCallOutput, ToolCallRequest, ToolCallResponse,
    Verdict as KernelVerdict,
};
use chio_manifest::{BridgeSecurityMetadata, ToolDefinition, ToolManifest};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[cfg(feature = "provider-adapter")]
pub mod adapter;

#[cfg(feature = "provider-adapter")]
pub use adapter::{
    OpenAiAdapter, OpenAiAdapterConfig as OpenAiProviderAdapterConfig, OPENAI_RESPONSES_API_VERSION,
};

#[cfg(feature = "provider-adapter")]
pub mod streaming;

#[cfg(feature = "provider-adapter")]
pub mod transport;

#[cfg(feature = "provider-adapter")]
pub use transport::{
    ChatCompletionsOutcome, OpenAiTransport, OPENAI_API_BASE_URL, OPENAI_API_KEY_ENV,
    OPENAI_CHAT_COMPLETIONS_PATH, OPENAI_RESPONSES_PATH,
};

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
    Manifest(#[from] chio_manifest::ManifestError),
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
    /// Whether this result is a nonce preflight instead of executed tool output.
    #[serde(default)]
    pub preflight: bool,
    /// Signed nonce to present on the retry path when `preflight` is true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<SignedExecutionNonce>,
    /// Receipt reference (if generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    /// Signed receipt returned by the kernel (if generated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ChioReceipt>,
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

/// Execution context required to route OpenAI tool calls through the kernel.
#[derive(Debug, Clone)]
pub struct OpenAiExecutionContext {
    /// Capability token authorizing the requested tools.
    pub capability: CapabilityToken,
    /// Hex-encoded public key or stable agent identifier for subject binding.
    pub agent_id: String,
    /// Optional DPoP proof bound to this invocation.
    pub dpop_proof: Option<dpop::DpopProof>,
    /// Optional execution nonces for strict kernel dispatch, keyed by OpenAI
    /// tool-call ID. Execution nonces are single-use and bound to one retry,
    /// so batch execution must not reuse one nonce across all tool calls.
    pub execution_nonces: BTreeMap<String, SignedExecutionNonce>,
    /// Optional governed transaction intent.
    pub governed_intent: Option<GovernedTransactionIntent>,
    /// Optional governed approval token.
    pub approval_token: Option<GovernedApprovalToken>,
    /// Complete approval token set for threshold-governed execution.
    pub approval_tokens: Vec<GovernedApprovalToken>,
    /// Signed proposal binding a threshold token set to this request.
    pub threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    /// Optional originating model metadata for model-constrained grants.
    pub model_metadata: Option<ModelMetadata>,
    /// Opaque signed authorization forwarded only to the installed verifier.
    pub supplemental_authorization: Option<OpaqueSupplementalAuthorization>,
    /// Authoritative identity and isolation state resolved by the trusted
    /// provider host. It is never derived from provider response fields.
    pub security_context: Option<SecurityInvocationContext>,
}

fn tool_call_operation_from_request(
    request: &ToolCallRequest,
) -> Result<ToolCallOperation, String> {
    let execution_nonce = request
        .execution_nonce
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| format!("serialize execution nonce for authority resolution: {error}"))?;
    Ok(ToolCallOperation {
        capability: request.capability.clone(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        supplemental_authorization: request.supplemental_authorization.clone(),
        governed_intent: request.governed_intent.clone(),
        approval_token: request.approval_token.clone(),
        approval_tokens: request.approval_tokens.clone(),
        threshold_approval_proposal: request.threshold_approval_proposal.clone(),
        execution_nonce,
        model_metadata: request.model_metadata.clone(),
        extra_metadata: None,
        declassification_grant: request.declassification_grant.clone(),
    })
}

/// The OpenAI adapter.
///
/// Wraps Chio tool manifests and processes OpenAI-style function calls
/// through the kernel guard pipeline.
#[derive(Debug)]
pub struct ChioOpenAiAdapter {
    manifest: ToolManifest,
    /// Maps function name to (server_id, tool_name).
    function_bindings: BTreeMap<String, (String, String)>,
    function_security: BTreeMap<String, BridgeSecurityMetadata>,
    manifest_registry: Option<chio_manifest::VerifiedManifestRegistry>,
}

impl ChioOpenAiAdapter {
    /// Create a new adapter from registered-key, policy, and topology admitted manifests.
    pub fn new(
        config: OpenAiAdapterConfig,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, OpenAiAdapterError> {
        let manifests = registry
            .verified_manifests()
            .map(|signed| signed.manifest.clone())
            .collect();
        Self::new_internal(config, manifests, Some(registry))
    }

    #[cfg(test)]
    pub(crate) fn new_from_unverified_internal(
        config: OpenAiAdapterConfig,
        manifests: Vec<ToolManifest>,
    ) -> Result<Self, OpenAiAdapterError> {
        Self::new_internal(config, manifests, None)
    }

    fn new_internal(
        config: OpenAiAdapterConfig,
        manifests: Vec<ToolManifest>,
        registry: Option<&chio_manifest::VerifiedManifestRegistry>,
    ) -> Result<Self, OpenAiAdapterError> {
        let mut all_tools = Vec::new();
        let mut function_bindings = BTreeMap::new();
        let mut function_security = BTreeMap::new();

        for manifest in &manifests {
            for tool in &manifest.tools {
                let func_name = tool.name.clone();
                if function_bindings.contains_key(&func_name) {
                    continue;
                }
                function_bindings.insert(
                    func_name.clone(),
                    (manifest.server_id.clone(), tool.name.clone()),
                );
                let security = match registry {
                    Some(registry) => registry
                        .bridge_security(&manifest.server_id, &tool.name)
                        .ok_or_else(|| {
                            OpenAiAdapterError::InvalidRequest(format!(
                                "verified manifest registry has no admitted security for {}/{}",
                                manifest.server_id, tool.name
                            ))
                        })?,
                    None => BridgeSecurityMetadata::from_tool(tool),
                };
                function_security.insert(func_name, security);
                all_tools.push(tool.clone());
            }
        }

        if all_tools.is_empty() {
            return Err(OpenAiAdapterError::InvalidRequest(
                "no tools to expose".to_string(),
            ));
        }

        let manifest = ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: Some("Chio tools exposed via OpenAI function calling".to_string()),
            version: config.server_version.clone(),
            tools: all_tools,
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: config.public_key.clone(),
        };

        chio_manifest::validate_manifest(&manifest)?;

        Ok(Self {
            manifest,
            function_bindings,
            function_security,
            manifest_registry: registry.cloned(),
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
        self.manifest.tools.iter().map(|t| t.name.clone()).collect()
    }

    /// Get a tool definition by function name.
    pub fn function_def(&self, name: &str) -> Option<&ToolDefinition> {
        self.manifest.tools.iter().find(|t| t.name == name)
    }

    fn build_tool_call_request(
        &self,
        tool_call: &OpenAiToolCall,
        execution: &OpenAiExecutionContext,
    ) -> Result<ToolCallRequest, String> {
        let (server_id, tool_name) = match self.function_bindings.get(&tool_call.function.name) {
            Some((server_id, name)) => (server_id.clone(), name.clone()),
            None => {
                return Err(format!(
                    "Error: function '{}' not found",
                    tool_call.function.name
                ));
            }
        };
        let arguments = serde_json::from_str::<Value>(&tool_call.function.arguments)
            .map_err(|error| format!("Error: failed to parse arguments: {error}"))?;
        let request = ToolCallRequest {
            request_id: format!("openai-{}", tool_call.id),
            capability: execution.capability.clone(),
            tool_name,
            server_id,
            agent_id: execution.agent_id.clone(),
            arguments,
            dpop_proof: execution.dpop_proof.clone(),
            execution_nonce: execution.execution_nonces.get(&tool_call.id).cloned(),
            governed_intent: execution.governed_intent.clone(),
            approval_token: execution.approval_token.clone(),
            approval_tokens: execution.approval_tokens.clone(),
            threshold_approval_proposal: execution.threshold_approval_proposal.clone(),
            model_metadata: execution.model_metadata.clone(),
            supplemental_authorization: execution.supplemental_authorization.clone(),
            federated_origin_kernel_id: None,
            declassification_grant: None,
        };
        request
            .validate()
            .map_err(|error| format!("Error: invalid authorization context: {error}"))?;
        Ok(request)
    }

    /// Execute an OpenAI tool call through the Chio kernel.
    ///
    /// This is the core interception point. Every function call produces
    /// a signed receipt via the kernel guard pipeline.
    pub fn execute_tool_call(
        &self,
        tool_call: &OpenAiToolCall,
        kernel: &ChioKernel,
        execution: &OpenAiExecutionContext,
    ) -> ToolCallResult {
        self.execute_tool_call_with_security_context_resolver(
            tool_call,
            kernel,
            execution,
            None,
            |_| Ok(execution.security_context.clone()),
        )
    }

    fn execute_tool_call_with_security_context_resolver<F>(
        &self,
        tool_call: &OpenAiToolCall,
        kernel: &ChioKernel,
        execution: &OpenAiExecutionContext,
        authenticated_session_id: Option<&SessionId>,
        resolve_security_context: F,
    ) -> ToolCallResult
    where
        F: FnOnce(&ToolCallRequest) -> Result<Option<SecurityInvocationContext>, String>,
    {
        let request = match self.build_tool_call_request(tool_call, execution) {
            Ok(request) => request,
            Err(error) => return denied_tool_call_result(tool_call, error),
        };

        let route_plan = match plan_authoritative_route(
            &request.request_id,
            DiscoveryProtocol::OpenAi,
            DiscoveryProtocol::Native,
            execution.governed_intent.as_ref(),
            &TargetProtocolRegistry::new(DiscoveryProtocol::Native),
            &BTreeMap::new(),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                return denied_tool_call_result(
                    tool_call,
                    format!("Error: failed to plan authoritative route: {error}"),
                );
            }
        };
        let route_metadata = match route_selection_metadata(&route_plan.evidence) {
            Ok(metadata) => metadata,
            Err(error) => {
                return denied_tool_call_result(
                    tool_call,
                    format!("Error: failed to serialize route selection: {error}"),
                );
            }
        };
        let Some(security) = self.function_security.get(&tool_call.function.name) else {
            return denied_tool_call_result(
                tool_call,
                "Error: internal bridge security sidecar is missing",
            );
        };
        let security_context = match resolve_security_context(&request) {
            Ok(security_context) => security_context,
            Err(error) => {
                return denied_tool_call_result(
                    tool_call,
                    format!("Error: failed to resolve authoritative security context: {error}"),
                );
            }
        };
        let evaluation = match (
            self.manifest_registry.as_ref(),
            security_context.as_ref(),
            authenticated_session_id,
        ) {
            (Some(registry), Some(security_context), Some(authenticated_session_id)) => kernel
                .evaluate_tool_call_blocking_with_manifest_security_and_authenticated_session_context(
                    &request,
                    registry,
                    security,
                    Some(route_metadata),
                    authenticated_session_id,
                    security_context,
                ),
            (Some(registry), Some(security_context), None) => kernel
                .evaluate_tool_call_blocking_with_manifest_security_and_security_context(
                    &request,
                    registry,
                    security,
                    Some(route_metadata),
                    security_context,
                ),
            (Some(registry), None, _) => kernel.evaluate_tool_call_blocking_with_manifest_security(
                &request,
                registry,
                security,
                Some(route_metadata),
            ),
            (None, _, _) => {
                kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(route_metadata))
            }
        };

        match evaluation {
            Ok(response) => {
                let preflight_reason = execution_nonce_preflight_reason(&response);
                let preflight = preflight_reason.is_some();
                let execution_nonce = response.execution_nonce.as_deref().cloned();
                let denied = !matches!(response.verdict, KernelVerdict::Allow) || preflight;
                let content = preflight_reason.unwrap_or_else(|| {
                    render_response_content(&response.output, response.reason.as_deref())
                });
                let receipt_ref = Some(response.receipt.id.clone());
                ToolCallResult {
                    tool_call_id: tool_call.id.clone(),
                    name: tool_call.function.name.clone(),
                    content,
                    denied,
                    preflight,
                    execution_nonce,
                    receipt_ref,
                    receipt: Some(response.receipt),
                }
            }
            Err(error) => denied_tool_call_result(tool_call, format!("Error: {error}")),
        }
    }

    /// Execute multiple tool calls (batch processing).
    pub fn execute_tool_calls(
        &self,
        tool_calls: &[OpenAiToolCall],
        kernel: &ChioKernel,
        execution: &OpenAiExecutionContext,
    ) -> Vec<ToolCallResult> {
        if tool_calls.len() > 1 && execution.security_context.is_some() {
            return tool_calls
                .iter()
                .map(|tool_call| {
                    denied_tool_call_result(
                        tool_call,
                        "Error: OpenAI batch security state must be resolved separately for each tool call",
                    )
                })
                .collect();
        }
        tool_calls
            .iter()
            .map(|tc| self.execute_tool_call(tc, kernel, execution))
            .collect()
    }

    /// Execute a batch while resolving authoritative security state after
    /// each request has been finalized and immediately before its kernel
    /// dispatch.
    pub fn execute_tool_calls_with_security_context_authority(
        &self,
        tool_calls: &[OpenAiToolCall],
        kernel: &ChioKernel,
        execution: &OpenAiExecutionContext,
        authenticated_context: &OperationContext,
        authority: &dyn SecurityInvocationContextAuthority,
    ) -> Vec<ToolCallResult> {
        if authenticated_context.agent_id.as_str() != execution.agent_id.as_str() {
            return tool_calls
                .iter()
                .map(|tool_call| {
                    denied_tool_call_result(
                        tool_call,
                        "Error: OpenAI batch authority context does not match the authenticated agent",
                    )
                })
                .collect();
        }

        tool_calls
            .iter()
            .map(|tool_call| {
                let mut dispatch_context = authenticated_context.clone();
                dispatch_context.request_id = RequestId::new(format!("openai-{}", tool_call.id));
                self.execute_tool_call_with_security_context_resolver(
                    tool_call,
                    kernel,
                    execution,
                    Some(&dispatch_context.session_id),
                    |request| {
                        let operation = tool_call_operation_from_request(request)?;
                        let security_context = authority
                            .resolve_security_invocation_context(&dispatch_context, &operation)
                            .map_err(|error| error.to_string())?;
                        if security_context.as_v1().session_id().as_str()
                            != dispatch_context.session_id.as_str()
                        {
                            return Err(
                                "authoritative security context does not match the authenticated session"
                                    .to_string(),
                            );
                        }
                        Ok(Some(security_context))
                    },
                )
            })
            .collect()
    }

    /// Convert tool call results to Chat Completions message format.
    ///
    /// Returns tool role messages suitable for the next Chat Completions request.
    pub fn results_to_messages(results: &[ToolCallResult]) -> Vec<Value> {
        results
            .iter()
            .filter(|result| !result.preflight)
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
            .filter(|result| !result.preflight)
            .map(|r| ResponsesApiOutput {
                output_type: "function_call_output".to_string(),
                call_id: r.tool_call_id.clone(),
                output: r.content.clone(),
            })
            .collect()
    }

    /// Extract tool calls from a Chat Completions response message.
    pub fn extract_tool_calls(message: &Value) -> Result<Vec<OpenAiToolCall>, OpenAiAdapterError> {
        let Some(tool_calls) = message.get("tool_calls") else {
            return Ok(Vec::new());
        };
        let calls = tool_calls.as_array().ok_or_else(|| {
            OpenAiAdapterError::InvalidRequest("tool_calls must be an array".to_string())
        })?;

        calls
            .iter()
            .enumerate()
            .map(|(index, call)| {
                let parsed =
                    serde_json::from_value::<OpenAiToolCall>(call.clone()).map_err(|e| {
                        OpenAiAdapterError::InvalidRequest(format!(
                            "tool_calls[{index}] is malformed: {e}"
                        ))
                    })?;
                validate_tool_call(parsed, &format!("tool_calls[{index}]"))
            })
            .collect()
    }

    /// Extract tool calls from a Responses API output.
    pub fn extract_responses_api_calls(
        output: &Value,
    ) -> Result<Vec<OpenAiToolCall>, OpenAiAdapterError> {
        // Responses API uses a different format with "output" array
        let Some(output_items) = output.get("output") else {
            return Ok(Vec::new());
        };
        let items = output_items.as_array().ok_or_else(|| {
            OpenAiAdapterError::InvalidRequest("output must be an array".to_string())
        })?;

        items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| {
                let item_type = item.get("type").and_then(Value::as_str)?;
                if item_type == "function_call" {
                    Some((index, item))
                } else {
                    None
                }
            })
            .map(|(index, item)| {
                let context = format!("output[{index}] function_call");
                let name = required_string_field(item, "name", &context)?;
                let arguments = required_string_field(item, "arguments", &context)?;
                let call_id = required_string_field(item, "call_id", &context)?;
                validate_tool_call(
                    OpenAiToolCall {
                        id: call_id,
                        call_type: "function".to_string(),
                        function: OpenAiFunctionCall { name, arguments },
                    },
                    &context,
                )
            })
            .collect()
    }
}

fn required_string_field(
    value: &Value,
    field: &str,
    context: &str,
) -> Result<String, OpenAiAdapterError> {
    let Some(value) = value.get(field).and_then(Value::as_str) else {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty {field}"
        )));
    };
    if value.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty {field}"
        )));
    }
    Ok(value.to_string())
}

fn validate_tool_call(
    call: OpenAiToolCall,
    context: &str,
) -> Result<OpenAiToolCall, OpenAiAdapterError> {
    if call.id.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty call_id"
        )));
    }
    if call.id.trim() != call.id {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} call_id must not contain surrounding whitespace"
        )));
    }
    if call.call_type != "function" {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} has unsupported type `{}`",
            call.call_type
        )));
    }
    if call.function.name.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty function.name"
        )));
    }
    if call.function.name.trim() != call.function.name {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} function.name must not contain surrounding whitespace"
        )));
    }
    if call.function.arguments.trim().is_empty() {
        return Err(OpenAiAdapterError::InvalidRequest(format!(
            "{context} missing non-empty function.arguments"
        )));
    }
    Ok(call)
}

fn denied_tool_call_result(
    tool_call: &OpenAiToolCall,
    content: impl Into<String>,
) -> ToolCallResult {
    ToolCallResult {
        tool_call_id: tool_call.id.clone(),
        name: tool_call.function.name.clone(),
        content: content.into(),
        denied: true,
        preflight: false,
        execution_nonce: None,
        receipt_ref: None,
        receipt: None,
    }
}

fn render_response_content(output: &Option<ToolCallOutput>, reason: Option<&str>) -> String {
    match output {
        Some(ToolCallOutput::Value(result)) => {
            if let Some(text) = result.as_str() {
                text.to_string()
            } else {
                serde_json::to_string(result).unwrap_or_else(|_| "{}".to_string())
            }
        }
        Some(ToolCallOutput::Stream(stream)) => {
            let chunks = stream
                .chunks
                .iter()
                .map(|chunk| chunk.data.clone())
                .collect::<Vec<_>>();
            serde_json::to_string(&chunks).unwrap_or_else(|_| "[]".to_string())
        }
        None => reason
            .map(|message| format!("Error: {message}"))
            .unwrap_or_else(|| "{}".to_string()),
    }
}

fn execution_nonce_preflight_reason(response: &ToolCallResponse) -> Option<String> {
    if !matches!(response.verdict, KernelVerdict::Allow) {
        return None;
    }
    let OperationTerminalState::Incomplete { reason } = &response.terminal_state else {
        return None;
    };
    Some(format!(
        "Error: execution nonce preflight did not execute the tool; retry through a nonce-aware path ({reason})"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
