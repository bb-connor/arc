//! ProviderAdapter implementation for Anthropic Messages batch payloads.
//!
//! This module lifts non-streaming `messages.create` `tool_use` content
//! blocks into Chio's shared [`chio_tool_call_fabric::ToolInvocation`] shape
//! and lowers kernel verdicts back into Anthropic `tool_result` blocks for
//! the next user message.

#[path = "streaming.rs"]
pub mod streaming;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderAdapter, ProviderError, ProviderId,
    ProviderRequest, ProviderResponse, ToolInvocation, ToolResult, VerdictResult,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{AnthropicAdapter, ToolResultBlock, ToolUseBlock};

const SERVER_TOOL_NAMES: [&str; 3] = [
    "computer_use_20241022",
    "bash_20241022",
    "text_editor_20241022",
];

impl AnthropicAdapter {
    /// Lift every Anthropic `tool_use` content block in a non-streaming
    /// `messages.create` response payload.
    ///
    /// Accepted payload forms:
    /// - a plain Anthropic Message object with a `content` array
    /// - an envelope with `body`, `response`, `payload`, or `message`
    /// - a single `tool_use` content block
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        let blocks = tool_use_blocks(raw)?;
        if blocks.is_empty() {
            return Err(ProviderError::Malformed(
                "messages.create payload did not contain Anthropic tool_use content blocks"
                    .to_string(),
            ));
        }

        let invocations = blocks
            .iter()
            .map(|block| self.invocation_from_tool_use(block))
            .collect::<Result<Vec<_>, _>>()?;
        self.replace_pending_tool_use_ids(blocks.iter().map(|block| block.id.clone()).collect())?;
        Ok(invocations)
    }

    fn lift_one(&self, raw: ProviderRequest) -> Result<ToolInvocation, ProviderError> {
        let blocks = tool_use_blocks(raw)?;
        if blocks.len() != 1 {
            return Err(ProviderError::Malformed(format!(
                "ProviderAdapter::lift expected exactly one Anthropic tool_use block, found {}",
                blocks.len()
            )));
        }

        let block = blocks.into_iter().next().ok_or_else(|| {
            ProviderError::Malformed(
                "ProviderAdapter::lift lost the extracted Anthropic tool_use block".to_string(),
            )
        })?;
        let invocation = self.invocation_from_tool_use(&block)?;
        self.replace_pending_tool_use_ids(vec![block.id])?;
        Ok(invocation)
    }

    fn invocation_from_tool_use(
        &self,
        block: &ToolUseBlock,
    ) -> Result<ToolInvocation, ProviderError> {
        validate_tool_use_block(block)?;
        ensure_server_tool_feature(&block.name)?;
        self.server_tool_gate().ensure_tool_allowed(&block.name)?;
        let arguments = canonical_json_bytes(&block.input)?;

        Ok(ToolInvocation {
            provider: ProviderId::Anthropic,
            tool_name: block.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Anthropic,
                request_id: block.id.clone(),
                api_version: self.config().api_version.clone(),
                principal: Principal::AnthropicWorkspace {
                    workspace_id: self.config().workspace_id.clone(),
                },
                received_at: SystemTime::now(),
            },
        })
    }

    /// Lower a kernel verdict and canonical tool result into an Anthropic
    /// `tool_result` content block.
    pub fn lower_tool_result_block(
        &self,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ToolResultBlock, ProviderError> {
        let tool_use_id = self.pop_pending_tool_use_id()?;
        match verdict {
            VerdictResult::Allow { .. } => {
                let content = parse_tool_result(result)?;
                Ok(ToolResultBlock::allow(tool_use_id, content))
            }
            VerdictResult::Deny { reason, .. } => {
                Ok(ToolResultBlock::deny(tool_use_id, deny_content(&reason)))
            }
        }
    }

    fn replace_pending_tool_use_ids(&self, ids: Vec<String>) -> Result<(), ProviderError> {
        let mut guard = self.pending_tool_use_ids.lock().map_err(|_| {
            ProviderError::Malformed("Anthropic pending tool_use state is unavailable".to_string())
        })?;
        guard.clear();
        guard.extend(ids);
        Ok(())
    }

    fn push_pending_tool_use_id(&self, id: String) -> Result<(), ProviderError> {
        let mut guard = self.pending_tool_use_ids.lock().map_err(|_| {
            ProviderError::Malformed("Anthropic pending tool_use state is unavailable".to_string())
        })?;
        guard.push_back(id);
        Ok(())
    }

    fn pop_pending_tool_use_id(&self) -> Result<String, ProviderError> {
        let mut guard = self.pending_tool_use_ids.lock().map_err(|_| {
            ProviderError::Malformed("Anthropic pending tool_use state is unavailable".to_string())
        })?;
        guard.pop_front().ok_or_else(|| {
            ProviderError::Malformed(
                "cannot lower Anthropic tool_result without a pending tool_use id".to_string(),
            )
        })
    }
}

impl ProviderAdapter for AnthropicAdapter {
    fn provider(&self) -> ProviderId {
        ProviderId::Anthropic
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }

    fn lift<'life0, 'async_trait>(
        &'life0 self,
        raw: ProviderRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ToolInvocation, ProviderError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { self.lift_one(raw) })
    }

    fn lower<'life0, 'async_trait>(
        &'life0 self,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Pin<Box<dyn Future<Output = Result<ProviderResponse, ProviderError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let block = self.lower_tool_result_block(verdict, result)?;
            serde_json::to_vec(&block)
                .map(ProviderResponse)
                .map_err(|error| {
                    ProviderError::Malformed(format!(
                        "Anthropic tool_result block failed JSON encoding: {error}"
                    ))
                })
        })
    }
}

fn tool_use_blocks(raw: ProviderRequest) -> Result<Vec<ToolUseBlock>, ProviderError> {
    let value: Value = serde_json::from_slice(&raw.0).map_err(|error| {
        ProviderError::Malformed(format!("messages.create payload was not JSON: {error}"))
    })?;
    let body = message_body(value)?;
    extract_tool_use_blocks(&body)
}

fn message_body(value: Value) -> Result<Value, ProviderError> {
    for field in ["body", "response", "payload", "message"] {
        if let Some(nested) = value.get(field) {
            return nested_message_body(nested).ok_or_else(|| {
                ProviderError::Malformed(format!(
                    "messages.create envelope field `{field}` was not a JSON object or string body"
                ))
            });
        }
    }

    Ok(value)
}

fn nested_message_body(value: &Value) -> Option<Value> {
    match value {
        Value::Object(_) => Some(value.clone()),
        Value::String(body) => serde_json::from_str(body).ok(),
        _ => None,
    }
}

fn extract_tool_use_blocks(body: &Value) -> Result<Vec<ToolUseBlock>, ProviderError> {
    if is_tool_use_block(body) {
        return parse_tool_use_block(body).map(|block| vec![block]);
    }

    let content = body.get("content").ok_or_else(|| {
        ProviderError::Malformed(
            "messages.create payload did not contain an Anthropic content array".to_string(),
        )
    })?;
    let content = content.as_array().ok_or_else(|| {
        ProviderError::Malformed("Anthropic message `content` field was not an array".to_string())
    })?;

    content
        .iter()
        .filter(|block| is_tool_use_block(block))
        .map(parse_tool_use_block)
        .collect()
}

fn is_tool_use_block(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|block_type| block_type == "tool_use")
}

fn parse_tool_use_block(value: &Value) -> Result<ToolUseBlock, ProviderError> {
    serde_json::from_value(value.clone()).map_err(|error| {
        ProviderError::Malformed(format!("Anthropic tool_use block was malformed: {error}"))
    })
}

fn validate_tool_use_block(block: &ToolUseBlock) -> Result<(), ProviderError> {
    if block.block_type != "tool_use" {
        return Err(ProviderError::Malformed(format!(
            "Anthropic content block type `{}` was not tool_use",
            block.block_type
        )));
    }
    if block.id.trim().is_empty() {
        return Err(ProviderError::Malformed(
            "Anthropic tool_use id was empty".to_string(),
        ));
    }
    if block.name.trim().is_empty() {
        return Err(ProviderError::Malformed(
            "Anthropic tool_use name was empty".to_string(),
        ));
    }
    if !block.input.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "Anthropic tool_use `{}` input was not a JSON object",
            block.id
        )));
    }
    Ok(())
}

fn ensure_server_tool_feature(name: &str) -> Result<(), ProviderError> {
    if SERVER_TOOL_NAMES.contains(&name) && !cfg!(feature = "computer-use") {
        return Err(ProviderError::Malformed(format!(
            "Anthropic server tool `{name}` requires the `computer-use` cargo feature"
        )));
    }
    Ok(())
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, ProviderError> {
    let mut out = Vec::new();
    write_canonical_value(value, &mut out)?;
    Ok(out)
}

fn write_canonical_value(value: &Value, out: &mut Vec<u8>) -> Result<(), ProviderError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(value) => {
            if *value {
                out.extend_from_slice(b"true");
            } else {
                out.extend_from_slice(b"false");
            }
        }
        Value::Number(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => write_json(value, out)?,
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_value(value, out)?;
            }
            out.push(b']');
        }
        Value::Object(values) => {
            out.push(b'{');
            let entries: BTreeMap<&str, &Value> = values
                .iter()
                .map(|(key, value)| (key.as_str(), value))
                .collect();
            for (index, (key, value)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json(key, out)?;
                out.push(b':');
                write_canonical_value(value, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_json<T: Serialize + ?Sized>(value: &T, out: &mut Vec<u8>) -> Result<(), ProviderError> {
    serde_json::to_writer(out, value).map_err(|error| {
        ProviderError::BadToolArgs(format!(
            "Anthropic tool_use input failed canonical JSON encoding: {error}"
        ))
    })
}

fn parse_tool_result(result: ToolResult) -> Result<Value, ProviderError> {
    serde_json::from_slice(&result.0).map_err(|error| {
        ProviderError::Malformed(format!("tool result was not JSON bytes: {error}"))
    })
}

fn deny_content(reason: &DenyReason) -> Value {
    let text = match reason {
        DenyReason::PolicyDeny { rule_id } => format!("policy_deny: {rule_id}"),
        DenyReason::GuardDeny { guard_id, detail } => {
            format!("guard_deny: {guard_id}: {detail}")
        }
        DenyReason::CapabilityExpired => "capability_expired".to_string(),
        DenyReason::PrincipalUnknown => "principal_unknown".to_string(),
        DenyReason::BudgetExceeded => "budget_exceeded".to_string(),
    };
    json!([{ "type": "text", "text": text }])
}
