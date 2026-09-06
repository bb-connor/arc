//! Provider-native adapter that mediates Ollama `/api/chat` tool-use traffic
//! through the Chio kernel. Pinned upstream API version: `2025-04` (see
//! [`transport::OLLAMA_API_VERSION`]).
//!
//! Ollama runs as a local HTTP daemon (default `http://localhost:11434`) and
//! surfaces tool calls as `tool_calls` entries on the assistant `message`
//! (mirroring the OpenAI `chat/completions` shape). Tool results travel back as
//! `tool` role messages on the next user turn.
//!
//! The adapter forwards a native `/api/chat` request to the daemon through the
//! shared [`chio_provider_adapter_core::http`] transport, then:
//!
//! - [`chat`](OllamaAdapter::chat) posts a non-streaming request and lifts every
//!   `tool_calls` entry into a [`chio_tool_call_fabric::ToolInvocation`];
//! - [`chat_stream`](OllamaAdapter::chat_stream) posts a streaming request and
//!   gates the NDJSON tool-call frames behind a kernel verdict;
//! - [`lift_batch`](OllamaAdapter::lift_batch) lifts tool calls from bytes that
//!   were captured out of band;
//! - [`lower_tool_message`](OllamaAdapter::lower_tool_message) lowers a kernel
//!   verdict back into a [`ToolResultMessage`].

#![forbid(unsafe_code)]

pub mod loaded_weights;
pub mod native;
pub mod streaming;
pub mod transport;

mod response;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use chio_core::canonical::canonical_json_bytes;
use chio_provider_adapter_core::http::{map_http_status, map_transport_error};
use chio_tool_call_fabric::{
    DenyReason, Principal, ProvenanceStamp, ProviderError, ProviderId, ProviderRequest, Redaction,
    ToolInvocation, ToolResult, VerdictResult,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::streaming::GatedNdjsonStream;
use crate::transport::OLLAMA_CHAT_PATH;

pub use native::{ToolCallFunction, ToolCallPart, ToolResultMessage};
pub use transport::{Transport, OLLAMA_API_VERSION, OLLAMA_CHAT_HOST};

/// Provider label used when classifying upstream transport failures.
const PROVIDER_LABEL: &str = "Ollama";

/// Configuration for the Ollama adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OllamaAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`OLLAMA_API_VERSION`].
    pub api_version: String,
    /// Ollama host or instance label. Ollama is a local daemon with no upstream
    /// identity provider, so the host is the stable provenance handle stamped
    /// into the [`Principal::OllamaHost`] slot.
    pub org_id: String,
}

impl OllamaAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`OLLAMA_API_VERSION`].
    pub fn new(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        public_key: impl Into<String>,
        org_id: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            server_name: server_name.into(),
            server_version: server_version.into(),
            public_key: public_key.into(),
            api_version: OLLAMA_API_VERSION.to_string(),
            org_id: org_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct OllamaAdapter {
    config: OllamaAdapterConfig,
    transport: Arc<dyn Transport>,
    admitted_security: Option<BTreeMap<String, chio_manifest::BridgeSecurityMetadata>>,
}

impl OllamaAdapter {
    /// Build a raw provider projection from a config and transport handle.
    ///
    /// This constructor has no manifest authority. Use
    /// [`Self::new_with_registry`] before lifted calls enter an evaluator.
    pub fn new(config: OllamaAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self {
            config,
            transport,
            admitted_security: None,
        }
    }

    /// Build an adapter bound to one verified, policy-admitted Chio server.
    pub fn new_with_registry(
        config: OllamaAdapterConfig,
        transport: Arc<dyn Transport>,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, OllamaAdapterError> {
        let manifest = registry
            .verified_manifest(&config.server_id)
            .map(|signed| &signed.manifest)
            .ok_or_else(|| OllamaAdapterError::RegistryManifestUnavailable {
                server_id: config.server_id.clone(),
            })?;
        if manifest.name != config.server_name
            || manifest.version != config.server_version
            || manifest.public_key != config.public_key
        {
            return Err(OllamaAdapterError::ConfigManifestMismatch {
                server_id: config.server_id.clone(),
            });
        }

        let mut admitted_security = BTreeMap::new();
        for tool in &manifest.tools {
            let security = registry
                .bridge_security(&config.server_id, &tool.name)
                .filter(chio_manifest::BridgeSecurityMetadata::has_registry_coordinates)
                .ok_or_else(|| OllamaAdapterError::RegistrySecurityUnavailable {
                    server_id: config.server_id.clone(),
                    tool_name: tool.name.clone(),
                })?;
            admitted_security.insert(tool.name.clone(), security);
        }

        Ok(Self {
            config,
            transport,
            admitted_security: Some(admitted_security),
        })
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Ollama
    }

    /// Pinned upstream API version (always [`OLLAMA_API_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &OllamaAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    pub(crate) fn ensure_supported_api_version(&self) -> Result<(), ProviderError> {
        if self.config.api_version != OLLAMA_API_VERSION {
            return Err(ProviderError::Malformed(format!(
                "Ollama adapter supports only API version {OLLAMA_API_VERSION}; configured {}",
                self.config.api_version
            )));
        }
        Ok(())
    }

    fn bridge_security_for_tool(
        &self,
        tool_name: &str,
    ) -> Result<Option<chio_manifest::BridgeSecurityMetadata>, ProviderError> {
        let Some(bindings) = &self.admitted_security else {
            return Ok(None);
        };
        bindings.get(tool_name).cloned().map(Some).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "registry-bound Ollama lift has no admitted security sidecar for tool `{tool_name}`"
            ))
        })
    }

    /// Post a non-streaming `/api/chat` request to the Ollama daemon and lift
    /// every `tool_calls` entry from the response.
    ///
    /// `request_body` is the raw native request JSON (model, messages, tools,
    /// and `stream: false`). The response body is buffered and run through
    /// [`lift_batch`](OllamaAdapter::lift_batch). Transport-layer failures are
    /// classified into the fabric [`ProviderError`] taxonomy and fail closed.
    pub async fn chat(&self, request_body: &[u8]) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let response = self
            .transport
            .post_json(OLLAMA_CHAT_PATH, request_body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        if let Some(error) = map_http_status(PROVIDER_LABEL, response.status, &response.body) {
            return Err(error);
        }
        self.lift_batch(ProviderRequest(response.body))
    }

    /// Post a streaming `/api/chat` request and gate its NDJSON tool-call frames.
    ///
    /// Ollama streams `/api/chat` as newline-delimited JSON. The buffered body
    /// is run through [`gate_sse_stream`](OllamaAdapter::gate_sse_stream): each
    /// `tool_calls` entry is evaluated by `evaluate` before its enclosing line
    /// is admitted to the forwarded byte stream.
    pub async fn chat_stream<F>(
        &self,
        request_body: &[u8],
        evaluate: F,
    ) -> Result<GatedNdjsonStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        self.ensure_supported_api_version()?;
        let body = self
            .transport
            .post_ndjson(OLLAMA_CHAT_PATH, request_body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        self.gate_sse_stream(&body, evaluate)
    }

    /// Lift every Ollama `tool_calls` entry in a non-streaming `/api/chat`
    /// response payload.
    pub fn lift_batch(&self, raw: ProviderRequest) -> Result<Vec<ToolInvocation>, ProviderError> {
        self.ensure_supported_api_version()?;
        let calls = response::tool_calls(raw)?;
        if calls.is_empty() {
            return Err(ProviderError::Malformed(
                "Ollama /api/chat payload did not contain tool_calls entries".to_string(),
            ));
        }
        calls
            .iter()
            .enumerate()
            .map(|(index, call)| self.invocation_from_tool_call(index, call))
            .collect()
    }

    pub(crate) fn invocation_from_tool_call(
        &self,
        index: usize,
        call: &ToolCallPart,
    ) -> Result<ToolInvocation, ProviderError> {
        self.ensure_supported_api_version()?;
        validate_tool_call(call)?;
        let bridge_security = self.bridge_security_for_tool(&call.function.name)?;
        let arguments = canonical_json_bytes(&call.function.arguments).map_err(|error| {
            ProviderError::BadToolArgs(format!(
                "Ollama tool_call args failed canonical JSON encoding: {error}"
            ))
        })?;

        Ok(ToolInvocation {
            provider: ProviderId::Ollama,
            tool_name: call.function.name.clone(),
            arguments,
            provenance: ProvenanceStamp {
                provider: ProviderId::Ollama,
                request_id: synthesised_request_id(&call.function.name, index),
                api_version: self.config.api_version.clone(),
                principal: Principal::OllamaHost {
                    host: self.config.org_id.clone(),
                },
                received_at: SystemTime::now(),
            },
            bridge_security,
        })
    }

    /// Lower a kernel verdict and tool result into a [`ToolResultMessage`].
    pub fn lower_tool_message(
        &self,
        tool_name: &str,
        verdict: VerdictResult,
        result: ToolResult,
    ) -> Result<ToolResultMessage, ProviderError> {
        self.ensure_supported_api_version()?;
        let tool_name = non_empty_str(tool_name, "tool_call.function.name")?;
        match verdict {
            VerdictResult::Allow { redactions, .. } => {
                lower_allow_tool_message(tool_name, result, &redactions)
            }
            VerdictResult::Deny { reason, .. } => lower_deny_tool_message(tool_name, &reason),
        }
    }
}

fn lower_allow_tool_message(
    tool_name: &str,
    result: ToolResult,
    redactions: &[Redaction],
) -> Result<ToolResultMessage, ProviderError> {
    let value = parse_value(&result.0)?;
    let value = apply_redactions(value, redactions, "Ollama tool_result")?;
    let content = canonical_json_bytes(&value).map_err(|error| {
        ProviderError::Malformed(format!(
            "Ollama tool_result canonical encoding failed: {error}"
        ))
    })?;
    let content = String::from_utf8(content).map_err(|error| {
        ProviderError::Malformed(format!(
            "Ollama tool_result canonical bytes were not UTF-8: {error}"
        ))
    })?;
    Ok(ToolResultMessage::new(tool_name, content))
}

fn lower_deny_tool_message(
    tool_name: &str,
    reason: &DenyReason,
) -> Result<ToolResultMessage, ProviderError> {
    let payload = deny_payload(reason);
    let content = serde_json::to_string(&payload).map_err(|error| {
        ProviderError::Malformed(format!("Ollama deny payload encoding failed: {error}"))
    })?;
    Ok(ToolResultMessage::new(tool_name, content))
}

impl chio_provider_adapter_core::Provider for OllamaAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum OllamaAdapterError {
    /// A lift/lower or payload-shape failure surfaced by the fabric.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// An outbound `/api/chat` call failed at the transport layer.
    #[error(transparent)]
    Transport(#[from] chio_provider_adapter_core::http::HttpTransportError),
    /// The configured server has no admitted signed manifest.
    #[error("verified manifest registry has no Ollama server {server_id}")]
    RegistryManifestUnavailable { server_id: String },
    /// Runtime configuration must identify exactly the admitted publisher surface.
    #[error("Ollama adapter config does not match admitted manifest for {server_id}")]
    ConfigManifestMismatch { server_id: String },
    /// A verified tool did not retain registry-admitted bridge metadata.
    #[error(
        "verified manifest registry has no admitted security sidecar for Ollama tool {server_id}/{tool_name}"
    )]
    RegistrySecurityUnavailable {
        server_id: String,
        tool_name: String,
    },
}

fn validate_tool_call(call: &ToolCallPart) -> Result<(), ProviderError> {
    non_empty_str(&call.function.name, "tool_call.function.name")?;
    if !call.function.arguments.is_object() {
        return Err(ProviderError::BadToolArgs(format!(
            "Ollama tool_call `{}` arguments were not a JSON object",
            call.function.name
        )));
    }
    Ok(())
}

fn synthesised_request_id(name: &str, index: usize) -> String {
    format!("ollama_{name}_call_{index}")
}

fn parse_value(bytes: &[u8]) -> Result<Value, ProviderError> {
    serde_json::from_slice(bytes).map_err(|error| {
        ProviderError::Malformed(format!("tool result was not JSON bytes: {error}"))
    })
}

fn apply_redactions(
    mut value: Value,
    redactions: &[Redaction],
    context: &str,
) -> Result<Value, ProviderError> {
    for redaction in redactions {
        if redaction.path.is_empty() {
            value = Value::String(redaction.replacement.clone());
            continue;
        }
        if !redaction.path.starts_with('/') {
            return Err(ProviderError::Malformed(format!(
                "{context} redaction path `{}` is not a JSON Pointer",
                redaction.path
            )));
        }
        let target = value.pointer_mut(&redaction.path).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "{context} redaction path `{}` did not resolve",
                redaction.path
            ))
        })?;
        *target = Value::String(redaction.replacement.clone());
    }
    Ok(value)
}

fn deny_payload(reason: &DenyReason) -> Value {
    let text = match reason {
        DenyReason::PolicyDeny { rule_id } => format!("policy_deny: {rule_id}"),
        DenyReason::GuardDeny { guard_id, detail } => {
            format!("guard_deny: {guard_id}: {detail}")
        }
        DenyReason::CapabilityExpired => "capability_expired".to_string(),
        DenyReason::PrincipalUnknown => "principal_unknown".to_string(),
        DenyReason::BudgetExceeded => "budget_exceeded".to_string(),
    };
    json!({ "error": text })
}

fn non_empty_str<'a>(value: &'a str, field: &str) -> Result<&'a str, ProviderError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(ProviderError::Malformed(format!(
            "Ollama {field} must not be empty"
        )))
    } else if trimmed != value {
        Err(ProviderError::Malformed(format!(
            "Ollama {field} must not contain surrounding whitespace"
        )))
    } else {
        Ok(value)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
