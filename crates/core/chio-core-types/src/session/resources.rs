use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::capability::token::CapabilityToken;
use crate::capability::{
    governance::{GovernedApprovalToken, GovernedTransactionIntent},
    scope::ModelMetadata,
    threshold_approval::{ThresholdApprovalProposal, MAX_THRESHOLD_APPROVAL_TOKENS},
};
use crate::message::OpaqueSupplementalAuthorization;
use crate::{Error, Result, ServerId, SignedDeclassificationGrant};

/// Normalized tool call payload. This is transport-agnostic and suitable for
/// direct kernel evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallOperation {
    pub capability: CapabilityToken,
    pub server_id: ServerId,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplemental_authorization: Option<OpaqueSupplementalAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent: Option<GovernedTransactionIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token: Option<GovernedApprovalToken>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_tokens: Vec<GovernedApprovalToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_approval_proposal: Option<ThresholdApprovalProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_metadata: Option<ModelMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declassification_grant: Option<SignedDeclassificationGrant>,
}

impl ToolCallOperation {
    /// Validate request bounds that cannot be enforced by serde field attributes.
    pub fn validate(&self) -> Result<()> {
        if let Some(authorization) = &self.supplemental_authorization {
            authorization.validate()?;
        }
        if self.approval_token.is_some() && !self.approval_tokens.is_empty() {
            return Err(Error::CanonicalJson(
                "approval_token and approval_tokens must not both be supplied".into(),
            ));
        }
        if self.approval_tokens.len() > MAX_THRESHOLD_APPROVAL_TOKENS {
            return Err(Error::CanonicalJson(
                "approval token set exceeds the protocol ceiling".into(),
            ));
        }
        Ok(())
    }
}

/// Resource metadata exposed through the session layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<serde_json::Value>,
}

/// Parameterized resource template metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTemplateDefinition {
    pub uri_template: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<serde_json::Value>,
}

/// Resource content payload returned by a read request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<serde_json::Value>,
}

/// Prompt argument metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PromptArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// Prompt metadata exposed through the session layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PromptDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<PromptArgument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icons: Option<serde_json::Value>,
}

/// Message inside a prompt response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PromptMessage {
    pub role: String,
    pub content: serde_json::Value,
}

/// Prompt retrieval result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PromptResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub messages: Vec<PromptMessage>,
}

/// Reference target for an MCP-style completion request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CompletionReference {
    Prompt { name: String },
    Resource { uri: String },
}

/// In-progress argument being completed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompletionArgument {
    pub name: String,
    pub value: String,
}

/// Completion result payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CompletionResult {
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    pub has_more: bool,
}

/// Message content submitted for client-side sampling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SamplingMessage {
    pub role: String,
    pub content: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "_meta")]
    pub meta: Option<serde_json::Value>,
}

/// Tool schema advertised to a client during a sampling request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SamplingTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// Controls whether tool use is allowed during client-side sampling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SamplingToolChoice {
    pub mode: String,
}
