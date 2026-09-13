//! Tool server manifests: signed declarations of available tools.
//!
//! Each tool server publishes a signed manifest at startup. The Kernel verifies
//! the signature before accepting any tools from the server.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

pub use chio_security_types::flow::{
    DeclassificationPurpose, ToolFlowDeclaration, ToolFlowValidationError,
};

use crate::capability::scope::MonetaryAmount;
use crate::crypto::{Keypair, PublicKey, Signature};
use crate::error::Result;
use crate::signer_binding::ensure_keypair_matches_embedded_key;

fn deserialize_present_option<'de, D, T>(
    deserializer: D,
) -> core::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Err(serde::de::Error::custom(
            "explicit null is not a canonical manifest representation",
        ));
    }
    T::deserialize(value)
        .map(Some)
        .map_err(serde::de::Error::custom)
}

/// A Chio tool server manifest. Signed by the server's Ed25519 key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifest {
    /// Unique identifier for this tool server.
    pub server_id: String,
    /// The server's Ed25519 public key.
    pub server_key: PublicKey,
    /// Tools offered by this server.
    pub tools: Vec<ToolDefinition>,
    /// Host capabilities the server requires (e.g. "fs_read", "network").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
    /// Ed25519 signature over canonical JSON of all fields above.
    pub signature: Signature,
}

/// The body of a manifest (everything except the signature), used for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolManifestBody {
    pub server_id: String,
    pub server_key: PublicKey,
    pub tools: Vec<ToolDefinition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_capabilities: Vec<String>,
}

impl ToolManifest {
    /// Sign a manifest body with the server's keypair.
    pub fn sign(body: ToolManifestBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(
            &body.server_key,
            keypair,
            "tool manifest",
            "server_key",
        )?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            server_id: body.server_id,
            server_key: body.server_key,
            tools: body.tools,
            required_capabilities: body.required_capabilities,
            signature,
        })
    }

    /// Extract the body for re-verification.
    #[must_use]
    pub fn body(&self) -> ToolManifestBody {
        ToolManifestBody {
            server_id: self.server_id.clone(),
            server_key: self.server_key.clone(),
            tools: self.tools.clone(),
            required_capabilities: self.required_capabilities.clone(),
        }
    }

    /// Verify the manifest signature against the server's public key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.server_key.verify_canonical(&body, &self.signature)
    }
}

/// A single tool offered by a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    /// Tool name (must be unique within the server).
    pub name: String,
    /// Human-readable description. Sanitized before the LLM sees it.
    /// Maximum 500 characters, validated at manifest verification time.
    pub description: String,
    /// JSON Schema for the tool's input parameters.
    pub input_schema: serde_json::Value,
    /// JSON Schema for the tool's output (optional).
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub output_schema: Option<serde_json::Value>,
    /// Optional advertised pricing metadata for operator and agent planning.
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub pricing: Option<ToolPricing>,
    /// Behavioral annotations for policy and scheduling decisions.
    pub annotations: ToolAnnotations,
    /// Categorical execution-time hint.
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub latency_hint: Option<LatencyHint>,
    /// Publisher-authenticated information-flow constraints.
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub flow: Option<ToolFlowDeclaration>,
}

/// Optional advertised pricing metadata for a tool manifest entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPricing {
    pub pricing_model: PricingModel,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub base_price: Option<MonetaryAmount>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub unit_price: Option<MonetaryAmount>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub billing_unit: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PricingModel {
    Flat,
    PerInvocation,
    PerUnit,
    Hybrid,
}

/// Behavioral annotations that help the Kernel make policy and scheduling
/// decisions without inspecting the tool implementation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAnnotations {
    /// Whether the tool only reads data (no side effects).
    pub read_only: bool,
    /// Whether the tool may cause irreversible changes.
    pub destructive: bool,
    /// Whether invoking the tool twice with the same input yields the same result.
    pub idempotent: bool,
    /// Whether a human must approve each invocation.
    pub requires_approval: bool,
    /// Expected execution time in milliseconds (for timeout planning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_duration_ms: Option<u64>,
}

/// Hint about how long a tool invocation typically takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LatencyHint {
    Instant,
    Fast,
    Moderate,
    Slow,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn sample_tool() -> ToolDefinition {
        ToolDefinition {
            name: "file_read".to_string(),
            description: "Read contents of a file".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string" }
                },
                "required": ["path"]
            }),
            output_schema: Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "content": { "type": "string" }
                }
            })),
            pricing: Some(ToolPricing {
                pricing_model: PricingModel::PerInvocation,
                base_price: None,
                unit_price: Some(MonetaryAmount {
                    units: 25,
                    currency: "USD".to_string(),
                }),
                billing_unit: Some("invocation".to_string()),
            }),
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
                estimated_duration_ms: Some(50),
            },
            latency_hint: Some(LatencyHint::Fast),
            flow: None,
        }
    }

    #[test]
    fn manifest_sign_and_verify() {
        let kp = Keypair::generate();
        let body = ToolManifestBody {
            server_id: "srv-files".to_string(),
            server_key: kp.public_key(),
            tools: vec![sample_tool()],
            required_capabilities: vec!["fs_read".to_string()],
        };
        let manifest = ToolManifest::sign(body, &kp).unwrap();
        assert!(manifest.verify_signature().unwrap());
    }

    #[test]
    fn manifest_wrong_key_fails() {
        let kp = Keypair::generate();
        let other_kp = Keypair::generate();
        let body = ToolManifestBody {
            server_id: "srv-files".to_string(),
            server_key: kp.public_key(),
            tools: vec![sample_tool()],
            required_capabilities: vec![],
        };
        let mut manifest = ToolManifest::sign(body, &kp).unwrap();
        manifest.server_key = other_kp.public_key();
        assert!(!manifest.verify_signature().unwrap());
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let kp = Keypair::generate();
        let body = ToolManifestBody {
            server_id: "srv-test".to_string(),
            server_key: kp.public_key(),
            tools: vec![sample_tool()],
            required_capabilities: vec!["network".to_string()],
        };
        let manifest = ToolManifest::sign(body, &kp).unwrap();

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let restored: ToolManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest.server_id, restored.server_id);
        assert_eq!(manifest.server_key, restored.server_key);
        assert_eq!(manifest.tools.len(), restored.tools.len());
        assert_eq!(manifest.tools[0].name, restored.tools[0].name);
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn tool_definition_serde_roundtrip() {
        let tool = sample_tool();
        let json = serde_json::to_string_pretty(&tool).unwrap();
        let restored: ToolDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(tool.name, restored.name);
        assert_eq!(tool.description, restored.description);
        assert_eq!(
            tool.pricing.as_ref().map(|pricing| pricing.pricing_model),
            restored
                .pricing
                .as_ref()
                .map(|pricing| pricing.pricing_model)
        );
        assert_eq!(tool.annotations.read_only, restored.annotations.read_only);
        assert_eq!(
            tool.annotations.estimated_duration_ms,
            restored.annotations.estimated_duration_ms
        );
        assert_eq!(tool.latency_hint, restored.latency_hint);
    }

    #[test]
    fn tool_annotations_default() {
        let ann = ToolAnnotations::default();
        assert!(!ann.read_only);
        assert!(!ann.destructive);
        assert!(!ann.idempotent);
        assert!(!ann.requires_approval);
        assert!(ann.estimated_duration_ms.is_none());
    }
}
