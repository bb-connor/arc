//! Fixed provider request mapping selected by the host, never by a worker.
use chio_core_types::capability::token::CapabilityToken;
use chio_process::ProcessError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PayloadConfig {
    Json,
    KernelMcpToolCall,
    MiniSweChat {
        model_id: String,
        model: String,
        tools: Vec<Value>,
        max_completion_tokens: u32,
        temperature: Option<f64>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelQuery {
    schema: String,
    model_id: String,
    turn: u64,
    messages: Vec<serde_json::Map<String, Value>>,
}

impl PayloadConfig {
    pub fn validate(&self) -> Result<(), ProcessError> {
        if let Self::MiniSweChat {
            model_id,
            model,
            tools,
            max_completion_tokens,
            temperature,
        } = self
        {
            if model_id.is_empty()
                || model_id.len() > 1024
                || model.is_empty()
                || model.len() > 256
                || tools.is_empty()
                || tools.len() > 16
                || tools.iter().any(|tool| !tool.is_object())
                || chio_core_types::canonical_json_bytes(tools)?.len() > 32_768
                || !(1..=32768).contains(max_completion_tokens)
                || temperature
                    .is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value))
            {
                return Err(ProcessError::Invalid(
                    "invalid fixed model preparation policy",
                ));
            }
        }
        Ok(())
    }

    pub fn body(&self, input: &Value) -> Result<Vec<u8>, ProcessError> {
        let value = match self {
            Self::Json => input.clone(),
            Self::KernelMcpToolCall => {
                return Err(ProcessError::Invalid(
                    "MCP payload requires the original caller capability",
                ));
            }
            Self::MiniSweChat {
                model_id,
                model,
                tools,
                max_completion_tokens,
                temperature,
            } => {
                let mut query: ModelQuery = serde_json::from_value(input.clone())?;
                if query.schema != "chio.mini-swe.model-query.v1"
                    || &query.model_id != model_id
                    || query.turn == 0
                    || query.messages.is_empty()
                    || query.messages.len() > 256
                {
                    return Err(ProcessError::Invalid(
                        "query differs from the pinned model route",
                    ));
                }
                for message in &mut query.messages {
                    message.remove("extra");
                }
                let mut value = json!({"model":model,"messages":query.messages,"tools":tools,"max_completion_tokens":max_completion_tokens,"stream":false});
                if let Some(temperature) = temperature {
                    value["temperature"] = json!(temperature);
                }
                value
            }
        };
        Ok(chio_core_types::canonical_json_bytes(&value)?)
    }

    /// Bind resource-side caller metadata inside durable host preparation.
    /// Worker input stays within `arguments`; it cannot choose the installed
    /// tool identity or replace the capability held by the process registry.
    pub fn body_for_caller(
        &self,
        input: &Value,
        tool_name: &str,
        parent: &CapabilityToken,
    ) -> Result<Vec<u8>, ProcessError> {
        if matches!(self, Self::KernelMcpToolCall) {
            let caller =
                chio_core_types::sha256_hex(&chio_core_types::canonical_json_bytes(parent)?);
            Ok(chio_core_types::canonical_json_bytes(&json!({
                "name": tool_name,
                "arguments": input,
                "_meta": {"chioCallerCapabilitySha256": caller},
            }))?)
        } else {
            self.body(input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_mapping_binds_the_installed_tool_and_original_caller(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use chio_core_types::capability::token::{CapabilityToken, CapabilityTokenBody};
        use chio_core_types::{canonical_json_bytes, sha256_hex, Keypair};

        let signer = Keypair::from_seed(&[41; 32]);
        let parent = CapabilityToken::sign(
            CapabilityTokenBody {
                id: "original-worker".into(),
                issuer: signer.public_key(),
                subject: signer.public_key(),
                scope: Default::default(),
                issued_at: 1,
                expires_at: 100,
                delegation_chain: vec![],
                aggregate_invocation_budget: None,
            },
            &signer,
        )?;
        let config: PayloadConfig = serde_json::from_value(json!({"kind":"kernel_mcp_tool_call"}))?;
        config.validate()?;
        let input = json!({"job_id":"job", "name":"assign", "_meta":{"chioCallerCapabilitySha256":"forged"}});
        let body: Value =
            serde_json::from_slice(&config.body_for_caller(&input, "complete", &parent)?)?;
        assert_eq!(body["name"], "complete");
        assert_eq!(body["arguments"], input);
        assert_eq!(
            body["_meta"]["chioCallerCapabilitySha256"],
            sha256_hex(&canonical_json_bytes(&parent)?)
        );
        assert!(config.body(&input).is_err());
        let plain: Value = serde_json::from_slice(
            &PayloadConfig::Json.body_for_caller(&input, "complete", &parent)?,
        )?;
        assert_eq!(plain, input);
        let mut changed = parent.clone();
        changed.id = "different-worker".into();
        assert_ne!(
            config.body_for_caller(&input, "complete", &changed)?,
            config.body_for_caller(&input, "complete", &parent)?
        );
        Ok(())
    }

    #[test]
    fn model_requests_cannot_select_provider_options_or_carry_worker_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config = PayloadConfig::MiniSweChat {
            model_id: "fixed".into(),
            model: "selected".into(),
            tools: vec![json!({"type":"function"})],
            max_completion_tokens: 32,
            temperature: None,
        };
        config.validate()?;
        let input = json!({"schema":"chio.mini-swe.model-query.v1","model_id":"fixed","turn":1,"messages":[{"role":"user","content":"hello","extra":{"private":"metadata"}}]});
        let request: Value = serde_json::from_slice(&config.body(&input)?)?;
        assert_eq!(request["model"], "selected");
        assert_eq!(request["max_completion_tokens"], 32);
        assert_eq!(request["stream"], false);
        assert!(request["messages"][0].get("extra").is_none());
        for (field, value) in [
            ("model_id", json!("other")),
            ("turn", json!(0)),
            ("model", json!("override")),
            ("stream", json!(true)),
        ] {
            let mut changed = input.clone();
            changed[field] = value;
            assert!(config.body(&changed).is_err());
        }
        Ok(())
    }
}
