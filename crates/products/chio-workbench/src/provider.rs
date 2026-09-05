//! Model transport; providers propose calls and never execute workspace tools.
use crate::{Error, Result};
use chio_egress_contract::{client_builder_with_contract, send_with_contract, HttpEgressContract};
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct Turn {
    pub content: Vec<Value>,
    pub stop_reason: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn model(&self) -> &str;
    async fn turn(&self, system: &str, messages: &[Value], tools: &[Value]) -> Result<Turn>;
}

pub struct Claude {
    client: reqwest::Client,
    key: reqwest::header::HeaderValue,
    model: String,
    egress: HttpEgressContract,
}

impl Claude {
    pub fn new(key: String, model: String) -> Result<Self> {
        if key.trim().is_empty() || model.trim().is_empty() {
            return Err(Error::Invalid(
                "ANTHROPIC_API_KEY and a model are required".into(),
            ));
        }
        let mut key = reqwest::header::HeaderValue::from_str(&key)
            .map_err(|_| Error::Invalid("invalid API key".into()))?;
        key.set_sensitive(true);
        let egress = HttpEgressContract {
            tenant_egress_namespace: "chio-workbench-model".into(),
            allowed_schemes: ["https".into()].into(),
            allowed_authority_set: ["api.anthropic.com:443".into()].into(),
            deny_loopback: true,
            deny_link_local: true,
            deny_ipv6_ula: true,
            max_redirect_chain: 0,
            max_response_bytes: 256 * 1024,
        };
        egress
            .validate()
            .map_err(|_| Error::Invalid("invalid model egress contract".into()))?;
        let client = client_builder_with_contract(&egress)
            .timeout(std::time::Duration::from_secs(90))
            .build()
            .map_err(|_| Error::Invalid("could not initialize model client".into()))?;
        Ok(Self {
            client,
            key,
            model,
            egress,
        })
    }
}

#[async_trait::async_trait]
impl Provider for Claude {
    fn model(&self) -> &str {
        &self.model
    }
    async fn turn(&self, system: &str, messages: &[Value], tools: &[Value]) -> Result<Turn> {
        let request = self.client.post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", self.key.clone()).header("anthropic-version", "2023-06-01")
            .json(&json!({"model":self.model,"max_tokens":2048,"system":system,"messages":messages,"tools":tools}))
            .build().map_err(|_| Error::Invalid("could not build model request".into()))?;
        let response = send_with_contract(&self.egress, &self.client, request)
            .await
            .map_err(|_| {
                Error::Invalid(
                    "model request failed; check connectivity and provider configuration".into(),
                )
            })?;
        if !response.status().is_success() {
            return Err(Error::Invalid(format!(
                "model request returned HTTP {}",
                response.status().as_u16()
            )));
        }
        parse_turn(&serde_json::from_slice(response.body())?)
    }
}

fn parse_turn(value: &Value) -> Result<Turn> {
    let content = value
        .get("content")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty() && items.len() <= 32)
        .ok_or_else(|| Error::Invalid("model returned invalid content".into()))?
        .clone();
    let stop_reason = value
        .get("stop_reason")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Invalid("model returned no stop reason".into()))?;
    let usage = &value["usage"];
    Ok(Turn {
        content,
        stop_reason: stop_reason.into(),
        input_tokens: usage["input_tokens"]
            .as_u64()
            .ok_or_else(|| Error::Invalid("model returned no input usage".into()))?,
        output_tokens: usage["output_tokens"]
            .as_u64()
            .ok_or_else(|| Error::Invalid("model returned no output usage".into()))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_accepts_only_the_configured_https_authority() -> Result<()> {
        let provider = Claude::new("test-key".into(), "test-model".into())?;
        assert!(provider
            .egress
            .enforce_url("https://api.anthropic.com/v1/messages", 0)
            .is_ok());
        for url in [
            "http://api.anthropic.com/v1/messages",
            "https://api.anthropic.com.evil.example/v1/messages",
            "https://api.anthropic.com:444/v1/messages",
            "https://127.0.0.1/v1/messages",
        ] {
            assert!(provider.egress.enforce_url(url, 0).is_err());
        }
        assert!(provider
            .egress
            .enforce_url("https://api.anthropic.com/v1/messages", 1)
            .is_err());
        assert!(provider
            .egress
            .enforce_response_bytes(256 * 1024 + 1)
            .is_err());
        Ok(())
    }

    #[test]
    fn provider_requires_complete_content_and_usage() -> Result<()> {
        let response = json!({
            "content":[{"type":"tool_use","id":"tool-1","name":"read_file","input":{"path":"calc.py"}}],
            "stop_reason":"tool_use",
            "usage":{"input_tokens":100,"output_tokens":20},
        });
        let turn = parse_turn(&response)?;
        assert_eq!(turn.content[0]["input"]["path"], "calc.py");
        assert_eq!(turn.input_tokens, 100);
        assert_eq!(turn.output_tokens, 20);
        for (key, value) in [
            ("content", json!([])),
            ("usage", json!({"input_tokens":100})),
            ("stop_reason", json!(null)),
        ] {
            let mut invalid = response.clone();
            invalid[key] = value;
            assert!(parse_turn(&invalid).is_err());
        }
        Ok(())
    }
}
