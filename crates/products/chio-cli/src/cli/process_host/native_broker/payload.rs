//! Fixed provider request mapping selected by the host, never by a worker.
use chio_process::ProcessError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PayloadConfig {
    Json,
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
}

#[cfg(test)]
mod tests {
    use super::*;
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
