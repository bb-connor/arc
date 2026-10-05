//! Fixed provider request mapping selected by the host, never by a worker.
use chio_process::ProcessError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PayloadConfig {
    Json,
    CallerBoundResource {
        route: chio_secret_broker::host_resource::HostResourceRoute,
    },
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
        if let Self::CallerBoundResource { route } = self {
            route.validate().map_err(|error| ProcessError::Preparation(Box::new(error)))?;
        }
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

    pub fn body_for_caller(&self, input: &Value, caller: &str) -> Result<Vec<u8>, ProcessError> {
        let value = match self {
            Self::Json => input.clone(),
            Self::CallerBoundResource { route } => {
                return route.encode(input, caller)
                    .map_err(|error| ProcessError::Preparation(Box::new(error)));
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_mapping_pins_the_route_and_rejects_worker_authority_fields(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let config: PayloadConfig = serde_json::from_value(json!({
            "kind": "caller_bound_resource",
            "route": {"resource": "postgres-jobs", "tenant": "tenant-one", "operation": "complete"}
        }))?;
        config.validate()?;
        let input = json!({"job_id": "one", "expected_fence": 2, "result": {"p95": 12.5}});
        // Authority is supplied by the host's durable preparation closure.
        let caller = "ab".repeat(32);
        let request: Value = serde_json::from_slice(&config.body_for_caller(&input, &caller)?)?;
        assert_eq!(request["route"]["tenant"], "tenant-one");
        assert_eq!(request["route"]["operation"], "complete");
        assert_eq!(request["caller_capability_sha256"], caller);
        assert_eq!(request["arguments"], input);
        for field in ["_meta", "route", "caller_capability_sha256"] {
            let mut forged = input.clone();
            forged[field] = json!("worker-selected");
            assert!(config.body_for_caller(&forged, &caller).is_err(), "{field}");
        }
        assert!(config.body_for_caller(&input, "not-a-digest").is_err());
        let other: Value = serde_json::from_slice(
            &config.body_for_caller(&input, &"cd".repeat(32))?,
        )?;
        assert_ne!(request["caller_capability_sha256"], other["caller_capability_sha256"]);
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
        let request: Value = serde_json::from_slice(&config.body_for_caller(&input, "")?)?;
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
            assert!(config.body_for_caller(&changed, "").is_err());
        }
        Ok(())
    }
}
