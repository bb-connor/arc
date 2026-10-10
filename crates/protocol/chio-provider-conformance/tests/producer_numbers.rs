//! Producer numbers must survive real provider lift, validation and result lowering.
#![cfg(all(
    feature = "fixtures-openai",
    feature = "fixtures-anthropic",
    feature = "fixtures-bedrock",
    feature = "fixtures-gemini",
    feature = "fixtures-groq",
    feature = "fixtures-mistral",
    feature = "fixtures-ollama",
    feature = "fixtures-cohere"
))]
use chio_tool_call_fabric::{
    ProviderRequest, ReceiptId, ToolInvocation, ToolResult, VerdictResult,
};
use serde_json::Value;
use std::sync::Arc;
type TestResult = Result<(), Box<dyn std::error::Error>>;

const NUMBERS: [(&str, &str); 5] = [
    ("21.0", "21"),
    ("0.0", "0"),
    ("0.50", "0.5"),
    ("1e-05", "0.00001"),
    ("9007199254740993", "9007199254740993"),
];
fn allow() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("numeric-result".into()),
    }
}
fn check_lift(
    lift: impl Fn(ProviderRequest) -> Result<Vec<ToolInvocation>, chio_tool_call_fabric::ProviderError>,
    template: &str,
    string_arguments: bool,
) -> TestResult {
    for (number, canonical) in NUMBERS {
        let document = format!(r#"{{"n":{number}}}"#);
        let arguments = if string_arguments {
            serde_json::to_string(&document)?
        } else {
            document
        };
        let invocations = lift(ProviderRequest(
            template.replace("ARGS", &arguments).into_bytes(),
        ))?;
        assert_eq!(invocations.len(), 1);
        invocations[0].validate()?;
        assert_eq!(
            invocations[0].arguments,
            format!(r#"{{"n":{canonical}}}"#).as_bytes()
        );
    }
    // Duplicates must reject before either outer or nested argument projection.
    let duplicate = r#"{"n":1,"n":2}"#;
    let arguments = if string_arguments {
        serde_json::to_string(duplicate)?
    } else {
        duplicate.into()
    };
    assert!(lift(ProviderRequest(
        template.replace("ARGS", &arguments).into_bytes()
    ))
    .is_err());
    Ok(())
}
fn contains_result(value: &Value, expected: &Value) -> bool {
    if let (Some(actual), Some(number)) = (value.get("n"), expected.get("n")) {
        if value.as_object().is_some_and(|map| map.len() == 1) {
            return if number.is_f64() {
                actual.as_f64() == number.as_f64()
            } else {
                actual.as_u64() == number.as_u64()
            };
        }
    }
    match value {
        Value::Object(map) => map.values().any(|v| contains_result(v, expected)),
        Value::Array(items) => items.iter().any(|v| contains_result(v, expected)),
        Value::String(text) => {
            serde_json::from_str::<Value>(text).is_ok_and(|v| contains_result(&v, expected))
        }
        _ => false,
    }
}
fn check_lower(
    lower: impl Fn(ToolResult) -> Result<Value, Box<dyn std::error::Error>>,
) -> TestResult {
    // serde_json is an actual producer of the previously rejected 21.0 spelling.
    for number in [
        serde_json::json!(21.0),
        serde_json::json!(0.0),
        serde_json::json!(9007199254740993_u64),
    ] {
        let expected = serde_json::json!({"n": number});
        let response = lower(ToolResult(serde_json::to_vec(&expected)?))?;
        assert!(
            contains_result(&response, &expected),
            "lowered result lost its number: {response}"
        );
    }
    assert!(lower(ToolResult(br#"{"n":1,"n":2}"#.to_vec())).is_err());
    Ok(())
}

#[test]
fn anthropic_producer_numbers() -> TestResult {
    use chio_anthropic_tools_adapter::{
        transport::MockTransport, AnthropicAdapter, AnthropicAdapterConfig,
    };
    let key = chio_core::Keypair::from_seed(&[17; 32])
        .public_key()
        .to_hex();
    let registry = registry()?;
    let adapter = AnthropicAdapter::new_with_registry(
        AnthropicAdapterConfig::new("provider", "Provider", "1", key, "producer"),
        Arc::new(MockTransport::new()),
        &registry,
    )?;
    check_lift(
        |request| adapter.lift_batch(request),
        r#"{"content":[{"type":"tool_use","id":"call","name":"f","input":ARGS}]}"#,
        false,
    )?;
    check_lower(|result| {
        Ok(serde_json::to_value(adapter.lower_tool_result_block(
            "f",
            allow(),
            result,
        )?)?)
    })
}

#[test]
fn bedrock_producer_numbers() -> TestResult {
    use chio_bedrock_converse_adapter::{
        transport::MockTransport, BedrockAdapter, BedrockAdapterConfig,
    };
    let key = chio_core::Keypair::from_seed(&[17; 32])
        .public_key()
        .to_hex();
    let adapter = BedrockAdapter::new(
        BedrockAdapterConfig::new(
            "provider",
            "Provider",
            "1",
            key,
            "arn:aws:iam::123456789012:role/test",
            "123456789012",
        ),
        Arc::new(MockTransport::new()),
    )?;
    check_lift(
        |request| adapter.lift_batch(request),
        r#"{"output":{"message":{"role":"assistant","content":[{"toolUse":{"toolUseId":"call","name":"f","input":ARGS}}]}}}"#,
        false,
    )?;
    check_lower(|result| {
        Ok(serde_json::from_slice(
            &adapter.lower_tool_result("f", allow(), result)?.0,
        )?)
    })
}

#[test]
fn gemini_producer_numbers() -> TestResult {
    use chio_gemini_tools_adapter::{transport::MockTransport, GeminiAdapter, GeminiAdapterConfig};
    let key = chio_core::Keypair::from_seed(&[17; 32])
        .public_key()
        .to_hex();
    let adapter = GeminiAdapter::new(
        GeminiAdapterConfig::new("provider", "Provider", "1", key, "producer"),
        Arc::new(MockTransport::new()),
    );
    check_lift(
        |request| adapter.lift_batch(request),
        r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"f","args":ARGS}}]}}]}"#,
        false,
    )?;
    check_lower(|result| {
        Ok(serde_json::to_value(adapter.lower_function_response(
            "f",
            allow(),
            result,
        )?)?)
    })
}

#[test]
fn groq_producer_numbers() -> TestResult {
    use chio_groq_tools_adapter::{transport::MockTransport, GroqAdapter, GroqAdapterConfig};
    let key = chio_core::Keypair::from_seed(&[17; 32])
        .public_key()
        .to_hex();
    let adapter = GroqAdapter::new(
        GroqAdapterConfig::new("provider", "Provider", "1", key, "producer"),
        Arc::new(MockTransport::new()),
    );
    check_lift(
        |request| adapter.lift_batch(request),
        r#"{"id":"response","choices":[{"message":{"tool_calls":[{"id":"call","type":"function","function":{"name":"f","arguments":ARGS}}]}}]}"#,
        true,
    )?;
    check_lower(|result| {
        Ok(serde_json::to_value(adapter.lower_function_response(
            "f",
            allow(),
            result,
        )?)?)
    })
}

#[test]
fn mistral_producer_numbers() -> TestResult {
    use chio_mistral_tools_adapter::{
        transport::MockTransport, MistralAdapter, MistralAdapterConfig,
    };
    let key = chio_core::Keypair::from_seed(&[17; 32])
        .public_key()
        .to_hex();
    let adapter = MistralAdapter::new(
        MistralAdapterConfig::new("provider", "Provider", "1", key, "producer"),
        Arc::new(MockTransport::new()),
    );
    check_lift(
        |request| adapter.lift_batch(request),
        r#"{"id":"response","choices":[{"message":{"tool_calls":[{"id":"call","type":"function","function":{"name":"f","arguments":ARGS}}]}}]}"#,
        true,
    )?;
    check_lower(|result| {
        Ok(serde_json::to_value(adapter.lower_function_response(
            "f",
            allow(),
            result,
        )?)?)
    })
}

#[test]
fn ollama_producer_numbers() -> TestResult {
    use chio_ollama_tools_adapter::{transport::MockTransport, OllamaAdapter, OllamaAdapterConfig};
    let key = chio_core::Keypair::from_seed(&[17; 32])
        .public_key()
        .to_hex();
    let adapter = OllamaAdapter::new(
        OllamaAdapterConfig::new("provider", "Provider", "1", key, "producer"),
        Arc::new(MockTransport::new("mock://ollama")),
    );
    check_lift(
        |request| adapter.lift_batch(request),
        r#"{"model":"llama","done":true,"message":{"tool_calls":[{"function":{"name":"f","arguments":ARGS}}]}}"#,
        false,
    )?;
    check_lower(|result| {
        Ok(serde_json::to_value(adapter.lower_tool_message(
            "f",
            allow(),
            result,
        )?)?)
    })
}

#[test]
fn cohere_producer_numbers() -> TestResult {
    use chio_cohere_tools_adapter::{transport::MockTransport, CohereAdapter, CohereAdapterConfig};
    let key = chio_core::Keypair::from_seed(&[17; 32])
        .public_key()
        .to_hex();
    let adapter = CohereAdapter::new(
        CohereAdapterConfig::new("provider", "Provider", "1", key, "producer"),
        Arc::new(MockTransport::new()),
    );
    check_lift(
        |request| adapter.lift_batch(request),
        r#"{"id":"response","message":{"tool_calls":[{"id":"call","type":"function","function":{"name":"f","arguments":ARGS}}]}}"#,
        true,
    )?;
    check_lower(|result| {
        Ok(serde_json::to_value(adapter.lower_tool_message(
            "f",
            allow(),
            result,
        )?)?)
    })
}

#[test]
fn openai_producer_numbers() -> TestResult {
    use chio_openai::adapter::{OpenAiAdapter, OpenAiAdapterConfig};
    use chio_tool_call_fabric::ProviderAdapter;
    let adapter = OpenAiAdapter::new(OpenAiAdapterConfig::new("producer"));
    check_lift(
        |request| adapter.lift_batch(request),
        r#"{"id":"response","output":[{"type":"function_call","call_id":"call","name":"f","arguments":ARGS}]}"#,
        true,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    check_lower(|result| {
        let payload = format!(
            r#"{{"call_id":"call","output":{}}}"#,
            std::str::from_utf8(&result.0)?
        );
        let result = ToolResult(payload.into_bytes());
        Ok(serde_json::from_slice(
            &runtime.block_on(adapter.lower(allow(), result))?.0,
        )?)
    })
}

fn registry() -> Result<chio_manifest::VerifiedManifestRegistry, Box<dyn std::error::Error>> {
    let signer = chio_core::Keypair::from_seed(&[17; 32]);
    let manifest: chio_manifest::ToolManifest = serde_json::from_value(serde_json::json!({
        "schema": chio_manifest::TOOL_MANIFEST_SCHEMA, "server_id":"provider",
        "name":"Provider", "version":"1", "public_key":signer.public_key().to_hex(),
        "tools":[{"name":"f", "description":"numeric producer", "input_schema":{"type":"object"},
            "annotations":{"read_only":true,"destructive":false,"idempotent":true,"requires_approval":false},
            "flow":chio_manifest::ToolFlowDeclaration::public_egress()}]
    }))?;
    let mut registry = chio_manifest::VerifiedManifestRegistry::default();
    registry.register_public_only(
        chio_manifest::sign_manifest(&manifest, &signer)?,
        &signer.public_key(),
        chio_manifest::RuntimeToolTopology::remote(),
    )?;
    Ok(registry)
}

#[test]
fn producer_numbers_survive_fragmented_stream_gate_and_original_forwarding() -> TestResult {
    use chio_groq_tools_adapter::{transport::MockTransport, GroqAdapter, GroqAdapterConfig};
    let key = chio_core::Keypair::from_seed(&[17; 32])
        .public_key()
        .to_hex();
    let adapter = GroqAdapter::new_with_registry(
        GroqAdapterConfig::new("provider", "Provider", "1", key, "producer"),
        Arc::new(MockTransport::new()),
        &registry()?,
    )?;
    for (number, canonical) in NUMBERS {
        let first = serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{
            "index":0,"id":"call","type":"function","function":{"name":"f","arguments":"{\"n\":"}
        }]}}]});
        let last = serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{
            "index":0,"function":{"arguments":format!("{number}}}")}
        }]},"finish_reason":"tool_calls"}]});
        let wire = format!("data: {first}\n\ndata: {last}\n\ndata: [DONE]\n\n");
        let mut evaluated = 0;
        let gated = adapter.gate_sse_stream(wire.as_bytes(), |invocation| {
            evaluated += 1;
            assert_eq!(
                invocation.arguments,
                format!(r#"{{"n":{canonical}}}"#).as_bytes()
            );
            Ok(allow())
        })?;
        assert_eq!(evaluated, 1);
        assert_eq!(gated.invocations.len(), 1);
        assert_eq!(gated.bytes, wire.as_bytes());
    }
    Ok(())
}
