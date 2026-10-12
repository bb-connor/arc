use std::collections::BTreeSet;
use std::sync::Arc;

use chio_bedrock_converse_adapter::transport::MockTransport;
use chio_bedrock_converse_adapter::{BedrockAdapter, BedrockAdapterConfig};
use chio_core::Keypair;
use chio_manifest::{
    RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolManifest, VerifiedManifestRegistry,
    TOOL_MANIFEST_SCHEMA,
};
use chio_tool_call_fabric::{ProviderError, ProviderRequest, ReceiptId, Redaction, VerdictResult};
use serde_json::{json, Value};

const README: &str = include_str!("../README.md");

#[derive(Debug)]
struct TaxonomyRow {
    class: String,
    envelope: Value,
    source: String,
}

fn adapter() -> Result<BedrockAdapter, String> {
    let signer = Keypair::from_seed(&[67; 32]);
    let config = BedrockAdapterConfig::new(
        "bedrock-1",
        "Bedrock Converse",
        "0.1.0",
        signer.public_key().to_hex(),
        "arn:aws:iam::111122223333:role/chio-bedrock-prod",
        "111122223333",
    );
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: config.server_id.clone(),
        name: config.server_name.clone(),
        description: None,
        version: config.server_version.clone(),
        tools: vec![ToolDefinition {
            name: "get_weather".to_string(),
            description: "Taxonomy fixture tool".to_string(),
            input_schema: json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: false,
                requires_approval: false,
            },
            latency_hint: None,
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer)
        .map_err(|error| format!("failed to sign Bedrock manifest: {error}"))?;
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .map_err(|error| format!("failed to admit Bedrock manifest: {error}"))?;
    BedrockAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry)
        .map_err(|error| format!("failed to build Bedrock adapter: {error}"))
}

fn raw(value: Value) -> Result<ProviderRequest, String> {
    serde_json::to_vec(&value)
        .map(ProviderRequest)
        .map_err(|error| format!("failed to encode provider request: {error}"))
}

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: Vec::<Redaction>::new(),
        receipt_id: ReceiptId("rcpt_bedrock_taxonomy_allow".to_string()),
    }
}

fn tool_use_stream() -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!([
        {"messageStart":{"role":"assistant"}},
        {
            "contentBlockStart": {
                "contentBlockIndex": 0,
                "start": {
                    "toolUse": {
                        "toolUseId": "tooluse_taxonomy_1",
                        "name": "get_weather",
                        "input": {}
                    }
                }
            }
        },
        {
            "contentBlockStop": {
                "contentBlockIndex": 0
            }
        },
        {
            "messageStop": {}
        }
    ]))
    .map_err(|error| format!("failed to encode stream fixture: {error}"))
}

fn malformed_delta_stream() -> Result<Vec<u8>, String> {
    serde_json::to_vec(&json!([
        {"messageStart":{"role":"assistant"}},
        {
            "contentBlockDelta": {
                "contentBlockIndex": 0,
                "delta": {
                    "toolUse": {
                        "input": "{}"
                    }
                }
            }
        }
    ]))
    .map_err(|error| format!("failed to encode malformed stream fixture: {error}"))
}

#[test]
fn readme_taxonomy_table_covers_adapter_visible_classes() -> Result<(), String> {
    let rows = taxonomy_rows()?;
    let classes = classes(&rows);
    for required in [
        "RateLimited",
        "BadToolArgs",
        "Upstream5xx",
        "TransportTimeout",
        "VerdictBudgetExceeded",
        "Malformed",
    ] {
        if !classes.contains(required) {
            return Err(format!(
                "README taxonomy did not cover ProviderError::{required}"
            ));
        }
    }

    if classes.contains("ContentPolicy") {
        return Err("Bedrock has no native ContentPolicy classifier".into());
    }

    if classes.contains("Other") {
        return Err("README taxonomy must not map native envelopes to ProviderError::Other".into());
    }

    Ok(())
}

#[test]
fn readme_taxonomy_envelopes_are_bedrock_specific() -> Result<(), String> {
    for row in taxonomy_rows()? {
        match row.class.as_str() {
            "RateLimited" => {
                require_status(&row, 429)?;
                require_body_string(&row, "/headers/x-amzn-errortype", "ThrottlingException")?;
                require_body_string(&row, "/operation", "Converse")?;
                if number_at(&row, "/retry_after_ms")? != 1000 {
                    return Err("Bedrock SDK throttling retry must be 1000 ms".into());
                }
                require_bedrock_source(&row)?;
            }
            "BadToolArgs" => {
                require_body_string(&row, "/toolUse/toolUseId", "tooluse_bad_args")?;
                require_body_string(&row, "/toolUse/name", "get_weather")?;
                if row
                    .envelope
                    .pointer("/toolUse/input")
                    .is_some_and(Value::is_object)
                {
                    return Err("BadToolArgs envelope input must not already be an object".into());
                }
            }
            "Upstream5xx" => {
                require_body_string(&row, "/operation", "Converse")?;
                require_body_string(&row, "/headers/x-amzn-errortype", "InternalServerException")?;
                let status = status(&row)
                    .ok_or_else(|| "Upstream5xx envelope did not include status".to_string())?;
                if !(500..600).contains(&status) {
                    return Err(format!("Upstream5xx envelope used non-5xx status {status}"));
                }
                require_bedrock_source(&row)?;
            }
            "TransportTimeout" => {
                require_body_string(&row, "/transport", "timeout")?;
                require_body_string(&row, "/provider", "bedrock")?;
                require_body_string(&row, "/operation", "Converse")?;
                require_positive_u64(&row, "/elapsed_ms")?;
            }
            "VerdictBudgetExceeded" => {
                require_body_string(&row, "/provider", "bedrock")?;
                require_body_string(&row, "/event", "contentBlockStart")?;
                let observed_ms = number_at(&row, "/observed_ms")?;
                let budget_ms = number_at(&row, "/budget_ms")?;
                if observed_ms <= budget_ms {
                    return Err("VerdictBudgetExceeded envelope must exceed budget_ms".into());
                }
            }
            "Malformed" => {
                require_body_string(&row, "/contentBlockDelta/delta/toolUse/input", "{}")?;
            }
            other => {
                return Err(format!(
                    "unexpected ProviderError class documented: {other}"
                ));
            }
        }
    }

    Ok(())
}

#[test]
fn current_adapter_paths_match_documented_classes() -> Result<(), String> {
    let classes = classes(&taxonomy_rows()?);
    for required in ["BadToolArgs", "Malformed", "VerdictBudgetExceeded"] {
        if !classes.contains(required) {
            return Err(format!(
                "README taxonomy did not cover current class {required}"
            ));
        }
    }

    let adapter = adapter()?;
    let bad_args = adapter.lift_batch(raw(json!({
        "content": [
            {
                "toolUse": {
                    "toolUseId": "tooluse_bad_args",
                    "name": "get_weather",
                    "input": "not an object"
                }
            }
        ]
    }))?);
    require_provider_error(bad_args, "BadToolArgs")?;

    let malformed =
        adapter.gate_converse_stream(
            &malformed_delta_stream()?,
            |_invocation| Ok(allow_verdict()),
        );
    require_provider_error(malformed, "Malformed")?;

    let budget = adapter.gate_converse_stream(&tool_use_stream()?, |_invocation| {
        Err(ProviderError::VerdictBudgetExceeded {
            observed_ms: 300,
            budget_ms: 250,
        })
    });
    require_provider_error(budget, "VerdictBudgetExceeded")?;

    Ok(())
}

fn taxonomy_rows() -> Result<Vec<TaxonomyRow>, String> {
    let mut in_table = false;
    let mut rows = Vec::new();

    for line in README.lines() {
        let trimmed = line.trim();
        if trimmed == "<!-- error-taxonomy:start -->" {
            in_table = true;
            continue;
        }
        if trimmed == "<!-- error-taxonomy:end -->" {
            break;
        }
        if !in_table || !trimmed.starts_with('|') {
            continue;
        }
        if trimmed.contains("ProviderError class") || trimmed.contains("---") {
            continue;
        }

        let cells = table_cells(trimmed)?;
        if cells.len() != 4 {
            return Err(format!(
                "taxonomy row should have 4 cells, found {} in {trimmed}",
                cells.len()
            ));
        }

        rows.push(TaxonomyRow {
            class: extract_provider_error_class(&cells[0])?,
            envelope: extract_inline_json(&cells[1])?,
            source: cells[2].clone(),
        });
    }

    if rows.is_empty() {
        return Err("README taxonomy table was not found".into());
    }

    Ok(rows)
}

fn table_cells(line: &str) -> Result<Vec<String>, String> {
    let without_prefix = line
        .strip_prefix('|')
        .ok_or_else(|| format!("taxonomy row missed leading pipe: {line}"))?;
    let without_suffix = without_prefix
        .strip_suffix('|')
        .ok_or_else(|| format!("taxonomy row missed trailing pipe: {line}"))?;
    Ok(without_suffix
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect())
}

fn extract_provider_error_class(cell: &str) -> Result<String, String> {
    for token in cell.split('`') {
        if let Some(class) = token.strip_prefix("ProviderError::") {
            return Ok(class.to_string());
        }
    }
    Err(format!(
        "cell did not contain a ProviderError class: {cell}"
    ))
}

fn extract_inline_json(cell: &str) -> Result<Value, String> {
    for token in cell.split('`') {
        let candidate = token.trim();
        if candidate.starts_with('{') {
            return serde_json::from_str(candidate)
                .map_err(|error| format!("inline JSON envelope did not parse: {error}"));
        }
    }
    Err(format!("cell did not contain inline JSON: {cell}"))
}

fn classes(rows: &[TaxonomyRow]) -> BTreeSet<String> {
    rows.iter().map(|row| row.class.clone()).collect()
}

fn require_bedrock_source(row: &TaxonomyRow) -> Result<(), String> {
    if row.source.contains("Bedrock") {
        Ok(())
    } else {
        Err(format!(
            "{} envelope source must name Bedrock, got {}",
            row.class, row.source
        ))
    }
}

fn require_status(row: &TaxonomyRow, expected: u64) -> Result<(), String> {
    let actual = status(row).ok_or_else(|| format!("{} envelope missed status", row.class))?;
    if actual != expected {
        return Err(format!(
            "{} envelope used status {actual}, wanted {expected}",
            row.class
        ));
    }
    Ok(())
}

fn status(row: &TaxonomyRow) -> Option<u64> {
    row.envelope.get("status").and_then(Value::as_u64)
}

fn require_body_string(row: &TaxonomyRow, pointer: &str, expected: &str) -> Result<(), String> {
    let actual = row
        .envelope
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{} envelope missed {pointer}", row.class))?;
    if actual != expected {
        return Err(format!(
            "{} envelope used {actual} at {pointer}, wanted {expected}",
            row.class
        ));
    }
    Ok(())
}

fn require_positive_u64(row: &TaxonomyRow, pointer: &str) -> Result<(), String> {
    let value = number_at(row, pointer)?;
    if value == 0 {
        return Err(format!("{} envelope used zero at {pointer}", row.class));
    }
    Ok(())
}

fn number_at(row: &TaxonomyRow, pointer: &str) -> Result<u64, String> {
    row.envelope
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{} envelope missed {pointer}", row.class))
}

fn require_provider_error<T>(
    result: Result<T, ProviderError>,
    expected: &str,
) -> Result<(), String> {
    let error = match result {
        Ok(_) => return Err(format!("expected ProviderError::{expected}, got success")),
        Err(error) => error,
    };

    let actual = match error {
        ProviderError::RateLimited { .. } => "RateLimited",
        ProviderError::ContentPolicy(_) => "ContentPolicy",
        ProviderError::BadToolArgs(_) => "BadToolArgs",
        ProviderError::Upstream5xx { .. } => "Upstream5xx",
        ProviderError::TransportTimeout { .. } => "TransportTimeout",
        ProviderError::VerdictBudgetExceeded { .. } => "VerdictBudgetExceeded",
        ProviderError::Malformed(_) => "Malformed",
        ProviderError::Other(_) => "Other",
        ProviderError::Clock(_) => "Clock",
        ProviderError::StreamCapacityExceeded => "StreamCapacityExceeded",
        ProviderError::UntrustedInput(_) => "UntrustedInput",
        ProviderError::Invocation(_) => "Invocation",
        ProviderError::Transport { .. } => "Transport",
    };

    if actual != expected {
        return Err(format!(
            "expected ProviderError::{expected}, got ProviderError::{actual}"
        ));
    }

    Ok(())
}

#[test]
fn guardrail_only_response_and_captured_stream_exceptions_are_malformed() -> Result<(), String> {
    let adapter = adapter()?;
    require_provider_error(
        adapter.lift_batch(raw(json!({
            "stopReason": "guardrail_intervened",
            "output": {"message": {"role": "assistant", "content": [{"text": "blocked"}]}},
            "trace": {"guardrail": {"action": "INTERVENED"}}
        }))?),
        "Malformed",
    )?;
    for kind in ["throttlingException", "internalServerException"] {
        let event = json!([
            {"messageStart": {"role": "assistant"}},
            {(kind): {"message": "captured failure"}}
        ]);
        let bytes = serde_json::to_vec(&event).map_err(|error| error.to_string())?;
        let evaluated = std::cell::Cell::new(false);
        let result = adapter.gate_converse_stream(&bytes, |_| {
            evaluated.set(true);
            Ok(allow_verdict())
        });
        require_provider_error(result, "Malformed")?;
        assert!(!evaluated.get());
    }
    Ok(())
}

#[tokio::test]
async fn documented_converse_sdk_errors_preserve_exception_mapping(
) -> Result<(), Box<dyn std::error::Error>> {
    use aws_sdk_bedrockruntime::config::retry::RetryConfig;
    use aws_sdk_bedrockruntime::config::{
        BehaviorVersion, Credentials, Region, SharedCredentialsProvider,
    };
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;
    use chio_bedrock_converse_adapter::{AwsSdkTransport, ConverseRequest};

    let mut rows = taxonomy_rows()?;
    rows.push(TaxonomyRow {
        class: "Upstream5xx".into(),
        envelope: json!({"status":503,"headers":{"x-amzn-errortype":"ServiceUnavailableException"},"body":{"message":"unavailable"}}),
        source: "Bedrock SDK Converse".into(),
    });
    for row in rows
        .into_iter()
        .filter(|row| matches!(row.class.as_str(), "RateLimited" | "Upstream5xx"))
    {
        let status = u16::try_from(status(&row).ok_or("missing status")?)?;
        let exception = row
            .envelope
            .pointer("/headers/x-amzn-errortype")
            .and_then(Value::as_str)
            .ok_or("missing SDK exception header")?;
        let request = http::Request::builder()
            .method("POST")
            .uri("https://bedrock-runtime.us-east-1.amazonaws.com/placeholder")
            .body(SdkBody::empty())?;
        let response = http::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("x-amzn-errortype", exception)
            .body(SdkBody::from(serde_json::to_vec(&row.envelope["body"])?))?;
        let replay = StaticReplayClient::new(vec![ReplayEvent::new(request, response)]);
        let sdk = aws_sdk_bedrockruntime::Config::builder()
            .behavior_version(BehaviorVersion::v2026_01_12())
            .retry_config(RetryConfig::disabled())
            .region(Region::new("us-east-1"))
            .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                "AKIDEXAMPLE",
                "secret",
                None,
                None,
                "chio-taxonomy",
            )))
            .http_client(replay)
            .build();
        let transport =
            AwsSdkTransport::from_client(aws_sdk_bedrockruntime::Client::from_conf(sdk));
        let config = BedrockAdapterConfig::new(
            "sdk-taxonomy",
            "Example",
            "1",
            "00",
            "arn:aws:iam::123456789012:user/example",
            "123456789012",
        );
        let adapter = BedrockAdapter::new(config, Arc::new(transport))?;
        let request = ConverseRequest::new(
            "anthropic.claude-3-sonnet-20240229-v1:0",
            vec![json!({"role":"user","content":[{"text":"test"}]})],
        );
        let result = adapter.converse(request).await;
        if let Err(ProviderError::RateLimited { retry_after_ms, .. }) = &result {
            assert_eq!(*retry_after_ms, 1000);
        }
        if let Err(ProviderError::Upstream5xx { status: actual, .. }) = &result {
            assert_eq!(*actual, status);
        }
        require_provider_error(result, &row.class)?;
    }
    Ok(())
}
