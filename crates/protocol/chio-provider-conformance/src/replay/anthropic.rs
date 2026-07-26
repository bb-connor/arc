use super::*;

/// Replay an Anthropic fixture through the Anthropic provider adapter.
#[cfg(feature = "fixtures-anthropic")]
pub fn replay_anthropic_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_anthropic()?;
    let captured = fixture.captured_verdicts()?;
    let workspace_id = fixture.anthropic_workspace_id()?;
    let adapter = anthropic_adapter(&fixture, workspace_id, &captured)?;

    let (mode, invocations, verdicts) = if fixture.has_anthropic_stream_tool_events() {
        let (invocations, verdicts) = replay_anthropic_stream(&fixture, &adapter, &captured)?;
        (ReplayMode::Stream, invocations, verdicts)
    } else {
        let invocations = replay_anthropic_batch(&fixture, &adapter)?;
        if captured.is_empty() && invocations.is_empty() {
            (ReplayMode::NoToolCall, Vec::new(), Vec::new())
        } else {
            let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
            (ReplayMode::Batch, invocations, verdicts)
        }
    };

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_anthropic_lowered_responses(&fixture, &adapter, &captured)?;

    Ok(ReplayOutcome {
        fixture_id: fixture.fixture_id,
        path: fixture.path,
        mode,
        records: fixture.records.len(),
        invocations: invocations.len(),
        verdicts: verdicts.len(),
        lowered_responses,
    })
}

/// Feature-disabled entrypoint that explains which feature is needed for Anthropic replay.
#[cfg(not(feature = "fixtures-anthropic"))]
pub fn replay_anthropic_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "Anthropic replay requires the fixtures-anthropic feature",
    ))
}

#[cfg(feature = "fixtures-anthropic")]
fn replay_anthropic_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_anthropic_tools_adapter::AnthropicAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if anthropic_response_has_no_tool_uses(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-anthropic")]
fn replay_anthropic_stream(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_anthropic_tools_adapter::AnthropicAdapter,
    captured: &[CapturedVerdict],
) -> Result<(Vec<ToolInvocation>, Vec<VerdictResult>), ReplayError> {
    fixture.ensure_anthropic_stream_verdict_chronology()?;
    let mut verdicts_by_id = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.verdict.clone()))
        .collect::<BTreeMap<_, _>>();
    let sse = fixture_sse_bytes(fixture)?;
    let gated = adapter.gate_sse_stream(&sse, |invocation| {
        let request_id = invocation.provenance.request_id.as_str();
        verdicts_by_id.remove(request_id).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "Anthropic stream replay produced unexpected invocation {request_id}"
            ))
        })
    })?;

    if let Some((request_id, _)) = verdicts_by_id.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("Anthropic stream replay did not produce invocation {request_id}"),
        ));
    }

    Ok((gated.invocations, gated.verdicts))
}

#[cfg(feature = "fixtures-anthropic")]
fn anthropic_adapter(
    fixture: &ProviderCaptureFixture,
    workspace_id: String,
    captured: &[CapturedVerdict],
) -> Result<chio_anthropic_tools_adapter::AnthropicAdapter, ReplayError> {
    use std::sync::Arc;

    use chio_anthropic_tools_adapter::transport::MockTransport;
    use chio_anthropic_tools_adapter::{AnthropicAdapter, AnthropicAdapterConfig};

    let signer = chio_core::Keypair::from_seed(&[31u8; 32]);
    let config = AnthropicAdapterConfig::new(
        "anthropic-1",
        "Anthropic Messages",
        "0.1.0",
        signer.public_key().to_hex(),
        workspace_id,
    );
    let signed =
        chio_manifest::sign_manifest(&anthropic_server_tool_manifest(fixture, captured), &signer)
            .map_err(|error| {
            invalid_fixture(
                &fixture.path,
                format!("Anthropic conformance manifest signing failed: {error}"),
            )
        })?;
    let mut registry = chio_manifest::VerifiedManifestRegistry::default();
    registry
        .register_public_only(
            signed,
            &signer.public_key(),
            chio_manifest::RuntimeToolTopology::remote(),
        )
        .map_err(|error| {
            invalid_fixture(
                &fixture.path,
                format!("Anthropic conformance manifest admission failed: {error}"),
            )
        })?;
    AnthropicAdapter::new_with_registry(config, Arc::new(MockTransport::new()), &registry).map_err(
        |error| {
            invalid_fixture(
                &fixture.path,
                format!("Anthropic conformance manifest failed validation: {error}"),
            )
        },
    )
}

#[cfg(feature = "fixtures-anthropic")]
fn anthropic_server_tool_manifest(
    fixture: &ProviderCaptureFixture,
    captured: &[CapturedVerdict],
) -> chio_manifest::ToolManifest {
    use chio_manifest::{
        LatencyHint, ServerTool, ToolDefinition, ToolManifest, TOOL_MANIFEST_SCHEMA,
    };

    let mut tool_names = captured
        .iter()
        .map(|entry| entry.invocation.tool_name.clone())
        .collect::<BTreeSet<_>>();
    for record in &fixture.records {
        collect_anthropic_tool_names(&record.payload, &mut tool_names);
    }
    if tool_names.is_empty() {
        tool_names.insert("conformance_no_tool_call".to_string());
    }
    ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "anthropic-1".into(),
        name: "Anthropic Messages".to_string(),
        description: Some("Anthropic conformance replay manifest".to_string()),
        version: "0.1.0".to_string(),
        tools: tool_names
            .into_iter()
            .map(|name| ToolDefinition {
                name,
                description: "Anthropic conformance replay tool".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: Some(serde_json::json!({"type": "object"})),
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: Some(LatencyHint::Fast),
                flow: None,
            })
            .collect(),
        server_tools: vec![
            ServerTool::ComputerUse,
            ServerTool::Bash,
            ServerTool::TextEditor,
        ],
        required_permissions: None,
        public_key: chio_core::Keypair::from_seed(&[31u8; 32])
            .public_key()
            .to_hex(),
    }
}

#[cfg(feature = "fixtures-anthropic")]
fn collect_anthropic_tool_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("tool_use") {
                if let Some(name) = object.get("name").and_then(Value::as_str) {
                    if !name.trim().is_empty() {
                        names.insert(name.to_string());
                    }
                }
            }
            for nested in object.values() {
                collect_anthropic_tool_names(nested, names);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_anthropic_tool_names(item, names);
            }
        }
        _ => {}
    }
}

#[cfg(feature = "fixtures-anthropic")]
pub(super) fn anthropic_tool_result_payload(
    path: &Path,
    expected_body: &Value,
) -> Result<Vec<u8>, ReplayError> {
    if expected_body.get("tool_use_id").is_none() {
        return Err(invalid_fixture(
            path,
            "Anthropic lowered tool_result was missing tool_use_id",
        ));
    }
    canonical_json_bytes_for("captured Anthropic tool_result envelope", expected_body)
        .map_err(ReplayError::from)
}
