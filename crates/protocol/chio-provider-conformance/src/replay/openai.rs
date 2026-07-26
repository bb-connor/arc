use super::*;

/// Replay an OpenAI fixture through the OpenAI provider adapter.
#[cfg(feature = "fixtures-openai")]
pub fn replay_openai_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let fixture = load_fixture(path)?;
    fixture.ensure_openai()?;
    let captured = fixture.captured_verdicts()?;
    let org_id = fixture.openai_org_id()?;
    let adapter = openai_adapter(&fixture, org_id, &captured)?;

    let (mode, invocations, verdicts) = if fixture.has_stream_tool_events() {
        let (invocations, verdicts) = replay_openai_stream(&fixture, &adapter, &captured)?;
        (ReplayMode::Stream, invocations, verdicts)
    } else {
        let invocations = replay_openai_batch(&fixture, &adapter)?;
        if captured.is_empty() && invocations.is_empty() {
            (ReplayMode::NoToolCall, Vec::new(), Vec::new())
        } else {
            let verdicts = captured.iter().map(|entry| entry.verdict.clone()).collect();
            (ReplayMode::Batch, invocations, verdicts)
        }
    };

    assert_replayed_invocations(&fixture, &captured, &invocations)?;
    assert_replayed_verdicts(&fixture, &captured, &verdicts)?;
    let lowered_responses = assert_openai_lowered_responses(&fixture, &adapter, &captured)?;

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

#[cfg(feature = "fixtures-openai")]
fn openai_adapter(
    fixture: &ProviderCaptureFixture,
    org_id: String,
    captured: &[CapturedVerdict],
) -> Result<chio_openai::OpenAiAdapter, ReplayError> {
    use chio_manifest::{
        RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
        VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
    };
    use chio_openai::adapter::OpenAiAdapterConfig;

    let signer = chio_core::Keypair::from_seed(&[36u8; 32]);
    let server_id = "openai-conformance";
    let mut tool_names = captured
        .iter()
        .map(|entry| entry.invocation.tool_name.clone())
        .collect::<BTreeSet<_>>();
    for record in &fixture.records {
        collect_openai_tool_names(&record.payload, &mut tool_names);
    }
    if tool_names.is_empty() {
        tool_names.insert("conformance_no_tool_call".to_string());
    }
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: server_id.to_string(),
        name: "OpenAI conformance".to_string(),
        description: Some("OpenAI conformance replay manifest".to_string()),
        version: "1".to_string(),
        tools: tool_names
            .into_iter()
            .map(|name| ToolDefinition {
                name,
                description: "OpenAI conformance replay tool".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations::default(),
                latency_hint: None,
                flow: Some(ToolFlowDeclaration::public_egress()),
            })
            .collect(),
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer).map_err(|error| {
        invalid_fixture(
            &fixture.path,
            format!("OpenAI conformance manifest signing failed: {error}"),
        )
    })?;
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .map_err(|error| {
            invalid_fixture(
                &fixture.path,
                format!("OpenAI conformance manifest admission failed: {error}"),
            )
        })?;
    chio_openai::OpenAiAdapter::new_with_registry(
        OpenAiAdapterConfig::new(org_id),
        server_id,
        &registry,
    )
    .map_err(|error| {
        invalid_fixture(
            &fixture.path,
            format!("OpenAI conformance manifest failed validation: {error}"),
        )
    })
}

#[cfg(feature = "fixtures-openai")]
fn collect_openai_tool_names(value: &Value, names: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("function_call") {
                if let Some(name) = object.get("name").and_then(Value::as_str) {
                    if !name.trim().is_empty() {
                        names.insert(name.to_string());
                    }
                }
            }
            for nested in object.values() {
                collect_openai_tool_names(nested, names);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_openai_tool_names(item, names);
            }
        }
        _ => {}
    }
}

/// Feature-disabled entrypoint that explains which feature is needed for OpenAI replay.
#[cfg(not(feature = "fixtures-openai"))]
pub fn replay_openai_fixture(path: impl AsRef<Path>) -> Result<ReplayOutcome, ReplayError> {
    let path = path.as_ref();
    Err(invalid_fixture(
        path,
        "OpenAI replay requires the fixtures-openai feature",
    ))
}

#[cfg(feature = "fixtures-openai")]
fn replay_openai_batch(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_openai::OpenAiAdapter,
) -> Result<Vec<ToolInvocation>, ReplayError> {
    let mut invocations = Vec::new();
    for record in fixture.upstream_responses() {
        if response_has_no_tool_calls(&record.payload) {
            continue;
        }

        let bytes = serde_json::to_vec(&record.payload)?;
        invocations.extend(adapter.lift_batch(ProviderRequest(bytes))?);
    }
    Ok(invocations)
}

#[cfg(feature = "fixtures-openai")]
fn replay_openai_stream(
    fixture: &ProviderCaptureFixture,
    adapter: &chio_openai::OpenAiAdapter,
    captured: &[CapturedVerdict],
) -> Result<(Vec<ToolInvocation>, Vec<VerdictResult>), ReplayError> {
    fixture.ensure_openai_stream_verdict_chronology()?;
    let mut verdicts_by_id = captured
        .iter()
        .map(|entry| (entry.invocation_id.clone(), entry.verdict.clone()))
        .collect::<BTreeMap<_, _>>();
    let sse = fixture_sse_bytes(fixture)?;
    let gated = adapter.gate_sse_stream(&sse, |invocation| {
        let request_id = invocation.provenance.request_id.as_str();
        verdicts_by_id.remove(request_id).ok_or_else(|| {
            ProviderError::Malformed(format!(
                "OpenAI stream replay produced unexpected invocation {request_id}"
            ))
        })
    })?;

    if let Some((request_id, _)) = verdicts_by_id.into_iter().next() {
        return Err(invalid_fixture(
            &fixture.path,
            format!("OpenAI stream replay did not produce invocation {request_id}"),
        ));
    }

    Ok((gated.invocations, gated.verdicts))
}
