#[cfg(feature = "provider-adapter")]
use std::time::{Duration, Instant};

#[cfg(feature = "provider-adapter")]
use chio_openai::adapter::OpenAiAdapter;
#[cfg(feature = "provider-adapter")]
use chio_tool_call_fabric::{ProviderError, ReceiptId, VerdictResult};
#[cfg(feature = "provider-adapter")]
use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "provider-adapter")]
const VERDICT_P99_BUDGET: Duration = Duration::from_millis(250);
#[cfg(feature = "provider-adapter")]
const P99_SAMPLE_COUNT: usize = 128;

#[cfg(feature = "provider-adapter")]
fn tool_call_stream() -> &'static [u8] {
    concat!(
        "event: response.created\n",
        "data: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_latency_1\"}}\n\n",
        "event: response.output_item.added\n",
        "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_latency_calendar\",\"name\":\"create_calendar_event\",\"arguments\":\"\"}}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_latency_calendar\",\"delta\":\"{\\\"title\\\":\"}\n\n",
        "event: response.function_call_arguments.delta\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"call_id\":\"call_latency_calendar\",\"delta\":\"\\\"Chio budget review\\\",\\\"duration_minutes\\\":30}\"}\n\n",
        "event: response.function_call_arguments.done\n",
        "data: {\"type\":\"response.function_call_arguments.done\",\"output_index\":0,\"item_id\":\"fc_latency_calendar\",\"arguments\":\"{\\\"title\\\":\\\"Chio budget review\\\",\\\"duration_minutes\\\":30}\"}\n\n",
        "event: response.output_item.done\n",
        "data: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_latency_calendar\",\"name\":\"create_calendar_event\",\"arguments\":\"{\\\"title\\\":\\\"Chio budget review\\\",\\\"duration_minutes\\\":30}\"}}\n\n",
        "event: response.completed\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_latency_1\"}}\n\n",
    )
    .as_bytes()
}

#[cfg(feature = "provider-adapter")]
fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_latency_allow".to_string()),
    }
}

#[cfg(feature = "provider-adapter")]
fn run_verdict_path(adapter: &OpenAiAdapter) -> Result<(), ProviderError> {
    let gated = adapter.gate_sse_stream(tool_call_stream(), |invocation| {
        black_box(invocation);
        Ok(allow_verdict())
    })?;

    if gated.invocations.len() != 1 {
        return Err(ProviderError::Malformed(format!(
            "expected one OpenAI tool invocation, observed {}",
            gated.invocations.len()
        )));
    }
    if gated.verdicts.len() != 1 {
        return Err(ProviderError::Malformed(format!(
            "expected one OpenAI verdict, observed {}",
            gated.verdicts.len()
        )));
    }

    black_box(gated);
    Ok(())
}

#[cfg(feature = "provider-adapter")]
fn measure_p99(adapter: &OpenAiAdapter) -> Result<Duration, ProviderError> {
    let mut samples = Vec::with_capacity(P99_SAMPLE_COUNT);

    for _ in 0..P99_SAMPLE_COUNT {
        let started = Instant::now();
        run_verdict_path(adapter)?;
        samples.push(started.elapsed());
    }

    samples.sort_unstable();
    let p99_index = ((samples.len() * 99).div_ceil(100)).saturating_sub(1);
    samples.get(p99_index).copied().ok_or_else(|| {
        ProviderError::Malformed("OpenAI verdict latency bench produced no samples".to_string())
    })
}

#[cfg(feature = "provider-adapter")]
fn admitted_adapter() -> Result<OpenAiAdapter, ProviderError> {
    use chio_core::crypto::Keypair;
    use chio_manifest::{
        RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
        VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
    };

    let signer = Keypair::from_seed(&[37u8; 32]);
    let server_id = "openai-latency";
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: server_id.to_string(),
        name: "OpenAI latency benchmark".to_string(),
        description: None,
        version: "1".to_string(),
        tools: vec![ToolDefinition {
            name: "create_calendar_event".to_string(),
            description: "OpenAI latency benchmark tool".to_string(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations::default(),
            latency_hint: None,
            flow: Some(ToolFlowDeclaration::public_egress()),
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: signer.public_key().to_hex(),
    };
    let signed = chio_manifest::sign_manifest(&manifest, &signer)
        .map_err(|error| ProviderError::Malformed(format!("sign latency manifest: {error}")))?;
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .map_err(|error| ProviderError::Malformed(format!("admit latency manifest: {error}")))?;
    OpenAiAdapter::new_with_registry("org_chio_latency", server_id, &registry)
}

#[cfg(feature = "provider-adapter")]
fn enforce_p99_budget() {
    let adapter = match admitted_adapter() {
        Ok(adapter) => adapter,
        Err(error) => panic!("OpenAI verdict latency adapter setup failed: {error}"),
    };
    let p99 = match measure_p99(&adapter) {
        Ok(p99) => p99,
        Err(error) => panic!("OpenAI verdict latency bench failed: {error}"),
    };

    assert!(
        p99 <= VERDICT_P99_BUDGET,
        "OpenAI verdict latency p99 {:?} exceeded {:?}",
        p99,
        VERDICT_P99_BUDGET
    );
}

#[cfg(feature = "provider-adapter")]
pub fn bench(c: &mut Criterion) {
    enforce_p99_budget();

    let adapter = match admitted_adapter() {
        Ok(adapter) => adapter,
        Err(error) => panic!("OpenAI verdict latency adapter setup failed: {error}"),
    };
    c.bench_function("openai/verdict_latency_gate_sse_stream", |b| {
        b.iter(|| {
            if let Err(error) = run_verdict_path(black_box(&adapter)) {
                panic!("OpenAI verdict latency iteration failed: {error}");
            }
        });
    });
}

#[cfg(feature = "provider-adapter")]
criterion_group!(benches, bench);
#[cfg(feature = "provider-adapter")]
criterion_main!(benches);

#[cfg(not(feature = "provider-adapter"))]
fn main() {}
