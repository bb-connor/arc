use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_core::Keypair;
use chio_gemini_tools_adapter::{
    transport, GeminiAdapter, GeminiAdapterConfig, GEMINI_API_VERSION,
};
use chio_manifest::{
    RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolManifest, VerifiedManifestRegistry,
    TOOL_MANIFEST_SCHEMA,
};
use chio_tool_call_fabric::{ProviderError, ReceiptId, VerdictResult};
use serde_json::json;

const COLD_INIT_P99_BUDGET: Duration = Duration::from_millis(500);
const P99_SAMPLE_COUNT: usize = 128;

fn stream_bytes() -> Result<Vec<u8>, ProviderError> {
    let payload = json!({
        "candidates": [{
            "content": {
                "parts": [
                    {"functionCall": {"name": "lookup_policy", "args": {"policy_id": "pol_latency"}}}
                ]
            }
        }]
    });
    let body = serde_json::to_vec(&payload).map_err(|error| {
        ProviderError::Malformed(format!("Gemini latency fixture encoding failed: {error}"))
    })?;
    let mut sse: Vec<u8> = Vec::with_capacity(body.len() + 8);
    sse.extend_from_slice(b"data: ");
    sse.extend_from_slice(&body);
    sse.extend_from_slice(b"\n\n");
    Ok(sse)
}

fn cold_adapter() -> Result<GeminiAdapter, ProviderError> {
    let signer = Keypair::from_seed(&[69; 32]);
    let config = GeminiAdapterConfig::new(
        "gemini-latency",
        "Gemini Latency",
        "0.1.0",
        signer.public_key().to_hex(),
        "proj_chio_latency",
    );
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: config.server_id.clone(),
        name: config.server_name.clone(),
        description: None,
        version: config.server_version.clone(),
        tools: vec![ToolDefinition {
            name: "lookup_policy".to_string(),
            description: "Latency fixture tool".to_string(),
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
    let signed = chio_manifest::sign_manifest(&manifest, &signer).map_err(|error| {
        ProviderError::Malformed(format!("Gemini latency manifest signing failed: {error}"))
    })?;
    let mut registry = VerifiedManifestRegistry::default();
    registry
        .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
        .map_err(|error| {
            ProviderError::Malformed(format!("Gemini latency manifest admission failed: {error}"))
        })?;
    GeminiAdapter::new_with_registry(config, Arc::new(transport::MockTransport::new()), &registry)
        .map_err(|error| {
            ProviderError::Malformed(format!("Gemini cold adapter init failed: {error}"))
        })
}

fn allow_verdict() -> VerdictResult {
    VerdictResult::Allow {
        redactions: vec![],
        receipt_id: ReceiptId("rcpt_gemini_latency_allow".to_string()),
    }
}

fn run_cold_verdict_path() -> Result<(), ProviderError> {
    let adapter = cold_adapter()?;
    let stream = stream_bytes()?;
    let gated = adapter.gate_sse_stream(&stream, |invocation| {
        black_box(invocation);
        Ok(allow_verdict())
    })?;

    if gated.invocations.len() != 1 {
        return Err(ProviderError::Malformed(format!(
            "expected one Gemini tool invocation, observed {}",
            gated.invocations.len()
        )));
    }
    if adapter.api_version() != GEMINI_API_VERSION {
        return Err(ProviderError::Malformed(format!(
            "Gemini API version drifted to {}",
            adapter.api_version()
        )));
    }
    black_box(gated);
    Ok(())
}

fn measure_p99() -> Result<Duration, ProviderError> {
    let mut samples = Vec::with_capacity(P99_SAMPLE_COUNT);
    for _ in 0..P99_SAMPLE_COUNT {
        let started = Instant::now();
        run_cold_verdict_path()?;
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p99_index = ((samples.len() * 99).div_ceil(100)).saturating_sub(1);
    samples.get(p99_index).copied().ok_or_else(|| {
        ProviderError::Malformed("Gemini verdict latency bench produced no samples".to_string())
    })
}

#[test]
fn cold_init_p99_stays_under_500ms() {
    let p99 = match measure_p99() {
        Ok(p99) => p99,
        Err(error) => panic!("Gemini verdict latency bench failed: {error}"),
    };
    assert!(
        p99 <= COLD_INIT_P99_BUDGET,
        "Gemini cold-init verdict latency p99 {:?} exceeded {:?}",
        p99,
        COLD_INIT_P99_BUDGET
    );
}
