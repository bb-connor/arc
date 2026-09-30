use chio_provider_conformance::{CaptureDirection, CaptureRecord};
use serde_json::Value;

use crate::cli::ScenarioSeed;
use crate::fixture::RecordPlan;
use crate::http::post_json_capture;
use crate::invoke::{captured_invocations, extract_anthropic_invocations, CapturedInvocation};
use crate::record::{
    anthropic_version, capture_record, live_request_record, request_body, stamp_anthropic_headers,
};
use crate::util::sse_records;
use crate::RecordError;

const ANTHROPIC_MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";

pub(crate) fn record_anthropic(
    seed: ScenarioSeed,
    api_key: &str,
    workspace_id: &str,
) -> Result<RecordPlan, RecordError> {
    let mut request_record = live_request_record(&seed);
    stamp_anthropic_headers(&mut request_record, workspace_id)?;
    let request_body = request_body(&request_record)?;
    let stream = request_body
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let response_text = post_json_capture(
        "anthropic",
        ANTHROPIC_MESSAGES_URL,
        &[
            ("x-api-key", api_key.to_string()),
            ("anthropic-version", anthropic_version(&request_record)?),
        ],
        &request_body,
    )?;
    if stream {
        let response_records = sse_records(&seed, &response_text)?;
        let invocations = anthropic_stream_invocations(&seed, workspace_id, &response_records)?;
        Ok(RecordPlan {
            seed,
            request_record,
            response_records,
            invocations,
        })
    } else {
        let response_payload = chio_provider_conformance::input::text::<Value>(&response_text)?;
        let response_record =
            capture_record(&seed, CaptureDirection::UpstreamResponse, response_payload);
        let invocations =
            anthropic_batch_invocations(&seed, workspace_id, &response_record.payload)?;
        Ok(RecordPlan {
            seed,
            request_record,
            response_records: vec![response_record],
            invocations,
        })
    }
}

fn anthropic_batch_invocations(
    seed: &ScenarioSeed,
    workspace_id: &str,
    payload: &Value,
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let invocations = extract_anthropic_invocations(seed, workspace_id, payload)?;
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "anthropic",
            message: "response did not include tool_use content blocks".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}

fn anthropic_stream_invocations(
    seed: &ScenarioSeed,
    workspace_id: &str,
    records: &[CaptureRecord],
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let invocations = crate::invoke::anthropic_stream_invocations(seed, workspace_id, records)?;
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "anthropic",
            message: "stream did not include complete tool_use blocks".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}
