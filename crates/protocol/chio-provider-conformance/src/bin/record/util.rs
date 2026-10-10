use std::path::Path;

use chio_provider_conformance::{CaptureDirection, CaptureRecord};
use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};

use crate::cli::ScenarioSeed;
use crate::record::capture_record;
use crate::RecordError;

pub(crate) fn required_json_str<'a>(
    value: &'a Value,
    field: &str,
    path: &Path,
) -> Result<&'a str, RecordError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_fixture(path, format!("captured tool call was missing {field}")))
}

pub(crate) fn seed_family(seed: &ScenarioSeed) -> Option<String> {
    seed.records.iter().find_map(|record| record.family.clone())
}

pub(crate) fn seed_api_snapshot(seed: &ScenarioSeed) -> Option<String> {
    seed.records
        .iter()
        .find_map(|record| record.api_snapshot.clone())
}

pub(crate) fn sse_records(
    seed: &ScenarioSeed,
    text: &str,
) -> Result<Vec<CaptureRecord>, RecordError> {
    parse_sse_payloads(text)?
        .into_iter()
        .map(|payload| {
            Ok(capture_record(
                seed,
                CaptureDirection::UpstreamEvent,
                payload,
            ))
        })
        .collect()
}

fn parse_sse_payloads(text: &str) -> Result<Vec<Value>, RecordError> {
    use chio_provider_adapter_core::{parse_sse_frames, SseParseOptions};
    let frames = parse_sse_frames(
        text.as_bytes(),
        SseParseOptions::ignoring_unknown("recorder")
            .with_done_sentinel("[DONE]")
            .with_event_type_cross_check(),
    )?;
    Ok(frames
        .into_iter()
        .filter_map(|frame| {
            frame.data.map(|data| {
                let event = frame.event.unwrap_or_else(|| {
                    data.get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("message")
                        .into()
                });
                json!({ "event": event, "data": data })
            })
        })
        .collect())
}

pub(crate) fn now_ts() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(crate) fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn invalid_fixture(path: impl AsRef<Path>, message: impl Into<String>) -> RecordError {
    RecordError::InvalidFixture {
        path: path.as_ref().to_path_buf(),
        message: message.into(),
    }
}
