use std::process::Command;

use chio_provider_conformance::CaptureDirection;
use serde_json::Value;

use crate::cli::ScenarioSeed;
use crate::fixture::RecordPlan;
use crate::invoke::{captured_invocations, extract_bedrock_invocations, CapturedInvocation};
use crate::record::{
    capture_record, insert_payload_field, live_request_record, request_body, stamp_bedrock_headers,
};
use crate::RecordError;

pub(crate) const BEDROCK_REGION: &str = "us-east-1";

pub(crate) fn record_bedrock(
    seed: ScenarioSeed,
    profile: Option<&str>,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
) -> Result<RecordPlan, RecordError> {
    let mut request_record = live_request_record(&seed);
    stamp_bedrock_headers(
        &mut request_record,
        caller_arn,
        account_id,
        assumed_role_session_arn,
    )?;
    let request_body = request_body(&request_record)?;
    let stream = request_record
        .payload
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|method| method == "ConverseStream")
        || request_body
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);
    if stream {
        return Err(RecordError::BedrockStreamUnsupported);
    }

    let response_payload = bedrock_converse(profile, &request_body)?;
    let mut response_record =
        capture_record(&seed, CaptureDirection::UpstreamResponse, response_payload);
    if let Some(tool_config) = request_body.get("toolConfig") {
        insert_payload_field(
            &mut response_record.payload,
            "toolConfig",
            tool_config.clone(),
        )?;
    }

    let invocations = bedrock_batch_invocations(
        &seed,
        caller_arn,
        account_id,
        assumed_role_session_arn,
        &response_record.payload,
    )?;
    Ok(RecordPlan {
        seed,
        request_record,
        response_records: vec![response_record],
        invocations,
    })
}

fn bedrock_batch_invocations(
    seed: &ScenarioSeed,
    caller_arn: &str,
    account_id: &str,
    assumed_role_session_arn: Option<&str>,
    payload: &Value,
) -> Result<Vec<CapturedInvocation>, RecordError> {
    let invocations = extract_bedrock_invocations(
        seed,
        caller_arn,
        account_id,
        assumed_role_session_arn,
        payload,
    )?;
    if invocations.is_empty() && seed.expected_invocations > 0 {
        return Err(RecordError::CaptureShape {
            provider: "bedrock",
            message: "response did not include toolUse content blocks".to_string(),
        });
    }
    Ok(captured_invocations(seed, invocations))
}

#[derive(Debug)]
pub(crate) struct BedrockIdentity {
    pub(crate) caller_arn: String,
    pub(crate) account_id: String,
    pub(crate) assumed_role_session_arn: Option<String>,
}

pub(crate) fn bedrock_caller_identity(
    profile: Option<&str>,
) -> Result<BedrockIdentity, RecordError> {
    let mut command = Command::new("aws");
    command.args(["sts", "get-caller-identity", "--output", "json"]);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    let output = crate::process::capture(command)?;
    let value: Value = chio_provider_conformance::input::json(&output)?;
    let caller_arn = value
        .get("Arn")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| RecordError::AwsCli {
            message: "STS output was missing Arn".to_string(),
        })?;
    let account_id = value
        .get("Account")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| RecordError::AwsCli {
            message: "STS output was missing Account".to_string(),
        })?;
    let assumed_role_session_arn = if caller_arn.starts_with("arn:aws:sts::") {
        Some(caller_arn.clone())
    } else {
        None
    };
    Ok(BedrockIdentity {
        caller_arn,
        account_id,
        assumed_role_session_arn,
    })
}

fn bedrock_converse(profile: Option<&str>, request_body: &Value) -> Result<Value, RecordError> {
    use std::io::Write;
    let mut input = tempfile::NamedTempFile::new()?;
    let bytes = chio_core::canonical_json_bytes(request_body)
        .map_err(chio_core::canonical::UntrustedJsonError::Canonicalization)?;
    chio_core::canonical::UntrustedJsonText::from_wire(
        &bytes,
        chio_provider_conformance::input::MAX_DOCUMENT_BYTES,
    )?;
    input.write_all(&bytes)?;
    input.flush()?;
    let mut command = Command::new("aws");
    command.args([
        "bedrock-runtime",
        "converse",
        "--region",
        BEDROCK_REGION,
        "--cli-input-json",
        &format!("file://{}", input.path().display()),
        "--output",
        "json",
    ]);
    if let Some(profile) = profile {
        command.args(["--profile", profile]);
    }
    let output = crate::process::capture(command)?;
    chio_provider_conformance::input::json(&output).map_err(RecordError::from)
}
