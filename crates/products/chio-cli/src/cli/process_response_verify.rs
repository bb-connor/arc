//! Offline binding of a worker response to its original invocation and host context.

use std::{io::Read, path::Path};

use chio_core::{
    crypto::{canonical_json_bytes, sha256_hex},
    receipt::{body::ChioReceipt, decision::Decision, kinds::ReceiptKind},
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::CliError;

const MAX_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

#[path = "process_response_verify/json.rs"]
mod checked_json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    operation_key: String,
    server_id: String,
    tool_name: String,
    arguments: Value,
    known_outcome_only: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    runtime_id: String,
    process_id: String,
    capability_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    request_id: String,
    verdict: String,
    output: Value,
    reason: Value,
    terminal_state: Value,
    receipt_json: String,
    execution_nonce_json: Value,
}

fn fail(message: impl ToString) -> CliError {
    CliError::cli_other_error(message.to_string())
}

fn require(condition: bool, field: &str) -> Result<(), CliError> {
    if condition {
        Ok(())
    } else {
        Err(fail(format!("process response binding mismatch: {field}")))
    }
}

fn read_document<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, CliError> {
    let file = std::fs::File::open(path).map_err(fail)?;
    require(
        file.metadata().map_err(fail)?.is_file(),
        "regular input file",
    )?;
    let mut text = String::new();
    file.take(MAX_DOCUMENT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(fail)?;
    require(
        text.len() as u64 <= MAX_DOCUMENT_BYTES,
        "input exceeds 16 MiB",
    )?;
    // Worker envelopes are ordinary JSON, including integer-valued floats.
    // Reject duplicate keys and lossy number parsing without changing the
    // stricter canonical signed-receipt parser.
    serde_json::from_value(checked_json::parse(&text)?).map_err(fail)
}

pub(crate) fn cmd_verify_process_response(
    response_path: &Path,
    request_path: &Path,
    context_path: &Path,
    key_path: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    let request: Request = read_document(request_path)?;
    let context: Context = read_document(context_path)?;
    let response: Response = read_document(response_path)?;
    let key = super::load_trusted_kernel_pubkey(key_path).map_err(fail)?;
    let receipt = super::receipt_verify::verify_original_receipt(&response.receipt_json, &key)?;
    verify_request(&request, &context, &response, &receipt)?;
    verify_decision(&response, &receipt)?;
    verify_output(&response, &receipt)?;
    if json_output {
        println!(
            "{}",
            json!({
                "schema": "chio.process.response-verification.v1",
                "receipt_verified": true,
                "response_bound": true,
                "checks": ["signature", "signer_pin", "action_parameter_hash",
                    "runtime", "process", "capability", "operation_key", "recovery_policy",
                    "tool", "arguments", "request_id", "verdict", "reason", "terminal_state",
                    "returned_output_content"],
                "unchecked_fields": ["execution_nonce_json"],
            })
        );
    } else {
        println!("Verified process request binding, receipt, decision and returned content. Execution nonces are not verified.");
    }
    Ok(())
}

fn verify_request(
    request: &Request,
    context: &Context,
    response: &Response,
    receipt: &ChioReceipt,
) -> Result<(), CliError> {
    for id in [
        &request.operation_key,
        &request.server_id,
        &request.tool_name,
        &context.runtime_id,
        &context.process_id,
        &context.capability_id,
    ] {
        require(!id.is_empty(), "nonempty request and context identifiers")?;
    }
    require(request.arguments.is_object(), "arguments object")?;
    require(
        receipt.receipt_kind == ReceiptKind::MediatedDecision,
        "mediated decision",
    )?;
    require(receipt.capability_id == context.capability_id, "capability")?;
    require(
        receipt.tool_server == request.server_id && receipt.tool_name == request.tool_name,
        "tool",
    )?;
    require(
        canonical_json_bytes(&request.arguments).map_err(fail)?
            == canonical_json_bytes(&receipt.action.parameters).map_err(fail)?,
        "arguments",
    )?;
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| fail("missing process receipt metadata"))?;
    let process = &metadata["chio_process"];
    for (field, expected) in [
        ("runtime_id", context.runtime_id.as_str()),
        ("process_id", context.process_id.as_str()),
        ("operation_key", request.operation_key.as_str()),
    ] {
        require(process[field].as_str() == Some(expected), field)?;
    }
    require(
        if request.known_outcome_only {
            process["recovery_policy"] == "known_outcome_only"
        } else {
            process.get("recovery_policy").is_none()
        },
        "recovery_policy",
    )?;
    let attempt = process["attempt"]
        .as_u64()
        .ok_or_else(|| fail("missing process attempt"))?;
    require(
        (1..=3).contains(&attempt) && (!request.known_outcome_only || attempt == 1),
        "attempt",
    )?;
    let identity = if attempt == 1 {
        json!([
            context.runtime_id,
            context.process_id,
            request.operation_key
        ])
    } else {
        json!([
            context.runtime_id,
            context.process_id,
            request.operation_key,
            attempt
        ])
    };
    let expected_id = format!(
        "process:{}",
        sha256_hex(&canonical_json_bytes(&identity).map_err(fail)?)
    );
    require(response.request_id == expected_id, "request_id derivation")?;
    require(
        metadata["receipt_context"]["request_id"] == expected_id,
        "signed request_id",
    )?;
    Ok(())
}

fn verify_decision(response: &Response, receipt: &ChioReceipt) -> Result<(), CliError> {
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| fail("missing receipt metadata"))?;
    let (verdict, reason, terminal) = match receipt.decision.as_ref() {
        Some(Decision::Allow) => ("allow", Value::Null, json!({"state": "completed"})),
        Some(Decision::Deny { reason, guard })
            if metadata["threshold_approval"]["state"] == "approval_required"
                && reason == "cumulative approval required"
                && guard == "kernel" =>
        {
            (
                "pending_approval",
                Value::Null,
                json!({"state": "incomplete", "reason": "approval_required"}),
            )
        }
        Some(Decision::Deny { reason, .. }) => {
            ("deny", json!(reason), json!({"state": "completed"}))
        }
        Some(Decision::Cancelled { reason }) => (
            "deny",
            json!(reason),
            json!({"state": "cancelled", "reason": reason}),
        ),
        Some(Decision::Incomplete { reason }) => {
            let nonce = &metadata["execution_nonce"];
            let preflight = nonce["tool_dispatched"] == false
                && matches!(nonce["stage"].as_str(), Some("preflight" | "authorization"));
            (
                if preflight { "allow" } else { "deny" },
                if preflight {
                    Value::Null
                } else {
                    json!(reason)
                },
                json!({"state": "incomplete", "reason": reason}),
            )
        }
        None => return Err(fail("receipt has no signed decision")),
    };
    require(response.verdict == verdict, "verdict")?;
    require(response.reason == reason, "reason")?;
    require(response.terminal_state == terminal, "terminal_state")?;
    // A nonce is a separate signed artifact. Retain it without claiming its
    // validity, expiry or usability from receipt verification alone.
    require(
        response.execution_nonce_json.is_null()
            || (verdict == "allow" && response.execution_nonce_json.is_string()),
        "execution nonce shape",
    )
}

fn verify_output(response: &Response, receipt: &ChioReceipt) -> Result<(), CliError> {
    // Denied delivery can sign a retained or redacted digest while withholding
    // the payload. Only an absent wire output is acceptable for ordinary denial.
    if matches!(receipt.decision, Some(Decision::Deny { .. })) && response.verdict == "deny" {
        return require(response.output.is_null(), "denied output must be withheld");
    }
    let digest = if response.output.is_null() {
        sha256_hex(b"null")
    } else {
        let object = response
            .output
            .as_object()
            .ok_or_else(|| fail("invalid output envelope"))?;
        require(object.len() == 2, "output envelope fields")?;
        match response.output["kind"].as_str() {
            Some("value") => {
                let value = object
                    .get("value")
                    .ok_or_else(|| fail("missing output value"))?;
                sha256_hex(&canonical_json_bytes(value).map_err(fail)?)
            }
            Some("stream") => verify_stream(&response.output["chunks"], receipt)?,
            _ => return Err(fail("unsupported output kind")),
        }
    };
    require(digest == receipt.content_hash, "output content hash")
}

fn verify_stream(chunks: &Value, receipt: &ChioReceipt) -> Result<String, CliError> {
    let chunks = chunks
        .as_array()
        .ok_or_else(|| fail("invalid stream chunks"))?;
    let mut hashes = Vec::with_capacity(chunks.len());
    let mut total_bytes = 0u64;
    for chunk in chunks {
        let bytes = canonical_json_bytes(chunk).map_err(fail)?;
        total_bytes += bytes.len() as u64;
        hashes.push(sha256_hex(&bytes));
    }
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| fail("missing stream metadata"))?;
    let stream = &metadata["stream"];
    require(
        stream["chunks_received"] == json!(chunks.len()),
        "stream chunk count",
    )?;
    require(stream["total_bytes"] == total_bytes, "stream byte count")?;
    require(
        stream["chunk_hashes"] == json!(hashes),
        "stream chunk hashes",
    )?;
    Ok(sha256_hex(hashes.concat().as_bytes()))
}
