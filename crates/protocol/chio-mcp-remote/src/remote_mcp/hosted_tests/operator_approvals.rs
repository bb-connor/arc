use super::support;
use reqwest::StatusCode;
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn ap23_mcp_refuses_unsigned_operator_decision() -> TestResult {
    let server = support::start_http_server("agent-token");
    let response = server
        .client
        .post(format!(
            "{}/admin/approvals/unknown/decision",
            server.base_url
        ))
        .bearer_auth(&server.admin_token)
        .json(&json!({"decision": "approved"}))
        .send()?;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "an operator bearer cannot ask the receipt signer to mint approval authority"
    );
    Ok(())
}

#[test]
fn ap23_mcp_requires_explicit_approval_authority_before_creating_pending_record() -> TestResult {
    let server = support::start_http_server("agent-token");
    let session = server.initialize_session();
    let trust: Value = server.get_admin_session_trust(&session.id).json()?;
    let capability = trust
        .get("capabilities")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(|value| value.get("capabilityId"))
        .and_then(Value::as_str)
        .ok_or("session did not expose its capability")?;
    let response = server
        .client
        .post(format!("{}/admin/approvals", server.base_url))
        .bearer_auth(&server.admin_token)
        .json(&json!({
            "session_id": session.id,
            "capability_id": capability,
            "request_id": "unconfigured-approval",
            "tool_name": "echo_json",
            "arguments": {"message": "exact"},
            "purpose": "test explicit approval authority"
        }))
        .send()?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    Ok(())
}

#[cfg(target_os = "linux")]
#[path = "operator_approvals/native.rs"]
mod native;
