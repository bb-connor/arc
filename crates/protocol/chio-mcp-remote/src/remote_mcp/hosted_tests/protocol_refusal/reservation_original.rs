//! A definite refusal before inbox enqueue cannot retain a credential-call latch.

use super::*;

const DEADLINE: Duration = Duration::from_secs(4);

fn call(wire_id: u64, logical_id: &str) -> Value {
    json!({"jsonrpc":"2.0","id":wire_id,"method":"tools/call","params":{
        "name":"echo_json","arguments":{"message":"reserve-original"},
        "_meta":{"chioRequestId":logical_id}}})
}

async fn exchange(
    fixture: &HttpFixture,
    token: &str,
    session: &str,
    message: &Value,
) -> TestResult<(StatusCode, Vec<u8>)> {
    let bytes = serde_json::to_vec(message)?;
    let response = tokio::time::timeout(
        DEADLINE,
        request(fixture, MCP_ENDPOINT_PATH, token, Some(session), &bytes),
    )
    .await??;
    let status = response.status();
    let body = tokio::time::timeout(
        DEADLINE,
        axum::body::to_bytes(response.into_body(), 128 * 1024),
    )
    .await??;
    Ok((status, body.to_vec()))
}

#[tokio::test]
async fn mcp_reserve_original_definite_alias_refusal_releases_only_its_pending_call() -> TestResult
{
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;
    let token = credential(&fixture, &session).await?;
    let mut rejected = call(31, "definite-alias-refusal");
    rejected["params"]["_meta"]["approvalToken"] = json!("rejected-first-alias");
    rejected["params"]["_meta"]["chioApprovalToken"] = json!("rejected-second-alias");

    // Both attempts take the actual authenticated HTTP path. The redemption
    // validator rejects these aliases before McpInboxSender::send can enqueue.
    let refused = exchange(&fixture, &token, &session, &rejected).await?;
    let repeated_refusal = exchange(&fixture, &token, &session, &rejected).await?;
    let calls_after_refusal = fixture.calls.load(Ordering::SeqCst);
    let valid = call(32, "after-definite-alias-refusal");
    let completed = exchange(&fixture, &token, &session, &valid).await?;
    let replay = exchange(&fixture, &token, &session, &valid).await?;
    let calls_after_replay = fixture.calls.load(Ordering::SeqCst);
    // A genuinely enqueued outcome still fences a new logical call until its
    // signed delivery acknowledgement arrives, even after an identical replay.
    let fenced = exchange(
        &fixture,
        &token,
        &session,
        &call(33, "must-await-real-delivery-ack"),
    )
    .await?;
    fixture.state.sessions.shutdown_all_active().await?;
    fixture.state.factory.shutdown_shared_upstream_owner()?;

    assert!(refused.0.is_client_error(), "invalid aliases were admitted");
    assert_eq!(calls_after_refusal, 0, "a refused call reached the tool");
    assert_eq!(
        repeated_refusal, refused,
        "a definite pre-enqueue refusal became a durable uncertain-call fence"
    );
    assert_eq!(
        completed.0,
        StatusCode::OK,
        "a definite non-enqueue retained the session credential latch: {}",
        String::from_utf8_lossy(&completed.1)
    );
    assert_eq!(
        replay.0,
        StatusCode::OK,
        "completed outcome was not replayable"
    );
    assert_eq!(calls_after_replay, 1, "replay dispatched the tool again");
    assert_eq!(
        fenced.0,
        StatusCode::FORBIDDEN,
        "a delivered but unacknowledged effect lost its durable fence"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    Ok(())
}
