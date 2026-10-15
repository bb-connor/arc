//! The hosted retry rule for sessions without a session credential: a
//! caller-stable `chioRequestId` binds one admission operation, so a retry
//! after a broken POST is refused and never redispatches. Without one, every
//! request gets a fresh kernel identity and a retry dispatches again.

use super::*;

const DEADLINE: Duration = Duration::from_secs(4);
const OPERATOR: &str = "operator-fixture";

fn call(wire_id: u64, logical_id: Option<&str>) -> Value {
    let mut message = json!({"jsonrpc":"2.0","id":wire_id,"method":"tools/call","params":{
        "name":"echo_json","arguments":{"message":"retry rule"}}});
    if let Some(logical_id) = logical_id {
        message["params"]["_meta"] = json!({"chioRequestId": logical_id});
    }
    message
}

async fn post(fixture: &HttpFixture, session: &str, message: &Value) -> TestResult<Response> {
    let bytes = serde_json::to_vec(message)?;
    tokio::time::timeout(
        DEADLINE,
        request(fixture, MCP_ENDPOINT_PATH, OPERATOR, Some(session), &bytes),
    )
    .await?
}

async fn terminal(response: Response) -> TestResult<Value> {
    assert_eq!(response.status(), StatusCode::OK);
    let body = tokio::time::timeout(
        DEADLINE,
        axum::body::to_bytes(response.into_body(), 128 * 1024),
    )
    .await??;
    let text = std::str::from_utf8(&body)?;
    let data = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .rfind(|data| !data.is_empty())
        .ok_or("no terminal SSE data frame")?;
    Ok(serde_json::from_str(data)?)
}

async fn calls_reach(fixture: &HttpFixture, expected: usize) -> TestResult {
    let started = std::time::Instant::now();
    while fixture.calls.load(Ordering::SeqCst) < expected {
        if started.elapsed() > DEADLINE {
            return Err(format!("tool calls never reached {expected}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}

fn tool_error(result: &Value) -> TestResult<&str> {
    assert_eq!(result["result"]["isError"], json!(true), "{result}");
    Ok(result["result"]["content"][0]["text"]
        .as_str()
        .ok_or("tool error text")?)
}

async fn shutdown(fixture: &HttpFixture) -> TestResult {
    fixture.state.sessions.shutdown_all_active().await?;
    fixture.state.factory.shutdown_shared_upstream_owner()?;
    Ok(())
}

#[tokio::test]
async fn a_same_session_retry_after_a_broken_post_is_refused_without_redispatch() -> TestResult {
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;

    drop(post(&fixture, &session, &call(60, Some("same-session"))).await?);
    calls_reach(&fixture, 1).await?;
    let started = std::time::Instant::now();
    let retry = loop {
        let retry =
            terminal(post(&fixture, &session, &call(61, Some("same-session"))).await?).await?;
        // A retry that overtakes the original is refused as in flight.
        if tool_error(&retry)? != "session error: request same-session is already in flight"
            || started.elapsed() > DEADLINE
        {
            break retry;
        }
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let calls = fixture.calls.load(Ordering::SeqCst);
    shutdown(&fixture).await?;

    assert_eq!(retry["id"], json!(61));
    assert_eq!(
        tool_error(&retry)?,
        "session error: request same-session already has authoritative lineage in this session"
    );
    assert_eq!(calls, 1, "the stable-id retry redispatched the tool");
    Ok(())
}

#[tokio::test]
async fn a_retry_from_another_session_is_refused_by_the_retained_operation() -> TestResult {
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;

    drop(post(&fixture, &session, &call(62, Some("other-session"))).await?);
    calls_reach(&fixture, 1).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let other = initialize(&fixture).await?;
    let retry = terminal(post(&fixture, &other, &call(63, Some("other-session"))).await?).await?;
    let calls = fixture.calls.load(Ordering::SeqCst);
    shutdown(&fixture).await?;

    assert_eq!(retry["id"], json!(63));
    let operation = tool_error(&retry)?
        .strip_prefix("durable admission failed: request id conflicts with retained operation ")
        .ok_or("expected the retained-operation conflict")?;
    assert!(
        operation.len() == 64 && operation.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{operation}"
    );
    assert_eq!(calls, 1, "the stable-id retry redispatched the tool");
    Ok(())
}

#[tokio::test]
async fn a_retry_without_a_stable_request_id_is_a_fresh_dispatch() -> TestResult {
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;

    drop(post(&fixture, &session, &call(64, None)).await?);
    calls_reach(&fixture, 1).await?;
    let retry = terminal(post(&fixture, &session, &call(64, None)).await?).await?;
    let calls = fixture.calls.load(Ordering::SeqCst);
    shutdown(&fixture).await?;

    assert_eq!(retry["id"], json!(64));
    assert_eq!(retry["result"]["isError"], json!(false), "{retry}");
    assert_eq!(
        calls, 2,
        "a request without chioRequestId must dispatch again"
    );
    Ok(())
}
