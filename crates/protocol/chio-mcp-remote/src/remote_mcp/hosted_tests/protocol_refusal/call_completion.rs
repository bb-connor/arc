//! A restricted call completes in its session whatever happens to the POST
//! stream that dispatched it.

use super::*;

const DEADLINE: Duration = Duration::from_secs(4);
const CALL_TABLE: &str = "remote_session_credential_calls";
const LATCH_TABLE: &str = "remote_session_credential_latches";

fn call(wire_id: u64, logical_id: &str) -> Value {
    json!({"jsonrpc":"2.0","id":wire_id,"method":"tools/call","params":{
        "name":"echo_json","arguments":{"message":"session-owned completion"},
        "_meta":{"chioRequestId":logical_id}}})
}

async fn post(
    fixture: &HttpFixture,
    token: &str,
    session: &str,
    message: &Value,
) -> TestResult<Response> {
    let bytes = serde_json::to_vec(message)?;
    tokio::time::timeout(
        DEADLINE,
        request(fixture, MCP_ENDPOINT_PATH, token, Some(session), &bytes),
    )
    .await?
}

async fn read(response: Response) -> TestResult<(StatusCode, Vec<u8>)> {
    let status = response.status();
    let body = tokio::time::timeout(
        DEADLINE,
        axum::body::to_bytes(response.into_body(), 128 * 1024),
    )
    .await??;
    Ok((status, body.to_vec()))
}

/// The last non-empty SSE data frame.
fn terminal(body: &[u8]) -> TestResult<Value> {
    let text = std::str::from_utf8(body)?;
    let data = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .rfind(|data| !data.is_empty())
        .ok_or("no terminal SSE data frame")?;
    Ok(serde_json::from_str(data)?)
}

fn call_state(fixture: &HttpFixture, session: &str, request_id: &str) -> TestResult<String> {
    let path = fixture
        .state
        .factory
        .config
        .session_db_path
        .as_deref()
        .ok_or("session db")?;
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let record: String = conn.query_row(
        &format!("SELECT record_json FROM {CALL_TABLE} WHERE session_id=?1 AND request_id=?2"),
        rusqlite::params![session, request_id],
        |row| row.get(0),
    )?;
    let record: Value = serde_json::from_str(&record)?;
    Ok(record["state"].as_str().ok_or("call state")?.to_owned())
}

async fn settled(fixture: &HttpFixture, session: &str, request_id: &str) -> TestResult<String> {
    let started = std::time::Instant::now();
    loop {
        let state = call_state(fixture, session, request_id)?;
        if state != "pending" || started.elapsed() > DEADLINE {
            return Ok(state);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn gate() -> (
    Arc<CallGate>,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (entered, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release) = std::sync::mpsc::channel();
    let gate = Arc::new(CallGate {
        entered,
        release: std::sync::Mutex::new(release),
    });
    (gate, entered_rx, release_tx)
}

async fn await_entered(entered: std::sync::mpsc::Receiver<()>) -> TestResult {
    tokio::task::spawn_blocking(move || entered.recv_timeout(DEADLINE)).await??;
    Ok(())
}

async fn shutdown(fixture: &HttpFixture) -> TestResult {
    fixture.state.sessions.shutdown_all_active().await?;
    fixture.state.factory.shutdown_shared_upstream_owner()?;
    Ok(())
}

#[tokio::test]
async fn a_disconnected_call_completes_and_its_retry_replays_without_redispatch() -> TestResult {
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;
    let token = credential(&fixture, &session).await?;

    let dispatched = post(&fixture, &token, &session, &call(41, "disconnected")).await?;
    assert_eq!(dispatched.status(), StatusCode::OK);
    drop(dispatched);

    let state = settled(&fixture, &session, "disconnected").await?;
    let (status, body) =
        read(post(&fixture, &token, &session, &call(42, "disconnected")).await?).await?;
    let calls = fixture.calls.load(Ordering::SeqCst);
    shutdown(&fixture).await?;

    assert_eq!(state, "completed_unacknowledged");
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let replay: Value = serde_json::from_slice(&body)?;
    assert_eq!(replay["id"], json!(42));
    assert_eq!(
        replay["result"]["_meta"]["chioDelivery"]["requestId"],
        json!("disconnected")
    );
    assert_eq!(calls, 1, "the retry dispatched the tool again");
    Ok(())
}

#[tokio::test]
async fn a_slow_reader_receives_the_outcome_the_session_already_persisted() -> TestResult {
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;
    let token = credential(&fixture, &session).await?;

    let dispatched = post(&fixture, &token, &session, &call(43, "slow-reader")).await?;
    let state = settled(&fixture, &session, "slow-reader").await?;
    let (status, body) = read(dispatched).await?;
    let (_, replayed) =
        read(post(&fixture, &token, &session, &call(44, "slow-reader")).await?).await?;
    let calls = fixture.calls.load(Ordering::SeqCst);
    shutdown(&fixture).await?;

    assert_eq!(state, "completed_unacknowledged");
    assert_eq!(status, StatusCode::OK);
    let delivered = terminal(&body)?;
    assert_eq!(delivered["id"], json!(43));
    let replayed: Value = serde_json::from_slice(&replayed)?;
    assert_eq!(
        delivered["result"]["_meta"]["chioDelivery"],
        replayed["result"]["_meta"]["chioDelivery"]
    );
    assert_eq!(calls, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_cancelled_before_the_response_keeps_the_pending_fence() -> TestResult {
    let (gate, entered, release) = gate();
    let fixture = fixture_with(Some(gate))?;
    let session = initialize(&fixture).await?;
    let token = credential(&fixture, &session).await?;

    let dispatched = post(&fixture, &token, &session, &call(45, "cancelled")).await?;
    await_entered(entered).await?;
    let Some(RemoteSessionEntry::Active(bound)) = fixture.state.sessions.lookup(&session).await
    else {
        return Err("authenticated bound session is not active".into());
    };
    bound.worker_serving_closed.send_replace(true);
    let (status, body) = read(dispatched).await?;
    release.send(())?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let state = call_state(&fixture, &session, "cancelled")?;
    let calls = fixture.calls.load(Ordering::SeqCst);
    shutdown(&fixture).await?;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        terminal(&body)?,
        json!({"jsonrpc":"2.0","id":45,"error":{"code":-32603,
            "message":"session worker stopped; effect is uncertain"}})
    );
    assert_eq!(state, "pending", "a cancelled call must keep its fence");
    assert_eq!(calls, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_outcome_persistence_keeps_the_pending_fence() -> TestResult {
    let (gate, entered, release) = gate();
    let fixture = fixture_with(Some(gate))?;
    let session = initialize(&fixture).await?;
    let token = credential(&fixture, &session).await?;

    let dispatched = post(&fixture, &token, &session, &call(46, "persist-fails")).await?;
    await_entered(entered).await?;
    {
        let path = fixture
            .state
            .factory
            .config
            .session_db_path
            .as_deref()
            .ok_or("session db")?;
        let conn = rusqlite::Connection::open(path)?;
        let removed = conn.execute(
            &format!("DELETE FROM {LATCH_TABLE} WHERE session_id=?1"),
            [&session],
        )?;
        assert_eq!(removed, 1);
    }
    release.send(())?;
    let (status, body) = read(dispatched).await?;
    let state = call_state(&fixture, &session, "persist-fails")?;
    let (retry_status, _) =
        read(post(&fixture, &token, &session, &call(47, "persist-fails")).await?).await?;
    let calls = fixture.calls.load(Ordering::SeqCst);
    shutdown(&fixture).await?;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        terminal(&body)?,
        json!({"jsonrpc":"2.0","id":46,"error":{"code":-32603,
            "message":"credential outcome persistence failed; effect is uncertain"}})
    );
    assert_eq!(state, "pending");
    assert_eq!(retry_status, StatusCode::CONFLICT);
    assert_eq!(calls, 1);
    Ok(())
}
