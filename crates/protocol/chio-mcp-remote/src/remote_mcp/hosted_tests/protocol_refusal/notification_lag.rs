//! A GET notification stream that falls behind the session broadcast keeps the
//! session alive and ends with a resync pass of re-read hints.

use super::*;
use axum::body::HttpBody;
use std::io::Write as _;

const FLOOD: usize = 300;

fn get_router(fixture: &HttpFixture) -> Router {
    Router::new()
        .route(MCP_ENDPOINT_PATH, post(handle_post).get(handle_get))
        .with_state(fixture.state.clone())
}

/// Read SSE frames until the stream ends or stays quiet.
async fn read_events(body: axum::body::Body) -> TestResult<(Vec<(String, Value)>, bool)> {
    let mut body = body;
    let mut text = String::new();
    let mut ended = false;
    loop {
        let frame = tokio::time::timeout(
            Duration::from_millis(500),
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut body).poll_frame(cx)),
        )
        .await;
        match frame {
            Ok(Some(frame)) => {
                if let Ok(data) = frame?.into_data() {
                    text.push_str(std::str::from_utf8(&data)?);
                }
            }
            Ok(None) => {
                ended = true;
                break;
            }
            Err(_) => break,
        }
    }
    let mut events = Vec::new();
    for block in text.split("\n\n") {
        let id = block
            .lines()
            .find_map(|line| line.strip_prefix("id: "))
            .unwrap_or_default()
            .to_owned();
        let data = block
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .collect::<String>();
        if !data.is_empty() {
            events.push((id, serde_json::from_str(&data)?));
        }
    }
    Ok((events, ended))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lagged_get_stream_resyncs_instead_of_closing_the_session() -> TestResult {
    let fixture = fixture()?;
    let session = initialize(&fixture).await?;
    let Some(RemoteSessionEntry::Active(bound)) = fixture.state.sessions.lookup(&session).await
    else {
        return Err("authenticated bound session is not active".into());
    };
    let response = get_router(&fixture)
        .oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri(MCP_ENDPOINT_PATH)
                .header(AUTHORIZATION, "Bearer operator-fixture")
                .header(ACCEPT, "text/event-stream")
                .header(MCP_SESSION_ID_HEADER, &session)
                .header(MCP_PROTOCOL_VERSION_HEADER, "2025-11-25")
                .body(axum::body::Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    // The stream is attached and subscribed but not yet read, so the flood
    // overruns its broadcast receiver.
    let mut writer = crate::session_core_writer::BroadcastJsonRpcWriter::new(
        bound.event_tx.clone(),
        bound.retained_notification_events.clone(),
        bound.next_event_id.clone(),
        bound.session_id.clone(),
        bound.input_tx.response_context(),
    );
    for index in 1..=FLOOD {
        let line = json!({"jsonrpc": "2.0", "method": "notifications/message",
            "params": {"level": "info", "data": format!("flood-{index}")}});
        writer.write_all(format!("{line}\n").as_bytes())?;
    }

    let (events, ended) = read_events(response.into_body()).await?;
    let still_active = matches!(
        fixture.state.sessions.lookup(&session).await,
        Some(RemoteSessionEntry::Active(_))
    );
    fixture.state.sessions.shutdown_all_active().await?;
    fixture.state.factory.shutdown_shared_upstream_owner()?;

    assert!(still_active, "a lagged GET stream closed its session");
    assert!(!ended, "the GET stream ended after a lag");
    let sequence = |id: &str| -> u64 {
        id.rsplit('-')
            .next()
            .and_then(|seq| seq.parse().ok())
            .unwrap_or_default()
    };
    assert!(
        events
            .windows(2)
            .all(|pair| sequence(&pair[0].0) < sequence(&pair[1].0)),
        "events are not in sequence order"
    );
    assert!(
        events
            .iter()
            .any(|(_, message)| message["params"]["data"] == json!(format!("flood-{FLOOD}"))),
        "the newest notification was lost"
    );
    let (_, warning) = events.last().ok_or("no events after the lag")?;
    assert_eq!(warning["method"], json!("notifications/message"));
    assert_eq!(warning["params"]["level"], json!("warning"));
    let text = warning["params"]["data"].as_str().ok_or("warning text")?;
    assert!(
        text.starts_with("notification stream skipped ")
            && text
                .ends_with(" session events; re-read every listed catalog and subscribed resource"),
        "{text}"
    );
    Ok(())
}
