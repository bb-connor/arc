//! Hosted-session scenarios that restart `chio mcp serve-http` between steps.
//! Language peers cannot restart the server, so the runner drives these itself.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Instant;

use reqwest::blocking::{Client, Response};
use reqwest::StatusCode;
use serde_json::{json, Value};

use super::{ConformanceRunOptions, RunnerError};
use crate::model::{
    AssertionOutcome, AssertionResult, DeploymentMode, PeerRole, ResultStatus, ScenarioCategory,
    ScenarioResult, Transport,
};

pub(super) const PEER_LABEL: &str = "chio-restart-probe";
const PROTOCOL_VERSION: &str = "2025-11-25";
const SUBSCRIBED_URI: &str = "fixture://docs/alpha";
const SUBSCRIPTION_SCENARIO: &str = "hosted-subscription-across-restart";
const REPLAY_SCENARIO: &str = "hosted-replay-across-restart";

/// One server-sent event: its id, when present, and its JSON payload.
struct SseEvent {
    id: Option<String>,
    message: Value,
}

struct Probe {
    client: Client,
    endpoint: String,
    token: String,
}

impl Probe {
    fn post(&self, session: Option<&str>, body: &Value) -> Result<Response, String> {
        let mut request = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.token)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .json(body);
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", PROTOCOL_VERSION);
        }
        request.send().map_err(|error| error.to_string())
    }

    fn rpc(&self, session: &str, body: &Value) -> Result<Vec<SseEvent>, String> {
        let response = self.post(Some(session), body)?;
        if response.status() != StatusCode::OK {
            return Err(format!("{} answered {}", body["method"], response.status()));
        }
        Ok(parse_sse(
            &response.text().map_err(|error| error.to_string())?,
        ))
    }

    fn open_subscribed_session(&self) -> Result<String, String> {
        let response = self.post(
            None,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": PEER_LABEL, "version": "0.1.0"}}}),
        )?;
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or("initialize returned no MCP-Session-Id")?;
        response.text().map_err(|error| error.to_string())?;
        let initialized = self.post(
            Some(&session),
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )?;
        if initialized.status() != StatusCode::ACCEPTED {
            return Err(format!(
                "notifications/initialized answered {}",
                initialized.status()
            ));
        }
        let subscribed = self.rpc(
            &session,
            &json!({"jsonrpc":"2.0","id":2,"method":"resources/subscribe",
                "params":{"uri": SUBSCRIBED_URI}}),
        )?;
        if !subscribed
            .iter()
            .any(|event| event.message["id"] == 2 && event.message["result"].is_object())
        {
            return Err("resources/subscribe did not succeed".into());
        }
        Ok(session)
    }

    /// Asks the fixture upstream to publish an update for the subscribed URI
    /// and returns the `resources/updated` events the request stream carried.
    fn trigger_update(&self, session: &str, id: u64) -> Result<Vec<SseEvent>, String> {
        let events = self.rpc(
            session,
            &json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{
                "name":"emit_fixture_notifications","arguments":{"uri": SUBSCRIBED_URI}}}),
        )?;
        Ok(events
            .into_iter()
            .filter(|event| {
                event.message["method"] == "notifications/resources/updated"
                    && event.message["params"]["uri"] == SUBSCRIBED_URI
            })
            .collect())
    }

    fn replay_status(&self, session: &str, cursor: &str) -> Result<StatusCode, String> {
        self.client
            .get(&self.endpoint)
            .bearer_auth(&self.token)
            .header("accept", "text/event-stream")
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .header("last-event-id", cursor)
            .send()
            .map(|response| response.status())
            .map_err(|error| error.to_string())
    }
}

fn parse_sse(body: &str) -> Vec<SseEvent> {
    body.split("\n\n")
        .filter_map(|frame| {
            let mut id = None;
            let mut data = String::new();
            for line in frame.lines() {
                if let Some(value) = line.strip_prefix("id:") {
                    id = Some(value.trim().to_owned());
                } else if let Some(value) = line.strip_prefix("data:") {
                    data.push_str(value.trim());
                }
            }
            serde_json::from_str(&data)
                .ok()
                .map(|message| SseEvent { id, message })
        })
        .collect()
}

fn assertion(name: &str, outcome: Result<(), String>) -> AssertionResult {
    match outcome {
        Ok(()) => AssertionResult {
            name: name.into(),
            status: AssertionOutcome::Pass,
            message: None,
        },
        Err(message) => AssertionResult {
            name: name.into(),
            status: AssertionOutcome::Fail,
            message: Some(message),
        },
    }
}

fn scenario_result(
    scenario_id: &str,
    started: Instant,
    assertions: Vec<AssertionResult>,
) -> ScenarioResult {
    let failure = assertions
        .iter()
        .find(|assertion| assertion.status != AssertionOutcome::Pass)
        .and_then(|assertion| assertion.message.clone());
    ScenarioResult {
        scenario_id: scenario_id.into(),
        peer: PEER_LABEL.into(),
        peer_role: PeerRole::ClientToChioServer,
        deployment_mode: DeploymentMode::RemoteHttp,
        transport: Transport::StreamableHttp,
        spec_version: PROTOCOL_VERSION.into(),
        category: ScenarioCategory::McpCore,
        status: if failure.is_some() {
            ResultStatus::Fail
        } else {
            ResultStatus::Pass
        },
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        assertions,
        notes: None,
        artifacts: BTreeMap::new(),
        failure_kind: failure.as_ref().map(|_| "assertion".to_owned()),
        failure_message: failure,
        expected_failure: None,
    }
}

/// Opens a subscribed session, records a notification cursor, restarts the
/// server through `restart`, then checks that the stale cursor is refused and
/// that the subscription still delivers updates.
pub(super) fn run(
    options: &ConformanceRunOptions,
    listen: SocketAddr,
    restart: impl FnOnce() -> Result<(), RunnerError>,
) -> Result<Vec<ScenarioResult>, RunnerError> {
    let started = Instant::now();
    let probe = Probe {
        client: Client::new(),
        endpoint: format!("http://{listen}/mcp"),
        token: options.auth_token.clone(),
    };
    let before = probe.open_subscribed_session().and_then(|session| {
        let cursor = probe
            .trigger_update(&session, 3)?
            .into_iter()
            .find_map(|event| event.id)
            .ok_or("no resources/updated event carried an id before the restart")?;
        Ok((session, cursor))
    });
    let (session, cursor) = match before {
        Ok(opened) => opened,
        Err(message) => {
            let failed = assertion("subscribed_session_before_restart", Err(message));
            return Ok(vec![
                scenario_result(SUBSCRIPTION_SCENARIO, started, vec![failed.clone()]),
                scenario_result(REPLAY_SCENARIO, started, vec![failed]),
            ]);
        }
    };

    restart()?;

    let replay = probe.replay_status(&session, &cursor).and_then(|status| {
        if status == StatusCode::CONFLICT {
            Ok(())
        } else {
            Err(format!(
                "a pre-restart cursor was answered {status}, not 409"
            ))
        }
    });
    let delivered = probe.trigger_update(&session, 4).and_then(|updates| {
        if updates.is_empty() {
            Err("the restored subscription delivered no resources/updated".into())
        } else {
            Ok(())
        }
    });
    Ok(vec![
        scenario_result(
            SUBSCRIPTION_SCENARIO,
            started,
            vec![assertion("subscription_delivers_after_restart", delivered)],
        ),
        scenario_result(
            REPLAY_SCENARIO,
            started,
            vec![assertion("pre_restart_cursor_refused", replay)],
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::parse_sse;

    #[test]
    fn sse_frames_keep_their_ids_and_skip_priming_events() {
        let events = parse_sse(
            "id: s-1\nretry: 1000\ndata:\n\nid: s-2\ndata: {\"method\":\"notifications/resources/updated\"}\n\ndata: {\"id\":3,\"result\":{}}\n\n",
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id.as_deref(), Some("s-2"));
        assert_eq!(
            events[0].message["method"],
            "notifications/resources/updated"
        );
        assert_eq!(events[1].id, None);
        assert_eq!(events[1].message["id"], 3);
    }
}
