//! Restart conformance uses bounded JSON and SSE response readers.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use chio_core::canonical::UntrustedJsonText;
use chio_egress_contract::{
    BlockingContractAgent, BlockingContractStream as Response, HttpEgressContract, HttpEgressError,
};
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
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// One server-sent event: its id, when present, and its JSON payload.
struct SseEvent {
    id: Option<String>,
    message: Value,
}

struct Probe {
    agent: BlockingContractAgent,
    endpoint: String,
    token: String,
    timeout: Duration,
}

impl Probe {
    fn post(&self, session: Option<&str>, body: &Value) -> Result<Response, String> {
        let payload = serde_json::to_vec(body).map_err(|error| error.to_string())?;
        let mut request = self
            .agent
            .post(&self.endpoint)
            .map_err(request_error)?
            .deadline(self.timeout)
            .body_limit(MAX_RESPONSE_BYTES as u64)
            .header("authorization", &format!("Bearer {}", self.token))
            .header("connection", "close")
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json");
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", PROTOCOL_VERSION);
        }
        request
            .send_bytes_streaming(&payload)
            .map_err(request_error)
    }

    fn rpc(&self, session: &str, body: &Value) -> Result<Vec<SseEvent>, String> {
        let response = self.post(Some(session), body)?;
        if response.status() != 200 {
            return Err(format!("{} answered {}", body["method"], response.status()));
        }
        parse_sse(&read_response(response)?)
    }

    fn open_subscribed_session(&self) -> Result<String, String> {
        let response = self.post(
            None,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": PEER_LABEL, "version": "0.1.0"}}}),
        )?;
        if !(200..300).contains(&response.status()) {
            return Err(format!("initialize answered {}", response.status()));
        }
        let session = response
            .header("mcp-session-id")
            .map(str::to_owned)
            .ok_or("initialize returned no MCP-Session-Id")?;
        validate_initialize(response)?;
        let initialized = self.post(
            Some(&session),
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )?;
        if initialized.status() != 202 {
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

    fn replay_status(&self, session: &str, cursor: &str) -> Result<u16, String> {
        self.agent
            .get(&self.endpoint)
            .map_err(request_error)?
            .deadline(self.timeout)
            .header("authorization", &format!("Bearer {}", self.token))
            .header("connection", "close")
            .header("accept", "text/event-stream")
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", PROTOCOL_VERSION)
            .header("last-event-id", cursor)
            .call_streaming()
            .map(|stream| stream.status())
            .map_err(request_error)
    }
}

fn validate_initialize(response: Response) -> Result<(), String> {
    let content_type = response
        .header("content-type")
        .and_then(|value| value.split(';').next())
        .unwrap_or("")
        .trim();
    let is_sse = content_type.eq_ignore_ascii_case("text/event-stream");
    let is_json = content_type.eq_ignore_ascii_case("application/json");
    if !is_sse && !is_json {
        return Err("initialize returned an unsupported content type".to_owned());
    }
    if is_sse && response.status() != 200 {
        return Err(format!("initialize answered {}", response.status()));
    }
    let body = read_response(response)?;
    let messages = if is_sse {
        parse_sse(&body)?
            .into_iter()
            .map(|event| event.message)
            .collect::<Vec<_>>()
    } else {
        let text = UntrustedJsonText::from_wire(body.as_bytes(), MAX_RESPONSE_BYTES)
            .map_err(|error| error.to_string())?;
        vec![text.decode_document().map_err(|error| error.to_string())?]
    };
    let mut responses = messages
        .iter()
        .filter(|message| message["id"] == 1 && message.get("method").is_none());
    let message = responses.next().ok_or("initialize did not succeed")?;
    let result = &message["result"];
    if responses.next().is_some()
        || message["jsonrpc"] != "2.0"
        || message.get("error").is_some()
        || !result.is_object()
        || result["protocolVersion"] != PROTOCOL_VERSION
        || !result["capabilities"].is_object()
        || !result["serverInfo"]["name"].is_string()
        || !result["serverInfo"]["version"].is_string()
    {
        return Err("initialize did not succeed".to_owned());
    }
    Ok(())
}

fn is_timeout(error: &(dyn std::error::Error + 'static)) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if error.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            )
        }) {
            return true;
        }
        cause = error.source();
    }
    false
}

fn too_large() -> String {
    format!("restart probe response exceeds {MAX_RESPONSE_BYTES} bytes")
}

fn request_error(error: HttpEgressError) -> String {
    if matches!(error, HttpEgressError::ResponseTooLarge { .. }) {
        too_large()
    } else if is_timeout(&error) {
        "restart probe request timed out".to_owned()
    } else {
        error.to_string()
    }
}

fn read_response(response: Response) -> Result<String, String> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    response
        .into_body()
        .read_to_end(&mut bytes)
        .map_err(|error| {
            if error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<HttpEgressError>())
                .is_some_and(|cause| matches!(cause, HttpEgressError::ResponseTooLarge { .. }))
            {
                too_large()
            } else if is_timeout(&error) {
                "restart probe response timed out".to_owned()
            } else {
                "restart probe response could not be read".to_owned()
            }
        })?;
    String::from_utf8(bytes).map_err(|_| "restart probe response is not UTF-8".to_owned())
}

fn parse_sse(body: &str) -> Result<Vec<SseEvent>, String> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(format!(
            "restart probe response exceeds {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let body = body.strip_prefix('\u{feff}').unwrap_or(body);
    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    let mut events = Vec::new();
    let mut id = None;
    let mut data = String::new();
    for line in normalized.split_terminator('\n') {
        if line.is_empty() {
            let _ = data.pop();
            if !data.is_empty() {
                let text = UntrustedJsonText::from_wire(data.as_bytes(), MAX_RESPONSE_BYTES)
                    .map_err(|error| error.to_string())?;
                let message = text.decode_document().map_err(|error| error.to_string())?;
                events.push(SseEvent {
                    id: id.take(),
                    message,
                });
            }
            id = None;
            data.clear();
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "id" if !value.contains('\0') => {
                id = (!value.is_empty()).then(|| value.to_owned());
            }
            "data" => {
                data.push_str(value);
                data.push('\n');
            }
            _ => {}
        }
    }
    if !data.strip_suffix('\n').unwrap_or(&data).is_empty() {
        return Err("restart probe response ends inside an SSE event".to_owned());
    }
    Ok(events)
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

pub(super) fn run(
    options: &ConformanceRunOptions,
    listen: SocketAddr,
    restart: impl FnOnce() -> Result<(), RunnerError>,
) -> Result<Vec<ScenarioResult>, RunnerError> {
    let started = Instant::now();
    let endpoint = format!("http://{listen}/mcp");
    let contract = HttpEgressContract::for_configured_url(
        "chio-conformance-restart-probe",
        &endpoint,
        MAX_RESPONSE_BYTES as u64,
    )?;
    let probe = Probe {
        agent: BlockingContractAgent::new(&contract, REQUEST_TIMEOUT, REQUEST_TIMEOUT)?,
        endpoint,
        token: options.auth_token.clone(),
        timeout: REQUEST_TIMEOUT,
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
        if status == 409 {
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
mod tests;
