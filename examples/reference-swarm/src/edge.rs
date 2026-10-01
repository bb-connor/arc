//! The MCP edge as a worker sees it, and the admin routes the orchestrator
//! uses to learn a session's capability and to revoke it.

use std::error::Error;

use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde_json::{json, Value};

#[cfg(test)]
#[path = "edge/outcome_tests.rs"]
mod outcome_tests;

type Fallible<T> = Result<T, Box<dyn Error>>;

/// One edge and the server it wraps.
#[derive(Clone, Debug)]
pub struct EdgeTarget {
    pub name: String,
    pub base_url: String,
    pub server_id: String,
}

/// What one tool call came back as.
#[derive(Clone, Debug)]
pub struct CallOutcome {
    pub is_error: bool,
    pub text: String,
    pub structured: Value,
    /// The `event` of a `notifications/message` the edge sent with the
    /// response, such as `tool_denied` when the kernel refused the call.
    pub event: Option<String>,
}

impl CallOutcome {
    /// The kernel refused the call outside the capability's grant.
    pub fn denied(&self) -> bool {
        self.event.as_deref() == Some("tool_denied")
    }

    /// A guard in the edge's policy refused the call before the tool saw it.
    pub fn guard_denied(&self) -> bool {
        self.is_error && self.text.starts_with("guard denied")
    }

    /// The capability behind the session has been revoked.
    pub fn revoked(&self) -> bool {
        self.is_error && self.text.contains("has been revoked")
    }

    /// Match the expected kernel error for this session's capability. The
    /// scenario must also corroborate this response with signed receipts;
    /// ordinary kernel errors need not carry a tool_denied notification.
    pub fn budget_exhausted(&self, capability_id: &str) -> bool {
        self.is_error
            && self
                .event
                .as_deref()
                .is_none_or(|event| event == "tool_denied")
            && self.text == format!("invocation budget exhausted for capability {capability_id}")
    }
}

/// A worker's session on one edge.
pub struct EdgeSession {
    http: Client,
    base_url: String,
    bearer: String,
    session_id: Option<String>,
    next_id: u64,
}

impl EdgeSession {
    /// Open a session: `initialize`, then the initialized notification.
    pub fn connect(target: &EdgeTarget, bearer: &str) -> Fallible<Self> {
        let mut session = Self::detached(target, bearer, None);
        let (result, _) = session.rpc(
            "initialize",
            json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": { "name": "reference-swarm", "version": env!("CARGO_PKG_VERSION") },
            }),
        )?;
        if result.get("protocolVersion").is_none() {
            return Err(format!(
                "{}: initialize answered without a protocol version",
                target.name
            )
            .into());
        }
        session.notify("notifications/initialized")?;
        Ok(session)
    }

    /// Continue an existing session by its id, without a handshake: what a
    /// worker does after the edge restarted.
    pub fn resume(target: &EdgeTarget, bearer: &str, session_id: &str) -> Self {
        Self::detached(target, bearer, Some(session_id.to_string()))
    }

    fn detached(target: &EdgeTarget, bearer: &str, session_id: Option<String>) -> Self {
        Self {
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            base_url: target.base_url.trim_end_matches('/').to_string(),
            bearer: bearer.to_string(),
            session_id,
            next_id: 1,
        }
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn list_tools(&mut self) -> Fallible<Vec<String>> {
        let (result, _) = self.rpc("tools/list", json!({}))?;
        Ok(result["tools"]
            .as_array()
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| tool["name"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn call(&mut self, name: &str, arguments: Value) -> Fallible<CallOutcome> {
        let (result, notifications) = self.rpc(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        )?;
        let event = notifications.iter().find_map(|notification| {
            (notification["method"] == "notifications/message")
                .then(|| {
                    notification["params"]["data"]["event"]
                        .as_str()
                        .map(str::to_string)
                })
                .flatten()
        });
        let text = result["content"]
            .as_array()
            .and_then(|content| content.first())
            .and_then(|item| item["text"].as_str())
            .unwrap_or_default()
            .to_string();
        Ok(CallOutcome {
            is_error: result["isError"].as_bool().unwrap_or(false),
            text,
            structured: result
                .get("structuredContent")
                .cloned()
                .unwrap_or(Value::Null),
            event,
        })
    }

    pub fn close(self) {
        let _ = self
            .http
            .delete(format!("{}/mcp", self.base_url))
            .headers(self.headers())
            .send();
    }

    fn headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(value) = format!("Bearer {}", self.bearer).parse() {
            headers.insert(AUTHORIZATION, value);
        }
        if let Ok(value) = "application/json".parse() {
            headers.insert(CONTENT_TYPE, value);
        }
        if let Ok(value) = "application/json, text/event-stream".parse() {
            headers.insert(ACCEPT, value);
        }
        if let Some(session) = &self.session_id {
            if let Ok(value) = session.parse() {
                headers.insert("Mcp-Session-Id", value);
            }
        }
        headers
    }

    fn notify(&self, method: &str) -> Fallible<()> {
        self.http
            .post(format!("{}/mcp", self.base_url))
            .headers(self.headers())
            .json(&json!({ "jsonrpc": "2.0", "method": method, "params": {} }))
            .send()?;
        Ok(())
    }

    /// Send one request and return its result and the notifications that
    /// arrived with it; a JSON-RPC error becomes an `Err`.
    fn rpc(&mut self, method: &str, params: Value) -> Fallible<(Value, Vec<Value>)> {
        let id = self.next_id;
        self.next_id += 1;
        let response = self
            .http
            .post(format!("{}/mcp", self.base_url))
            .headers(self.headers())
            .json(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .send()?;
        if let Some(session) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
        {
            self.session_id = Some(session.to_string());
        }
        let status = response.status();
        let messages = messages_of(response)?;
        let mut notifications = Vec::new();
        let mut answer = None;
        for message in messages {
            if message.get("method").is_some() && message.get("id").is_none() {
                notifications.push(message);
            } else if message["id"] == json!(id) {
                answer = Some(message);
            }
        }
        let Some(answer) = answer else {
            return Err(format!("{method}: no response with id {id} (HTTP {status})").into());
        };
        if let Some(error) = answer.get("error") {
            return Err(format!(
                "{method}: JSON-RPC error {}: {}",
                error["code"],
                error["message"].as_str().unwrap_or("")
            )
            .into());
        }
        Ok((answer["result"].clone(), notifications))
    }
}

/// Every JSON object an edge response carries, whether plain JSON or an
/// event stream of `data:` lines.
fn messages_of(response: Response) -> Fallible<Vec<Value>> {
    let event_stream = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| content_type.contains("text/event-stream"));
    let status = response.status();
    let body = response.text()?;
    if !event_stream {
        if body.trim().is_empty() {
            return Ok(Vec::new());
        }
        return serde_json::from_str(&body)
            .map(|message| vec![message])
            .map_err(|error| {
                format!(
                    "HTTP {status} answered with a body that is not JSON ({error}): {}",
                    body.chars().take(200).collect::<String>()
                )
                .into()
            });
    }
    Ok(body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .collect())
}

/// The admin surface of one edge.
pub struct EdgeAdmin {
    http: Client,
    base_url: String,
    bearer: String,
}

impl EdgeAdmin {
    pub fn new(target: &EdgeTarget, admin_bearer: &str) -> Self {
        Self {
            http: Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            base_url: target.base_url.trim_end_matches('/').to_string(),
            bearer: admin_bearer.to_string(),
        }
    }

    pub fn healthy(&self) -> bool {
        self.http
            .get(format!("{}/admin/health", self.base_url))
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer))
            .send()
            .is_ok_and(|response| response.status().is_success())
    }

    /// The capability the edge issued for a session.
    pub fn session_capability_id(&self, session_id: &str) -> Fallible<String> {
        let trust: Value = self
            .http
            .get(format!(
                "{}/admin/sessions/{session_id}/trust",
                self.base_url
            ))
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer))
            .send()?
            .error_for_status()?
            .json()?;
        trust["capabilities"]
            .as_array()
            .and_then(|capabilities| capabilities.first())
            .and_then(|capability| capability["capabilityId"].as_str())
            .map(str::to_string)
            .ok_or_else(|| "session trust carries no capability".into())
    }

    /// Revoke a capability; `true` when this call revoked it.
    pub fn revoke(&self, capability_id: &str) -> Fallible<bool> {
        let revoked: Value = self
            .http
            .post(format!("{}/admin/revocations", self.base_url))
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer))
            .json(&json!({ "capability_id": capability_id }))
            .send()?
            .error_for_status()?
            .json()?;
        if revoked["revoked"] != json!(true) {
            return Err(format!("revocation of {capability_id} was not recorded").into());
        }
        Ok(revoked["newlyRevoked"].as_bool().unwrap_or(false))
    }
}
