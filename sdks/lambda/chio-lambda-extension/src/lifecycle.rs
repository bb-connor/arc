//! AWS Lambda Extension Runtime API lifecycle.
//!
//! The Extensions API lets a process that ships alongside the Lambda function
//! handler observe the invocation lifecycle. The contract (summarised from
//! <https://docs.aws.amazon.com/lambda/latest/dg/runtimes-extensions-api.html>):
//!
//! 1. Read the `AWS_LAMBDA_RUNTIME_API` environment variable, which contains
//!    the `host:port` of the Runtime API for this execution environment.
//! 2. `POST /2020-01-01/extension/register` with the extension name and the
//!    set of lifecycle events we want (`INVOKE`, `SHUTDOWN`).
//! 3. The response carries a `Lambda-Extension-Identifier` header. That id is
//!    required on every subsequent call.
//! 4. Loop forever calling `GET /2020-01-01/extension/event/next`. Each
//!    response is a JSON document describing either an `INVOKE` event (which
//!    blocks handler execution until we return for the next event) or a
//!    `SHUTDOWN` event (terminal; the extension has a short window to flush
//!    state before the sandbox is frozen).
//!
//! This module intentionally keeps the Runtime API wire contract isolated so
//! the rest of the extension can be exercised with unit tests that do not need
//! a live Lambda environment.

use std::time::Duration;

use serde::Deserialize;
use tracing::{debug, info, warn};

/// Environment variable Lambda uses to advertise the Runtime API endpoint.
pub const RUNTIME_API_ENV: &str = "AWS_LAMBDA_RUNTIME_API";

/// The API version segment used by every Extensions API endpoint.
const API_VERSION: &str = "2020-01-01";

/// Header used by the Runtime API to identify a registered extension.
const EXTENSION_ID_HEADER: &str = "Lambda-Extension-Identifier";

/// Header used on register requests to name the extension.
const EXTENSION_NAME_HEADER: &str = "Lambda-Extension-Name";

/// Errors produced by the lifecycle driver.
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("{RUNTIME_API_ENV} is not set; cannot register as a Lambda Extension")]
    MissingRuntimeApi,
    #[error("Runtime API request failed: {0}")]
    Transport(String),
    #[error("Runtime API returned non-success status {status}: {body}")]
    BadStatus { status: u16, body: String },
    #[error("Runtime API response missing {EXTENSION_ID_HEADER} header")]
    MissingExtensionId,
    #[error("Failed to decode Runtime API response: {0}")]
    Decode(String),
}

/// A single extension lifecycle event pulled from the Runtime API.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "eventType")]
pub enum ExtensionEvent {
    #[serde(rename = "INVOKE")]
    Invoke(InvokeEvent),
    #[serde(rename = "SHUTDOWN")]
    Shutdown(ShutdownEvent),
}

/// Payload emitted immediately before the function handler is invoked.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct InvokeEvent {
    pub deadline_ms: u64,
    pub request_id: String,
    pub invoked_function_arn: String,
    pub tracing: Option<serde_json::Value>,
}

/// Payload emitted when the execution environment is being recycled. The
/// extension has `DEADLINE - now` milliseconds (at most two seconds in
/// practice) to flush state before the sandbox is frozen.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct ShutdownEvent {
    pub shutdown_reason: String,
    pub deadline_ms: u64,
}

/// Handle returned after registering with the Runtime API. Clone-safe so the
/// HTTP server and the lifecycle loop can share it without additional locking.
#[derive(Debug, Clone)]
pub struct ExtensionHandle {
    base_url: String,
    extension_id: String,
    http: reqwest_like::Client,
}

impl ExtensionHandle {
    /// The opaque identifier assigned to this extension instance by the
    /// Runtime API. Surfaced for structured logging in callers that
    /// register in one place and log context in another.
    #[must_use]
    #[allow(dead_code)]
    pub fn id(&self) -> &str {
        &self.extension_id
    }
}

/// Register this process as a Lambda Extension and subscribe to INVOKE +
/// SHUTDOWN events.
pub async fn register(extension_name: &str) -> Result<ExtensionHandle, LifecycleError> {
    let runtime_api =
        std::env::var(RUNTIME_API_ENV).map_err(|_| LifecycleError::MissingRuntimeApi)?;
    let base_url = format!("http://{runtime_api}/{API_VERSION}/extension");
    let client = reqwest_like::Client::new();

    let body = serde_json::json!({
        "events": ["INVOKE", "SHUTDOWN"],
    });

    let register_url = format!("{base_url}/register");
    let response = client
        .post(&register_url)
        .header(EXTENSION_NAME_HEADER, extension_name)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&body).map_err(|err| LifecycleError::Decode(err.to_string()))?)
        .send()
        .await?;

    if !response.status_is_success() {
        let status = response.status();
        let body = response.into_text().await.unwrap_or_default();
        return Err(LifecycleError::BadStatus { status, body });
    }

    let extension_id = response
        .header(EXTENSION_ID_HEADER)
        .ok_or(LifecycleError::MissingExtensionId)?
        .to_string();

    info!(
        extension = extension_name,
        extension_id = %extension_id,
        "registered as Lambda Extension"
    );

    Ok(ExtensionHandle {
        base_url,
        extension_id,
        http: client,
    })
}

/// Block until the Runtime API has another event for us. The call itself can
/// block for the entire function invocation budget, so the caller must not
/// hold any locks while awaiting.
pub async fn next_event(handle: &ExtensionHandle) -> Result<ExtensionEvent, LifecycleError> {
    let url = format!("{}/event/next", handle.base_url);
    let response = handle
        .http
        .get(&url)
        .header(EXTENSION_ID_HEADER, handle.extension_id.as_str())
        .send()
        .await?;

    if !response.status_is_success() {
        let status = response.status();
        let body = response.into_text().await.unwrap_or_default();
        return Err(LifecycleError::BadStatus { status, body });
    }

    let text = response
        .into_text()
        .await
        .map_err(|err| LifecycleError::Decode(err.to_string()))?;
    debug!(%text, "extension event");
    serde_json::from_str(&text).map_err(|err| LifecycleError::Decode(err.to_string()))
}

/// Run the lifecycle loop until a SHUTDOWN event is received or an error
/// occurs. On SHUTDOWN the supplied `on_shutdown` closure is awaited; its
/// result is logged but not propagated because once we return from this
/// function the sandbox is seconds from being frozen regardless.
pub async fn run_loop<F, Fut>(
    handle: ExtensionHandle,
    mut on_shutdown: F,
) -> Result<(), LifecycleError>
where
    F: FnMut(ShutdownEvent) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    loop {
        match next_event(&handle).await {
            Ok(ExtensionEvent::Invoke(event)) => {
                debug!(
                    request_id = %event.request_id,
                    arn = %event.invoked_function_arn,
                    "INVOKE event"
                );
            }
            Ok(ExtensionEvent::Shutdown(event)) => {
                info!(
                    reason = %event.shutdown_reason,
                    deadline_ms = event.deadline_ms,
                    "SHUTDOWN event - flushing state"
                );
                // Bound the shutdown work: Lambda gives us ~2 seconds. Give
                // ourselves a 1.5 second ceiling so we still return to the
                // Runtime API before it force-kills us.
                let budget = Duration::from_millis(1_500);
                let result = tokio::time::timeout(budget, on_shutdown(event)).await;
                if result.is_err() {
                    warn!("SHUTDOWN flush exceeded {budget:?}");
                }
                return Ok(());
            }
            Err(err) => {
                warn!(?err, "lifecycle loop error");
                return Err(err);
            }
        }
    }
}

/// Tiny, dependency-free HTTP client used only for the Runtime API. We avoid
/// pulling in `reqwest` to keep the extension binary small; the Runtime API
/// is plain HTTP/1.1 on a Unix-like `host:port` with no TLS.
mod reqwest_like {
    use std::collections::HashMap;
    use std::io;

    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpStream;
    use tracing::trace;

    use super::LifecycleError;

    #[derive(Debug, Clone, Default)]
    pub(super) struct Client;

    impl Client {
        pub(super) fn new() -> Self {
            Self
        }

        pub(super) fn post(&self, url: &str) -> RequestBuilder {
            RequestBuilder::new("POST", url)
        }

        pub(super) fn get(&self, url: &str) -> RequestBuilder {
            RequestBuilder::new("GET", url)
        }
    }

    pub(super) struct RequestBuilder {
        method: &'static str,
        url: String,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
    }

    impl RequestBuilder {
        fn new(method: &'static str, url: &str) -> Self {
            Self {
                method,
                url: url.to_string(),
                headers: HashMap::new(),
                body: None,
            }
        }

        pub(super) fn header(mut self, key: &str, value: &str) -> Self {
            self.headers.insert(key.to_string(), value.to_string());
            self
        }

        pub(super) fn body(mut self, body: Vec<u8>) -> Self {
            self.body = Some(body);
            self
        }

        pub(super) async fn send(self) -> Result<HttpResponse, LifecycleError> {
            let parsed = parse_url(&self.url)
                .map_err(|err| LifecycleError::Transport(err.to_string()))?;
            trace!(host = %parsed.host_port, path = %parsed.path, "runtime api request");

            let stream = TcpStream::connect(&parsed.host_port)
                .await
                .map_err(|err| LifecycleError::Transport(err.to_string()))?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
                .await
                .map_err(|err| LifecycleError::Transport(err.to_string()))?;
            tokio::spawn(async move {
                if let Err(err) = conn.await {
                    tracing::debug!(?err, "runtime api connection closed");
                }
            });

            let mut builder = Request::builder().method(self.method).uri(&parsed.path);
            builder = builder.header("Host", parsed.host_header.as_str());
            for (k, v) in &self.headers {
                builder = builder.header(k.as_str(), v.as_str());
            }
            let body_bytes = self.body.unwrap_or_default();
            let req = builder
                .body(Full::new(Bytes::from(body_bytes)))
                .map_err(|err| LifecycleError::Transport(err.to_string()))?;

            let response = sender
                .send_request(req)
                .await
                .map_err(|err| LifecycleError::Transport(err.to_string()))?;
            Ok(HttpResponse::from_hyper(response))
        }
    }

    pub(super) struct HttpResponse {
        status: u16,
        headers: HashMap<String, String>,
        body: Incoming,
    }

    impl HttpResponse {
        fn from_hyper(response: Response<Incoming>) -> Self {
            let status = response.status().as_u16();
            let mut headers = HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(v) = value.to_str() {
                    headers.insert(name.as_str().to_string(), v.to_string());
                }
            }
            let body = response.into_body();
            Self {
                status,
                headers,
                body,
            }
        }

        pub(super) fn status(&self) -> u16 {
            self.status
        }

        pub(super) fn status_is_success(&self) -> bool {
            (200..300).contains(&self.status)
        }

        pub(super) fn header(&self, name: &str) -> Option<&str> {
            // Runtime API headers are case-insensitive; try exact + lowercase.
            if let Some(v) = self.headers.get(name) {
                return Some(v.as_str());
            }
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }

        pub(super) async fn into_text(self) -> Result<String, io::Error> {
            let collected = self
                .body
                .collect()
                .await
                .map_err(|err| io::Error::other(err.to_string()))?;
            let bytes = collected.to_bytes();
            String::from_utf8(bytes.to_vec())
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
        }
    }

    struct ParsedUrl {
        host_port: String,
        host_header: String,
        path: String,
    }

    fn parse_url(url: &str) -> Result<ParsedUrl, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("expected http:// url, got {url}"))?;
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(format!("missing host in url {url}"));
        }
        Ok(ParsedUrl {
            host_port: authority.to_string(),
            host_header: authority.to_string(),
            path: path.to_string(),
        })
    }

    impl From<LifecycleError> for std::io::Error {
        fn from(value: LifecycleError) -> Self {
            std::io::Error::other(value.to_string())
        }
    }

    impl From<std::io::Error> for LifecycleError {
        fn from(value: std::io::Error) -> Self {
            LifecycleError::Transport(value.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_invoke_event() {
        let raw = r#"{
            "eventType": "INVOKE",
            "deadlineMs": 1700000000000,
            "requestId": "abc-123",
            "invokedFunctionArn": "arn:aws:lambda:us-east-1:1:function:foo"
        }"#;
        let event: ExtensionEvent = serde_json::from_str(raw).unwrap();
        match event {
            ExtensionEvent::Invoke(invoke) => {
                assert_eq!(invoke.request_id, "abc-123");
                assert_eq!(invoke.deadline_ms, 1_700_000_000_000);
            }
            ExtensionEvent::Shutdown(_) => panic!("expected INVOKE"),
        }
    }

    #[test]
    fn parses_shutdown_event() {
        let raw = r#"{
            "eventType": "SHUTDOWN",
            "shutdownReason": "SPINDOWN",
            "deadlineMs": 1700000002000
        }"#;
        let event: ExtensionEvent = serde_json::from_str(raw).unwrap();
        match event {
            ExtensionEvent::Shutdown(shutdown) => {
                assert_eq!(shutdown.shutdown_reason, "SPINDOWN");
                assert_eq!(shutdown.deadline_ms, 1_700_000_002_000);
            }
            ExtensionEvent::Invoke(_) => panic!("expected SHUTDOWN"),
        }
    }
}
