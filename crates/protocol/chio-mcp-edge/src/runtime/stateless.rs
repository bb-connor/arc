use super::errors::JsonRpcProtocolErrorArgs;
use super::jsonrpc::jsonrpc_protocol_error;
use super::*;
use crate::stateless::{
    unsupported_protocol_version_data, JSONRPC_UNSUPPORTED_PROTOCOL_VERSION, MCP_2026_07_28,
    META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION, META_SERVER_INFO, STATELESS_PROTOCOL_VERSIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
};

/// Methods 2026-07-28 removed from the core protocol.
const REMOVED_STATELESS_METHODS: &[&str] = &[
    "ping",
    "logging/setLevel",
    "resources/subscribe",
    "resources/unsubscribe",
    "tasks/list",
    "tasks/get",
    "tasks/result",
    "tasks/cancel",
];

/// Results that carry `ttlMs` and `cacheScope` (`CacheableResult`).
const CACHEABLE_METHODS: &[&str] = &[
    "server/discover",
    "tools/list",
    "prompts/list",
    "resources/list",
    "resources/read",
    "resources/templates/list",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestEra {
    /// Served under the revision negotiated by `initialize`.
    Handshake,
    /// Served under the revision named in the request's own `_meta`.
    Stateless,
}

impl ChioMcpEdge {
    /// Classify a request by protocol era. A stateless request on an
    /// uninitialized edge opens the kernel session it runs in; an edge opened
    /// by one era refuses requests from the other.
    pub(super) fn admit_request_era(
        &mut self,
        id: &Value,
        method: &str,
        params: &Value,
    ) -> Result<RequestEra, Value> {
        let Some(requested) = params
            .get("_meta")
            .and_then(|meta| meta.get(META_PROTOCOL_VERSION))
            .cloned()
        else {
            if self.stateless {
                return Err(unsupported_protocol_version(id.clone(), &Value::Null));
            }
            return Ok(RequestEra::Handshake);
        };
        if !requested
            .as_str()
            .is_some_and(|version| STATELESS_PROTOCOL_VERSIONS.contains(&version))
        {
            return Err(unsupported_protocol_version(id.clone(), &requested));
        }
        if method == "initialize" {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_REQUEST,
                "initialize is not part of a stateless protocol revision",
            ));
        }
        if REMOVED_STATELESS_METHODS.contains(&method) {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_METHOD_NOT_FOUND,
                "method not found",
            ));
        }
        if params.get("task").is_some() {
            return Err(jsonrpc_error(
                id.clone(),
                JSONRPC_INVALID_PARAMS,
                "task-augmented requests are not served under a stateless protocol revision",
            ));
        }
        match self.state {
            EdgeState::Ready { .. } if self.stateless => {}
            EdgeState::Uninitialized if method == "server/discover" => {}
            EdgeState::Uninitialized => self.open_stateless_session(id, params)?,
            _ => {
                return Err(jsonrpc_error(
                    id.clone(),
                    JSONRPC_INVALID_REQUEST,
                    "this MCP session was opened by initialize and refuses per-request protocol metadata",
                ))
            }
        }
        Ok(RequestEra::Stateless)
    }

    fn open_stateless_session(&mut self, id: &Value, params: &Value) -> Result<(), Value> {
        let authorization = self.stateless_authorization(id, params)?;
        // Server-initiated requests need a handshake stream the stateless
        // revision does not have, so roots, sampling and elicitation stay off.
        let peer_capabilities = PeerCapabilities {
            authorization: Some(authorization),
            ..PeerCapabilities::default()
        };
        let session_id = self
            .open_kernel_session(peer_capabilities)
            .map_err(|message| jsonrpc_error(id.clone(), JSONRPC_INTERNAL_ERROR, &message))?;
        self.kernel.activate_session(&session_id).map_err(|error| {
            jsonrpc_error(
                id.clone(),
                JSONRPC_INTERNAL_ERROR,
                &format!("failed to activate session: {error}"),
            )
        })?;
        self.stateless = true;
        self.state = EdgeState::Ready { session_id };
        Ok(())
    }

    fn stateless_authorization(
        &self,
        id: &Value,
        params: &Value,
    ) -> Result<chio_core::capability::features::CapabilityNegotiation, Value> {
        let client_capabilities = params
            .get("_meta")
            .and_then(|meta| meta.get(META_CLIENT_CAPABILITIES))
            .cloned()
            .unwrap_or_else(|| json!({}));
        crate::authorization::negotiate_authorization_capabilities(
            &json!({ "capabilities": client_capabilities }),
        )
        .map_err(|error| jsonrpc_error(id.clone(), JSONRPC_INVALID_PARAMS, &error.to_string()))
    }

    pub(super) fn handle_server_discover(&self, id: Value, params: &Value) -> Value {
        let authorization = match self.stateless_authorization(&id, params) {
            Ok(authorization) => authorization,
            Err(error) => return error,
        };
        let mut capabilities = self.advertised_capabilities(&authorization, MCP_2026_07_28);
        stateless_capabilities(&mut capabilities);
        jsonrpc_result(
            id,
            json!({
                "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
                "capabilities": Value::Object(capabilities),
            }),
        )
    }

    /// Add the members 2026-07-28 requires on every result.
    pub(super) fn finish_stateless_response(&self, method: &str, mut response: Value) -> Value {
        let Some(result) = response.get_mut("result").and_then(Value::as_object_mut) else {
            return response;
        };
        result
            .entry("resultType")
            .or_insert_with(|| json!("complete"));
        if CACHEABLE_METHODS.contains(&method) {
            // Results are authorized per principal, so no intermediary may
            // share them and no client may reuse them without re-asking.
            result.insert("ttlMs".to_string(), json!(0));
            result.insert("cacheScope".to_string(), json!("private"));
        }
        let meta = result.entry("_meta").or_insert_with(|| json!({}));
        if let Some(meta) = meta.as_object_mut() {
            meta.insert(
                META_SERVER_INFO.to_string(),
                json!({
                    "name": self.config.server_name,
                    "version": self.config.server_version,
                }),
            );
        }
        response
    }
}

/// Withdraw what the stateless revision cannot deliver: change notifications
/// need `subscriptions/listen`, logging needs per-request `logLevel`, and core
/// tasks moved to an extension this edge does not serve.
fn stateless_capabilities(capabilities: &mut serde_json::Map<String, Value>) {
    for key in ["tools", "prompts", "resources"] {
        if let Some(entry) = capabilities.get_mut(key).and_then(Value::as_object_mut) {
            if entry.contains_key("listChanged") {
                entry.insert("listChanged".to_string(), json!(false));
            }
            if entry.contains_key("subscribe") {
                entry.insert("subscribe".to_string(), json!(false));
            }
        }
    }
    capabilities.remove("logging");
    capabilities.remove("tasks");
    if let Some(protocol) = capabilities
        .get_mut("experimental")
        .and_then(|experimental| experimental.get_mut(CHIO_PROTOCOL_CAPABILITY_KEY))
        .and_then(Value::as_object_mut)
    {
        protocol.insert(
            "supportedProtocolVersions".to_string(),
            json!(SUPPORTED_PROTOCOL_VERSIONS),
        );
    }
}

fn unsupported_protocol_version(id: Value, requested: &Value) -> Value {
    jsonrpc_protocol_error(JsonRpcProtocolErrorArgs {
        id,
        jsonrpc_code: JSONRPC_UNSUPPORTED_PROTOCOL_VERSION,
        message: "Unsupported protocol version",
        chio_code: CHIO_ERROR_PROTOCOL_VERSION_UNSUPPORTED,
        name: "protocol_version_unsupported",
        retry_strategy: "do_not_retry_until_version_change",
        guidance: "retry with one of the server's supported protocol versions",
        context: Some(unsupported_protocol_version_data(requested)),
    })
}
