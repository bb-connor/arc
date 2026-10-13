//! Identifiers for MCP protocol revision 2026-07-28, the stateless core.
//!
//! A stateless request names its revision in
//! `params._meta["io.modelcontextprotocol/protocolVersion"]` instead of an
//! `initialize` handshake. Transports use these constants to recognize such a
//! request before handing it to [`crate::ChioMcpEdge`].

use serde_json::{json, Value};

/// The stateless revision, served through per-request `_meta`.
pub const MCP_2026_07_28: &str = "2026-07-28";
/// The handshake revision, served through `initialize`.
pub const MCP_2025_11_25: &str = "2025-11-25";
/// Every revision this edge serves, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[MCP_2026_07_28, MCP_2025_11_25];
/// Revisions accepted through per-request `_meta`.
pub const STATELESS_PROTOCOL_VERSIONS: &[&str] = &[MCP_2026_07_28];

pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
pub const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";

/// HTTP headers disagree with the body, or a required header is missing.
pub const JSONRPC_HEADER_MISMATCH: i64 = -32020;
/// The requested revision is not served.
pub const JSONRPC_UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// The `_meta` protocol version a JSON-RPC message names, if any.
#[must_use]
pub fn requested_protocol_version(message: &Value) -> Option<&Value> {
    message
        .get("params")?
        .get("_meta")?
        .get(META_PROTOCOL_VERSION)
}

/// The `data` member of an `UnsupportedProtocolVersionError`.
#[must_use]
pub fn unsupported_protocol_version_data(requested: &Value) -> Value {
    json!({
        "supported": SUPPORTED_PROTOCOL_VERSIONS,
        "requested": requested,
    })
}
