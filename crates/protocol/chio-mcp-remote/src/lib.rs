#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

mod rate_limit;
use rate_limit::{rate_limit_mcp_request, McpRateLimiter};
mod clock;
use chio_security_types::clock::{AuthorityDeadline, Clock, ClockError, UnixMillis};
pub use clock::RemoteClock;
mod input;
use input::{
    decode as decode_json, BoundedJson, SenderConstraintError, MAX_AUTH_JSON_BYTES,
    MAX_SESSION_JSON_BYTES,
};

pub use chio_control_plane::{CliError, JwtProviderProfile};

#[path = "remote_mcp/admin.rs"]
mod remote_mcp_admin;
#[path = "remote_mcp/approvals.rs"]
mod remote_mcp_approvals;
#[path = "remote_mcp/session_credentials.rs"]
mod remote_mcp_session_credentials;
#[path = "remote_mcp/session_store.rs"]
mod remote_mcp_session_store;

use remote_mcp_session_store::*;

include!("remote_mcp/session_core.rs");
include!("remote_mcp/session_identity.rs");
include!("remote_mcp/session_resume.rs");
include!("remote_mcp/session_shared_upstream.rs");
include!("remote_mcp/session_forms.rs");
include!("remote_mcp/http_service.rs");
include!("remote_mcp/http_service_auth.rs");
include!("remote_mcp/oauth.rs");
#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "remote_mcp/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "remote_mcp/hosted_tests/mod.rs"]
mod hosted_tests;
