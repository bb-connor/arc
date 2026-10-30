#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

#[path = "remote_mcp/config.rs"]
mod config;
pub use config::RemoteServeHttpConfig;

mod rate_limit;
use rate_limit::{rate_limit_mcp_request, McpRateLimiter};
mod clock;
use chio_security_types::clock::{AuthorityDeadline, Clock, ClockError, UnixMillis};
pub use clock::RemoteClock;
#[path = "remote_mcp/idp_keys/mod.rs"]
pub mod idp_keys;
mod oauth_error;
pub use oauth_error::{OAuthError, OAuthRejection};
#[path = "remote_mcp/enterprise_provider_registry.rs"]
mod enterprise_provider_registry;
mod input;
#[path = "remote_mcp/sender_constraint.rs"]
mod sender_constraint;
use enterprise_provider_registry::{
    EnterpriseProviderRegistryFile, EnterpriseProviderRegistryRefusal,
};
#[path = "remote_mcp/root_exchange/mod.rs"]
pub mod root_exchange;
mod transport_identity;
use input::{
    decode as decode_json, BoundedJson, SenderConstraintError, MAX_AUTH_JSON_BYTES,
    MAX_SESSION_JSON_BYTES,
};
pub use transport_identity::TrustedProxyConfig;
use transport_identity::{SenderRequest, TransportIdentity};

pub use chio_control_plane::{CliError, JwtProviderProfile};

#[path = "remote_mcp/admin.rs"]
mod remote_mcp_admin;
#[path = "remote_mcp/approval_policy.rs"]
mod remote_mcp_approval_policy;
pub use remote_mcp_approval_policy::RemoteApprovalConfig;
#[path = "remote_mcp/http_body.rs"]
mod http_body;
#[path = "remote_mcp/post_completion.rs"]
mod post_completion;
#[path = "remote_mcp/protocol_refusal_http.rs"]
mod protocol_refusal_http;
#[path = "remote_mcp/approvals.rs"]
mod remote_mcp_approvals;
#[path = "remote_mcp/session_credentials.rs"]
mod remote_mcp_session_credentials;
#[path = "remote_mcp/session_worker.rs"]
mod session_worker;
#[path = "remote_mcp/stateless_http.rs"]
mod stateless_http;
use http_body::read_limited_mcp_post_body;
#[path = "remote_mcp/session_store.rs"]
mod remote_mcp_session_store;

use remote_mcp_session_store::*;

include!("remote_mcp/session_core.rs");
include!("remote_mcp/session_identity.rs");
include!("remote_mcp/session_resume.rs");
include!("remote_mcp/session_shared_upstream.rs");
include!("remote_mcp/session_forms.rs");
#[path = "remote_mcp/session_recovery.rs"]
mod session_recovery;
use session_recovery::{
    restore_persisted_sessions, restored_event_seed, resume_deadline, RestoredSession,
};
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
