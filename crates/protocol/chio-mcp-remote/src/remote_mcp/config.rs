use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use chio_core::crypto::PublicKey;
use chio_egress_contract::HttpEgressContract;

#[cfg(test)]
use crate::SessionLifecyclePolicy;
use crate::{
    JwtProviderProfile, OAuthClientRegistration, RemoteApprovalConfig, RemoteClock,
    TrustedProxyConfig,
};
#[cfg(test)]
use chio_mcp_adapter::edge::McpTransport;

#[derive(Clone)]
pub struct RemoteServeHttpConfig {
    /// Activated DPoP replay authority loaded from
    /// `CHIO_DPOP_REPLAY_AUTHORITY_FILE`; required when the policy requires DPoP.
    pub dpop_replay_authority: Option<chio_kernel::dpop::authority::DpopReplayAuthority>,
    pub clock: RemoteClock,
    pub listen: SocketAddr,
    /// Listener confidentiality and explicit plaintext policy.
    pub transport: chio_http_serve::ServerTransportConfig,
    /// Explicit authenticated proxy trust for TLS and attestation binding evidence.
    pub trusted_proxy: Option<TrustedProxyConfig>,
    pub auth_token: Option<String>,
    pub auth_jwt_public_key: Option<String>,
    pub auth_jwt_discovery_url: Option<String>,
    pub auth_introspection_url: Option<String>,
    pub auth_introspection_client_id: Option<String>,
    pub auth_introspection_client_secret: Option<String>,
    pub auth_jwt_provider_profile: Option<JwtProviderProfile>,
    pub auth_server_seed_path: Option<PathBuf>,
    pub identity_federation_seed_path: Option<PathBuf>,
    pub enterprise_providers_file: Option<PathBuf>,
    pub auth_jwt_issuer: Option<String>,
    pub auth_jwt_audience: Option<String>,
    pub admin_token: Option<String>,
    /// Explicit operator principals and activated native approval replay custody.
    pub approval: Option<RemoteApprovalConfig>,
    pub control_url: Option<String>,
    /// Trust-control internal listener base URL; durable admission reaches
    /// the admission authority through it.
    pub control_internal_url: Option<String>,
    pub control_token: Option<String>,
    /// Dedicated trust-control bearer used only for remote capability issuance.
    pub remote_authority_workload_token: Option<String>,
    /// Exact current capability-authority key expected from trust-control.
    pub control_authority_public_key: Option<PublicKey>,
    /// Exact trusted capability-authority key set expected from trust-control.
    pub control_authority_trusted_public_keys: Vec<PublicKey>,
    /// Operator egress allowances every trust-control client of this server
    /// dials under.
    pub egress_allowances: Arc<chio_egress_contract::EgressAllowanceSet>,
    pub public_base_url: Option<String>,
    pub auth_servers: Vec<String>,
    pub auth_authorization_endpoint: Option<String>,
    pub auth_token_endpoint: Option<String>,
    pub auth_registration_endpoint: Option<String>,
    pub auth_jwks_uri: Option<String>,
    pub auth_scopes: Vec<String>,
    /// Clients the embedded authorization server accepts, each with one exact
    /// redirect URI. A client with several redirect URIs appears once per URI.
    pub auth_clients: Vec<OAuthClientRegistration>,
    pub auth_subject: String,
    pub auth_code_ttl_secs: u64,
    pub auth_access_token_ttl_secs: u64,
    pub receipt_db_path: Option<PathBuf>,
    pub revocation_db_path: Option<PathBuf>,
    pub authority_seed_path: Option<PathBuf>,
    pub authority_db_path: Option<PathBuf>,
    pub budget_db_path: Option<PathBuf>,
    pub session_db_path: Option<PathBuf>,
    /// Dedicated, operator-managed HMAC keyring for durable session records.
    /// This keyring must remain independent from authority and bearer secrets.
    pub resume_hmac_keyring_path: Option<PathBuf>,
    pub policy_path: PathBuf,
    pub server_id: String,
    pub server_name: String,
    pub server_version: String,
    pub signed_manifest_path: Option<PathBuf>,
    pub manifest_public_key: Option<String>,
    /// Pinned authority that prepares every native launch. The factory must
    /// fail closed when its policy, migration state, or manifest binding no
    /// longer authorizes the exact subprocess.
    #[cfg(test)]
    pub(crate) test_transport: Option<Arc<dyn McpTransport>>,
    #[cfg(test)]
    pub(crate) test_lifecycle_policy: Option<SessionLifecyclePolicy>,
    /// A session output line bound below the production bound.
    #[cfg(test)]
    pub(crate) test_session_line_bytes: Option<usize>,
    pub native_launch_factory: Arc<dyn chio_mcp_adapter::transport::NativeMcpLaunchFactory>,
    pub page_size: usize,
    pub tools_list_changed: bool,
    pub shared_hosted_owner: bool,
    pub wrapped_command: String,
    pub wrapped_args: Vec<String>,
    /// Typed HTTP egress contract that gates outbound HTTP from the remote
    /// MCP runtime (most prominently the OAuth introspection endpoint).
    /// Production deployments must populate this; absence falls back to
    /// substrate fail-closed at dispatch.
    pub egress_contract: Option<HttpEgressContract>,
}
