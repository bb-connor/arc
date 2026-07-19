use super::*;
use chio_http_core::ThresholdApprovalRequestContextResolver;
use std::sync::Arc;
use std::time::Duration;

/// Default wall-clock ceiling on a single upstream proxy hop, including reading
/// the full response body. Kept below the serve site's drain window so an
/// in-flight hop is resolved and receipted before a shutdown force-closes the
/// connection.
pub const DEFAULT_UPSTREAM_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// Trusted production authority required before threshold collector routes are mounted.
#[derive(Clone)]
pub struct ThresholdApprovalCollectorConfig {
    pub(crate) current_policy_hash: String,
    pub(crate) trusted_policy_authorities: Vec<PublicKey>,
    pub(crate) request_context_resolver: Arc<dyn ThresholdApprovalRequestContextResolver>,
}

impl ThresholdApprovalCollectorConfig {
    #[must_use]
    pub fn new(
        current_policy_hash: String,
        trusted_policy_authorities: Vec<PublicKey>,
        request_context_resolver: Arc<dyn ThresholdApprovalRequestContextResolver>,
    ) -> Self {
        Self {
            current_policy_hash,
            trusted_policy_authorities,
            request_context_resolver,
        }
    }
}

impl std::fmt::Debug for ThresholdApprovalCollectorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdApprovalCollectorConfig")
            .field("current_policy_hash", &self.current_policy_hash)
            .field(
                "trusted_policy_authority_count",
                &self.trusted_policy_authorities.len(),
            )
            .finish_non_exhaustive()
    }
}

/// Configuration for the protect proxy.
pub struct ProtectConfig {
    /// Upstream URL to proxy to.
    pub upstream: String,
    /// Optional in-memory OpenAPI spec content (YAML or JSON).
    pub spec_content: Option<String>,
    /// Optional OpenAPI spec path. When omitted, the proxy auto-discovers the spec.
    pub spec_path: Option<String>,
    /// Address to listen on (e.g., "127.0.0.1:9090").
    pub listen_addr: String,
    /// Optional SQLite path for receipt persistence.
    pub receipt_db: Option<String>,
    /// Optional bearer token that authorizes remote sidecar control requests.
    pub sidecar_control_token: Option<String>,
    /// Optional seed used to keep the sidecar signer stable across restarts.
    pub signer_seed_hex: Option<String>,
    /// Explicit capability issuers trusted by the HTTP authority.
    pub trusted_capability_issuers: Vec<PublicKey>,
    /// Wall-clock ceiling on a single upstream proxy hop, including reading the
    /// full response body. Raise it for upstreams with legitimately slow calls or
    /// large bounded responses; the serve site widens its drain window to match so
    /// an in-flight hop is still receipted before shutdown force-closes it.
    /// Defaults to [`DEFAULT_UPSTREAM_REQUEST_TIMEOUT`].
    pub upstream_request_timeout: Duration,
}

impl std::fmt::Debug for ProtectConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectConfig")
            .field("upstream", &self.upstream)
            .field(
                "spec_content",
                &self.spec_content.as_ref().map(|_| "<inline>"),
            )
            .field("spec_path", &self.spec_path)
            .field("listen_addr", &self.listen_addr)
            .field("receipt_db", &self.receipt_db)
            .field(
                "sidecar_control_token",
                &self.sidecar_control_token.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "signer_seed_hex",
                &self.signer_seed_hex.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "trusted_capability_issuers",
                &self.trusted_capability_issuers,
            )
            .field("upstream_request_timeout", &self.upstream_request_timeout)
            .finish()
    }
}
