//! Provider-native adapter that mediates Anthropic Messages API tool-use
//! traffic through the Chio kernel. Pinned upstream API version:
//! `anthropic-version: 2023-06-01` (see [`transport::ANTHROPIC_VERSION`]).
//!
//! The adapter is a mediation gateway: [`AnthropicAdapter::send_messages`]
//! forwards a native `messages.create` request body to
//! `https://api.anthropic.com/v1/messages` over the shared HTTP transport with
//! `x-api-key` plus `anthropic-version` headers, then
//! [`lift_batch`](AnthropicAdapter::lift_batch) lifts every `tool_use` content
//! block in the response into a [`chio_tool_call_fabric::ToolInvocation`].
//! [`lower_tool_result_block`](AnthropicAdapter::lower_tool_result_block) lowers
//! a kernel verdict back into the `tool_result` block returned on the next
//! turn, and [`gate_sse_stream`](AnthropicAdapter::gate_sse_stream) gates the
//! streaming path.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod loaded_weights;
pub mod manifest;
pub mod native;
pub mod transport;

use std::sync::Arc;

use chio_provider_adapter_core::http::map_transport_error;
use chio_tool_call_fabric::{
    ProviderError, ProviderId, ProviderRequest, ToolInvocation, VerdictResult,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use adapter::streaming::GatedSseStream;
pub use manifest::AnthropicServerToolGate;
pub use native::{ToolResultBlock, ToolUseBlock};
pub use transport::{
    anthropic_transport, anthropic_transport_from_env, AuthScheme, HttpTransport, MockTransport,
    Transport, ANTHROPIC_MESSAGES_PATH, ANTHROPIC_VERSION, COMPUTER_USE_BETA,
};

/// Provider label used in transport-failure messages.
const PROVIDER_LABEL: &str = "Anthropic";

/// Configuration for the Anthropic Messages adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnthropicAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`ANTHROPIC_VERSION`].
    pub api_version: String,
    /// Anthropic workspace identifier (populates
    /// [`chio_tool_call_fabric::Principal::AnthropicWorkspace`] on every
    /// emitted [`chio_tool_call_fabric::ProvenanceStamp`]).
    pub workspace_id: String,
}

impl AnthropicAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`ANTHROPIC_VERSION`]. Other fields are passed through verbatim.
    pub fn new(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        public_key: impl Into<String>,
        workspace_id: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            server_name: server_name.into(),
            server_version: server_version.into(),
            public_key: public_key.into(),
            api_version: ANTHROPIC_VERSION.to_string(),
            workspace_id: workspace_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct AnthropicAdapter {
    config: AnthropicAdapterConfig,
    transport: Arc<dyn Transport>,
    server_tool_gate: AnthropicServerToolGate,
    manifest_registry: Option<chio_manifest::VerifiedManifestRegistry>,
}

impl AnthropicAdapter {
    /// Build a transport-only adapter with tool lifting disabled fail-closed.
    /// Use [`Self::new_with_registry`] for any tool execution path.
    pub fn new(config: AnthropicAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self {
            config,
            transport,
            server_tool_gate: AnthropicServerToolGate::deny_all(),
            manifest_registry: None,
        }
    }

    /// Build an adapter from a registry that has already verified the
    /// publisher signature and operator policy for every exposed tool.
    pub fn new_with_registry(
        config: AnthropicAdapterConfig,
        transport: Arc<dyn Transport>,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, AnthropicAdapterError> {
        let manifest = registry
            .verified_manifest(&config.server_id)
            .map(|signed| &signed.manifest)
            .ok_or_else(|| AnthropicAdapterError::RegistryManifestUnavailable {
                server_id: config.server_id.clone(),
            })?;
        if manifest.name != config.server_name
            || manifest.version != config.server_version
            || manifest.public_key != config.public_key
        {
            return Err(AnthropicAdapterError::ConfigManifestMismatch {
                server_id: config.server_id.clone(),
            });
        }
        Ok(Self {
            config,
            transport,
            server_tool_gate: AnthropicServerToolGate::from_manifest(manifest)?,
            manifest_registry: Some(registry.clone()),
        })
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Anthropic
    }

    /// Pinned upstream API version (always [`ANTHROPIC_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &AnthropicAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Borrow the manifest-derived server-tool gate.
    pub fn server_tool_gate(&self) -> &AnthropicServerToolGate {
        &self.server_tool_gate
    }

    pub(crate) fn bridge_security_for_tool(
        &self,
        tool_name: &str,
    ) -> Option<chio_manifest::BridgeSecurityMetadata> {
        let registry = self.manifest_registry.as_ref()?;
        if chio_manifest::ServerTool::from_anthropic_wire_name(tool_name).is_some() {
            registry.bridge_security_for_server_tool(&self.config.server_id, tool_name)
        } else {
            registry.bridge_security(&self.config.server_id, tool_name)
        }
    }

    /// Forward a native `messages.create` request to the upstream Anthropic
    /// endpoint and lift the tool-use blocks in the response.
    ///
    /// `request_body` is the Messages API JSON body
    /// (`{ model, messages, tools, max_tokens, .. }`). It is POSTed to
    /// [`ANTHROPIC_MESSAGES_PATH`] over the configured transport with the
    /// `x-api-key` and `anthropic-version` headers; a non-2xx status, timeout,
    /// or transport failure is mapped into the fabric [`ProviderError`]
    /// taxonomy and fails closed. On success the response body is handed to
    /// [`lift_batch`](Self::lift_batch).
    pub async fn send_messages(
        &self,
        request_body: &[u8],
    ) -> Result<Vec<ToolInvocation>, ProviderError> {
        let response = self.post_messages(request_body).await?;
        self.lift_batch(ProviderRequest(response.body))
    }

    /// Forward a streaming `messages.create` request and gate the SSE response.
    ///
    /// The request is POSTed to [`ANTHROPIC_MESSAGES_PATH`]; the buffered
    /// `text/event-stream` body is then run through
    /// [`gate_sse_stream`](Self::gate_sse_stream) with the supplied evaluator so
    /// every buffered `tool_use` block is gated at `content_block_stop` before
    /// any bytes are released.
    pub async fn send_messages_stream<F>(
        &self,
        request_body: &[u8],
        evaluate: F,
    ) -> Result<GatedSseStream, ProviderError>
    where
        F: FnMut(&ToolInvocation) -> Result<VerdictResult, ProviderError>,
    {
        let body = self
            .transport
            .post_sse(ANTHROPIC_MESSAGES_PATH, request_body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))?;
        self.gate_sse_stream(&body, evaluate)
    }

    /// Perform the raw upstream POST and return the buffered response, mapping
    /// any transport failure into the fabric error taxonomy.
    async fn post_messages(
        &self,
        request_body: &[u8],
    ) -> Result<transport::HttpResponse, ProviderError> {
        self.transport
            .post_json(ANTHROPIC_MESSAGES_PATH, request_body)
            .await
            .map_err(|error| map_transport_error(PROVIDER_LABEL, error))
    }

    /// Whether this build was compiled with the `computer-use` cargo
    /// feature. Surfaced here so callers can refuse to start a session that
    /// requests server tools without the feature flag set, without having
    /// to thread `cfg` macros through their own code.
    pub fn computer_use_enabled() -> bool {
        cfg!(feature = "computer-use")
    }
}

impl chio_provider_adapter_core::Provider for AnthropicAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum AnthropicAdapterError {
    /// Bubbled up from the shared HTTP transport layer.
    #[error(transparent)]
    Transport(#[from] transport::HttpTransportError),
    /// The upstream response could not be lifted into the canonical fabric
    /// types.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// The `computer-use` cargo feature is required but not enabled.
    #[error("server-tool surface requires the `computer-use` cargo feature")]
    ComputerUseFeatureDisabled,
    /// Raised when the manifest used to build the server-tool gate is invalid.
    #[error(transparent)]
    Manifest(#[from] chio_manifest::ManifestError),
    /// The configured server has no admitted signed manifest.
    #[error("verified manifest registry has no Anthropic server {server_id}")]
    RegistryManifestUnavailable { server_id: String },
    /// Runtime configuration must identify exactly the admitted publisher surface.
    #[error("Anthropic adapter config does not match admitted manifest for {server_id}")]
    ConfigManifestMismatch { server_id: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn registry_adapter(transport: Arc<dyn Transport>) -> AnthropicAdapter {
        let signer = chio_core::Keypair::from_seed(&[17; 32]);
        let config = AnthropicAdapterConfig::new(
            "anthropic-1",
            "Anthropic Messages",
            "0.1.0",
            signer.public_key().to_hex(),
            "wks_test",
        );
        let manifest = chio_manifest::ToolManifest {
            schema: chio_manifest::TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: None,
            version: config.server_version.clone(),
            tools: vec![chio_manifest::ToolDefinition {
                name: "get_weather".to_string(),
                description: "Get weather".to_string(),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: chio_manifest::ToolAnnotations {
                    read_only: true,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                },
                latency_hint: None,
                flow: None,
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &signer)
            .expect("sign explicit Anthropic unit manifest");
        let mut registry = chio_manifest::VerifiedManifestRegistry::default();
        registry
            .register_public_only(
                signed,
                &signer.public_key(),
                chio_manifest::RuntimeToolTopology::remote(),
            )
            .expect("admit explicit Anthropic unit manifest");
        AnthropicAdapter::new_with_registry(config, transport, &registry)
            .expect("build registry-backed Anthropic unit adapter")
    }

    fn config() -> AnthropicAdapterConfig {
        AnthropicAdapterConfig::new(
            "anthropic-1",
            "Anthropic Messages",
            "0.1.0",
            "deadbeef",
            "wks_test",
        )
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, ANTHROPIC_VERSION);
        assert_eq!(cfg.api_version, "2023-06-01");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = AnthropicAdapter::new(cfg, Arc::new(transport));
        assert_eq!(adapter.provider(), ProviderId::Anthropic);
        assert_eq!(adapter.api_version(), "2023-06-01");
    }

    #[test]
    fn config_round_trips_canonical_json() {
        let cfg = config();
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let back: AnthropicAdapterConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cfg, back);
    }
    #[test]
    fn computer_use_flag_matches_cfg() {
        // Whatever the cargo feature is set to in this build, the helper
        // must reflect it. Both branches are covered: the gate-check builds
        // the crate with and without `--features computer-use`.
        assert_eq!(
            AnthropicAdapter::computer_use_enabled(),
            cfg!(feature = "computer-use")
        );
    }

    fn tool_use_response() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "id": "msg_01outbound",
            "type": "message",
            "role": "assistant",
            "content": [{
                "type": "tool_use",
                "id": "toolu_weather_1",
                "name": "get_weather",
                "input": { "location": "Paris" }
            }]
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn send_messages_posts_and_lifts() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_json_response(tool_use_response());
        let adapter = registry_adapter(mock.clone());

        let request = b"{\"model\":\"claude\",\"messages\":[]}";
        let invocations = adapter.send_messages(request).await.unwrap();

        // The lifted invocation came back from the real outbound parse path.
        assert_eq!(invocations.len(), 1);
        assert_eq!(invocations[0].tool_name, "get_weather");
        assert_eq!(invocations[0].provenance.request_id, "toolu_weather_1");
        assert!(invocations[0]
            .bridge_security
            .as_ref()
            .is_some_and(chio_manifest::BridgeSecurityMetadata::has_registry_coordinates));

        // The adapter posted the request body to the Messages path.
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, ANTHROPIC_MESSAGES_PATH);
        assert_eq!(calls[0].body, request);
    }

    #[tokio::test]
    async fn send_messages_maps_upstream_status() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_error(transport::HttpTransportError::Status {
            code: 429,
            body: "rate limited".to_string(),
        });
        let adapter = AnthropicAdapter::new(config(), mock);

        let error = adapter
            .send_messages(b"{}")
            .await
            .expect_err("a 429 must fail closed");
        assert!(matches!(error, ProviderError::RateLimited { .. }));
    }

    #[tokio::test]
    async fn send_messages_timeout_fails_closed() {
        let mock = Arc::new(transport::MockTransport::new());
        mock.push_error(transport::HttpTransportError::Timeout {
            url: "https://api.anthropic.com/v1/messages".to_string(),
            timeout_ms: 60_000,
        });
        let adapter = AnthropicAdapter::new(config(), mock);

        let error = adapter
            .send_messages(b"{}")
            .await
            .expect_err("a timeout must fail closed");
        assert!(matches!(
            error,
            ProviderError::TransportTimeout { ms: 60_000 }
        ));
    }

    #[tokio::test]
    async fn send_messages_exhausted_mock_fails_closed() {
        let mock = Arc::new(transport::MockTransport::new());
        let adapter = AnthropicAdapter::new(config(), mock);

        let error = adapter
            .send_messages(b"{}")
            .await
            .expect_err("an empty mock script must fail closed");
        // An exhausted mock surfaces through the transport-error mapping as a
        // malformed upstream payload rather than a silent empty success.
        assert!(matches!(error, ProviderError::Malformed(_)));
    }
}
