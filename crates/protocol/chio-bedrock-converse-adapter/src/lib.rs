//! Mediates Amazon Bedrock Runtime Converse and ConverseStream tool-use
//! traffic through the Chio kernel.
//!
//! The v1 region is restricted to [`transport::BEDROCK_REGION`] (`us-east-1`).
//! The live transport ([`transport::AwsSdkTransport`]) calls the Bedrock
//! Runtime Converse operation through the AWS SDK for Rust (SigV4-signed); a
//! recording [`transport::MockTransport`] replays scripted responses for
//! hermetic tests.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod iam_principals;
pub mod loaded_weights;
pub mod native;
pub mod transport;

use std::collections::BTreeMap;
use std::sync::Arc;

use chio_attest_verify::{AttestVerifier, ExpectedIdentity};
use chio_tool_call_fabric::{Principal, ProviderId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use iam_principals::{
    AwsStsCallerIdentityProvider, BedrockCallerIdentity, IamPrincipalConfigError,
    IamPrincipalMapping, IamPrincipalsConfig, ResolvedBedrockPrincipal,
    DEFAULT_IAM_PRINCIPALS_CONFIG_PATH,
};
pub use native::{ToolConfig, ToolResultBlock, ToolResultStatus, ToolSpec, ToolUseBlock};
pub use transport::{
    AwsSdkTransport, BedrockOperation, ConverseRequest, MockTransport, Transport, TransportError,
    BEDROCK_CONVERSE_API_VERSION, BEDROCK_REGION,
};

/// Configuration for the Bedrock Converse adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BedrockAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and manifests.
    pub server_name: String,
    /// Adapter version string, independent of the upstream SDK version.
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API surface, always [`BEDROCK_CONVERSE_API_VERSION`].
    pub api_version: String,
    /// AWS region this adapter is pinned to, always [`BEDROCK_REGION`].
    pub region: String,
    /// IAM caller ARN that will populate Bedrock provenance.
    pub caller_arn: String,
    /// AWS account id corresponding to [`Self::caller_arn`].
    pub account_id: String,
    /// Assumed-role session ARN when the caller is an STS session.
    pub assumed_role_session_arn: Option<String>,
}

impl BedrockAdapterConfig {
    /// Construct a configuration pinned to the v1 Bedrock region and API surface.
    pub fn new(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        public_key: impl Into<String>,
        caller_arn: impl Into<String>,
        account_id: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            server_name: server_name.into(),
            server_version: server_version.into(),
            public_key: public_key.into(),
            api_version: BEDROCK_CONVERSE_API_VERSION.to_string(),
            region: BEDROCK_REGION.to_string(),
            caller_arn: caller_arn.into(),
            account_id: account_id.into(),
            assumed_role_session_arn: None,
        }
    }

    /// Attach an assumed-role session ARN to the configured Bedrock
    /// principal.
    pub fn with_assumed_role_session_arn(
        mut self,
        assumed_role_session_arn: impl Into<String>,
    ) -> Self {
        self.assumed_role_session_arn = Some(assumed_role_session_arn.into());
        self
    }

    /// Validate that an externally loaded config is still pinned to the
    /// single v1 region and API surface.
    pub fn validate(&self) -> Result<(), BedrockAdapterError> {
        if self.api_version != BEDROCK_CONVERSE_API_VERSION {
            return Err(BedrockAdapterError::UnsupportedApiVersion {
                requested: self.api_version.clone(),
            });
        }
        if self.region != BEDROCK_REGION {
            return Err(BedrockAdapterError::UnsupportedRegion {
                requested: self.region.clone(),
            });
        }
        Ok(())
    }

    /// Convert the configured caller fields into the shared fabric
    /// principal shape.
    pub fn principal(&self) -> Principal {
        Principal::BedrockIam {
            caller_arn: self.caller_arn.clone(),
            account_id: self.account_id.clone(),
            assumed_role_session_arn: self.assumed_role_session_arn.clone(),
        }
    }
}

/// Adapter handle for Bedrock Converse.
#[derive(Clone)]
pub struct BedrockAdapter {
    config: BedrockAdapterConfig,
    transport: Arc<dyn Transport>,
    principal_owner: Option<String>,
    matched_iam_principal_pattern: Option<String>,
    admitted_security: Option<BTreeMap<String, chio_manifest::BridgeSecurityMetadata>>,
}

impl BedrockAdapter {
    /// Build a raw provider projection from config and transport, rejecting
    /// configs that drift from the v1 `us-east-1` pin.
    ///
    /// This constructor has no manifest authority. Use
    /// [`Self::new_with_registry`] before lifted calls enter an evaluator.
    pub fn new(
        config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
    ) -> Result<Self, BedrockAdapterError> {
        config.validate()?;
        if transport.region() != BEDROCK_REGION {
            return Err(BedrockAdapterError::UnsupportedRegion {
                requested: transport.region().to_string(),
            });
        }
        Ok(Self {
            config,
            transport,
            principal_owner: None,
            matched_iam_principal_pattern: None,
            admitted_security: None,
        })
    }

    /// Build an adapter bound to one verified, policy-admitted Chio server.
    pub fn new_with_registry(
        config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, BedrockAdapterError> {
        let admitted_security = admitted_security_snapshot(&config, registry)?;
        let mut adapter = Self::new(config, transport)?;
        adapter.admitted_security = Some(admitted_security);
        Ok(adapter)
    }

    /// Build an identity-bound raw projection by loading a signed IAM
    /// principal map and resolving the caller identity.
    ///
    /// This constructor has no manifest authority. Use
    /// [`Self::new_with_signed_iam_principals_config_and_registry`] before
    /// lifted calls enter an evaluator.
    pub fn new_with_signed_iam_principals_config(
        mut config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
        caller_identity: BedrockCallerIdentity,
        iam_principals_path: impl AsRef<std::path::Path>,
        verifier: &dyn AttestVerifier,
        expected_identity: &ExpectedIdentity,
    ) -> Result<Self, BedrockAdapterError> {
        config.validate()?;
        if transport.region() != BEDROCK_REGION {
            return Err(BedrockAdapterError::UnsupportedRegion {
                requested: transport.region().to_string(),
            });
        }

        let iam_config = IamPrincipalsConfig::load_signed_from_path(
            iam_principals_path,
            verifier,
            expected_identity,
        )?;
        let resolved = iam_config.resolve(&caller_identity)?;

        config.caller_arn = resolved.caller_arn.clone();
        config.account_id = resolved.account_id.clone();
        config.assumed_role_session_arn = resolved.assumed_role_session_arn.clone();

        Ok(Self {
            config,
            transport,
            principal_owner: Some(resolved.owner),
            matched_iam_principal_pattern: Some(resolved.matched_pattern),
            admitted_security: None,
        })
    }

    /// Build an execution-ready adapter with both signed IAM identity and
    /// verified manifest security bound before any tool traffic is lifted.
    pub fn new_with_signed_iam_principals_config_and_registry(
        config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
        caller_identity: BedrockCallerIdentity,
        iam_principals_path: impl AsRef<std::path::Path>,
        verifier: &dyn AttestVerifier,
        expected_identity: &ExpectedIdentity,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, BedrockAdapterError> {
        let mut adapter = Self::new_with_signed_iam_principals_config(
            config,
            transport,
            caller_identity,
            iam_principals_path,
            verifier,
            expected_identity,
        )?;
        adapter.admitted_security = Some(admitted_security_snapshot(&adapter.config, registry)?);
        Ok(adapter)
    }

    /// Resolve STS identity once per process, then initialize an identity-bound
    /// raw projection from the signed IAM principal config.
    pub async fn new_with_signed_iam_principals_config_from_sts(
        config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
        sts_provider: &AwsStsCallerIdentityProvider,
        iam_principals_path: impl AsRef<std::path::Path>,
        verifier: &dyn AttestVerifier,
        expected_identity: &ExpectedIdentity,
    ) -> Result<Self, BedrockAdapterError> {
        let caller_identity = sts_provider.get_caller_identity_once().await?;
        Self::new_with_signed_iam_principals_config(
            config,
            transport,
            caller_identity,
            iam_principals_path,
            verifier,
            expected_identity,
        )
    }

    /// Resolve STS identity once per process, then bind both the signed IAM
    /// identity and verified manifest security before tool evaluation.
    pub async fn new_with_signed_iam_principals_config_from_sts_and_registry(
        config: BedrockAdapterConfig,
        transport: Arc<dyn Transport>,
        sts_provider: &AwsStsCallerIdentityProvider,
        iam_principals_path: impl AsRef<std::path::Path>,
        verifier: &dyn AttestVerifier,
        expected_identity: &ExpectedIdentity,
        registry: &chio_manifest::VerifiedManifestRegistry,
    ) -> Result<Self, BedrockAdapterError> {
        let caller_identity = sts_provider.get_caller_identity_once().await?;
        Self::new_with_signed_iam_principals_config_and_registry(
            config,
            transport,
            caller_identity,
            iam_principals_path,
            verifier,
            expected_identity,
            registry,
        )
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Bedrock
    }

    /// Pinned upstream API surface.
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Pinned AWS region.
    pub fn region(&self) -> &str {
        &self.config.region
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &BedrockAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    pub(crate) fn bridge_security_for_tool(
        &self,
        tool_name: &str,
    ) -> Result<Option<chio_manifest::BridgeSecurityMetadata>, chio_tool_call_fabric::ProviderError>
    {
        let Some(bindings) = &self.admitted_security else {
            return Ok(None);
        };
        bindings.get(tool_name).cloned().map(Some).ok_or_else(|| {
            chio_tool_call_fabric::ProviderError::Malformed(format!(
                "registry-bound Bedrock lift has no admitted security sidecar for tool `{tool_name}`"
            ))
        })
    }

    /// Run one batch Bedrock Runtime Converse turn through the transport and
    /// lift every `toolUse` block in the response into the shared fabric
    /// [`ToolInvocation`](chio_tool_call_fabric::ToolInvocation) shape.
    ///
    /// Transport-layer failures (throttling, upstream 5xx, timeout, rejected
    /// request) are mapped into the adapter-visible
    /// [`chio_tool_call_fabric::ProviderError`] taxonomy and fail closed before
    /// any invocation is produced.
    pub async fn converse(
        &self,
        request: transport::ConverseRequest,
    ) -> Result<Vec<chio_tool_call_fabric::ToolInvocation>, chio_tool_call_fabric::ProviderError>
    {
        let body = self
            .transport
            .converse(&request)
            .await
            .map_err(map_transport_error)?;
        self.lift_batch(chio_tool_call_fabric::ProviderRequest(body))
    }

    /// Chio owner/team label resolved from the signed IAM principal map.
    pub fn principal_owner(&self) -> Option<&str> {
        self.principal_owner.as_deref()
    }

    /// Mapping pattern that authorized the configured IAM principal.
    pub fn matched_iam_principal_pattern(&self) -> Option<&str> {
        self.matched_iam_principal_pattern.as_deref()
    }
}

fn admitted_security_snapshot(
    config: &BedrockAdapterConfig,
    registry: &chio_manifest::VerifiedManifestRegistry,
) -> Result<BTreeMap<String, chio_manifest::BridgeSecurityMetadata>, BedrockAdapterError> {
    let manifest = registry
        .verified_manifest(&config.server_id)
        .map(|signed| &signed.manifest)
        .ok_or_else(|| BedrockAdapterError::RegistryManifestUnavailable {
            server_id: config.server_id.clone(),
        })?;
    if manifest.name != config.server_name
        || manifest.version != config.server_version
        || manifest.public_key != config.public_key
    {
        return Err(BedrockAdapterError::ConfigManifestMismatch {
            server_id: config.server_id.clone(),
        });
    }

    let mut admitted_security = BTreeMap::new();
    for tool in &manifest.tools {
        let security = registry
            .bridge_security(&config.server_id, &tool.name)
            .filter(chio_manifest::BridgeSecurityMetadata::has_registry_coordinates)
            .ok_or_else(|| BedrockAdapterError::RegistrySecurityUnavailable {
                server_id: config.server_id.clone(),
                tool_name: tool.name.clone(),
            })?;
        admitted_security.insert(tool.name.clone(), security);
    }
    Ok(admitted_security)
}

impl chio_provider_adapter_core::Provider for BedrockAdapter {
    fn provider_id(&self) -> ProviderId {
        self.provider()
    }

    fn api_version(&self) -> &str {
        self.api_version()
    }
}

/// Adapter-local configuration and transport errors.
#[derive(Debug, Error)]
pub enum BedrockAdapterError {
    #[error("bedrock converse adapter supports only us-east-1 in v1; requested {requested}")]
    UnsupportedRegion { requested: String },
    #[error(
        "bedrock converse adapter supports only bedrock.converse.v1 in v1; requested {requested}"
    )]
    UnsupportedApiVersion { requested: String },
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    #[error(transparent)]
    IamPrincipals(#[from] iam_principals::IamPrincipalConfigError),
    /// The configured server has no admitted signed manifest.
    #[error("verified manifest registry has no Bedrock server {server_id}")]
    RegistryManifestUnavailable { server_id: String },
    /// Runtime configuration must identify exactly the admitted publisher surface.
    #[error("Bedrock adapter config does not match admitted manifest for {server_id}")]
    ConfigManifestMismatch { server_id: String },
    /// A verified tool did not retain registry-admitted bridge metadata.
    #[error(
        "verified manifest registry has no admitted security sidecar for Bedrock tool {server_id}/{tool_name}"
    )]
    RegistrySecurityUnavailable {
        server_id: String,
        tool_name: String,
    },
}

/// Map a wire-level [`transport::TransportError`] into the adapter-visible
/// fabric [`ProviderError`](chio_tool_call_fabric::ProviderError) taxonomy.
fn map_transport_error(error: transport::TransportError) -> chio_tool_call_fabric::ProviderError {
    use chio_tool_call_fabric::ProviderError;
    use transport::TransportError;

    match error {
        TransportError::RateLimited { retry_after_ms } => {
            ProviderError::RateLimited { retry_after_ms }
        }
        TransportError::Timeout { ms } => ProviderError::TransportTimeout { ms },
        TransportError::Upstream { status, message } => ProviderError::Upstream5xx {
            status,
            body: message,
        },
        TransportError::Rejected(detail)
        | TransportError::MalformedRequest(detail)
        | TransportError::DecodeResponse(detail) => ProviderError::Malformed(detail),
        other => ProviderError::Malformed(other.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core::Keypair;
    use chio_manifest::{
        RuntimeToolTopology, ToolAnnotations, ToolDefinition, ToolFlowDeclaration, ToolManifest,
        VerifiedManifestRegistry, TOOL_MANIFEST_SCHEMA,
    };
    use serde_json::json;

    fn config() -> BedrockAdapterConfig {
        BedrockAdapterConfig::new(
            "bedrock-1",
            "Bedrock Converse",
            "0.1.0",
            "deadbeef",
            "arn:aws:iam::123456789012:role/ChioAgentRole",
            "123456789012",
        )
    }

    fn admitted_registry(
        tool_name: &str,
    ) -> (
        BedrockAdapterConfig,
        VerifiedManifestRegistry,
        ToolFlowDeclaration,
    ) {
        let signer = Keypair::from_seed(&[63; 32]);
        let config = BedrockAdapterConfig::new(
            "bedrock-1",
            "Bedrock Converse",
            "0.1.0",
            signer.public_key().to_hex(),
            "arn:aws:iam::123456789012:role/ChioAgentRole",
            "123456789012",
        );
        let flow = ToolFlowDeclaration::public_egress();
        let manifest = ToolManifest {
            schema: TOOL_MANIFEST_SCHEMA.to_string(),
            server_id: config.server_id.clone(),
            name: config.server_name.clone(),
            description: None,
            version: config.server_version.clone(),
            tools: vec![ToolDefinition {
                name: tool_name.to_string(),
                description: "Admitted Bedrock tool".to_string(),
                input_schema: json!({"type": "object"}),
                output_schema: None,
                pricing: None,
                annotations: ToolAnnotations {
                    read_only: false,
                    destructive: false,
                    idempotent: false,
                    requires_approval: false,
                    estimated_duration_ms: None,
                },
                latency_hint: None,
                flow: Some(flow.clone()),
            }],
            server_tools: Vec::new(),
            required_permissions: None,
            public_key: signer.public_key().to_hex(),
        };
        let signed = chio_manifest::sign_manifest(&manifest, &signer).unwrap();
        let mut registry = VerifiedManifestRegistry::default();
        registry
            .register_public_only(signed, &signer.public_key(), RuntimeToolTopology::remote())
            .unwrap();
        (config, registry, flow)
    }

    fn tool_use_payload(tool_name: &str) -> chio_tool_call_fabric::ProviderRequest {
        chio_tool_call_fabric::ProviderRequest(
            serde_json::to_vec(&json!({
                "toolUse": {
                    "toolUseId": "tooluse_registry_1",
                    "name": tool_name,
                    "input": {"city": "Paris"}
                }
            }))
            .unwrap(),
        )
    }

    #[test]
    fn config_pins_region_and_api_version() {
        let cfg = config();
        assert_eq!(cfg.region, BEDROCK_REGION);
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.api_version, BEDROCK_CONVERSE_API_VERSION);
    }

    #[test]
    fn adapter_reports_provider_pin_and_region() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = BedrockAdapter::new(cfg, Arc::new(transport)).unwrap();
        assert_eq!(adapter.provider(), ProviderId::Bedrock);
        assert_eq!(adapter.api_version(), "bedrock.converse.v1");
        assert_eq!(adapter.region(), "us-east-1");
    }

    #[test]
    fn registry_bound_lift_preserves_exact_flow_sidecar() {
        let (config, registry, expected_flow) = admitted_registry("get_weather");
        let adapter = BedrockAdapter::new_with_registry(
            config,
            Arc::new(transport::MockTransport::new()),
            &registry,
        )
        .unwrap();
        let invocation = adapter
            .lift_batch(tool_use_payload("get_weather"))
            .unwrap()
            .remove(0);

        let security = invocation
            .bridge_security
            .as_ref()
            .expect("registry-bound lift retains security");
        assert!(security.has_registry_coordinates());
        assert_eq!(
            chio_core::canonical::canonical_json_bytes(security.flow().expect("flow sidecar"))
                .unwrap(),
            chio_core::canonical::canonical_json_bytes(&expected_flow).unwrap()
        );
    }

    #[test]
    fn registry_bound_constructor_rejects_missing_server() {
        let (mut config, registry, _) = admitted_registry("get_weather");
        config.server_id = "missing-bedrock".to_string();

        let error = match BedrockAdapter::new_with_registry(
            config,
            Arc::new(transport::MockTransport::new()),
            &registry,
        ) {
            Ok(_) => panic!("missing admitted server must fail closed"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            BedrockAdapterError::RegistryManifestUnavailable { .. }
        ));
    }

    #[test]
    fn registry_bound_constructor_rejects_config_mismatch() {
        let (mut config, registry, _) = admitted_registry("get_weather");
        config.public_key = "wrong-key".to_string();

        let error = match BedrockAdapter::new_with_registry(
            config,
            Arc::new(transport::MockTransport::new()),
            &registry,
        ) {
            Ok(_) => panic!("config identity mismatch must fail closed"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            BedrockAdapterError::ConfigManifestMismatch { .. }
        ));
    }

    #[test]
    fn registry_bound_lift_rejects_unknown_tool_sidecar() {
        let (config, registry, _) = admitted_registry("get_weather");
        let adapter = BedrockAdapter::new_with_registry(
            config,
            Arc::new(transport::MockTransport::new()),
            &registry,
        )
        .unwrap();

        let error = adapter
            .lift_batch(tool_use_payload("send_email"))
            .expect_err("unknown tool must not inherit an admitted sidecar");

        assert!(error.to_string().contains(
            "registry-bound Bedrock lift has no admitted security sidecar for tool `send_email`"
        ));
    }

    #[test]
    fn config_rejects_non_us_east_1() {
        let mut cfg = config();
        cfg.region = "us-west-2".to_string();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(err, BedrockAdapterError::UnsupportedRegion { .. }));
    }

    #[test]
    fn config_rejects_unknown_api_version() {
        let mut cfg = config();
        cfg.api_version = "bedrock.converse.v2".to_string();
        let err = cfg.validate().unwrap_err();
        assert!(matches!(
            err,
            BedrockAdapterError::UnsupportedApiVersion { .. }
        ));
    }

    #[test]
    fn principal_uses_bedrock_iam_shape() {
        let cfg = config().with_assumed_role_session_arn(
            "arn:aws:sts::123456789012:assumed-role/ChioAgentRole/session-1",
        );
        let principal = cfg.principal();
        assert!(matches!(
            principal,
            Principal::BedrockIam {
                caller_arn,
                account_id,
                assumed_role_session_arn: Some(_),
            } if caller_arn == "arn:aws:iam::123456789012:role/ChioAgentRole"
                && account_id == "123456789012"
        ));
    }

    #[test]
    fn config_round_trips_json() {
        let cfg = config();
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let back: BedrockAdapterConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cfg, back);
    }
    #[test]
    fn transport_error_maps_into_fabric_taxonomy() {
        use chio_tool_call_fabric::ProviderError;

        assert!(matches!(
            map_transport_error(transport::TransportError::RateLimited {
                retry_after_ms: 1000
            }),
            ProviderError::RateLimited {
                retry_after_ms: 1000
            }
        ));
        assert!(matches!(
            map_transport_error(transport::TransportError::Timeout { ms: 30000 }),
            ProviderError::TransportTimeout { ms: 30000 }
        ));
        assert!(matches!(
            map_transport_error(transport::TransportError::Upstream {
                status: 500,
                message: "boom".to_string(),
            }),
            ProviderError::Upstream5xx { status: 500, .. }
        ));
        assert!(matches!(
            map_transport_error(transport::TransportError::Rejected("bad".to_string())),
            ProviderError::Malformed(_)
        ));
    }
}
