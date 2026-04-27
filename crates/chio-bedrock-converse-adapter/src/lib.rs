//! # chio-bedrock-converse-adapter
//!
//! Provider-native scaffold for mediating Amazon Bedrock Runtime Converse
//! and ConverseStream tool-use traffic through the Chio kernel.
//!
//! Pinned behavior for M07.P4.T1:
//!
//! - The Bedrock Runtime SDK crate is inherited from one workspace
//!   dependency pin: `aws-sdk-bedrockruntime = "1.130.0"`.
//! - The v1 region is restricted to [`transport::BEDROCK_REGION`], currently
//!   `us-east-1`.
//! - The scaffold exposes native `toolUse` / `toolResult` shapes and a
//!   mock-friendly transport surface for the `Converse` and `ConverseStream`
//!   operations only.
//! - No AWS client is constructed and no network call is made by tests or
//!   normal builds.
//!
//! Later M07.P4 tickets add batch lift/lower, stream buffering, and IAM
//! principal resolution. T1 deliberately ships zero `todo!()`,
//! `unimplemented!()`, or bare `panic!()` calls in trust-boundary paths.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod native;
pub mod transport;

use std::sync::Arc;

use chio_tool_call_fabric::{Principal, ProviderId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use native::{ToolConfig, ToolResultBlock, ToolResultStatus, ToolSpec, ToolUseBlock};
pub use transport::{BedrockOperation, Transport, BEDROCK_CONVERSE_API_VERSION, BEDROCK_REGION};

/// Configuration for the Bedrock Converse adapter.
///
/// This mirrors the provider adapter scaffold used by the other M07
/// adapters while carrying the Bedrock IAM principal fields needed by later
/// provenance work. T1 accepts an already-known principal and does not call
/// STS; M07.P4.T4 replaces that bootstrap path with signed mapping-file
/// resolution.
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
    /// AWS region allowed by this scaffold, always [`BEDROCK_REGION`].
    pub region: String,
    /// IAM caller ARN that will populate Bedrock provenance.
    pub caller_arn: String,
    /// AWS account id corresponding to [`Self::caller_arn`].
    pub account_id: String,
    /// Assumed-role session ARN when the caller is an STS session.
    pub assumed_role_session_arn: Option<String>,
}

impl BedrockAdapterConfig {
    /// Construct a configuration pinned to the v1 Bedrock region and API
    /// surface. The caller principal is passed in explicitly so T1 remains
    /// offline and deterministic.
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
///
/// T1 owns the config and a shared transport handle. Later tickets wire the
/// [`chio_tool_call_fabric::ProviderAdapter`] trait onto this struct for
/// batch and streaming lift/lower behavior.
#[derive(Clone)]
pub struct BedrockAdapter {
    config: BedrockAdapterConfig,
    transport: Arc<dyn Transport>,
}

impl BedrockAdapter {
    /// Build a new adapter from config and transport, rejecting configs that
    /// drift from the v1 `us-east-1` pin.
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
        Ok(Self { config, transport })
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

    /// Name of the SDK client type pulled in by the workspace pin.
    ///
    /// This references the SDK crate without constructing a client, so the
    /// build proves the dependency resolves while remaining offline.
    pub fn sdk_client_type_name() -> &'static str {
        std::any::type_name::<aws_sdk_bedrockruntime::Client>()
    }
}

/// Adapter-local scaffold errors.
#[derive(Debug, Error)]
pub enum BedrockAdapterError {
    /// Returned when a config or transport requests any region other than
    /// the v1 Bedrock region.
    #[error("bedrock converse adapter supports only us-east-1 in v1; requested {requested}")]
    UnsupportedRegion { requested: String },
    /// Returned when a config requests a Converse surface other than the
    /// pinned v1 API marker.
    #[error(
        "bedrock converse adapter supports only bedrock.converse.v1 in v1; requested {requested}"
    )]
    UnsupportedApiVersion { requested: String },
    /// Bubbled up from the transport layer.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    /// Structured placeholder for lift/lower paths that land in later
    /// tickets.
    #[error("bedrock converse adapter call site is not implemented in T1: {0}")]
    NotImplementedInT1(&'static str),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
    fn sdk_pin_is_visible_without_constructing_client() {
        assert!(BedrockAdapter::sdk_client_type_name()
            .contains("aws_sdk_bedrockruntime::client::Client"));
    }

    #[test]
    fn error_display_is_em_dash_free() {
        let cases = vec![
            BedrockAdapterError::UnsupportedRegion {
                requested: "us-west-2".to_string(),
            },
            BedrockAdapterError::UnsupportedApiVersion {
                requested: "bedrock.converse.v2".to_string(),
            },
            BedrockAdapterError::NotImplementedInT1("converse lift"),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }
}
