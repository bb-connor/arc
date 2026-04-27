//! # chio-anthropic-tools-adapter
//!
//! Provider-native adapter that mediates Anthropic Messages API tool-use
//! traffic through the Chio kernel.
//!
//! Pinned upstream API version: **`anthropic-version: 2023-06-01`** (see
//! [`transport::ANTHROPIC_VERSION`]).
//!
//! ## M07.P3 sequencing
//!
//! This crate lands in four atomic tickets:
//!
//! - **T1** scaffolds the crate, pins the API version, and
//!   declares the `computer-use` cargo feature. It defines the in-memory
//!   shape of [`native::ToolUseBlock`], [`native::ToolResultBlock`], and the
//!   structural [`transport::Transport`] trait. No HTTP client and no
//!   [`chio_tool_call_fabric::ProviderAdapter`] impl shipped in T1.
//! - **T2** implements the [`chio_tool_call_fabric::ProviderAdapter`] trait
//!   for batch `messages.create`: parse `tool_use` blocks, build
//!   [`chio_tool_call_fabric::ToolInvocation`], lower the kernel verdict
//!   into a `tool_result` block on the next request.
//! - **T3** wires SSE streaming on top of `messages.stream`, evaluating the
//!   verdict at the `content_block_start` event for `tool_use` and
//!   buffering `input_json_delta` events until the verdict resolves.
//! - **T4** adds the `chio-manifest` `server_tools` allowlist that gates the
//!   server-tool variants exposed under the `computer-use` feature.
//!
//! T1 deliberately ships zero `todo!()`, `unimplemented!()`, or bare
//! `panic!()` calls anywhere in the trust-boundary path. Anything that is
//! still placeholder material is either absent (waiting for T2/T3/T4) or
//! returns a structured [`AnthropicAdapterError::NotImplementedInT1`] error.
//!
//! ## House rules
//!
//! - No em dashes (U+2014) anywhere in code, comments, or docs.
//! - Fail-closed: invalid configuration rejects at construction time.
//! - Workspace clippy lints `unwrap_used = "deny"` and `expect_used = "deny"`
//!   apply; no exceptions.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod manifest;
pub mod native;
pub mod transport;

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;

use chio_tool_call_fabric::ProviderId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use manifest::AnthropicServerToolGate;
pub use native::{ToolResultBlock, ToolUseBlock};
pub use transport::{Transport, ANTHROPIC_VERSION, COMPUTER_USE_BETA};

/// Configuration for the Anthropic Messages adapter.
///
/// Mirrors the `<Provider>AdapterConfig` shape used elsewhere in the
/// workspace (see `crates/chio-mcp-adapter/src/lib.rs:50-62` for the
/// reference layout). The `api_version` field is set automatically to
/// [`ANTHROPIC_VERSION`] at construction time but is exposed publicly so
/// downstream telemetry can read it without re-deriving the constant.
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
///
/// Holds the configuration, shared [`Transport`], and the tool-use ids that
/// need to be lowered into the next Anthropic `tool_result` block. The
/// adapter is `Clone` because the streaming work in T3 hands a borrow into a
/// per-stream task.
#[derive(Clone)]
pub struct AnthropicAdapter {
    config: AnthropicAdapterConfig,
    transport: Arc<dyn Transport>,
    pending_tool_use_ids: Arc<Mutex<VecDeque<String>>>,
    server_tool_gate: AnthropicServerToolGate,
}

impl AnthropicAdapter {
    /// Build a new adapter from a config and a transport handle.
    ///
    /// The transport is held behind an [`Arc`] so a single mock or real HTTP
    /// client can back several adapter instances (one per workspace, for
    /// example).
    pub fn new(config: AnthropicAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self {
            config,
            transport,
            pending_tool_use_ids: Arc::new(Mutex::new(VecDeque::new())),
            server_tool_gate: AnthropicServerToolGate::deny_all(),
        }
    }

    /// Build a new adapter whose server-tool gate is sourced from a validated
    /// Chio tool manifest.
    pub fn new_with_manifest(
        config: AnthropicAdapterConfig,
        transport: Arc<dyn Transport>,
        manifest: &chio_manifest::ToolManifest,
    ) -> Result<Self, AnthropicAdapterError> {
        Ok(Self {
            config,
            transport,
            pending_tool_use_ids: Arc::new(Mutex::new(VecDeque::new())),
            server_tool_gate: AnthropicServerToolGate::from_manifest(manifest)?,
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

    /// Borrow the transport handle (T2/T3 will use this to issue requests).
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Borrow the manifest-derived server-tool gate.
    pub fn server_tool_gate(&self) -> &AnthropicServerToolGate {
        &self.server_tool_gate
    }

    /// Whether this build was compiled with the `computer-use` cargo
    /// feature. Surfaced here so callers can refuse to start a session that
    /// requests server tools without the feature flag set, without having
    /// to thread `cfg` macros through their own code.
    pub fn computer_use_enabled() -> bool {
        cfg!(feature = "computer-use")
    }
}

/// Adapter-local error taxonomy.
///
/// Native Anthropic envelope mappings into [`chio_tool_call_fabric::ProviderError`]
/// land in T2/T3 alongside the actual lift/lower implementations; T1 only
/// surfaces the structured stand-in [`AnthropicAdapterError::NotImplementedInT1`]
/// so any premature call site fails closed with a typed error rather than a
/// `todo!()` panic.
#[derive(Debug, Error)]
pub enum AnthropicAdapterError {
    /// Returned by any T1 placeholder method that has not yet been
    /// implemented. T2/T3 replace these call sites with real logic.
    #[error("anthropic adapter call site is not implemented in T1: {0}")]
    NotImplementedInT1(&'static str),
    /// Bubbled up from the transport layer when a wire-level error occurs.
    /// The transport scaffold in T1 emits these structurally; T2 wires them
    /// into [`chio_tool_call_fabric::ProviderError`].
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    /// Raised when the requested feature requires the `computer-use` build
    /// flag but the adapter was compiled without it. Default builds reject
    /// server tools so production never silently exercises beta surfaces.
    #[error("server-tool surface requires the `computer-use` cargo feature")]
    ComputerUseFeatureDisabled,
    /// Raised when the manifest used to build the server-tool gate is invalid.
    #[error(transparent)]
    Manifest(#[from] chio_manifest::ManifestError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
    fn error_display_is_em_dash_free() {
        let cases = vec![
            AnthropicAdapterError::NotImplementedInT1("messages.create lift"),
            AnthropicAdapterError::ComputerUseFeatureDisabled,
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
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
}
