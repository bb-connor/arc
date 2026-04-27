//! Anthropic Messages transport scaffold.
//!
//! T1 ships the structural foundations only:
//!
//! - The pinned API version constant [`ANTHROPIC_VERSION`].
//! - The beta header constant [`COMPUTER_USE_BETA`] used when the
//!   `computer-use` cargo feature is enabled (T2/T3 actually stamp the
//!   header onto outgoing requests).
//! - The [`Transport`] trait defining the wire-level surface that a real
//!   `reqwest`-backed implementation (landing in T2) and the T1
//!   [`MockTransport`] both satisfy.
//! - A [`MockTransport`] that records calls in memory for tests, keeping
//!   the module mock-friendly until the HTTP client is added.
//!
//! The trait is intentionally minimal in T1. T2 will extend it with batch
//! `messages.create` and T3 will add streaming `messages.stream` once the
//! state machine is wired through the fabric.

use std::sync::Mutex;

use thiserror::Error;

/// Pinned Anthropic Messages API version.
///
/// Stamped on every outgoing request via the `anthropic-version` HTTP
/// header. Bumping this string requires re-recording the conformance
/// fixtures at `crates/chio-provider-conformance/fixtures/anthropic/` and a
/// dedicated PR (see `.planning/trajectory/07-provider-native-adapters.md`,
/// "Pinned upstream API versions" section).
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Beta header value used when the `computer-use` cargo feature is on.
///
/// Sent as `anthropic-beta: computer-use-2025-01-24` in T2/T3. Default
/// builds do not enable the feature; production traffic never carries the
/// beta header unless the operator opts in (see milestone doc lines 50,
/// 399-402, 470).
pub const COMPUTER_USE_BETA: &str = "computer-use-2025-01-24";

/// Default Anthropic Messages endpoint.
///
/// T1 only exposes the constant; T2 wires it into the `reqwest` client.
pub const ANTHROPIC_MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";

/// Wire-level transport errors.
///
/// T1 exposes a small structured surface so the lib-level error type
/// (`crate::AnthropicAdapterError`) can wrap it without depending on a
/// later `reqwest` integration. T2 maps these into the workspace-shared
/// [`chio_tool_call_fabric::ProviderError`] taxonomy.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The mock transport exhausted its scripted responses.
    #[error("mock transport has no scripted response for `{endpoint}`")]
    MockExhausted { endpoint: String },
    /// A structural placeholder reserved for the real `reqwest` transport
    /// that lands in T2. Surfaced here so call sites can pattern-match
    /// exhaustively today without waiting on the HTTP integration.
    #[error("anthropic transport HTTP path is not implemented in T1: {0}")]
    NotImplementedInT1(&'static str),
}

/// Wire-level transport contract.
///
/// Implementors carry the upstream HTTP client (real or mock) and expose
/// just enough surface for the adapter to issue Anthropic Messages calls.
/// T1 keeps the trait deliberately small; T2 extends it with batch
/// `messages.create` and T3 with the streaming `messages.stream` path.
pub trait Transport: Send + Sync {
    /// Pinned `anthropic-version` header value advertised by this transport.
    ///
    /// Defaults to [`ANTHROPIC_VERSION`]; implementors override only when
    /// running a fixture replay that captured a previous pin.
    fn anthropic_version(&self) -> &str {
        ANTHROPIC_VERSION
    }

    /// Beta header value emitted alongside `anthropic-version` when the
    /// `computer-use` cargo feature is active. Implementors that do not
    /// support the beta surface return `None`.
    fn computer_use_beta(&self) -> Option<&str> {
        if cfg!(feature = "computer-use") {
            Some(COMPUTER_USE_BETA)
        } else {
            None
        }
    }

    /// Endpoint URL the transport targets. Defaults to the production
    /// Anthropic Messages URL; overridden by mocks in tests.
    fn endpoint(&self) -> &str {
        ANTHROPIC_MESSAGES_URL
    }
}

/// In-memory transport that records every call placed against it.
///
/// Used by T1 unit tests and by every later phase's mock-driven tests. Real
/// HTTP traffic ships in T2 via a `reqwest`-backed implementor that lives
/// in this module alongside [`MockTransport`].
#[derive(Default)]
pub struct MockTransport {
    /// Captured `(endpoint, raw-body-bytes)` tuples in order of issue.
    calls: Mutex<Vec<(String, Vec<u8>)>>,
}

impl MockTransport {
    /// Construct an empty mock transport.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a placed call. T2 will upgrade this into an actual request
    /// dispatch on the real transport; the mock keeps the API stable.
    pub fn record(&self, endpoint: &str, body: &[u8]) {
        if let Ok(mut guard) = self.calls.lock() {
            guard.push((endpoint.to_string(), body.to_vec()));
        }
    }

    /// Snapshot the recorded calls for assertions.
    pub fn calls(&self) -> Vec<(String, Vec<u8>)> {
        self.calls
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl Transport for MockTransport {
    fn endpoint(&self) -> &str {
        "mock://anthropic"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn pinned_constants_are_correct() {
        assert_eq!(ANTHROPIC_VERSION, "2023-06-01");
        assert_eq!(COMPUTER_USE_BETA, "computer-use-2025-01-24");
        assert_eq!(
            ANTHROPIC_MESSAGES_URL,
            "https://api.anthropic.com/v1/messages"
        );
    }

    #[test]
    fn mock_transport_records_calls() {
        let mock = MockTransport::new();
        mock.record("/v1/messages", b"{\"foo\":1}");
        mock.record("/v1/messages", b"{\"foo\":2}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, "/v1/messages");
        assert_eq!(calls[1].1, b"{\"foo\":2}");
    }

    #[test]
    fn mock_transport_advertises_pin() {
        let mock = MockTransport::new();
        assert_eq!(mock.anthropic_version(), ANTHROPIC_VERSION);
        assert_eq!(mock.endpoint(), "mock://anthropic");
    }

    #[test]
    fn computer_use_header_tracks_feature() {
        let mock = MockTransport::new();
        assert_eq!(
            mock.computer_use_beta().is_some(),
            cfg!(feature = "computer-use")
        );
    }

    #[test]
    fn transport_error_display_is_em_dash_free() {
        let cases = vec![
            TransportError::MockExhausted {
                endpoint: "/v1/messages".to_string(),
            },
            TransportError::NotImplementedInT1("messages.create"),
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }
}
