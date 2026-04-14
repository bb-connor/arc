//! Core proxy logic for validating capability tokens on UI-facing events.

use arc_core::capability::CapabilityToken;
use arc_core::crypto::Keypair;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::event::{AgUiEvent, EventClassification};
use crate::receipt::{AgUiReceipt, AgUiReceiptBody};
use crate::transport::{Transport, TransportKind};

/// Configuration for the AG-UI proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiProxyConfig {
    /// Whether to allow display-only events without a capability token.
    #[serde(default)]
    pub allow_display_without_capability: bool,

    /// Event classifications that require explicit capability grants.
    /// Defaults to all mutating actions.
    #[serde(default = "default_restricted_classifications")]
    pub restricted_classifications: Vec<EventClassification>,

    /// Maximum events per second before throttling.
    #[serde(default = "default_max_events_per_second")]
    pub max_events_per_second: u64,
}

fn default_restricted_classifications() -> Vec<EventClassification> {
    vec![
        EventClassification::Mutate,
        EventClassification::Navigate,
        EventClassification::Create,
        EventClassification::Destroy,
        EventClassification::Submit,
    ]
}

fn default_max_events_per_second() -> u64 {
    1000
}

impl Default for AgUiProxyConfig {
    fn default() -> Self {
        Self {
            allow_display_without_capability: false,
            restricted_classifications: default_restricted_classifications(),
            max_events_per_second: default_max_events_per_second(),
        }
    }
}

/// The proxy's decision for an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyDecision {
    /// Forward the event to the UI.
    Forward,
    /// Block the event with a reason.
    Block { reason: String },
}

/// AG-UI proxy that validates capability tokens for UI-facing events.
pub struct AgUiProxy {
    config: AgUiProxyConfig,
    signing_key: Keypair,
}

impl AgUiProxy {
    /// Create a new AG-UI proxy with the given config and signing key.
    pub fn new(config: AgUiProxyConfig, signing_key: Keypair) -> Self {
        Self {
            config,
            signing_key,
        }
    }

    /// Evaluate an event against the proxy policy and produce a receipt.
    ///
    /// Returns the decision and a signed receipt.
    pub fn evaluate(
        &self,
        event: &AgUiEvent,
        capability: Option<&CapabilityToken>,
        transport: &mut Transport,
    ) -> Result<(ProxyDecision, AgUiReceipt), AgUiProxyError> {
        let decision = self.decide(event, capability);
        let receipt = self.build_receipt(event, capability, transport.kind, &decision)?;

        match &decision {
            ProxyDecision::Forward => {
                debug!(
                    event_id = %event.event_id,
                    event_type = ?event.event_type,
                    "AG-UI proxy forwarding event"
                );
                transport.record_forwarded();
            }
            ProxyDecision::Block { reason } => {
                warn!(
                    event_id = %event.event_id,
                    reason = %reason,
                    "AG-UI proxy blocked event"
                );
                transport.record_blocked();
            }
        }

        Ok((decision, receipt))
    }

    fn decide(
        &self,
        event: &AgUiEvent,
        capability: Option<&CapabilityToken>,
    ) -> ProxyDecision {
        // Check if this classification requires a capability
        let requires_capability = self
            .config
            .restricted_classifications
            .contains(&event.classification);

        if requires_capability {
            match capability {
                None => ProxyDecision::Block {
                    reason: format!(
                        "capability required for {:?} events",
                        event.classification
                    ),
                },
                Some(cap) => {
                    // Validate time bounds
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    if let Err(e) = cap.validate_time(now) {
                        return ProxyDecision::Block {
                            reason: format!("capability time validation failed: {e}"),
                        };
                    }

                    ProxyDecision::Forward
                }
            }
        } else if self.config.allow_display_without_capability || capability.is_some() {
            ProxyDecision::Forward
        } else {
            ProxyDecision::Block {
                reason: "no capability token provided".to_string(),
            }
        }
    }

    fn build_receipt(
        &self,
        event: &AgUiEvent,
        capability: Option<&CapabilityToken>,
        transport_kind: TransportKind,
        decision: &ProxyDecision,
    ) -> Result<AgUiReceipt, AgUiProxyError> {
        let payload_hash = AgUiReceipt::hash_payload(&event.payload)
            .map_err(|e| AgUiProxyError::ReceiptSigning(e.to_string()))?;

        let (allowed, denial_reason) = match decision {
            ProxyDecision::Forward => (true, None),
            ProxyDecision::Block { reason } => (false, Some(reason.clone())),
        };

        let capability_id = capability
            .map(|c| c.id.clone())
            .unwrap_or_else(|| "<none>".to_string());

        let body = AgUiReceiptBody {
            id: format!("agui-{}", event.event_id),
            timestamp: event.timestamp,
            event_id: event.event_id.clone(),
            agent_id: event.agent_id.clone(),
            session_id: event.session_id.clone(),
            capability_id,
            event_type: event.event_type.clone(),
            target: event.target.clone(),
            classification: event.classification.clone(),
            transport: transport_kind,
            allowed,
            denial_reason,
            payload_hash,
            kernel_key: self.signing_key.public_key(),
        };

        AgUiReceipt::sign(body, &self.signing_key)
            .map_err(|e| AgUiProxyError::ReceiptSigning(e.to_string()))
    }

    /// Return a reference to the proxy configuration.
    #[must_use]
    pub fn config(&self) -> &AgUiProxyConfig {
        &self.config
    }
}

/// Errors from the AG-UI proxy.
#[derive(Debug, thiserror::Error)]
pub enum AgUiProxyError {
    #[error("receipt signing failed: {0}")]
    ReceiptSigning(String),

    #[error("invalid event: {0}")]
    InvalidEvent(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{EventType, TargetComponent};

    fn make_event(classification: EventClassification) -> AgUiEvent {
        AgUiEvent {
            event_id: "evt-test".to_string(),
            timestamp: 1700000000,
            agent_id: "agent-1".to_string(),
            session_id: Some("sess-1".to_string()),
            event_type: EventType::TextStream,
            target: Some(TargetComponent {
                component_type: "chat".to_string(),
                component_id: None,
            }),
            classification,
            payload: serde_json::json!({"text": "hi"}),
        }
    }

    fn make_capability() -> CapabilityToken {
        let kp = Keypair::generate();
        CapabilityToken::sign(
            arc_core::capability::CapabilityTokenBody {
                id: "cap-test".to_string(),
                issuer: kp.public_key(),
                subject: Keypair::generate().public_key(),
                scope: arc_core::capability::ArcScope::default(),
                issued_at: 0,
                expires_at: u64::MAX,
                delegation_chain: vec![],
            },
            &kp,
        )
        .unwrap()
    }

    #[test]
    fn display_event_blocked_without_capability_by_default() {
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), Keypair::generate());
        let event = make_event(EventClassification::Display);
        let mut transport =
            Transport::new(TransportKind::Sse, "conn-1".to_string(), "agent-1".to_string());

        let (decision, receipt) = proxy.evaluate(&event, None, &mut transport).unwrap();
        assert!(matches!(decision, ProxyDecision::Block { .. }));
        assert!(!receipt.allowed);
        assert_eq!(transport.events_blocked, 1);
    }

    #[test]
    fn display_event_allowed_when_configured() {
        let config = AgUiProxyConfig {
            allow_display_without_capability: true,
            ..Default::default()
        };
        let proxy = AgUiProxy::new(config, Keypair::generate());
        let event = make_event(EventClassification::Display);
        let mut transport = Transport::new(
            TransportKind::Sse,
            "conn-1".to_string(),
            "agent-1".to_string(),
        );

        let (decision, receipt) = proxy.evaluate(&event, None, &mut transport).unwrap();
        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(transport.events_forwarded, 1);
    }

    #[test]
    fn mutating_event_requires_capability() {
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), Keypair::generate());
        let event = make_event(EventClassification::Mutate);
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-1".to_string(),
            "agent-1".to_string(),
        );

        // Without capability
        let (decision, _) = proxy.evaluate(&event, None, &mut transport).unwrap();
        assert!(matches!(decision, ProxyDecision::Block { .. }));

        // With capability
        let cap = make_capability();
        let (decision, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();
        assert_eq!(decision, ProxyDecision::Forward);
        assert!(receipt.allowed);
        assert_eq!(receipt.capability_id, "cap-test");
    }

    #[test]
    fn receipt_includes_transport_and_event_metadata() {
        let kp = Keypair::generate();
        let proxy = AgUiProxy::new(AgUiProxyConfig::default(), kp);
        let event = make_event(EventClassification::Display);
        let cap = make_capability();
        let mut transport = Transport::new(
            TransportKind::WebSocket,
            "ws-2".to_string(),
            "agent-1".to_string(),
        );

        let (_, receipt) = proxy.evaluate(&event, Some(&cap), &mut transport).unwrap();
        assert_eq!(receipt.transport, TransportKind::WebSocket);
        assert_eq!(receipt.event_type, EventType::TextStream);
        assert!(receipt.target.is_some());
        assert!(receipt.verify().unwrap());
    }
}
