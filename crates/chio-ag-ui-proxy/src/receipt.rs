//! UI-facing receipts for AG-UI proxy events.
//!
//! Each event that passes through the proxy produces a receipt that records
//! the event type, target component, action classification, and the proxy's
//! decision. These receipts extend the standard Chio receipt model with
//! UI-specific metadata.

use chio_core::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::event::{EventClassification, EventType, TargetComponent};
use crate::transport::TransportKind;

/// Schema identifier for AG-UI receipts.
pub const AG_UI_RECEIPT_SCHEMA: &str = "chio.ag-ui-receipt.v1";

/// A receipt for an agent-to-UI event processed by the proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiReceipt {
    /// Unique receipt ID.
    pub id: String,
    /// Unix timestamp (seconds) when the receipt was created.
    pub timestamp: u64,
    /// The event ID that was evaluated.
    pub event_id: String,
    /// Agent that produced the event.
    pub agent_id: String,
    /// Session, if bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Capability ID used for authorization.
    pub capability_id: String,
    /// Type of event.
    pub event_type: EventType,
    /// Target component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetComponent>,
    /// Action classification.
    pub classification: EventClassification,
    /// Transport used.
    pub transport: TransportKind,
    /// Whether the event was allowed or denied.
    pub allowed: bool,
    /// Denial reason, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    /// SHA-256 hash of the event payload.
    pub payload_hash: String,
    /// Kernel public key for verification.
    pub kernel_key: PublicKey,
    /// Signature over the receipt body.
    pub signature: Signature,
}

/// The body of an AG-UI receipt (everything except the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgUiReceiptBody {
    pub id: String,
    pub timestamp: u64,
    pub event_id: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub capability_id: String,
    pub event_type: EventType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetComponent>,
    pub classification: EventClassification,
    pub transport: TransportKind,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
    pub payload_hash: String,
    pub kernel_key: PublicKey,
}

impl AgUiReceipt {
    /// Sign a receipt body with the given keypair.
    pub fn sign(body: AgUiReceiptBody, keypair: &Keypair) -> Result<Self, chio_core::Error> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            event_id: body.event_id,
            agent_id: body.agent_id,
            session_id: body.session_id,
            capability_id: body.capability_id,
            event_type: body.event_type,
            target: body.target,
            classification: body.classification,
            transport: body.transport,
            allowed: body.allowed,
            denial_reason: body.denial_reason,
            payload_hash: body.payload_hash,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    /// Verify the receipt signature.
    pub fn verify(&self) -> Result<bool, chio_core::Error> {
        let body = AgUiReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            event_id: self.event_id.clone(),
            agent_id: self.agent_id.clone(),
            session_id: self.session_id.clone(),
            capability_id: self.capability_id.clone(),
            event_type: self.event_type.clone(),
            target: self.target.clone(),
            classification: self.classification.clone(),
            transport: self.transport,
            allowed: self.allowed,
            denial_reason: self.denial_reason.clone(),
            payload_hash: self.payload_hash.clone(),
            kernel_key: self.kernel_key.clone(),
        };
        self.kernel_key.verify_canonical(&body, &self.signature)
    }

    /// Compute the payload hash for an event payload.
    pub fn hash_payload(payload: &serde_json::Value) -> Result<String, chio_core::Error> {
        let bytes = canonical_json_bytes(payload)?;
        Ok(sha256_hex(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_receipt() {
        let kp = Keypair::generate();
        let body = AgUiReceiptBody {
            id: "rcpt-1".to_string(),
            timestamp: 1700000000,
            event_id: "evt-1".to_string(),
            agent_id: "agent-1".to_string(),
            session_id: Some("sess-1".to_string()),
            capability_id: "cap-1".to_string(),
            event_type: EventType::TextStream,
            target: Some(TargetComponent {
                component_type: "chat".to_string(),
                component_id: None,
            }),
            classification: EventClassification::Display,
            transport: TransportKind::Sse,
            allowed: true,
            denial_reason: None,
            payload_hash: "abc123".to_string(),
            kernel_key: kp.public_key(),
        };

        let receipt = AgUiReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify().unwrap());
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let kp = Keypair::generate();
        let body = AgUiReceiptBody {
            id: "rcpt-2".to_string(),
            timestamp: 1700000000,
            event_id: "evt-2".to_string(),
            agent_id: "agent-1".to_string(),
            session_id: None,
            capability_id: "cap-2".to_string(),
            event_type: EventType::Navigation,
            target: None,
            classification: EventClassification::Navigate,
            transport: TransportKind::WebSocket,
            allowed: false,
            denial_reason: Some("blocked".to_string()),
            payload_hash: "def456".to_string(),
            kernel_key: kp.public_key(),
        };

        let mut receipt = AgUiReceipt::sign(body, &kp).unwrap();
        receipt.allowed = true; // tamper
        assert!(!receipt.verify().unwrap());
    }

    #[test]
    fn hash_payload() {
        let payload = serde_json::json!({"text": "hello"});
        let hash = AgUiReceipt::hash_payload(&payload).unwrap();
        assert!(!hash.is_empty());

        // Same payload, same hash
        let hash2 = AgUiReceipt::hash_payload(&payload).unwrap();
        assert_eq!(hash, hash2);
    }
}
