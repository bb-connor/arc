//! HTTP receipt: signed proof that an HTTP request was evaluated by ARC.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use arc_core_types::crypto::{Keypair, PublicKey, Signature};
use arc_core_types::receipt::GuardEvidence;
use arc_core_types::{canonical_json_bytes, sha256_hex};

use crate::method::HttpMethod;
use crate::verdict::Verdict;

pub const ARC_HTTP_STATUS_SCOPE_KEY: &str = "arc_http_status_scope";
pub const ARC_DECISION_RECEIPT_ID_KEY: &str = "arc_decision_receipt_id";
pub const ARC_KERNEL_RECEIPT_ID_KEY: &str = "arc_kernel_receipt_id";
pub const ARC_HTTP_STATUS_SCOPE_DECISION: &str = "decision";
pub const ARC_HTTP_STATUS_SCOPE_FINAL: &str = "final";

/// Signed receipt for an HTTP request evaluation.
/// Binds the request identity, route, method, verdict, and guard evidence
/// under an Ed25519 signature from the kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpReceipt {
    /// Unique receipt ID (UUIDv7 recommended).
    pub id: String,

    /// Unique request ID this receipt covers.
    pub request_id: String,

    /// The matched route pattern (e.g., "/pets/{petId}").
    pub route_pattern: String,

    /// HTTP method of the evaluated request.
    pub method: HttpMethod,

    /// SHA-256 hash of the caller identity.
    pub caller_identity_hash: String,

    /// Session ID the request belonged to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// The kernel's verdict.
    pub verdict: Verdict,

    /// Per-guard evidence collected during evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,

    /// HTTP status ARC associated with the evaluation outcome at receipt-signing
    /// time.
    ///
    /// For deny receipts this is the concrete error status ARC will emit.
    /// For allow receipts produced before an upstream or inner response exists,
    /// this is evaluation-time status metadata rather than guaranteed
    /// downstream response evidence.
    pub response_status: u16,

    /// Unix timestamp (seconds) when the receipt was created.
    pub timestamp: u64,

    /// SHA-256 hash binding the request content to this receipt.
    pub content_hash: String,

    /// SHA-256 hash of the policy that was applied.
    pub policy_hash: String,

    /// Capability ID that was exercised, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,

    /// Optional metadata for extensibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// The kernel's public key (for verification without out-of-band lookup).
    pub kernel_key: PublicKey,

    /// Ed25519 signature over canonical JSON of the body fields.
    pub signature: Signature,
}

/// The body of an HTTP receipt (everything except the signature).
/// Used for signing and verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpReceiptBody {
    pub id: String,
    pub request_id: String,
    pub route_pattern: String,
    pub method: HttpMethod,
    pub caller_identity_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    pub response_status: u16,
    pub timestamp: u64,
    pub content_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
}

impl HttpReceipt {
    /// Sign a receipt body with the kernel's keypair.
    pub fn sign(body: HttpReceiptBody, keypair: &Keypair) -> arc_core_types::Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            request_id: body.request_id,
            route_pattern: body.route_pattern,
            method: body.method,
            caller_identity_hash: body.caller_identity_hash,
            session_id: body.session_id,
            verdict: body.verdict,
            evidence: body.evidence,
            response_status: body.response_status,
            timestamp: body.timestamp,
            content_hash: body.content_hash,
            policy_hash: body.policy_hash,
            capability_id: body.capability_id,
            metadata: body.metadata,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    /// Extract the body for re-verification.
    #[must_use]
    pub fn body(&self) -> HttpReceiptBody {
        HttpReceiptBody {
            id: self.id.clone(),
            request_id: self.request_id.clone(),
            route_pattern: self.route_pattern.clone(),
            method: self.method,
            caller_identity_hash: self.caller_identity_hash.clone(),
            session_id: self.session_id.clone(),
            verdict: self.verdict.clone(),
            evidence: self.evidence.clone(),
            response_status: self.response_status,
            timestamp: self.timestamp,
            content_hash: self.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            capability_id: self.capability_id.clone(),
            metadata: self.metadata.clone(),
            kernel_key: self.kernel_key.clone(),
        }
    }

    /// Verify the receipt signature against the embedded kernel key.
    pub fn verify_signature(&self) -> arc_core_types::Result<bool> {
        let body = self.body();
        self.kernel_key.verify_canonical(&body, &self.signature)
    }

    /// Whether this receipt records an allow verdict.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        self.verdict.is_allowed()
    }

    /// Whether this receipt records a deny verdict.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        self.verdict.is_denied()
    }

    fn arc_receipt_body(&self) -> arc_core_types::ArcReceiptBody {
        let action = arc_core_types::ToolCallAction {
            parameters: serde_json::json!({
                "method": self.method.to_string(),
                "route": self.route_pattern,
                "request_id": self.request_id,
            }),
            parameter_hash: self.content_hash.clone(),
        };

        arc_core_types::ArcReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            capability_id: self.capability_id.clone().unwrap_or_default(),
            tool_server: "http".to_string(),
            tool_name: format!("{} {}", self.method, self.route_pattern),
            action,
            decision: self.verdict.to_decision(),
            content_hash: self.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            evidence: self.evidence.clone(),
            metadata: self.metadata.clone(),
            kernel_key: self.kernel_key.clone(),
        }
    }

    /// Convert this HTTP receipt into a signed core ArcReceipt for unified storage.
    pub fn to_arc_receipt_with_keypair(
        &self,
        keypair: &Keypair,
    ) -> arc_core_types::Result<arc_core_types::ArcReceipt> {
        let mut arc_body = self.arc_receipt_body();
        let canonical = canonical_json_bytes(&arc_body)?;
        arc_body.content_hash = sha256_hex(&canonical);
        arc_core_types::ArcReceipt::sign(arc_body, keypair)
    }

    /// Convert this HTTP receipt into a core ArcReceipt for unified storage.
    ///
    /// This method fails closed because a valid ArcReceipt signature cannot be
    /// derived from an HttpReceipt without the kernel signing keypair.
    pub fn to_arc_receipt(&self) -> arc_core_types::Result<arc_core_types::ArcReceipt> {
        Err(arc_core_types::Error::CanonicalJson(
            "cannot convert HttpReceipt into signed ArcReceipt without the kernel keypair"
                .to_string(),
        ))
    }
}

#[must_use]
pub fn http_status_metadata_decision() -> Value {
    let mut map = Map::new();
    map.insert(
        ARC_HTTP_STATUS_SCOPE_KEY.to_string(),
        Value::String(ARC_HTTP_STATUS_SCOPE_DECISION.to_string()),
    );
    Value::Object(map)
}

#[must_use]
pub fn http_status_metadata_final(decision_receipt_id: Option<&str>) -> Value {
    let mut map = Map::new();
    map.insert(
        ARC_HTTP_STATUS_SCOPE_KEY.to_string(),
        Value::String(ARC_HTTP_STATUS_SCOPE_FINAL.to_string()),
    );
    if let Some(id) = decision_receipt_id {
        map.insert(
            ARC_DECISION_RECEIPT_ID_KEY.to_string(),
            Value::String(id.to_string()),
        );
    }
    Value::Object(map)
}

#[must_use]
pub fn http_status_scope(metadata: Option<&Value>) -> Option<&str> {
    metadata
        .and_then(Value::as_object)
        .and_then(|object| object.get(ARC_HTTP_STATUS_SCOPE_KEY))
        .and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Verdict;

    fn test_keypair() -> Keypair {
        Keypair::generate()
    }

    fn sample_body(keypair: &Keypair) -> HttpReceiptBody {
        HttpReceiptBody {
            id: "receipt-001".to_string(),
            request_id: "req-001".to_string(),
            route_pattern: "/pets/{petId}".to_string(),
            method: HttpMethod::Get,
            caller_identity_hash: "abc123".to_string(),
            session_id: Some("sess-001".to_string()),
            verdict: Verdict::Allow,
            evidence: vec![],
            response_status: 200,
            timestamp: 1700000000,
            content_hash: "deadbeef".to_string(),
            policy_hash: "cafebabe".to_string(),
            capability_id: None,
            metadata: None,
            kernel_key: keypair.public_key(),
        }
    }

    #[test]
    fn sign_and_verify() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_allowed());
        assert!(!receipt.is_denied());
    }

    #[test]
    fn deny_receipt() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.verdict = Verdict::deny("no capability", "CapabilityGuard");
        body.response_status = 403;
        let receipt = HttpReceipt::sign(body, &kp).unwrap();
        assert!(receipt.is_denied());
        assert!(receipt.verify_signature().unwrap());
    }

    #[test]
    fn body_roundtrip() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body.clone(), &kp).unwrap();
        let extracted = receipt.body();
        assert_eq!(extracted.id, body.id);
        assert_eq!(extracted.route_pattern, body.route_pattern);
    }

    #[test]
    fn serde_roundtrip() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body, &kp).unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let back: HttpReceipt = serde_json::from_str(&json).unwrap();
        assert!(back.verify_signature().unwrap());
    }

    #[test]
    fn to_arc_receipt_conversion() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let receipt = HttpReceipt::sign(body, &kp).unwrap();
        let error = receipt.to_arc_receipt().unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot convert HttpReceipt into signed ArcReceipt"));
    }

    #[test]
    fn receipt_with_evidence_entries() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.evidence = vec![
            GuardEvidence {
                guard_name: "PolicyGuard".to_string(),
                verdict: true,
                details: Some("session-scoped allow".to_string()),
            },
            GuardEvidence {
                guard_name: "RateLimitGuard".to_string(),
                verdict: true,
                details: None,
            },
        ];
        let receipt = HttpReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert_eq!(receipt.evidence.len(), 2);
        assert_eq!(receipt.evidence[0].guard_name, "PolicyGuard");
        assert!(receipt.evidence[0].verdict);
    }

    #[test]
    fn receipt_with_metadata() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.metadata = Some(serde_json::json!({
            "trace_id": "abc123",
            "tags": ["production", "v2"]
        }));
        let receipt = HttpReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        let meta = receipt.metadata.as_ref().unwrap();
        assert_eq!(meta["trace_id"], "abc123");
    }

    #[test]
    fn receipt_with_capability_id() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.capability_id = Some("cap-xyz-789".to_string());
        let receipt = HttpReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert_eq!(receipt.capability_id.as_deref(), Some("cap-xyz-789"));
        let arc_receipt = receipt.to_arc_receipt_with_keypair(&kp).unwrap();
        assert_eq!(arc_receipt.capability_id, "cap-xyz-789");
        assert!(arc_receipt.verify_signature().unwrap());
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let kp = test_keypair();
        let body = sample_body(&kp);
        let mut receipt = HttpReceipt::sign(body, &kp).unwrap();
        // Tamper with the response status
        receipt.response_status = 500;
        assert!(!receipt.verify_signature().unwrap());
    }

    #[test]
    fn receipt_metadata_scope_roundtrip_and_signature_verifies() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.metadata = Some(http_status_metadata_final(Some("decision-001")));

        let receipt = HttpReceipt::sign(body, &kp).unwrap();
        assert_eq!(
            http_status_scope(receipt.metadata.as_ref()),
            Some(ARC_HTTP_STATUS_SCOPE_FINAL)
        );
        assert!(receipt.verify_signature().unwrap());
    }

    #[test]
    fn tampering_with_status_scope_metadata_breaks_signature() {
        let kp = test_keypair();
        let mut body = sample_body(&kp);
        body.metadata = Some(http_status_metadata_decision());

        let mut receipt = HttpReceipt::sign(body, &kp).unwrap();
        receipt.metadata = Some(http_status_metadata_final(Some("decision-001")));

        assert!(!receipt.verify_signature().unwrap());
    }
}
