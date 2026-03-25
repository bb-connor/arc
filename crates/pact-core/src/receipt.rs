//! PACT receipts: signed proof that a tool call was evaluated.
//!
//! Every tool invocation -- whether allowed or denied -- produces a receipt.
//! Receipts are the immutable audit trail of the PACT protocol.

use serde::{Deserialize, Serialize};

use crate::crypto::{canonical_json_bytes, sha256_hex, Keypair, PublicKey, Signature};
use crate::error::Result;
use crate::session::{OperationKind, OperationTerminalState, RequestId, SessionId};

/// A PACT receipt. Signed proof that a tool call was evaluated by the Kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PactReceipt {
    /// Unique receipt ID (UUIDv7 recommended).
    pub id: String,
    /// Unix timestamp (seconds) when the receipt was created.
    pub timestamp: u64,
    /// ID of the capability token that was exercised (or presented).
    pub capability_id: String,
    /// Tool server that handled the invocation.
    pub tool_server: String,
    /// Tool that was invoked (or attempted).
    pub tool_name: String,
    /// The action that was evaluated.
    pub action: ToolCallAction,
    /// The Kernel's decision.
    pub decision: Decision,
    /// SHA-256 hash of the evaluated content for this receipt.
    pub content_hash: String,
    /// SHA-256 hash of the policy that was applied.
    pub policy_hash: String,
    /// Per-guard evidence collected during evaluation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    /// Optional receipt metadata for stream/accounting details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    /// The Kernel's public key (for verification without out-of-band lookup).
    pub kernel_key: PublicKey,
    /// Ed25519 signature over canonical JSON of all fields above.
    pub signature: Signature,
}

/// The body of a receipt (everything except the signature), used for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PactReceiptBody {
    pub id: String,
    pub timestamp: u64,
    pub capability_id: String,
    pub tool_server: String,
    pub tool_name: String,
    pub action: ToolCallAction,
    pub decision: Decision,
    pub content_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<GuardEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
}

/// Signed audit record for a nested child request handled under a parent tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildRequestReceipt {
    pub id: String,
    pub timestamp: u64,
    pub session_id: SessionId,
    pub parent_request_id: RequestId,
    pub request_id: RequestId,
    pub operation_kind: OperationKind,
    pub terminal_state: OperationTerminalState,
    pub outcome_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
    pub signature: Signature,
}

/// The body of a child-request receipt (everything except the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildRequestReceiptBody {
    pub id: String,
    pub timestamp: u64,
    pub session_id: SessionId,
    pub parent_request_id: RequestId,
    pub request_id: RequestId,
    pub operation_kind: OperationKind,
    pub terminal_state: OperationTerminalState,
    pub outcome_hash: String,
    pub policy_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub kernel_key: PublicKey,
}

impl PactReceipt {
    /// Sign a receipt body with the Kernel's keypair.
    pub fn sign(body: PactReceiptBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            capability_id: body.capability_id,
            tool_server: body.tool_server,
            tool_name: body.tool_name,
            action: body.action,
            decision: body.decision,
            content_hash: body.content_hash,
            policy_hash: body.policy_hash,
            evidence: body.evidence,
            metadata: body.metadata,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    /// Extract the body for re-verification.
    #[must_use]
    pub fn body(&self) -> PactReceiptBody {
        PactReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            capability_id: self.capability_id.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            action: self.action.clone(),
            decision: self.decision.clone(),
            content_hash: self.content_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            evidence: self.evidence.clone(),
            metadata: self.metadata.clone(),
            kernel_key: self.kernel_key.clone(),
        }
    }

    /// Verify the receipt signature against the embedded kernel key.
    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.kernel_key.verify_canonical(&body, &self.signature)
    }

    /// Whether this receipt records an allow decision.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self.decision, Decision::Allow)
    }

    /// Whether this receipt records a deny decision.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self.decision, Decision::Deny { .. })
    }

    /// Whether this receipt records a cancelled terminal outcome.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.decision, Decision::Cancelled { .. })
    }

    /// Whether this receipt records an incomplete terminal outcome.
    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        matches!(self.decision, Decision::Incomplete { .. })
    }
}

impl ChildRequestReceipt {
    pub fn sign(body: ChildRequestReceiptBody, keypair: &Keypair) -> Result<Self> {
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            timestamp: body.timestamp,
            session_id: body.session_id,
            parent_request_id: body.parent_request_id,
            request_id: body.request_id,
            operation_kind: body.operation_kind,
            terminal_state: body.terminal_state,
            outcome_hash: body.outcome_hash,
            policy_hash: body.policy_hash,
            metadata: body.metadata,
            kernel_key: body.kernel_key,
            signature,
        })
    }

    #[must_use]
    pub fn body(&self) -> ChildRequestReceiptBody {
        ChildRequestReceiptBody {
            id: self.id.clone(),
            timestamp: self.timestamp,
            session_id: self.session_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            request_id: self.request_id.clone(),
            operation_kind: self.operation_kind,
            terminal_state: self.terminal_state.clone(),
            outcome_hash: self.outcome_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            metadata: self.metadata.clone(),
            kernel_key: self.kernel_key.clone(),
        }
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.kernel_key.verify_canonical(&body, &self.signature)
    }
}

/// The Kernel's verdict on a tool call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Decision {
    /// The tool call was allowed and executed.
    Allow,
    /// The tool call was denied.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
        /// The guard or validation step that triggered the denial.
        guard: String,
    },
    /// The tool call was interrupted by explicit cancellation.
    Cancelled {
        /// Human-readable reason for the cancellation.
        reason: String,
    },
    /// The tool call did not reach a complete terminal result.
    Incomplete {
        /// Human-readable reason for the incomplete terminal state.
        reason: String,
    },
}

/// Describes the tool call that was evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallAction {
    /// The parameters that were passed to the tool (or attempted).
    pub parameters: serde_json::Value,
    /// SHA-256 hash of the canonical JSON of `parameters`.
    pub parameter_hash: String,
}

impl ToolCallAction {
    /// Construct from raw parameters, computing the hash automatically.
    pub fn from_parameters(parameters: serde_json::Value) -> Result<Self> {
        let canonical = canonical_json_bytes(&parameters)?;
        let hash = sha256_hex(&canonical);
        Ok(Self {
            parameters,
            parameter_hash: hash,
        })
    }

    /// Verify that `parameter_hash` matches the canonical hash of `parameters`.
    pub fn verify_hash(&self) -> Result<bool> {
        let canonical = canonical_json_bytes(&self.parameters)?;
        let expected = sha256_hex(&canonical);
        Ok(self.parameter_hash == expected)
    }
}

/// Evidence from a single guard's evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvidence {
    /// Name of the guard (e.g. "ForbiddenPathGuard").
    pub guard_name: String,
    /// Whether the guard passed (true) or denied (false).
    pub verdict: bool,
    /// Optional details about the guard's decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Financial metadata attached to receipts for monetary grant invocations.
///
/// For allow receipts under a monetary grant, this struct is serialized under
/// the "financial" key in `PactReceiptBody::metadata`.
///
/// For denial receipts caused by budget exhaustion, `attempted_cost` is
/// populated with the cost that would have been charged.
///
/// # Field Invariants
///
/// Callers constructing this struct must uphold the following invariants:
///
/// - `cost_charged <= budget_total`: the amount charged for a single invocation
///   must not exceed the total budget allocation.
/// - `budget_remaining == budget_total - cost_charged` (approximately): the
///   remaining budget field should reflect the post-charge balance. Due to HA
///   split-brain scenarios, `budget_remaining` may be a best-effort snapshot
///   rather than a strict invariant at read time, but callers must ensure it is
///   computed correctly at write time.
/// - For denial receipts, `cost_charged` should be 0 and `attempted_cost`
///   should hold the cost that was rejected.
///
/// These invariants are not enforced by the type system and must be upheld by
/// the kernel when constructing financial metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialReceiptMetadata {
    /// Index of the matching grant in the capability token's scope.
    pub grant_index: u32,
    /// Cost charged for this invocation in currency minor units (e.g. cents for USD).
    pub cost_charged: u64,
    /// ISO 4217 currency code (e.g. "USD").
    pub currency: String,
    /// Remaining budget after this charge, in currency minor units.
    pub budget_remaining: u64,
    /// Total budget for this grant, in currency minor units.
    pub budget_total: u64,
    /// Depth of the delegation chain at the time of invocation.
    pub delegation_depth: u32,
    /// Identifier of the root budget holder in the delegation chain.
    pub root_budget_holder: String,
    /// Optional payment reference for external settlement systems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
    /// Settlement status for this charge.
    pub settlement_status: SettlementStatus,
    /// Optional itemized cost breakdown for audit purposes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_breakdown: Option<serde_json::Value>,
    /// Cost that was attempted but denied (populated only on denial receipts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_cost: Option<u64>,
}

/// Canonical settlement states for receipt-side financial metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    /// No external settlement applies to this receipt (for example, a pre-execution denial).
    NotApplicable,
    /// Settlement has been initiated but is not yet final.
    Pending,
    /// The recorded charge is final for the current execution path.
    Settled,
    /// Execution completed, but settlement failed or became invalid.
    Failed,
}

/// Universal receipt-side attribution for capability context.
///
/// This metadata gives downstream analytics a deterministic local join path
/// from a receipt to the capability subject and, when available, the matched
/// grant within the capability scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptAttributionMetadata {
    /// Hex-encoded subject public key of the capability holder.
    pub subject_key: String,
    /// Hex-encoded issuer public key of the capability issuer.
    pub issuer_key: String,
    /// Delegation depth of the capability used for this receipt.
    pub delegation_depth: u32,
    /// Index of the matched grant when the request resolved to a specific grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_index: Option<u32>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn make_action() -> ToolCallAction {
        ToolCallAction::from_parameters(serde_json::json!({
            "path": "/app/src/main.rs"
        }))
        .unwrap()
    }

    fn make_receipt_body(kp: &Keypair) -> PactReceiptBody {
        PactReceiptBody {
            id: "rcpt-001".to_string(),
            timestamp: 1710000000,
            capability_id: "cap-001".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action: make_action(),
            decision: Decision::Allow,
            content_hash: sha256_hex(br#"{"ok":true}"#),
            policy_hash: "abc123def456".to_string(),
            evidence: vec![
                GuardEvidence {
                    guard_name: "ForbiddenPathGuard".to_string(),
                    verdict: true,
                    details: None,
                },
                GuardEvidence {
                    guard_name: "SecretLeakGuard".to_string(),
                    verdict: true,
                    details: Some("no secrets detected".to_string()),
                },
            ],
            metadata: Some(serde_json::json!({
                "sandbox": {
                    "enforced": true
                }
            })),
            kernel_key: kp.public_key(),
        }
    }

    fn make_child_receipt_body(kp: &Keypair) -> ChildRequestReceiptBody {
        ChildRequestReceiptBody {
            id: "child-rcpt-001".to_string(),
            timestamp: 1710000001,
            session_id: SessionId::new("sess-001"),
            parent_request_id: RequestId::new("parent-001"),
            request_id: RequestId::new("child-001"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: sha256_hex(br#"{"message":"sampled"}"#),
            policy_hash: "abc123def456".to_string(),
            metadata: Some(serde_json::json!({
                "outcome": "result"
            })),
            kernel_key: kp.public_key(),
        }
    }

    #[test]
    fn receipt_sign_and_verify() {
        let kp = Keypair::generate();
        let body = make_receipt_body(&kp);
        let receipt = PactReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_allowed());
        assert!(!receipt.is_denied());
    }

    #[test]
    fn receipt_deny_decision() {
        let kp = Keypair::generate();
        let body = PactReceiptBody {
            decision: Decision::Deny {
                reason: "path /etc/passwd is forbidden".to_string(),
                guard: "ForbiddenPathGuard".to_string(),
            },
            ..make_receipt_body(&kp)
        };
        let receipt = PactReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_denied());
        assert!(!receipt.is_allowed());
    }

    #[test]
    fn receipt_cancelled_decision() {
        let kp = Keypair::generate();
        let body = PactReceiptBody {
            decision: Decision::Cancelled {
                reason: "cancelled by user".to_string(),
            },
            ..make_receipt_body(&kp)
        };
        let receipt = PactReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_cancelled());
        assert!(!receipt.is_allowed());
        assert!(!receipt.is_denied());
    }

    #[test]
    fn receipt_incomplete_decision() {
        let kp = Keypair::generate();
        let body = PactReceiptBody {
            decision: Decision::Incomplete {
                reason: "stream terminated before final frame".to_string(),
            },
            ..make_receipt_body(&kp)
        };
        let receipt = PactReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert!(receipt.is_incomplete());
        assert!(!receipt.is_allowed());
        assert!(!receipt.is_denied());
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let kp = Keypair::generate();
        let body = make_receipt_body(&kp);
        let receipt = PactReceipt::sign(body, &kp).unwrap();

        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let restored: PactReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.id, restored.id);
        assert_eq!(receipt.capability_id, restored.capability_id);
        assert_eq!(receipt.tool_name, restored.tool_name);
        assert_eq!(receipt.content_hash, restored.content_hash);
        assert!(restored.verify_signature().unwrap());
    }

    #[test]
    fn receipt_wrong_key_fails() {
        let kp = Keypair::generate();
        let other_kp = Keypair::generate();
        // Body claims kernel_key is other_kp but we sign with kp
        let body = PactReceiptBody {
            kernel_key: other_kp.public_key(),
            ..make_receipt_body(&kp)
        };
        let receipt = PactReceipt::sign(body, &kp).unwrap();
        // Verify against embedded kernel_key (other_kp) should fail
        assert!(!receipt.verify_signature().unwrap());
    }

    #[test]
    fn tool_call_action_hash_verification() {
        let action = make_action();
        assert!(action.verify_hash().unwrap());
    }

    #[test]
    fn tool_call_action_tampered_hash() {
        let mut action = make_action();
        action.parameter_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(!action.verify_hash().unwrap());
    }

    #[test]
    fn decision_serde_roundtrip() {
        let allow = Decision::Allow;
        let json = serde_json::to_string(&allow).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(allow, restored);

        let deny = Decision::Deny {
            reason: "forbidden".to_string(),
            guard: "TestGuard".to_string(),
        };
        let json = serde_json::to_string(&deny).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(deny, restored);

        let cancelled = Decision::Cancelled {
            reason: "cancelled by client".to_string(),
        };
        let json = serde_json::to_string(&cancelled).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(cancelled, restored);

        let incomplete = Decision::Incomplete {
            reason: "stream ended early".to_string(),
        };
        let json = serde_json::to_string(&incomplete).unwrap();
        let restored: Decision = serde_json::from_str(&json).unwrap();
        assert_eq!(incomplete, restored);
    }

    #[test]
    fn guard_evidence_serde_roundtrip() {
        let evidence = vec![
            GuardEvidence {
                guard_name: "Guard1".to_string(),
                verdict: true,
                details: None,
            },
            GuardEvidence {
                guard_name: "Guard2".to_string(),
                verdict: false,
                details: Some("blocked".to_string()),
            },
        ];

        let json = serde_json::to_string_pretty(&evidence).unwrap();
        let restored: Vec<GuardEvidence> = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence.len(), restored.len());
        assert_eq!(evidence[0].guard_name, restored[0].guard_name);
        assert_eq!(evidence[1].details, restored[1].details);
    }

    #[test]
    fn child_receipt_sign_and_verify() {
        let kp = Keypair::generate();
        let body = make_child_receipt_body(&kp);
        let receipt = ChildRequestReceipt::sign(body, &kp).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert_eq!(receipt.operation_kind, OperationKind::CreateMessage);
        assert_eq!(receipt.request_id, RequestId::new("child-001"));
    }

    #[test]
    fn financial_receipt_metadata_serde_roundtrip() {
        let meta = FinancialReceiptMetadata {
            grant_index: 2,
            cost_charged: 150,
            currency: "USD".to_string(),
            budget_remaining: 850,
            budget_total: 1000,
            delegation_depth: 1,
            root_budget_holder: "agent-root-001".to_string(),
            payment_reference: Some("ref-abc123".to_string()),
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: Some(serde_json::json!({"compute": 100, "io": 50})),
            attempted_cost: None,
        };

        let json = serde_json::to_string(&meta).unwrap();
        let restored: FinancialReceiptMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(meta.grant_index, restored.grant_index);
        assert_eq!(meta.cost_charged, restored.cost_charged);
        assert_eq!(meta.currency, restored.currency);
        assert_eq!(meta.budget_remaining, restored.budget_remaining);
        assert_eq!(meta.budget_total, restored.budget_total);
        assert_eq!(meta.delegation_depth, restored.delegation_depth);
        assert_eq!(meta.root_budget_holder, restored.root_budget_holder);
        assert_eq!(meta.settlement_status, restored.settlement_status);
        assert_eq!(meta.payment_reference, restored.payment_reference);
        assert!(restored.attempted_cost.is_none());
    }

    #[test]
    fn financial_receipt_metadata_under_financial_key() {
        let meta = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 200,
            currency: "USD".to_string(),
            budget_remaining: 800,
            budget_total: 1000,
            delegation_depth: 0,
            root_budget_holder: "agent-root-001".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::Settled,
            cost_breakdown: None,
            attempted_cost: None,
        };

        let wrapped = serde_json::json!({"financial": meta});
        let extracted: FinancialReceiptMetadata =
            serde_json::from_value(wrapped["financial"].clone()).unwrap();
        assert_eq!(extracted.cost_charged, 200);
        assert_eq!(extracted.settlement_status, SettlementStatus::Settled);
    }

    #[test]
    fn financial_receipt_metadata_attempted_cost_optional() {
        // With attempted_cost Some: field present in JSON
        let meta_with = FinancialReceiptMetadata {
            grant_index: 0,
            cost_charged: 0,
            currency: "USD".to_string(),
            budget_remaining: 0,
            budget_total: 1000,
            delegation_depth: 0,
            root_budget_holder: "agent-root-001".to_string(),
            payment_reference: None,
            settlement_status: SettlementStatus::NotApplicable,
            cost_breakdown: None,
            attempted_cost: Some(500),
        };
        let json_with = serde_json::to_string(&meta_with).unwrap();
        assert!(json_with.contains("attempted_cost"));

        // Without attempted_cost: field absent from JSON
        let meta_without = FinancialReceiptMetadata {
            attempted_cost: None,
            ..meta_with
        };
        let json_without = serde_json::to_string(&meta_without).unwrap();
        assert!(!json_without.contains("attempted_cost"));
    }

    #[test]
    fn settlement_status_serde_roundtrip() {
        let status = SettlementStatus::Failed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"failed\"");
        let restored: SettlementStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, SettlementStatus::Failed);
    }

    #[test]
    fn receipt_attribution_metadata_serde_roundtrip() {
        let metadata = ReceiptAttributionMetadata {
            subject_key: "subject-key".to_string(),
            issuer_key: "issuer-key".to_string(),
            delegation_depth: 2,
            grant_index: Some(1),
        };

        let json = serde_json::to_string(&metadata).unwrap();
        let restored: ReceiptAttributionMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, metadata);
    }

    #[test]
    fn child_receipt_serde_roundtrip() {
        let kp = Keypair::generate();
        let body = make_child_receipt_body(&kp);
        let receipt = ChildRequestReceipt::sign(body, &kp).unwrap();
        let json = serde_json::to_string_pretty(&receipt).unwrap();
        let restored: ChildRequestReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(receipt.id, restored.id);
        assert_eq!(receipt.parent_request_id, restored.parent_request_id);
        assert_eq!(receipt.outcome_hash, restored.outcome_hash);
        assert!(restored.verify_signature().unwrap());
    }
}
