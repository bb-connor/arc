use arc_core::{ArcReceipt, Decision};
use serde::{Deserialize, Serialize};

use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptDecisionKind {
    Allow,
    Deny,
    Cancelled,
    Incomplete,
}

impl From<&Decision> for ReceiptDecisionKind {
    fn from(value: &Decision) -> Self {
        match value {
            Decision::Allow => Self::Allow,
            Decision::Deny { .. } => Self::Deny,
            Decision::Cancelled { .. } => Self::Cancelled,
            Decision::Incomplete { .. } => Self::Incomplete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptVerification {
    pub signature_valid: bool,
    pub parameter_hash_valid: bool,
    pub decision: ReceiptDecisionKind,
}

pub fn parse_receipt_json(input: &str) -> Result<ArcReceipt> {
    Ok(serde_json::from_str(input)?)
}

pub fn receipt_body_canonical_json(receipt: &ArcReceipt) -> Result<String> {
    Ok(arc_core::canonical_json_string(&receipt.body())?)
}

pub fn verify_receipt(receipt: &ArcReceipt) -> Result<ReceiptVerification> {
    Ok(ReceiptVerification {
        signature_valid: receipt.verify_signature()?,
        parameter_hash_valid: receipt.action.verify_hash()?,
        decision: ReceiptDecisionKind::from(&receipt.decision),
    })
}

pub fn verify_receipt_json(input: &str) -> Result<ReceiptVerification> {
    let receipt = parse_receipt_json(input)?;
    verify_receipt(&receipt)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{verify_receipt, ReceiptDecisionKind};
    use arc_core::{
        sha256_hex, ArcReceipt, ArcReceiptBody, Decision, GuardEvidence, Keypair, ToolCallAction,
    };

    fn sample_receipt() -> ArcReceipt {
        let seed = [7u8; 32];
        let keypair = Keypair::from_seed(&seed);
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "path": "/workspace/docs/roadmap.md",
            "mode": "read"
        }))
        .unwrap();
        let body = ArcReceiptBody {
            id: "rcpt-bindings-allow".to_string(),
            timestamp: 1710000100,
            capability_id: "cap-bindings-001".to_string(),
            tool_server: "srv-files".to_string(),
            tool_name: "file_read".to_string(),
            action,
            decision: Decision::Allow,
            content_hash: sha256_hex(br#"{"ok":true}"#),
            policy_hash: "policy-bindings-v1".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: "ForbiddenPathGuard".to_string(),
                verdict: true,
                details: Some("path allowed".to_string()),
            }],
            metadata: Some(serde_json::json!({
                "surface": "bindings-test"
            })),
            trust_level: arc_core::TrustLevel::default(),
            kernel_key: keypair.public_key(),
        };
        ArcReceipt::sign(body, &keypair).unwrap()
    }

    #[test]
    fn verify_valid_receipt() {
        let receipt = sample_receipt();
        let verification = verify_receipt(&receipt).unwrap();
        assert_eq!(
            verification,
            super::ReceiptVerification {
                signature_valid: true,
                parameter_hash_valid: true,
                decision: ReceiptDecisionKind::Allow,
            }
        );
    }
}
