//! Execution-only evidence, without output-release or financial authority.
//!
//! The signed metadata object carries `receipt_semantics: {profile: ...}` and
//! the closed `execution_evidence` block below. Only ordinary receipt context
//! and the receipt signing nonce may accompany those blocks. Identifiers use
//! the durable admission contract (1 through 512 bytes, without NUL); SHA-256
//! commitments and the native `outcome_id` use exactly 64 lowercase hexadecimal
//! characters. This full native profile has no redaction, actor-chain, BBS, or
//! separately copied guard-detail evidence.
//!
//! The validator consumes a typed receipt. Raw artifact consumers must also
//! reject duplicate JSON keys and unknown receipt-envelope fields before
//! deserializing, since a JSON value cannot retain duplicate-key evidence.

use alloc::string::String;
use serde::{Deserialize, Serialize};

use super::body::ChioReceipt;
use super::kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel};
use super::signing::{ChioReceiptSigningBody, CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY};
use crate::crypto::PublicKey;

/// Receipt semantics for native execution before its financial successor.
pub const PRE_SETTLEMENT_EXECUTION_PROFILE: &str = "chio.pre_settlement_execution.v1";
/// Closed execution metadata schema.
pub const EXECUTION_EVIDENCE_SCHEMA: &str = "chio.execution_evidence.v1";
/// Top-level key for the execution metadata.
pub const EXECUTION_EVIDENCE_METADATA_KEY: &str = "execution_evidence";

/// Original durable execution identities and canonical source commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ExecutionEvidenceMetadata {
    pub schema: String,
    pub phase: String,
    pub authority_uuid: String,
    pub operation_id: String,
    pub request_id: String,
    pub request_binding_hash: String,
    pub request_sha256: String,
    pub hold_id: String,
    pub authorization_id: String,
    pub outcome_id: String,
    pub raw_outcome_sha256: String,
    pub resolved_output_sha256: String,
    pub post_return_evaluation_sha256: String,
    pub post_guard_decision_sha256: String,
    pub pricing_verdict_sha256: String,
}

/// Fail-closed execution receipt rejection reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionEvidenceError {
    ReceiptSignatureInvalid,
    SignerNotAdmitted,
    InvalidReceiptSemantics,
    InvalidMetadata,
    WrongProfile,
    WrongSchema,
    WrongPhase,
    InvalidField { field: &'static str },
    FinancialAuthorityPresent,
    ContentHashMismatch,
}

impl core::fmt::Display for ExecutionEvidenceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "execution evidence rejected: {self:?}")
    }
}

impl core::error::Error for ExecutionEvidenceError {}

impl ExecutionEvidenceMetadata {
    /// Validate the closed version, execution phase and original commitments.
    pub fn validate(&self) -> Result<(), ExecutionEvidenceError> {
        if self.schema != EXECUTION_EVIDENCE_SCHEMA {
            return Err(ExecutionEvidenceError::WrongSchema);
        }
        if self.phase != "execution_confirmed" {
            return Err(ExecutionEvidenceError::WrongPhase);
        }
        for (field, value) in [
            ("authority_uuid", &self.authority_uuid),
            ("operation_id", &self.operation_id),
            ("request_id", &self.request_id),
            ("hold_id", &self.hold_id),
            ("authorization_id", &self.authorization_id),
        ] {
            validate_identifier(value, field)?;
        }
        for (field, value) in [
            ("outcome_id", &self.outcome_id),
            ("request_binding_hash", &self.request_binding_hash),
            ("request_sha256", &self.request_sha256),
            ("raw_outcome_sha256", &self.raw_outcome_sha256),
            ("resolved_output_sha256", &self.resolved_output_sha256),
            (
                "post_return_evaluation_sha256",
                &self.post_return_evaluation_sha256,
            ),
            (
                "post_guard_decision_sha256",
                &self.post_guard_decision_sha256,
            ),
            ("pricing_verdict_sha256", &self.pricing_verdict_sha256),
        ] {
            super::validation::require_lowercase_hex_chars(value, 64, field)
                .map_err(|_| ExecutionEvidenceError::InvalidField { field })?;
        }
        Ok(())
    }
}

fn validate_identifier(value: &str, field: &'static str) -> Result<(), ExecutionEvidenceError> {
    if value.is_empty() || value.len() > 512 || value.bytes().any(|byte| byte == 0) {
        return Err(ExecutionEvidenceError::InvalidField { field });
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionReceiptSemantics {
    profile: String,
}

/// Verify signed, admitted native execution evidence and its closed metadata.
///
/// This proves the admitted kernel's execution statement. It does not prove
/// source-store availability, output release, budget exposure or settlement.
pub fn verify_pre_settlement_execution_receipt(
    receipt: &ChioReceipt,
    admitted_kernel_keys: &[PublicKey],
) -> Result<ExecutionEvidenceMetadata, ExecutionEvidenceError> {
    let body = receipt.body();
    let signing_body =
        ChioReceiptSigningBody::from_body_and_bbs(&body, receipt.bbs_signature.as_ref());
    if !matches!(receipt.verify_signature(), Ok(true))
        || !matches!(
            receipt
                .kernel_key
                .verify_canonical_strict(&signing_body, &receipt.signature),
            Ok(true)
        )
    {
        return Err(ExecutionEvidenceError::ReceiptSignatureInvalid);
    }
    if !admitted_kernel_keys.contains(&receipt.kernel_key) {
        return Err(ExecutionEvidenceError::SignerNotAdmitted);
    }
    if receipt.receipt_kind != ReceiptKind::MediatedDecision
        || receipt.boundary_class != BoundaryClass::Prevent
        || receipt.trust_level != TrustLevel::Mediated
        || receipt.tool_origin != ToolOrigin::ChioInternal
        || receipt.observation_outcome.is_some()
        || receipt.redaction_mode != RedactionMode::None
        || !receipt.actor_chain.is_empty()
        || !receipt.evidence.is_empty()
        || receipt.bbs_projection_version.is_some()
        || receipt.bbs_signature.is_some()
        || !receipt.is_allowed()
    {
        return Err(ExecutionEvidenceError::InvalidReceiptSemantics);
    }
    let metadata = receipt
        .metadata
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .ok_or(ExecutionEvidenceError::InvalidMetadata)?;
    if [
        "financial",
        "budget_authority",
        "execution_nonce",
        "mediated_spend",
        "spend_authority",
    ]
    .iter()
    .any(|key| metadata.contains_key(*key))
    {
        return Err(ExecutionEvidenceError::FinancialAuthorityPresent);
    }
    if metadata.keys().any(|key| {
        !matches!(
            key.as_str(),
            EXECUTION_EVIDENCE_METADATA_KEY
                | "receipt_semantics"
                | "receipt_context"
                | CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY
        )
    }) {
        return Err(ExecutionEvidenceError::InvalidMetadata);
    }
    let semantics: ExecutionReceiptSemantics = serde_json::from_value(
        metadata
            .get("receipt_semantics")
            .ok_or(ExecutionEvidenceError::WrongProfile)?
            .clone(),
    )
    .map_err(|_| ExecutionEvidenceError::WrongProfile)?;
    if semantics.profile != PRE_SETTLEMENT_EXECUTION_PROFILE {
        return Err(ExecutionEvidenceError::WrongProfile);
    }
    let execution: ExecutionEvidenceMetadata = serde_json::from_value(
        metadata
            .get(EXECUTION_EVIDENCE_METADATA_KEY)
            .ok_or(ExecutionEvidenceError::InvalidMetadata)?
            .clone(),
    )
    .map_err(|_| ExecutionEvidenceError::InvalidMetadata)?;
    execution.validate()?;
    if let Some(nonce) = metadata.get(CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY) {
        validate_identifier(
            nonce
                .as_str()
                .ok_or(ExecutionEvidenceError::InvalidMetadata)?,
            CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
        )?;
    }
    if let Some(context) = metadata.get("receipt_context") {
        let context = context
            .as_object()
            .ok_or(ExecutionEvidenceError::InvalidMetadata)?;
        if let Some(request_id) = context.get("request_id") {
            if request_id.as_str() != Some(execution.request_id.as_str()) {
                return Err(ExecutionEvidenceError::InvalidField {
                    field: "receipt_context.request_id",
                });
            }
        }
    }
    if execution.resolved_output_sha256 != receipt.content_hash {
        return Err(ExecutionEvidenceError::ContentHashMismatch);
    }
    if !matches!(receipt.action.verify_hash(), Ok(true)) {
        return Err(ExecutionEvidenceError::InvalidField {
            field: "action.parameter_hash",
        });
    }
    Ok(execution)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;
    use crate::receipt::body::ChioReceiptBody;
    use crate::receipt::decision::{Decision, ToolCallAction};
    use crate::receipt::kinds::{
        BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
    };
    use alloc::{string::ToString, vec::Vec};
    use serde_json::{json, Value};

    fn body(key: &Keypair) -> ChioReceiptBody {
        let hash = crate::sha256_hex(b"resolved output");
        ChioReceiptBody {
            id: "execution-test".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "native".to_string(),
            tool_name: "test".to_string(),
            action: ToolCallAction::from_parameters(json!({"input":1})).unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::ChioInternal,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: hash.clone(),
            policy_hash: crate::sha256_hex(b"policy"),
            evidence: Vec::new(),
            metadata: Some(json!({
                "receipt_semantics": {"profile": PRE_SETTLEMENT_EXECUTION_PROFILE},
                "execution_evidence": {
                    "schema": EXECUTION_EVIDENCE_SCHEMA,
                    "phase": "execution_confirmed",
                    "authority_uuid": "authority-1",
                    "operation_id": "operation-1",
                    "request_id": "request-1",
                    "request_binding_hash": "01".repeat(32),
                    "request_sha256": "02".repeat(32),
                    "hold_id": "hold-1",
                    "authorization_id": "authorization-1",
                    "outcome_id": "07".repeat(32),
                    "raw_outcome_sha256": "03".repeat(32),
                    "resolved_output_sha256": hash,
                    "post_return_evaluation_sha256": "04".repeat(32),
                    "post_guard_decision_sha256": "05".repeat(32),
                    "pricing_verdict_sha256": "06".repeat(32)
                }
            })),
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: key.public_key(),
            bbs_projection_version: None,
        }
    }

    fn verify_body(
        body: ChioReceiptBody,
        key: &Keypair,
    ) -> Result<ExecutionEvidenceMetadata, ExecutionEvidenceError> {
        let receipt = ChioReceipt::sign(body, key).unwrap();
        verify_pre_settlement_execution_receipt(&receipt, &[key.public_key()])
    }

    #[test]
    fn execution_evidence_accepts_signed_original_sources_without_financial_authority() {
        let key = Keypair::generate();
        let metadata = verify_body(body(&key), &key).unwrap();
        assert_eq!(metadata.operation_id, "operation-1");
        assert_eq!(metadata.hold_id, "hold-1");
        assert_eq!(
            metadata.resolved_output_sha256,
            crate::sha256_hex(b"resolved output")
        );
    }

    #[test]
    fn execution_evidence_rejects_signed_financial_authority_injection() {
        let key = Keypair::generate();
        for name in [
            "financial",
            "budget_authority",
            "execution_nonce",
            "mediated_spend",
            "spend_authority",
        ] {
            for value in [Value::Null, json!({"profile":"chio.mediated_spend.v1"})] {
                let mut candidate = body(&key);
                candidate.metadata.as_mut().unwrap()[name] = value;
                assert_eq!(
                    verify_body(candidate, &key),
                    Err(ExecutionEvidenceError::FinancialAuthorityPresent),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn execution_evidence_rejects_wrong_schema_phase_profile_and_unknown_fields() {
        let key = Keypair::generate();
        for (field, value, error) in [
            (
                "schema",
                json!("chio.execution_evidence.v2"),
                ExecutionEvidenceError::WrongSchema,
            ),
            (
                "phase",
                json!("settled"),
                ExecutionEvidenceError::WrongPhase,
            ),
            (
                "unknown",
                json!("extra"),
                ExecutionEvidenceError::InvalidMetadata,
            ),
            (
                "request_id",
                Value::Null,
                ExecutionEvidenceError::InvalidMetadata,
            ),
        ] {
            let mut candidate = body(&key);
            candidate.metadata.as_mut().unwrap()["execution_evidence"][field] = value;
            assert_eq!(verify_body(candidate, &key), Err(error));
        }
        let mut candidate = body(&key);
        candidate.metadata.as_mut().unwrap()["receipt_semantics"]["profile"] =
            json!("chio.mediated_spend.v1");
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::WrongProfile)
        );
        let mut candidate = body(&key);
        candidate.metadata.as_mut().unwrap()["receipt_semantics"]["extra"] = json!(true);
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::WrongProfile)
        );
    }

    #[test]
    fn execution_evidence_rejects_malformed_identifiers_and_commitments() {
        let key = Keypair::generate();
        for field in [
            "authority_uuid",
            "operation_id",
            "request_id",
            "hold_id",
            "authorization_id",
            "outcome_id",
        ] {
            for value in [
                String::new(),
                "bad\0identifier".to_string(),
                "x".repeat(513),
            ] {
                let mut candidate = body(&key);
                candidate.metadata.as_mut().unwrap()["execution_evidence"][field] = json!(value);
                assert_eq!(
                    verify_body(candidate, &key),
                    Err(ExecutionEvidenceError::InvalidField { field })
                );
            }
        }
        for field in [
            "outcome_id",
            "request_binding_hash",
            "request_sha256",
            "raw_outcome_sha256",
            "resolved_output_sha256",
            "post_return_evaluation_sha256",
            "post_guard_decision_sha256",
            "pricing_verdict_sha256",
        ] {
            for value in ["aa".repeat(31), "AA".repeat(32), "zz".repeat(32)] {
                let mut candidate = body(&key);
                candidate.metadata.as_mut().unwrap()["execution_evidence"][field] = json!(value);
                assert_eq!(
                    verify_body(candidate, &key),
                    Err(ExecutionEvidenceError::InvalidField { field })
                );
            }
        }
    }

    #[test]
    fn execution_evidence_rejects_missing_blocks_and_unknown_metadata_wrappers() {
        let key = Keypair::generate();
        for field in ["execution_evidence", "receipt_semantics"] {
            let mut candidate = body(&key);
            candidate
                .metadata
                .as_mut()
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(verify_body(candidate, &key).is_err());
        }
        let mut candidate = body(&key);
        candidate.metadata.as_mut().unwrap()["unknown"] = json!({});
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidMetadata)
        );
    }

    #[test]
    fn execution_evidence_rejects_signed_parameter_hash_substitution() {
        let key = Keypair::generate();
        let mut candidate = body(&key);
        candidate.action.parameter_hash = crate::sha256_hex(b"different input");
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidField {
                field: "action.parameter_hash"
            })
        );
    }

    #[test]
    fn execution_evidence_allows_receipt_context_without_changing_profile() {
        let key = Keypair::generate();
        let mut candidate = body(&key);
        candidate.metadata.as_mut().unwrap()["receipt_context"] = json!({"caller_run_id":"run-1"});
        assert!(verify_body(candidate, &key).is_ok());
    }

    #[test]
    fn execution_evidence_rejects_conflicting_receipt_context_request_id() {
        let key = Keypair::generate();
        let mut candidate = body(&key);
        candidate.metadata.as_mut().unwrap()["receipt_context"] =
            json!({"request_id":"different-request"});
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidField {
                field: "receipt_context.request_id"
            })
        );
    }

    #[test]
    fn execution_evidence_metadata_deserialization_rejects_duplicate_keys() {
        let key = Keypair::generate();
        let candidate = body(&key);
        let raw =
            serde_json::to_string(&candidate.metadata.unwrap()["execution_evidence"]).unwrap();
        let duplicated = raw.replacen('{', "{\"phase\":\"execution_confirmed\",", 1);
        assert!(serde_json::from_str::<ExecutionEvidenceMetadata>(&duplicated).is_err());
    }

    #[test]
    fn execution_evidence_rejects_signed_output_substitution() {
        let key = Keypair::generate();
        let mut candidate = body(&key);
        candidate.content_hash = crate::sha256_hex(b"different output");
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::ContentHashMismatch)
        );
    }

    #[test]
    fn execution_evidence_rejects_unadmitted_and_altered_signatures() {
        let key = Keypair::generate();
        let mut receipt = ChioReceipt::sign(body(&key), &key).unwrap();
        assert_eq!(
            verify_pre_settlement_execution_receipt(&receipt, &[]),
            Err(ExecutionEvidenceError::SignerNotAdmitted)
        );
        receipt.tool_name = "changed".to_string();
        assert_eq!(
            verify_pre_settlement_execution_receipt(&receipt, &[key.public_key()]),
            Err(ExecutionEvidenceError::ReceiptSignatureInvalid)
        );
    }

    #[test]
    fn execution_evidence_rejects_admitted_weak_key_forgery() {
        let key = Keypair::generate();
        let mut receipt = ChioReceipt::sign(body(&key), &key).unwrap();
        let weak =
            PublicKey::from_hex("0100000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        receipt.kernel_key = weak.clone();
        receipt.id = crate::receipt::body::chio_receipt_id(&receipt.body()).unwrap();
        receipt.signature = crate::crypto::Signature::from_hex(
            "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        ).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert_eq!(
            verify_pre_settlement_execution_receipt(&receipt, &[weak]),
            Err(ExecutionEvidenceError::ReceiptSignatureInvalid)
        );
    }

    #[test]
    fn execution_evidence_rejects_signed_disclosure_and_actor_provenance() {
        let key = Keypair::generate();
        let mut candidate = body(&key);
        candidate.redaction_mode = RedactionMode::Redacted;
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidReceiptSemantics)
        );
        let mut candidate = body(&key);
        candidate
            .actor_chain
            .push(crate::receipt::metadata::ActorRef {
                actor_id: "other".to_string(),
                actor_kind: None,
            });
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidReceiptSemantics)
        );
        let mut candidate = body(&key);
        candidate.metadata.as_mut().unwrap()["execution_evidence"]["outcome_id"] =
            json!("not-a-digest");
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidField {
                field: "outcome_id"
            })
        );
    }

    #[test]
    fn execution_evidence_rejects_added_guard_detail_claims() {
        let key = Keypair::generate();
        let mut candidate = body(&key);
        candidate
            .evidence
            .push(crate::receipt::metadata::GuardEvidence {
                guard_name: "invented".to_string(),
                verdict: true,
                details: None,
            });
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidReceiptSemantics)
        );
    }

    #[test]
    fn execution_evidence_rejects_signed_bbs_projection() {
        use crate::receipt::signing::*;
        let key = Keypair::generate();
        let mut candidate = body(&key);
        candidate.bbs_projection_version = Some(CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string());
        let bbs = BbsReceiptSignature {
            schema: CHIO_RECEIPT_BBS_SIGNATURE_SCHEMA.to_string(),
            projection_version: CHIO_RECEIPT_BBS_PROJECTION_VERSION_V1.to_string(),
            algorithm: CHIO_RECEIPT_BBS_SIGNATURE_ALGORITHM.to_string(),
            ciphersuite: CHIO_RECEIPT_BBS_CIPHERSUITE_V1.to_string(),
            issuer_fingerprint: "issuer:chio:test-bbs".to_string(),
            issuer_public_key_hex: "11".repeat(96),
            message_count: CHIO_RECEIPT_BBS_MESSAGE_COUNT_V1,
            signature_hex: "22".repeat(80),
        };
        let receipt = ChioReceipt::sign_with_bbs(candidate, &key, bbs).unwrap();
        assert!(receipt.verify_signature().unwrap());
        assert_eq!(
            verify_pre_settlement_execution_receipt(&receipt, &[key.public_key()]),
            Err(ExecutionEvidenceError::InvalidReceiptSemantics)
        );
    }

    #[test]
    fn execution_evidence_rejects_signed_caller_and_advisory_receipts() {
        let key = Keypair::generate();
        let mut candidate = body(&key);
        candidate.decision = Some(Decision::Deny {
            reason: "output guard denied".to_string(),
            guard: "post-return".to_string(),
        });
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidReceiptSemantics)
        );
        let mut candidate = body(&key);
        candidate.tool_origin = ToolOrigin::CallerExecuted;
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidReceiptSemantics)
        );
        let mut candidate = body(&key);
        candidate.receipt_kind = ReceiptKind::AdvisoryEvaluation;
        candidate.trust_level = TrustLevel::Advisory;
        candidate.boundary_class = BoundaryClass::AdvisoryOnly;
        candidate.decision = None;
        candidate.observation_outcome = Some(crate::receipt::kinds::ObservationOutcome::Evaluated);
        assert_eq!(
            verify_body(candidate, &key),
            Err(ExecutionEvidenceError::InvalidReceiptSemantics)
        );
    }
}
