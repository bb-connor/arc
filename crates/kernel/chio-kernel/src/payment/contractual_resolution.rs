//! Contractually authorized capture waiver, separate from execution and budget.
use super::{PaymentJournalRecord, PaymentJournalState, PaymentRailMode, PaymentSettleAction};
use crate::admission_operation::{AdmissionOperationState, AdmissionOperationV1};
use chio_core::{
    canonical_json_bytes,
    crypto::{Keypair, PublicKey, Signature},
    sha256_hex,
};
use serde::{Deserialize, Serialize};

pub const CONTRACTUAL_CAPTURE_WAIVER_SCHEMA: &str = "chio.contractual-capture-waiver.v1";
pub const CAPTURE_WAIVER_TERMS_ARGUMENT: &str = "chio_capture_waiver_terms_digest";
pub(super) const MAX: u64 = (1u64 << 53) - 1;
#[derive(Debug, Clone, thiserror::Error)]
#[error("capture waiver rejected: {0}")]
pub struct CaptureWaiverError(pub String);
pub(super) fn fail(message: impl std::fmt::Display) -> CaptureWaiverError {
    CaptureWaiverError(message.to_string())
}
pub fn capture_waiver_digest<T: Serialize>(value: &T) -> Result<String, CaptureWaiverError> {
    Ok(sha256_hex(&canonical_json_bytes(value).map_err(fail)?))
}
fn preimage<T: Serialize>(value: &T, role: &str) -> Result<Vec<u8>, CaptureWaiverError> {
    let bytes = canonical_json_bytes(value).map_err(fail)?;
    if bytes.len() > 256 * 1024 {
        return Err(fail("signed evidence exceeds bound"));
    }
    let mut result = format!("{CONTRACTUAL_CAPTURE_WAIVER_SCHEMA}\0{role}\0").into_bytes();
    result.extend(bytes);
    Ok(result)
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractualCaptureWaiverPolicyV1 {
    pub receiver_key: PublicKey,
    pub counterparty_key: PublicKey,
    pub observation_key: PublicKey,
    pub rail: String,
    pub currency: String,
}
impl ContractualCaptureWaiverPolicyV1 {
    pub fn validate(&self) -> Result<(), CaptureWaiverError> {
        if self.receiver_key == self.counterparty_key
            || self.rail == "unspecified"
            || !super::payment_identifier_is_valid(&self.rail)
            || self.currency.len() != 3
            || !self.currency.bytes().all(|b| b.is_ascii_uppercase())
        {
            return Err(fail("invalid receiver-pinned policy"));
        }
        Ok(())
    }
}
/// Signed before admission. The context digest excludes derived agreement and allocation identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractualCaptureWaiverTermsV1 {
    pub schema: String,
    pub policy_digest: String,
    pub contract_context_digest: String,
    pub capability_digest: String,
    pub request_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedContractualCaptureWaiverTermsV1 {
    pub body: ContractualCaptureWaiverTermsV1,
    pub receiver_signature: Signature,
    pub counterparty_signature: Signature,
}
impl SignedContractualCaptureWaiverTermsV1 {
    pub fn verify(
        &self,
        policy: &ContractualCaptureWaiverPolicyV1,
    ) -> Result<(), CaptureWaiverError> {
        policy.validate()?;
        let t = &self.body;
        if t.schema != CONTRACTUAL_CAPTURE_WAIVER_SCHEMA
            || t.policy_digest != capture_waiver_digest(policy)?
            || !digest_valid(&t.contract_context_digest)
            || !digest_valid(&t.capability_digest)
            || !super::payment_identifier_is_valid(&t.request_id)
            || t.issued_at_unix_ms == 0
            || t.expires_at_unix_ms <= t.issued_at_unix_ms
            || t.expires_at_unix_ms > MAX
            || t.expires_at_unix_ms - t.issued_at_unix_ms > 86_400_000
            || !policy
                .receiver_key
                .verify(&preimage(t, "receiver")?, &self.receiver_signature)
            || !policy
                .counterparty_key
                .verify(&preimage(t, "counterparty")?, &self.counterparty_signature)
        {
            return Err(fail("invalid original signed waiver terms"));
        }
        Ok(())
    }
    pub fn sign(
        body: ContractualCaptureWaiverTermsV1,
        receiver: &Keypair,
        counterparty: &Keypair,
    ) -> Result<Self, CaptureWaiverError> {
        Ok(Self {
            receiver_signature: receiver.sign(&preimage(&body, "receiver")?),
            counterparty_signature: counterparty.sign(&preimage(&body, "counterparty")?),
            body,
        })
    }
}
/// The configured receiver-owned observer must verify external refund finality,
/// exact funding agreement, allocation and context before signing. RPC JSON alone
/// is never authority. Native sources are independently checked by the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureWaiverObservationV1 {
    pub terms_digest: String,
    pub operation_id: String,
    pub journal_digest: String,
    pub raw_output_digest: String,
    pub contract_context_digest: String,
    pub agreement_digest: String,
    pub allocation_id: String,
    pub refund_reference: String,
    pub evidence_digest: String,
    pub observed_at_unix_ms: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedCaptureWaiverObservationV1 {
    pub body: CaptureWaiverObservationV1,
    pub signature: Signature,
}
impl SignedCaptureWaiverObservationV1 {
    pub fn sign(
        body: CaptureWaiverObservationV1,
        observer: &Keypair,
    ) -> Result<Self, CaptureWaiverError> {
        Ok(Self {
            signature: observer.sign(&preimage(&body, "observation")?),
            body,
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractualCaptureWaiverRequestV1 {
    pub terms: SignedContractualCaptureWaiverTermsV1,
    pub observation: SignedCaptureWaiverObservationV1,
}
#[derive(Debug, Clone)]
pub struct CaptureWaiverSourceV1 {
    pub operation: AdmissionOperationV1,
    pub journal: PaymentJournalRecord,
    pub raw_output_digest: String,
    pub retained_terms_digest: String,
    pub issuer: PublicKey,
    pub subject: PublicKey,
}
impl ContractualCaptureWaiverRequestV1 {
    pub fn qualify(
        &self,
        policy: &ContractualCaptureWaiverPolicyV1,
        source: &CaptureWaiverSourceV1,
        now: u64,
    ) -> Result<(), CaptureWaiverError> {
        self.terms.verify(policy)?;
        source.journal.validate().map_err(fail)?;
        let t = &self.terms.body;
        let o = &self.observation.body;
        let j = &source.journal;
        let op = &source.operation;
        let b = op.binding().to_persisted();
        if !policy
            .observation_key
            .verify(&preimage(o, "observation")?, &self.observation.signature)
        {
            return Err(fail("receiver-pinned observation signature is invalid"));
        }
        if t.capability_digest != b.authorization_capability_hash.as_str()
            || t.request_id != b.request_id.as_str()
            || source.issuer != policy.receiver_key
            || source.subject != policy.counterparty_key
            || source.retained_terms_digest != capture_waiver_digest(&self.terms)?
        {
            return Err(fail(
                "waiver terms differ from the original retained authority",
            ));
        }
        if t.contract_context_digest != o.contract_context_digest
            || o.terms_digest != source.retained_terms_digest
            || o.operation_id != b.operation_id.as_str()
            || o.journal_digest != capture_waiver_digest(j)?
            || o.raw_output_digest != source.raw_output_digest
            || !digest_valid(&o.raw_output_digest)
            || !digest_valid(&o.evidence_digest)
            || !digest_valid(&o.agreement_digest)
            || !super::payment_identifier_is_valid(&o.allocation_id)
            || !super::payment_identifier_is_valid(&o.refund_reference)
        {
            return Err(fail(
                "refund observation differs from its signed terms or native sources",
            ));
        }
        if t.issued_at_unix_ms > j.created_at_unix_ms
            || o.observed_at_unix_ms < j.created_at_unix_ms
            || now < o.observed_at_unix_ms
            || now >= t.expires_at_unix_ms
        {
            return Err(fail(
                "waiver authority or observation is outside its original time window",
            ));
        }
        if op.state() != AdmissionOperationState::Finalizing
            || op.tool_outcome_id().is_none()
            || j.operation_id != o.operation_id
            || j.request_id != t.request_id
            || j.capability_id != b.capability_id.as_str()
            || j.request_namespace_digest != b.request_namespace_digest.as_str()
            || j.hold_id.as_deref() != op.budget_hold_id().map(|id| id.as_str())
            || op.payment_participant_id().map(|id| id.as_str()) != Some(o.operation_id.as_str())
            || j.rail != policy.rail
            || j.currency != policy.currency
            || j.rail_mode != PaymentRailMode::ReversibleHold
            || !matches!(
                j.state,
                PaymentJournalState::Settling | PaymentJournalState::ReconcileFailed
            )
            || j.transaction_id.is_some()
            || j.settle_action != Some(PaymentSettleAction::Capture)
            || j.settle_amount_units.is_none_or(|n| n == 0)
        {
            return Err(fail(
                "waiver requires the exact known positive capture awaiting settlement",
            ));
        }
        Ok(())
    }
}
