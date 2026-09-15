//! Separately authorized release of a hold after an unknown execution terminal.
//!
//! Consent changes the payment claim. It never establishes that execution had no
//! effect, restores an invocation, or changes the original admission terminal.

use chio_core::{
    canonical_json_bytes,
    capability::token::CapabilityToken,
    crypto::{Keypair, PublicKey, Signature},
    sha256_hex,
};
use serde::{Deserialize, Serialize};

use super::{
    PaymentJournalRecord, PaymentJournalState, PaymentJournalTransition, PaymentRailMode,
    PaymentReleaseAuthorityBinding, PaymentReleaseAuthorityKind,
};
use crate::admission_operation::{
    AdmissionOperationKind, AdmissionOperationState, AdmissionOperationV1,
    AdmissionParticipantRequirements, PersistedAdmissionOperationV1,
    SignedAdmissionTerminalProjectionV1, StoreMutationFence,
};

pub const UNKNOWN_PAYMENT_RELEASE_SCHEMA: &str = "chio.unknown-payment-release.v1";
const MAX_INTEGER: u64 = (1_u64 << 53) - 1;
const MAX_WINDOW_MS: u64 = 86_400_000;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown payment release rejected: {0}")]
pub struct UnknownPaymentReleaseError(pub String);

fn fail(message: &str) -> UnknownPaymentReleaseError {
    UnknownPaymentReleaseError(message.into())
}

pub fn unknown_release_digest<T: Serialize>(
    value: &T,
) -> Result<String, UnknownPaymentReleaseError> {
    Ok(sha256_hex(
        &canonical_json_bytes(value).map_err(|e| fail(&e.to_string()))?,
    ))
}

/// Supplied by the receiving host's local configuration, never selected by a
/// request. The capability issuer and subject must also match these exact keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnknownPaymentReleasePolicyV1 {
    pub receiver_key: PublicKey,
    pub counterparty_key: PublicKey,
    pub rail: String,
    pub currency: String,
}

impl UnknownPaymentReleasePolicyV1 {
    pub fn validate(&self) -> Result<(), UnknownPaymentReleaseError> {
        if self.receiver_key == self.counterparty_key
            || self.rail.is_empty()
            || self.rail.len() > 512
            || self.rail == "unspecified"
            || !self.rail.bytes().all(|b| b.is_ascii_graphic())
            || self.currency.len() != 3
            || !self.currency.bytes().all(|b| b.is_ascii_uppercase())
        {
            return Err(fail("invalid locally configured release policy"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnknownPaymentReleaseTermsV1 {
    pub schema: String,
    pub policy_digest: String,
    pub operation_id: String,
    pub terminal_projection_digest: String,
    pub incident: SignedAdmissionTerminalProjectionV1,
    pub capability: CapabilityToken,
    pub authorized_journal: PaymentJournalRecord,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnknownPaymentReleaseProposalV1 {
    pub body: UnknownPaymentReleaseTermsV1,
    pub receiver_signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoSignedUnknownPaymentReleaseV1 {
    pub proposal: UnknownPaymentReleaseProposalV1,
    pub counterparty_signature: Signature,
}

fn preimage(
    body: &UnknownPaymentReleaseTermsV1,
    role: &[u8],
) -> Result<Vec<u8>, UnknownPaymentReleaseError> {
    let canonical = canonical_json_bytes(body).map_err(|e| fail(&e.to_string()))?;
    if canonical.len() > 256 * 1024 {
        return Err(fail("release terms exceed 256 KiB"));
    }
    let mut bytes = b"chio.unknown-payment-release.v1\0".to_vec();
    bytes.extend_from_slice(role);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

impl UnknownPaymentReleaseProposalV1 {
    pub fn sign(
        body: UnknownPaymentReleaseTermsV1,
        receiver: &Keypair,
    ) -> Result<Self, UnknownPaymentReleaseError> {
        let receiver_signature = receiver.sign(&preimage(&body, b"receiver")?);
        Ok(Self {
            body,
            receiver_signature,
        })
    }

    pub fn verify_receiver(
        &self,
        policy: &UnknownPaymentReleasePolicyV1,
    ) -> Result<(), UnknownPaymentReleaseError> {
        policy.validate()?;
        if !policy.receiver_key.verify(
            &preimage(&self.body, b"receiver")?,
            &self.receiver_signature,
        ) {
            return Err(fail("receiver did not sign these release terms"));
        }
        Ok(())
    }

    pub fn countersign(
        self,
        counterparty: &Keypair,
    ) -> Result<CoSignedUnknownPaymentReleaseV1, UnknownPaymentReleaseError> {
        let counterparty_signature = counterparty.sign(&preimage(&self.body, b"counterparty")?);
        Ok(CoSignedUnknownPaymentReleaseV1 {
            proposal: self,
            counterparty_signature,
        })
    }
}

/// Signature verification alone does not mint this value. Qualification also
/// binds local policy, the exact terminal and the still-authorized journal.
#[derive(Debug, Clone)]
pub struct VerifiedUnknownPaymentReleaseV1 {
    policy: UnknownPaymentReleasePolicyV1,
    request: CoSignedUnknownPaymentReleaseV1,
    operation: PersistedAdmissionOperationV1,
    accepted_at_unix_ms: u64,
}

impl CoSignedUnknownPaymentReleaseV1 {
    pub fn qualify(
        &self,
        policy: &UnknownPaymentReleasePolicyV1,
        operation: &AdmissionOperationV1,
        authorized_journal: &PaymentJournalRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<VerifiedUnknownPaymentReleaseV1, UnknownPaymentReleaseError> {
        self.proposal.verify_receiver(policy)?;
        let terms = &self.proposal.body;
        if !policy.counterparty_key.verify(
            &preimage(terms, b"counterparty")?,
            &self.counterparty_signature,
        ) {
            return Err(fail("counterparty did not sign these release terms"));
        }
        let binding = operation.binding().to_persisted();
        let incident = terms.incident.verify().map_err(|e| fail(&e.to_string()))?;
        let expected_participants = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            payment: true,
            ..AdmissionParticipantRequirements::NONE
        };
        authorized_journal
            .validate()
            .map_err(|e| fail(&e.to_string()))?;
        let replay = operation
            .terminal_replay()
            .ok_or_else(|| fail("operation is not terminal"))?;
        if terms.schema != UNKNOWN_PAYMENT_RELEASE_SCHEMA
            || terms.policy_digest != unknown_release_digest(policy)?
            || terms.operation_id != binding.operation_id.as_str()
            || terms.terminal_projection_digest != replay.projection_digest().as_str()
            || incident.signer_key() != &policy.receiver_key
            || incident.terminal_operation() != operation
            || operation.state() != AdmissionOperationState::OutcomeUnknownAfterDispatch
            || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
            || operation.binding().participant_requirements() != expected_participants
            || operation.tool_outcome_id().is_some()
            || authorized_journal.state != PaymentJournalState::Authorized
            || authorized_journal.rail_mode != PaymentRailMode::ReversibleHold
            || authorized_journal.operation_id != terms.operation_id
            || authorized_journal.capability_id != binding.capability_id.as_str()
            || authorized_journal.request_id != binding.request_id.as_str()
            || authorized_journal.request_namespace_digest
                != binding.request_namespace_digest.as_str()
            || authorized_journal.hold_id.as_deref()
                != operation.budget_hold_id().map(|x| x.as_str())
            || operation.payment_participant_id().map(|x| x.as_str())
                != Some(terms.operation_id.as_str())
            || unknown_release_digest(&terms.authorized_journal)?
                != unknown_release_digest(authorized_journal)?
            || authorized_journal.rail != policy.rail
            || authorized_journal.currency != policy.currency
            || terms.capability.issuer != policy.receiver_key
            || terms.capability.subject != policy.counterparty_key
            || !terms.capability.delegation_chain.is_empty()
            || terms.capability.id != authorized_journal.capability_id
            || unknown_release_digest(&terms.capability)?
                != binding.authorization_capability_hash.as_str()
            || !terms
                .capability
                .verify_signature()
                .map_err(|e| fail(&e.to_string()))?
            || terms.issued_at_unix_ms == 0
            || terms.issued_at_unix_ms > trusted_now_unix_ms
            || terms.issued_at_unix_ms < incident.context().trusted_time_unix_ms
            || trusted_now_unix_ms >= terms.expires_at_unix_ms
            || terms.expires_at_unix_ms > MAX_INTEGER
            || terms
                .expires_at_unix_ms
                .saturating_sub(terms.issued_at_unix_ms)
                > MAX_WINDOW_MS
        {
            return Err(fail(
                "release terms do not bind the locally authorized unknown hold",
            ));
        }
        Ok(VerifiedUnknownPaymentReleaseV1 {
            policy: policy.clone(),
            request: self.clone(),
            operation: operation.to_persisted(),
            accepted_at_unix_ms: trusted_now_unix_ms,
        })
    }
}

/// An append-only successor to the original journal. Its original operation and
/// authorization stay unchanged. Decoding is not authority to initiate release.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnknownPaymentReleaseRecordV1 {
    policy: UnknownPaymentReleasePolicyV1,
    request: CoSignedUnknownPaymentReleaseV1,
    operation: PersistedAdmissionOperationV1,
    accepted_at_unix_ms: u64,
    accepted_fence: StoreMutationFence,
    transaction_id: Option<String>,
    completed_at_unix_ms: Option<u64>,
    completed_fence: Option<StoreMutationFence>,
}

impl UnknownPaymentReleaseRecordV1 {
    pub fn accepted(
        verified: VerifiedUnknownPaymentReleaseV1,
        fence: StoreMutationFence,
    ) -> Result<Self, UnknownPaymentReleaseError> {
        let record = Self {
            policy: verified.policy,
            request: verified.request,
            operation: verified.operation,
            accepted_at_unix_ms: verified.accepted_at_unix_ms,
            accepted_fence: fence,
            transaction_id: None,
            completed_at_unix_ms: None,
            completed_fence: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), UnknownPaymentReleaseError> {
        let operation = AdmissionOperationV1::from_persisted(self.operation.clone())
            .map_err(|e| fail(&e.to_string()))?;
        self.request.qualify(
            &self.policy,
            &operation,
            &self.request.proposal.body.authorized_journal,
            self.accepted_at_unix_ms,
        )?;
        let incident = self
            .request
            .proposal
            .body
            .incident
            .verify()
            .map_err(|e| fail(&e.to_string()))?;
        validate_fence_successor(&incident.context().store_fence, &self.accepted_fence)?;
        match (
            &self.transaction_id,
            self.completed_at_unix_ms,
            &self.completed_fence,
        ) {
            (None, None, None) => (),
            (Some(_), Some(at), Some(fence))
                if at >= self.accepted_at_unix_ms && at <= MAX_INTEGER =>
            {
                validate_fence_successor(&self.accepted_fence, fence)?;
            }
            _ => return Err(fail("release completion fields disagree")),
        }
        self.current_journal()?;
        Ok(())
    }

    pub fn complete(
        &self,
        transaction_id: String,
        at: u64,
        fence: StoreMutationFence,
    ) -> Result<Self, UnknownPaymentReleaseError> {
        self.validate()?;
        if self.transaction_id.is_some() {
            return Err(fail("release already completed"));
        }
        let mut completed = self.clone();
        completed.transaction_id = Some(transaction_id);
        completed.completed_at_unix_ms = Some(at);
        completed.completed_fence = Some(fence);
        completed.validate()?;
        Ok(completed)
    }

    pub fn current_journal(&self) -> Result<PaymentJournalRecord, UnknownPaymentReleaseError> {
        let original = &self.request.proposal.body.authorized_journal;
        let evidence_digest = unknown_release_digest(&self.request)?;
        let mut journal = original
            .apply_transition(&PaymentJournalTransition::BeginRelease {
                authority: PaymentReleaseAuthorityBinding {
                    kind: PaymentReleaseAuthorityKind::MutuallyAgreedUnknown,
                    operation_id: original.operation_id.clone(),
                    operation_version: self.operation.version,
                    evidence_id: evidence_digest.clone(),
                    evidence_digest,
                },
            })
            .map_err(|e| fail(&e.to_string()))?;
        if let Some(id) = &self.transaction_id {
            journal = journal
                .apply_transition(&PaymentJournalTransition::SettlementCompleted {
                    transaction_id: id.clone(),
                })
                .map_err(|e| fail(&e.to_string()))?;
        }
        Ok(journal)
    }

    pub fn request(&self) -> &CoSignedUnknownPaymentReleaseV1 {
        &self.request
    }
    pub fn policy(&self) -> &UnknownPaymentReleasePolicyV1 {
        &self.policy
    }
    pub fn accepted_fence(&self) -> &StoreMutationFence {
        &self.accepted_fence
    }
    pub fn original_operation(&self) -> &PersistedAdmissionOperationV1 {
        &self.operation
    }
    pub fn operation_id(&self) -> &str {
        &self.request.proposal.body.operation_id
    }
    pub fn original_journal(&self) -> &PaymentJournalRecord {
        &self.request.proposal.body.authorized_journal
    }
    pub fn is_complete(&self) -> bool {
        self.transaction_id.is_some()
    }
    pub fn completion(&self) -> Option<(&str, u64, &StoreMutationFence)> {
        Some((
            self.transaction_id.as_deref()?,
            self.completed_at_unix_ms?,
            self.completed_fence.as_ref()?,
        ))
    }
    pub fn sequence(&self) -> u64 {
        if self.is_complete() {
            2
        } else {
            1
        }
    }
}

/// Explicitly trusted storage boundary for this new economic operation. Every
/// mutation must validate the active owner fence and trusted time, serialize
/// concurrent writers, and retain the original admission and authorization.
/// Decoded requests and caller-supplied records never substitute for stored state.
pub trait QualifiedUnknownPaymentReleaseStore: Send + Sync {
    fn unknown_release_source(
        &self,
        operation_id: &str,
        fence: &StoreMutationFence,
    ) -> Result<(AdmissionOperationV1, PaymentJournalRecord), UnknownPaymentReleaseError>;
    fn load_unknown_release(
        &self,
        operation_id: &str,
        fence: &StoreMutationFence,
    ) -> Result<Option<UnknownPaymentReleaseRecordV1>, UnknownPaymentReleaseError>;
    fn begin_unknown_release(
        &self,
        policy: &UnknownPaymentReleasePolicyV1,
        request: &CoSignedUnknownPaymentReleaseV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<UnknownPaymentReleaseRecordV1, UnknownPaymentReleaseError>;
    fn complete_unknown_release(
        &self,
        operation_id: &str,
        request_digest: &str,
        transaction_id: &str,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<UnknownPaymentReleaseRecordV1, UnknownPaymentReleaseError>;
    fn list_pending_unknown_releases(
        &self,
        fence: &StoreMutationFence,
        limit: usize,
    ) -> Result<Vec<UnknownPaymentReleaseRecordV1>, UnknownPaymentReleaseError>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnknownPaymentReleaseReceiptBodyV1 {
    pub schema: String,
    pub record: UnknownPaymentReleaseRecordV1,
}

pub type SignedUnknownPaymentReleaseReceiptV1 =
    chio_core::receipt::lineage::SignedExportEnvelope<UnknownPaymentReleaseReceiptBodyV1>;
pub const UNKNOWN_PAYMENT_RELEASE_RECEIPT_SCHEMA: &str = "chio.unknown-payment-release-receipt.v1";

pub fn verify_unknown_payment_release_receipt(
    receipt: &SignedUnknownPaymentReleaseReceiptV1,
    receiver: &PublicKey,
    counterparty: &PublicKey,
) -> Result<(), UnknownPaymentReleaseError> {
    let record = &receipt.body.record;
    record.validate()?;
    if receipt.body.schema != UNKNOWN_PAYMENT_RELEASE_RECEIPT_SCHEMA
        || !record.is_complete()
        || &receipt.signer_key != receiver
        || &record.policy.receiver_key != receiver
        || &record.policy.counterparty_key != counterparty
        || !receipt
            .verify_signature()
            .map_err(|e| fail(&e.to_string()))?
    {
        return Err(fail("receipt does not prove this agreed release completed"));
    }
    Ok(())
}

/// A host-wired native mediator for an explicitly agreed monetary successor.
/// It never dispatches work. The receiver supplies its own key, store and rail.
pub struct UnknownPaymentReleaseRuntime<'a> {
    store: &'a dyn QualifiedUnknownPaymentReleaseStore,
    adapter: &'a dyn super::PaymentAdapter,
    signer: &'a Keypair,
    fence: &'a StoreMutationFence,
}

impl<'a> UnknownPaymentReleaseRuntime<'a> {
    pub fn new(
        store: &'a dyn QualifiedUnknownPaymentReleaseStore,
        adapter: &'a dyn super::PaymentAdapter,
        signer: &'a Keypair,
        fence: &'a StoreMutationFence,
    ) -> Self {
        Self {
            store,
            adapter,
            signer,
            fence,
        }
    }

    pub fn resolve(
        &self,
        policy: &UnknownPaymentReleasePolicyV1,
        request: &CoSignedUnknownPaymentReleaseV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SignedUnknownPaymentReleaseReceiptV1, UnknownPaymentReleaseError> {
        if policy.receiver_key != self.signer.public_key() {
            return Err(fail("release signer differs from local receiver policy"));
        }
        self.check_rail(policy)?;
        // This durable transition precedes every possible rail side effect.
        let record =
            self.store
                .begin_unknown_release(policy, request, self.fence, trusted_now_unix_ms)?;
        self.finish(record, trusted_now_unix_ms)
    }

    pub fn resume(
        &self,
        operation_id: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<SignedUnknownPaymentReleaseReceiptV1, UnknownPaymentReleaseError> {
        let record = self
            .store
            .load_unknown_release(operation_id, self.fence)?
            .ok_or_else(|| fail("no accepted release intent exists"))?;
        self.finish(record, trusted_now_unix_ms)
    }

    pub fn reconcile_pending(
        &self,
        trusted_now_unix_ms: u64,
    ) -> Result<usize, UnknownPaymentReleaseError> {
        let mut completed = 0usize;
        loop {
            let page = self.store.list_pending_unknown_releases(self.fence, 256)?;
            if page.is_empty() {
                return Ok(completed);
            }
            for record in page {
                self.finish(record, trusted_now_unix_ms)?;
                completed = completed
                    .checked_add(1)
                    .ok_or_else(|| fail("release recovery count overflow"))?;
            }
        }
    }

    fn check_rail(
        &self,
        policy: &UnknownPaymentReleasePolicyV1,
    ) -> Result<(), UnknownPaymentReleaseError> {
        policy.validate()?;
        if self.adapter.rail_id() != policy.rail
            || self.adapter.rail_mode() != Some(PaymentRailMode::ReversibleHold)
        {
            return Err(fail(
                "configured rail cannot perform the agreed reversible release",
            ));
        }
        Ok(())
    }

    fn finish(
        &self,
        mut record: UnknownPaymentReleaseRecordV1,
        trusted_now_unix_ms: u64,
    ) -> Result<SignedUnknownPaymentReleaseReceiptV1, UnknownPaymentReleaseError> {
        record.validate()?;
        if record.policy.receiver_key != self.signer.public_key() {
            return Err(fail("release receiver key changed"));
        }
        self.check_rail(&record.policy)?;
        if !record.is_complete() {
            let journal = record.original_journal();
            let authorization = journal
                .authorization_id
                .as_deref()
                .ok_or_else(|| fail("release lacks authorization id"))?;
            let result = self
                .adapter
                .release(authorization, &journal.operation_id)
                .map_err(|e| fail(&e.to_string()))?;
            if result.settlement_status != super::RailSettlementStatus::Released {
                return Err(fail("rail has not confirmed hold release"));
            }
            record = self.store.complete_unknown_release(
                record.operation_id(),
                &unknown_release_digest(record.request())?,
                &result.transaction_id,
                self.fence,
                trusted_now_unix_ms,
            )?;
        }
        let receiver = record.policy.receiver_key.clone();
        let counterparty = record.policy.counterparty_key.clone();
        let receipt = SignedUnknownPaymentReleaseReceiptV1::sign(
            UnknownPaymentReleaseReceiptBodyV1 {
                schema: UNKNOWN_PAYMENT_RELEASE_RECEIPT_SCHEMA.into(),
                record,
            },
            self.signer,
        )
        .map_err(|e| fail(&e.to_string()))?;
        verify_unknown_payment_release_receipt(&receipt, &receiver, &counterparty)?;
        Ok(receipt)
    }
}

fn validate_fence_successor(
    old: &StoreMutationFence,
    new: &StoreMutationFence,
) -> Result<(), UnknownPaymentReleaseError> {
    if new.store_uuid.is_empty()
        || new.lease_id.is_empty()
        || new.lease_id.len() > 512
        || new.owner_epoch == 0
        || new.owner_epoch > MAX_INTEGER
        || old.store_uuid != new.store_uuid
        || (new.owner_epoch <= old.owner_epoch && old != new)
    {
        return Err(fail("release does not follow the retained store fence"));
    }
    Ok(())
}
