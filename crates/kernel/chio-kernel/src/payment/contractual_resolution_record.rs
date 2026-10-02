//! Validated append-only capture-waiver acceptance and completion.
use super::contractual_resolution::*;
use super::{
    PaymentJournalRecord, PaymentJournalState, PaymentReleaseAuthorityBinding,
    PaymentReleaseAuthorityKind,
};
use crate::admission_operation::{
    AdmissionOperationV1, PersistedAdmissionOperationV1, StoreMutationFence,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractualCaptureWaiverRecordV1 {
    policy: ContractualCaptureWaiverPolicyV1,
    request: ContractualCaptureWaiverRequestV1,
    operation: PersistedAdmissionOperationV1,
    journal: PaymentJournalRecord,
    accepted_at_unix_ms: u64,
    accepted_fence: StoreMutationFence,
    completed_at_unix_ms: Option<u64>,
    completed_fence: Option<StoreMutationFence>,
}
impl ContractualCaptureWaiverRecordV1 {
    pub fn accepted(
        policy: &ContractualCaptureWaiverPolicyV1,
        request: &ContractualCaptureWaiverRequestV1,
        source: &CaptureWaiverSourceV1,
        fence: StoreMutationFence,
        now: u64,
    ) -> Result<Self, CaptureWaiverError> {
        request.qualify(policy, source, now)?;
        let record = Self {
            policy: policy.clone(),
            request: request.clone(),
            operation: source.operation.to_persisted(),
            journal: source.journal.clone(),
            accepted_at_unix_ms: now,
            accepted_fence: fence,
            completed_at_unix_ms: None,
            completed_fence: None,
        };
        record.validate()?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<(), CaptureWaiverError> {
        let source = CaptureWaiverSourceV1 {
            operation: AdmissionOperationV1::from_persisted(self.operation.clone())
                .map_err(fail)?,
            journal: self.journal.clone(),
            raw_output_digest: self.request.observation.body.raw_output_digest.clone(),
            retained_terms_digest: capture_waiver_digest(&self.request.terms)?,
            issuer: self.policy.receiver_key.clone(),
            subject: self.policy.counterparty_key.clone(),
        };
        self.request
            .qualify(&self.policy, &source, self.accepted_at_unix_ms)?;
        let f = &self.accepted_fence;
        if f.store_uuid.is_empty()
            || f.lease_id.is_empty()
            || f.owner_epoch == 0
            || f.owner_epoch > MAX
        {
            return Err(fail("invalid acceptance fence"));
        }
        match (&self.completed_fence, self.completed_at_unix_ms) {
            (None, None) => (),
            (Some(n), Some(at))
                if at >= self.accepted_at_unix_ms
                    && at <= MAX
                    && n.store_uuid == f.store_uuid
                    && (n == f || n.owner_epoch > f.owner_epoch) => {}
            _ => return Err(fail("invalid completion fence or time")),
        }
        Ok(())
    }
    pub fn complete(
        &self,
        now: u64,
        fence: StoreMutationFence,
    ) -> Result<Self, CaptureWaiverError> {
        self.validate()?;
        if self.is_complete() {
            return Err(fail("waiver already completed"));
        }
        let mut next = self.clone();
        next.completed_at_unix_ms = Some(now);
        next.completed_fence = Some(fence);
        next.validate()?;
        Ok(next)
    }
    pub fn current_journal(&self) -> Result<PaymentJournalRecord, CaptureWaiverError> {
        self.validate()?;
        let mut j = self.journal.clone();
        j.journal_version += self.sequence();
        j.state = if self.is_complete() {
            PaymentJournalState::Resolved
        } else {
            PaymentJournalState::Resolving
        };
        j.release_authority = Some(PaymentReleaseAuthorityBinding {
            kind: PaymentReleaseAuthorityKind::ContractualCaptureWaiver,
            operation_id: j.operation_id.clone(),
            operation_version: self.operation.version,
            evidence_id: self.request.observation.body.refund_reference.clone(),
            evidence_digest: capture_waiver_digest(&self.request)?,
        });
        j.transaction_id = self
            .is_complete()
            .then(|| self.request.observation.body.refund_reference.clone());
        j.validate().map_err(fail)?;
        Ok(j)
    }
    pub fn is_complete(&self) -> bool {
        self.completed_at_unix_ms.is_some()
    }
    pub fn sequence(&self) -> u64 {
        if self.is_complete() {
            2
        } else {
            1
        }
    }
    pub fn request(&self) -> &ContractualCaptureWaiverRequestV1 {
        &self.request
    }
    pub fn policy(&self) -> &ContractualCaptureWaiverPolicyV1 {
        &self.policy
    }
    pub fn original_journal(&self) -> &PaymentJournalRecord {
        &self.journal
    }
    pub fn original_operation(&self) -> &PersistedAdmissionOperationV1 {
        &self.operation
    }
    pub fn operation_id(&self) -> &str {
        &self.journal.operation_id
    }
    pub fn accepted_fence(&self) -> &StoreMutationFence {
        &self.accepted_fence
    }
    pub fn completion(&self) -> Option<(u64, &StoreMutationFence)> {
        Some((self.completed_at_unix_ms?, self.completed_fence.as_ref()?))
    }
}
/// Trusted host storage boundary; every mutation revalidates actual retained sources.
pub trait QualifiedContractualCaptureWaiverStore: Send + Sync {
    fn capture_waiver_source(
        &self,
        id: &str,
        fence: &StoreMutationFence,
    ) -> Result<CaptureWaiverSourceV1, CaptureWaiverError>;
    fn load_capture_waiver(
        &self,
        id: &str,
        fence: &StoreMutationFence,
    ) -> Result<Option<ContractualCaptureWaiverRecordV1>, CaptureWaiverError>;
    fn begin_capture_waiver(
        &self,
        policy: &ContractualCaptureWaiverPolicyV1,
        request: &ContractualCaptureWaiverRequestV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ContractualCaptureWaiverRecordV1, CaptureWaiverError>;
    fn complete_capture_waiver(
        &self,
        id: &str,
        digest: &str,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<ContractualCaptureWaiverRecordV1, CaptureWaiverError>;
}
