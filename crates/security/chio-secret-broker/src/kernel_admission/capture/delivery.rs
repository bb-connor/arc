//! Signed completion must describe the kernel's original physical capture.
use super::original::OriginalBrokerRequest;
use super::{rejected, BrokerNativeCaptureReader};
use crate::budget::{CaptureExecutionHoldRequest, CombinedCaptureCommit};
use crate::kernel_admission::BrokerAdmissionParticipant;
use crate::protocol::{BrokerExecuteRequest, BrokerExecuteResponse};
use crate::store::AttemptRegistration;
use crate::Result;
use chio_kernel::admission_operation::AdmissionOperationId;
use chio_kernel::budget_store::BudgetInvocationState;

/// Public readback of one original composite capture. The host signs this
/// projection in its existing observation artifact. It contains no retained
/// private request or credential, and never authorizes another dispatch.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBrokerCompletionEvidence {
    pub registration: AttemptRegistration,
    pub capture: CombinedCaptureCommit,
    pub invocation_quotas: Vec<NativeBrokerQuotaObservation>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBrokerQuotaObservation {
    pub profile: String,
    pub owner_id: String,
    pub grant_index: Option<u32>,
    pub max_invocations: u32,
}

impl NativeBrokerQuotaObservation {
    fn quota(&self) -> Result<chio_kernel::budget_store::BudgetInvocationQuota> {
        use chio_kernel::budget_store::{
            BudgetInvocationQuota, BudgetQuotaKey, BudgetQuotaProfile,
        };
        if self.owner_id.len() > 4096 || self.max_invocations == 0 {
            return Err(rejected());
        }
        let key = BudgetQuotaKey {
            profile: BudgetQuotaProfile::parse(&self.profile).ok_or_else(rejected)?,
            owner_id: self.owner_id.clone(),
            grant_index: self.grant_index,
        };
        key.validate().map_err(|_| rejected())?;
        Ok(BudgetInvocationQuota {
            key,
            max_invocations: self.max_invocations,
        })
    }
}

impl NativeBrokerCompletionEvidence {
    pub fn verify(
        &self,
        operation: &chio_kernel::admission_operation::AdmissionOperationBindingV1,
        request: &BrokerExecuteRequest,
        response: &BrokerExecuteResponse,
        trusted_signer: &chio_core_types::PublicKey,
        observed_at_unix_ms: u64,
    ) -> Result<()> {
        self.registration.validate()?;
        if self.invocation_quotas.len() > 128 {
            return Err(rejected());
        }
        let quotas = self
            .invocation_quotas
            .iter()
            .map(NativeBrokerQuotaObservation::quota)
            .collect::<Result<Vec<_>>>()?;
        crate::ipc_client::validate_execute_response(request, response, trusted_signer)?;
        let expected = super::super::registration::registration_for_original_request(
            operation,
            request,
            &quotas,
            &self.registration.revocation_authority_domain,
        )?;
        let receipt = &response.receipt.body;
        let evidence = &response.evidence;
        if expected != self.registration
            || operation.request_id().as_str() != request.invocation_id
            || operation.capability_id().as_str() != request.capability.body.parent_capability_id
            || receipt.operation_id != operation.operation_id().as_str()
            || receipt.quotas != self.registration.quotas
            || receipt.issued_at_unix_seconds < request.capability.body.not_before_unix_seconds
            || receipt.issued_at_unix_seconds > observed_at_unix_ms / 1000
            || evidence.revocation_set_digest != self.capture.checked_revocation_set_digest
            || evidence.budget_commit_index != self.capture.budget_commit_index
            || evidence.revocation_commit_index != self.capture.revocation_commit_index
            || evidence.authority_commit_index != self.capture.authority_commit_index
            || evidence.leader_epoch != self.capture.leader_epoch
        {
            return Err(rejected());
        }
        Ok(())
    }
}

pub(super) struct CapturedBrokerDelivery {
    pub(super) execute: BrokerExecuteRequest,
    registration: AttemptRegistration,
    capture: CombinedCaptureCommit,
    earliest_completion_unix_seconds: u64,
}

impl CapturedBrokerDelivery {
    pub(super) fn verify_response(
        &self,
        participant: &BrokerAdmissionParticipant,
        response: &BrokerExecuteResponse,
        trusted_now_unix_ms: u64,
    ) -> Result<()> {
        participant
            .client
            .validate_completed_response(&self.execute, response)?;
        let receipt = &response.receipt.body;
        let evidence = &response.evidence;
        // Completion can be observed after capability expiry. Authenticate its
        // historical time against original authority and the trusted receiver
        // clock; do not turn this read into a new live authorization check.
        if receipt.issued_at_unix_seconds < self.earliest_completion_unix_seconds
            || receipt.issued_at_unix_seconds > trusted_now_unix_ms / 1_000
            || receipt.operation_id != self.registration.ids.operation_id
            || receipt.quotas != self.registration.quotas
            || evidence.revocation_set_digest != self.capture.checked_revocation_set_digest
            || evidence.budget_commit_index != self.capture.budget_commit_index
            || evidence.revocation_commit_index != self.capture.revocation_commit_index
            || evidence.authority_commit_index != self.capture.authority_commit_index
            || evidence.leader_epoch != self.capture.leader_epoch
        {
            return Err(rejected());
        }
        Ok(())
    }
}

impl BrokerNativeCaptureReader {
    pub fn completed_evidence(
        &self,
        participant: &BrokerAdmissionParticipant,
        operation_id: &AdmissionOperationId,
        response: &BrokerExecuteResponse,
        trusted_now_unix_ms: u64,
    ) -> Result<NativeBrokerCompletionEvidence> {
        let original = self
            .read_original(operation_id, trusted_now_unix_ms)?
            .ok_or_else(rejected)?;
        let delivery = self.captured_delivery(participant, &original, trusted_now_unix_ms)?;
        delivery.verify_response(participant, response, trusted_now_unix_ms)?;
        Ok(NativeBrokerCompletionEvidence {
            registration: delivery.registration,
            capture: delivery.capture,
            invocation_quotas: original
                .custody
                .ok_or_else(rejected)?
                .invocation_quotas
                .into_iter()
                .map(|quota| NativeBrokerQuotaObservation {
                    profile: quota.key.profile.as_str().into(),
                    owner_id: quota.key.owner_id,
                    grant_index: quota.key.grant_index,
                    max_invocations: quota.max_invocations,
                })
                .collect(),
        })
    }

    /// Verify historical completion against original retained authority and
    /// physical custody. This neither permits a new dispatch nor changes an
    /// uncertain operation's accounting or recovery state.
    pub fn verify_completed_response(
        &self,
        participant: &BrokerAdmissionParticipant,
        operation_id: &AdmissionOperationId,
        response: &BrokerExecuteResponse,
        trusted_now_unix_ms: u64,
    ) -> Result<()> {
        let original = self
            .read_original(operation_id, trusted_now_unix_ms)?
            .ok_or_else(rejected)?;
        self.captured_delivery(participant, &original, trusted_now_unix_ms)?
            .verify_response(participant, response, trusted_now_unix_ms)
    }

    pub(super) fn captured_delivery(
        &self,
        participant: &BrokerAdmissionParticipant,
        original: &OriginalBrokerRequest,
        now: u64,
    ) -> Result<CapturedBrokerDelivery> {
        let registration = self
            .registration_for_original(participant, original)?
            .ok_or_else(rejected)?;
        let custody = original.custody.as_ref().ok_or_else(rejected)?;
        if custody.invocation_state != BudgetInvocationState::Captured {
            return Err(rejected());
        }
        let revocation_ids = custody.admission.revocation_set.ids().to_vec();
        let request = CaptureExecutionHoldRequest {
            operation_id: registration.ids.operation_id.clone(),
            invocation_id: registration.invocation_id.clone(),
            parent_capability_id: registration.parent_capability_id.clone(),
            broker_capability_id: registration.broker_capability_id.clone(),
            hold_id: registration.ids.hold_id.clone(),
            capture_event_id: registration.ids.capture_event_id.clone(),
            revocation_set_digest: crate::revocation::digest_canonical_revocation_ids(
                &revocation_ids,
            )?,
            revocation_ids,
            authority_metadata_digest: registration.authority_metadata_digest.clone(),
            authorization_artifact_digest: crate::capability::capability_digest(
                &original.execute.capability,
            )?,
        };
        let capture = self
            .read_capture_for_original(&request, original, now)?
            .ok_or_else(rejected)?;
        Ok(CapturedBrokerDelivery {
            execute: original.execute.clone(),
            registration,
            capture,
            earliest_completion_unix_seconds: original
                .retained
                .request_for_revalidation()
                .capability
                .issued_at
                .max(original.execute.capability.body.not_before_unix_seconds),
        })
    }
}
