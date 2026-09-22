//! Original broker material, authenticated through the kernel's retained hold.
use super::{canonical, rejected, unavailable, BrokerNativeCaptureReader};
use crate::kernel_admission::registration::registration_for_original_request;
use crate::kernel_admission::BrokerAdmissionParticipant;
use crate::protocol::BrokerExecuteRequest;
use crate::store::AttemptRegistration;
use crate::Result;
use chio_kernel::admission_operation::{
    AdmissionOperationId, AdmissionOperationStore, AdmissionOperationV1,
    RetainedToolAdmissionRequestV1,
};
use chio_kernel::supplemental_quota::{
    supplemental_authorization_artifact_digest, SupplementalQuotaVerifierBinding,
};

pub(super) struct OriginalBrokerRequest {
    pub operation: AdmissionOperationV1,
    retained: RetainedToolAdmissionRequestV1,
    pub execute: BrokerExecuteRequest,
}

impl BrokerNativeCaptureReader {
    /// Reconstruct the original registration from authenticated kernel custody.
    /// The configured participant supplies its domain; submitted data cannot
    /// choose one. This historical read neither prepares nor permits dispatch.
    pub fn read_registration(
        &self,
        participant: &BrokerAdmissionParticipant,
        operation_id: &AdmissionOperationId,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<(AttemptRegistration, BrokerExecuteRequest)>> {
        if participant.binding() != &self.participant {
            return Err(rejected());
        }
        let Some(original) = self.read_original(operation_id, trusted_now_unix_ms)? else {
            return Ok(None);
        };
        let Some(custody) = self
            .store
            .load_admission_budget_custody(operation_id, &self.fence, trusted_now_unix_ms)
            .map_err(unavailable)?
        else {
            return Ok(None);
        };
        let admission = &custody.admission;
        let artifact = supplemental_authorization_artifact_digest(&canonical(&original.execute)?);
        let verifier = SupplementalQuotaVerifierBinding {
            verifier_identity: admission
                .supplemental_verifier_id
                .clone()
                .ok_or_else(rejected)?,
            configuration_digest: admission
                .supplemental_verifier_config_digest
                .clone()
                .ok_or_else(rejected)?,
        };
        if original
            .operation
            .budget_hold_id()
            .map(|hold| hold.as_str())
            != Some(custody.hold_id.as_str())
            || custody.capability_id != original.operation.binding().capability_id().as_str()
            || admission.operation_id != operation_id.as_str()
            || original
                .retained
                .retained_matching_grant(custody.grant_index)
                .is_none()
            || !self.participant.matches_verifier(&verifier)
            || admission
                .supplemental_authorization_artifact_digest
                .as_ref()
                != Some(&artifact)
            || !admission.authorization_artifact_digests.contains(&artifact)
        {
            return Err(rejected());
        }
        let registration = registration_for_original_request(
            original.operation.binding(),
            &original.execute,
            &custody.invocation_quotas,
            participant.revocation_authority_domain(),
        )?;
        Ok(Some((registration, original.execute)))
    }

    pub(super) fn read_original(
        &self,
        operation_id: &AdmissionOperationId,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<OriginalBrokerRequest>> {
        let Some((operation, retained)) = self
            .store
            .load_retained_tool_request(operation_id, &self.fence, trusted_now_unix_ms)
            .map_err(unavailable)?
        else {
            return Ok(None);
        };
        retained
            .validate_native_security_authority(&self.native)
            .map_err(|_| rejected())?;
        if retained
            .authority_profile()
            .and_then(|profile| profile.supplemental_participant())
            != Some(&self.participant)
        {
            return Err(rejected());
        }
        let request = retained.request_for_revalidation();
        let execute: BrokerExecuteRequest =
            serde_json::from_value(request.arguments.clone()).map_err(|_| rejected())?;
        execute.validate_bounds()?;
        if canonical(&execute)? != canonical(&request.arguments)?
            || execute.invocation_id != operation.binding().request_id().as_str()
            || execute.capability.body.parent_capability_id
                != operation.binding().capability_id().as_str()
            || execute.capability.body.subject != request.capability.subject
        {
            return Err(rejected());
        }
        Ok(Some(OriginalBrokerRequest {
            operation,
            retained,
            execute,
        }))
    }
}
