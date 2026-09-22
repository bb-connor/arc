//! Broker projection of an original native kernel capture. All methods are reads.
use super::{canonical, registration::registration_quotas, rejected};
use crate::budget::{CaptureExecutionHoldRequest, CombinedCaptureCommit};
use crate::service::broker_request_digest;
use crate::store::derive_attempt_ids_for_operation;
use crate::{BrokerError, Result};
use chio_core_types::StoreMutationFence;
use chio_kernel::admission_operation::{AdmissionOperationId, NativeSecurityAuthorityBindingV1};
use chio_kernel::budget_store::BudgetInvocationCaptureDecision;
use chio_kernel::supplemental_admission::SupplementalAdmissionAuthorityBindingV1;
use chio_kernel::supplemental_quota::{
    supplemental_authorization_artifact_digest, SupplementalQuotaVerifierBinding,
};
use chio_store_sqlite::admission_operation_store::SqliteAdmissionOperationStore;
use chio_store_sqlite::SqliteAuthorityStore;

mod connection;
mod original;
pub use connection::BrokerKernelConnection;

/// Independently selected native and broker participants, pinned to a serving
/// owner. This is historical accounting, not permission to send a provider
/// request. Live parent checks and the broker's original prepared attempt still
/// govern execution. It never captures, reverses or creates quota custody.
pub struct BrokerNativeCaptureReader {
    store: SqliteAdmissionOperationStore,
    fence: StoreMutationFence,
    native: NativeSecurityAuthorityBindingV1,
    participant: SupplementalAdmissionAuthorityBindingV1,
}

impl BrokerNativeCaptureReader {
    pub fn new(
        authority: &SqliteAuthorityStore,
        native: NativeSecurityAuthorityBindingV1,
        participant: SupplementalAdmissionAuthorityBindingV1,
    ) -> Result<Self> {
        let fence = authority.mutation_fence();
        if native.store_uuid().as_str() != fence.store_uuid {
            return Err(rejected());
        }
        Ok(Self {
            store: authority.admission_operation_store(),
            fence,
            native,
            participant,
        })
    }

    /// Translate the broker's deterministic aliases only after authenticating
    /// their original kernel operation, exact request and physical capture.
    /// Time must come from the trusted host, never from the authority RPC body.
    pub fn read_capture(
        &self,
        request: &CaptureExecutionHoldRequest,
        trusted_now_unix_ms: u64,
    ) -> Result<Option<CombinedCaptureCommit>> {
        request.validate()?;
        let operation_id = AdmissionOperationId::from_persisted(request.operation_id.clone())
            .map_err(|_| rejected())?;
        let Some(original) = self.read_original(&operation_id, trusted_now_unix_ms)? else {
            return Ok(None);
        };
        let operation = original.operation;
        let execute = original.execute;
        let bytes = canonical(&execute)?;
        let ids = derive_attempt_ids_for_operation(
            &execute.capability.body.capability_id,
            &execute.invocation_id,
            &execute.proof.body.nonce,
            &broker_request_digest(&execute)?,
            operation_id.as_str(),
        )?;
        if request.invocation_id != execute.invocation_id
            || request.invocation_id != operation.binding().request_id().as_str()
            || request.parent_capability_id != execute.capability.body.parent_capability_id
            || request.parent_capability_id != operation.binding().capability_id().as_str()
            || request.broker_capability_id != execute.capability.body.capability_id
            || request.hold_id != ids.hold_id
            || request.capture_event_id != ids.capture_event_id
            || request.authority_metadata_digest
                != operation.binding().request_binding_hash().as_str()
            || request.authorization_artifact_digest
                != crate::capability::capability_digest(&execute.capability)?
        {
            return Err(rejected());
        }
        let Some(witness) = self
            .store
            .load_native_dispatch_capture_witness(&operation_id, &self.fence, trusted_now_unix_ms)
            .map_err(unavailable)?
        else {
            return Ok(None);
        };
        if witness.capture.operation.binding() != operation.binding() {
            return Err(rejected());
        }
        let BudgetInvocationCaptureDecision::Captured(capture) = witness.capture.decision else {
            return Err(rejected());
        };
        let binding = capture.admission_binding.as_ref().ok_or_else(rejected)?;
        let verifier = SupplementalQuotaVerifierBinding {
            verifier_identity: binding
                .supplemental_verifier_id
                .clone()
                .ok_or_else(rejected)?,
            configuration_digest: binding
                .supplemental_verifier_config_digest
                .clone()
                .ok_or_else(rejected)?,
        };
        let artifact_digest = supplemental_authorization_artifact_digest(&bytes);
        // The two protocols use different digest domains. Authenticate exact
        // canonical members before returning the independently validated broker
        // digest; copying the kernel digest would identify a different set.
        if binding.operation_id != request.operation_id
            || binding.revocation_set.ids() != request.revocation_ids
            || !self.participant.matches_verifier(&verifier)
            || binding.supplemental_authorization_artifact_digest.as_ref() != Some(&artifact_digest)
            || !binding
                .authorization_artifact_digests
                .contains(&artifact_digest)
        {
            return Err(rejected());
        }
        registration_quotas(
            &capture
                .invocation_quota_usages
                .iter()
                .map(|usage| usage.quota.clone())
                .collect::<Vec<_>>(),
            &execute,
        )?;
        let budget_commit_index = capture
            .metadata
            .budget_commit_index
            .filter(|index| *index > 0)
            .ok_or_else(rejected)?;
        let authority = capture.metadata.authority.as_ref().ok_or_else(rejected)?;
        Ok(Some(CombinedCaptureCommit {
            checked_revocation_set_digest: request.revocation_set_digest.clone(),
            budget_commit_index,
            revocation_commit_index: witness.revocation_commit_index,
            authority_commit_index: witness.authority_commit_index,
            leader_epoch: authority.lease_epoch,
        }))
    }
}

fn unavailable(_: chio_kernel::admission_operation::AdmissionOperationStoreError) -> BrokerError {
    BrokerError::AuthorityUnavailable("original kernel admission readback failed".into())
}
