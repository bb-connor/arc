//! Classified feedback stays in the fenced native authority; signatures authorize policy separately.
#[cfg(test)]
mod error_categories;
mod transport;
use super::{RecoveryRuntime, RecoveryRuntimeError};
use chio_core_types::{capability::token::CapabilityToken, StoreMutationFence};
use chio_kernel::{
    admission_operation::AdmissionOperationStoreError,
    recovery::{
        AuthenticatedRecoveryActor, RecoveryAuthorityPort, RecoveryCommandPortError,
        RecoveryPermission,
    },
};
use chio_security_types::recovery::*;
use chio_store_sqlite::admission_operation_store::{
    NativeSemanticPolicyBasisV1, SqliteAdmissionOperationStore, StoredDecisionReportV1,
    StoredPolicyMaintenanceProposalV1,
};
use std::sync::Arc;
#[cfg(test)]
pub(super) use transport::call_with_occupied_maintenance_capacity;
pub use transport::recovery_maintenance_router;

pub struct RecoveryMaintenanceRuntime {
    runtime: Arc<RecoveryRuntime>,
    store: Arc<SqliteAdmissionOperationStore>,
    fence: StoreMutationFence,
}
impl core::fmt::Debug for RecoveryMaintenanceRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryMaintenanceRuntime([redacted])")
    }
}
impl RecoveryMaintenanceRuntime {
    pub fn new(
        runtime: Arc<RecoveryRuntime>,
        store: Arc<SqliteAdmissionOperationStore>,
        fence: StoreMutationFence,
    ) -> Result<Self, RecoveryRuntimeError> {
        let profile = store
            .deployment(runtime.scope(), &fence, now()?)
            .map_err(store_error)?;
        let selected = runtime
            .kernel
            .recovery_deployment(runtime.scope())
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        if chio_core_types::canonical_json_bytes(&profile)
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?
            != chio_core_types::canonical_json_bytes(&selected)
                .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?
        {
            return Err(RecoveryRuntimeError::UnsupportedProfile);
        }
        Ok(Self {
            runtime,
            store,
            fence,
        })
    }
    fn actor(
        &self,
        capability: &CapabilityToken,
        permission: RecoveryPermission,
    ) -> Result<AuthenticatedRecoveryActor, RecoveryRuntimeError> {
        self.runtime
            .kernel
            .authenticate_recovery_actor(self.runtime.scope(), capability, permission)
            .map_err(super::authentication_error)
    }
    fn optional_reader(
        &self,
        capability: &CapabilityToken,
    ) -> Result<Option<AuthenticatedRecoveryActor>, RecoveryRuntimeError> {
        match self.actor(capability, RecoveryPermission::KnowledgeRead) {
            Ok(actor) => Ok(Some(actor)),
            Err(RecoveryRuntimeError::AuthorityDenied) => Ok(None),
            Err(error) => Err(error),
        }
    }
    pub fn submit_report(
        &self,
        capability: &CapabilityToken,
        command: &CommandId,
        report: &DecisionReportV1,
    ) -> Result<StoredDecisionReportV1, RecoveryRuntimeError> {
        report
            .validate()
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        let actor = self.actor(capability, RecoveryPermission::Report)?;
        let reader = self.optional_reader(capability)?;
        self.store
            .submit_decision_report(
                &actor,
                reader.as_ref(),
                command,
                report,
                &self.fence,
                now()?,
            )
            .map_err(command_error)
    }
    pub fn read_report(
        &self,
        capability: &CapabilityToken,
        id: &EvidenceRef,
    ) -> Result<StoredDecisionReportV1, RecoveryRuntimeError> {
        let actor = self.actor(capability, RecoveryPermission::Inspect)?;
        let reader = self.optional_reader(capability)?;
        self.store
            .read_decision_report(&actor, reader.as_ref(), id, &self.fence, now()?)
            .map_err(store_error)
    }
    pub fn propose(
        &self,
        capability: &CapabilityToken,
        proposal: &PolicyMaintenanceProposalV1,
    ) -> Result<StoredPolicyMaintenanceProposalV1, RecoveryRuntimeError> {
        proposal
            .validate()
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        let actor = self.actor(capability, RecoveryPermission::Maintain)?;
        let reader = self.actor(capability, RecoveryPermission::KnowledgeRead)?;
        self.store
            .propose_policy_maintenance(&actor, &reader, proposal, &self.fence, now()?)
            .map_err(command_error)
    }
    pub fn policy_basis(
        &self,
        capability: &CapabilityToken,
    ) -> Result<NativeSemanticPolicyBasisV1, RecoveryRuntimeError> {
        let actor = self.actor(capability, RecoveryPermission::Maintain)?;
        self.store
            .read_semantic_policy_basis(&actor, &self.fence, now()?)
            .map_err(store_error)
    }
}
fn command_error(error: RecoveryCommandPortError) -> RecoveryRuntimeError {
    match error {
        RecoveryCommandPortError::Conflict => RecoveryRuntimeError::Conflict,
        RecoveryCommandPortError::OriginRefused => RecoveryRuntimeError::OriginRefused,
        RecoveryCommandPortError::Busy => RecoveryRuntimeError::Busy,
        RecoveryCommandPortError::Store(error) => store_error(error),
    }
}
fn store_error(error: AdmissionOperationStoreError) -> RecoveryRuntimeError {
    super::native_store_errors::store_error(error)
}
fn now() -> Result<u64, RecoveryRuntimeError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| RecoveryRuntimeError::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| RecoveryRuntimeError::Unavailable)
}
