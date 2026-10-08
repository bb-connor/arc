//! Trusted host custody around native confined launch and separately admitted returns.
#![forbid(unsafe_code)]
use chio_core_types::{capability::token::CapabilityToken, recovery::*};
use chio_kernel::{knowledge::*, recovery::*, ChioKernel, KernelError};
use chio_security_types::{confinement::*, knowledge::*, recovery::*};
use chio_store_sqlite::admission_operation_store::{
    ConfinedChildReservationInput, ConfinedReturnAdmissionInput, NativeConfinedInstallationV1,
    NativeConfinedReservationV1, SqliteAdmissionOperationStore,
};
use std::sync::Arc;
use zeroize::Zeroizing;

mod acknowledgement;
pub use acknowledgement::ConfinedDeliveryError;

#[cfg(unix)]
mod channels;
#[cfg(unix)]
mod execution;
#[cfg(unix)]
pub use execution::confined_execution_profile;
#[cfg(unix)]
pub use execution::ConfinedExecution;

#[derive(Clone)]
pub struct NativeConfinedRuntime {
    kernel: Arc<ChioKernel>,
    store: Arc<SqliteAdmissionOperationStore>,
    broker: Arc<dyn ArtifactBlobPort>,
    installation: NativeConfinedInstallationV1,
    fence: chio_kernel::admission_operation::StoreMutationFence,
    #[cfg(test)]
    fault: Option<ConfinedFaultObserver>,
}
/// Private return bytes have no getter, Clone or Deserialize. Only a fresh
/// native admission can move them into an independently selected parent sink.
/// ```compile_fail
/// use chio_control_plane::confinement::PreparedConfinedReturn;
/// fn duplicate(value: PreparedConfinedReturn) { let _ = value.clone(); }
/// ```
pub struct PreparedConfinedReturn {
    request: RequestId,
    seal: ArtifactBlobSealV1,
    artifact: ArtifactVersionRefV1,
    bytes: Zeroizing<Vec<u8>>,
}
impl core::fmt::Debug for PreparedConfinedReturn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PreparedConfinedReturn([redacted])")
    }
}
fn refused(_error: impl core::fmt::Display) -> KernelError {
    KernelError::DurableAdmission("confined return unavailable".into())
}
fn now() -> Result<u64, KernelError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(refused)
        .and_then(|time| u64::try_from(time.as_millis()).map_err(refused))
}
impl NativeConfinedRuntime {
    pub fn new(
        kernel: Arc<ChioKernel>,
        store: Arc<SqliteAdmissionOperationStore>,
        broker: Arc<dyn ArtifactBlobPort>,
        installation: NativeConfinedInstallationV1,
        fence: chio_kernel::admission_operation::StoreMutationFence,
    ) -> Result<Self, KernelError> {
        if kernel.durable_authority_id() != Some(installation.scope.authority_domain.as_str())
            || installation.scope.authority_domain.as_str() != fence.store_uuid
            || broker.runtime_id() != installation.contract.parent.runtime.as_str()
        {
            return Err(refused("authority composition"));
        }
        store
            .configure_confinement(&installation)
            .map_err(refused)?;
        Ok(Self {
            kernel,
            store,
            broker,
            installation,
            fence,
            #[cfg(test)]
            fault: None,
        })
    }
    #[cfg(test)]
    pub(crate) fn with_test_cutpoint(mut self, observer: ConfinedFaultObserver) -> Self {
        self.fault = Some(observer);
        self
    }
    fn cutpoint(&self, stage: ConfinedCutpoint) -> Result<(), KernelError> {
        #[cfg(test)]
        if let Some(observer) = &self.fault {
            return observer(stage);
        }
        let _ = stage;
        Ok(())
    }
    fn actor(
        &self,
        capability: &CapabilityToken,
        permission: RecoveryPermission,
    ) -> Result<AuthenticatedRecoveryActor, KernelError> {
        self.kernel
            .authenticate_recovery_actor(&self.installation.scope, capability, permission)
    }
    /// Reserve and attach a direct child through the original process journal.
    /// The sealed native identity survives either store's lost acknowledgement.
    pub fn reserve(
        &self,
        capability: &CapabilityToken,
        process: &chio_process::ProcessRuntime,
        request: &RequestId,
        child: &CapabilityToken,
        seeds: &[ArtifactVersionRefV1],
        observation: &ArtifactVersionRefV1,
    ) -> Result<NativeConfinedReservationV1, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::ConfinedLaunch)?;
        let parent = process
            .process(self.installation.scope.process_id.as_str())
            .map_err(refused)?;
        if parent.parent_id.is_some() || process.runtime_id() != self.broker.runtime_id() {
            return Err(refused("parent process"));
        }
        let reservation = self
            .store
            .reserve_confined_child(
                &actor,
                ConfinedChildReservationInput {
                    request,
                    parent: &parent.capability,
                    child,
                    seeds,
                    observation,
                },
                &self.fence,
                now()?,
            )
            .map_err(refused)?;
        self.cutpoint(ConfinedCutpoint::Reserved)?;
        if reservation.state == IsolationStateV1::Reserved {
            process
                .spawn(
                    parent.id.as_str(),
                    reservation.boundary.child.as_str(),
                    child,
                )
                .map_err(refused)?;
            self.kernel
                .register_delegation_parent(child)
                .map_err(refused)?;
        }
        self.broker.reserve_confined_return(&reservation.boundary)?;
        self.cutpoint(ConfinedCutpoint::Attached)?;
        Ok(reservation)
    }
    /// Reconcile a lost staging acknowledgement from retained evidence. This
    /// classified review is separate from the parent's admitted value route.
    pub fn review_return(
        &self,
        capability: &CapabilityToken,
        request: &RequestId,
    ) -> Result<ConfinedReturnEvidenceV1, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::ConfinedReturn)?;
        self.store
            .confined_return_evidence(&actor, request, &self.fence, now()?)
            .map_err(refused)
    }
    pub fn prepare_return(
        &self,
        capability: &CapabilityToken,
        request: &RequestId,
    ) -> Result<PreparedConfinedReturn, KernelError> {
        let actor = self.actor(capability, RecoveryPermission::ConfinedReturn)?;
        let (seal, artifact) = self
            .store
            .prepare_confined_return(&actor, request, &self.fence, now()?)
            .map_err(refused)?;
        let bytes = Zeroizing::new(self.broker.read_private(&seal)?);
        if knowledge_content_digest(&bytes) != seal.content
            || bytes.len() as u64 != seal.bytes.get()
        {
            return Err(refused("immutable return"));
        }
        Ok(PreparedConfinedReturn {
            request: request.clone(),
            seal,
            artifact,
            bytes,
        })
    }
    pub fn deliver(
        &self,
        capability: &CapabilityToken,
        prepared: PreparedConfinedReturn,
        sink: &dyn ArtifactReleaseSink,
        disclosure: Option<&SignedConfinedDisclosureV1>,
        endorsement: Option<&SignedConfinedEndorsementV1>,
    ) -> Result<ReturnAdmissionV1, ConfinedDeliveryError> {
        let actor = self.actor(capability, RecoveryPermission::ConfinedReturn)?;
        let profile = self
            .store
            .knowledge_installation(&actor, &self.fence, now()?)
            .map_err(refused)?;
        let recipient = profile
            .recipients
            .as_slice()
            .iter()
            .find(|r| r.recipient == *sink.recipient())
            .ok_or_else(|| refused("receiving context"))?;
        self.broker
            .validate_process(&self.installation.scope.process_id, &recipient.context)?;
        self.cutpoint(ConfinedCutpoint::BeforeAdmission)?;
        self.broker
            .validate_process(&self.installation.scope.process_id, &recipient.context)?;
        let admission = self
            .store
            .admit_confined_return(
                &actor,
                ConfinedReturnAdmissionInput {
                    request: &prepared.request,
                    seal: &prepared.seal,
                    parent: sink.recipient(),
                    disclosure,
                    endorsement,
                },
                &self.fence,
                now()?,
            )
            .map_err(refused)?;
        if admission.artifact != prepared.artifact {
            return Err(refused("return substitution").into());
        }
        self.cutpoint(ConfinedCutpoint::ReturnCommitted)?;
        self.cutpoint(ConfinedCutpoint::BeforeDelivery)?;
        self.broker
            .validate_process(&self.installation.scope.process_id, &recipient.context)?;
        self.store
            .acknowledge_confined_return(
                &actor,
                &prepared.request,
                &admission,
                false,
                &self.fence,
                now()?,
            )
            .map_err(refused)?;
        self.broker.begin_confined_delivery(
            &actor,
            &prepared.request,
            &prepared.seal,
            &admission,
        )?;
        self.cutpoint(ConfinedCutpoint::DeliveryOrdered)?;
        let delivered = sink.deliver(&admission.admitted, &prepared.bytes).is_ok();
        // Own the actual result before any fallible post-I/O cutpoint or write.
        let pending = ConfinedDeliveryError::pending(
            refused("return acknowledgement pending"),
            actor,
            prepared.request,
            admission,
            delivered,
        );
        if self.cutpoint(ConfinedCutpoint::DeliveryCompleted).is_err() {
            return Err(pending);
        }
        let acknowledged = pending.reconcile(&self.store, &self.fence)?;
        if !delivered {
            return Err(refused("delivery uncertain").into());
        }
        Ok(acknowledged)
    }
    /// Accept a stop request without disclosing input or execution progress.
    /// Stopping revokes future admissions and retains original custody. This
    /// acknowledgement does not retract an earlier ordered return or effect.
    pub fn cancel(
        &self,
        capability: &CapabilityToken,
        process: &chio_process::ProcessRuntime,
        request: &RequestId,
    ) -> Result<(), KernelError> {
        let actor = self.actor(capability, RecoveryPermission::ConfinedCancel)?;
        let accepted = self
            .store
            .cancel_confined_child(&actor, request, &self.fence, now()?)
            .map_err(refused)?;
        match process.cancel(accepted.child().as_str()) {
            Ok(_)
            | Err(chio_process::ProcessError::NotFound(_))
            | Err(chio_process::ProcessError::ConfinedReturnAlreadyOrdered) => (),
            Err(error) => return Err(refused(error)),
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ConfinedCutpoint {
    Reserved,
    Attached,
    LaunchPrepared,
    Enforced,
    ObservationCommitted,
    BeforeInput,
    ReturnStaged,
    BeforeAdmission,
    ReturnCommitted,
    BeforeDelivery,
    DeliveryOrdered,
    DeliveryCompleted,
}
#[cfg(test)]
type ConfinedFaultObserver = Arc<dyn Fn(ConfinedCutpoint) -> Result<(), KernelError> + Send + Sync>;
