//! Native proof precedes the Process transaction that orders the first byte.
use super::*;
use chio_kernel::admission_operation::ConfinedReturnDeliveryInput;
use chio_security_types::confinement::ReturnAdmissionV1;

impl ProcessArtifactBroker {
    pub(super) fn begin_verified_confined_delivery(
        &self,
        actor: &chio_kernel::recovery::AuthenticatedRecoveryActor,
        request: &RequestId,
        seal: &ArtifactBlobSealV1,
        admission: &ReturnAdmissionV1,
    ) -> Result<(), KernelError> {
        let proof = self.runtime.enforcement.verified_confined_return_delivery(
            ConfinedReturnDeliveryInput {
                actor,
                request,
                seal,
                admission,
            },
        )?;
        self.runtime
            .with_store(|store| store.begin_verified_confined_delivery(proof, seal, admission))
            .map_err(refused)
    }
}
