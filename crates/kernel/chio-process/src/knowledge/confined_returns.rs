//! Confined values use only native-verified, precharged immutable slots.
use super::*;
use chio_kernel::admission_operation::ConfinedReturnCandidateInput;
use chio_security_types::confinement::IsolationBoundaryV1;

impl ProcessArtifactBroker {
    pub(super) fn stage_verified_confined_return(
        &self,
        actor: &chio_kernel::recovery::AuthenticatedRecoveryActor,
        boundary: &IsolationBoundaryV1,
        bytes: &[u8],
    ) -> Result<ArtifactBlobSealV1, KernelError> {
        // The native source/actor/producer gate runs before inspecting or
        // mutating the process slot. Its opaque proof is never caller supplied.
        let verified = self
            .runtime
            .enforcement
            .verified_confined_return_candidate(ConfinedReturnCandidateInput {
                actor,
                boundary,
                bytes,
            })?;
        self.validate_confined_attachment(boundary)?;
        let generation = self
            .runtime
            .with_store(|store| store.fill_verified_confined_return_slot(verified, boundary, bytes))
            .map_err(refused)?;
        Ok(ArtifactBlobSealV1 {
            object: ArtifactObjectId::new(boundary.boundary.as_str()).map_err(refused)?,
            runtime: ProtectedText::new(self.runtime_id()).map_err(refused)?,
            process: boundary.child.clone(),
            content: knowledge_content_digest(bytes),
            bytes: SafeInteger::new(bytes.len() as u64).map_err(refused)?,
            generation: ProtectedText::new(&format!("confined:{generation}")).map_err(refused)?,
        })
    }

    pub(super) fn read_confined_slot(
        &self,
        seal: &ArtifactBlobSealV1,
        retained: bool,
    ) -> Result<Vec<u8>, KernelError> {
        if seal.runtime.as_str() != self.runtime_id() || seal.bytes.get() > 8 {
            return Err(refused("confined seal"));
        }
        let bytes = self
            .runtime
            .with_store(|store| {
                store.read_confined_return_slot(
                    seal.process.as_str(),
                    seal.object.as_str(),
                    &hex(seal.content.as_bytes()),
                    seal.generation.as_str(),
                    retained,
                )
            })
            .map_err(refused)?;
        if bytes.len() as u64 != seal.bytes.get()
            || knowledge_content_digest(&bytes) != seal.content
        {
            return Err(refused("immutable confined bytes"));
        }
        Ok(bytes)
    }
}
