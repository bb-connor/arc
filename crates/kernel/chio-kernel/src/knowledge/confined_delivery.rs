//! Only current native RETURN verification authorizes an exact Process marker.
use super::*;
use crate::admission_operation::ConfinedReturnDeliveryInput;
use chio_security_types::confinement::{IsolationBoundaryV1, ReturnAdmissionV1};

fn refused() -> crate::KernelError {
    crate::KernelError::DurableAdmission("confined delivery unavailable".into())
}
fn binding<T: Serialize>(value: &T) -> Result<String, crate::KernelError> {
    chio_core_types::canonical_json_bytes(value)
        .map(|bytes| chio_core_types::crypto::sha256_hex(&bytes))
        .map_err(|_| refused())
}
impl DurableKnowledgeEnforcement {
    pub fn verified_confined_return_delivery(
        &self,
        input: ConfinedReturnDeliveryInput<'_>,
    ) -> Result<VerifiedConfinedReturnDelivery, crate::KernelError> {
        let seal = binding(input.seal)?;
        let admission = binding(input.admission)?;
        let request = input.request.clone();
        let scope = input.actor.scope().clone();
        let boundary = self
            .store
            .verify_confined_return_delivery(
                input,
                &self.fence,
                crate::kernel::current_unix_timestamp_ms(),
            )
            .map_err(|_| refused())?;
        if boundary.scope != scope || boundary.request != request {
            return Err(refused());
        }
        Ok(VerifiedConfinedReturnDelivery {
            boundary,
            seal,
            admission,
        })
    }
}

/// Single-use proof issued only after actual current native RETURN verification.
/// It has no public constructor, clone, deserializer or inspectable fields.
///
/// ```compile_fail
/// use chio_kernel::knowledge::VerifiedConfinedReturnDelivery;
/// fn duplicate(proof: VerifiedConfinedReturnDelivery) { let _ = proof.clone(); }
/// ```
pub struct VerifiedConfinedReturnDelivery {
    boundary: IsolationBoundaryV1,
    seal: String,
    admission: String,
}
impl VerifiedConfinedReturnDelivery {
    /// The owning Process transaction consumes this proof and separately joins
    /// both retained signed endpoints and its exact filled immutable slot.
    pub fn consume_for(
        self,
        seal: &ArtifactBlobSealV1,
        admission: &ReturnAdmissionV1,
    ) -> Result<IsolationBoundaryV1, crate::KernelError> {
        if self.seal != binding(seal)? || self.admission != binding(admission)? {
            return Err(refused());
        }
        Ok(self.boundary)
    }
}
impl core::fmt::Debug for VerifiedConfinedReturnDelivery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedConfinedReturnDelivery([redacted])")
    }
}
