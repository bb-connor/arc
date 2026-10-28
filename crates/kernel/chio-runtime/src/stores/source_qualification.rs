use super::SqliteRuntimeOrchestrationStore;
use chio_kernel::admission_operation::{
    AdmissionIdentifier, AdmissionOperationStoreError, RuntimeSourcePort,
    RuntimeSourceQualificationV1,
};

impl RuntimeSourcePort for SqliteRuntimeOrchestrationStore {
    fn qualify(
        &self,
        source_id: &AdmissionIdentifier,
        runtime_authority_id: &AdmissionIdentifier,
        destination_authority_id: &AdmissionIdentifier,
    ) -> Result<RuntimeSourceQualificationV1, AdmissionOperationStoreError> {
        RuntimeSourcePort::qualify(
            &self.inner,
            source_id,
            runtime_authority_id,
            destination_authority_id,
        )
    }

    fn verify_exact(
        &self,
        expected: &RuntimeSourceQualificationV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        RuntimeSourcePort::verify_exact(&self.inner, expected)
    }
}
