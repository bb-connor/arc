//! Fresh scoped data, independent of historical join results and write custody.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityAuthorityBindingV1, NativeSecurityFlowObservationV1,
};
use chio_security_types::ports::FlowStateKey;

impl SqliteAdmissionOperationStore {
    /// Observe native labels and the exact context-row generation in one fenced
    /// read transaction. The selected initialization is checked independently.
    /// This may precede the first admission/join; it creates no row, operation,
    /// lease, journal event, activation or permission to mutate or dispatch.
    pub fn observe_security_participant_flow(
        &self,
        binding: &NativeSecurityAuthorityBindingV1,
        key: &FlowStateKey,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<NativeSecurityFlowObservationV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let observed_at = observed_time(&tx, trusted_now_unix_ms)?;
        verify_coverage(&tx).map_err(map_owner_error)?;
        let initialized = records::load_metadata(&tx, binding.security_authority_id().as_str())?
            .ok_or_else(|| invalid("selected native initialization is absent"))?;
        if initialized.admission_binding()? != *binding
            || binding.store_uuid().as_str() != fence.store_uuid
        {
            return Err(invalid("selected native initialization binding differs"));
        }
        let (snapshot, stored_context_generation) =
            crate::security_state::observe_native_flow_state(
                &tx,
                binding.security_authority_id().as_str(),
                key,
            )
            .map_err(invalid)?;
        NativeSecurityFlowObservationV1::new(
            binding.clone(),
            key.clone(),
            snapshot,
            stored_context_generation,
            observed_at,
        )
    }
}
