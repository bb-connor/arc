//! Portable egress commands resolve data, then enter the actual custody writer.
use super::*;
use chio_kernel::admission_operation::NativeSecurityEgressContext;
use chio_security_types::ports::{
    CommittedEgressFence, EgressFence, EgressFenceCommit, EgressFenceRequest,
};

impl SqliteAdmissionOperationStore {
    fn resolve_native_egress_initialization(
        &self,
        context: &NativeSecurityEgressContext<'_>,
    ) -> Result<SecurityParticipantStateInitialization, AdmissionOperationStoreError> {
        let initialized = self
            .load_security_participant_state(
                context.binding.security_authority_id(),
                context.lease.store_fence(),
                context.trusted_now_unix_ms,
            )?
            .ok_or_else(|| invariant("selected native initialization is absent"))?;
        if initialized.admission_binding()? != *context.binding {
            return Err(invariant("selected native initialization binding differs"));
        }
        // This read grants no authority. Each writer independently verifies
        // these exact initialization bytes, live material and actual lease in
        // its write transaction, including after any nested domain effects.
        Ok(initialized)
    }

    pub(super) fn acquire_native_egress_from_port(
        &self,
        context: &NativeSecurityEgressContext<'_>,
        command: &EgressFenceRequest,
    ) -> Result<EgressFence, AdmissionOperationStoreError> {
        let initialized = self.resolve_native_egress_initialization(context)?;
        self.acquire_security_participant_egress(
            context.operation,
            context.lease,
            &initialized,
            context.security_context,
            context.request,
            command,
            context.trusted_now_unix_ms,
        )
    }

    pub(super) fn commit_native_egress_from_port(
        &self,
        context: &NativeSecurityEgressContext<'_>,
        command: &EgressFenceCommit,
    ) -> Result<CommittedEgressFence, AdmissionOperationStoreError> {
        let initialized = self.resolve_native_egress_initialization(context)?;
        self.commit_security_participant_egress(
            context.operation,
            context.lease,
            &initialized,
            context.security_context,
            context.request,
            command,
            context.trusted_now_unix_ms,
        )
    }
}
