//! The real native original owns pre-effect finishing obligations.
use super::*;
use chio_kernel::admission_operation::NativeSecurityEgressContext;

impl SqliteAdmissionOperationStore {
    /// This boundary precedes an external authorization. Borrowed context and
    /// retained envelope data cannot provide prepaid finishing authority.
    /// The complete native purpose factory has not been installed, so an
    /// authenticated fresh native operation is refused before the first write.
    pub(in crate::admission_operation_store) fn require_native_pre_authorization_finishing_funding_from_port(
        &self,
        context: &NativeSecurityEgressContext<'_>,
    ) -> Result<(), AdmissionOperationStoreError> {
        let operation = context.operation;
        operation.validate()?;
        if operation.state() != AdmissionOperationState::CapturePending
            || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
            || operation.dispatch_commit().is_some()
            || operation.budget_hold_id().is_none()
            || operation.provider_attempt().is_none_or(|attempt| {
                attempt.is_caller_report() && !attempt.is_native_caller_report()
            })
        {
            return Err(invalid(
                "native pre-authorization requires fresh kernel capture custody",
            ));
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(context.lease.store_fence()))?;
        let origin = self
            .serving_owner
            .prepare_native_source_transaction(&tx)
            .map_err(map_owner_error)?;
        let now = observed_time(&tx, context.trusted_now_unix_ms)?;
        verify_participant_recovery_tx(&tx, &self.serving_owner, operation, context.lease, now)?;
        ensure_no_reserved_terminal_stage(&tx, operation.binding().operation_id())?;
        let original = retained_request::load_retained_request_tx(&tx, operation)?
            .ok_or_else(|| invalid("native pre-authorization lost its actual original"))?;
        original.validate_binding(operation.binding())?;
        original.validate_request_material(context.request)?;
        original.validate_native_security_authority(context.binding)?;
        original.validate_native_security_context(context.security_context)?;
        if original.authority_profile().is_none()
            || context.binding.store_uuid().as_str() != self.serving_owner.fence.store_uuid
        {
            return Err(invalid(
                "native pre-authorization changed its original authority",
            ));
        }
        // Startup authenticated the complete source history. These bounded
        // immutable fields independently bind this actual owner and initial
        // transaction cut; no caller-selected initialization is accepted.
        records::load_current_metadata(&tx, context.binding)?;
        origin.verify(&tx).map_err(map_owner_error)?;
        Err(invalid(
            "native external authorization lacks authenticated finishing funding",
        ))
    }
}
