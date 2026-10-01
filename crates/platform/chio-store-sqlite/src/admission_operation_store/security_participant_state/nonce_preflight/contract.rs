//! Preflight can only taint the original strict-nonce Prepared operation.
use super::*;

pub(super) fn require_original(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    initialized: &SecurityParticipantStateInitialization,
    context: &chio_kernel::SecurityInvocationContext,
    intent: &NativeSecurityNoncePreflightJoinRequestV1,
) -> Result<(), AdmissionOperationStoreError> {
    operation.validate()?;
    intent.validate(operation.binding().operation_id())?;
    if operation.state() != AdmissionOperationState::Prepared
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || !operation
            .binding()
            .participant_requirements()
            .execution_nonce
        || operation.provider_attempt().is_some()
        || operation.dispatch_commit().is_some()
        || operation.budget_hold_id().is_some()
        || operation.execution_nonce_id().is_some()
        || operation.execution_nonce_issuance_digest().is_some()
        || operation.execution_nonce_preflight_digest().is_some()
    {
        return Err(invalid(
            "native nonce preflight requires original pre-issuance custody",
        ));
    }
    let original =
        super::super::super::retained_request::load_retained_request_tx(connection, operation)?
            .ok_or_else(|| invalid("native nonce preflight lacks its original retained request"))?;
    original.validate_native_security_authority(&initialized.admission_binding()?)?;
    original.validate_native_security_context(context)?;
    if original.authority_profile().is_none() {
        return Err(invalid(
            "native nonce preflight lacks its original authority profile",
        ));
    }
    let context = context.as_v1();
    let key = intent.key();
    if &key.tenant_id != context.tenant_id()
        || &key.principal_id != context.principal_id()
        || &key.session_id != context.session_id()
        || &key.lineage_id != context.lineage_root_id()
        || &key.isolation_epoch_id != context.isolation_epoch_id()
    {
        return Err(invalid(
            "native nonce preflight differs from its original security identity",
        ));
    }
    Ok(())
}
