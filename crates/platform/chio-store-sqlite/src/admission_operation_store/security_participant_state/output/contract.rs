//! Original native capture and exact post-return artifacts, not caller markers.
use super::*;

pub(super) fn require_original(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    initialized: &SecurityParticipantStateInitialization,
    intent: &NativeSecurityOutputJoinRequestV1,
    require_payload: bool,
) -> Result<(), AdmissionOperationStoreError> {
    operation.validate()?;
    if operation.state() != AdmissionOperationState::Finalizing
        || operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.native_dispatch_ledger_digest().is_none()
        || operation
            .binding()
            .participant_requirements()
            .execution_nonce
        || operation
            .provider_attempt()
            .is_none_or(|attempt| attempt.is_caller_report())
    {
        return Err(invalid(
            "native output requires original kernel-owned capture",
        ));
    }
    super::super::dispatch_ledger::verify_capture_attachment(connection, operation)?;
    let original =
        super::super::super::retained_request::load_retained_request_tx(connection, operation)?
            .ok_or_else(|| invalid("native output lacks its original retained request"))?;
    original.validate_native_security_authority(&initialized.admission_binding()?)?;
    if original.authority_profile().is_none() {
        return Err(invalid(
            "native output lacks its original authority profile",
        ));
    }
    let joined =
        super::super::history::load_for_operation(connection, operation.binding().operation_id())?
            .ok_or_else(|| invalid("native output cannot adopt an absent input join"))?;
    if joined.authority != initialized.authority
        || joined.initialization != initialized.digest
        || &joined.request.key != intent.key()
        || AdmissionOperationV1::from_persisted(joined.operation)?.version() >= operation.version()
    {
        return Err(invalid(
            "native output differs from its original input custody",
        ));
    }
    if let Some(raw) = crate::tool_outcome_store::verify_native_output_artifacts(
        connection,
        operation,
        intent,
        require_payload,
    )? {
        original.validate_native_security_context(
            raw.security_invocation_context
                .as_ref()
                .ok_or_else(|| invalid("native output lacks its admitted security identity"))?,
        )?;
        let request = serde_json::from_str(
            raw.request_canonical_json
                .as_deref()
                .ok_or_else(|| invalid("native output lacks its frozen request"))?,
        )
        .map_err(invalid)?;
        original.validate_request_material(&request)?;
    }
    Ok(())
}
