//! Binding checks shared by current commands and historical record validation.
use super::*;
use chio_kernel::admission_operation::{
    NativeSecurityAuthorityBindingV1, RetainedToolAdmissionRequestV1,
};

pub(super) fn require_original(
    connection: &Connection,
    operation: &AdmissionOperationV1,
    context: &SecurityInvocationContext,
    binding: &NativeSecurityAuthorityBindingV1,
    fence: &EgressFence,
) -> Result<RetainedToolAdmissionRequestV1, AdmissionOperationStoreError> {
    operation.validate()?;
    if operation.binding().kind() != AdmissionOperationKind::ToolDispatch
        || operation.state() != AdmissionOperationState::CapturePending
        || operation.dispatch_commit().is_some()
        || operation
            .binding()
            .participant_requirements()
            .execution_nonce
    {
        return Err(invalid(
            "native egress requires pre-dispatch capture custody, not nonce authority",
        ));
    }
    let original =
        super::super::super::retained_request::load_retained_request_tx(connection, operation)?
            .ok_or_else(|| invalid("native egress lacks original retained request"))?;
    original.validate_native_security_context(context)?;
    original.validate_native_security_authority(binding)?;
    if original.authority_profile().is_none() {
        return Err(invalid("native egress requires original authority profile"));
    }
    let trusted = context.as_v1();
    let key = &fence.key;
    if &key.tenant_id != trusted.tenant_id()
        || &key.principal_id != trusted.principal_id()
        || &key.lineage_id != trusted.lineage_root_id()
        || &key.session_id != trusted.session_id()
        || &key.isolation_epoch_id != trusted.isolation_epoch_id()
        || trusted.flow_state_generation() != Some(fence.context_generation)
        || fence.request_id.as_str() != original.request_for_revalidation().request_id
        || fence.request_id.as_str() != operation.binding().request_id().as_str()
        || hex::encode(fence.request_hash.as_bytes())
            != operation.binding().action_parameter_hash().as_str()
    {
        return Err(invalid(
            "native egress differs from original request or current flow observation",
        ));
    }
    let joined =
        super::super::history::load_for_operation(connection, operation.binding().operation_id())?
            .ok_or_else(|| invalid("native egress requires this operation's original join"))?;
    if joined.authority != *binding.security_authority_id()
        || joined.initialization != binding.initialization_digest().as_str()
        || AdmissionOperationV1::from_persisted(joined.operation)?.version() > operation.version()
    {
        return Err(invalid("native egress cannot adopt another join"));
    }
    Ok(original)
}

pub(in crate::admission_operation_store::security_participant_state) fn live_request_hash(
    request: &ToolCallRequest,
) -> Result<AdmissionDigest, AdmissionOperationStoreError> {
    let bytes = canonical_json_bytes(request).map_err(invalid)?;
    if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
        return Err(invalid("native live request exceeds bounds"));
    }
    Ok(AdmissionDigest::try_new(
        "native_live_request_hash",
        sha256_hex(&bytes),
    )?)
}
