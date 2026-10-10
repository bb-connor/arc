//! Fenced original custody under the trusted host's authenticated namespace.
use super::*;
use chio_kernel::admission_operation::{AuthenticatedRequestNamespace, RequestNamespaceDigest};

pub(in crate::admission_operation_store) fn resolve_scoped(
    tx: &Transaction<'_>,
    seed: &ToolCallRequest,
    profile: &RecoveryDeploymentV1,
    now: u64,
    proof: &RecoveryOriginalRequestScope,
) -> Result<RecoveryOriginV1, RecoveryCommandPortError> {
    if !proof.matches(&profile.scope, seed) || proof.namespace() != &native_namespace(profile)? {
        return Err(RecoveryCommandPortError::OriginRefused);
    }
    resolve_selected(
        tx,
        seed,
        profile,
        now,
        proof.namespace(),
        proof.request_id(),
    )
}

/// Trusted native setup resolves its own installed sessionless invocation.
/// Fresh public creation additionally requires resolve_scoped's process proof.
pub(in crate::admission_operation_store) fn resolve_native_original(
    tx: &Transaction<'_>,
    seed: &ToolCallRequest,
    profile: &RecoveryDeploymentV1,
    now: u64,
) -> Result<RecoveryOriginV1, RecoveryCommandPortError> {
    let request = AdmissionIdentifier::try_new("request_id", &seed.request_id)
        .map_err(AdmissionOperationStoreError::from)?;
    resolve_selected(
        tx,
        seed,
        profile,
        now,
        &native_namespace(profile)?,
        &request,
    )
}

fn resolve_selected(
    tx: &Transaction<'_>,
    seed: &ToolCallRequest,
    profile: &RecoveryDeploymentV1,
    now: u64,
    namespace: &RequestNamespaceDigest,
    request: &AdmissionIdentifier,
) -> Result<RecoveryOriginV1, RecoveryCommandPortError> {
    let identifiers = {
        let mut query = tx
            .prepare(
                "SELECT operation_id FROM admission_operations
             WHERE request_namespace_digest=?1 AND request_id=?2 LIMIT 2",
            )
            .map_err(sqlite_error)?;
        let values = query
            .query_map(params![namespace.as_str(), request.as_str()], |row| {
                row.get::<_, String>(0)
            })
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        values
    };
    let identifier = match identifiers.as_slice() {
        [] => return Err(RecoveryCommandPortError::OriginRefused),
        [value] => AdmissionOperationId::from_persisted(value.clone())
            .map_err(AdmissionOperationStoreError::from)?,
        _ => return Err(invariant("original namespace has duplicate request custody").into()),
    };
    let stored = load_by_operation_id_tx(tx, &identifier)?
        .ok_or_else(|| invariant("selected recovery original disappeared"))?;
    stored.verify_decision_time(now)?;
    let operation = &stored.operation;
    if operation.binding().request_namespace_digest() != namespace
        || operation.binding().request_id() != request
    {
        return Err(invariant("selected recovery original identity changed").into());
    }
    if !effect_free(operation) {
        return Err(RecoveryCommandPortError::OriginRefused);
    }
    let retained = super::super::retained_request::load_retained_request_tx(tx, operation)?
        .ok_or(RecoveryCommandPortError::OriginRefused)?;
    retained.validate_request_material(seed)?;
    retained.validate_native_security_context(&profile.security_context)?;
    retained.validate_native_security_authority(&profile.native_authority)?;
    // Corruption, fences and ambiguous commits remain operational errors.
    super::super::projection::verify_stored_terminal_projection(tx, &stored)?;
    origin(operation, seed).map_err(Into::into)
}

/// Recheck permanent ownership by exact operation, never by a global RID scan.
pub(in crate::admission_operation_store) fn revalidate(
    tx: &Transaction<'_>,
    seed: &ToolCallRequest,
    profile: &RecoveryDeploymentV1,
    now: u64,
    expected: &RecoveryOriginV1,
) -> Result<(), AdmissionOperationStoreError> {
    let identifier = AdmissionOperationId::from_persisted(
        expected.operation.operation_id().as_str().to_owned(),
    )?;
    let stored = load_by_operation_id_tx(tx, &identifier)?
        .ok_or_else(|| invariant("owned recovery original is absent"))?;
    stored.verify_decision_time(now)?;
    let operation = &stored.operation;
    if operation.binding().request_namespace_digest() != &native_namespace(profile)?
        || operation.binding().request_id().as_str() != seed.request_id
        || !effect_free(operation)
        || origin(operation, seed)? != *expected
    {
        return Err(invariant("owned recovery original binding changed"));
    }
    let retained = super::super::retained_request::load_retained_request_tx(tx, operation)?
        .ok_or_else(|| invariant("owned recovery original request is absent"))?;
    retained.validate_request_material(seed)?;
    retained.validate_native_security_context(&profile.security_context)?;
    retained.validate_native_security_authority(&profile.native_authority)?;
    super::super::projection::verify_stored_terminal_projection(tx, &stored)
}

fn effect_free(operation: &AdmissionOperationV1) -> bool {
    operation.binding().kind() == AdmissionOperationKind::ToolDispatch
        && operation.state() == AdmissionOperationState::CompensatedBeforeDispatch
        && operation.dispatch_commit().is_none()
}

fn native_namespace(
    profile: &RecoveryDeploymentV1,
) -> Result<RequestNamespaceDigest, AdmissionOperationStoreError> {
    // The independently installed native binding names its coordinator. Flow
    // tenant and process selectors never select an admission namespace.
    if profile.native_authority.store_uuid().as_str() != profile.scope.authority_domain.as_str() {
        return Err(invariant("recovery native coordinator changed"));
    }
    Ok(AuthenticatedRequestNamespace::for_local_system(
        profile.native_authority.store_uuid().clone(),
    )?
    .digest()
    .clone())
}

fn origin(
    operation: &AdmissionOperationV1,
    seed: &ToolCallRequest,
) -> Result<RecoveryOriginV1, AdmissionOperationStoreError> {
    Ok(RecoveryOriginV1 {
        operation: native::operation_ref(operation)?,
        request_id: RequestId::new(&seed.request_id)
            .map_err(|_| invariant("recovery original identity refused"))?,
        closure: EvidenceRef::new(&format!(
            "closure:{}",
            operation.binding().operation_id().as_str(),
        ))
        .map_err(|_| invariant("recovery original closure refused"))?,
    })
}
