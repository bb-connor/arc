//! Scope custody and native capture routing are independently authenticated.
use super::*;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSetupContextIndexV1 {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    native_authority: chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
    security_context: SecurityInvocationContext,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantSetupRequirementV1 {
    domain_version: VersionV1,
    authority_domain: AuthorityDomainId,
    tenant_id: RecoveryTenantId,
}

pub(super) fn tenant_key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "protected-setup-tenant:{}",
        sha256_hex(&protected::encode(&(
            &scope.authority_domain,
            &scope.tenant_id
        ))?)
    ))
}

/// A configured tenant cannot remove its protection by selecting another process.
pub(super) fn tenant_required(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<bool, AdmissionOperationStoreError> {
    if let Some(row) = authenticated_record(tx, &tenant_key(scope)?)? {
        let required: TenantSetupRequirementV1 = protected::decode(&row.payload)?;
        if row.kind != "command"
            || row.version != 1
            || row.scope != required_scope(scope)?
            || required.authority_domain != scope.authority_domain
            || required.tenant_id != scope.tenant_id
        {
            return Err(refused("tenant setup requirement custody"));
        }
        return Ok(true);
    }
    // The original tenant-keyed selection remains an authenticated protection
    // marker after scoped migration or explicit completed-self-test retirement.
    let Some(row) = authenticated_record(tx, &legacy_key(scope)?)? else {
        return Ok(false);
    };
    let value = selection_codec::decode(&row.payload)?;
    require_selection_envelope(&row, &value)?;
    if value.probe.scope.authority_domain != scope.authority_domain
        || value.probe.scope.tenant_id != scope.tenant_id
    {
        return Err(refused("historical setup tenant changed"));
    }
    Ok(true)
}

fn required_scope(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&protected::encode(&(
        &scope.authority_domain,
        &scope.tenant_id,
    ))?))
}

pub(super) fn mark_tenant_required(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let key = tenant_key(scope)?;
    let required = TenantSetupRequirementV1 {
        domain_version: VersionV1,
        authority_domain: scope.authority_domain.clone(),
        tenant_id: scope.tenant_id.clone(),
    };
    let payload = protected::encode(&required)?;
    if let Some(row) = authenticated_record(tx, &key)? {
        if row.kind != "command"
            || row.version != 1
            || row.scope != required_scope(scope)?
            || row.payload != payload
        {
            return Err(refused("tenant setup requirement changed"));
        }
        return Ok(false);
    }
    protected::save(
        tx,
        owner,
        &key,
        &required_scope(scope)?,
        "command",
        &payload,
        None,
    )?;
    Ok(true)
}

/// Flow generation is a mutable source observation, not process identity.
fn context_key(
    native: &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
) -> Result<String, AdmissionOperationStoreError> {
    let context = context.as_v1();
    Ok(format!(
        "protected-setup-context:{}",
        sha256_hex(&protected::encode(&(
            native,
            context.tenant_id(),
            context.session_id(),
            context.principal_id(),
            context.lineage_root_id(),
            context.isolation_epoch_id(),
            context.context_generation(),
        ))?)
    ))
}

/// Trusted deployment installation registers a unique process routing identity.
/// Equal native contexts cannot silently select whichever scope installed last.
pub(in crate::admission_operation_store) fn register_native_setup_context(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    deployment: &RecoveryDeploymentV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let key = context_key(&deployment.native_authority, &deployment.security_context)?;
    let mut changed = false;
    if let Some(row) = authenticated_record(tx, &key)? {
        let prior: NativeSetupContextIndexV1 = protected::decode(&row.payload)?;
        if row.kind != "command"
            || row.version != 1
            || row.scope != protected::scope_key(&deployment.scope)?
            || prior.scope != deployment.scope
            || prior.native_authority != deployment.native_authority
            || context_key(&prior.native_authority, &prior.security_context)? != key
        {
            return Err(refused("native setup context has another owner"));
        }
    } else {
        let mapping = NativeSetupContextIndexV1 {
            domain_version: VersionV1,
            scope: deployment.scope.clone(),
            native_authority: deployment.native_authority.clone(),
            security_context: deployment.security_context.clone(),
        };
        protected::save(
            tx,
            owner,
            &key,
            &protected::scope_key(&deployment.scope)?,
            "command",
            &protected::encode(&mapping)?,
            None,
        )?;
        changed = true;
    }
    if deployment.setup_policy.is_some() {
        changed |= mark_tenant_required(tx, owner, &deployment.scope)?;
    }
    Ok(changed)
}

pub(super) fn capture_scope(
    tx: &Connection,
    owner: &SqliteServingOwner,
    context: &SecurityInvocationContext,
    native: &chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1,
) -> Result<Option<RecoveryScopeV1>, AdmissionOperationStoreError> {
    let key = context_key(native, context)?;
    let tenant_scope = RecoveryScopeV1 {
        authority_domain: AuthorityDomainId::new(&owner.fence.store_uuid).map_err(refused)?,
        tenant_id: RecoveryTenantId::new(context.as_v1().tenant_id().as_str()).map_err(refused)?,
        process_id: ProcessId::new("native-capture").map_err(refused)?,
    };
    let required = tenant_required(tx, &tenant_scope)?;
    let Some(row) = authenticated_record(tx, &key)? else {
        return if required {
            Err(refused("protected native capture scope absent"))
        } else {
            Ok(None)
        };
    };
    let mapping: NativeSetupContextIndexV1 = protected::decode(&row.payload)?;
    if row.kind != "command"
        || row.version != 1
        || row.scope != protected::scope_key(&mapping.scope)?
        || mapping.scope.authority_domain != tenant_scope.authority_domain
        || mapping.scope.tenant_id != tenant_scope.tenant_id
        || mapping.native_authority != *native
        || context_key(&mapping.native_authority, &mapping.security_context)? != key
    {
        return Err(refused("native capture routing custody"));
    }
    let current = protected::deployment_tx(tx, &mapping.scope)?;
    if current.native_authority != *native
        || context_key(&current.native_authority, &current.security_context)? != key
    {
        return Err(refused("native capture routing changed"));
    }
    if required || current.setup_policy.is_some() {
        Ok(Some(mapping.scope))
    } else {
        Ok(None)
    }
}
