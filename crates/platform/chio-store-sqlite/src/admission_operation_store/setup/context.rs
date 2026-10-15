//! Scope custody and native capture routing are independently authenticated.

use chio_core::sha256_hex;
use chio_kernel::admission_operation::{
    AdmissionOperationStoreError, NativeSecurityAuthorityBindingV1,
};
use chio_kernel::recovery::RecoveryDeploymentV1;
use chio_kernel::SecurityInvocationContext;
use chio_security_types::recovery::{
    AuthorityDomainId, RecoveryScopeV1, RecoveryTenantId, VersionV1,
};
use rusqlite::Transaction;
use serde::{Deserialize, Serialize};

use crate::serving_owner::SqliteServingOwner;

use super::super::recovery_records::{
    encode_protected, protected_scope_key, ProtectedRecordKind, ProtectedWrite, RecordKind,
};
use super::{authenticated_record, refused, save_setup_record, CONTEXT_PREFIX, TENANT_PREFIX};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSetupContextIndexV1 {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    native_authority: NativeSecurityAuthorityBindingV1,
    security_context: SecurityInvocationContext,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantSetupRequirementV1 {
    domain_version: VersionV1,
    authority_domain: AuthorityDomainId,
    tenant_id: RecoveryTenantId,
}

fn tenant_key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "{TENANT_PREFIX}{}",
        sha256_hex(&encode_protected(&(
            &scope.authority_domain,
            &scope.tenant_id
        ))?)
    ))
}

fn required_scope(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode_protected(&(
        &scope.authority_domain,
        &scope.tenant_id,
    ))?))
}

/// A configured tenant cannot remove its protection by selecting another process.
fn mark_tenant_required(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let key = tenant_key(scope)?;
    let marker_scope = required_scope(scope)?;
    let payload = encode_protected(&TenantSetupRequirementV1 {
        domain_version: VersionV1,
        authority_domain: scope.authority_domain.clone(),
        tenant_id: scope.tenant_id.clone(),
    })?;
    if let Some(row) = authenticated_record(tx, &key)? {
        if row.kind != RecordKind::Command
            || row.version != 1
            || row.scope != marker_scope
            || row.payload != payload
        {
            return Err(refused("tenant setup requirement changed"));
        }
        return Ok(false);
    }
    save_setup_record(
        tx,
        owner,
        &ProtectedWrite {
            key: &key,
            scope: &marker_scope,
            kind: ProtectedRecordKind::Command,
            payload: &payload,
        },
    )?;
    Ok(true)
}

/// Flow generation is a mutable source observation, not process identity.
fn context_key(
    native: &NativeSecurityAuthorityBindingV1,
    context: &SecurityInvocationContext,
) -> Result<String, AdmissionOperationStoreError> {
    let context = context.as_v1();
    Ok(format!(
        "{CONTEXT_PREFIX}{}",
        sha256_hex(&encode_protected(&(
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
/// Returns whether any setup record was newly written.
pub(in crate::admission_operation_store) fn register_native_setup_context(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    deployment: &RecoveryDeploymentV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let key = context_key(&deployment.native_authority, &deployment.security_context)?;
    let scope = protected_scope_key(&deployment.scope)?;
    let mut changed = false;
    if let Some(row) = authenticated_record(tx, &key)? {
        let prior: NativeSetupContextIndexV1 = row.decode_payload()?;
        if row.kind != RecordKind::Command
            || row.version != 1
            || row.scope != scope
            || prior.scope != deployment.scope
            || prior.native_authority != deployment.native_authority
            || context_key(&prior.native_authority, &prior.security_context)? != key
        {
            return Err(refused("native setup context has another owner"));
        }
    } else {
        let payload = encode_protected(&NativeSetupContextIndexV1 {
            domain_version: VersionV1,
            scope: deployment.scope.clone(),
            native_authority: deployment.native_authority.clone(),
            security_context: deployment.security_context.clone(),
        })?;
        save_setup_record(
            tx,
            owner,
            &ProtectedWrite {
                key: &key,
                scope: &scope,
                kind: ProtectedRecordKind::Command,
                payload: &payload,
            },
        )?;
        changed = true;
    }
    if deployment.setup_policy.is_some() {
        changed |= mark_tenant_required(tx, owner, &deployment.scope)?;
    }
    Ok(changed)
}
