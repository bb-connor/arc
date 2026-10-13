//! Immutable original verification roots, separate from the current deployment.
use super::*;
use chio_core::recovery::RecoveryDigestDomain;

#[path = "original_installation.rs"]
mod original_installation;

pub(in crate::admission_operation_store) const SQL: &str =
    include_str!("../../recovery_deployment_history.sql");

#[cfg(feature = "admission-test-support")]
#[path = "legacy_restore_actor_trace.rs"]
mod legacy_restore_actor_trace;

fn key(
    scope: &RecoveryScopeV1,
    digest: DeploymentDigest,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "deployment-history:{}:{}",
        scope_key(scope)?,
        hex(digest.as_bytes())
    ))
}

pub(super) fn retain(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &RecoveryDeploymentV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let digest = DeploymentDigest::from_bytes(hash(RecoveryDigestDomain::Deployment, profile)?);
    let key = key(&profile.scope, digest)?;
    let bytes = encode(profile)?;
    if let Some(existing) = raw(tx, &key)? {
        if existing.version != 1
            || existing.kind != "deployment"
            || existing.scope != scope_key(&profile.scope)?
            || existing.payload != bytes
        {
            return Err(invariant("recovery immutable deployment custody changed"));
        }
        return Ok(false);
    }
    save(
        tx,
        owner,
        &key,
        &scope_key(&profile.scope)?,
        "deployment",
        &bytes,
        None,
    )?;
    Ok(true)
}

/// Retain both sides before replacing current configuration. This also
/// preserves a legitimate schema35 current profile before its first rotation.
pub(super) fn preserve_installation(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &RecoveryDeploymentV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let mut changed = false;
    if raw(tx, &format!("deployment:{}", scope_key(&profile.scope)?))?.is_some() {
        changed |= retain(tx, owner, &deployment_tx(tx, &profile.scope)?)?;
    }
    changed |= retain(tx, owner, profile)?;
    Ok(changed)
}

pub(super) fn lookup(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    fence: &StoreMutationFence,
) -> Result<RecoveryCapturedDeploymentV1, AdmissionOperationStoreError> {
    let digest = record.deployment_digest;
    if record
        .captured_deployment
        .as_ref()
        .is_some_and(|reference| {
            reference.deployment_digest != digest || reference.record_version.get() != 1
        })
    {
        return Err(invariant("recovery captured deployment reference changed"));
    }
    let profile = if let Some(row) = raw_checked(tx, &key(&record.scope, digest)?)? {
        if row.version != 1 || row.kind != "deployment" || row.scope != scope_key(&record.scope)? {
            return Err(invariant("recovery historical deployment version changed"));
        }
        decode::<RecoveryDeploymentV1>(&row.payload)?
    } else {
        if record.captured_deployment.is_some() {
            return Err(invariant("required captured deployment custody is absent"));
        }
        let current = deployment_tx(tx, &record.scope)?;
        if DeploymentDigest::from_bytes(hash(RecoveryDigestDomain::Deployment, &current)?) != digest
        {
            return Ok(RecoveryCapturedDeploymentV1::LegacyUnavailable);
        }
        current
    };
    if profile.scope != record.scope
        || DeploymentDigest::from_bytes(hash(RecoveryDigestDomain::Deployment, &profile)?) != digest
    {
        return Err(invariant("recovery historical deployment digest changed"));
    }
    validate_deployment(&profile, fence)?;
    super::super::security_participant_state::verify_recovery_initialization(
        tx,
        &profile.native_authority,
    )?;
    Ok(RecoveryCapturedDeploymentV1::Verified(Box::new(profile)))
}

/// Select a retained deployment by its exact installation before the first
/// original record commit. The caller validates original record purpose and
/// authorization within its already authenticated authority transaction.
pub(in crate::admission_operation_store) fn original_record_deployment(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    original_key: &str,
) -> Result<Option<RecoveryDeploymentV1>, AdmissionOperationStoreError> {
    original_installation::for_record(tx, scope, original_key)
}

/// Resolve an old restore actor after the caller checks the original opaque
/// capability, complete restore identity and purpose. No authority is minted.
pub(in crate::admission_operation_store) fn original_restore_actor(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    restore_key: &str,
    supplied_subject: &chio_core::PublicKey,
) -> Result<
    Option<(chio_security_types::PrincipalId, AuthorityScopeDigest)>,
    AdmissionOperationStoreError,
> {
    #[cfg(feature = "admission-test-support")]
    legacy_restore_actor_trace::entered();
    let prefix = format!("knowledge-restore:{}:", scope_key(scope)?);
    if restore_key.strip_prefix(&prefix).is_none_or(str::is_empty) {
        return Err(invariant("legacy restore original scope changed"));
    }
    let Some(profile) = original_record_deployment(tx, scope, restore_key)? else {
        return Ok(None);
    };
    let mut assignments = profile.actors.as_slice().iter().filter(|assignment| {
        &assignment.subject == supplied_subject
            && assignment
                .permissions
                .as_slice()
                .contains(&RecoveryPermission::KnowledgeRead)
    });
    let Some(original) = assignments.next() else {
        return Ok(None);
    };
    if assignments.next().is_some() {
        return Err(invariant("legacy restore original actor is ambiguous"));
    }
    Ok(Some((original.principal.clone(), profile.authority_scope)))
}
