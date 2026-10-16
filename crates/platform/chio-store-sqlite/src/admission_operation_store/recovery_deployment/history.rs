//! Immutable deployment verification roots, retained beside the current
//! deployment. Each installed profile is retained once at version 1.

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_kernel::recovery::RecoveryDeploymentV1;
use rusqlite::Transaction;

use crate::serving_owner::SqliteServingOwner;

use super::super::invariant;
use super::super::recovery_records::{
    encode_protected, load_record, protected_scope_key, ProtectedRecordKind, ProtectedWrite,
    RecordKind,
};
use super::{
    current_deployment, current_key, deployment_digest, digest_hex, planning, HISTORY_PREFIX,
};

fn history_key(
    profile: &RecoveryDeploymentV1,
) -> Result<(String, String), AdmissionOperationStoreError> {
    let scope = protected_scope_key(&profile.scope)?;
    let key = format!(
        "{HISTORY_PREFIX}{scope}:{}",
        digest_hex(deployment_digest(profile)?.as_bytes())
    );
    Ok((key, scope))
}

/// Retain `profile` as an immutable root, or confirm its exact retained bytes.
fn retain(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &RecoveryDeploymentV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let (key, scope) = history_key(profile)?;
    let bytes = encode_protected(profile)?;
    if let Some(existing) = load_record(tx, &key)? {
        if existing.version != 1
            || existing.kind != RecordKind::Deployment
            || existing.scope != scope
            || existing.payload != bytes
        {
            return Err(invariant("recovery immutable deployment custody changed"));
        }
        return Ok(false);
    }
    planning::save_planned(
        tx,
        owner,
        profile,
        &ProtectedWrite {
            key: &key,
            scope: &scope,
            kind: ProtectedRecordKind::Deployment,
            payload: &bytes,
        },
    )?;
    Ok(true)
}

/// Retain the prior current profile and the new profile before the current
/// deployment changes. Returns whether any root was newly retained.
pub(super) fn preserve_installation(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    profile: &RecoveryDeploymentV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let mut changed = false;
    let current = current_key(&protected_scope_key(&profile.scope)?);
    if load_record(tx, &current)?.is_some() {
        changed |= retain(tx, owner, &current_deployment(tx, &profile.scope)?)?;
    }
    changed |= retain(tx, owner, profile)?;
    Ok(changed)
}
