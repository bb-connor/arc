//! Scoped textual identities never confer the identity of a signed capability.
use super::*;
use chio_security_types::ports::SessionId;

pub(super) fn root_scope(
    tx: &Connection,
    runtime: &str,
    root: &str,
) -> Result<Option<RecoveryScopeV1>, AdmissionOperationStoreError> {
    let runtime = SessionId::new(runtime).map_err(refused)?;
    // Ordinary process journals accept wider identifiers than recovery scopes.
    // Such a root has no recovery owner and retains its ordinary context.
    let Ok(root) = ProcessId::new(root) else {
        return Ok(None);
    };
    let owner = format!(
        "knowledge-owner:{}",
        sha256_hex(&protected::encode(&(&runtime, &root))?)
    );
    let scope = load::<RecoveryScopeV1>(tx, &owner)?;
    if let Some(scope) = &scope {
        let profile = super::super::installation(tx, scope)?;
        if scope.process_id != root
            || profile.scope != *scope
            || profile.producer_context.as_v1().session_id() != &runtime
            || physical_owner_key(&profile)? != owner
        {
            return Err(refused("confined root binding"));
        }
    }
    Ok(scope)
}

pub(super) fn capability_key(
    scope: &RecoveryScopeV1,
    capability: &CapabilityToken,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "confined-cap:{}:{}",
        scope_key(scope)?,
        sha256_hex(capability.id.as_bytes())
    ))
}

pub(super) fn token_key(
    capability: &CapabilityToken,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(digest_key(capability_digest(capability)?))
}

fn digest_key(digest: ConfinedCapabilityDigest) -> String {
    format!("confined-token:{}", hex::encode(digest.as_bytes()))
}

fn legacy_key(capability: &CapabilityToken) -> String {
    format!("confined-cap:{}", sha256_hex(capability.id.as_bytes()))
}

fn binding(
    tx: &Connection,
    index: &str,
) -> Result<Option<BoundaryRecord>, AdmissionOperationStoreError> {
    let Some(record_key) = load::<String>(tx, index)? else {
        return Ok(None);
    };
    let record: BoundaryRecord =
        load(tx, &record_key)?.ok_or_else(|| refused("boundary lookup"))?;
    let boundary = &record.reservation.boundary;
    if record_key != key(&boundary.scope, &boundary.request)? {
        return Err(refused("capability index binding"));
    }
    Ok(Some(record))
}

/// Complete signed-token lookup also detects attachment under another root or
/// runtime. The legacy textual index is relevant only for matching token bytes.
pub(super) fn whole_token(
    tx: &Connection,
    capability: &CapabilityToken,
) -> Result<Option<BoundaryRecord>, AdmissionOperationStoreError> {
    let digest = capability_digest(capability)?;
    if let Some(record) = binding(tx, &digest_key(digest))? {
        if record.reservation.boundary.child_capability != digest {
            return Err(refused("signed token index binding"));
        }
        return Ok(Some(record));
    }
    Ok(binding(tx, &legacy_key(capability))?
        .filter(|record| record.reservation.boundary.child_capability == digest))
}

pub(super) fn scoped_token(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    capability: &CapabilityToken,
) -> Result<Option<BoundaryRecord>, AdmissionOperationStoreError> {
    let Some(record) = binding(tx, &capability_key(scope, capability)?)? else {
        return Ok(None);
    };
    if record.reservation.boundary.scope != *scope {
        return Err(refused("scoped capability index binding"));
    }
    Ok(
        (record.reservation.boundary.child_capability == capability_digest(capability)?)
            .then_some(record),
    )
}

pub(super) fn require_unused(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    capability: &CapabilityToken,
) -> Result<(), AdmissionOperationStoreError> {
    if binding(tx, &capability_key(scope, capability)?)?.is_some()
        || whole_token(tx, capability)?.is_some()
        || binding(tx, &legacy_key(capability))?
            .is_some_and(|record| record.reservation.boundary.scope == *scope)
    {
        return Err(refused("child capability reused"));
    }
    Ok(())
}
