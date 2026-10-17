//! Canonical installation identities and immutable native route ownership.
use chio_core::recovery::semantic_content_digest;
use chio_kernel::admission_operation::NativeSecurityAuthorityBindingV1;
use chio_kernel::recovery::recovery_flow_key;
use chio_kernel::SecurityInvocationContext;
use chio_security_types::recovery::{
    AuthorityDomainId, ProtectedText, RecoveryScopeV1, RecoveryTenantId,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::super::recovery_records::{
    decode_protected_payload, encode_protected, load_record, protected_scope_key,
    require_latest_projection_head, ProtectedRecord, RecordKind,
};
use super::{invariant, AdmissionOperationStoreError, NativeSemanticInstallation};

pub(super) const CURRENT_PREFIX: &str = "semantic-deployment:";
pub(super) const HISTORY_PREFIX: &str = "semantic-deployment-history:";
pub(super) const ROUTE_PREFIX: &str = "semantic-route:";

pub(super) fn current_key(scope: &RecoveryScopeV1) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!("{CURRENT_PREFIX}{}", protected_scope_key(scope)?))
}

pub(super) fn history_key(
    installation: &NativeSemanticInstallation,
) -> Result<String, AdmissionOperationStoreError> {
    let digest = semantic_content_digest(installation)
        .map_err(|_| invariant("semantic installation digest refused"))?;
    Ok(format!(
        "{HISTORY_PREFIX}{}:{}",
        protected_scope_key(&installation.deployment.body().scope)?,
        hex::encode(digest.as_bytes()),
    ))
}

/// The scoped owner of one exact native route remains reserved after removal.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteOwnership {
    pub scope: RecoveryScopeV1,
    pub native_authority: NativeSecurityAuthorityBindingV1,
    pub security_context: SecurityInvocationContext,
    pub server: ProtectedText<128>,
    pub tool: ProtectedText<128>,
}

impl RouteOwnership {
    pub(super) fn key(&self) -> Result<String, AdmissionOperationStoreError> {
        let digest = chio_core::sha256_hex(&encode_protected(&(
            self.native_authority.security_authority_id(),
            recovery_flow_key(&self.security_context),
            self.security_context.as_v1().context_generation(),
            self.server.as_str(),
            self.tool.as_str(),
        ))?);
        Ok(format!("{ROUTE_PREFIX}{digest}"))
    }

    fn validate(&self, domain: &AuthorityDomainId) -> Result<(), AdmissionOperationStoreError> {
        if self.scope.authority_domain != *domain
            || self.native_authority.store_uuid().as_str() != domain.as_str()
            || self.scope.tenant_id.as_str() != self.security_context.as_v1().tenant_id().as_str()
        {
            return Err(invariant("semantic route scope differs"));
        }
        Ok(())
    }
}

pub(super) fn planning_tenant(
    key: &str,
    scope: &str,
    kind: RecordKind,
    payload: &[u8],
    domain: &AuthorityDomainId,
) -> Result<RecoveryTenantId, AdmissionOperationStoreError> {
    if kind != RecordKind::Deployment {
        return Err(invariant("semantic planning record kind differs"));
    }
    let owner = if key.starts_with(ROUTE_PREFIX) {
        let route: RouteOwnership = decode_protected_payload(payload)?;
        route.validate(domain)?;
        if route.key()? != key {
            return Err(invariant("semantic planning route identity differs"));
        }
        route.scope
    } else {
        let installation: NativeSemanticInstallation = decode_protected_payload(payload)?;
        installation.validate_binding(domain)?;
        let expected = if key.starts_with(CURRENT_PREFIX) {
            current_key(&installation.deployment.body().scope)?
        } else if key.starts_with(HISTORY_PREFIX) {
            history_key(&installation)?
        } else {
            return Err(invariant("semantic planning namespace refused"));
        };
        if key != expected {
            return Err(invariant("semantic planning installation identity differs"));
        }
        installation.deployment.body().scope.clone()
    };
    if protected_scope_key(&owner)? != scope {
        return Err(invariant("semantic planning record scope differs"));
    }
    Ok(owner.tenant_id)
}

pub(super) fn load_owned(
    tx: &Connection,
    key: &str,
    scope: &str,
) -> Result<Option<ProtectedRecord>, AdmissionOperationStoreError> {
    let Some(record) = load_record(tx, key)? else {
        return Ok(None);
    };
    if record.kind != RecordKind::Deployment || record.scope != scope || record.native.is_some() {
        return Err(invariant("semantic protected record ownership differs"));
    }
    require_latest_projection_head(tx, &record)?;
    Ok(Some(record))
}
