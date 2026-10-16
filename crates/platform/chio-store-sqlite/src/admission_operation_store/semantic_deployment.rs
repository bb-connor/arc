//! Atomic trusted installation of signed semantic registries and native routes.
use chio_kernel::admission_operation::{AdmissionOperationStoreError, StoreMutationFence};
use chio_kernel::recovery::recovery_flow_key;
use chio_security_types::recovery::{AuthorityDomainId, RecoveryScopeV1, RecoveryTenantId};
use rusqlite::{Connection, Transaction};

use super::recovery_records::{
    encode_protected, protected_scope_key, ProtectedRecordKind, ProtectedWrite, RecordKind,
};
use super::recovery_resources::{require_recovery_floor_before_transaction, RecoveryPressureStage};
use super::{invariant, sqlite_error, SqliteAdmissionOperationStore};
use crate::serving_owner::SqliteServingOwner;

mod installation;
mod records;

pub use installation::NativeSemanticInstallation;

pub(super) fn owns_planning_key(key: &str) -> bool {
    key.starts_with(records::CURRENT_PREFIX)
        || key.starts_with(records::HISTORY_PREFIX)
        || key.starts_with(records::ROUTE_PREFIX)
}

pub(super) fn mutable_planning_key(key: &str) -> bool {
    key.starts_with(records::CURRENT_PREFIX)
}

pub(super) fn planning_tenant(
    key: &str,
    scope: &str,
    kind: RecordKind,
    payload: &[u8],
    domain: &AuthorityDomainId,
) -> Result<RecoveryTenantId, AdmissionOperationStoreError> {
    records::planning_tenant(key, scope, kind, payload, domain)
}

fn physical_domain(
    owner: &SqliteServingOwner,
) -> Result<AuthorityDomainId, AdmissionOperationStoreError> {
    AuthorityDomainId::new(&owner.fence.store_uuid)
        .map_err(|_| invariant("semantic physical authority refused"))
}

fn require_history(
    tx: &Connection,
    value: &NativeSemanticInstallation,
) -> Result<(), AdmissionOperationStoreError> {
    let scope = protected_scope_key(&value.deployment.body().scope)?;
    let history = records::load_owned(tx, &records::history_key(value)?, &scope)?
        .ok_or_else(|| invariant("semantic installation history disappeared"))?;
    if history.version != 1 || history.payload != encode_protected(value)? {
        return Err(invariant("semantic installation history differs"));
    }
    Ok(())
}

fn require_routes(
    tx: &Connection,
    value: &NativeSemanticInstallation,
) -> Result<(), AdmissionOperationStoreError> {
    let scope = protected_scope_key(&value.deployment.body().scope)?;
    for route in value.deployment.body().routes.as_slice() {
        let claim = route_claim(value, route);
        let retained = records::load_owned(tx, &claim.key()?, &scope)?
            .ok_or_else(|| invariant("semantic route ownership disappeared"))?;
        if retained.version != 1 || retained.payload != encode_protected(&claim)? {
            return Err(invariant("semantic route ownership differs"));
        }
    }
    Ok(())
}

fn route_claim(
    value: &NativeSemanticInstallation,
    route: &chio_security_types::semantic::SemanticRouteV1,
) -> records::RouteOwnership {
    records::RouteOwnership {
        scope: value.deployment.body().scope.clone(),
        native_authority: value.native_authority.clone(),
        security_context: value.security_context.clone(),
        server: route.server.clone(),
        tool: route.tool.clone(),
    }
}

fn save(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    payload: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    super::recovery_deployment::planning::save_planned(
        tx,
        owner,
        &ProtectedWrite {
            key,
            scope,
            kind: ProtectedRecordKind::Deployment,
            payload,
        },
    )
}

impl SqliteAdmissionOperationStore {
    /// Trusted operator setup atomically installs a complete signed registry.
    /// Identical input preserves all versions and journal counts.
    pub fn configure_semantic_deployment(
        &self,
        expected_scope: &RecoveryScopeV1,
        value: &NativeSemanticInstallation,
    ) -> Result<(), AdmissionOperationStoreError> {
        let domain = physical_domain(&self.serving_owner)?;
        value.validate_binding(&domain)?;
        value.compile(expected_scope)?;
        let payload = encode_protected(value)?;
        let scope = protected_scope_key(&value.deployment.body().scope)?;
        let key = records::current_key(&value.deployment.body().scope)?;
        let mut connection = self.connection()?;
        require_recovery_floor_before_transaction(&connection, RecoveryPressureStage::Intake)?;
        let tx = self.begin_write(&mut connection, None)?;
        super::recovery_deployment::verify_planning_allocations(&tx)?;
        super::security_participant_state::verify_recovery_initialization(
            &tx,
            &value.native_authority,
        )?;
        if let Some(current) = records::load_owned(&tx, &key, &scope)? {
            let old: NativeSemanticInstallation = current.decode_payload()?;
            old.validate_binding(&domain)?;
            require_history(&tx, &old)?;
            require_routes(&tx, &old)?;
            if current.payload == payload {
                tx.commit().map_err(sqlite_error)?;
                return Ok(());
            }
            if value.deployment.body().generation <= old.deployment.body().generation
                || value.operator_root != old.operator_root
                || value.native_authority != old.native_authority
                || recovery_flow_key(&value.security_context)
                    != recovery_flow_key(&old.security_context)
            {
                return Err(invariant("semantic deployment generation or owner differs"));
            }
        }
        for route in value.deployment.body().routes.as_slice() {
            let claim = route_claim(value, route);
            let route_key = claim.key()?;
            let route_payload = encode_protected(&claim)?;
            if let Some(current) = records::load_owned(&tx, &route_key, &scope)? {
                if current.version != 1 || current.payload != route_payload {
                    return Err(invariant("semantic route ownership differs"));
                }
            } else {
                save(&tx, &self.serving_owner, &route_key, &scope, &route_payload)?;
            }
        }
        let history_key = records::history_key(value)?;
        if records::load_owned(&tx, &history_key, &scope)?.is_some() {
            return Err(invariant("semantic installation history identity reused"));
        }
        save(&tx, &self.serving_owner, &history_key, &scope, &payload)?;
        save(&tx, &self.serving_owner, &key, &scope, &payload)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }

    /// Trusted operator readback under the current serving fence and clock.
    pub fn read_semantic_installation(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeSemanticInstallation, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        super::verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        super::schema::authority_validation_time(&tx, now, &self.serving_owner)?;
        super::recovery_deployment::verify_planning_allocations(&tx)?;
        let key = records::current_key(scope)?;
        let record = records::load_owned(&tx, &key, &protected_scope_key(scope)?)?
            .ok_or_else(|| invariant("semantic deployment is absent"))?;
        let value: NativeSemanticInstallation = record.decode_payload()?;
        value.validate_binding(&physical_domain(&self.serving_owner)?)?;
        if value.deployment.body().scope != *scope {
            return Err(invariant("semantic deployment scope differs"));
        }
        super::security_participant_state::verify_recovery_initialization(
            &tx,
            &value.native_authority,
        )?;
        require_history(&tx, &value)?;
        require_routes(&tx, &value)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(value)
    }
}
