//! Trusted operator installation and rotation of one scoped recovery
//! deployment, together with its native setup routing, immutable deployment
//! history and planning allocation, in one fenced owning transaction.

use std::collections::BTreeSet;

use chio_core::recovery::RecoveryDigestDomain;
use chio_kernel::admission_operation::{AdmissionOperationStoreError, StoreMutationFence};
use chio_kernel::recovery::{
    recovery_authority_scope_digest, recovery_digest, RecoveryDeploymentV1,
};
use chio_security_types::flow::InformationLabel;
use chio_security_types::recovery::{
    AuthorityObligationV1, ContractDigest, DeploymentDigest, RecoveryScopeV1,
};
use rusqlite::Connection;
use serde::Serialize;

use super::recovery_records::{
    encode_protected, load_record, protected_scope_key, ProtectedRecordKind, ProtectedWrite,
};
use super::recovery_resources::{require_recovery_floor_before_transaction, RecoveryPressureStage};
use super::{invariant, sqlite_error, SqliteAdmissionOperationStore};

mod history;
mod planning;
#[cfg(all(test, unix))]
mod tests;

pub(super) use planning::verify_planning_allocations;

const CURRENT_PREFIX: &str = "deployment:";
const HISTORY_PREFIX: &str = "deployment-history:";
const MAX_RESPONSE_BYTES: u64 = 65536;

impl SqliteAdmissionOperationStore {
    /// Trusted operator setup installs or rotates one scoped deployment.
    /// Every pending action revalidates the current assignment and profile
    /// digest; this call grants no execution, capture or funding authority.
    pub fn configure_recovery_deployment(
        &self,
        deployment: &RecoveryDeploymentV1,
    ) -> Result<(), AdmissionOperationStoreError> {
        validate_deployment_installation(deployment, &self.serving_owner.fence)?;
        let mut connection = self.connection()?;
        require_recovery_floor_before_transaction(&connection, RecoveryPressureStage::Intake)?;
        let tx = self.begin_write(&mut connection, None)?;
        super::security_participant_state::verify_recovery_initialization(
            &tx,
            &deployment.native_authority,
        )?;
        let scope = protected_scope_key(&deployment.scope)?;
        let key = current_key(&scope);
        let encoded = encode_protected(deployment)?;
        let context_changed =
            super::setup::register_native_setup_context(&tx, &self.serving_owner, deployment)?;
        let history_changed = history::preserve_installation(&tx, &self.serving_owner, deployment)?
            || context_changed;
        if load_record(&tx, &key)?.is_some_and(|current| current.payload == encoded) {
            if history_changed {
                self.commit_write(tx)?;
                self.sync_after_write(&connection)?;
            } else {
                tx.commit().map_err(sqlite_error)?;
            }
            return Ok(());
        }
        planning::save_planned(
            &tx,
            &self.serving_owner,
            deployment,
            &ProtectedWrite {
                key: &key,
                scope: &scope,
                kind: ProtectedRecordKind::Deployment,
                payload: &encoded,
            },
        )?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
}

pub(super) fn current_key(scope: &str) -> String {
    format!("{CURRENT_PREFIX}{scope}")
}

fn digest<T: Serialize>(
    domain: RecoveryDigestDomain,
    value: &T,
) -> Result<[u8; 32], AdmissionOperationStoreError> {
    recovery_digest(domain, value).map_err(|_| invariant("recovery digest refused"))
}

fn deployment_digest(
    profile: &RecoveryDeploymentV1,
) -> Result<DeploymentDigest, AdmissionOperationStoreError> {
    digest(RecoveryDigestDomain::Deployment, profile).map(DeploymentDigest::from_bytes)
}

fn digest_hex(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// The current deployment of `scope`, decoded from its exact canonical bytes.
fn current_deployment(
    tx: &Connection,
    scope: &RecoveryScopeV1,
) -> Result<RecoveryDeploymentV1, AdmissionOperationStoreError> {
    let record = load_record(tx, &current_key(&protected_scope_key(scope)?))?
        .ok_or_else(|| invariant("recovery profile is unsupported"))?;
    let deployment: RecoveryDeploymentV1 = record.decode_payload()?;
    if deployment.scope != *scope {
        return Err(invariant("recovery scope changed"));
    }
    Ok(deployment)
}

/// Structural and binding checks of one deployment against this authority.
pub(super) fn validate_deployment(
    profile: &RecoveryDeploymentV1,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    let context = profile.security_context.as_v1();
    if profile.scope.authority_domain.as_str() != fence.store_uuid
        || profile.native_authority.store_uuid().as_str() != fence.store_uuid
        || profile.scope.tenant_id.as_str() != context.tenant_id().as_str()
        || profile.recipient.as_str() != profile.server_id.as_str()
        || profile.effect_cardinality.get() != 1
        || profile.aggregate_issuer.algorithm() != chio_core::SigningAlgorithm::Ed25519
        || !(1..=MAX_RESPONSE_BYTES).contains(&profile.effect_contract.max_response_bytes.get())
        || !profile
            .effect_contract
            .resource
            .as_str()
            .starts_with("https://")
        || profile.contract_digest
            != ContractDigest::from_bytes(digest(
                RecoveryDigestDomain::EffectContract,
                &profile.effect_contract,
            )?)
        || profile.authority_scope
            != recovery_authority_scope_digest(profile)
                .map_err(|_| invariant("recovery scope digest refused"))?
    {
        return Err(invariant("recovery deployment refused"));
    }
    let mut subjects = BTreeSet::new();
    let mut principals = BTreeSet::new();
    for actor in profile.actors.as_slice() {
        let permissions = actor.permissions.as_slice();
        if !subjects.insert(actor.subject.to_hex())
            || !principals.insert(actor.principal.clone())
            || permissions.is_empty()
            || permissions
                .iter()
                .zip(permissions.iter().skip(1))
                .any(|(left, right)| left >= right)
        {
            return Err(invariant("recovery actor assignment refused"));
        }
    }
    let mut issuers = BTreeSet::new();
    let mut represented = BTreeSet::new();
    for coverage in profile.coverage.as_slice() {
        if !issuers.insert(coverage.issuer_id.clone())
            || !represented.insert(coverage.principal.clone())
            || coverage.obligations.as_slice().iter().any(|power| {
                !matches!(
                    power,
                    AuthorityObligationV1::OwnerRelease { .. }
                        | AuthorityObligationV1::CompartmentRelease { .. }
                )
            })
        {
            return Err(invariant("recovery coverage assignment refused"));
        }
    }
    Ok(())
}

/// Installation additionally refuses an unbounded preview clearance.
fn validate_deployment_installation(
    profile: &RecoveryDeploymentV1,
    fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationStoreError> {
    validate_deployment(profile, fence)?;
    if profile
        .actors
        .as_slice()
        .iter()
        .any(|actor| matches!(actor.preview_clearance, InformationLabel::Top))
    {
        return Err(invariant("recovery preview clearance refused"));
    }
    Ok(())
}
