//! The v1 planning allocation of deployment records. One global and one
//! tenant allocation account for every current and historical deployment
//! write of this authority; both start empty and count authenticated events.

use std::collections::{BTreeMap, BTreeSet};

use chio_core::recovery::RecoveryDigestDomain;
use chio_core::sha256_hex;
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use chio_kernel::recovery::{recovery_authority_scope_digest, RecoveryDeploymentV1};
use chio_security_types::recovery::{
    AuthorityDomainId, ContractDigest, RecoveryTenantId, SafeInteger,
};
use rusqlite::{Connection, Transaction};
use serde::{Deserialize, Serialize};

use crate::serving_owner::SqliteServingOwner;

use super::super::recovery_records::{
    decode_protected_payload, encode_protected, first_version_retains, load_record,
    persist_protected_record, protected_scope_key, ProtectedRecord, ProtectedRecordKind,
    ProtectedWrite, RecordKind,
};
use super::super::recovery_resources::{require_recovery_floor, RecoveryPressureStage};
use super::super::{invariant, sqlite_error, stored_u64};
use super::{current_key, deployment_digest, digest, digest_hex, CURRENT_PREFIX, HISTORY_PREFIX};

const QUOTA_PREFIX: &str = "recovery-planning-quota:";
const MAX_METADATA_BYTES: usize = 1024;
const GLOBAL_BYTES: u64 = 48 * 1024 * 1024;
const TENANT_BYTES: u64 = 24 * 1024 * 1024;
const GLOBAL_EVENTS: u64 = 57344;
const TENANT_EVENTS: u64 = 28672;
const MAX_DATA_RECORDS: u64 = 2 * GLOBAL_EVENTS + 128;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanningBudget {
    schema: PlanningBudgetSchema,
    authority_domain: AuthorityDomainId,
    tenant_id: Option<RecoveryTenantId>,
    writes: SafeInteger,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
enum PlanningBudgetSchema {
    #[serde(rename = "chio.recovery.planning-reservation.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Usage {
    bytes: u64,
    events: u64,
}

impl Usage {
    fn add(&mut self, bytes: u64, events: u64) -> Result<(), AdmissionOperationStoreError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invariant("recovery planning bytes exhausted"))?;
        self.events = self
            .events
            .checked_add(events)
            .ok_or_else(|| invariant("recovery planning events exhausted"))?;
        Ok(())
    }
}

struct Inventory {
    global: Usage,
    tenants: BTreeMap<RecoveryTenantId, Usage>,
}

fn metadata_scope(
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(sha256_hex(&encode_protected(&(
        RecoveryDigestDomain::PlanningOwner.name(),
        domain,
        tenant,
    ))?))
}

fn metadata_key(
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
) -> Result<String, AdmissionOperationStoreError> {
    let domain_hash = sha256_hex(&encode_protected(domain)?);
    Ok(match tenant {
        None => format!("{QUOTA_PREFIX}{domain_hash}:global"),
        Some(tenant) => format!(
            "{QUOTA_PREFIX}{domain_hash}:tenant:{}",
            sha256_hex(&encode_protected(tenant)?)
        ),
    })
}

fn physical_domain(tx: &Connection) -> Result<AuthorityDomainId, AdmissionOperationStoreError> {
    let domain: String = tx
        .query_row(
            "SELECT store_uuid FROM main.chio_serving_owner WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    AuthorityDomainId::new(&domain)
        .map_err(|_| invariant("recovery planning physical owner refused"))
}

fn table_exists(tx: &Connection, name: &str) -> Result<bool, AdmissionOperationStoreError> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )
    .map_err(sqlite_error)
}

/// Whether any planning record, event or global reference exists. Before
/// the global chain is installed only an entirely empty recovery inventory
/// of a never-served owner passes.
fn any_planning_history(tx: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    if !table_exists(tx, "authority_global_commits")? {
        let retained: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM main.admission_operation_recovery_records)
                    OR EXISTS(SELECT 1 FROM main.admission_operation_recovery_events)
                    OR EXISTS(SELECT 1 FROM main.sqlite_schema
                              WHERE type = 'table' AND name = 'authority_global_commit_meta')",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if retained {
            return Err(invariant(
                "recovery history lost its global authority chain",
            ));
        }
        if table_exists(tx, "chio_serving_owner")? {
            let (epoch, lease): (i64, Option<String>) = tx
                .query_row(
                    "SELECT owner_epoch, lease_id FROM main.chio_serving_owner WHERE singleton = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(sqlite_error)?;
            if epoch != 0 || lease.is_some() {
                return Err(invariant(
                    "established recovery owner lost its global authority chain",
                ));
            }
        }
        return Ok(false);
    }
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.admission_operation_recovery_records
                WHERE record_key GLOB 'recovery-planning-quota:*'
                   OR record_key GLOB 'deployment:*' OR record_key GLOB 'deployment-history:*'
                   OR record_key GLOB 'semantic-deployment:*'
                   OR record_key GLOB 'semantic-deployment-history:*'
                   OR record_key GLOB 'semantic-route:*')
            OR EXISTS(SELECT 1 FROM main.admission_operation_recovery_events
                WHERE record_key GLOB 'recovery-planning-quota:*'
                   OR record_key GLOB 'deployment:*' OR record_key GLOB 'deployment-history:*'
                   OR record_key GLOB 'semantic-deployment:*'
                   OR record_key GLOB 'semantic-deployment-history:*'
                   OR record_key GLOB 'semantic-route:*')
            OR EXISTS(SELECT 1 FROM main.authority_global_commits
                WHERE projection_kind = 'recovery'
                  AND (projection_key GLOB 'recovery-planning-quota:*'
                       OR projection_key GLOB 'deployment:*'
                       OR projection_key GLOB 'deployment-history:*'
                       OR projection_key GLOB 'semantic-deployment:*'
                       OR projection_key GLOB 'semantic-deployment-history:*'
                       OR projection_key GLOB 'semantic-route:*'))",
        [],
        |row| row.get(0),
    )
    .map_err(sqlite_error)
}

/// The tenant a planned deployment record belongs to, after its key, kind,
/// physical owner, tenant, authority scope and contract bindings match.
fn data_tenant(
    key: &str,
    scope: &str,
    kind: RecordKind,
    profile: &RecoveryDeploymentV1,
    domain: &AuthorityDomainId,
) -> Result<RecoveryTenantId, AdmissionOperationStoreError> {
    if kind != RecordKind::Deployment {
        return Err(invariant("recovery planning record kind changed"));
    }
    let scope_hash = protected_scope_key(&profile.scope)?;
    let expected = if key.starts_with(HISTORY_PREFIX) {
        format!(
            "{HISTORY_PREFIX}{scope_hash}:{}",
            digest_hex(deployment_digest(profile)?.as_bytes())
        )
    } else if key.starts_with(CURRENT_PREFIX) {
        current_key(&scope_hash)
    } else {
        return Err(invariant("recovery planning namespace refused"));
    };
    if key != expected
        || profile.native_authority.store_uuid().as_str() != domain.as_str()
        || profile.security_context.as_v1().tenant_id().as_str() != profile.scope.tenant_id.as_str()
        || profile.authority_scope
            != recovery_authority_scope_digest(profile)
                .map_err(|_| invariant("recovery planning profile binding refused"))?
        || profile.contract_digest
            != ContractDigest::from_bytes(digest(
                RecoveryDigestDomain::EffectContract,
                &profile.effect_contract,
            )?)
    {
        return Err(invariant("recovery planning deployment binding changed"));
    }
    if profile.scope.authority_domain != *domain || scope_hash != scope {
        return Err(invariant("recovery planning scope changed"));
    }
    Ok(profile.scope.tenant_id.clone())
}

fn record_tenant(
    key: &str,
    scope: &str,
    kind: RecordKind,
    payload: &[u8],
    domain: &AuthorityDomainId,
) -> Result<RecoveryTenantId, AdmissionOperationStoreError> {
    if super::super::semantic_deployment::owns_planning_key(key) {
        super::super::semantic_deployment::planning_tenant(key, scope, kind, payload, domain)
    } else {
        let profile: RecoveryDeploymentV1 = decode_protected_payload(payload)?;
        data_tenant(key, scope, kind, &profile, domain)
    }
}

fn mutable_planning_key(key: &str) -> bool {
    key.starts_with(CURRENT_PREFIX) || super::super::semantic_deployment::mutable_planning_key(key)
}

fn inventory(
    tx: &Connection,
    domain: &AuthorityDomainId,
) -> Result<Inventory, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key GLOB 'deployment:*' OR record_key GLOB 'deployment-history:*'
                   OR record_key GLOB 'semantic-deployment:*'
                   OR record_key GLOB 'semantic-deployment-history:*'
                   OR record_key GLOB 'semantic-route:*'
             ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let mut inventory = Inventory {
        global: Usage::default(),
        tenants: BTreeMap::new(),
    };
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?;
    for (index, key) in keys.enumerate() {
        if u64::try_from(index)
            .ok()
            .is_none_or(|index| index >= MAX_DATA_RECORDS)
        {
            return Err(invariant("recovery planning inventory exhausted"));
        }
        let key = key.map_err(sqlite_error)?;
        let record = load_record(tx, &key)?
            .ok_or_else(|| invariant("recovery planning projection disappeared"))?;
        let tenant = record_tenant(&key, &record.scope, record.kind, &record.payload, domain)?;
        if !mutable_planning_key(&key) && record.version != 1 {
            return Err(invariant("recovery immutable planning record changed"));
        }
        let events: i64 = tx
            .query_row(
                "SELECT count(*) FROM main.admission_operation_recovery_events
                 WHERE record_key = ?1",
                [&key],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let events = stored_u64(events, "recovery planning events")?;
        if events != record.version {
            return Err(invariant("recovery planning history coverage changed"));
        }
        let bytes = u64::try_from(record.payload.len())
            .map_err(|_| invariant("recovery planning payload refused"))?;
        inventory.global.add(bytes, events)?;
        inventory
            .tenants
            .entry(tenant)
            .or_default()
            .add(bytes, events)?;
    }
    Ok(inventory)
}

const fn ceilings(tenant: bool) -> (u64, u64) {
    if tenant {
        (TENANT_BYTES, TENANT_EVENTS)
    } else {
        (GLOBAL_BYTES, GLOBAL_EVENTS)
    }
}

/// The retained allocation of `tenant` (or the global one), checked against
/// the authenticated usage it accounts for and against its exact first write.
fn load(
    tx: &Connection,
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
    usage: &Usage,
) -> Result<Option<PlanningBudget>, AdmissionOperationStoreError> {
    let Some((budget, record)) = peek(tx, domain, tenant)? else {
        return Ok(None);
    };
    let (byte_ceiling, event_ceiling) = ceilings(tenant.is_some());
    if budget.writes.get() == 0
        || budget.writes.get() != record.version
        || usage.events != budget.writes.get()
        || usage.bytes > byte_ceiling
        || budget.writes.get() > event_ceiling
    {
        return Err(invariant("recovery planning quota counters changed"));
    }
    let mut first = budget.clone();
    first.writes = SafeInteger::new(1).map_err(|_| invariant("recovery planning unit refused"))?;
    let first = encode_protected(&first)?;
    let retained = first_version_retains(
        tx,
        &ProtectedWrite {
            key: &record.key,
            scope: &record.scope,
            kind: ProtectedRecordKind::Command,
            payload: &first,
        },
    )?;
    if !retained {
        return Err(invariant("recovery planning baseline changed"));
    }
    Ok(Some(budget))
}

fn peek(
    tx: &Connection,
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
) -> Result<Option<(PlanningBudget, ProtectedRecord)>, AdmissionOperationStoreError> {
    let Some(record) = load_record(tx, &metadata_key(domain, tenant)?)? else {
        return Ok(None);
    };
    if record.payload.len() > MAX_METADATA_BYTES
        || record.scope != metadata_scope(domain, tenant)?
        || record.kind != RecordKind::Command
    {
        return Err(invariant("recovery planning quota is corrupt"));
    }
    let budget: PlanningBudget = record.decode_payload()?;
    if budget.authority_domain != *domain || budget.tenant_id.as_ref() != tenant {
        return Err(invariant("recovery planning quota owner changed"));
    }
    Ok(Some((budget, record)))
}

fn new_budget(
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
    usage: &Usage,
) -> Result<PlanningBudget, AdmissionOperationStoreError> {
    if *usage != Usage::default() {
        return Err(invariant("recovery planning tenant lost its allocation"));
    }
    Ok(PlanningBudget {
        schema: PlanningBudgetSchema::V1,
        authority_domain: domain.clone(),
        tenant_id: tenant.cloned(),
        writes: SafeInteger::ZERO,
    })
}

/// Charge one write that replaces `old_bytes` with `new_bytes`.
fn next_budget(
    budget: &mut PlanningBudget,
    usage: &Usage,
    old_bytes: u64,
    new_bytes: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let next_bytes = usage
        .bytes
        .checked_sub(old_bytes)
        .and_then(|bytes| bytes.checked_add(new_bytes))
        .ok_or_else(|| invariant("recovery planning next bytes refused"))?;
    let next_events = usage
        .events
        .checked_add(1)
        .ok_or_else(|| invariant("recovery planning next events refused"))?;
    let (byte_ceiling, event_ceiling) = ceilings(budget.tenant_id.is_some());
    if next_bytes > byte_ceiling || next_events > event_ceiling {
        return Err(invariant(if budget.tenant_id.is_some() {
            "recovery tenant planning resource exhausted"
        } else {
            "recovery planning resource exhausted"
        }));
    }
    budget.writes = budget
        .writes
        .get()
        .checked_add(1)
        .and_then(|writes| SafeInteger::new(writes).ok())
        .ok_or_else(|| invariant("recovery planning write count exhausted"))?;
    Ok(())
}

fn persist_budget(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    budget: &PlanningBudget,
) -> Result<(), AdmissionOperationStoreError> {
    let payload = encode_protected(budget)?;
    if payload.len() > MAX_METADATA_BYTES || budget.writes.get() == 0 {
        return Err(invariant("recovery planning quota resource exhausted"));
    }
    let key = metadata_key(&budget.authority_domain, budget.tenant_id.as_ref())?;
    let scope = metadata_scope(&budget.authority_domain, budget.tenant_id.as_ref())?;
    persist_protected_record(
        tx,
        owner,
        &ProtectedWrite {
            key: &key,
            scope: &scope,
            kind: ProtectedRecordKind::Command,
            payload: &payload,
        },
    )
    .map(|_| ())
}

/// Persist one deployment record and charge both allocations atomically.
/// Only current installation projections may be rewritten.
pub(in crate::admission_operation_store) fn save_planned(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    write: &ProtectedWrite<'_>,
) -> Result<(), AdmissionOperationStoreError> {
    let domain = physical_domain(tx)?;
    if domain.as_str() != owner.fence.store_uuid {
        return Err(invariant("recovery planning writer owner changed"));
    }
    if write.kind != ProtectedRecordKind::Deployment {
        return Err(invariant("recovery planning record kind changed"));
    }
    let selected = record_tenant(
        write.key,
        write.scope,
        RecordKind::Deployment,
        write.payload,
        &domain,
    )?;
    require_recovery_floor(tx, RecoveryPressureStage::Intake)?;
    let existing = load_record(tx, write.key)?;
    if let Some(record) = &existing {
        if record.scope != write.scope
            || record.kind != RecordKind::Deployment
            || !mutable_planning_key(write.key)
        {
            return Err(invariant("recovery planning immutable identity changed"));
        }
        record_tenant(
            write.key,
            &record.scope,
            record.kind,
            &record.payload,
            &domain,
        )?;
    }
    let retained_global = peek(tx, &domain, None)?;
    if retained_global.is_none() && any_planning_history(tx)? {
        return Err(invariant("recovery planning global allocation disappeared"));
    }
    let before = inventory(tx, &domain)?;
    let mut global = if retained_global.is_some() {
        load(tx, &domain, None, &before.global)?
            .ok_or_else(|| invariant("recovery planning global allocation disappeared"))?
    } else {
        new_budget(&domain, None, &before.global)?
    };
    let empty = Usage::default();
    let tenant_usage = before.tenants.get(&selected).unwrap_or(&empty);
    let mut tenant = match load(tx, &domain, Some(&selected), tenant_usage)? {
        Some(tenant) => tenant,
        None => new_budget(&domain, Some(&selected), tenant_usage)?,
    };
    let old_bytes = existing.as_ref().map_or(Ok(0), |record| {
        u64::try_from(record.payload.len())
            .map_err(|_| invariant("recovery planning payload refused"))
    })?;
    let new_bytes = u64::try_from(write.payload.len())
        .map_err(|_| invariant("recovery planning payload refused"))?;
    next_budget(&mut global, &before.global, old_bytes, new_bytes)?;
    next_budget(&mut tenant, tenant_usage, old_bytes, new_bytes)?;
    persist_protected_record(tx, owner, write)?;
    persist_budget(tx, owner, &global)?;
    persist_budget(tx, owner, &tenant)?;
    let after = inventory(tx, &domain)?;
    load(tx, &domain, None, &after.global)?
        .ok_or_else(|| invariant("recovery planning global allocation disappeared"))?;
    load(
        tx,
        &domain,
        Some(&selected),
        after
            .tenants
            .get(&selected)
            .ok_or_else(|| invariant("recovery planning tenant data disappeared"))?,
    )?
    .ok_or_else(|| invariant("recovery planning tenant allocation disappeared"))?;
    Ok(())
}

/// Startup verification of every planning allocation against the
/// authenticated deployment inventory. It never allocates.
pub(in crate::admission_operation_store) fn verify_planning_allocations(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    if !any_planning_history(tx)? {
        return Ok(());
    }
    let domain = physical_domain(tx)?;
    let inventory = inventory(tx, &domain)?;
    let global = load(tx, &domain, None, &inventory.global)?
        .ok_or_else(|| invariant("recovery planning global allocation disappeared"))?;
    let global_key = metadata_key(&domain, None)?;
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM main.admission_operation_recovery_records
             WHERE record_key GLOB 'recovery-planning-quota:*' ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let keys = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?;
    let mut tenants = BTreeSet::new();
    for (index, key) in keys.enumerate() {
        if u64::try_from(index)
            .ok()
            .is_none_or(|index| index > global.writes.get())
        {
            return Err(invariant("recovery planning quota inventory exhausted"));
        }
        let key = key.map_err(sqlite_error)?;
        if key == global_key {
            continue;
        }
        let record = load_record(tx, &key)?
            .ok_or_else(|| invariant("recovery planning quota disappeared"))?;
        if record.payload.len() > MAX_METADATA_BYTES {
            return Err(invariant("recovery planning quota resource exhausted"));
        }
        let budget: PlanningBudget = record.decode_payload()?;
        let tenant = budget
            .tenant_id
            .ok_or_else(|| invariant("recovery planning duplicate global quota"))?;
        if key != metadata_key(&domain, Some(&tenant))? || !tenants.insert(tenant.clone()) {
            return Err(invariant("recovery planning tenant allocation changed"));
        }
        let usage = inventory
            .tenants
            .get(&tenant)
            .ok_or_else(|| invariant("recovery planning tenant data disappeared"))?;
        load(tx, &domain, Some(&tenant), usage)?
            .ok_or_else(|| invariant("recovery planning tenant allocation disappeared"))?;
    }
    if inventory
        .tenants
        .keys()
        .any(|tenant| !tenants.contains(tenant))
    {
        return Err(invariant("recovery planning tenant allocation disappeared"));
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "planning_tests.rs"]
mod tests;
