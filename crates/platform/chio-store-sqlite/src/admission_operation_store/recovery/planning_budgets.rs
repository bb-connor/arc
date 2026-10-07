//! Protected intake allocations with immutable compatible-history baselines.
use super::*;
use std::collections::BTreeMap;

#[cfg(test)]
#[path = "planning_reservation_tests.rs"]
mod planning_reservation_tests;

const MAX_METADATA_BYTES: usize = 1024;
const GLOBAL_BYTES: u64 = 48 * 1024 * 1024;
const TENANT_BYTES: u64 = 24 * 1024 * 1024;
const GLOBAL_EVENTS: u64 = 57344;
const TENANT_EVENTS: u64 = 28672;
const MAX_DATA_RECORDS: usize = 2 * GLOBAL_EVENTS as usize + 128;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanningBudget {
    schema: PlanningBudgetSchema,
    authority_domain: AuthorityDomainId,
    tenant_id: Option<RecoveryTenantId>,
    legacy_cutoff_sequence: SafeInteger,
    baseline_bytes: SafeInteger,
    baseline_events: SafeInteger,
    writes: SafeInteger,
}

#[derive(Clone, Serialize, Deserialize)]
enum PlanningBudgetSchema {
    #[serde(rename = "chio.recovery.planning-reservation.v1")]
    V1,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanningOrigin {
    scope: RecoveryScopeV1,
    workflow_id: WorkflowId,
    continuation_id: ContinuationId,
    origin: RecoveryOriginV1,
}

#[derive(Default)]
struct Usage {
    bytes: u64,
    events: u64,
    before_cutoff: u64,
}

impl Usage {
    fn add(
        &mut self,
        bytes: u64,
        events: u64,
        before_cutoff: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invariant("recovery planning bytes exhausted"))?;
        self.events = self
            .events
            .checked_add(events)
            .ok_or_else(|| invariant("recovery planning events exhausted"))?;
        self.before_cutoff = self
            .before_cutoff
            .checked_add(before_cutoff)
            .ok_or_else(|| invariant("recovery planning baseline exhausted"))?;
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
    Ok(sha256_hex(&encode(&(
        chio_core_types::recovery::RecoveryDigestDomain::PlanningOwner.name(),
        domain,
        tenant,
    ))?))
}

fn metadata_key(
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
) -> Result<String, AdmissionOperationStoreError> {
    let domain_hash = sha256_hex(&encode(domain)?);
    Ok(match tenant {
        None => format!("recovery-planning-quota:{domain_hash}:global"),
        Some(tenant) => format!(
            "recovery-planning-quota:{domain_hash}:tenant:{}",
            sha256_hex(&encode(tenant)?)
        ),
    })
}

fn physical_domain(tx: &Connection) -> Result<AuthorityDomainId, AdmissionOperationStoreError> {
    let domain: String = tx
        .query_row(
            "SELECT store_uuid FROM chio_serving_owner WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    AuthorityDomainId::new(&domain)
        .map_err(|_| invariant("recovery planning physical owner refused"))
}

fn any_metadata(tx: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    let global_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND lower(name)='authority_global_commits')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !global_exists {
        // Fresh owner provisioning verifies the admission schema before it
        // installs the global chain. Only an entirely empty recovery inventory
        // can pass that ordering; retained or partial authority state refuses.
        let retained: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records)
                OR EXISTS(SELECT 1 FROM admission_operation_recovery_events)
                OR EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND lower(name)='authority_global_commit_meta')",
            [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if retained {
            return Err(invariant(
                "recovery history lost its global authority chain",
            ));
        }
        let owner_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND lower(name)='chio_serving_owner')",
            [], |row| row.get(0),
        ).map_err(sqlite_error)?;
        if owner_exists {
            let (epoch, lease): (i64, Option<String>) = tx
                .query_row(
                    "SELECT owner_epoch,lease_id FROM chio_serving_owner WHERE singleton=1",
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
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-planning-quota:*')
            OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-planning-quota:*')
            OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND projection_key GLOB 'recovery-planning-quota:*')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)
}

/// Validate typed canonical scope and exact namespace ownership before counting.
fn data_scope(
    key: &str,
    row_scope: &str,
    kind: &str,
    payload: &[u8],
    domain: &AuthorityDomainId,
) -> Result<RecoveryScopeV1, AdmissionOperationStoreError> {
    let scope = if key.starts_with("deployment:") || key.starts_with("deployment-history:") {
        if kind != "deployment" {
            return Err(invariant("recovery planning record kind changed"));
        }
        let profile: RecoveryDeploymentV1 = decode(payload)?;
        let scope_hash = scope_key(&profile.scope)?;
        let expected = if key.starts_with("deployment:") {
            format!("deployment:{scope_hash}")
        } else {
            format!(
                "deployment-history:{scope_hash}:{}",
                hex(&hash(
                    chio_core_types::recovery::RecoveryDigestDomain::Deployment,
                    &profile
                )?)
            )
        };
        if key != expected
            || profile.native_authority.store_uuid().as_str() != domain.as_str()
            || profile.security_context.as_v1().tenant_id().as_str()
                != profile.scope.tenant_id.as_str()
            || profile.authority_scope
                != recovery_authority_scope_digest(&profile)
                    .map_err(|_| invariant("recovery planning profile binding refused"))?
            || profile.contract_digest
                != ContractDigest::from_bytes(hash(
                    chio_core_types::recovery::RecoveryDigestDomain::EffectContract,
                    &profile.effect_contract,
                )?)
        {
            return Err(invariant("recovery planning deployment binding changed"));
        }
        profile.scope
    } else if key.starts_with("recovery-origin:") {
        if kind != "command" {
            return Err(invariant("recovery planning origin kind changed"));
        }
        let claim: PlanningOrigin = decode(payload)?;
        let expected = format!(
            "recovery-origin:{}",
            hex(&hash(
                chio_core_types::recovery::RecoveryDigestDomain::OriginClaim,
                claim.origin.operation.operation_id()
            )?)
        );
        if key != expected {
            return Err(invariant("recovery planning origin binding changed"));
        }
        claim.scope
    } else {
        return Err(invariant("recovery planning namespace refused"));
    };
    if scope.authority_domain != *domain || scope_key(&scope)? != row_scope {
        return Err(invariant("recovery planning scope changed"));
    }
    Ok(scope)
}

fn inventory(
    tx: &Connection,
    domain: &AuthorityDomainId,
    cutoff: u64,
) -> Result<Inventory, AdmissionOperationStoreError> {
    // The correlated exclusions are accepted only after all their protected
    // immutable workflow allocations and archive roots have been verified.
    verify_native_archive_allocations(tx)?;
    let mut keys = tx.prepare(
        "SELECT r.record_key FROM admission_operation_recovery_records r
         WHERE (r.record_key GLOB 'deployment:*' OR r.record_key GLOB 'deployment-history:*' OR r.record_key GLOB 'recovery-origin:*')
           AND NOT EXISTS(SELECT 1 FROM admission_operation_recovery_records q
               WHERE q.kind='command' AND q.record_key GLOB 'workflow-quota:*'
                 AND json_extract(q.payload,'$.native_archive.record_key')=r.record_key)
         ORDER BY r.record_key",
    ).map_err(sqlite_error)?;
    let mut inventory = Inventory {
        global: Usage::default(),
        tenants: BTreeMap::new(),
    };
    for (index, key) in keys
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .enumerate()
    {
        if index >= MAX_DATA_RECORDS {
            return Err(invariant("recovery planning inventory exhausted"));
        }
        let key = key.map_err(sqlite_error)?;
        let row =
            raw(tx, &key)?.ok_or_else(|| invariant("recovery planning projection disappeared"))?;
        let scope = data_scope(&key, &row.scope, &row.kind, &row.payload, domain)?;
        if (key.starts_with("deployment-history:") || key.starts_with("recovery-origin:"))
            && row.version != 1
        {
            return Err(invariant("recovery immutable planning record changed"));
        }
        let (events, before): (i64, i64) = tx.query_row(
            "SELECT count(*),coalesce(sum(sequence<=?2),0) FROM admission_operation_recovery_events WHERE record_key=?1",
            params![key, i64::try_from(cutoff).map_err(|_| invariant("recovery planning cutoff refused"))?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(sqlite_error)?;
        let events = stored_u64(events, "recovery planning events")?;
        let before = stored_u64(before, "recovery planning baseline events")?;
        if events != row.version || before > events {
            return Err(invariant("recovery planning history coverage changed"));
        }
        let bytes = u64::try_from(row.payload.len())
            .map_err(|_| invariant("recovery planning payload refused"))?;
        inventory.global.add(bytes, events, before)?;
        inventory
            .tenants
            .entry(scope.tenant_id)
            .or_default()
            .add(bytes, events, before)?;
    }
    Ok(inventory)
}

fn load(
    tx: &Connection,
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
    usage: &Usage,
) -> Result<Option<PlanningBudget>, AdmissionOperationStoreError> {
    let key = metadata_key(domain, tenant)?;
    let Some(row) = raw(tx, &key)? else {
        if retained_history(tx, &key)? {
            return Err(invariant("recovery planning quota projection disappeared"));
        }
        return Ok(None);
    };
    if row.payload.len() > MAX_METADATA_BYTES
        || row.kind != "command"
        || row.scope != metadata_scope(domain, tenant)?
    {
        return Err(invariant("recovery planning quota is corrupt"));
    }
    let budget: PlanningBudget = decode(&row.payload)?;
    let byte_ceiling = if tenant.is_some() {
        TENANT_BYTES
    } else {
        GLOBAL_BYTES
    };
    if budget.authority_domain != *domain
        || budget.tenant_id.as_ref() != tenant
        || budget.writes.get() == 0
        || budget.writes.get() != row.version
        || usage.events.checked_sub(budget.baseline_events.get()) != Some(budget.writes.get())
        || usage.before_cutoff != budget.baseline_events.get()
        || budget
            .baseline_bytes
            .get()
            .checked_add(byte_ceiling)
            .is_none_or(|ceiling| usage.bytes > ceiling)
        || budget.writes.get()
            > if tenant.is_some() {
                TENANT_EVENTS
            } else {
                GLOBAL_EVENTS
            }
    {
        return Err(invariant("recovery planning quota counters changed"));
    }
    let mut first = budget.clone();
    first.writes = SafeInteger::new(1).map_err(|_| invariant("recovery planning unit refused"))?;
    let digest = record_digest(&key, &row.scope, "command", 1, &encode(&first)?, None, None)?;
    let retained: Option<(i64,String)> = tx.query_row(
        "SELECT sequence,record_digest FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=1",
        [&key], |row| Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(sqlite_error)?;
    let (sequence, retained) =
        retained.ok_or_else(|| invariant("recovery planning baseline lost its event"))?;
    let sequence = stored_u64(sequence, "recovery planning first sequence")?;
    if digest != retained
        || sequence <= budget.legacy_cutoff_sequence.get()
        || (tenant.is_none()
            && budget.legacy_cutoff_sequence.get().checked_add(2) != Some(sequence))
    {
        return Err(invariant("recovery planning baseline changed"));
    }
    Ok(Some(budget))
}

fn peek(
    tx: &Connection,
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
) -> Result<Option<PlanningBudget>, AdmissionOperationStoreError> {
    let key = metadata_key(domain, tenant)?;
    let Some(row) = raw(tx, &key)? else {
        if retained_history(tx, &key)? {
            return Err(invariant("recovery planning quota projection disappeared"));
        }
        return Ok(None);
    };
    if row.payload.len() > MAX_METADATA_BYTES
        || row.scope != metadata_scope(domain, tenant)?
        || row.kind != "command"
    {
        return Err(invariant("recovery planning quota is corrupt"));
    }
    let budget: PlanningBudget = decode(&row.payload)?;
    if budget.authority_domain != *domain || budget.tenant_id.as_ref() != tenant {
        return Err(invariant("recovery planning quota owner changed"));
    }
    Ok(Some(budget))
}

fn new_budget(
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
    cutoff: u64,
    usage: &Usage,
) -> Result<PlanningBudget, AdmissionOperationStoreError> {
    if usage.events != usage.before_cutoff {
        return Err(invariant("recovery planning tenant lost its allocation"));
    }
    Ok(PlanningBudget {
        schema: PlanningBudgetSchema::V1,
        authority_domain: domain.clone(),
        tenant_id: tenant.cloned(),
        legacy_cutoff_sequence: SafeInteger::new(cutoff)
            .map_err(|_| invariant("recovery planning cutoff refused"))?,
        baseline_bytes: SafeInteger::new(usage.bytes)
            .map_err(|_| invariant("recovery planning baseline bytes refused"))?,
        baseline_events: SafeInteger::new(usage.before_cutoff)
            .map_err(|_| invariant("recovery planning baseline events refused"))?,
        writes: SafeInteger::ZERO,
    })
}

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
    let (byte_ceiling, event_ceiling) = if budget.tenant_id.is_some() {
        (TENANT_BYTES, TENANT_EVENTS)
    } else {
        (GLOBAL_BYTES, GLOBAL_EVENTS)
    };
    if budget
        .baseline_bytes
        .get()
        .checked_add(byte_ceiling)
        .is_none_or(|ceiling| next_bytes > ceiling)
        || budget
            .baseline_events
            .get()
            .checked_add(event_ceiling)
            .is_none_or(|ceiling| next_events > ceiling)
    {
        return Err(invariant(if budget.tenant_id.is_some() {
            "recovery tenant planning resource exhausted"
        } else {
            "recovery planning resource exhausted"
        }));
    }
    budget.writes = SafeInteger::new(
        budget
            .writes
            .get()
            .checked_add(1)
            .ok_or_else(|| invariant("recovery planning write count exhausted"))?,
    )
    .map_err(|_| invariant("recovery planning write count refused"))?;
    Ok(())
}

fn persist_budget(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    budget: &PlanningBudget,
) -> Result<(), AdmissionOperationStoreError> {
    let payload = encode(budget)?;
    if payload.len() > MAX_METADATA_BYTES || budget.writes.get() == 0 {
        return Err(invariant("recovery planning quota resource exhausted"));
    }
    persist_record(
        tx,
        owner,
        &metadata_key(&budget.authority_domain, budget.tenant_id.as_ref())?,
        &metadata_scope(&budget.authority_domain, budget.tenant_id.as_ref())?,
        "command",
        &payload,
        None,
    )
}

/// Only called from the owning generic planning save, after writer fencing.
pub(super) fn save(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    kind: &str,
    payload: &[u8],
) -> Result<(), AdmissionOperationStoreError> {
    let domain = physical_domain(tx)?;
    if domain.as_str() != owner.fence.store_uuid {
        return Err(invariant("recovery planning writer owner changed"));
    }
    let selected = data_scope(key, scope, kind, payload, &domain)?;
    let existing = raw(tx, key)?;
    if let Some(row) = &existing {
        if row.scope != scope || row.kind != kind || !key.starts_with("deployment:") {
            return Err(invariant("recovery planning immutable identity changed"));
        }
        data_scope(key, &row.scope, &row.kind, &row.payload, &domain)?;
    }

    // The default-off old-format constructor admits only its fresh fixed path,
    // same owner and bounded real writes. It suppresses new metadata only.
    #[cfg(feature = "admission-test-support")]
    if super::super::legacy_planning_test_support::constructing_legacy_planning(tx, owner, true)? {
        let (bytes,events): (i64,i64) = tx.query_row(
            "SELECT (SELECT coalesce(sum(length(payload)),0) FROM admission_operation_recovery_records),
                (SELECT count(*) FROM admission_operation_recovery_events)", [], |row| Ok((row.get(0)?,row.get(1)?)),
        ).map_err(sqlite_error)?;
        let old = existing.as_ref().map_or(0, |row| row.payload.len() as u64);
        let next = stored_u64(bytes, "legacy planning retained bytes")?
            .checked_sub(old)
            .and_then(|bytes| bytes.checked_add(payload.len() as u64));
        if next.is_none_or(|bytes| bytes > GLOBAL_BYTES)
            || stored_u64(events, "legacy planning retained events")? >= GLOBAL_EVENTS
        {
            return Err(invariant("recovery legacy retained resource exhausted"));
        }
        return persist_record(tx, owner, key, scope, kind, payload, None);
    }

    let retained_global = peek(tx, &domain, None)?;
    let cutoff = match &retained_global {
        Some(global) => global.legacy_cutoff_sequence.get(),
        None => {
            if any_metadata(tx)? {
                return Err(invariant("recovery planning global allocation disappeared"));
            }
            // Rare first allocation checks the complete authenticated global
            // history. Its recovery coverage validator is pure and cannot
            // invoke this initializer, so the call does not recurse.
            crate::serving_owner::verify_authenticated_recovery_history(tx)
                .map_err(map_owner_error)?;
            let sequence: i64 = tx
                .query_row(
                    "SELECT coalesce(max(sequence),0) FROM admission_operation_recovery_events",
                    [],
                    |row| row.get(0),
                )
                .map_err(sqlite_error)?;
            stored_u64(sequence, "recovery planning legacy cutoff")?
        }
    };
    let before = inventory(tx, &domain, cutoff)?;
    let mut global = if retained_global.is_some() {
        load(tx, &domain, None, &before.global)?
            .ok_or_else(|| invariant("recovery planning global allocation disappeared"))?
    } else {
        new_budget(&domain, None, cutoff, &before.global)?
    };
    let empty = Usage::default();
    let tenant_usage = before.tenants.get(&selected.tenant_id).unwrap_or(&empty);
    let mut tenant = match load(tx, &domain, Some(&selected.tenant_id), tenant_usage)? {
        Some(tenant) => {
            if tenant.legacy_cutoff_sequence.get() != cutoff {
                return Err(invariant("recovery planning tenant cutoff changed"));
            }
            tenant
        }
        None => new_budget(&domain, Some(&selected.tenant_id), cutoff, tenant_usage)?,
    };
    let old_bytes = existing.as_ref().map_or(0, |row| row.payload.len() as u64);
    next_budget(&mut global, &before.global, old_bytes, payload.len() as u64)?;
    next_budget(&mut tenant, tenant_usage, old_bytes, payload.len() as u64)?;
    // Both baselines were fixed from BEFORE the data change. Normal protected
    // events and global commits retain each of these three writes atomically.
    persist_record(tx, owner, key, scope, kind, payload, None)?;
    persist_budget(tx, owner, &global)?;
    persist_budget(tx, owner, &tenant)?;
    let after = inventory(tx, &domain, cutoff)?;
    load(tx, &domain, None, &after.global)?
        .ok_or_else(|| invariant("recovery planning global allocation disappeared"))?;
    load(
        tx,
        &domain,
        Some(&selected.tenant_id),
        after
            .tenants
            .get(&selected.tenant_id)
            .ok_or_else(|| invariant("recovery planning tenant data disappeared"))?,
    )?
    .ok_or_else(|| invariant("recovery planning tenant allocation disappeared"))?;
    Ok(())
}

/// Pure validation used from the normal protected/global history walk.
/// It never allocates and never calls the global history initializer.
pub(super) fn verify_all(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    if !any_metadata(tx)? {
        return Ok(());
    }
    let domain = physical_domain(tx)?;
    let global = peek(tx, &domain, None)?
        .ok_or_else(|| invariant("recovery planning global allocation disappeared"))?;
    let cutoff = global.legacy_cutoff_sequence.get();
    let inventory = inventory(tx, &domain, cutoff)?;
    let global = load(tx, &domain, None, &inventory.global)?
        .ok_or_else(|| invariant("recovery planning global allocation disappeared"))?;
    let mut statement = tx.prepare("SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-planning-quota:*' ORDER BY record_key").map_err(sqlite_error)?;
    let mut tenants = std::collections::BTreeSet::new();
    let global_key = metadata_key(&domain, None)?;
    for (index, key) in statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
        .enumerate()
    {
        if index as u64 > global.writes.get() {
            return Err(invariant("recovery planning quota inventory exhausted"));
        }
        let key = key.map_err(sqlite_error)?;
        if key == global_key {
            continue;
        }
        let row = raw(tx, &key)?.ok_or_else(|| invariant("recovery planning quota disappeared"))?;
        if row.payload.len() > MAX_METADATA_BYTES {
            return Err(invariant("recovery planning quota resource exhausted"));
        }
        let budget: PlanningBudget = decode(&row.payload)?;
        let tenant = budget
            .tenant_id
            .ok_or_else(|| invariant("recovery planning duplicate global quota"))?;
        if key != metadata_key(&domain, Some(&tenant))?
            || budget.legacy_cutoff_sequence.get() != cutoff
            || !tenants.insert(tenant.clone())
        {
            return Err(invariant("recovery planning tenant allocation changed"));
        }
        let usage = inventory
            .tenants
            .get(&tenant)
            .ok_or_else(|| invariant("recovery planning tenant data disappeared"))?;
        load(tx, &domain, Some(&tenant), usage)?
            .ok_or_else(|| invariant("recovery planning tenant allocation disappeared"))?;
    }
    for (tenant, usage) in &inventory.tenants {
        if usage.events > usage.before_cutoff && !tenants.contains(tenant) {
            return Err(invariant("recovery planning tenant allocation disappeared"));
        }
    }
    Ok(())
}
