//! Live workflow slots are reusable; original identities and audit history are retained.
use super::*;

#[cfg(test)]
#[path = "active_allocation_head_tests.rs"]
mod active_allocation_head_tests;

const MAX_CAPACITY_METADATA_BYTES: usize = 4096;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capacity {
    schema: CapacitySchema,
    authority_domain: AuthorityDomainId,
    tenant_id: Option<RecoveryTenantId>,
    legacy_cutoff: SafeInteger,
    baseline: SafeInteger,
    admitted: SafeInteger,
    retired: SafeInteger,
}

#[derive(Clone, Serialize, Deserialize)]
enum CapacitySchema {
    #[serde(rename = "chio.recovery.active-capacity.v1")]
    V1,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Allocation {
    schema: AllocationSchema,
    scope: RecoveryScopeV1,
    workflow_id: WorkflowId,
    creation_version: SafeInteger,
    creation_digest: String,
    retirement: Option<Retirement>,
}

#[derive(Clone, Serialize, Deserialize)]
enum AllocationSchema {
    #[serde(rename = "chio.recovery.workflow-allocation.v1")]
    V1,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Retirement {
    workflow_version: SafeInteger,
    workflow_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    captured_terminal: Option<ProjectionDigest>,
}

fn capacity_identity(
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
) -> Result<(String, String), AdmissionOperationStoreError> {
    let scope = sha256_hex(&encode(&(
        chio_core_types::recovery::RecoveryDigestDomain::ActiveWorkflowOwner.name(),
        domain,
        tenant,
    ))?);
    Ok((format!("recovery-workflow-capacity:{scope}"), scope))
}

fn allocation_key(
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "recovery-workflow-allocation:{}:{}",
        scope_key(scope)?,
        workflow.as_str()
    ))
}

fn checked(tx: &Connection, key: &str) -> Result<Option<RawRecord>, AdmissionOperationStoreError> {
    let row = raw_checked(tx, key)?;
    if row.is_some() {
        // Current counters and leases cannot be replayed from an earlier
        // authentic version. Historical baseline/source events stay as-of.
        source_reference(tx, key)?;
    }
    Ok(row)
}

fn event(
    tx: &Connection,
    key: &str,
    version: u64,
) -> Result<(u64, String), AdmissionOperationStoreError> {
    historical_record_commit(tx, key, version)?;
    let (sequence, digest): (i64, String) = tx.query_row(
        "SELECT sequence,record_digest FROM admission_operation_recovery_events WHERE record_key=?1 AND record_version=?2",
        params![key,i64::try_from(version).map_err(|_|invariant("recovery allocation version exhausted"))?],
        |row|Ok((row.get(0)?,row.get(1)?)),
    ).optional().map_err(sqlite_error)?.ok_or_else(||invariant("recovery allocation source event disappeared"))?;
    Ok((
        stored_u64(sequence, "recovery allocation sequence")?,
        digest,
    ))
}

impl Capacity {
    fn active(&self) -> Result<u64, AdmissionOperationStoreError> {
        self.baseline
            .get()
            .checked_add(self.admitted.get())
            .and_then(|count| count.checked_sub(self.retired.get()))
            .ok_or_else(|| invariant("recovery active counter is corrupt"))
    }

    fn verify(&self, tx: &Connection, version: u64) -> Result<(), AdmissionOperationStoreError> {
        self.active()?;
        if self
            .admitted
            .get()
            .checked_add(self.retired.get())
            .and_then(|n| n.checked_add(1))
            != Some(version)
        {
            return Err(invariant("recovery active counter version changed"));
        }
        let (key, scope) = capacity_identity(&self.authority_domain, self.tenant_id.as_ref())?;
        let (first_sequence, first_digest) = event(tx, &key, 1)?;
        let mut first = self.clone();
        first.admitted = SafeInteger::ZERO;
        first.retired = SafeInteger::ZERO;
        if first_sequence <= self.legacy_cutoff.get()
            || first_digest
                != record_digest(&key, &scope, "command", 1, &encode(&first)?, None, None)?
            || (self.tenant_id.is_none()
                && self.legacy_cutoff.get().checked_add(1) != Some(first_sequence))
        {
            return Err(invariant("recovery active counter baseline changed"));
        }
        Ok(())
    }
}

fn load_capacity(
    tx: &Connection,
    domain: &AuthorityDomainId,
    tenant: Option<&RecoveryTenantId>,
) -> Result<Option<Capacity>, AdmissionOperationStoreError> {
    let (key, scope) = capacity_identity(domain, tenant)?;
    let Some(row) = checked(tx, &key)? else {
        return Ok(None);
    };
    if row.kind != "command"
        || row.scope != scope
        || row.payload.len() > MAX_CAPACITY_METADATA_BYTES
    {
        return Err(invariant("recovery active capacity owner changed"));
    }
    let value: Capacity = decode(&row.payload)?;
    if value.authority_domain != *domain || value.tenant_id.as_ref() != tenant {
        return Err(invariant("recovery active capacity scope changed"));
    }
    value.verify(tx, row.version)?;
    Ok(Some(value))
}

fn save_capacity(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    capacity: &Capacity,
) -> Result<(), AdmissionOperationStoreError> {
    let (key, scope) = capacity_identity(&capacity.authority_domain, capacity.tenant_id.as_ref())?;
    let payload = encode(capacity)?;
    if payload.len() > MAX_CAPACITY_METADATA_BYTES {
        return Err(invariant("recovery capacity metadata exhausted"));
    }
    persist_record(tx, owner, &key, &scope, "command", &payload, None)
}

fn load_allocation(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<Option<Allocation>, AdmissionOperationStoreError> {
    let key = allocation_key(scope, workflow)?;
    let Some(row) = checked(tx, &key)? else {
        return Ok(None);
    };
    let value: Allocation = decode(&row.payload)?;
    if row.kind != "command"
        || row.scope != scope_key(scope)?
        || row.payload.len() > MAX_CAPACITY_METADATA_BYTES
        || value.scope != *scope
        || value.workflow_id != *workflow
        || row.version != if value.retirement.is_some() { 2 } else { 1 }
    {
        return Err(invariant("recovery workflow allocation owner changed"));
    }
    let mut first = value.clone();
    first.retirement = None;
    if event(tx, &key, 1)?.1
        != record_digest(
            &key,
            &scope_key(scope)?,
            "command",
            1,
            &encode(&first)?,
            None,
            None,
        )?
    {
        return Err(invariant("recovery workflow allocation baseline changed"));
    }
    let source = workflow_key(scope, workflow)?;
    if event(tx, &source, value.creation_version.get())?.1 != value.creation_digest {
        return Err(invariant("recovery allocation lost its creation source"));
    }
    if let Some(retirement) = &value.retirement {
        if event(tx, &source, retirement.workflow_version.get())?.1 != retirement.workflow_digest {
            return Err(invariant("recovery allocation lost its closure source"));
        }
        if let Some(expected) = &retirement.captured_terminal {
            let physical = workflow_tx(tx, scope, workflow)?;
            require_terminal_retirement(tx, &physical, expected)?;
            if retirement.workflow_version != physical.revision {
                return Err(invariant("retired captured workflow source changed"));
            }
        }
    }
    Ok(Some(value))
}

fn save_allocation(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    value: &Allocation,
) -> Result<(), AdmissionOperationStoreError> {
    let payload = encode(value)?;
    if payload.len() > MAX_CAPACITY_METADATA_BYTES {
        return Err(invariant("recovery allocation metadata exhausted"));
    }
    persist_record(
        tx,
        owner,
        &allocation_key(&value.scope, &value.workflow_id)?,
        &scope_key(&value.scope)?,
        "command",
        &payload,
        None,
    )
}

/// One live-owner migration creates conservative leases without deleting old identities.
fn initialize(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
) -> Result<Capacity, AdmissionOperationStoreError> {
    let domain = AuthorityDomainId::new(&owner.fence.store_uuid)
        .map_err(|_| invariant("recovery active owner refused"))?;
    if let Some(global) = load_capacity(tx, &domain, None)? {
        return Ok(global);
    }
    let partial: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-workflow-capacity:*' OR record_key GLOB 'recovery-workflow-allocation:*')
            OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-workflow-capacity:*' OR record_key GLOB 'recovery-workflow-allocation:*')
            OR EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery' AND (projection_key GLOB 'recovery-workflow-capacity:*' OR projection_key GLOB 'recovery-workflow-allocation:*'))",
        [],|row|row.get(0),
    ).map_err(sqlite_error)?;
    if partial {
        return Err(invariant(
            "recovery active migration projection disappeared",
        ));
    }
    crate::serving_owner::verify_authenticated_recovery_history(tx).map_err(map_owner_error)?;
    let (cutoff,count): (i64,i64) = tx.query_row(
        "SELECT (SELECT coalesce(max(sequence),0) FROM admission_operation_recovery_events),
            (SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow' AND record_key GLOB 'workflow:*')",
        [],|row|Ok((row.get(0)?,row.get(1)?)),
    ).map_err(sqlite_error)?;
    let cutoff = SafeInteger::new(stored_u64(cutoff, "recovery active cutoff")?)
        .map_err(|_| invariant("recovery cutoff refused"))?;
    let global = Capacity {
        schema: CapacitySchema::V1,
        authority_domain: domain.clone(),
        tenant_id: None,
        legacy_cutoff: cutoff,
        baseline: SafeInteger::new(stored_u64(count, "recovery active baseline")?)
            .map_err(|_| invariant("recovery baseline refused"))?,
        admitted: SafeInteger::ZERO,
        retired: SafeInteger::ZERO,
    };
    save_capacity(tx, owner, &global)?;
    let mut statement = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE kind='workflow' AND record_key GLOB 'workflow:*'
         ORDER BY json_extract(payload,'$.scope.tenant_id'),record_key",
    ).map_err(sqlite_error)?;
    let mut tenant: Option<RecoveryTenantId> = None;
    let mut tenant_count = 0_u64;
    for key in statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key = key.map_err(sqlite_error)?;
        let row =
            raw(tx, &key)?.ok_or_else(|| invariant("recovery legacy workflow disappeared"))?;
        let record: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
        if key != workflow_key(&record.scope, &record.workflow_id)?
            || row.scope != scope_key(&record.scope)?
            || record.revision.get() != row.version
            || record.scope.authority_domain != domain
        {
            return Err(invariant("recovery legacy allocation source changed"));
        }
        if tenant.as_ref() != Some(&record.scope.tenant_id) {
            if let Some(previous) = tenant.take() {
                save_capacity(
                    tx,
                    owner,
                    &Capacity {
                        tenant_id: Some(previous),
                        baseline: SafeInteger::new(tenant_count)
                            .map_err(|_| invariant("recovery baseline refused"))?,
                        ..global.clone()
                    },
                )?;
            }
            tenant = Some(record.scope.tenant_id.clone());
            tenant_count = 0;
        }
        tenant_count = tenant_count
            .checked_add(1)
            .ok_or_else(|| invariant("recovery legacy allocation exhausted"))?;
        save_allocation(
            tx,
            owner,
            &Allocation {
                schema: AllocationSchema::V1,
                scope: record.scope.clone(),
                workflow_id: record.workflow_id.clone(),
                creation_version: record.revision,
                creation_digest: event(tx, &key, row.version)?.1,
                retirement: None,
            },
        )?;
    }
    if let Some(tenant) = tenant {
        save_capacity(
            tx,
            owner,
            &Capacity {
                tenant_id: Some(tenant),
                baseline: SafeInteger::new(tenant_count)
                    .map_err(|_| invariant("recovery baseline refused"))?,
                ..global.clone()
            },
        )?;
    }
    // Old never-admitted cancellations already carry the owning writer fence
    // against future begin/capture. Revalidate that exact proof before release.
    let mut closed = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE kind='workflow' AND record_key GLOB 'workflow:*'
           AND json_extract(payload,'$.control')='cancelled' ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    for key in closed
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let row = raw(tx, &key.map_err(sqlite_error)?)?
            .ok_or_else(|| invariant("recovery legacy closure disappeared"))?;
        let record: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
        retire_cancelled(tx, owner, &record)?;
    }
    load_capacity(tx, &domain, None)?
        .ok_or_else(|| invariant("recovery active migration lost its capacity"))
}

fn capacities(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
) -> Result<(Capacity, Capacity), AdmissionOperationStoreError> {
    if scope.authority_domain.as_str() != owner.fence.store_uuid {
        return Err(invariant("recovery active authority changed"));
    }
    let global = initialize(tx, owner)?;
    let tenant = if let Some(tenant) =
        load_capacity(tx, &scope.authority_domain, Some(&scope.tenant_id))?
    {
        tenant
    } else {
        let legacy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE kind='workflow' AND record_key GLOB 'workflow:*' AND json_extract(payload,'$.scope.tenant_id')=?1)",
            [scope.tenant_id.as_str()],|row|row.get(0),
        ).map_err(sqlite_error)?;
        if legacy {
            return Err(invariant("recovery tenant capacity disappeared"));
        }
        let tenant = Capacity {
            tenant_id: Some(scope.tenant_id.clone()),
            baseline: SafeInteger::ZERO,
            ..global.clone()
        };
        let tenant = Capacity {
            admitted: SafeInteger::ZERO,
            retired: SafeInteger::ZERO,
            ..tenant
        };
        save_capacity(tx, owner, &tenant)?;
        tenant
    };
    if tenant.legacy_cutoff != global.legacy_cutoff {
        return Err(invariant("recovery capacity cutoff changed"));
    }
    Ok((global, tenant))
}

pub(super) fn require_capacity(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    scope: &RecoveryScopeV1,
) -> Result<(), AdmissionOperationStoreError> {
    let (global, tenant) = capacities(tx, owner, scope)?;
    if global.active()? >= 128 || tenant.active()? >= MAX_RECOVERY_WORKFLOWS as u64 {
        return Err(invariant("recovery workflow quota exhausted"));
    }
    Ok(())
}

pub(super) fn register(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if load_allocation(tx, &record.scope, &record.workflow_id)?.is_some() {
        return Err(invariant("recovery workflow allocation already exists"));
    }
    let (mut global, mut tenant) = capacities(tx, owner, &record.scope)?;
    if global.active()? >= 128 || tenant.active()? >= MAX_RECOVERY_WORKFLOWS as u64 {
        return Err(invariant("recovery workflow quota exhausted"));
    }
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let row =
        raw(tx, &key)?.ok_or_else(|| invariant("recovery workflow allocation source absent"))?;
    if row.version != 1 || encode(record)? != row.payload {
        return Err(invariant("recovery allocation creation changed"));
    }
    save_allocation(
        tx,
        owner,
        &Allocation {
            schema: AllocationSchema::V1,
            scope: record.scope.clone(),
            workflow_id: record.workflow_id.clone(),
            creation_version: record.revision,
            creation_digest: event(tx, &key, 1)?.1,
            retirement: None,
        },
    )?;
    for account in [&mut global, &mut tenant] {
        account.admitted = SafeInteger::new(
            account
                .admitted
                .get()
                .checked_add(1)
                .ok_or_else(|| invariant("recovery admission count exhausted"))?,
        )
        .map_err(|_| invariant("recovery admission count exhausted"))?;
        save_capacity(tx, owner, account)?;
    }
    Ok(())
}

/// A never-admitted cancellation seals future begin/capture through the physical workflow.
pub(super) fn retire_cancelled(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if record.control != WorkflowControlV1::Cancelled
        || !record.admission_closed
        || record.captured
        || record.admission.is_some()
        || record.native_link.is_some()
        || record.process_reservation.is_some()
        || record.effect != EffectObservationV1::NeverAdmitted
        || record.historical_hold.is_some()
        || auxiliary_historical_hold(tx, record)?.is_some()
    {
        return Ok(());
    }
    persist_retirement(tx, owner, record, None).map(|_| ())
}

/// Only the native absence/compensation owner can retire a materialized lease.
/// This preserves the physical workflow, acknowledged reservation and charges.
pub(super) fn retire_no_future_native_admission(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    proof: &super::original_owner::AuthenticatedNoFutureNativeAdmission<'_, '_, '_>,
) -> Result<bool, AdmissionOperationStoreError> {
    proof.verify(tx)?;
    if !proof.matches_owner(owner)
        || load_allocation(tx, &proof.record().scope, &proof.record().workflow_id)?.is_none()
    {
        return Err(invariant(
            "original retirement lacks its actual allocated serving owner",
        ));
    }
    persist_retirement(tx, owner, proof.record(), None)
}

pub(super) fn require_live_allocation(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let allocation = load_allocation(tx, &record.scope, &record.workflow_id)?
        .ok_or_else(|| invariant("unused setup lacks an authentic live workflow allocation"))?;
    if allocation.retirement.is_some() {
        return Err(invariant("unused setup allocation was already retired"));
    }
    Ok(())
}

pub(super) fn require_no_future_retired_allocation(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let allocation = load_allocation(tx, &record.scope, &record.workflow_id)?
        .ok_or_else(|| invariant("original closure lost its retained workflow allocation"))?;
    let retirement = allocation
        .retirement
        .ok_or_else(|| invariant("original closure retains an active workflow allocation"))?;
    if retirement.workflow_version != record.revision
        || retirement.captured_terminal.is_some()
        || retirement.workflow_digest
            != event(
                tx,
                &workflow_key(&record.scope, &record.workflow_id)?,
                record.revision.get(),
            )?
            .1
    {
        return Err(invariant(
            "original no-future retirement changed its physical closure source",
        ));
    }
    Ok(())
}

fn require_terminal_retirement(
    tx: &Connection,
    physical: &RecoveryWorkflowRecordV1,
    expected: &ProjectionDigest,
) -> Result<(), AdmissionOperationStoreError> {
    if super::super::historical_holds::effective(tx, physical)?.is_some()
        && (super::super::historical_holds::blocks_original_private_settlement(tx, physical)?
            || !super::super::terminal_custody::private_settlement_committed(tx, physical)?)
    {
        return Err(invariant(
            "captured terminal retirement retains its historical hold",
        ));
    }
    auxiliary_captured_terminal(tx, physical)?
        .ok_or_else(|| invariant("retired captured workflow lost terminal custody"))?;
    let key = super::super::terminal_custody::terminal_key(&physical.scope, &physical.workflow_id)?;
    if source_reference(tx, &key)?.digest() != expected {
        return Err(invariant(
            "retired captured workflow terminal source changed",
        ));
    }
    Ok(())
}

/// A qualified native terminal, not a derived Complete clone, releases a live slot.
pub(super) fn retire_captured_terminal(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    physical: &RecoveryWorkflowRecordV1,
    terminal: &super::super::terminal_custody::CapturedWorkflowTerminalV1,
) -> Result<bool, AdmissionOperationStoreError> {
    super::super::terminal_custody::verify_terminal(
        tx,
        &physical.scope,
        &physical.workflow_id,
        terminal,
    )?;
    let retained = auxiliary_captured_terminal(tx, physical)?
        .ok_or_else(|| invariant("captured retirement requires its quota-owned terminal"))?;
    if encode(&retained)? != encode(terminal)? {
        return Err(invariant("captured retirement terminal custody changed"));
    }
    let key = super::super::terminal_custody::terminal_key(&physical.scope, &physical.workflow_id)?;
    let digest = *source_reference(tx, &key)?.digest();
    require_terminal_retirement(tx, physical, &digest)?;
    persist_retirement(tx, owner, physical, Some(digest))
}

fn persist_retirement(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
    captured_terminal: Option<ProjectionDigest>,
) -> Result<bool, AdmissionOperationStoreError> {
    let Some(mut allocation) = load_allocation(tx, &record.scope, &record.workflow_id)? else {
        // Finishing legacy work never demands new intake/migration allocation.
        return Ok(false);
    };
    if allocation.retirement.is_some() {
        return Ok(false);
    }
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let row = raw(tx, &key)?.ok_or_else(|| invariant("recovery closure source absent"))?;
    if encode(record)? != row.payload {
        return Err(invariant("recovery closure source changed"));
    }
    let (mut global, mut tenant) = capacities(tx, owner, &record.scope)?;
    allocation.retirement = Some(Retirement {
        workflow_version: record.revision,
        workflow_digest: event(tx, &key, row.version)?.1,
        captured_terminal,
    });
    save_allocation(tx, owner, &allocation)?;
    for account in [&mut global, &mut tenant] {
        account.retired = SafeInteger::new(
            account
                .retired
                .get()
                .checked_add(1)
                .ok_or_else(|| invariant("recovery retirement count exhausted"))?,
        )
        .map_err(|_| invariant("recovery retirement count exhausted"))?;
        account.active()?;
        save_capacity(tx, owner, account)?;
    }
    Ok(true)
}

fn any_metadata(tx: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    let retained: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-workflow-capacity:*' OR record_key GLOB 'recovery-workflow-allocation:*')
            OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-workflow-capacity:*' OR record_key GLOB 'recovery-workflow-allocation:*')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    let global_exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND lower(name)='authority_global_commits')",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    if !global_exists {
        // The outer planning verifier permits this only in pristine provisioning.
        return if retained {
            Err(invariant("recovery active metadata lost its global chain"))
        } else {
            Ok(false)
        };
    }
    let references: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM authority_global_commits WHERE projection_kind='recovery'
            AND (projection_key GLOB 'recovery-workflow-capacity:*' OR projection_key GLOB 'recovery-workflow-allocation:*'))",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    Ok(retained || references)
}

fn verify_counts(
    tx: &Connection,
    global: &Capacity,
    tenant: &RecoveryTenantId,
    counts: [u64; 3],
) -> Result<(), AdmissionOperationStoreError> {
    let account = load_capacity(tx, &global.authority_domain, Some(tenant))?
        .ok_or_else(|| invariant("recovery tenant capacity absent"))?;
    if [
        account.baseline.get(),
        account.admitted.get(),
        account.retired.get(),
    ] != counts
        || account.legacy_cutoff != global.legacy_cutoff
    {
        return Err(invariant(
            "recovery tenant capacity does not match retained allocations",
        ));
    }
    Ok(())
}

/// Startup holds one tenant tally while streaming immutable workflow identities.
pub(super) fn verify_all(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    if !any_metadata(tx)? {
        return Ok(());
    }
    let domain: String = tx
        .query_row(
            "SELECT store_uuid FROM chio_serving_owner WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let domain =
        AuthorityDomainId::new(&domain).map_err(|_| invariant("recovery active owner refused"))?;
    let global = load_capacity(tx, &domain, None)?
        .ok_or_else(|| invariant("recovery active capacity absent"))?;
    let mut tenant = None;
    let mut counts = [0_u64; 3];
    let mut total = [0_u64; 3];
    let mut tenants = 0_u64;
    let mut workflows = 0_u64;
    let mut statement = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE kind='workflow' AND record_key GLOB 'workflow:*'
         ORDER BY json_extract(payload,'$.scope.tenant_id'),record_key",
    ).map_err(sqlite_error)?;
    for key in statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key = key.map_err(sqlite_error)?;
        let row = raw(tx, &key)?.ok_or_else(|| invariant("recovery allocation workflow absent"))?;
        let record: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
        let allocation = load_allocation(tx, &record.scope, &record.workflow_id)?
            .ok_or_else(|| invariant("recovery allocation absent"))?;
        if key != workflow_key(&record.scope, &record.workflow_id)?
            || row.scope != scope_key(&record.scope)?
            || record.scope.authority_domain != domain
            || row.version != record.revision.get()
        {
            return Err(invariant("recovery allocation workflow changed"));
        }
        if tenant.as_ref() != Some(&record.scope.tenant_id) {
            if let Some(previous) = tenant.take() {
                verify_counts(tx, &global, &previous, counts)?;
            }
            tenant = Some(record.scope.tenant_id.clone());
            counts = [0; 3];
            tenants = tenants
                .checked_add(1)
                .ok_or_else(|| invariant("recovery tenant count exhausted"))?;
        }
        workflows = workflows
            .checked_add(1)
            .ok_or_else(|| invariant("recovery workflow count exhausted"))?;
        let source_sequence = event(tx, &key, allocation.creation_version.get())?.0;
        let category = usize::from(source_sequence > global.legacy_cutoff.get());
        if category == 1 && allocation.creation_version.get() != 1 {
            return Err(invariant(
                "new recovery allocation changed its creation version",
            ));
        }
        counts[category] = counts[category]
            .checked_add(1)
            .ok_or_else(|| invariant("recovery allocation count exhausted"))?;
        total[category] = total[category]
            .checked_add(1)
            .ok_or_else(|| invariant("recovery allocation count exhausted"))?;
        if let Some(retirement) = &allocation.retirement {
            if let Some(terminal) = &retirement.captured_terminal {
                require_terminal_retirement(tx, &record, terminal)?;
            } else if record.control != WorkflowControlV1::Cancelled
                || !record.admission_closed
                || record.captured
                || record.admission.is_some()
                || record.native_link.is_some()
                || record.process_reservation.is_some()
                || record.effect != EffectObservationV1::NeverAdmitted
                || record.historical_hold.is_some()
                || auxiliary_historical_hold(tx, &record)?.is_some()
            {
                return Err(invariant(
                    "retired recovery allocation regained an obligation",
                ));
            }
            counts[2] = counts[2]
                .checked_add(1)
                .ok_or_else(|| invariant("recovery retirement count exhausted"))?;
            total[2] = total[2]
                .checked_add(1)
                .ok_or_else(|| invariant("recovery retirement count exhausted"))?;
        }
    }
    if let Some(tenant) = tenant {
        verify_counts(tx, &global, &tenant, counts)?;
    }
    let (capacity_rows, allocation_rows): (i64, i64) = tx.query_row(
        "SELECT
            (SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-workflow-capacity:*'),
            (SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-workflow-allocation:*')",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(sqlite_error)?;
    if stored_u64(capacity_rows, "recovery capacity count")?
        != tenants
            .checked_add(1)
            .ok_or_else(|| invariant("recovery tenant count exhausted"))?
        || stored_u64(allocation_rows, "recovery allocation count")? != workflows
        || [
            global.baseline.get(),
            global.admitted.get(),
            global.retired.get(),
        ] != total
    {
        return Err(invariant(
            "recovery capacity does not match retained allocations",
        ));
    }
    Ok(())
}
