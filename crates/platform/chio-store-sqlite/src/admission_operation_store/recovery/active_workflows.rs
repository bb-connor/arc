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
        if self.baseline != SafeInteger::ZERO {
            return Err(invariant(
                "recovery active capacity adopted prior workflows",
            ));
        }
        self.admitted
            .get()
            .checked_sub(self.retired.get())
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

/// The first live-owner intake provisions the global zero-baseline capacity.
/// Any workflow/allocation/capacity history predating it refuses: a supported
/// store always creates capacity before its first workflow row exists.
fn initialize(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
) -> Result<Capacity, AdmissionOperationStoreError> {
    let domain = AuthorityDomainId::new(&owner.fence.store_uuid)
        .map_err(|_| invariant("recovery active owner refused"))?;
    if let Some(global) = load_capacity(tx, &domain, None)? {
        return Ok(global);
    }
    if any_metadata(tx)? {
        return Err(invariant(
            "recovery active capacity baseline is absent with retained history",
        ));
    }
    let cutoff: i64 = tx
        .query_row(
            "SELECT coalesce(max(sequence),0) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let cutoff = SafeInteger::new(stored_u64(cutoff, "recovery active cutoff")?)
        .map_err(|_| invariant("recovery cutoff refused"))?;
    let global = Capacity {
        schema: CapacitySchema::V1,
        authority_domain: domain,
        tenant_id: None,
        legacy_cutoff: cutoff,
        baseline: SafeInteger::ZERO,
        admitted: SafeInteger::ZERO,
        retired: SafeInteger::ZERO,
    };
    save_capacity(tx, owner, &global)?;
    Ok(global)
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
        let existing_workflow: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE kind='workflow' AND record_key GLOB 'workflow:*' AND json_extract(payload,'$.scope.tenant_id')=?1)",
            [scope.tenant_id.as_str()],|row|row.get(0),
        ).map_err(sqlite_error)?;
        if existing_workflow {
            return Err(invariant("recovery tenant capacity disappeared"));
        }
        let tenant = Capacity {
            tenant_id: Some(scope.tenant_id.clone()),
            admitted: SafeInteger::ZERO,
            retired: SafeInteger::ZERO,
            ..global.clone()
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

/// Whether the workflow's live allocation already committed its retirement.
/// A retired lease is the verified capacity release a linked successor
/// generation requires before the predecessor's original can transfer.
pub(super) fn retirement_committed(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<bool, AdmissionOperationStoreError> {
    Ok(load_allocation(tx, scope, workflow)?
        .is_some_and(|allocation| allocation.retirement.is_some()))
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
    // A supported workflow row always carries its registered allocation.
    let Some(mut allocation) = load_allocation(tx, &record.scope, &record.workflow_id)? else {
        return Err(invariant("recovery workflow allocation disappeared"));
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

/// Whether any workflow/allocation/capacity history is retained in records,
/// events or authority-global commit references. Provision and the startup
/// tally both refuse such history while the global capacity baseline is absent.
fn any_metadata(tx: &Connection) -> Result<bool, AdmissionOperationStoreError> {
    let retained: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-workflow-capacity:*' OR record_key GLOB 'recovery-workflow-allocation:*' OR record_key GLOB 'workflow:*')
            OR EXISTS(SELECT 1 FROM admission_operation_recovery_events WHERE record_key GLOB 'recovery-workflow-capacity:*' OR record_key GLOB 'recovery-workflow-allocation:*' OR record_key GLOB 'workflow:*')",
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
            AND (projection_key GLOB 'recovery-workflow-capacity:*' OR projection_key GLOB 'recovery-workflow-allocation:*' OR projection_key GLOB 'workflow:*'))",
        [], |row| row.get(0),
    ).map_err(sqlite_error)?;
    Ok(retained || references)
}

fn verify_counts(
    tx: &Connection,
    global: &Capacity,
    tenant: &RecoveryTenantId,
    counts: [u64; 2],
) -> Result<(), AdmissionOperationStoreError> {
    let account = load_capacity(tx, &global.authority_domain, Some(tenant))?
        .ok_or_else(|| invariant("recovery tenant capacity absent"))?;
    if [account.admitted.get(), account.retired.get()] != counts
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
    // Tallies are [admitted, retired] per tenant and overall.
    let mut tenant = None;
    let mut counts = [0_u64; 2];
    let mut total = [0_u64; 2];
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
            counts = [0; 2];
            tenants = tenants
                .checked_add(1)
                .ok_or_else(|| invariant("recovery tenant count exhausted"))?;
        }
        workflows = workflows
            .checked_add(1)
            .ok_or_else(|| invariant("recovery workflow count exhausted"))?;
        if allocation.creation_version.get() != 1
            || event(tx, &key, 1)?.0 <= global.legacy_cutoff.get()
        {
            return Err(invariant(
                "recovery workflow allocation predates its capacity baseline",
            ));
        }
        counts[0] = counts[0]
            .checked_add(1)
            .ok_or_else(|| invariant("recovery allocation count exhausted"))?;
        total[0] = total[0]
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
            counts[1] = counts[1]
                .checked_add(1)
                .ok_or_else(|| invariant("recovery retirement count exhausted"))?;
            total[1] = total[1]
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
        || [global.admitted.get(), global.retired.get()] != total
    {
        return Err(invariant(
            "recovery capacity does not match retained allocations",
        ));
    }
    Ok(())
}
