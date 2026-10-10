//! Fixed workflow progress, mutating identities and native archive allocations.
use super::*;
use chio_core::recovery::RecoveryDigestDomain;

#[path = "historical_hold_allocation.rs"]
mod historical_hold_allocation;
use historical_hold_allocation::WorkflowHoldAllocation;
pub(in crate::admission_operation_store) use historical_hold_allocation::{
    auxiliary_historical_hold, save_auxiliary_historical_hold,
};

#[path = "terminal_allocation.rs"]
mod terminal_allocation;
use terminal_allocation::WorkflowTerminalAllocation;
#[path = "release_allocation.rs"]
mod release_allocation;
use release_allocation::WorkflowReleaseAllocation;
pub(in crate::admission_operation_store) use release_allocation::{
    auxiliary_captured_release, save_auxiliary_captured_release,
};
pub(in crate::admission_operation_store) use terminal_allocation::{
    auxiliary_captured_terminal, save_auxiliary_captured_terminal,
};

#[cfg(test)]
#[path = "workflow_reservation_tests.rs"]
mod workflow_reservation_tests;

#[cfg(feature = "admission-test-support")]
#[path = "workflow_quota_head_test_support.rs"]
mod workflow_quota_head_test_support;
#[cfg(test)]
#[path = "workflow_quota_head_tests.rs"]
mod workflow_quota_head_tests;

/// Owning callsites select a fixed workflow allowance, never a wire flag.
#[derive(Clone, Copy)]
pub(in crate::admission_operation_store) enum WorkflowWriteClass {
    Planning,
    Control,
    Native,
}

const MAX_WORKFLOW_QUOTA_BYTES: usize = 4096;
const MAX_WORKFLOW_COMMAND_BYTES: usize = 4096;
const COMMAND_SLOT_CEILINGS: [u64; 6] = [8, 8, 8, 24, 8, 8];
const WORKFLOW_SLOT_CEILINGS: [u64; 3] = [8, 2, 128];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowQuota {
    schema: WorkflowQuotaSchema,
    scope: RecoveryScopeV1,
    workflow_id: WorkflowId,
    baseline_revision: SafeInteger,
    baseline_commands: SafeInteger,
    planning: SafeInteger,
    control: SafeInteger,
    native: SafeInteger,
    commands: [SafeInteger; 6],
    native_archive: Option<WorkflowArchiveAllocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_hold: Option<WorkflowHoldAllocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_terminal: Option<WorkflowTerminalAllocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_release: Option<WorkflowReleaseAllocation>,
}

#[derive(Clone, Serialize, Deserialize)]
enum WorkflowQuotaSchema {
    #[serde(rename = "chio.recovery.workflow-reservation.v1")]
    V1,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowArchiveAllocation {
    record_key: String,
    deployment_digest: DeploymentDigest,
    record_version: SafeInteger,
}

fn quota_key(
    scope: &RecoveryScopeV1,
    id: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "workflow-quota:{}:{}",
        scope_key(scope)?,
        id.as_str()
    ))
}

fn command_slot(body: &RecoveryCommandBodyV1) -> Result<usize, AdmissionOperationStoreError> {
    match body {
        RecoveryCommandBodyV1::CreateWorkflow { .. } => Ok(0),
        RecoveryCommandBodyV1::SelectOffer { .. } => Ok(1),
        RecoveryCommandBodyV1::SubmitApproval { .. } => Ok(2),
        RecoveryCommandBodyV1::ResumeWorkflow { .. } => Ok(3),
        RecoveryCommandBodyV1::CancelWorkflow { .. } => Ok(4),
        RecoveryCommandBodyV1::ReportDecision { .. } => Ok(5),
        RecoveryCommandBodyV1::InspectWorkflow { .. } => {
            Err(invariant("inspection cannot allocate a command identity"))
        }
    }
}

fn owned_commands(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<u64, AdmissionOperationStoreError> {
    let scope_hash = scope_key(scope)?;
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE scope_key=?1 AND kind='command' AND record_key GLOB 'command:*'
           AND json_extract(payload,'$.response.workflow_id')=?2 ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    let owned = raw(tx, &workflow_key(scope, workflow)?)?;
    let mut count = 0_u64;
    for key in statement
        .query_map(params![&scope_hash, workflow.as_str()], |row| {
            row.get::<_, String>(0)
        })
        .map_err(sqlite_error)?
    {
        let row = raw(tx, &key.map_err(sqlite_error)?)?
            .ok_or_else(|| invariant("recovery command identity disappeared"))?;
        if row.scope != scope_hash || row.kind != "command" || row.version != 1 {
            return Err(invariant("recovery command identity changed"));
        }
        let (_, response) = commands::decode_record(&row.payload)?;
        if response.workflow_id != *workflow
            || response.revision.get() == 0
            || owned
                .as_ref()
                .is_none_or(|record| response.revision.get() > record.version)
        {
            return Err(invariant("recovery command workflow version changed"));
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| invariant("recovery command inventory exhausted"))?;
    }
    Ok(count)
}

impl WorkflowQuota {
    fn workflow_units(&self) -> Result<u64, AdmissionOperationStoreError> {
        [self.planning, self.control, self.native]
            .iter()
            .try_fold(0_u64, |sum, value| {
                sum.checked_add(value.get())
                    .ok_or_else(|| invariant("recovery workflow quota is corrupt"))
            })
    }

    fn command_units(&self) -> Result<u64, AdmissionOperationStoreError> {
        self.commands.iter().try_fold(0_u64, |sum, value| {
            sum.checked_add(value.get())
                .ok_or_else(|| invariant("recovery workflow quota is corrupt"))
        })
    }

    fn units(&self) -> Result<u64, AdmissionOperationStoreError> {
        self.workflow_units()?
            .checked_add(self.command_units()?)
            .and_then(|sum| sum.checked_add(u64::from(self.native_archive.is_some())))
            .and_then(|sum| sum.checked_add(u64::from(self.native_hold.is_some())))
            .and_then(|sum| sum.checked_add(u64::from(self.native_terminal.is_some())))
            .and_then(|sum| sum.checked_add(u64::from(self.native_release.is_some())))
            .ok_or_else(|| invariant("recovery workflow quota is corrupt"))
    }

    fn validate(
        &self,
        tx: &Connection,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
        revision: u64,
        commands: u64,
        version: u64,
    ) -> Result<(), AdmissionOperationStoreError> {
        let workflow_counters = [self.planning, self.control, self.native];
        if self.scope != *scope
            || self.workflow_id != *workflow
            || workflow_counters
                .iter()
                .zip(WORKFLOW_SLOT_CEILINGS)
                .any(|(used, ceiling)| used.get() > ceiling)
            || self
                .commands
                .iter()
                .zip(COMMAND_SLOT_CEILINGS)
                .any(|(used, ceiling)| used.get() > ceiling)
            || revision.checked_sub(self.baseline_revision.get()) != Some(self.workflow_units()?)
            || commands.checked_sub(self.baseline_commands.get()) != Some(self.command_units()?)
            || (self.native_release.is_some() && self.native_terminal.is_none())
            || version != self.units()?
            || version == 0
        {
            return Err(invariant("recovery workflow quota is corrupt"));
        }
        self.verify_first_allocation(tx)?;
        if let Some(hold) = &self.native_hold {
            hold.verify(tx, scope, workflow)?;
        }
        if let Some(terminal) = &self.native_terminal {
            terminal.verify(tx, scope, workflow)?;
        } else {
            terminal_allocation::require_absent_terminal(tx, scope, workflow)?;
        }
        if let Some(release) = &self.native_release {
            release.verify(tx, scope, workflow)?;
        } else {
            release_allocation::require_absent_release(tx, scope, workflow)?;
        }
        if let Some(archive) = &self.native_archive {
            let expected = format!(
                "deployment-history:{}:{}",
                scope_key(scope)?,
                hex(archive.deployment_digest.as_bytes())
            );
            let row = raw(tx, &archive.record_key)?
                .ok_or_else(|| invariant("recovery native archive allocation disappeared"))?;
            let profile: RecoveryDeploymentV1 = decode(&row.payload)?;
            if archive.record_key != expected
                || archive.record_version.get() != 1
                || row.version != 1
                || row.kind != "deployment"
                || row.scope != scope_key(scope)?
                || profile.scope != *scope
                || DeploymentDigest::from_bytes(hash(RecoveryDigestDomain::Deployment, &profile)?)
                    != archive.deployment_digest
            {
                return Err(invariant("recovery native archive allocation changed"));
            }
        }
        Ok(())
    }

    fn verify_first_allocation(&self, tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
        let key = quota_key(&self.scope, &self.workflow_id)?;
        let retained: Option<String> = tx
            .query_row(
                "SELECT record_digest FROM admission_operation_recovery_events
             WHERE record_key=?1 AND record_version=1",
                [&key],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let retained =
            retained.ok_or_else(|| invariant("recovery workflow quota baseline lost its event"))?;
        // Thirteen single-unit preimages preserve the first owner. Its
        // authenticated digest fixes both legacy baselines permanently.
        let mut first = self.clone();
        first.planning = SafeInteger::ZERO;
        first.control = SafeInteger::ZERO;
        first.native = SafeInteger::ZERO;
        first.commands = [SafeInteger::ZERO; 6];
        first.native_archive = None;
        first.native_hold = None;
        first.native_terminal = None;
        first.native_release = None;
        let counters = [self.planning, self.control, self.native];
        for (class, counter) in counters.iter().map(Some).chain([None; 10]).enumerate() {
            let mut candidate = first.clone();
            let one = SafeInteger::new(1).map_err(|_| invariant("recovery quota unit refused"))?;
            if let Some(counter) = counter {
                if counter.get() == 0 {
                    continue;
                }
                match class {
                    0 => candidate.planning = one,
                    1 => candidate.control = one,
                    _ => candidate.native = one,
                }
            } else if class < 9 {
                if self.commands[class - 3].get() == 0 {
                    continue;
                }
                candidate.commands[class - 3] = one;
            } else if class == 9 {
                let Some(archive) = &self.native_archive else {
                    continue;
                };
                candidate.native_archive = Some(archive.clone());
            } else if class == 10 {
                let Some(hold) = &self.native_hold else {
                    continue;
                };
                candidate.native_hold = Some(hold.clone());
            } else if class == 11 {
                let Some(terminal) = &self.native_terminal else {
                    continue;
                };
                candidate.native_terminal = Some(terminal.clone());
            } else {
                let Some(release) = &self.native_release else {
                    continue;
                };
                candidate.native_release = Some(release.clone());
            }
            let digest = record_digest(
                &key,
                &scope_key(&self.scope)?,
                "command",
                1,
                &encode(&candidate)?,
                None,
                None,
            )?;
            if retained == digest {
                return Ok(());
            }
        }
        Err(invariant("recovery workflow quota baseline changed"))
    }
}

fn workflow_quota(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<WorkflowQuota, AdmissionOperationStoreError> {
    workflow_quota_with_count(tx, scope, workflow, None)
}

/// A pristine native purpose is proven from the actual FIRST allocation, never
/// inferred from absent workflow fields or a legacy zero baseline.
pub(super) fn require_unmaterialized_no_native_accounting(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    let key = quota_key(&record.scope, &record.workflow_id)?;
    let source = source_reference(tx, &key)?;
    let quota = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    if source.kind() != "command"
        || quota.baseline_revision != SafeInteger::ZERO
        || quota.baseline_commands != SafeInteger::ZERO
        || quota.native != SafeInteger::ZERO
        || quota.native_archive.is_some()
        || quota.native_hold.is_some()
        || quota.native_terminal.is_some()
        || quota.native_release.is_some()
        || record.action.is_some()
        || record.process_reservation.is_some()
    {
        return Err(invariant(
            "unused original lacks its authentic zero native-purpose allocation",
        ));
    }
    Ok(())
}

pub(super) fn verify_unused_setup_control_quota(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
    previous_version: u64,
    previous_digest: &ProjectionDigest,
) -> Result<(), AdmissionOperationStoreError> {
    let key = quota_key(&record.scope, &record.workflow_id)?;
    let source = source_reference(tx, &key)?;
    let mut before = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    if previous_version.checked_add(1) != Some(source.version()) || before.control.get() == 0 {
        return Err(invariant(
            "unused setup closure lost its single reserved control purpose",
        ));
    }
    before.control = SafeInteger::new(before.control.get() - 1)
        .map_err(|_| invariant("unused setup prior control count refused"))?;
    if before.units()? != previous_version
        || record_digest(
            &key,
            &scope_key(&record.scope)?,
            "command",
            previous_version,
            &encode(&before)?,
            None,
            None,
        )? != hex(previous_digest.as_bytes())
    {
        return Err(invariant(
            "unused setup closure changed its retained purpose preimage",
        ));
    }
    Ok(())
}

/// The first durable Resume request belongs to this exact physical generation.
pub(in crate::admission_operation_store) fn workflow_resume_requested(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<bool, AdmissionOperationStoreError> {
    Ok(workflow_quota(tx, &record.scope, &record.workflow_id)?.commands[3].get() != 0)
}

/// Observe a charged original Report purpose on the exact current physical WF.
/// Same-value aliases and Inspect do not charge this purpose. The bool supplies
/// no feedback body, source authority, mutation allowance or resource credit.
pub(in crate::admission_operation_store) fn workflow_report_requested(
    tx: &Connection,
    physical: &RecoveryWorkflowRecordV1,
) -> Result<bool, AdmissionOperationStoreError> {
    let key = workflow_key(&physical.scope, &physical.workflow_id)?;
    let row = raw_checked(tx, &key)?
        .ok_or_else(|| invariant("original report charge lost its physical workflow"))?;
    let source = source_reference(tx, &key)?;
    if row.kind != "workflow"
        || row.scope != scope_key(&physical.scope)?
        || row.version != physical.revision.get()
        || source.version() != row.version
        || row.payload != encode(physical)?
    {
        return Err(invariant(
            "original report charge requires the current physical workflow",
        ));
    }
    // The ordinary typed loader verifies current quota/global heads, the exact
    // immutable FIRST preimage, fixed purpose ceilings and physical revision.
    // Its pre-baseline total is not reinterpreted as a Report-purpose count.
    Ok(workflow_quota(tx, &physical.scope, &physical.workflow_id)?.commands[5].get() != 0)
}

fn workflow_quota_with_count(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
    verified_commands: Option<u64>,
) -> Result<WorkflowQuota, AdmissionOperationStoreError> {
    let key = quota_key(scope, workflow)?;
    let physical_key = workflow_key(scope, workflow)?;
    let workflow_row = raw_checked(tx, &physical_key)?;
    if workflow_row.is_some() {
        source_reference(tx, &physical_key)?;
    }
    let revision = match &workflow_row {
        Some(row) => {
            let record: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
            if row.scope != scope_key(scope)?
                || row.kind != "workflow"
                || record.scope != *scope
                || record.workflow_id != *workflow
                || record.revision.get() != row.version
            {
                return Err(invariant("recovery workflow quota owner changed"));
            }
            row.version
        }
        None => 0,
    };
    if let Some(row) = raw_checked(tx, &key)? {
        source_reference(tx, &key)?;
        if row.payload.len() > MAX_WORKFLOW_QUOTA_BYTES
            || row.scope != scope_key(scope)?
            || row.kind != "command"
        {
            return Err(invariant("recovery workflow quota is corrupt"));
        }
        let quota: WorkflowQuota = decode(&row.payload)?;
        // Normal writes read the authenticated counter. Startup independently
        // rederives the immutable command inventory without a lifetime ceiling.
        let commands = match verified_commands {
            Some(commands) => commands,
            None => quota
                .baseline_commands
                .get()
                .checked_add(quota.command_units()?)
                .ok_or_else(|| invariant("recovery command count exhausted"))?,
        };
        quota.validate(tx, scope, workflow, revision, commands, row.version)?;
        if let Some(archive) = &quota.native_archive {
            let retained: RecoveryWorkflowRecordV1 = decode(
                &workflow_row
                    .as_ref()
                    .ok_or_else(|| invariant("recovery archive workflow disappeared"))?
                    .payload,
            )?;
            if retained.deployment_digest != archive.deployment_digest
                || (retained.captured
                    && retained
                        .captured_deployment
                        .as_ref()
                        .is_none_or(|reference| {
                            reference.deployment_digest != archive.deployment_digest
                                || reference.record_version.get() != 1
                        }))
            {
                return Err(invariant("recovery archive workflow reference changed"));
            }
        }
        return Ok(quota);
    }
    if retained_history(tx, &key)? {
        return Err(invariant("recovery workflow quota projection disappeared"));
    }
    terminal_allocation::require_absent_terminal(tx, scope, workflow)?;
    release_allocation::require_absent_release(tx, scope, workflow)?;
    let commands = match verified_commands {
        Some(commands) => commands,
        None if workflow_row.is_some() => owned_commands(tx, scope, workflow)?,
        None => {
            if retained_history(tx, &workflow_key(scope, workflow)?)? {
                return Err(invariant(
                    "recovery quota owner disappeared with retained history",
                ));
            }
            0
        }
    };
    Ok(WorkflowQuota {
        schema: WorkflowQuotaSchema::V1,
        scope: scope.clone(),
        workflow_id: workflow.clone(),
        baseline_revision: SafeInteger::new(revision)
            .map_err(|_| invariant("recovery quota baseline refused"))?,
        baseline_commands: SafeInteger::new(commands)
            .map_err(|_| invariant("recovery quota baseline refused"))?,
        planning: SafeInteger::ZERO,
        control: SafeInteger::ZERO,
        native: SafeInteger::ZERO,
        commands: [SafeInteger::ZERO; 6],
        native_archive: None,
        native_hold: None,
        native_terminal: None,
        native_release: None,
    })
}

fn save_quota(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    quota: &WorkflowQuota,
) -> Result<(), AdmissionOperationStoreError> {
    let payload = encode(quota)?;
    if payload.len() > MAX_WORKFLOW_QUOTA_BYTES || quota.units()? == 0 {
        return Err(invariant("recovery workflow quota resource exhausted"));
    }
    persist_record(
        tx,
        owner,
        &quota_key(&quota.scope, &quota.workflow_id)?,
        &scope_key(&quota.scope)?,
        "command",
        &payload,
        None,
    )?;
    workflow_quota(tx, &quota.scope, &quota.workflow_id)?;
    Ok(())
}

pub(in crate::admission_operation_store) fn require_command_slot(
    tx: &Transaction<'_>,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
    body: &RecoveryCommandBodyV1,
) -> Result<(), AdmissionOperationStoreError> {
    let slot = command_slot(body)?;
    #[cfg(feature = "admission-test-support")]
    if command_quota_test_support::constructing_legacy_workflow(tx, scope, workflow, false)? {
        return Ok(());
    }
    if workflow_quota(tx, scope, workflow)?.commands[slot].get() >= COMMAND_SLOT_CEILINGS[slot] {
        return Err(invariant("recovery command quota exhausted"));
    }
    Ok(())
}

pub(in crate::admission_operation_store) fn save_workflow(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &mut RecoveryWorkflowRecordV1,
    class: WorkflowWriteClass,
) -> Result<(), AdmissionOperationStoreError> {
    let key = workflow_key(&record.scope, &record.workflow_id)?;
    let existing = raw(tx, &key)?;
    if let Some(row) = &existing {
        let physical: RecoveryWorkflowRecordV1 = decode(&row.payload)?;
        if !physical.captured
            && physical.origin.is_some()
            && !original_owner_is_current(tx, &physical)?
        {
            return Err(invariant(
                "closed original owner cannot acquire another workflow mutation",
            ));
        }
        if auxiliary_historical_hold(tx, &physical)?.is_some() {
            return Err(invariant("auxiliary held workflow cannot be rewritten"));
        }
        if auxiliary_captured_terminal(tx, &physical)?.is_some() {
            return Err(invariant("auxiliary terminal workflow cannot be rewritten"));
        }
        if auxiliary_captured_release(tx, &physical)?.is_some() {
            return Err(invariant("auxiliary released workflow cannot be rewritten"));
        }
    }
    #[cfg(feature = "admission-test-support")]
    let legacy = command_quota_test_support::constructing_legacy_workflow(
        tx,
        &record.scope,
        &record.workflow_id,
        true,
    )?;
    #[cfg(not(feature = "admission-test-support"))]
    let legacy = false;
    if existing.is_none() {
        if !legacy {
            super::active_workflows::require_capacity(tx, owner, &record.scope)?;
        }
        if !matches!(class, WorkflowWriteClass::Planning) {
            return Err(invariant(
                "new recovery workflow must reserve planning capacity",
            ));
        }
    }
    let is_new = existing.is_none();
    let next = existing.map_or(Ok(1), |row| {
        row.version
            .checked_add(1)
            .ok_or_else(|| invariant("recovery version exhausted"))
    })?;
    let mut quota = (!legacy)
        .then(|| workflow_quota(tx, &record.scope, &record.workflow_id))
        .transpose()?;
    if let Some(quota) = &mut quota {
        let (used, ceiling) = match class {
            WorkflowWriteClass::Planning => (&mut quota.planning, WORKFLOW_SLOT_CEILINGS[0]),
            WorkflowWriteClass::Control => (&mut quota.control, WORKFLOW_SLOT_CEILINGS[1]),
            WorkflowWriteClass::Native => (&mut quota.native, WORKFLOW_SLOT_CEILINGS[2]),
        };
        if used.get() >= ceiling {
            return Err(invariant("recovery workflow allowance exhausted"));
        }
        *used = SafeInteger::new(used.get() + 1)
            .map_err(|_| invariant("recovery workflow allowance exhausted"))?;
    }
    record.revision =
        SafeInteger::new(next).map_err(|_| invariant("recovery version exhausted"))?;
    let native = record
        .admission
        .as_ref()
        .map(|intent| AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone()))
        .transpose()?;
    let initial = record.action.as_ref().map(|action| {
        (
            hex(action.request_namespace.as_bytes()),
            action.request_id.as_str(),
        )
    });
    let binding = native
        .as_ref()
        .map(|binding| {
            (
                binding.request_namespace_digest().as_str(),
                binding.request_id().as_str(),
            )
        })
        .or_else(|| {
            initial
                .as_ref()
                .map(|(namespace, request)| (namespace.as_str(), *request))
        });
    persist_record(
        tx,
        owner,
        &key,
        &scope_key(&record.scope)?,
        "workflow",
        &encode(record)?,
        binding,
    )?;
    if let Some(quota) = quota {
        save_quota(tx, owner, &quota)?;
    }
    if !legacy && is_new {
        super::active_workflows::register(tx, owner, record)?;
    }
    super::active_workflows::retire_cancelled(tx, owner, record)?;
    Ok(())
}

/// The body and owner were validated by commands::apply in this writer.
pub(in crate::admission_operation_store) fn save_command(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    key: &str,
    scope: &str,
    payload: &[u8],
    body: &RecoveryCommandBodyV1,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if !key.starts_with("command:")
        || scope != scope_key(&record.scope)?
        || payload.len() > MAX_WORKFLOW_COMMAND_BYTES
    {
        return Err(invariant("recovery command resource identity refused"));
    }
    let slot = command_slot(body)?;
    let (_, response) = commands::decode_record(payload)?;
    if response.workflow_id != record.workflow_id
        || response.revision != record.revision
        || raw(tx, key)?.is_some()
    {
        return Err(invariant("recovery command owner changed"));
    }
    #[cfg(feature = "admission-test-support")]
    let legacy = command_quota_test_support::constructing_legacy_workflow(
        tx,
        &record.scope,
        &record.workflow_id,
        false,
    )?;
    #[cfg(not(feature = "admission-test-support"))]
    let legacy = false;
    let mut quota = (!legacy)
        .then(|| workflow_quota(tx, &record.scope, &record.workflow_id))
        .transpose()?;
    if let Some(quota) = &mut quota {
        let used = &mut quota.commands[slot];
        if used.get() >= COMMAND_SLOT_CEILINGS[slot] {
            return Err(invariant("recovery command quota exhausted"));
        }
        *used = SafeInteger::new(used.get() + 1)
            .map_err(|_| invariant("recovery command quota exhausted"))?;
    }
    #[cfg(feature = "admission-test-support")]
    if legacy {
        command_quota_test_support::retain_legacy_command_identity(
            tx,
            &record.scope,
            &record.workflow_id,
        )?;
    }
    persist_record(tx, owner, key, scope, "command", payload, None)?;
    if let Some(quota) = quota {
        save_quota(tx, owner, &quota)?;
    }
    Ok(())
}

#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) fn save_legacy_inspection(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    record: &RecoveryWorkflowRecordV1,
    command_id: &CommandId,
) -> Result<(), AdmissionOperationStoreError> {
    if actor.permission() != RecoveryPermission::Inspect
        || actor.scope() != &record.scope
        || !command_id.as_str().starts_with("legacy-status-poll-")
    {
        return Err(invariant("legacy inspection identity refused"));
    }
    let body = RecoveryCommandBodyV1::InspectWorkflow {
        workflow_id: record.workflow_id.clone(),
    };
    let key = format!(
        "command:{}",
        sha256_hex(&encode(&(
            actor.scope(),
            actor.principal(),
            body.permission(),
            command_id,
        ))?)
    );
    if raw(tx, &key)?.is_some() {
        return Err(invariant("legacy inspection identity already retained"));
    }
    command_quota_test_support::retain_legacy_command_identity(
        tx,
        actor.scope(),
        &record.workflow_id,
    )?;
    let response = RecoveryCommandResponseV1 {
        command_id: command_id.clone(),
        workflow_id: record.workflow_id.clone(),
        revision: record.revision,
        control: record.control,
        effect: record.effect.clone(),
        release: record.release.clone(),
    };
    let payload = encode(
        &serde_json::json!({ "digest": CommandDigest::from_bytes(hash(RecoveryDigestDomain::Command, &body)?), "response": response }),
    )?;
    persist_record(
        tx,
        owner,
        &key,
        &scope_key(actor.scope())?,
        "command",
        &payload,
        None,
    )
}

/// One exact captured deployment snapshot has its own native allocation.
pub(in crate::admission_operation_store) fn save_captured_deployment_history(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
    operation: &AdmissionOperationV1,
    profile: &RecoveryDeploymentV1,
) -> Result<(), AdmissionOperationStoreError> {
    let retained = workflow_tx(tx, &record.scope, &record.workflow_id)?;
    let current = deployment_tx(tx, &record.scope)?;
    let digest = DeploymentDigest::from_bytes(hash(RecoveryDigestDomain::Deployment, profile)?);
    let intent = record
        .admission
        .as_ref()
        .ok_or_else(|| invariant("recovery capture intent is absent"))?;
    if encode(&retained)? != encode(record)?
        || encode(&current)? != encode(profile)?
        || record.captured
        || record.admission_closed
        || record.control != WorkflowControlV1::Active
        || record.historical_hold.is_some()
        || profile.scope != record.scope
        || digest != record.deployment_digest
        || intent.native_binding != operation.binding().to_persisted()
        || record.native_link.as_ref().map(OperationId::as_str)
            != Some(operation.binding().operation_id().as_str())
        || owner.fence.store_uuid != record.scope.authority_domain.as_str()
    {
        return Err(invariant("recovery capture archive owner refused"));
    }
    let key = format!(
        "deployment-history:{}:{}",
        scope_key(&record.scope)?,
        hex(digest.as_bytes())
    );
    let payload = encode(profile)?;
    if let Some(existing) = raw(tx, &key)? {
        if existing.version != 1
            || existing.kind != "deployment"
            || existing.scope != scope_key(&record.scope)?
            || existing.payload != payload
        {
            return Err(invariant("recovery capture archive changed"));
        }
        return Ok(());
    }
    let mut quota = workflow_quota(tx, &record.scope, &record.workflow_id)?;
    if quota.native_archive.is_some() {
        return Err(invariant("recovery capture archive allocation exhausted"));
    }
    persist_record(
        tx,
        owner,
        &key,
        &scope_key(&record.scope)?,
        "deployment",
        &payload,
        None,
    )?;
    quota.native_archive = Some(WorkflowArchiveAllocation {
        record_key: key,
        deployment_digest: digest,
        record_version: SafeInteger::new(1)
            .map_err(|_| invariant("recovery archive version refused"))?,
    });
    save_quota(tx, owner, &quota)
}

/// Ordinary participants cannot declare a workflow/native write class.
pub(super) fn verify_native_archive_allocations(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE record_key GLOB 'workflow-quota:*'
           AND json_extract(payload,'$.native_archive') IS NOT NULL ORDER BY record_key",
        )
        .map_err(sqlite_error)?;
    for key in statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key = key.map_err(sqlite_error)?;
        let row =
            raw(tx, &key)?.ok_or_else(|| invariant("recovery archive allocation disappeared"))?;
        let quota: WorkflowQuota = decode(&row.payload)?;
        if key != quota_key(&quota.scope, &quota.workflow_id)? {
            return Err(invariant("recovery archive allocation owner changed"));
        }
        workflow_quota(tx, &quota.scope, &quota.workflow_id)?;
    }
    Ok(())
}

pub(super) fn verify_all(tx: &Connection) -> Result<(), AdmissionOperationStoreError> {
    let mut commands = tx.prepare(
        "SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'command:*' ORDER BY record_key",
    ).map_err(sqlite_error)?;
    for key in commands
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let row = raw(tx, &key.map_err(sqlite_error)?)?
            .ok_or_else(|| invariant("recovery command identity disappeared"))?;
        let (_, response) = super::super::commands::decode_record(&row.payload)?;
        let owner: Option<(i64, Vec<u8>)> = tx.query_row(
            "SELECT version,payload FROM admission_operation_recovery_records
             WHERE record_key=('workflow:' || ?1 || ':' || ?2) AND kind='workflow' AND scope_key=?1",
            params![&row.scope, response.workflow_id.as_str()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(sqlite_error)?;
        let (version, payload) =
            owner.ok_or_else(|| invariant("recovery command workflow disappeared"))?;
        let record: RecoveryWorkflowRecordV1 = decode(&payload)?;
        if row.kind != "command"
            || row.version != 1
            || row.scope != scope_key(&record.scope)?
            || record.workflow_id != response.workflow_id
            || response.revision.get() == 0
            || record.revision.get() != stored_u64(version, "recovery command workflow version")?
            || response.revision.get() > record.revision.get()
        {
            return Err(invariant("recovery command workflow scope changed"));
        }
    }
    let mut statement = tx.prepare("SELECT record_key FROM admission_operation_recovery_records WHERE record_key GLOB 'workflow-quota:*' ORDER BY record_key").map_err(sqlite_error)?;
    for key in statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sqlite_error)?
    {
        let key = key.map_err(sqlite_error)?;
        let row = raw(tx, &key)?.ok_or_else(|| invariant("recovery workflow quota disappeared"))?;
        let quota: WorkflowQuota = decode(&row.payload)?;
        if key != quota_key(&quota.scope, &quota.workflow_id)? {
            return Err(invariant("recovery workflow quota owner changed"));
        }
        workflow_quota_with_count(
            tx,
            &quota.scope,
            &quota.workflow_id,
            Some(owned_commands(tx, &quota.scope, &quota.workflow_id)?),
        )?;
    }
    Ok(())
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Model predecessor allowance exhaustion only on a genuine finalizing
    /// capture. Typed native writes change physical revision and its counter.
    pub fn exhaust_captured_finalizing_native_allowance_for_test(
        &self,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(&self.serving_owner.fence))?;
        let mut record = workflow_tx(&tx, scope, workflow)?;
        super::super::historical_holds::require_unheld(&tx, &record)?;
        let before = record.clone();
        let intent = record
            .admission
            .as_ref()
            .ok_or_else(|| invariant("finalizing allowance fixture intent absent"))?;
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
        let native = load_by_operation_id_tx(&tx, binding.operation_id())?
            .ok_or_else(|| invariant("finalizing allowance fixture native absent"))?;
        if native.operation.state() != AdmissionOperationState::Finalizing {
            return Err(invariant(
                "allowance fixture requires actual Finalizing custody",
            ));
        }
        let (captured, roots) =
            native::captured_custody(&tx, binding.operation_id(), &self.serving_owner.fence)?
                .ok_or_else(|| invariant("finalizing allowance fixture capture absent"))?;
        if encode(&captured)? != encode(&record)?
            || !matches!(roots, RecoveryCapturedDeploymentV1::Verified(_))
        {
            return Err(invariant("finalizing allowance fixture roots unavailable"));
        }
        let native_before = encode(&native.operation.to_persisted())?;
        for _ in 0..WORKFLOW_SLOT_CEILINGS[2] {
            if workflow_quota(&tx, scope, workflow)?.native.get() == WORKFLOW_SLOT_CEILINGS[2] {
                break;
            }
            save_workflow(
                &tx,
                &self.serving_owner,
                &mut record,
                WorkflowWriteClass::Native,
            )?;
        }
        if workflow_quota(&tx, scope, workflow)?.native.get() != WORKFLOW_SLOT_CEILINGS[2] {
            return Err(invariant("finalizing allowance fixture missed native128"));
        }
        let current = load_by_operation_id_tx(&tx, binding.operation_id())?
            .ok_or_else(|| invariant("finalizing allowance fixture native disappeared"))?;
        if encode(&current.operation.to_persisted())? != native_before {
            return Err(invariant(
                "allowance fixture changed original native custody",
            ));
        }
        let mut normalized = record;
        normalized.revision = before.revision;
        if encode(&normalized)? != encode(&before)? {
            return Err(invariant(
                "allowance fixture changed captured source fields",
            ));
        }
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }

    /// Bounded exhausted-allowance fixture. This never replaces a payload,
    /// baseline, native operation, signed proof or capture fact supplied by a test.
    pub fn exhaust_captured_recovery_native_allowance_for_test(
        &self,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<(), AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(&self.serving_owner.fence))?;
        let mut record = workflow_tx(&tx, scope, workflow)?;
        super::super::historical_holds::require_unheld(&tx, &record)?;
        let intent = record
            .admission
            .as_ref()
            .ok_or_else(|| invariant("native allowance fixture intent absent"))?;
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
        native::captured_custody(&tx, binding.operation_id(), &self.serving_owner.fence)?
            .ok_or_else(|| invariant("native allowance fixture capture absent"))?;
        for _ in 0..WORKFLOW_SLOT_CEILINGS[2] {
            if workflow_quota(&tx, scope, workflow)?.native.get() == WORKFLOW_SLOT_CEILINGS[2] {
                break;
            }
            save_workflow(
                &tx,
                &self.serving_owner,
                &mut record,
                WorkflowWriteClass::Native,
            )?;
        }
        if workflow_quota(&tx, scope, workflow)?.native.get() != WORKFLOW_SLOT_CEILINGS[2] {
            return Err(invariant(
                "native allowance fixture did not reach its bound",
            ));
        }
        self.commit_write(tx)?;
        self.sync_after_write(&connection)
    }
}
