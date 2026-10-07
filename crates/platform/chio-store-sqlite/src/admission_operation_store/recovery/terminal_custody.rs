//! Bounded original terminal facts keep captured workflow bytes immutable.
use super::*;
use serde::{Deserialize, Serialize};

pub(in crate::admission_operation_store) const MAX_TERMINAL_CUSTODY_BYTES: usize = 4096;

pub(in crate::admission_operation_store) fn require_current_terminal_format(
    tx: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let version: Option<i32> = tx
        .query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key=?1",
            [ADMISSION_OPERATION_SCHEMA_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    if ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION < 39
        || version != Some(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)
    {
        return Err(invariant(
            "captured terminal custody requires the current serving format",
        ));
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct CapturedWorkflowTerminalV1 {
    schema: TerminalSchema,
    workflow_id: WorkflowId,
    workflow_source: WorkflowSource,
    operation: OperationRef,
    projection_digest: ProjectionDigest,
    effect_count: SafeInteger,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum TerminalSchema {
    #[serde(rename = "chio.recovery.captured-terminal.v1")]
    V1,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WorkflowSource {
    version: SafeInteger,
    digest: ProjectionDigest,
    event_sequence: SafeInteger,
    global_commit_sequence: SafeInteger,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct CapturedWorkflowReleaseV1 {
    schema: ReleaseSchema,
    workflow_id: WorkflowId,
    terminal_digest: ProjectionDigest,
    operation: OperationRef,
    deployment_digest: DeploymentDigest,
    authority_scope: AuthorityScopeDigest,
    principal: chio_security_types::PrincipalId,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
enum ReleaseSchema {
    #[serde(rename = "chio.recovery.captured-release.v1")]
    V1,
}

pub(in crate::admission_operation_store) fn terminal_key(
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "captured-terminal:{}:{}",
        scope_key(scope)?,
        workflow.as_str()
    ))
}

pub(in crate::admission_operation_store) fn release_key(
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "captured-release:{}:{}",
        scope_key(scope)?,
        workflow.as_str()
    ))
}

/// The qualified native terminal writer invokes this before its transaction
/// commits. No external actor or current disclosure policy is involved.
pub(in crate::admission_operation_store) fn publish_completed(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    operation: &AdmissionOperationV1,
) -> Result<bool, AdmissionOperationStoreError> {
    if operation.state() != AdmissionOperationState::Completed {
        return Ok(false);
    }
    let Some(record) = native::located(tx, operation.binding())? else {
        return Ok(false);
    };
    if !record.captured {
        return Err(invariant(
            "completed recovery original lacks captured custody",
        ));
    }
    require_current_terminal_format(tx)?;
    let id = operation.binding().operation_id();
    let stored = load_by_operation_id_tx(tx, id)?
        .ok_or_else(|| invariant("captured terminal original operation absent"))?;
    if stored.operation != *operation {
        return Err(invariant(
            "captured terminal selected another original operation",
        ));
    }
    super::super::projection::verify_stored_terminal_projection(tx, &stored)?;
    let Some((record, custody)) = native::captured_custody(tx, id, &owner.fence)? else {
        return Err(invariant("captured terminal original custody absent"));
    };
    if historical_holds::effective(tx, &record)?.is_some() {
        return Ok(false);
    }
    match custody {
        RecoveryCapturedDeploymentV1::Verified(_) => {}
        RecoveryCapturedDeploymentV1::LegacyUnavailable => {
            native::quarantine_historical(
                tx,
                owner,
                id,
                RecoveryHistoricalHoldReasonV1::LegacyDeploymentUnavailable,
            )?;
            return Ok(true);
        }
        RecoveryCapturedDeploymentV1::Quarantined => {
            return Err(invariant("captured terminal verifier is unavailable"))
        }
    }
    let reference = native::operation_ref(operation)?;
    let complete = EffectObservationV1::Complete {
        operation: reference.clone(),
        effect_count: record.effect_cardinality,
    };
    if record.effect.is_settled() && record.effect != complete {
        return Err(invariant(
            "captured terminal changes a settled original fact",
        ));
    }
    let source = source_reference(tx, &workflow_key(&record.scope, &record.workflow_id)?)?;
    let terminal = CapturedWorkflowTerminalV1 {
        schema: TerminalSchema::V1,
        workflow_id: record.workflow_id.clone(),
        workflow_source: WorkflowSource {
            version: safe(source.version())?,
            digest: *source.digest(),
            event_sequence: safe(source.event_sequence())?,
            global_commit_sequence: safe(source.global_commit_sequence())?,
        },
        operation: reference,
        projection_digest: terminal_digest(operation)?,
        effect_count: record.effect_cardinality,
    };
    save_auxiliary_captured_terminal(tx, owner, &record, &terminal)
}

/// Called only after the owning result writer validates current release basis.
/// Repeated release records add no mutation and never replace current checks.
pub(super) fn publish_release(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    record: &RecoveryWorkflowRecordV1,
    actor: &AuthenticatedRecoveryActor,
    profile: &RecoveryDeploymentV1,
    operation: &AdmissionOperationV1,
) -> Result<(), AdmissionOperationStoreError> {
    require_current_terminal_format(tx)?;
    if auxiliary_captured_release(tx, record)?.is_some() {
        return Ok(());
    }
    publish_completed(tx, owner, operation)?;
    if auxiliary_captured_terminal(tx, record)?.is_none() {
        return Err(invariant("captured result release lacks terminal custody"));
    }
    let release = CapturedWorkflowReleaseV1 {
        schema: ReleaseSchema::V1,
        workflow_id: record.workflow_id.clone(),
        terminal_digest: *source_reference(tx, &terminal_key(&record.scope, &record.workflow_id)?)?
            .digest(),
        operation: native::operation_ref(operation)?,
        deployment_digest: DeploymentDigest::from_bytes(hash(
            chio_core::recovery::RecoveryDigestDomain::Deployment,
            profile,
        )?),
        authority_scope: profile.authority_scope,
        principal: actor.principal().clone(),
    };
    save_auxiliary_captured_release(tx, owner, record, &release)?;
    Ok(())
}

/// Project authenticated terminal facts into a clone for observation only.
/// Callers that persist a workflow must keep its unchanged physical record.
pub(in crate::admission_operation_store) fn view(
    tx: &Connection,
    mut physical: RecoveryWorkflowRecordV1,
) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
    let terminal = auxiliary_captured_terminal(tx, &physical)?;
    let release = auxiliary_captured_release(tx, &physical)?;
    if let Some(terminal) = terminal {
        let complete = EffectObservationV1::Complete {
            operation: terminal.operation.clone(),
            effect_count: terminal.effect_count,
        };
        if physical.effect.is_settled() && physical.effect != complete {
            return Err(invariant(
                "captured terminal contradicts a settled workflow",
            ));
        }
        physical.effect = complete;
        physical.admission_closed = true;
        if release.is_some() {
            physical.release = ReleaseDispositionV1::Released {
                release_id: ReleaseId::new(&format!(
                    "output:{}",
                    terminal.operation.operation_id().as_str()
                ))
                .map_err(|_| invariant("captured release identity refused"))?,
            };
        } else if !matches!(physical.release, ReleaseDispositionV1::Released { .. }) {
            physical.release = ReleaseDispositionV1::Withheld {
                evidence: EvidenceRef::new(&format!(
                    "output:{}",
                    terminal.operation.operation_id().as_str()
                ))
                .map_err(|_| invariant("captured terminal identity refused"))?,
            };
        }
    } else if release.is_some() {
        return Err(invariant("captured release lacks its original terminal"));
    }
    physical.reported_decision = commands::reported_feedback(tx, &physical)?;
    Ok(physical)
}

pub(super) fn require_unfinished(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<(), AdmissionOperationStoreError> {
    if auxiliary_captured_terminal(tx, record)?.is_some() {
        return Err(invariant("captured recovery original is already complete"));
    }
    Ok(())
}

/// Quota authentication calls this verifier. It never reads quota or a derived
/// workflow view and therefore cannot recursively authenticate its own pointer.
pub(in crate::admission_operation_store) fn verify_terminal(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
    terminal: &CapturedWorkflowTerminalV1,
) -> Result<(), AdmissionOperationStoreError> {
    let record = workflow_tx(tx, scope, workflow)?;
    let source = source_reference(tx, &workflow_key(scope, workflow)?)?;
    if terminal.workflow_id != *workflow
        || source.kind() != "workflow"
        || source.scope_key() != scope_key(scope)?
        || terminal.workflow_source.version.get() != source.version()
        || &terminal.workflow_source.digest != source.digest()
        || terminal.workflow_source.event_sequence.get() != source.event_sequence()
        || terminal.workflow_source.global_commit_sequence.get() != source.global_commit_sequence()
        || terminal.effect_count != record.effect_cardinality
    {
        return Err(invariant("captured terminal workflow source changed"));
    }
    require_bounded(terminal)?;
    let operation =
        AdmissionOperationId::from_persisted(terminal.operation.operation_id().as_str())?;
    let stored = load_by_operation_id_tx(tx, &operation)?
        .ok_or_else(|| invariant("captured terminal original operation absent"))?;
    if stored.operation.state() != AdmissionOperationState::Completed
        || native::operation_ref(&stored.operation)? != terminal.operation
        || terminal_digest(&stored.operation)? != terminal.projection_digest
    {
        return Err(invariant("captured terminal original native fact changed"));
    }
    let original = native::verify_physical_capture(tx, &record, &stored.operation)?;
    super::super::projection::verify_stored_terminal_projection(tx, &stored)?;
    let fence = retained_store_fence(tx)?;
    let profile = match deployment_history::lookup(tx, &record, &fence)? {
        RecoveryCapturedDeploymentV1::Verified(profile) => profile,
        RecoveryCapturedDeploymentV1::LegacyUnavailable
        | RecoveryCapturedDeploymentV1::Quarantined => {
            return Err(invariant("captured terminal original verifier unavailable"))
        }
    };
    native::verify_captured_roots(tx, &record, &stored.operation, &original, &profile)
}

/// A retained release is historical data. Public delivery still revalidates
/// current actor, policy, classifier and every inherited restriction.
pub(in crate::admission_operation_store) fn verify_release(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    workflow: &WorkflowId,
    release: &CapturedWorkflowReleaseV1,
) -> Result<(), AdmissionOperationStoreError> {
    require_bounded(release)?;
    let terminal_key = terminal_key(scope, workflow)?;
    let row = raw_checked(tx, &terminal_key)?
        .ok_or_else(|| invariant("captured release lost its terminal custody"))?;
    if row.kind != "command" || row.version != 1 || row.scope != scope_key(scope)? {
        return Err(invariant("captured release terminal header changed"));
    }
    let terminal: CapturedWorkflowTerminalV1 = decode(&row.payload)?;
    verify_terminal(tx, scope, workflow, &terminal)?;
    if release.workflow_id != *workflow
        || release.operation != terminal.operation
        || &release.terminal_digest != source_reference(tx, &terminal_key)?.digest()
    {
        return Err(invariant("captured release original terminal changed"));
    }
    let key = release_key(scope, workflow)?;
    let profile = if raw_checked(tx, &key)?.is_some() {
        deployment_history::original_record_deployment(tx, scope, &key)?
            .ok_or_else(|| invariant("captured release original current profile unavailable"))?
    } else {
        // Only the exact first publication uses the current profile. The
        // qualified writer has already checked current release authority.
        deployment_tx(tx, scope)?
    };
    if release.deployment_digest
        != DeploymentDigest::from_bytes(hash(
            chio_core::recovery::RecoveryDigestDomain::Deployment,
            &profile,
        )?)
        || release.authority_scope != profile.authority_scope
        || !profile.actors.as_slice().iter().any(|assignment| {
            assignment.principal == release.principal
                && assignment.permissions.as_slice().iter().any(|permission| {
                    matches!(
                        permission,
                        RecoveryPermission::Resume | RecoveryPermission::Inspect
                    )
                })
        })
    {
        return Err(invariant(
            "captured release historical actor profile changed",
        ));
    }
    Ok(())
}

fn retained_store_fence(
    tx: &Connection,
) -> Result<StoreMutationFence, AdmissionOperationStoreError> {
    let (store_uuid, lease_id, owner_epoch): (String, Option<String>, i64) = tx
        .query_row(
            "SELECT store_uuid,lease_id,owner_epoch FROM chio_serving_owner WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(sqlite_error)?;
    Ok(StoreMutationFence {
        store_uuid,
        lease_id: lease_id.ok_or_else(|| invariant("captured terminal serving lease absent"))?,
        owner_epoch: stored_u64(owner_epoch, "captured terminal serving owner")?,
    })
}

fn terminal_digest(
    operation: &AdmissionOperationV1,
) -> Result<ProjectionDigest, AdmissionOperationStoreError> {
    let digest = operation
        .terminal_replay()
        .ok_or_else(|| invariant("captured terminal projection absent"))?
        .projection_digest()
        .as_str();
    Ok(ProjectionDigest::from_bytes(native::decode_hex(digest)?))
}

fn require_bounded<T: Serialize>(value: &T) -> Result<(), AdmissionOperationStoreError> {
    if encode(value)?.len() > MAX_TERMINAL_CUSTODY_BYTES {
        return Err(invariant("captured terminal custody exceeds its bound"));
    }
    Ok(())
}

fn safe(value: u64) -> Result<SafeInteger, AdmissionOperationStoreError> {
    SafeInteger::new(value).map_err(|_| invariant("captured terminal source value refused"))
}

/// Previously qualified native completions may precede auxiliary custody.
/// Fixed key pages keep cold repair bounded per operation and in memory.
pub(crate) fn repair_completed_at_startup(
    connection: &mut Connection,
    owner: &SqliteServingOwner,
) -> Result<usize, crate::SqliteServingOwnerError> {
    let mut cursor = String::new();
    let mut repaired = 0_usize;
    loop {
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(crate::SqliteServingOwnerError::from)?;
        verify_active_owner(&tx, owner, Some(&owner.fence)).map_err(startup_error)?;
        owner.verify_authority_anchor(&tx)?;
        require_current_terminal_format(&tx).map_err(startup_error)?;
        let keys = {
            let mut statement = tx
                .prepare(
                    "SELECT record_key FROM admission_operation_recovery_records
                     WHERE kind='workflow' AND record_key>?1 ORDER BY record_key LIMIT 32",
                )
                .map_err(crate::SqliteServingOwnerError::from)?;
            let rows = statement
                .query_map([&cursor], |row| row.get::<_, String>(0))
                .map_err(crate::SqliteServingOwnerError::from)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(crate::SqliteServingOwnerError::from)?
        };
        let mut changed = false;
        for key in &keys {
            let raw = raw_checked(&tx, key)
                .map_err(startup_error)?
                .ok_or_else(|| startup_error(invariant("captured workflow disappeared")))?;
            let record: RecoveryWorkflowRecordV1 = decode(&raw.payload).map_err(startup_error)?;
            if raw.scope != scope_key(&record.scope).map_err(startup_error)?
                || key
                    != &workflow_key(&record.scope, &record.workflow_id).map_err(startup_error)?
                || raw.version != record.revision.get()
            {
                return Err(startup_error(invariant("captured workflow header changed")));
            }
            if !record.captured {
                continue;
            }
            let intent = record.admission.as_ref().ok_or_else(|| {
                startup_error(invariant("captured workflow original intent absent"))
            })?;
            let id = AdmissionOperationId::from_persisted(intent.native_operation_id.as_str())
                .map_err(AdmissionOperationStoreError::from)
                .map_err(startup_error)?;
            let stored = load_by_operation_id_tx(&tx, &id)
                .map_err(startup_error)?
                .ok_or_else(|| {
                    startup_error(invariant("captured workflow original operation absent"))
                })?;
            if stored.operation.state() == AdmissionOperationState::Completed
                && publish_completed(&tx, owner, &stored.operation).map_err(startup_error)?
            {
                changed = true;
                repaired = repaired.checked_add(1).ok_or_else(|| {
                    startup_error(invariant("captured workflow repair count exhausted"))
                })?;
            }
        }
        if let Some(last) = keys.last() {
            cursor = last.clone();
        }
        tx.commit().map_err(|error| {
            owner.outcome_unknown(format!(
                "captured workflow startup commit outcome unknown: {error}"
            ))
        })?;
        if changed {
            owner.sync_authority_anchor(connection)?;
        }
        if keys.len() < 32 {
            return Ok(repaired);
        }
    }
}

fn startup_error(error: AdmissionOperationStoreError) -> crate::SqliteServingOwnerError {
    crate::SqliteServingOwnerError::Invalid(error.to_string())
}

#[cfg(feature = "admission-test-support")]
impl SqliteAdmissionOperationStore {
    /// Read the authenticated private projection without granting public
    /// preview or output authority. This fixture never changes custody.
    pub fn inspect_captured_workflow_terminal_for_test(
        &self,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
    ) -> Result<RecoveryWorkflowRecordV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        let physical = workflow_tx(&tx, scope, workflow)?;
        if !physical.captured {
            return Err(invariant(
                "private terminal fixture requires captured custody",
            ));
        }
        let view = historical_holds::view(&tx, physical)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(view)
    }
}
