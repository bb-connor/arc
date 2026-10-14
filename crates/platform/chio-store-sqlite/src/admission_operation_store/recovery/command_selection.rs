//! A command selects retained physical custody in its actual owning transaction.
use super::*;
use crate::admission_operation_store::recovery::{commands, historical_holds};
use settled_command_aliases::retained_command_alias_outcome;

pub(in crate::admission_operation_store) fn command_outcome(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
    response: RecoveryCommandResponseV1,
) -> Result<RecoveryCommandPortOutcome, AdmissionOperationStoreError> {
    let (key, digest) = commands::identity(actor, command)?;
    let outcome = if matches!(
        command.command,
        RecoveryCommandBodyV1::InspectWorkflow { .. }
    ) {
        if actor.permission() != RecoveryPermission::Inspect {
            return Err(invariant("selected command permission changed"));
        }
        let physical = workflow_tx(tx, actor.scope(), &response.workflow_id)?;
        RecoveryCommandPortOutcome {
            selection: RecoveryCommandPortSelection {
                scope: actor.scope().clone(),
                workflow_id: response.workflow_id.clone(),
                command_id: response.command_id.clone(),
                command_digest: digest,
                accepted_root_revision: response.revision,
                generation: accepted_generation(tx, &physical, response.revision.get())?,
                mode: RecoveryCommandContinuationMode::ControlOnly,
            },
            response: response.clone(),
        }
    } else {
        retained_outcome(tx, actor, &key, &command.command_id)?
            .ok_or_else(|| invariant("selected command lost its committed identity"))?
    };
    if outcome.selection.command_digest != digest
        || encode(&outcome.response)? != encode(&response)?
        || outcome.selection.scope != *actor.scope()
        || outcome.selection.workflow_id != response.workflow_id
        || outcome.selection.command_id != command.command_id
        || outcome.selection.accepted_root_revision != response.revision
    {
        return Err(invariant("selected command changed its committed response"));
    }
    Ok(outcome)
}

fn command_key(
    actor: &AuthenticatedRecoveryActor,
    command: &CommandId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "command:{}",
        sha256_hex(&encode(&(
            actor.scope(),
            actor.principal(),
            actor.permission().wire_name(),
            command,
        ))?)
    ))
}

fn retained_outcome(
    tx: &Connection,
    actor: &AuthenticatedRecoveryActor,
    command_key: &str,
    command_id: &CommandId,
) -> Result<Option<RecoveryCommandPortOutcome>, AdmissionOperationStoreError> {
    let alias = retained_command_alias_outcome(tx, command_key, actor, command_id)?;
    let Some(row) = raw_checked(tx, command_key)? else {
        return Ok(alias);
    };
    if alias.is_some()
        || row.version != 1
        || row.scope != scope_key(actor.scope())?
        || row.kind != "command"
    {
        return Err(invariant("selected command retained namespace changed"));
    }
    let source = source_reference(tx, command_key)?;
    let native_none: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM admission_operation_recovery_records WHERE record_key=?1",
            [command_key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let (digest, response) = commands::decode_record(&row.payload)?;
    if !native_none || response.command_id != *command_id {
        return Err(invariant("selected command identity lost its exact frame"));
    }
    let physical = workflow_tx(tx, actor.scope(), &response.workflow_id)?;
    let generation = accepted_generation(tx, &physical, response.revision.get())?;
    if source.global_commit_sequence() <= generation.global_commit_sequence.get() {
        return Err(invariant("selected command precedes its accepted source"));
    }
    // Normal predecessor Resume identities may include old no-op commands.
    // They retain only this same fixed continuation. This is not a claim that
    // a purpose counter identifies one unique first command ID.
    let mode = if matches!(
        actor.permission(),
        RecoveryPermission::Create | RecoveryPermission::Resume
    ) {
        if original_owner_is_current(tx, &physical)? {
            RecoveryCommandContinuationMode::SameCurrentGeneration
        } else {
            RecoveryCommandContinuationMode::HistoricalGenerationReadOnly
        }
    } else {
        RecoveryCommandContinuationMode::ControlOnly
    };
    Ok(Some(RecoveryCommandPortOutcome {
        selection: RecoveryCommandPortSelection {
            scope: actor.scope().clone(),
            workflow_id: response.workflow_id.clone(),
            command_id: response.command_id.clone(),
            command_digest: digest,
            accepted_root_revision: response.revision,
            generation,
            mode,
        },
        response,
    }))
}

fn accepted_generation(
    tx: &Connection,
    physical: &RecoveryWorkflowRecordV1,
    accepted_revision: u64,
) -> Result<RecoveryCommandAcceptedGeneration, AdmissionOperationStoreError> {
    let key = workflow_key(&physical.scope, &physical.workflow_id)?;
    let current = source_reference(tx, &key)?;
    if current.kind() != "workflow"
        || current.scope_key() != scope_key(&physical.scope)?
        || current.version() != physical.revision.get()
        || accepted_revision == 0
        || accepted_revision > current.version()
    {
        return Err(invariant(
            "selected physical generation changed its latest head",
        ));
    }
    let (accepted_digest, accepted_global) =
        historical_record_reference(tx, &key, accepted_revision)?;
    let (initial_digest, initial_global) = historical_record_reference(tx, &key, 1)?;
    let accepted_event: i64 = tx
        .query_row(
            "SELECT sequence FROM admission_operation_recovery_events
             WHERE record_key=?1 AND record_version=?2",
            params![
                &key,
                i64::try_from(accepted_revision)
                    .map_err(|_| invariant("selected source version exhausted"))?
            ],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if initial_global > accepted_global {
        return Err(invariant(
            "selected generation precedes its immutable baseline",
        ));
    }
    Ok(RecoveryCommandAcceptedGeneration {
        record_key: RecoveryProtectedRecordKey::new(key)?,
        record_version: SafeInteger::new(accepted_revision)
            .map_err(|_| invariant("selected source version exhausted"))?,
        record_digest: projection_digest(&accepted_digest)?,
        event_sequence: SafeInteger::new(stored_u64(accepted_event, "selected source event")?)
            .map_err(|_| invariant("selected source event exhausted"))?,
        global_commit_sequence: SafeInteger::new(accepted_global)
            .map_err(|_| invariant("selected source commit exhausted"))?,
        initial_record_digest: projection_digest(&initial_digest)?,
        initial_global_commit_sequence: SafeInteger::new(initial_global)
            .map_err(|_| invariant("selected initial commit exhausted"))?,
        generation: RecoveryGenerationOrdinal::new(1)?,
        step_id: physical.step_id.clone(),
        continuation_id: physical.continuation_id.clone(),
    })
}

fn projection_digest(text: &str) -> Result<ProjectionDigest, AdmissionOperationStoreError> {
    let bytes: [u8; 32] = hex::decode(text)
        .map_err(|_| invariant("selected projection digest is corrupt"))?
        .try_into()
        .map_err(|_| invariant("selected projection digest is corrupt"))?;
    Ok(ProjectionDigest::from_bytes(bytes))
}

fn same_generation(
    actual: &RecoveryCommandAcceptedGeneration,
    expected: &RecoveryCommandAcceptedGeneration,
) -> bool {
    actual.record_key == expected.record_key
        && actual.record_version == expected.record_version
        && actual.record_digest == expected.record_digest
        && actual.event_sequence == expected.event_sequence
        && actual.global_commit_sequence == expected.global_commit_sequence
        && actual.initial_record_digest == expected.initial_record_digest
        && actual.initial_global_commit_sequence == expected.initial_global_commit_sequence
        && actual.generation == expected.generation
        && actual.step_id == expected.step_id
        && actual.continuation_id == expected.continuation_id
}

pub(in crate::admission_operation_store) fn load_selected_workflow(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    deployment: &RecoveryDeploymentV1,
    selection: &RecoveryCommandPortSelection,
) -> Result<RecoveryCommandSelectedWorkflowData, AdmissionOperationStoreError> {
    if selection.scope != *actor.scope()
        || selection.generation.generation.get() != 1
        || selection.accepted_root_revision != selection.generation.record_version
    {
        return Err(invariant(
            "selected generation changed its authenticated scope",
        ));
    }
    let physical = crate::admission_operation_store::recovery::workflow_preview_tx(
        tx,
        actor,
        deployment,
        &selection.workflow_id,
    )?;
    let actual = if actor.permission() == RecoveryPermission::Inspect {
        let body = RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: selection.workflow_id.clone(),
        };
        let digest = CommandDigest::from_bytes(hash(
            chio_core_types::recovery::RecoveryDigestDomain::Command,
            &body,
        )?);
        if selection.mode != RecoveryCommandContinuationMode::ControlOnly
            || selection.command_digest != digest
        {
            return Err(invariant("selected inspection acquired a driver mode"));
        }
        RecoveryCommandPortSelection {
            scope: actor.scope().clone(),
            workflow_id: selection.workflow_id.clone(),
            command_id: selection.command_id.clone(),
            command_digest: digest,
            accepted_root_revision: selection.accepted_root_revision,
            generation: accepted_generation(tx, &physical, selection.accepted_root_revision.get())?,
            mode: RecoveryCommandContinuationMode::ControlOnly,
        }
    } else {
        retained_outcome(
            tx,
            actor,
            &command_key(actor, &selection.command_id)?,
            &selection.command_id,
        )?
        .ok_or_else(|| invariant("selected command lost its retained source"))?
        .selection
    };
    if actual.scope != selection.scope
        || actual.workflow_id != selection.workflow_id
        || actual.command_id != selection.command_id
        || actual.command_digest != selection.command_digest
        || actual.accepted_root_revision != selection.accepted_root_revision
        || !same_generation(&actual.generation, &selection.generation)
        || physical.step_id != selection.generation.step_id
        || physical.continuation_id != selection.generation.continuation_id
    {
        return Err(invariant("selected command changed its immutable custody"));
    }
    let effective_mode = match (actual.mode, selection.mode) {
        (
            RecoveryCommandContinuationMode::ControlOnly,
            RecoveryCommandContinuationMode::ControlOnly,
        ) => RecoveryCommandContinuationMode::ControlOnly,
        (
            RecoveryCommandContinuationMode::SameCurrentGeneration,
            RecoveryCommandContinuationMode::SameCurrentGeneration,
        ) => RecoveryCommandContinuationMode::SameCurrentGeneration,
        (
            RecoveryCommandContinuationMode::SameCurrentGeneration,
            RecoveryCommandContinuationMode::HistoricalGenerationReadOnly,
        ) => RecoveryCommandContinuationMode::HistoricalGenerationReadOnly,
        (
            RecoveryCommandContinuationMode::HistoricalGenerationReadOnly,
            RecoveryCommandContinuationMode::SameCurrentGeneration
            | RecoveryCommandContinuationMode::HistoricalGenerationReadOnly,
        ) => RecoveryCommandContinuationMode::HistoricalGenerationReadOnly,
        _ => return Err(invariant("selected command upgraded its retained mode")),
    };
    Ok(RecoveryCommandSelectedWorkflowData {
        record: historical_holds::view(tx, physical)?,
        effective_mode,
    })
}

impl SqliteAdmissionOperationStore {
    /// Selection is authenticated before the same command transaction commits.
    pub(in crate::admission_operation_store) fn recovery_command_outcome(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        original_process: Option<&dyn RecoveryProcessOriginPort>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoveryCommandPortOutcome, RecoveryCommandPortError> {
        if actor.permission().wire_name() != command.command.permission() {
            return Err(invariant("recovery permission refused").into());
        }
        let result = (|| {
            let mut connection = self.connection()?;
            let read = self.begin_read(&mut connection)?;
            crate::admission_operation_store::schema::verify_active_owner(
                &read,
                &self.serving_owner,
                Some(fence),
            )?;
            let read_now =
                crate::admission_operation_store::schema::authority_validation_time(&read, now)?;
            let deployment = deployment_tx(&read, actor.scope())?;
            crate::admission_operation_store::recovery::verify_actor(
                &read,
                actor,
                &deployment,
                read_now,
            )?;
            let retained = commands::inspect_or_replay(
                &read,
                &self.serving_owner,
                actor,
                command,
                &deployment,
            )?;
            let intake = if retained.is_none() {
                commands::fresh_command_intake_headroom(&read, actor, command, &deployment)?
            } else {
                false
            };
            if let Some(response) = retained {
                let outcome = command_outcome(&read, actor, command, response)?;
                read.commit().map_err(sqlite_error)?;
                return Ok(outcome);
            }
            read.commit().map_err(sqlite_error)?;
            crate::admission_operation_store::recovery::resources::check(&connection, intake)?;
            let tx = self.begin_write(&mut connection, Some(fence))?;
            let now =
                crate::admission_operation_store::schema::authority_validation_time(&tx, now)?;
            let deployment = deployment_tx(&tx, actor.scope())?;
            crate::admission_operation_store::recovery::verify_actor(&tx, actor, &deployment, now)?;
            let response = commands::apply(
                &tx,
                &self.serving_owner,
                actor,
                command,
                &deployment,
                now,
                original_process,
            )?;
            let outcome = command_outcome(&tx, actor, command, response)?;
            self.commit_write(tx)?;
            self.sync_after_write(&connection)?;
            Ok(outcome)
        })();
        #[cfg(feature = "admission-test-support")]
        if let Err(error) = &result {
            crate::admission_operation_store::recovery::command_quota_test_support::record_command_refusal(error);
        }
        result
    }
}
