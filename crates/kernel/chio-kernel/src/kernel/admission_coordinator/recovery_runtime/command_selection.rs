//! Initial-generation command drivers use the authenticated accepted source.
//! Generation advancement stays refused until every owning writer opts in.
use super::*;
use chio_core_types::recovery::RecoveryDigestDomain;

fn command_kernel_error(error: KernelError) -> RecoveryCommandError {
    match error {
        KernelError::RecoveryAuthorityDenied => RecoveryCommandError::AuthorityDenied,
        KernelError::RecoveryMediationRequired => RecoveryCommandError::MediationRequired,
        _ => RecoveryCommandError::Unavailable,
    }
}
fn command_port_error(error: RecoveryCommandPortError) -> RecoveryCommandError {
    match error {
        RecoveryCommandPortError::Store(
            crate::admission_operation::AdmissionOperationStoreError::RecoveryAuthorityDenied,
        ) => RecoveryCommandError::AuthorityDenied,
        RecoveryCommandPortError::Store(
            crate::admission_operation::AdmissionOperationStoreError::RecoveryMediationRequired,
        ) => RecoveryCommandError::MediationRequired,
        RecoveryCommandPortError::Conflict => RecoveryCommandError::Conflict,
        RecoveryCommandPortError::OriginRefused => RecoveryCommandError::OriginRefused,
        RecoveryCommandPortError::Busy => RecoveryCommandError::Busy,
        _ => RecoveryCommandError::Unavailable,
    }
}
fn selection_refused() -> KernelError {
    KernelError::DurableAdmission("recovery accepted command selection refused".into())
}
fn capability_body(
    actor: &AuthenticatedRecoveryActor,
) -> Result<CapabilityBodyDigest, KernelError> {
    Ok(CapabilityBodyDigest::from_bytes(recovery_digest(
        RecoveryDigestDomain::CapabilityBody,
        &actor.capability().signing_body(),
    )?))
}
fn validate_outcome(
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
    outcome: &RecoveryCommandPortOutcome,
) -> Result<(), KernelError> {
    let selected = &outcome.selection;
    let generation = &selected.generation;
    let digest = CommandDigest::from_bytes(recovery_digest(
        RecoveryDigestDomain::Command,
        &command.command,
    )?);
    if selected.scope != *actor.scope()
        || selected.command_id != command.command_id
        || selected.command_digest != digest
        || outcome.response.command_id != command.command_id
        || selected.workflow_id != outcome.response.workflow_id
        || selected.accepted_root_revision != outcome.response.revision
        || generation.record_version != outcome.response.revision
        || generation.generation.get() != 1
        || generation.record_version.get() == 0
        || generation.event_sequence.get() == 0
        || generation.global_commit_sequence.get() == 0
        || generation.initial_global_commit_sequence.get() == 0
        || generation.initial_global_commit_sequence > generation.global_commit_sequence
        || (selected.mode == RecoveryCommandContinuationMode::SameCurrentGeneration
            && !matches!(
                actor.permission(),
                RecoveryPermission::Create | RecoveryPermission::Resume
            ))
    {
        return Err(selection_refused());
    }
    let requested = match &command.command {
        RecoveryCommandBodyV1::CreateWorkflow { .. } => None,
        RecoveryCommandBodyV1::InspectWorkflow { workflow_id }
        | RecoveryCommandBodyV1::SelectOffer { workflow_id, .. }
        | RecoveryCommandBodyV1::SubmitApproval { workflow_id, .. }
        | RecoveryCommandBodyV1::ResumeWorkflow { workflow_id, .. }
        | RecoveryCommandBodyV1::CancelWorkflow { workflow_id, .. }
        | RecoveryCommandBodyV1::ReportDecision { workflow_id, .. } => Some(workflow_id),
    };
    if requested.is_some_and(|workflow| workflow != &selected.workflow_id) {
        return Err(selection_refused());
    }
    Ok(())
}
fn mode_is_downgrade(
    accepted: RecoveryCommandContinuationMode,
    current: RecoveryCommandContinuationMode,
) -> bool {
    accepted == current
        || (accepted == RecoveryCommandContinuationMode::SameCurrentGeneration
            && current == RecoveryCommandContinuationMode::HistoricalGenerationReadOnly)
}

impl ChioKernel {
    /// The public response is unchanged. Only the actual installed native port
    /// can supply this Kernel's nonserialized accepted command selection.
    pub fn execute_recovery_command_outcome_with_origin<'kernel>(
        &'kernel self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        original_process: &dyn RecoveryProcessOriginPort,
    ) -> Result<RecoveryCommandOutcome<'kernel>, RecoveryCommandError> {
        self.revalidate_recovery_actor(actor)
            .map_err(command_kernel_error)?;
        let (port, runtime, now) = self.recovery_port().map_err(command_kernel_error)?;
        // This independent process snapshot occurs before native BEGIN/write.
        let prepared_original = match &command.command {
            RecoveryCommandBodyV1::CreateWorkflow { request_seed, .. } => {
                Some(crate::recovery::PreparedOriginalProcessOrigin::new(
                    original_process,
                    actor.scope(),
                    request_seed.as_str(),
                    port.deployment(actor.scope(), &runtime.fence, now),
                ))
            }
            _ => None,
        };
        let original = prepared_original
            .as_ref()
            .map(|value| value as &dyn RecoveryProcessOriginPort);
        let outcome = port
            .command_with_selection(actor, command, original, &runtime.fence, now)
            .map_err(command_port_error)?;
        validate_outcome(actor, command, &outcome).map_err(command_kernel_error)?;
        let actor_body = capability_body(actor).map_err(command_kernel_error)?;
        Ok(RecoveryCommandOutcome {
            response: outcome.response,
            selection: RecoveryCommandSelection {
                kernel: self,
                port,
                fence: runtime.fence.clone(),
                scope: actor.scope().clone(),
                principal: actor.principal().clone(),
                permission: actor.permission(),
                capability_body_digest: actor_body,
                backend: outcome.selection,
            },
        })
    }

    /// Read the selected physical generation under fresh current authority.
    /// A backend may downgrade an execution selection, never upgrade an alias.
    pub fn read_recovery_command_selection(
        &self,
        actor: &AuthenticatedRecoveryActor,
        selection: &RecoveryCommandSelection<'_>,
    ) -> Result<RecoveryCommandSelectedWorkflow, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        let (port, runtime, now) = self.recovery_port()?;
        if !std::ptr::eq(self, selection.kernel)
            || !std::ptr::addr_eq(port, selection.port)
            || runtime.fence != selection.fence
            || actor.scope() != &selection.scope
            || actor.principal() != &selection.principal
            || actor.permission() != selection.permission
            || capability_body(actor)? != selection.capability_body_digest
            || selection.backend.generation.generation.get() != 1
        {
            return Err(selection_refused());
        }
        let selected = port
            .load_selection(actor, &selection.backend, &runtime.fence, now)
            .map_err(durable_store_error)?;
        let record = &selected.record;
        if !mode_is_downgrade(selection.backend.mode, selected.effective_mode)
            || record.scope != selection.backend.scope
            || record.workflow_id != selection.backend.workflow_id
            || record.step_id != selection.backend.generation.step_id
            || record.continuation_id != selection.backend.generation.continuation_id
            || record.revision < selection.backend.generation.record_version
        {
            return Err(selection_refused());
        }
        Ok(RecoveryCommandSelectedWorkflow {
            record: selected.record,
            effective_mode: selected.effective_mode,
        })
    }
}
