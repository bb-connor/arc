use super::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "admission-test-support")]
#[path = "report_feedback_test_support.rs"]
mod report_feedback_test_support;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandRecord {
    digest: CommandDigest,
    response: RecoveryCommandResponseV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reported_decision: Option<ReportFeedback>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportFeedback {
    workflow_id: WorkflowId,
    expected_revision: SafeInteger,
    decision: RecoveryReportedDecision,
}

pub(super) fn reported_feedback(
    tx: &Connection,
    record: &RecoveryWorkflowRecordV1,
) -> Result<Option<RecoveryReportedDecision>, AdmissionOperationStoreError> {
    let mut statement = tx
        .prepare(
            "SELECT record_key FROM admission_operation_recovery_records
         WHERE scope_key=?1 AND kind='command' AND record_key GLOB 'command:*'
           AND json_type(CAST(payload AS TEXT),'$.reported_decision') IS NOT NULL
           AND json_extract(CAST(payload AS TEXT),'$.reported_decision.workflow_id')=?2 LIMIT 2",
        )
        .map_err(sqlite_error)?;
    let rows = statement
        .query_map(
            params![scope_key(&record.scope)?, record.workflow_id.as_str()],
            |row| row.get::<_, String>(0),
        )
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    if rows.len() > 1 {
        return Err(invariant("recovery report has ambiguous original custody"));
    }
    let Some(key) = rows.first() else {
        // Terminal and hold views are observation clones. Authenticate the raw
        // workflow before interpreting its original feedback or charged purpose.
        let physical = workflow_tx(tx, &record.scope, &record.workflow_id)?;
        if physical.reported_decision.is_none() && workflow_report_requested(tx, &physical)? {
            return Err(invariant(
                "recovery report lost its original charged source",
            ));
        }
        return Ok(physical.reported_decision);
    };
    let row =
        raw_checked(tx, key)?.ok_or_else(|| invariant("recovery report source disappeared"))?;
    source_reference(tx, key)?;
    let report: CommandRecord = decode(&row.payload)?;
    let feedback = report
        .reported_decision
        .ok_or_else(|| invariant("recovery report body disappeared"))?;
    let body = RecoveryCommandBodyV1::ReportDecision {
        workflow_id: feedback.workflow_id.clone(),
        expected_revision: feedback.expected_revision,
        decision: feedback.decision,
    };
    if row.kind != "command"
        || row.version != 1
        || row.scope != scope_key(&record.scope)?
        || feedback.workflow_id != record.workflow_id
        || report.response.workflow_id != record.workflow_id
        || report.response.revision.get() > record.revision.get()
        || feedback.expected_revision.get() > report.response.revision.get()
        || report.digest
            != CommandDigest::from_bytes(hash(
                chio_core_types::recovery::RecoveryDigestDomain::Command,
                &body,
            )?)
        || record
            .reported_decision
            .is_some_and(|prior| prior != feedback.decision)
    {
        return Err(invariant(
            "recovery report original input or source changed",
        ));
    }
    Ok(Some(feedback.decision))
}

pub(super) fn decode_record(
    payload: &[u8],
) -> Result<(CommandDigest, RecoveryCommandResponseV1), AdmissionOperationStoreError> {
    let record: CommandRecord = decode(payload)?;
    if let Some(feedback) = &record.reported_decision {
        let body = RecoveryCommandBodyV1::ReportDecision {
            workflow_id: feedback.workflow_id.clone(),
            expected_revision: feedback.expected_revision,
            decision: feedback.decision,
        };
        if feedback.workflow_id != record.response.workflow_id
            || feedback.expected_revision.get() > record.response.revision.get()
            || record.digest
                != CommandDigest::from_bytes(hash(
                    chio_core_types::recovery::RecoveryDigestDomain::Command,
                    &body,
                )?)
        {
            return Err(invariant(
                "recovery report original command binding changed",
            ));
        }
    }
    Ok((record.digest, record.response))
}

pub(super) fn identity(
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
) -> Result<(String, CommandDigest), AdmissionOperationStoreError> {
    let key = format!(
        "command:{}",
        sha256_hex(&encode(&(
            actor.scope(),
            actor.principal(),
            command.command.permission(),
            &command.command_id,
        ))?)
    );
    let digest = CommandDigest::from_bytes(hash(
        chio_core_types::recovery::RecoveryDigestDomain::Command,
        &command.command,
    )?);
    Ok((key, digest))
}

fn creation_workflow_id(
    scope: &RecoveryScopeV1,
    creation_key: &CreationKey,
) -> Result<WorkflowId, AdmissionOperationStoreError> {
    WorkflowId::new(&format!(
        "workflow:{}",
        sha256_hex(&encode(&(scope, creation_key))?),
    ))
    .map_err(|_| invariant("recovery identity refused"))
}

/// Authorized readers answer Inspect from current state. Mutation replays keep
/// their exact committed response without allocating or checking fresh capacity.
pub(super) fn inspect_or_replay(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
    deployment: &RecoveryDeploymentV1,
) -> Result<Option<RecoveryCommandResponseV1>, RecoveryCommandPortError> {
    if actor.permission().wire_name() != command.command.permission() {
        return Err(invariant("recovery permission refused").into());
    }
    // Authorize the selected audience before setup, retained identities,
    // conflicts or fresh allocation can reveal whether a workflow exists.
    let selected = match &command.command {
        RecoveryCommandBodyV1::CreateWorkflow { creation_key, .. } => {
            let id = creation_workflow_id(actor.scope(), creation_key)?;
            if raw_checked(tx, &workflow_key(actor.scope(), &id)?)?.is_some() {
                Some(workflow_preview_tx(tx, actor, deployment, &id)?)
            } else {
                None
            }
        }
        body => Some(workflow_preview_tx(
            tx,
            actor,
            deployment,
            selector(body)?.0,
        )?),
    };
    super::super::setup::require_command(tx, actor, &owner.fence, command)?;
    if let RecoveryCommandBodyV1::InspectWorkflow { workflow_id } = &command.command {
        let current = workflow_preview_tx(tx, actor, deployment, workflow_id)?;
        return Ok(Some(response(
            command,
            &historical_holds::view(tx, current)?,
        )));
    }
    let (key, digest) = identity(actor, command)?;
    let alias = retained_command_alias(tx, &key, actor, command)?;
    if let Some(existing) = raw_checked(tx, &key)? {
        source_reference(tx, &key)?;
        if alias.is_some() {
            return Err(invariant("recovery command has two retained identities").into());
        }
        if existing.version != 1
            || existing.kind != "command"
            || existing.scope != scope_key(actor.scope())?
        {
            return Err(invariant("recovery command identity changed").into());
        }
        let (existing_digest, response) = decode_record(&existing.payload)?;
        if response.command_id != command.command_id {
            return Err(invariant("recovery command response identity changed").into());
        }
        workflow_preview_tx(tx, actor, deployment, &response.workflow_id)?;
        if existing_digest != digest {
            return Err(RecoveryCommandPortError::Conflict);
        }
        return Ok(Some(response));
    }
    if let Some((existing_digest, response)) = alias {
        workflow_preview_tx(tx, actor, deployment, &response.workflow_id)?;
        if existing_digest != digest {
            return Err(RecoveryCommandPortError::Conflict);
        }
        return Ok(Some(response));
    }
    if let Some(current) = selected {
        source_reference(tx, &workflow_key(&current.scope, &current.workflow_id)?)?;
    }
    Ok(None)
}

/// Fresh same-value identities still retain their exact body and response.
/// Only their admission class differs from a first mutation or execution request.
pub(super) fn fresh_command_intake_headroom(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
    deployment: &RecoveryDeploymentV1,
) -> Result<bool, RecoveryCommandPortError> {
    Ok(requires_command_intake_headroom(&command.command)
        || settled_alias_candidate(tx, actor, command, deployment)?.is_some())
}

fn settled_alias_candidate(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
    deployment: &RecoveryDeploymentV1,
) -> Result<Option<RecoveryWorkflowRecordV1>, RecoveryCommandPortError> {
    let record = match &command.command {
        RecoveryCommandBodyV1::CreateWorkflow { creation_key, .. } => {
            let id = creation_workflow_id(actor.scope(), creation_key)?;
            if raw_checked(tx, &workflow_key(actor.scope(), &id)?)?.is_none() {
                return Ok(None);
            }
            workflow_preview_tx(tx, actor, deployment, &id)?
        }
        RecoveryCommandBodyV1::InspectWorkflow { .. } => return Ok(None),
        body => workflow_preview_tx(tx, actor, deployment, selector(body)?.0)?,
    };
    if same_value_command(tx, actor, command, &record)? {
        Ok(Some(record))
    } else {
        Ok(None)
    }
}

fn same_value_command(
    tx: &Transaction<'_>,
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
    record: &RecoveryWorkflowRecordV1,
) -> Result<bool, RecoveryCommandPortError> {
    if let RecoveryCommandBodyV1::CreateWorkflow { request_seed, .. } = &command.command {
        return if record.creation_seed == *request_seed {
            Ok(true)
        } else {
            Err(RecoveryCommandPortError::Conflict)
        };
    }
    if selector(&command.command)?
        .1
        .is_some_and(|revision| revision != record.revision)
    {
        return Err(RecoveryCommandPortError::Conflict);
    }
    match &command.command {
        RecoveryCommandBodyV1::ResumeWorkflow { .. } => {
            historical_holds::require_unheld(tx, record)?;
            if record.admission_closed
                && record.admission.is_none()
                && !record.captured
                && record.effect == EffectObservationV1::NeverAdmitted
            {
                return Ok(false);
            }
            Ok(record.admission.is_some()
                || record.captured
                || workflow_resume_requested(tx, record)?)
        }
        RecoveryCommandBodyV1::SelectOffer { offer_id, .. } => {
            historical_holds::require_unheld(tx, record)?;
            require_active(record)?;
            if record.process_reservation.is_none() {
                return Err(invariant("recovery process reservation is absent").into());
            }
            let action = record
                .action
                .as_ref()
                .ok_or_else(|| invariant("recovery offer is absent"))?;
            if offer_id.as_str()
                != format!(
                    "offer:{}",
                    hex(&hash(
                        chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
                        action,
                    )?)
                )
            {
                return Err(invariant("recovery offer changed").into());
            }
            Ok(record.selected)
        }
        RecoveryCommandBodyV1::SubmitApproval { approval, .. } => {
            historical_holds::require_unheld(tx, record)?;
            require_active(record)?;
            if !record.selected {
                return Err(invariant("recovery identity is not reserved").into());
            }
            let submitted: RecoveryApprovalSubmissionV1 =
                chio_core_types::recovery::decode_contract(approval.as_str().as_bytes())
                    .map_err(|_| invariant("recovery approval wire bound refused"))?;
            let submitted = RecoveryRetainedApprovalV1::try_from(submitted)
                .map_err(|_| invariant("recovery approval custody bound refused"))?;
            if submitted.intent.reviewer != *actor.principal() {
                return Err(invariant("recovery reviewer changed").into());
            }
            match &record.approval {
                Some(existing) if encode(existing)? == encode(&submitted)? => Ok(true),
                Some(_) => Err(RecoveryCommandPortError::Conflict),
                None => Ok(false),
            }
        }
        RecoveryCommandBodyV1::CancelWorkflow { .. } => {
            Ok(historical_holds::effective(tx, record)?.is_some()
                || auxiliary_captured_terminal(tx, record)?.is_some()
                || record.control != WorkflowControlV1::Active)
        }
        RecoveryCommandBodyV1::ReportDecision { decision, .. } => {
            historical_holds::require_unheld(tx, record)?;
            if !super::terminal_custody::view(tx, record.clone())?
                .effect
                .is_settled()
            {
                return Err(invariant("recovery effect is unresolved").into());
            }
            match reported_feedback(tx, record)? {
                Some(existing) if existing == *decision => Ok(true),
                Some(_) => Err(RecoveryCommandPortError::Conflict),
                None => Ok(false),
            }
        }
        RecoveryCommandBodyV1::InspectWorkflow { .. }
        | RecoveryCommandBodyV1::CreateWorkflow { .. } => {
            Err(invariant("recovery command alias shape refused").into())
        }
    }
}

/// Only this module can mint a same-value alias. The proof borrows the actual
/// writer and authenticated actors; stored descriptive fields cannot mint it.
pub(in crate::admission_operation_store) struct VerifiedSettledCommandAlias<'tx, 'conn> {
    transaction: &'tx Transaction<'conn>,
    actor: &'tx AuthenticatedRecoveryActor,
    command: &'tx RecoveryCommandV1,
    deployment: &'tx RecoveryDeploymentV1,
    record: &'tx RecoveryWorkflowRecordV1,
    source: ProtectedSourceReference,
    digest: CommandDigest,
    now: u64,
}

impl VerifiedSettledCommandAlias<'_, '_> {
    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<(), RecoveryCommandPortError> {
        if !std::ptr::eq::<Connection>(&**tx, &**self.transaction) {
            return Err(invariant("command alias changed its physical writer").into());
        }
        verify_source_reference(tx, &self.source)?;
        verify_actor(tx, self.actor, self.deployment, self.now)?;
        verify_preview(self.actor, self.deployment, self.record)?;
        if self.actor.scope() != &self.record.scope
            || self.actor.permission().wire_name() != self.command.command.permission()
            || self.source.record_key()
                != workflow_key(&self.record.scope, &self.record.workflow_id)?
            || self.source.version() != self.record.revision.get()
            || identity(self.actor, self.command)?.1 != self.digest
            || !same_value_command(tx, self.actor, self.command, self.record)?
        {
            return Err(invariant("command alias is not the accepted same value").into());
        }
        Ok(())
    }
    pub(in crate::admission_operation_store) fn actor(&self) -> &AuthenticatedRecoveryActor {
        self.actor
    }
    pub(in crate::admission_operation_store) fn record(&self) -> &RecoveryWorkflowRecordV1 {
        self.record
    }
    pub(in crate::admission_operation_store) fn source(&self) -> &ProtectedSourceReference {
        &self.source
    }
    pub(in crate::admission_operation_store) fn digest(&self) -> CommandDigest {
        self.digest
    }
    pub(in crate::admission_operation_store) fn response(
        &self,
    ) -> Result<RecoveryCommandResponseV1, AdmissionOperationStoreError> {
        Ok(response(
            self.command,
            &historical_holds::view(self.transaction, self.record.clone())?,
        ))
    }
}

fn response(
    command: &RecoveryCommandV1,
    record: &RecoveryWorkflowRecordV1,
) -> RecoveryCommandResponseV1 {
    RecoveryCommandResponseV1 {
        command_id: command.command_id.clone(),
        workflow_id: record.workflow_id.clone(),
        revision: record.revision,
        control: record.control,
        effect: record.effect.clone(),
        release: record.release.clone(),
    }
}

pub(in crate::admission_operation_store) fn apply(
    tx: &Transaction<'_>,
    owner: &SqliteServingOwner,
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
    deployment: &RecoveryDeploymentV1,
    now: u64,
    original_process: Option<&dyn RecoveryProcessOriginPort>,
) -> Result<RecoveryCommandResponseV1, RecoveryCommandPortError> {
    if let Some(response) = inspect_or_replay(tx, owner, actor, command, deployment)? {
        return Ok(response);
    }
    if let Some(record) = settled_alias_candidate(tx, actor, command, deployment)? {
        let witness = VerifiedSettledCommandAlias {
            transaction: tx,
            actor,
            command,
            deployment,
            source: source_reference(tx, &workflow_key(&record.scope, &record.workflow_id)?)?,
            record: &record,
            digest: identity(actor, command)?.1,
            now,
        };
        return save_settled_command_alias(tx, owner, witness);
    }
    if matches!(
        command.command,
        RecoveryCommandBodyV1::CreateWorkflow { .. }
    ) && original_process.is_none()
    {
        return Err(invariant("recovery original process authority is absent").into());
    }
    let scope = scope_key(actor.scope())?;
    let (key, digest) = identity(actor, command)?;
    let workflow = match &command.command {
        RecoveryCommandBodyV1::CreateWorkflow { creation_key, .. } => {
            creation_workflow_id(actor.scope(), creation_key)?
        }
        body => selector(body)?.0.clone(),
    };
    require_command_slot(tx, actor.scope(), &workflow, &command.command)?;
    let record = match &command.command {
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: _,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed,
        } => {
            let id = workflow.clone();
            let seed: ToolCallRequest =
                chio_core_types::recovery::decode_contract(request_seed.as_str().as_bytes())
                    .map_err(|_| invariant("recovery seed wire bound refused"))?;
            validate_seed(&seed, deployment)?;
            let proof = original_process
                .ok_or_else(|| invariant("recovery original process authority is absent"))?
                .original_request_scope(
                    actor.scope(),
                    &seed,
                    deployment.security_context.as_v1().session_id().as_str(),
                )?;
            let origin = original_resolution::resolve_scoped(tx, &seed, deployment, now, &proof)?;
            if let Some(existing) = raw_checked(tx, &workflow_key(actor.scope(), &id)?)? {
                let existing: RecoveryWorkflowRecordV1 = decode(&existing.payload)?;
                if existing.creation_seed != *request_seed
                    || existing.origin.as_ref() != Some(&origin)
                {
                    return Err(RecoveryCommandPortError::Conflict);
                }
                existing
            } else {
                // The owning save reserves a live slot. Closed identities and
                // their exact command responses remain immutable cold history.
                let suffix = sha256_hex(&encode(&(actor.scope(), &id))?);
                let mut new = RecoveryWorkflowRecordV1 {
                    scope: actor.scope().clone(),
                    origin: Some(origin),
                    workflow_id: id,
                    step_id: StepId::new(&format!("step:{suffix}"))
                        .map_err(|_| invariant("recovery identity refused"))?,
                    continuation_id: ContinuationId::new(&format!("continuation:{suffix}"))
                        .map_err(|_| invariant("recovery identity refused"))?,
                    revision: SafeInteger::new(1)
                        .map_err(|_| invariant("recovery version refused"))?,
                    control: WorkflowControlV1::Active,
                    seed,
                    creation_seed: request_seed.clone(),
                    deployment_digest: DeploymentDigest::from_bytes(hash(
                        chio_core_types::recovery::RecoveryDigestDomain::Deployment,
                        deployment,
                    )?),
                    created_by: actor.principal().clone(),
                    effect_cardinality: deployment.effect_cardinality,
                    action: None,
                    process_reservation: None,
                    selected: false,
                    review: None,
                    approval: None,
                    issuance: None,
                    signed_grant: None,
                    envelope: None,
                    admission: None,
                    admission_closed: false,
                    native_link: None,
                    captured: false,
                    captured_deployment: None,
                    historical_hold: None,
                    effect: EffectObservationV1::NeverAdmitted,
                    release: ReleaseDispositionV1::NotAvailable,
                    original_flow: None,
                    reported_decision: None,
                    provider_finality: None,
                    provider_lookups: SafeInteger::ZERO,
                };
                origins::claim(tx, owner, &new)?;
                save_workflow(tx, owner, &mut new, WorkflowWriteClass::Planning)?;
                new
            }
        }
        body => {
            let (id, revision) = selector(body)?;
            let mut record = workflow_preview_tx(tx, actor, deployment, id)?;
            let held = historical_holds::effective(tx, &record)?.is_some();
            if revision.is_some_and(|revision| revision != record.revision) {
                return Err(RecoveryCommandPortError::Conflict);
            }
            match body {
                RecoveryCommandBodyV1::ResumeWorkflow { .. } => {
                    if held {
                        return Err(
                            invariant("recovery workflow is historically quarantined").into()
                        );
                    }
                }
                RecoveryCommandBodyV1::InspectWorkflow { .. } => {
                    return Err(invariant("inspection cannot allocate a command identity").into());
                }
                RecoveryCommandBodyV1::SelectOffer { offer_id, .. } => {
                    historical_holds::require_unheld(tx, &record)?;
                    require_active(&record)?;
                    if record.process_reservation.is_none() {
                        return Err(invariant("recovery process reservation is absent").into());
                    }
                    let action = record
                        .action
                        .as_ref()
                        .ok_or_else(|| invariant("recovery offer is absent"))?;
                    if offer_id.as_str()
                        != format!(
                            "offer:{}",
                            hex(&hash(
                                chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
                                action
                            )?)
                        )
                    {
                        return Err(invariant("recovery offer changed").into());
                    }
                    fresh_basis(tx, deployment, &record, now)?;
                    if !record.selected {
                        super::terminal_custody::require_unfinished(tx, &record)?;
                        record.selected = true;
                        save_workflow(tx, owner, &mut record, WorkflowWriteClass::Planning)?;
                    }
                }
                RecoveryCommandBodyV1::SubmitApproval { approval, .. } => {
                    historical_holds::require_unheld(tx, &record)?;
                    require_active(&record)?;
                    if !record.selected {
                        return Err(invariant("recovery identity is not reserved").into());
                    }
                    let submitted: RecoveryApprovalSubmissionV1 =
                        chio_core_types::recovery::decode_contract(approval.as_str().as_bytes())
                            .map_err(|_| invariant("recovery approval wire bound refused"))?;
                    let submitted = RecoveryRetainedApprovalV1::try_from(submitted)
                        .map_err(|_| invariant("recovery approval custody bound refused"))?;
                    verify_preview(actor, deployment, &record)?;
                    if submitted.intent.reviewer != *actor.principal() {
                        return Err(invariant("recovery reviewer changed").into());
                    }
                    validate_approval(&record, &submitted, deployment, now)?;
                    fresh_basis(tx, deployment, &record, now)?;
                    match &record.approval {
                        Some(existing) if encode(existing)? == encode(&submitted)? => {}
                        Some(_) => return Err(RecoveryCommandPortError::Conflict),
                        None => {
                            super::terminal_custody::require_unfinished(tx, &record)?;
                            record.approval = Some(submitted);
                            save_workflow(tx, owner, &mut record, WorkflowWriteClass::Planning)?;
                        }
                    }
                }
                RecoveryCommandBodyV1::CancelWorkflow { .. } => {
                    if !held
                        && auxiliary_captured_terminal(tx, &record)?.is_none()
                        && record.control == WorkflowControlV1::Active
                    {
                        record.control = WorkflowControlV1::CancelRequested;
                        if record.admission.is_none() {
                            record.admission_closed = true;
                            record.control = WorkflowControlV1::Cancelled;
                        }
                        save_workflow(tx, owner, &mut record, WorkflowWriteClass::Control)?;
                    }
                }
                RecoveryCommandBodyV1::ReportDecision { decision, .. } => {
                    historical_holds::require_unheld(tx, &record)?;
                    if !super::terminal_custody::view(tx, record.clone())?
                        .effect
                        .is_settled()
                    {
                        return Err(invariant("recovery effect is unresolved").into());
                    }
                    match reported_feedback(tx, &record)? {
                        Some(existing) if existing != *decision => {
                            return Err(RecoveryCommandPortError::Conflict)
                        }
                        Some(_) => {}
                        None => {
                            if auxiliary_captured_terminal(tx, &record)?.is_none() {
                                record.reported_decision = Some(*decision);
                                save_workflow(tx, owner, &mut record, WorkflowWriteClass::Control)?;
                            }
                        }
                    }
                }
                RecoveryCommandBodyV1::CreateWorkflow { .. } => {
                    return Err(invariant("recovery command shape refused").into())
                }
            }
            record
        }
    };
    // Exactly one effectful continuation exists in this native recovery template. Settlement
    // never clears selection, consumption or the spent step to permit another.
    let response = response(command, &historical_holds::view(tx, record.clone())?);
    save_command(
        tx,
        owner,
        &key,
        &scope,
        &encode(&CommandRecord {
            digest,
            response: response.clone(),
            reported_decision: match &command.command {
                RecoveryCommandBodyV1::ReportDecision {
                    workflow_id,
                    expected_revision,
                    decision,
                } => {
                    super::terminal_custody::require_current_terminal_format(tx)?;
                    Some(ReportFeedback {
                        workflow_id: workflow_id.clone(),
                        expected_revision: *expected_revision,
                        decision: *decision,
                    })
                }
                _ => None,
            },
        })?,
        &command.command,
        &record,
    )?;
    Ok(response)
}

fn selector(
    body: &RecoveryCommandBodyV1,
) -> Result<(&WorkflowId, Option<SafeInteger>), AdmissionOperationStoreError> {
    match body {
        RecoveryCommandBodyV1::InspectWorkflow { workflow_id } => Ok((workflow_id, None)),
        RecoveryCommandBodyV1::SelectOffer {
            workflow_id,
            expected_revision,
            ..
        }
        | RecoveryCommandBodyV1::SubmitApproval {
            workflow_id,
            expected_revision,
            ..
        }
        | RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id,
            expected_revision,
        }
        | RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id,
            expected_revision,
        }
        | RecoveryCommandBodyV1::ReportDecision {
            workflow_id,
            expected_revision,
            ..
        } => Ok((workflow_id, Some(*expected_revision))),
        _ => Err(invariant("recovery command selector refused")),
    }
}
