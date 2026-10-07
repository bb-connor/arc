//! Selected operator self-test custody and report acceptance.
use super::*;

impl SqliteAdmissionOperationStore {
    /// Trusted selected operator pins and creates a new exact self-test in the
    /// same transaction. The supplied actor still needs fresh Create authority.
    /// This method is not exposed through the agent control listener.
    pub fn pin_setup_creation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        host: NativeSetupCreationHost<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<WorkflowId, AdmissionOperationStoreError> {
        let wire = chio_core::canonical_json_bytes(command).map_err(refused)?;
        let _: RecoveryCommandV1 = chio_core::recovery::decode_contract(&wire).map_err(refused)?;
        let RecoveryCommandBodyV1::CreateWorkflow {
            creation_key,
            request_seed,
            ..
        } = &command.command
        else {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        };
        let NativeSetupCreationHost {
            receipt_key,
            operator,
            process,
        } = host;
        let seed: ToolCallRequest =
            chio_core::recovery::decode_contract(request_seed.as_str().as_bytes())
                .map_err(refused)?;
        // Prepare host journal custody before entering the native writer. The
        // writer still authenticates the actor, profile and retained operation.
        let original_process = super::original_scope::PreparedSetupOriginalProcess::prepare(
            process,
            actor.scope(),
            &seed,
            self.deployment(actor.scope(), fence, now),
        );
        self.recovery_mutation(actor, fence, now, |tx, recovery, now| {
            if actor.permission() != RecoveryPermission::Create {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
            }
            let (_, _, _, root) = profile(tx, actor.scope(), receipt_key)?;
            if &root != operator {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
            }
            register_native_setup_context(tx, &self.serving_owner, recovery)?;
            let workflow = WorkflowId::new(&format!(
                "workflow:{}",
                sha256_hex(&protected::encode(&(actor.scope(), creation_key))?)
            ))
            .map_err(refused)?;
            let original_scope = original_process
                .original_request_scope(
                    actor.scope(),
                    &seed,
                    recovery.security_context.as_v1().session_id().as_str(),
                )
                .map_err(|error| original_custody_error(error.into()))?;
            let origin = super::super::recovery::original_resolution::resolve_scoped(
                tx,
                &seed,
                recovery,
                now,
                &original_scope,
            )
            .map_err(original_custody_error)?;
            let creation = CanonicalPayloadDigest::from_bytes(digest(
                RecoveryDigestDomain::SetupCreation,
                &(request_seed, &origin),
            )?);
            if let Some(existing) = load(tx, actor.scope())? {
                if current(tx, &existing).is_ok() && now < existing.probe.expires_at_unix_ms.get() {
                    if existing.probe.scope != *actor.scope()
                        || existing.probe.benign_workflow != workflow
                        || existing.creation != creation
                        || existing.receipt_key != *receipt_key
                        || existing.operator != *operator
                    {
                        return Err(refused("active self-test cannot change"));
                    }
                } else {
                    if protected::raw(tx, &protected::workflow_key(actor.scope(), &workflow)?)?
                        .is_some()
                    {
                        return Err(refused("new profile needs a new unfinished self-test"));
                    }
                    let selection = make_selection(
                        tx,
                        SelectionInput {
                            scope: actor.scope(),
                            workflow: &workflow,
                            receipt_key,
                            operator,
                        },
                        creation,
                        SafeInteger::new(1).map_err(refused)?,
                        fence,
                        now,
                    )?;
                    save(tx, &self.serving_owner, &selection)?;
                }
            } else {
                let selection = make_selection(
                    tx,
                    SelectionInput {
                        scope: actor.scope(),
                        workflow: &workflow,
                        receipt_key,
                        operator,
                    },
                    creation,
                    SafeInteger::new(1).map_err(refused)?,
                    fence,
                    now,
                )?;
                save(tx, &self.serving_owner, &selection)?;
            }
            let response = super::super::recovery::apply_command(
                tx,
                &self.serving_owner,
                actor,
                command,
                recovery,
                now,
                Some(&original_process),
            )
            .map_err(refused)?;
            if response.workflow_id != workflow {
                return Err(refused("self-test creation identity"));
            }
            Ok(workflow)
        })
    }
    /// Trusted local operator pins a single unfinished model-free workflow.
    pub fn configure_protected_setup(
        &self,
        scope: &RecoveryScopeV1,
        workflow: &WorkflowId,
        receipt_key: &PublicKey,
        operator: &PublicKey,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeSetupPreparationV1, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        super::recovery::require_intake_headroom(&connection)?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let (_, _, _, root) = profile(&tx, scope, receipt_key)?;
        if &root != operator {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
        let deployment = protected::deployment_tx(&tx, scope)?;
        let registered = register_native_setup_context(&tx, &self.serving_owner, &deployment)?;
        if let Some(value) = load(&tx, scope)? {
            current(&tx, &value)?;
            if value.probe.scope != *scope
                || value.probe.benign_workflow != *workflow
                || value.receipt_key != *receipt_key
                || value.operator != *operator
            {
                return Err(refused("pinned self-test changed"));
            }
            if registered {
                self.commit_write(tx)?;
                self.sync_after_write(&connection)?;
            } else {
                tx.commit().map_err(sqlite_error)?;
            }
            return Ok(preparation(&value));
        }
        let record = protected::workflow_tx(&tx, scope, workflow)?;
        if record.captured || record.native_link.is_some() {
            return Err(refused("self-test must be unfinished"));
        }
        let value = make_selection(
            &tx,
            SelectionInput {
                scope,
                workflow,
                receipt_key,
                operator,
            },
            creation(&record)?,
            record.revision,
            fence,
            now,
        )?;
        save(&tx, &self.serving_owner, &value)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(preparation(&value))
    }
    pub fn setup_preparation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<NativeSetupPreparationV1, NativeSetupPreparationError> {
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            let mut value = load(tx, actor.scope())?
                .ok_or(AdmissionOperationStoreError::RecoveryMediationRequired)?;
            authorized(tx, actor, profile, &value)?;
            if value.evidence.is_none() {
                if now >= value.probe.expires_at_unix_ms.get() {
                    return Err(NativeSetupPreparationError::Expired);
                }
                if fence_digest(fence)? != value.previous_fence {
                    return Err(NativeSetupPreparationError::WriterChanged);
                }
                require_fresh_uncaptured_source(tx, profile, &value, now)?;
                if !value.command_bound {
                    bind_benign_command(tx, &mut value, now)?;
                    save(tx, &self.serving_owner, &value)?;
                }
            }
            Ok(preparation(&value))
        })
    }
    /// Observe mandatory setup custody through the current native owner. This
    /// metadata read grants neither readiness nor execution authority.
    pub fn protected_setup_required(
        &self,
        scope: &RecoveryScopeV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<bool, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        schema::authority_validation_time(&tx, now)?;
        let deployment = protected::deployment_tx(&tx, scope)?;
        super::super::security_participant_state::verify_recovery_initialization(
            &tx,
            &deployment.native_authority,
        )?;
        // The retained tenant marker cannot be removed by constructing a bare
        // runtime or selecting a different process in the same tenant.
        let required = deployment.setup_policy.is_some() || context::tenant_required(&tx, scope)?;
        tx.commit().map_err(sqlite_error)?;
        Ok(required)
    }
    /// Current operator inventory observation, with no readiness assertion or
    /// self-test command creation. The native owner verifies fresh Inspect
    /// authority and the installed mediator closure before returning a digest.
    pub fn observe_setup_coverage(
        &self,
        actor: &AuthenticatedRecoveryActor,
        receipt_key: &PublicKey,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<CoverageDigest, AdmissionOperationStoreError> {
        let mut connection = self.connection()?;
        let tx = self.begin_read(&mut connection)?;
        verify_active_owner(&tx, &self.serving_owner, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let deployment = protected::deployment_tx(&tx, actor.scope())?;
        super::super::recovery::verify_actor(&tx, actor, &deployment, now)?;
        if actor.permission() != RecoveryPermission::Inspect {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
        profile(&tx, actor.scope(), receipt_key)?;
        let coverage = required_coverage(&tx, actor.scope())?;
        tx.commit().map_err(sqlite_error)?;
        Ok(coverage)
    }
    pub fn commit_setup_probe(
        &self,
        actor: &AuthenticatedRecoveryActor,
        evidence: &NativeSetupProbeEvidenceV1<'_>,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<SignedRecoverySetupProbeV1, AdmissionOperationStoreError> {
        let NativeSetupProbeEvidenceV1 {
            probe,
            benign,
            denied_request,
            denied,
        } = *evidence;
        if !super::incoming_proof::verify(probe.verify_signature())?
            || !benign.verify_signature().map_err(refused)?
            || !denied.verify_signature().map_err(refused)?
        {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            let mut value =
                load(tx, actor.scope())?.ok_or_else(|| refused("setup selection absent"))?;
            authorized(tx, actor, profile, &value)?;
            if let Some(evidence) = &value.evidence {
                if &evidence.probe == probe {
                    return Ok(evidence.probe.clone());
                }
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
            }
            if probe.body() != &value.probe
                || probe.authority_key() != &value.operator
                || now >= value.probe.expires_at_unix_ms.get()
                || fence_digest(fence)? != value.previous_fence
                || denied.kernel_key != value.receipt_key
                || !denied.is_denied()
                || denied_request.request_id != value.probe.denied_command.as_str()
                || denied_request.server_id != profile.server_id.as_str()
                || denied_request.tool_name != profile.tool_name.as_str()
                || denied.tool_server != denied_request.server_id
                || denied.tool_name != denied_request.tool_name
            {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
            }
            let operation = completed(tx, &value, benign)?;
            super::denied_counterpart::verify_denied_counterpart(
                tx,
                &value,
                profile,
                denied_request,
                denied,
                now,
            )?;
            value.evidence = Some(Evidence {
                probe: probe.clone(),
                operation,
                benign_receipt: SourceDigest::from_bytes(digest(
                    RecoveryDigestDomain::SetupBenignReceipt,
                    benign,
                )?),
                denied_command: CommandDigest::from_bytes(digest(
                    RecoveryDigestDomain::SetupDeniedCommand,
                    &(&value.probe.denied_command, denied_request, denied),
                )?),
            });
            save(tx, &self.serving_owner, &value)?;
            Ok(probe.clone())
        })
    }
    pub fn prepare_setup_report(
        &self,
        actor: &AuthenticatedRecoveryActor,
        probe: &SignedRecoverySetupProbeV1,
        benign: &ChioReceipt,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<RecoverySetupReportV1, AdmissionOperationStoreError> {
        if !super::incoming_proof::verify(probe.verify_signature())?
            || !benign.verify_signature().map_err(refused)?
        {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
        self.recovery_mutation(actor, fence, now, |tx, profile, now| {
            let value =
                load(tx, actor.scope())?.ok_or_else(|| refused("setup selection absent"))?;
            authorized(tx, actor, profile, &value)?;
            let evidence = value
                .evidence
                .as_ref()
                .ok_or_else(|| refused("probe evidence absent"))?;
            let current_fence = fence_digest(fence)?;
            if &evidence.probe != probe {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
            }
            if current_fence == value.previous_fence
                || (now >= value.probe.expires_at_unix_ms.get()
                    && retained_qualification(&value)?.is_none())
            {
                return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
            }
            if completed(tx, &value, benign)? != evidence.operation {
                return Err(refused("retained benign operation changed"));
            }
            if SourceDigest::from_bytes(digest(RecoveryDigestDomain::SetupBenignReceipt, benign)?)
                != evidence.benign_receipt
            {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
            }
            Ok(RecoverySetupReportV1 {
                domain_version: VersionV1,
                probe: value.probe.clone(),
                benign_operation: evidence.operation.clone(),
                benign_receipt: evidence.benign_receipt,
                denied_command_digest: evidence.denied_command,
                previous_serving_fence: value.previous_fence,
                current_serving_fence: current_fence,
                qualified_at_unix_ms: SafeInteger::new(now).map_err(refused)?,
            })
        })
    }
    /// A signed claim is accepted only against retained native self-test custody.
    pub fn accept_setup_report(
        &self,
        report: &SignedRecoverySetupReportV1,
        fence: &StoreMutationFence,
        now: u64,
    ) -> Result<SignedRecoverySetupReportV1, AdmissionOperationStoreError> {
        if !super::incoming_proof::verify(report.verify_signature())? {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
        let mut connection = self.connection()?;
        let tx = self.begin_write(&mut connection, Some(fence))?;
        let now = schema::authority_validation_time(&tx, now)?;
        let mut value = load(&tx, &report.body().probe.scope)?
            .ok_or_else(|| refused("setup selection absent"))?;
        current(&tx, &value)?;
        let evidence = value
            .evidence
            .as_ref()
            .ok_or_else(|| refused("probe evidence absent"))?;
        let body = report.body();
        if body.probe != value.probe
            || report.authority_key() != &value.operator
            || body.previous_serving_fence != value.previous_fence
            || body.current_serving_fence != fence_digest(fence)?
            || body.benign_operation != evidence.operation
            || body.benign_receipt != evidence.benign_receipt
            || body.denied_command_digest != evidence.denied_command
            || body.qualified_at_unix_ms.get() > now
        {
            return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
        }
        if now >= value.probe.expires_at_unix_ms.get() && retained_qualification(&value)?.is_none()
        {
            return Err(AdmissionOperationStoreError::RecoveryMediationRequired);
        }
        let operation = load_by_operation_id_tx(
            &tx,
            &AdmissionOperationId::from_persisted(evidence.operation.as_str())?,
        )?
        .ok_or_else(|| refused("lost benign operation"))?;
        if operation.operation.state() != AdmissionOperationState::Completed {
            return Err(refused("benign completion"));
        }
        if let Some(existing) = &value.report {
            if existing == report {
                tx.commit().map_err(sqlite_error)?;
                return Ok(existing.clone());
            }
            if existing.body().current_serving_fence == body.current_serving_fence {
                return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
            }
        }
        value.report = Some(report.clone());
        save(&tx, &self.serving_owner, &value)?;
        self.commit_write(tx)?;
        self.sync_after_write(&connection)?;
        Ok(report.clone())
    }
}

/// This is a refusal before exposing a dispatch command. Native issuance and
/// capture still own the complete fresh authority checks after preparation.
fn require_fresh_uncaptured_source(
    tx: &Transaction<'_>,
    profile: &RecoveryDeploymentV1,
    value: &Selection,
    now: u64,
) -> Result<(), NativeSetupPreparationError> {
    let record = protected::workflow_tx(tx, &value.probe.scope, &value.probe.benign_workflow)?;
    if record.native_link.is_some() {
        return Ok(());
    }
    let Some(action) = &record.action else {
        return Ok(());
    };
    if now
        >= action
            .authorization_requirements
            .validity_ceiling_unix_ms
            .get()
        || record.deployment_digest
            != DeploymentDigest::from_bytes(digest(RecoveryDigestDomain::Deployment, profile)?)
    {
        return Err(NativeSetupPreparationError::StaleSource);
    }
    let original = record
        .original_flow
        .as_ref()
        .ok_or_else(|| refused("setup source absent"))?;
    let (current, _) = crate::security_state::observe_native_flow_state(
        tx,
        profile.native_authority.security_authority_id().as_str(),
        &original.key,
    )
    .map_err(refused)?;
    if current.as_ref() != Some(original) {
        return Err(NativeSetupPreparationError::StaleSource);
    }
    Ok(())
}

struct SelectionInput<'a> {
    scope: &'a RecoveryScopeV1,
    workflow: &'a WorkflowId,
    receipt_key: &'a PublicKey,
    operator: &'a PublicKey,
}
/// Freeze the command once, after native selection and approval. Subsequent
/// workflow changes are still rejected by the ordinary revision/replay owner.
fn bind_benign_command(
    tx: &Transaction<'_>,
    value: &mut Selection,
    now: u64,
) -> Result<(), AdmissionOperationStoreError> {
    let record = protected::workflow_tx(tx, &value.probe.scope, &value.probe.benign_workflow)?;
    if record.captured || record.native_link.is_some() {
        return Err(refused("setup command already acquired"));
    }
    if record.control != WorkflowControlV1::Active
        || !record.selected
        || record.approval.is_none()
        || record.action.is_none()
        || creation(&record)? != value.creation
        || now >= value.probe.expires_at_unix_ms.get()
    {
        return Err(refused("setup command is not eligible"));
    }
    let RecoveryCommandBodyV1::ResumeWorkflow {
        workflow_id,
        expected_revision,
    } = &mut value.command.command
    else {
        return Err(refused("setup command identity"));
    };
    if workflow_id != &value.probe.benign_workflow {
        return Err(refused("setup workflow identity"));
    }
    *expected_revision = record.revision;
    value.command_bound = true;
    Ok(())
}
fn make_selection(
    tx: &Connection,
    input: SelectionInput<'_>,
    creation: CanonicalPayloadDigest,
    revision: SafeInteger,
    fence: &StoreMutationFence,
    now: u64,
) -> Result<Selection, AdmissionOperationStoreError> {
    let SelectionInput {
        scope,
        workflow,
        receipt_key,
        operator,
    } = input;
    let (authority, deployment, source, root) = profile(tx, scope, receipt_key)?;
    if &root != operator {
        return Err(AdmissionOperationStoreError::RecoveryAuthorityDenied);
    }
    let previous_fence = fence_digest(fence)?;
    let challenge = sha256_hex(&protected::encode(&(
        scope,
        workflow,
        &source,
        &previous_fence,
    ))?);
    Ok(Selection {
        probe: RecoverySetupProbeV1 {
            domain_version: VersionV1,
            scope: scope.clone(),
            probe_id: ChallengeId::new(&challenge).map_err(refused)?,
            native_authority: authority,
            deployment,
            source_profile: source,
            required_coverage: required_coverage(tx, scope)?,
            benign_workflow: workflow.clone(),
            denied_command: CommandId::new(&format!("setup-denied:{challenge}"))
                .map_err(refused)?,
            issued_at_unix_ms: SafeInteger::new(now).map_err(refused)?,
            expires_at_unix_ms: SafeInteger::new(
                now.checked_add(900_000).ok_or_else(|| refused("clock"))?,
            )
            .map_err(refused)?,
        },
        creation,
        command: RecoveryCommandV1 {
            schema: RecoveryCommandSchema::V1,
            version: VersionV1,
            command_id: CommandId::new(&format!("setup-benign:{}", workflow.as_str()))
                .map_err(refused)?,
            command: RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: revision,
            },
        },
        command_bound: false,
        operator: root,
        receipt_key: receipt_key.clone(),
        previous_fence,
        evidence: None,
        report: None,
    })
}

/// An accepted report preserves the exact completed self-test. It grants no
/// new execution, and every re-attestation still checks the current native
/// profile, serving writer, actor and completed operation independently.
fn retained_qualification(
    value: &Selection,
) -> Result<Option<&SignedRecoverySetupReportV1>, AdmissionOperationStoreError> {
    let Some(report) = &value.report else {
        return Ok(None);
    };
    let evidence = value
        .evidence
        .as_ref()
        .ok_or_else(|| refused("accepted setup evidence absent"))?;
    let body = report.body();
    if !report.verify_signature().map_err(refused)?
        || report.authority_key() != &value.operator
        || body.probe != value.probe
        || evidence.probe.body() != &value.probe
        || evidence.probe.authority_key() != &value.operator
        || !evidence.probe.verify_signature().map_err(refused)?
        || body.previous_serving_fence != value.previous_fence
        || body.benign_operation != evidence.operation
        || body.benign_receipt != evidence.benign_receipt
        || body.denied_command_digest != evidence.denied_command
    {
        return Err(refused("accepted setup report custody"));
    }
    Ok(Some(report))
}
