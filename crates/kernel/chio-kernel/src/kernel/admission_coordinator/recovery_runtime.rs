//! Narrow recovery controls over the selected original native authority.
use super::*;
use crate::kernel::kernel_scopes::RECEIPT_EVALUATION_SCOPE_KEY;
use crate::recovery::*;
use chio_security_types::recovery::*;

#[path = "recovery_runtime/command_selection.rs"]
mod command_selection;

#[cfg(feature = "admission-test-support")]
#[path = "recovery_runtime/authenticated_original_test.rs"]
mod authenticated_original_test;
#[cfg(feature = "admission-test-support")]
#[path = "recovery_runtime/caller_wait_test.rs"]
mod caller_wait_test;

fn unsupported() -> KernelError {
    KernelError::DurableAdmission("native recovery profile is unsupported".into())
}

impl ChioKernel {
    /// Restore an unacknowledged preflight attachment from its physical owner.
    /// Re-running preflight could consume a new input generation or replay a
    /// reversed hold. Neither is necessary when the original issuance exists.
    pub(crate) fn load_recovery_original_nonce(
        &self,
        record: &RecoveryWorkflowRecordV1,
    ) -> Result<Option<crate::execution_nonce::SignedExecutionNonce>, KernelError> {
        if record.control != WorkflowControlV1::Active || record.captured || record.admission_closed
        {
            return Ok(None);
        }
        let Some(intent) = &record.admission else {
            return Ok(None);
        };
        let runtime = self.durable_runtime()?;
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
        let Some(operation) = runtime
            .store
            .load_by_operation_id(binding.operation_id())
            .map_err(durable_store_error)?
        else {
            return Ok(None);
        };
        if operation.binding() != &binding {
            return Err(unsupported());
        }
        if operation.state() != AdmissionOperationState::Prepared
            || !binding.participant_requirements().execution_nonce
        {
            return Ok(None);
        }
        let now = runtime.refresh_trusted_time(0);
        self.load_durable_nonce_issuance(&operation, now)?
            .map(|issuance| {
                if !self.durable_nonce_issuance_is_live(&operation, now)? {
                    return Err(unsupported());
                }
                Ok(issuance.signed_nonce().clone())
            })
            .transpose()
    }
    pub fn reserve_recovery_provider_lookup(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<RecoveryProviderLookup, KernelError> {
        self.reserve_recovery_provider_lookup_inner(actor, workflow, None)
    }
    /// Protected transports select their actual request budget before entering
    /// the writer. The original lookup deadline is never refreshed on return.
    pub fn reserve_recovery_provider_lookup_with_budget(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        budget: RecoveryProviderLookupBudget,
    ) -> Result<RecoveryProviderLookup, KernelError> {
        self.reserve_recovery_provider_lookup_inner(actor, workflow, Some(budget))
    }
    fn reserve_recovery_provider_lookup_inner(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        budget: Option<RecoveryProviderLookupBudget>,
    ) -> Result<RecoveryProviderLookup, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        if actor.permission() != RecoveryPermission::Settle {
            return Err(unsupported());
        }
        self.reconcile_recovery_original(actor, workflow)?;
        let deployment = self.recovery_deployment(actor.scope())?;
        let (port, runtime, now) = self.recovery_port()?;
        let record = self.read_recovery_workflow(actor, workflow)?;
        let intent = record.admission.as_ref().ok_or_else(unsupported)?;
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
        let captured_deployment = match port
            .captured_deployment(binding.operation_id(), &runtime.fence, now)
            .map_err(durable_store_error)?
            .ok_or_else(unsupported)?
        {
            RecoveryCapturedDeploymentV1::Verified(profile) => *profile,
            RecoveryCapturedDeploymentV1::LegacyUnavailable
            | RecoveryCapturedDeploymentV1::Quarantined => return Err(unsupported()),
        };
        let workflow = match budget {
            Some(budget) => port.reserve_provider_lookup_with_budget(
                actor,
                workflow,
                &runtime.fence,
                now,
                budget,
            ),
            None => port.reserve_provider_lookup(actor, workflow, &runtime.fence, now),
        }
        .map_err(durable_store_error)?;
        Ok(RecoveryProviderLookup {
            workflow,
            deployment,
            captured_deployment,
            expires_at_unix_ms: now
                .saturating_add(MAX_RECOVERY_PROVIDER_OBSERVATION_MS)
                .min(actor.capability().expires_at.saturating_mul(1000)),
            request_budget: budget,
        })
    }
    pub fn attach_recovery_provider_finality(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        finality: &chio_core_types::recovery::SignedRecoveryProviderFinalityV1,
    ) -> Result<RecoveryWorkflowRecordV1, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        if actor.permission() != RecoveryPermission::Settle {
            return Err(unsupported());
        }
        let (port, runtime, now) = self.recovery_port()?;
        port.attach_provider_finality(actor, workflow, finality, &runtime.fence, now)
            .map_err(durable_store_error)
    }

    pub fn acknowledge_recovery_reservation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        reservation: &RecoveryProcessReservationV1,
        process: &dyn RecoveryProcessReservationPort,
    ) -> Result<(), KernelError> {
        self.revalidate_recovery_actor(actor)?;
        process
            .verify_reservation(reservation)
            .map_err(durable_store_error)?;
        let (port, runtime, now) = self.recovery_port()?;
        port.acknowledge_reservation(actor, workflow, reservation, &runtime.fence, now)
            .map_err(durable_store_error)
    }

    /// Replay the retained original result under a current control identity.
    /// The initiating capability is historical data here and is never admitted.
    pub fn replay_recovery_result(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<ToolCallResponse, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        if !matches!(
            actor.permission(),
            RecoveryPermission::Resume | RecoveryPermission::Inspect
        ) {
            return Err(unsupported());
        }
        let record = self.read_recovery_workflow(actor, workflow)?;
        let intent = record.admission.as_ref().ok_or_else(unsupported)?;
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding.clone())?;
        let runtime = self.durable_runtime()?;
        let operation = runtime
            .store
            .load_by_operation_id(binding.operation_id())
            .map_err(durable_store_error)?
            .ok_or_else(unsupported)?;
        if operation.binding() != &binding
            || operation.state() != AdmissionOperationState::Completed
        {
            return Err(unsupported());
        }
        let custody = self.load_recovery_request_custody(actor, workflow)?;
        let retained_request = self
            .load_original_request_for_finalization(&operation, runtime.refresh_trusted_time(0))?
            .ok_or_else(unsupported)?;
        let admission = DurableToolAdmission {
            operation,
            aggregate_quota: None,
            supplemental_quota: None,
            retained_request: Some(retained_request),
            issued_nonce: None,
            nonce_preflight: None,
            _live_owner: None,
        };
        let response =
            self.completed_recovery_tool_response(&admission, custody.request(), actor)?;
        self.revalidate_recovery_actor(actor)?;
        Ok(response)
    }
    pub fn observe_recovery_completion(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<RecoveryWorkflowRecordV1, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        if actor.permission() != RecoveryPermission::Resume {
            return Err(unsupported());
        }
        let (port, runtime, now) = self.recovery_port()?;
        port.settle(actor, workflow, &runtime.fence, now)
            .map_err(durable_store_error)
    }
    /// Resume uses the original native recovery owner before considering any
    /// pre-effect progress. Captured or uncertain work never reenters invoke.
    pub fn reconcile_recovery_continuation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<RecoveryWorkflowRecordV1, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        if actor.permission() != RecoveryPermission::Resume {
            return Err(unsupported());
        }
        self.reconcile_recovery_original(actor, workflow)?;
        self.observe_recovery_completion(actor, workflow)
    }
    /// Drive only the original native recovery protocol. No invoke or fresh
    /// admission path is reachable through this current settlement permission.
    fn reconcile_recovery_original(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<(), KernelError> {
        let record = self.read_recovery_workflow(actor, workflow)?;
        let Some(intent) = record.admission else {
            return Ok(());
        };
        let binding = AdmissionOperationBindingV1::from_persisted(intent.native_binding)?;
        let runtime = self.durable_runtime()?;
        let Some(operation) = runtime
            .store
            .load_by_operation_id(binding.operation_id())
            .map_err(durable_store_error)?
        else {
            return Ok(());
        };
        if operation.binding() != &binding {
            return Err(unsupported());
        }
        let Some(_owner) = runtime
            .mutation_sequencer
            .try_own_operation(binding.operation_id())?
        else {
            return Ok(());
        };
        let now = runtime.refresh_trusted_time(0);
        if self.quarantine_unavailable_recovery(&operation, now)? {
            return Ok(());
        }
        match operation.state() {
            AdmissionOperationState::Prepared
                if record.control == WorkflowControlV1::Active
                    && self.durable_nonce_issuance_is_live(&operation, now)? => {}
            AdmissionOperationState::ReadyToDispatch
                if record.control == WorkflowControlV1::Active
                    && self.durable_caller_reservation_is_live(&operation, now)? => {}
            AdmissionOperationState::Prepared
            | AdmissionOperationState::BrokerAttemptRegistered
            | AdmissionOperationState::BudgetAuthorized
            | AdmissionOperationState::ApprovalReserved
            | AdmissionOperationState::ReadyToDispatch
            | AdmissionOperationState::CapturePending => {
                self.compensate_durable_admission_before_dispatch(&operation,
                    serde_json::json!({"authority":"scoped-recovery","cause":"original-pre-dispatch-closure"}), now, None)?;
            }
            AdmissionOperationState::ApprovalRequired
                if record.control != WorkflowControlV1::Active
                    || operation
                        .parked_approval_deadline_unix_ms()?
                        .is_some_and(|deadline| deadline <= now) =>
            {
                self.compensate_durable_admission_before_dispatch(&operation,
                    serde_json::json!({"authority":"scoped-recovery","cause":"original-approval-closure"}), now, None)?;
            }
            AdmissionOperationState::DispatchCommitted => {
                self.reconcile_scoped_dispatch_committed_original(&operation, now)?;
            }
            AdmissionOperationState::Finalizing => {
                let retained_request =
                    self.load_original_request_for_finalization(&operation, now)?;
                let mut admission = DurableToolAdmission {
                    operation,
                    aggregate_quota: None,
                    supplemental_quota: None,
                    retained_request,
                    issued_nonce: None,
                    nonce_preflight: None,
                    _live_owner: None,
                };
                let returned = self.load_durable_tool_return(&admission)?;
                let request = returned
                    .recovery_request()
                    .map_err(tool_outcome_error)?
                    .ok_or_else(unsupported)?;
                RECEIPT_EVALUATION_SCOPE_KEY
                    .sync_scope(uuid::Uuid::now_v7().to_string(), || {
                        self.finalize_durable_tool_return(&mut admission, &request, &returned)
                    })?;
            }
            _ => {}
        }
        Ok(())
    }

    // The scoped continuation retains the same authenticated pending caller
    // decision as global recovery. This never renews or retries a dispatch.
    fn reconcile_scoped_dispatch_committed_original(
        &self,
        operation: &AdmissionOperationV1,
        now: u64,
    ) -> Result<(), KernelError> {
        if self.retain_authenticated_caller_wait(operation, now)? {
            return Ok(());
        }
        self.terminalize_dispatch_committed_admission(operation, now)
    }
    pub fn reserve_recovery_review(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        review: &ApprovalIntentV1,
    ) -> Result<ApprovalIntentV1, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        let (port, runtime, now) = self.recovery_port()?;
        port.reserve_review(actor, workflow, review, &runtime.fence, now)
            .map_err(durable_store_error)
    }
    fn recovery_port(
        &self,
    ) -> Result<(&dyn RecoveryAuthorityPort, &DurableAdmissionRuntime, u64), KernelError> {
        let runtime = self.durable_runtime()?;
        let port = runtime.store.recovery_authority().ok_or_else(unsupported)?;
        Ok((port, runtime, runtime.refresh_trusted_time(0)))
    }
    pub fn recovery_deployment(
        &self,
        scope: &RecoveryScopeV1,
    ) -> Result<RecoveryDeploymentV1, KernelError> {
        let (port, runtime, now) = self.recovery_port()?;
        if scope.authority_domain.as_str() != runtime.fence.store_uuid {
            return Err(unsupported());
        }
        let deployment = port
            .deployment(scope, &runtime.fence, now)
            .map_err(durable_store_error)?;
        if self.native_security_authority_binding()?.as_ref() != Some(&deployment.native_authority)
            || self.config.policy_hash != hex(&deployment.policy_digest)
            || self
                .tool_servers
                .get(deployment.server_id.as_str())
                .and_then(|server| server.recovery_effect_contract())
                .as_ref()
                != Some(&deployment.effect_contract)
        {
            return Err(unsupported());
        }
        Ok(deployment)
    }

    /// Observe the native requirement for a live protected mediator. This is
    /// data only; it cannot qualify setup or authorize new tool execution.
    pub fn protected_recovery_setup_required(
        &self,
        scope: &RecoveryScopeV1,
    ) -> Result<bool, KernelError> {
        self.recovery_deployment(scope)?;
        let (port, runtime, now) = self.recovery_port()?;
        port.protected_setup_required(scope, &runtime.fence, now)
            .map_err(durable_store_error)
    }

    /// Execute control commands without supplying process-journal authority.
    /// Creation fails closed through this route. Trusted creation hosts use
    /// `execute_recovery_command_with_origin`; `RecoveryRuntime` wires its journal.
    pub fn execute_recovery_command(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
    ) -> Result<RecoveryCommandResponseV1, RecoveryCommandError> {
        self.execute_recovery_command_inner(actor, command, None)
    }
    /// Fresh creation requires the trusted owning process journal. Supplying a
    /// port cannot replace the native original-operation and closure checks.
    pub fn execute_recovery_command_with_origin(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        original_process: &dyn RecoveryProcessOriginPort,
    ) -> Result<RecoveryCommandResponseV1, RecoveryCommandError> {
        self.execute_recovery_command_inner(actor, command, Some(original_process))
    }
    fn execute_recovery_command_inner(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandV1,
        original_process: Option<&dyn RecoveryProcessOriginPort>,
    ) -> Result<RecoveryCommandResponseV1, RecoveryCommandError> {
        self.revalidate_recovery_actor(actor)
            .map_err(|error| match error {
                KernelError::RecoveryAuthorityDenied => RecoveryCommandError::AuthorityDenied,
                KernelError::RecoveryMediationRequired => RecoveryCommandError::MediationRequired,
                _ => RecoveryCommandError::Unavailable,
            })?;
        let (port, runtime, now) = self
            .recovery_port()
            .map_err(|_| RecoveryCommandError::Unavailable)?;
        // Do not acquire a process journal while holding the native writer.
        // Store replay/preflight decides whether fresh origin authority is
        // needed, and only then consumes this exact cached result.
        let prepared_original = match (&command.command, original_process) {
            (RecoveryCommandBodyV1::CreateWorkflow { request_seed, .. }, Some(process)) => {
                Some(crate::recovery::PreparedOriginalProcessOrigin::new(
                    process,
                    actor.scope(),
                    request_seed.as_str(),
                    port.deployment(actor.scope(), &runtime.fence, now),
                ))
            }
            _ => None,
        };
        let original_process = prepared_original
            .as_ref()
            .map(|prepared| prepared as &dyn RecoveryProcessOriginPort);
        port.command(actor, command, original_process, &runtime.fence, now)
            .map_err(|error| match error {
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
            })
    }
    pub fn read_recovery_workflow(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<RecoveryWorkflowRecordV1, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        let (port, runtime, now) = self.recovery_port()?;
        port.load_workflow(actor, workflow, &runtime.fence, now)
            .map_err(durable_store_error)
    }
    pub fn observe_recovery_source(
        &self,
        scope: &RecoveryScopeV1,
    ) -> Result<crate::admission_operation::NativeSecurityFlowObservationV1, KernelError> {
        let deployment = self.recovery_deployment(scope)?;
        let (_, runtime, now) = self.recovery_port()?;
        runtime
            .store
            .observe_native_security_flow(
                &deployment.native_authority,
                &recovery_flow_key(&deployment.security_context),
                &runtime.fence,
                now,
            )
            .map_err(durable_store_error)
    }
    pub fn materialize_recovery_action(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        action: &ActionIntentV1,
    ) -> Result<RecoveryWorkflowRecordV1, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        let deployment = self.recovery_deployment(actor.scope())?;
        let (port, runtime, now) = self.recovery_port()?;
        let observation = runtime
            .store
            .observe_native_security_flow(
                &deployment.native_authority,
                &recovery_flow_key(&deployment.security_context),
                &runtime.fence,
                now,
            )
            .map_err(durable_store_error)?;
        port.materialize(actor, workflow, action, &observation, &runtime.fence, now)
            .map_err(durable_store_error)
    }
    pub fn reserve_recovery_issuance(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        body: &chio_core_types::recovery::RecoveryGrantBodyV2,
    ) -> Result<chio_core_types::recovery::RecoveryGrantBodyV2, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        let (port, runtime, now) = self.recovery_port()?;
        port.reserve_issuance(actor, workflow, body, &runtime.fence, now)
            .map_err(durable_store_error)
    }
    pub fn attach_recovery_signature(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        grant: &chio_core_types::recovery::SignedRecoveryGrantV2,
    ) -> Result<(), KernelError> {
        self.revalidate_recovery_actor(actor)?;
        let (port, runtime, now) = self.recovery_port()?;
        port.attach_signature(actor, workflow, grant, &runtime.fence, now)
            .map_err(durable_store_error)
    }
    pub fn finalize_recovery_envelope(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
        envelope: &FinalizedRequestEnvelopeV1,
        identity: &RecoveryNativeIdentity,
    ) -> Result<(), KernelError> {
        self.revalidate_recovery_actor(actor)?;
        let (port, runtime, now) = self.recovery_port()?;
        port.finalize_envelope(actor, workflow, envelope, identity, &runtime.fence, now)
            .map_err(durable_store_error)
    }
    pub fn settle_recovery_workflow(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<RecoveryWorkflowRecordV1, KernelError> {
        self.revalidate_recovery_actor(actor)?;
        if actor.permission() != RecoveryPermission::Settle {
            return Err(unsupported());
        }
        self.reconcile_recovery_original(actor, workflow)?;
        let (port, runtime, now) = self.recovery_port()?;
        port.settle(actor, workflow, &runtime.fence, now)
            .map_err(durable_store_error)
    }

    /// Compute the original admission identity without entering admission,
    /// preflight, budget reservation or any connector. The native begin checks
    /// this complete binding again in the same transaction as admission.
    pub fn recovery_native_identity(
        &self,
        request: &ToolCallRequest,
        context: &SecurityInvocationContext,
    ) -> Result<RecoveryNativeIdentity, KernelError> {
        if request.execution_nonce.is_some()
            || request.dpop_proof.is_some()
            || request.governed_intent.is_some()
            || request.approval_token.is_some()
            || !request.approval_tokens.is_empty()
            || request.threshold_approval_proposal.is_some()
            || request.supplemental_authorization.is_some()
            || request.federated_origin_kernel_id.is_some()
        {
            return Err(unsupported());
        }
        let runtime = self.durable_runtime()?;
        if self
            .tool_servers
            .get(&request.server_id)
            .is_none_or(|server| {
                server.tool_is_read_only(&request.tool_name)
                    || !server.tool_names().contains(&request.tool_name)
            })
        {
            return Err(unsupported());
        }
        self.validate_security_invocation_context_binding(request, Some(context), None)?;
        let security = self
            .admission_security_binding(Some(context))?
            .ok_or_else(unsupported)?;
        if security.native_authority().is_none() {
            return Err(unsupported());
        }
        let grants = crate::request_matching::resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )
        .map_err(|_| unsupported())?;
        if grants.iter().any(|matching| {
            matching.grant.dpop_required == Some(true)
                || matching.grant.max_cost_per_invocation.is_some()
                || matching.grant.max_total_cost.is_some()
                || matching.grant.constraints.iter().any(|constraint| {
                    matches!(
                        constraint,
                        Constraint::RequireApprovalAbove { .. }
                            | Constraint::GovernedIntentRequired
                            | Constraint::RequireCumulativeApprovalAbove { .. }
                            | Constraint::RequireFindingRecovery(_)
                    )
                })
        }) {
            return Err(unsupported());
        }
        let profile = self.admission_authority_profile()?;
        let plan = self.durable_post_return_plan_for_fresh_native_profile(
            self.native_output_retention.as_deref(),
        )?;
        let immutable =
            crate::admission_operation::immutable_tool_request_hash_with_original_semantics(
                request,
                &grants,
                &plan.frozen_steps,
                Some(&security),
                Some(&profile),
                self.native_output_retention.as_deref(),
            )
            .map_err(durable_store_error)?;
        let nonce = self.durable_nonce_participant_required(
            &runtime.store.admission_projection_capabilities(),
        )?;
        let coordinator = AdmissionIdentifier::try_new(
            "coordinator_authority_id",
            runtime.fence.store_uuid.clone(),
        )?;
        let namespace = match self.receipt_tenant_id_for_request(Some(&request.request_id)) {
            Some(tenant) => {
                AuthenticatedRequestNamespace::from_authentication_context(coordinator, tenant)?
            }
            None => AuthenticatedRequestNamespace::for_local_system(coordinator)?,
        };
        let action = ToolCallAction::from_parameters(request.arguments.clone())
            .map_err(|_| unsupported())?;
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::ToolDispatch,
            namespace,
            request_id: AdmissionIdentifier::try_new("request_id", request.request_id.clone())?,
            capability_id: AdmissionIdentifier::try_new(
                "capability_id",
                request.capability.id.clone(),
            )?,
            authorization_capability_hash: admission_digest(
                "authorization_capability_hash",
                &request.capability,
            )?,
            request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
                immutable,
                AdmissionDigest::try_new("action_parameter_hash", action.parameter_hash)?,
                AdmissionParticipantRequirements {
                    broker_attempt: true,
                    budget_capture: true,
                    execution_nonce: nonce,
                    observation_attempt_zero: self.settlement_observer.is_some(),
                    ..AdmissionParticipantRequirements::NONE
                },
            )?,
            policy_hash: AdmissionDigest::try_new("policy_hash", self.config.policy_hash.clone())?,
            effect_class: SideEffectClass::SideEffecting,
        })?;
        Ok(RecoveryNativeIdentity { binding })
    }

    /// Observe the existing request namespace without reserving any participant.
    /// Used to frame exact semantic actions before endorsement proofs exist.
    pub fn semantic_request_namespace(
        &self,
        request_id: &str,
    ) -> Result<chio_security_types::recovery::RequestNamespaceDigest, KernelError> {
        let runtime = self.durable_runtime()?;
        let coordinator = AdmissionIdentifier::try_new(
            "coordinator_authority_id",
            runtime.fence.store_uuid.clone(),
        )?;
        let request_id = request_id.to_owned();
        let namespace = match self.receipt_tenant_id_for_request(Some(&request_id)) {
            Some(tenant) => {
                AuthenticatedRequestNamespace::from_authentication_context(coordinator, tenant)?
            }
            None => AuthenticatedRequestNamespace::for_local_system(coordinator)?,
        };
        let value = namespace.digest().as_str();
        if value.len() != 64 {
            return Err(unsupported());
        }
        let mut bytes = [0; 32];
        for (byte, pair) in bytes.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).map_err(|_| unsupported())?, 16)
                .map_err(|_| unsupported())?;
        }
        Ok(chio_security_types::recovery::RequestNamespaceDigest::from_bytes(bytes))
    }
}

impl ChioKernel {
    pub(super) fn captured_recovery_deployment(
        &self,
        operation: &AdmissionOperationV1,
    ) -> Result<Option<RecoveryCapturedDeploymentV1>, KernelError> {
        let runtime = self.durable_runtime()?;
        let Some(port) = runtime.store.recovery_authority() else {
            return Ok(None);
        };
        port.captured_deployment(
            operation.binding().operation_id(),
            &runtime.fence,
            runtime.refresh_trusted_time(0),
        )
        .map_err(durable_store_error)
    }

    /// A typed, authenticated verifier absence creates one durable hold. Store
    /// integrity and mandatory-custody failures are propagated unchanged.
    pub(super) fn quarantine_unavailable_recovery(
        &self,
        operation: &AdmissionOperationV1,
        now: u64,
    ) -> Result<bool, KernelError> {
        let reason = match self.captured_recovery_deployment(operation)? {
            None => return Ok(false),
            Some(RecoveryCapturedDeploymentV1::Quarantined) => {
                let original = self
                    .load_original_request_for_finalization(operation, now)?
                    .ok_or_else(unsupported)?;
                let admission = DurableToolAdmission {
                    operation: operation.clone(),
                    aggregate_quota: None,
                    supplemental_quota: None,
                    retained_request: Some(original),
                    issued_nonce: None,
                    nonce_preflight: None,
                    _live_owner: None,
                };
                // A durable hold cannot hide a later physical return fault.
                // Its reason remains monotone even if old authority returns.
                self.frozen_recovery_signer_unavailable(&admission)?;
                return Ok(true);
            }
            Some(RecoveryCapturedDeploymentV1::LegacyUnavailable) => {
                RecoveryHistoricalHoldReasonV1::LegacyDeploymentUnavailable
            }
            Some(RecoveryCapturedDeploymentV1::Verified(profile)) => {
                let original = self
                    .load_original_request_for_finalization(operation, now)?
                    .ok_or_else(unsupported)?;
                original
                    .validate_native_security_authority(&profile.native_authority)
                    .map_err(durable_store_error)?;
                original
                    .validate_native_security_context(&profile.security_context)
                    .map_err(durable_store_error)?;
                let admission = DurableToolAdmission {
                    operation: operation.clone(),
                    aggregate_quota: None,
                    supplemental_quota: None,
                    retained_request: Some(original.clone()),
                    issued_nonce: None,
                    nonce_preflight: None,
                    _live_owner: None,
                };
                // Signing rotation cannot orphan an authenticated effect. The
                // private finalizer selects current signing for a distinct
                // withheld attestation; immutable raw faults still propagate.
                self.frozen_recovery_signer_unavailable(&admission)?;
                let declarations = super::super::security_dispatch::callback(
                    "historical output verifier selection",
                    || Ok(self.post_invocation_pipeline.durable_identities()),
                )?;
                if declarations.is_ok()
                    && original.post_return_steps()
                        == self.durable_post_return_plan()?.frozen_steps.as_slice()
                {
                    return Ok(false);
                }
                // An older signer hold stays authenticated and immutable if a
                // second, unavailable verifier prevents its private discharge.
                if operation.state() == AdmissionOperationState::Finalizing {
                    let (port, runtime, now) = self.recovery_port()?;
                    if port
                        .historical_release(operation.binding().operation_id(), &runtime.fence, now)
                        .map_err(durable_store_error)?
                        .is_some_and(|record| record.historical_hold.is_some())
                    {
                        return Ok(true);
                    }
                }
                RecoveryHistoricalHoldReasonV1::FrozenOutputVerifierUnavailable
            }
        };
        let (port, runtime, now) = self.recovery_port()?;
        port.quarantine_historical(
            operation.binding().operation_id(),
            reason,
            &runtime.fence,
            now,
        )
        .map_err(durable_store_error)?;
        Ok(true)
    }

    /// Current result delivery is separate from captured-effect settlement.
    pub(super) fn release_current_recovery_result(
        &self,
        admission: &DurableToolAdmission,
        actor: &AuthenticatedRecoveryActor,
        request: &ToolCallRequest,
        raw: &RawInvocationOutcomeV1,
        output: &ToolCallOutput,
    ) -> Result<(), KernelError> {
        self.revalidate_recovery_actor(actor)?;
        if self.is_emergency_stopped() {
            return Err(unsupported());
        }
        let profile = self.recovery_deployment(actor.scope())?;
        let historical = match self
            .captured_recovery_deployment(&admission.operation)?
            .ok_or_else(unsupported)?
        {
            RecoveryCapturedDeploymentV1::Verified(profile) => profile,
            RecoveryCapturedDeploymentV1::LegacyUnavailable
            | RecoveryCapturedDeploymentV1::Quarantined => return Err(unsupported()),
        };
        if historical.scope != *actor.scope() || historical.policy_digest != profile.policy_digest {
            return Err(unsupported());
        }
        let context = raw.security_invocation_context().ok_or_else(unsupported)?;
        let original = admission
            .original_retained_request()
            .ok_or_else(unsupported)?;
        original
            .validate_request_material(request)
            .map_err(durable_store_error)?;
        original
            .validate_native_security_authority(&historical.native_authority)
            .map_err(durable_store_error)?;
        original
            .validate_native_security_context(context)
            .map_err(durable_store_error)?;
        let hook = self
            .security_pre_dispatch_hook
            .as_ref()
            .ok_or_else(unsupported)?;
        if self.native_security_authority_binding()?.as_ref() != Some(&profile.native_authority) {
            return Err(unsupported());
        }
        let classified_output = super::super::security_dispatch::callback(
            "current recovery result classification",
            || {
                Ok(
                    hook.classify_recovery_result(&RecoveryResultClassificationContext {
                        operation: &admission.operation,
                        request,
                        security_context: context,
                        output,
                    }),
                )
            },
        )?
        .map_err(|_| unsupported())?;
        if matches!(
            classified_output,
            chio_security_types::InformationLabel::Top
        ) || self.is_emergency_stopped()
        {
            return Err(unsupported());
        }
        self.revalidate_recovery_actor(actor)?;
        if self.native_security_authority_binding()?.as_ref() != Some(&profile.native_authority) {
            return Err(unsupported());
        }
        let current = self.recovery_deployment(actor.scope())?;
        let digest = DeploymentDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::Deployment,
            &profile,
        )?);
        if DeploymentDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::Deployment,
            &current,
        )?) != digest
        {
            return Err(unsupported());
        }
        // Re-read physical capture and original verification roots after the
        // unlocked callback. The final writer rechecks current actor/profile.
        let retained = match self
            .captured_recovery_deployment(&admission.operation)?
            .ok_or_else(unsupported)?
        {
            RecoveryCapturedDeploymentV1::Verified(profile) => profile,
            RecoveryCapturedDeploymentV1::LegacyUnavailable
            | RecoveryCapturedDeploymentV1::Quarantined => return Err(unsupported()),
        };
        if recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::Deployment,
            retained.as_ref(),
        )? != recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::Deployment,
            historical.as_ref(),
        )? {
            return Err(unsupported());
        }
        let basis = RecoveryResultReleaseBasis {
            deployment_digest: digest,
            operation_id: admission.operation.binding().operation_id().clone(),
            request_binding_hash: admission.operation.binding().request_binding_hash().clone(),
            operation_version: admission.operation.version(),
            classified_output,
        };
        let record = self.read_recovery_workflow(
            actor,
            &request
                .declassification_grant
                .as_ref()
                .and_then(|grant| grant.recovery_v2())
                .ok_or_else(unsupported)?
                .body()
                .recovery
                .workflow_id,
        )?;
        let (port, runtime, now) = self.recovery_port()?;
        port.release_result(actor, &record.workflow_id, &basis, &runtime.fence, now)
            .map_err(durable_store_error)?;
        self.revalidate_recovery_actor(actor)?;
        if self.is_emergency_stopped() {
            return Err(unsupported());
        }
        if self.native_security_authority_binding()?.as_ref() != Some(&profile.native_authority)
            || DeploymentDigest::from_bytes(recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::Deployment,
                &self.recovery_deployment(actor.scope())?,
            )?) != digest
        {
            return Err(unsupported());
        }
        Ok(())
    }
}
pub(super) fn hex(digest: &PolicyDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(64);
    for byte in digest.as_bytes() {
        result.push(HEX[usize::from(byte >> 4)] as char);
        result.push(HEX[usize::from(byte & 15)] as char);
    }
    result
}

impl ChioKernel {
    pub(in crate::kernel) fn recovery_verification_context_for(
        &self,
        operation: &crate::admission_operation::AdmissionOperationId,
    ) -> Result<Option<RecoveryVerificationContextV1>, KernelError> {
        let runtime = self.durable_runtime()?;
        let Some(port) = runtime.store.recovery_authority() else {
            return Ok(None);
        };
        port.verification_context(operation, &runtime.fence, runtime.refresh_trusted_time(0))
            .map_err(durable_store_error)
    }
}

impl ChioKernel {
    pub fn durable_knowledge_enforcement(
        &self,
    ) -> Result<crate::knowledge::DurableKnowledgeEnforcement, crate::KernelError> {
        let runtime = self.durable_runtime()?;
        Ok(crate::knowledge::DurableKnowledgeEnforcement {
            store: runtime.store.clone(),
            fence: runtime.fence.clone(),
        })
    }
    pub fn durable_knowledge_enforced(&self, runtime_id: &str) -> Result<bool, crate::KernelError> {
        self.durable_knowledge_enforcement()?.enforced(runtime_id)
    }
}
