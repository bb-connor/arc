use crate::security::adapters::NativeFlowResolver;
use chio_core_types::recovery::decode_contract;
use chio_core_types::{capability::token::CapabilityToken, Ed25519Backend, SigningBackend};
use chio_kernel::recovery::{
    AuthenticatedRecoveryActor, RecoveryCommandContinuationMode, RecoveryCommandError,
    RecoveryCommandResponseV1, RecoveryPermission,
};
use chio_kernel::ChioKernel;
use chio_process::ProcessRuntime;
use chio_security_types::recovery::*;
use std::sync::{Arc, OnceLock};

#[path = "runtime/native_work.rs"]
mod native_work;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryRuntimeError {
    #[error("invalid recovery command")]
    InvalidCommand,
    #[error("recovery authority refused")]
    AuthorityDenied,
    #[error("recovery command conflicted or is stale")]
    Conflict,
    #[error("recovery original is not eligible")]
    OriginRefused,
    #[error("recovery process journal is busy")]
    Busy,
    #[error("recovery profile is unsupported")]
    UnsupportedProfile,
    #[error("required protected mediator or artifact broker is unavailable")]
    UncoveredMediation,
    #[error("the operator must restart the native serving writer before qualification")]
    RestartRequired,
    #[error("the protected recovery setup probe has expired")]
    ProbeExpired,
    #[error("recovery projection exceeds the supported response bound")]
    ProjectionTooLarge,
    #[error("recovery effect is unresolved")]
    UnknownEffect,
    #[error("recovery authority is unavailable; retain the original command identity")]
    Unavailable,
}

#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryCommandResultV1 {
    pub status: RecoveryCommandResponseV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_response: Option<RecoveryResultProjectionV1>,
}
#[derive(serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryResultProjectionV1 {
    pub receipt: chio_core_types::receipt::body::ChioReceipt,
    pub result: Option<serde_json::Value>,
}
impl core::fmt::Debug for RecoveryCommandResultV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryCommandResultV1([redacted])")
    }
}
impl core::fmt::Debug for RecoveryResultProjectionV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryResultProjectionV1([redacted])")
    }
}

/// Trusted host composition with one pinned, native disclosure deployment.
/// Signing happens outside all store transactions. No background model,
/// command notification or generic retry middleware can start another effect.
#[derive(Clone)]
pub struct RecoveryRuntime {
    pub(super) kernel: Arc<ChioKernel>,
    pub(super) process: ProcessRuntime,
    pub(super) flow: Arc<NativeFlowResolver>,
    pub(super) scope: RecoveryScopeV1,
    pub(super) signer: Arc<Ed25519Backend>,
    pub(super) protected_mediator: Arc<OnceLock<Arc<crate::knowledge::NativeKnowledgeRuntime>>>,
}
impl core::fmt::Debug for RecoveryRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryRuntime([redacted])")
    }
}
impl RecoveryRuntime {
    pub fn new(
        kernel: Arc<ChioKernel>,
        process: ProcessRuntime,
        flow: Arc<NativeFlowResolver>,
        scope: RecoveryScopeV1,
        signer: Arc<Ed25519Backend>,
    ) -> Result<Self, RecoveryRuntimeError> {
        let profile = kernel
            .recovery_deployment(&scope)
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        let context = process
            .recovery_security_context(scope.process_id.as_str())
            .map_err(|_| RecoveryRuntimeError::UnsupportedProfile)?;
        if !flow.supports_recovery(&profile.native_authority)
            || context != profile.security_context
            || signer.public_key() != profile.aggregate_issuer
            || kernel.execution_nonce_required()
                != (profile.attachment_profile == RecoveryAttachmentProfile::OperationOwnedNonce)
        {
            return Err(RecoveryRuntimeError::UnsupportedProfile);
        }
        Ok(Self {
            kernel,
            process,
            flow,
            scope,
            signer,
            protected_mediator: Arc::new(OnceLock::new()),
        })
    }
    pub fn scope(&self) -> &RecoveryScopeV1 {
        &self.scope
    }
    /// The selected live broker is checked outside native transactions. Native
    /// command and capture owners independently recheck the installed profile.
    pub(super) fn validate_protected_mediation(&self) -> Result<(), RecoveryRuntimeError> {
        let required = self
            .kernel
            .protected_recovery_setup_required(&self.scope)
            .map_err(|_| RecoveryRuntimeError::UncoveredMediation)?;
        if let Some(mediator) = self.protected_mediator.get() {
            let profile = self
                .kernel
                .recovery_deployment(&self.scope)
                .map_err(|_| RecoveryRuntimeError::UncoveredMediation)?;
            mediator
                .validate_setup_binding(&self.scope, &profile.native_authority)
                .map_err(|_| RecoveryRuntimeError::UncoveredMediation)?;
        } else if required {
            return Err(RecoveryRuntimeError::UncoveredMediation);
        }
        Ok(())
    }
    // Keep custody decoding outside the long-lived effect driver's poll frame.
    // A completed native resume remains available after mediator loss.
    fn require_command_mediation(
        &self,
        actor: &AuthenticatedRecoveryActor,
        command: &RecoveryCommandBodyV1,
    ) -> Result<(), RecoveryRuntimeError> {
        let required = match command {
            RecoveryCommandBodyV1::CreateWorkflow { .. }
            | RecoveryCommandBodyV1::SelectOffer { .. }
            | RecoveryCommandBodyV1::SubmitApproval { .. } => true,
            RecoveryCommandBodyV1::ResumeWorkflow { workflow_id, .. } => {
                !self
                    .kernel
                    .read_recovery_workflow(actor, workflow_id)
                    .map_err(super::authentication_error)?
                    .captured
            }
            _ => false,
        };
        if required {
            self.validate_protected_mediation()?;
        }
        Ok(())
    }

    /// A canonical request and stable command ID are shared by CLI and SDKs.
    /// Successful command replay is freshly authorized before every projection.
    pub async fn execute(
        &self,
        capability: &CapabilityToken,
        bytes: &[u8],
    ) -> Result<RecoveryCommandResultV1, RecoveryRuntimeError> {
        let command: RecoveryCommandV1 =
            decode_contract(bytes).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        self.execute_command(capability, &command).await
    }
    pub fn execute_command<'a>(
        &'a self,
        capability: &'a CapabilityToken,
        command: &'a RecoveryCommandV1,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<RecoveryCommandResultV1, RecoveryRuntimeError>>
                + Send
                + 'a,
        >,
    > {
        let fixed_time = chio_kernel::fixed_runtime_unix_secs_for_current_thread();
        Box::pin(async move {
            let wire = chio_core_types::canonical_json_bytes(command)
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
            let _: RecoveryCommandV1 =
                decode_contract(&wire).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
            let principal =
                native_work::checked_principal(&self.kernel, &self.scope, capability, fixed_time)?;
            let runtime = self.clone();
            let capability = capability.clone();
            let command = command.clone();
            let work =
                async move { Box::pin(runtime.execute_command_inner(&capability, &command)).await };
            native_work::execute(principal, fixed_time, work).await
        })
    }
    async fn execute_command_inner(
        &self,
        capability: &CapabilityToken,
        command: &RecoveryCommandV1,
    ) -> Result<RecoveryCommandResultV1, RecoveryRuntimeError> {
        let wire = chio_core_types::canonical_json_bytes(command)
            .map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        let _: RecoveryCommandV1 =
            decode_contract(&wire).map_err(|_| RecoveryRuntimeError::InvalidCommand)?;
        let permission = permission(&command.command);
        let actor = self
            .kernel
            .authenticate_recovery_actor(&self.scope, capability, permission)
            .map_err(super::authentication_error)?;
        self.require_command_mediation(&actor, &command.command)?;
        let outcome = self
            .kernel
            .execute_recovery_command_outcome_with_origin(&actor, command, &self.process)
            .map_err(|error| match error {
                RecoveryCommandError::AuthorityDenied => RecoveryRuntimeError::AuthorityDenied,
                RecoveryCommandError::MediationRequired => RecoveryRuntimeError::UncoveredMediation,
                RecoveryCommandError::Conflict => RecoveryRuntimeError::Conflict,
                RecoveryCommandError::OriginRefused => RecoveryRuntimeError::OriginRefused,
                RecoveryCommandError::Busy => RecoveryRuntimeError::Busy,
                RecoveryCommandError::Unavailable => RecoveryRuntimeError::Unavailable,
            })?;
        let status = outcome.response().clone();
        let selection = outcome.selection();
        let selected = self
            .kernel
            .read_recovery_command_selection(&actor, selection)
            .map_err(super::authentication_error)?;
        if selected.mode() != RecoveryCommandContinuationMode::SameCurrentGeneration {
            // Fresh visibility is mandatory, but the exact accepted reply
            // remains read-only. A fresh alias never drives the first Resume.
            let current = self
                .kernel
                .authenticate_recovery_actor(&self.scope, capability, permission)
                .map_err(super::authentication_error)?;
            self.kernel
                .read_recovery_command_selection(&current, selection)
                .map_err(super::authentication_error)?;
            return Ok(RecoveryCommandResultV1 {
                status,
                original_response: None,
            });
        }
        let mut original_response = None;
        #[cfg(test)]
        match &command.command {
            RecoveryCommandBodyV1::CreateWorkflow { .. } => super::test_cutpoint("creation"),
            RecoveryCommandBodyV1::SelectOffer { .. } => super::test_cutpoint("selection"),
            RecoveryCommandBodyV1::SubmitApproval { .. } => super::test_cutpoint("approval"),
            _ => {}
        }
        match &command.command {
            RecoveryCommandBodyV1::CreateWorkflow { .. } => {
                self.materialize(&actor, &status.workflow_id)?;
            }
            RecoveryCommandBodyV1::ResumeWorkflow { workflow_id, .. } => {
                let record = self
                    .kernel
                    .read_recovery_command_selection(&actor, selection)
                    .map_err(super::authentication_error)?;
                if record.mode() != RecoveryCommandContinuationMode::SameCurrentGeneration {
                    return Ok(RecoveryCommandResultV1 {
                        status,
                        original_response: None,
                    });
                }
                let mut record = record.record().clone();
                if record.admission.is_some() {
                    record = self
                        .kernel
                        .reconcile_recovery_continuation(&actor, workflow_id)
                        .map_err(super::authentication_error)?;
                }
                if record.control == WorkflowControlV1::Active
                    && !record.admission_closed
                    && !record.effect.is_settled()
                    && !record.captured
                    && !matches!(
                        record.effect,
                        EffectObservationV1::Unknown { .. }
                            | EffectObservationV1::AwaitingApproval { .. }
                            | EffectObservationV1::AwaitingCallerReport { .. }
                    )
                {
                    let reservation = self.prepare_original(&actor, workflow_id)?;
                    let custody = self
                        .kernel
                        .load_recovery_request_custody(&actor, workflow_id)
                        .map_err(|_| RecoveryRuntimeError::Unavailable)?;
                    self.process
                        .finalize_recovery_call(&reservation, &custody)
                        .map_err(|_| RecoveryRuntimeError::Conflict)?;
                    #[cfg(test)]
                    super::test_cutpoint("process-finalized");
                    let _response = Box::pin(self.process.invoke_known_only(
                        self.scope.process_id.as_str(),
                        reservation.operation_key(),
                        custody.request(),
                    ))
                    .await
                    .map_err(|_| RecoveryRuntimeError::Unavailable)?;
                    #[cfg(test)]
                    {
                        super::test_cutpoint("returned-response");
                    }
                    // Fresh control identity, assignment, revocation and source
                    // clearance gate every return, including a native replay.
                    let current = self
                        .kernel
                        .authenticate_recovery_actor(&self.scope, capability, permission)
                        .map_err(super::authentication_error)?;
                    self.authorize_return(&current, workflow_id)?;
                    let completed = self
                        .kernel
                        .observe_recovery_completion(&current, workflow_id)
                        .map_err(super::authentication_error)?;
                    // Native custody determines completion. The process return
                    // withholds bytes until scoped replay; a preflight receipt
                    // alone never establishes a completed effect.
                    if matches!(completed.effect, EffectObservationV1::Complete { .. }) {
                        let response = self
                            .kernel
                            .replay_recovery_result(&current, workflow_id)
                            .map_err(super::authentication_error)?;
                        original_response = Some(project_response(response)?);
                    }
                } else if record.effect.is_settled() {
                    self.authorize_return(&actor, workflow_id)?;
                    if matches!(record.effect, EffectObservationV1::Complete { .. })
                        && record.provider_finality.is_none()
                    {
                        let response = self
                            .kernel
                            .replay_recovery_result(&actor, workflow_id)
                            .map_err(super::authentication_error)?;
                        original_response = Some(project_response(response)?);
                    }
                }
            }
            _ => {}
        }
        #[cfg(test)]
        if matches!(
            command.command,
            RecoveryCommandBodyV1::ResumeWorkflow { .. }
        ) {
            super::test_cutpoint("projection");
        }
        let current = self
            .kernel
            .authenticate_recovery_actor(&self.scope, capability, permission)
            .map_err(super::authentication_error)?;
        let record = self
            .kernel
            .read_recovery_command_selection(&current, selection)
            .map_err(super::authentication_error)?;
        if record.mode() != RecoveryCommandContinuationMode::SameCurrentGeneration {
            return Ok(RecoveryCommandResultV1 {
                status,
                original_response: None,
            });
        }
        let record = record.record().clone();
        Ok(RecoveryCommandResultV1 {
            status: RecoveryCommandResponseV1 {
                command_id: command.command_id.clone(),
                workflow_id: record.workflow_id,
                revision: record.revision,
                control: record.control,
                effect: record.effect,
                release: record.release,
            },
            original_response,
        })
    }
    /// Current settlement control is independent of the initiating token and
    /// cannot authorize invoke. It only inspects/settles the retained original.
    pub fn settle(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
    ) -> Result<RecoveryCommandResponseV1, RecoveryRuntimeError> {
        let actor = self
            .kernel
            .authenticate_recovery_actor(&self.scope, capability, RecoveryPermission::Settle)
            .map_err(super::authentication_error)?;
        let record = self
            .kernel
            .settle_recovery_workflow(&actor, workflow)
            .map_err(super::authentication_error)?;
        Ok(RecoveryCommandResponseV1 {
            command_id: CommandId::new("settlement-observation")
                .map_err(|_| RecoveryRuntimeError::InvalidCommand)?,
            workflow_id: record.workflow_id,
            revision: record.revision,
            control: record.control,
            effect: record.effect,
            release: record.release,
        })
    }
    /// Reserve a bounded original-operation lookup under current control,
    /// observe outside transactions, then reauthenticate before attaching proof.
    /// Blocking native phases use owned capacity independent of the caller's
    /// async driver. The accepted lookup keeps its original deadline and budget.
    pub async fn settle_from_provider(
        &self,
        capability: &CapabilityToken,
        workflow: &WorkflowId,
        connector: &super::PinnedSupportIssueConnector,
    ) -> Result<RecoveryCommandResponseV1, RecoveryRuntimeError> {
        let fixed_time = chio_kernel::fixed_runtime_unix_secs_for_current_thread();
        let principal =
            native_work::checked_principal(&self.kernel, &self.scope, capability, fixed_time)?;
        let kernel = self.kernel.clone();
        let scope = self.scope.clone();
        let authentication_capability = capability.clone();
        let actor = native_work::execute_settlement(principal.clone(), fixed_time, async move {
            kernel
                .authenticate_recovery_actor(
                    &scope,
                    &authentication_capability,
                    RecoveryPermission::Settle,
                )
                .map_err(super::authentication_error)
        })
        .await?;
        let observation_owner = connector
            .prepare_observation(
                capability
                    .expires_at
                    .checked_mul(1000)
                    .ok_or(RecoveryRuntimeError::Unavailable)?,
            )
            .map_err(|_| RecoveryRuntimeError::Unavailable)?;
        let kernel = self.kernel.clone();
        let selected_workflow = workflow.clone();
        let request_budget = observation_owner.request_budget();
        let lookup = native_work::execute_settlement(principal.clone(), fixed_time, async move {
            kernel
                .reserve_recovery_provider_lookup_with_budget(
                    &actor,
                    &selected_workflow,
                    request_budget,
                )
                .map_err(super::authentication_error)
        })
        .await?;
        let observation = observation_owner
            .observe(lookup)
            .await
            .map_err(|_| RecoveryRuntimeError::UnknownEffect)?;
        let runtime = self.clone();
        let settlement_capability = capability.clone();
        let selected_workflow = workflow.clone();
        native_work::execute_settlement(principal, fixed_time, async move {
            let current = runtime
                .kernel
                .authenticate_recovery_actor(
                    &runtime.scope,
                    &settlement_capability,
                    RecoveryPermission::Settle,
                )
                .map_err(super::authentication_error)?;
            runtime
                .kernel
                .attach_recovery_provider_finality(&current, &selected_workflow, &observation)
                .map_err(super::authentication_error)?;
            runtime.settle(&settlement_capability, &selected_workflow)
        })
        .await
    }
    fn authorize_return(
        &self,
        actor: &AuthenticatedRecoveryActor,
        workflow: &WorkflowId,
    ) -> Result<(), RecoveryRuntimeError> {
        self.kernel
            .read_recovery_workflow(actor, workflow)
            .map_err(super::authentication_error)?;
        let profile = self
            .kernel
            .recovery_deployment(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let assignment = profile
            .actors
            .as_slice()
            .iter()
            .find(|assignment| assignment.principal == *actor.principal())
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?;
        let observation = self
            .kernel
            .observe_recovery_source(&self.scope)
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        let state = observation
            .snapshot()
            .ok_or(RecoveryRuntimeError::AuthorityDenied)?;
        let source = state
            .principal_label
            .join_restrictions(&state.lineage_label)
            .and_then(|source| source.join_restrictions(&state.session_label))
            .map_err(|_| RecoveryRuntimeError::AuthorityDenied)?;
        if !source.flows_to(&assignment.preview_clearance) {
            return Err(RecoveryRuntimeError::AuthorityDenied);
        }
        Ok(())
    }
}
fn permission(body: &RecoveryCommandBodyV1) -> RecoveryPermission {
    match body {
        RecoveryCommandBodyV1::CreateWorkflow { .. } => RecoveryPermission::Create,
        RecoveryCommandBodyV1::InspectWorkflow { .. } => RecoveryPermission::Inspect,
        RecoveryCommandBodyV1::SelectOffer { .. } => RecoveryPermission::Select,
        RecoveryCommandBodyV1::SubmitApproval { .. } => RecoveryPermission::Approve,
        RecoveryCommandBodyV1::ResumeWorkflow { .. } => RecoveryPermission::Resume,
        RecoveryCommandBodyV1::CancelWorkflow { .. } => RecoveryPermission::Cancel,
        RecoveryCommandBodyV1::ReportDecision { .. } => RecoveryPermission::Report,
    }
}

fn project_response(
    response: chio_kernel::ToolCallResponse,
) -> Result<RecoveryResultProjectionV1, RecoveryRuntimeError> {
    let result = match response.output {
        Some(chio_kernel::ToolCallOutput::Value(value)) => Some(value),
        None => None,
        _ => return Err(RecoveryRuntimeError::UnsupportedProfile),
    };
    Ok(RecoveryResultProjectionV1 {
        receipt: response.receipt,
        result,
    })
}
