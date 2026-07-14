use std::fmt;
use std::sync::Arc;

use serde::Serialize;

use super::*;
use crate::admission_operation::{
    AdmissionAttachment, AdmissionBeginResult, AdmissionCompensationStatus,
    AdmissionCompletedProjection, AdmissionDigest, AdmissionDispatchState, AdmissionIdentifier,
    AdmissionOperationBindingInputV1, AdmissionOperationBindingV1, AdmissionOperationCommand,
    AdmissionOperationKind, AdmissionOperationState, AdmissionOperationV1,
    AdmissionParticipantRequirements, AdmissionProjectionContext, AdmissionReceiptMetadataV1,
    AdmissionReceiptSchema, AdmissionRequestBindingV1, AdmissionTerminalProjection,
    AuthenticatedRequestNamespace, ObservationAttemptZero, ProviderAttemptBindingV1,
    QualifiedAdmissionOperationStoreExt, SideEffectClass, StoreMutationFence,
    VerifiedAdmissionReceipt, ADMISSION_RECEIPT_METADATA_KEY,
};
use crate::budget_store::{BudgetAdmissionBinding, BudgetEventAuthority};
use crate::receipt_store::QualifiedAdmissionProjectionStore;
use crate::supplemental_quota::CanonicalRevocationSet;
use crate::tool_outcome::{
    EvaluationModeV1, EvaluationPhaseV1, FrozenEvaluationStepV1, InvocationOutputV1,
    PostReturnEvaluationRecordV1, PostReturnNormalizedRequestContextV1, QualifiedToolOutcomeStore,
    RawInvocationOutcomeV1, SettlementDispositionV1, ToolOutcomeRecordV1, ToolOutcomeStoreError,
    ToolOutcomeTerminalEvidenceV1, ToolOutcomeTransitionV1,
};

const RECOVERY_LEASE_DURATION_MS: u64 = 60_000;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Clone)]
pub(crate) struct DurableAdmissionRuntime {
    store: Arc<dyn QualifiedAdmissionProjectionStore>,
    outcome_store: Arc<dyn QualifiedToolOutcomeStore>,
    fence: StoreMutationFence,
    claimant_id: AdmissionIdentifier,
}

impl fmt::Debug for DurableAdmissionRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableAdmissionRuntime")
            .field("fence", &self.fence)
            .field("claimant_id", &self.claimant_id)
            .finish_non_exhaustive()
    }
}

impl DurableAdmissionRuntime {
    pub(crate) fn new(
        store: Arc<dyn QualifiedAdmissionProjectionStore>,
        outcome_store: Arc<dyn QualifiedToolOutcomeStore>,
        fence: StoreMutationFence,
        kernel_id: &str,
    ) -> Result<Self, crate::admission_operation::AdmissionOperationError> {
        AdmissionIdentifier::try_new("store_uuid", fence.store_uuid.clone())?;
        AdmissionIdentifier::try_new("store_lease_id", fence.lease_id.clone())?;
        if fence.owner_epoch == 0 || fence.owner_epoch > I_JSON_MAX_SAFE_INTEGER {
            return Err(crate::admission_operation::AdmissionOperationError::InvalidStoreFence);
        }
        let claimant_id =
            AdmissionIdentifier::try_new("admission_claimant_id", format!("kernel:{kernel_id}"))?;
        Ok(Self {
            store,
            outcome_store,
            fence,
            claimant_id,
        })
    }

    fn authority(&self) -> BudgetEventAuthority {
        BudgetEventAuthority {
            authority_id: self.fence.store_uuid.clone(),
            lease_id: self.fence.lease_id.clone(),
            lease_epoch: self.fence.owner_epoch,
        }
    }
}

pub(crate) struct DurableToolAdmission {
    operation: AdmissionOperationV1,
}

#[derive(Serialize)]
struct LocalToolReturnEvidence<'a> {
    schema: &'static str,
    operation_id: &'a str,
    provider_attempt: &'a ProviderAttemptBindingV1,
    output: &'a InvocationOutputV1,
    reported_cost: &'a Option<ToolInvocationCost>,
}

#[derive(Serialize)]
struct KernelPostReturnContext<'a> {
    schema: &'static str,
    request_binding_hash: &'a str,
    matched_grant_index: usize,
    elapsed_millis: u64,
    max_stream_total_bytes: u64,
    max_stream_chunks: u64,
    max_stream_duration_secs: u64,
}

#[derive(Serialize)]
struct KernelOutputGuardDecision<'a> {
    schema: &'static str,
    resolved_output_digest: &'a str,
    complete: bool,
}

#[derive(Serialize)]
struct KernelPricingVerdict {
    schema: &'static str,
    disposition: &'static str,
}

impl DurableToolAdmission {
    pub(crate) fn operation_id(&self) -> &str {
        self.operation.binding().operation_id().as_str()
    }

    pub(crate) fn budget_hold_id(&self, grant_index: usize) -> String {
        format!("admission-budget:{}:{grant_index}", self.operation_id())
    }

    pub(crate) fn budget_authorize_event_id(&self, grant_index: usize) -> String {
        format!("{}:authorize", self.budget_hold_id(grant_index))
    }

    pub(crate) fn permits_grant(&self, grant_index: usize) -> bool {
        self.operation
            .budget_hold_id()
            .is_none_or(|hold_id| hold_id.as_str() == self.budget_hold_id(grant_index))
    }

    pub(crate) fn can_resume_captured_hold(&self) -> bool {
        self.operation.state() == AdmissionOperationState::CapturePending
    }
}

#[derive(Serialize)]
struct ImmutableToolAdmissionRequest<'a> {
    schema: &'static str,
    server_id: &'a str,
    tool_name: &'a str,
    agent_id: &'a str,
    arguments: &'a serde_json::Value,
    governed_intent: &'a Option<chio_core::capability::governance::GovernedTransactionIntent>,
    model_metadata: &'a Option<chio_core::capability::scope::ModelMetadata>,
    federated_origin_kernel_id: &'a Option<String>,
    matching_grants: Vec<ImmutableMatchingGrant<'a>>,
}

#[derive(Serialize)]
struct ImmutableMatchingGrant<'a> {
    index: usize,
    grant: &'a ToolGrant,
}

impl ChioKernel {
    pub(crate) fn begin_durable_tool_admission(
        &self,
        request: &ToolCallRequest,
        matching_grants: &[MatchingGrant<'_>],
        trusted_now_unix_ms: u64,
    ) -> Result<Option<DurableToolAdmission>, KernelError> {
        let effect_class = if matching_grants.iter().any(|matching| {
            matching.grant.max_cost_per_invocation.is_some()
                || matching.grant.max_total_cost.is_some()
        }) {
            SideEffectClass::Monetary
        } else {
            SideEffectClass::SideEffecting
        };
        if !self.durable_admission_mode.covers(effect_class) {
            return Ok(None);
        }
        let Some(runtime) = self.durable_admission_runtime.as_ref() else {
            if self.config.allow_ephemeral_receipt_log {
                return Ok(None);
            }
            return Err(KernelError::DurableAdmission(
                "no qualified admission operation store is configured".to_string(),
            ));
        };
        if effect_class == SideEffectClass::Monetary {
            return Err(KernelError::DurableAdmission(
                "durable monetary finalization requires a qualified payment journal".to_owned(),
            ));
        }
        if !self.post_invocation_pipeline.is_empty() {
            return Err(KernelError::DurableAdmission(
                "durable post-invocation hooks require frozen implementation identities".to_owned(),
            ));
        }
        if self.execution_nonce_config.is_some() {
            return Err(KernelError::DurableAdmission(
                "durable execution nonces require an atomic admission participant".to_owned(),
            ));
        }
        let projection_capabilities = runtime.store.admission_projection_capabilities();
        let observer_required = self.settlement_observer.is_some();
        if !projection_capabilities.operation_terminal
            || !projection_capabilities.tool_outcome
            || (observer_required && !projection_capabilities.observation_attempt_zero)
        {
            return Err(KernelError::DurableAdmission(
                "admission store lacks atomic terminal tool-outcome projection support".to_owned(),
            ));
        }

        let immutable_request = ImmutableToolAdmissionRequest {
            schema: "chio.tool-admission-request.v1",
            server_id: &request.server_id,
            tool_name: &request.tool_name,
            agent_id: &request.agent_id,
            arguments: &request.arguments,
            governed_intent: &request.governed_intent,
            model_metadata: &request.model_metadata,
            federated_origin_kernel_id: &request.federated_origin_kernel_id,
            matching_grants: matching_grants
                .iter()
                .map(|matching| ImmutableMatchingGrant {
                    index: matching.index,
                    grant: matching.grant,
                })
                .collect(),
        };
        let immutable_request_hash =
            admission_digest("immutable_request_hash", &immutable_request)?;
        let action =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::DurableAdmission(format!(
                    "tool action parameters are invalid: {error}"
                ))
            })?;
        let action_parameter_hash =
            AdmissionDigest::try_new("action_parameter_hash", action.parameter_hash.clone())?;
        let authorization_capability_hash =
            admission_digest("authorization_capability_hash", &request.capability)?;
        let policy_hash = AdmissionDigest::try_new("policy_hash", self.config.policy_hash.clone())
            .map_err(|_| {
                KernelError::DurableAdmission(
                    "durable admission requires a canonical SHA-256 policy hash".to_owned(),
                )
            })?;
        let requirements = AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            observation_attempt_zero: observer_required,
            ..AdmissionParticipantRequirements::NONE
        };
        let coordinator_authority_id = AdmissionIdentifier::try_new(
            "coordinator_authority_id",
            runtime.fence.store_uuid.clone(),
        )?;
        let namespace = match self.receipt_tenant_id_for_request(Some(&request.request_id)) {
            Some(tenant_id) => AuthenticatedRequestNamespace::from_authentication_context(
                coordinator_authority_id,
                tenant_id,
            )?,
            None => AuthenticatedRequestNamespace::for_local_system(coordinator_authority_id)?,
        };
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind: AdmissionOperationKind::ToolDispatch,
            namespace,
            request_id: AdmissionIdentifier::try_new("request_id", request.request_id.clone())?,
            capability_id: AdmissionIdentifier::try_new(
                "capability_id",
                request.capability.id.clone(),
            )?,
            authorization_capability_hash,
            request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
                immutable_request_hash,
                action_parameter_hash,
                requirements,
            )?,
            policy_hash,
            effect_class,
        })?;
        let prepared = AdmissionOperationV1::prepare(binding, runtime.fence.owner_epoch)?;
        let operation = match runtime
            .store
            .begin(&prepared, &runtime.fence, trusted_now_unix_ms)
            .map_err(durable_store_error)?
        {
            AdmissionBeginResult::Created(operation) => operation,
            AdmissionBeginResult::ExactReplay { operation, .. }
                if matches!(
                    operation.state(),
                    AdmissionOperationState::Prepared
                        | AdmissionOperationState::BrokerAttemptRegistered
                        | AdmissionOperationState::BudgetAuthorized
                        | AdmissionOperationState::ReadyToDispatch
                        | AdmissionOperationState::CapturePending
                ) =>
            {
                operation
            }
            AdmissionBeginResult::ExactReplay { operation, .. } => {
                return Err(KernelError::DurableAdmission(format!(
                    "request replay is retained in state {:?}",
                    operation.state()
                )));
            }
            AdmissionBeginResult::Conflict {
                existing_operation_id,
            } => {
                return Err(KernelError::DurableAdmission(format!(
                    "request id conflicts with retained operation {}",
                    existing_operation_id.as_str()
                )));
            }
        };
        let expected_attempt = ProviderAttemptBindingV1 {
            operation_id: operation.binding().operation_id().as_str().to_string(),
            attempt_id: format!("attempt:{}", operation.binding().operation_id().as_str()),
            transport_id: format!("kernel-tool-server:{}", request.server_id),
            transport_key_epoch: runtime.fence.owner_epoch,
        };
        expected_attempt.validate().map_err(|error| {
            KernelError::DurableAdmission(format!("provider attempt binding is invalid: {error}"))
        })?;
        let operation = match operation.state() {
            AdmissionOperationState::Prepared => self.apply_admission_command(
                operation,
                vec![AdmissionAttachment::BrokerAttempt(expected_attempt)],
                AdmissionOperationState::BrokerAttemptRegistered,
                trusted_now_unix_ms,
            )?,
            _ if operation.provider_attempt() == Some(&expected_attempt) => operation,
            _ => {
                return Err(KernelError::DurableAdmission(
                    "retained provider attempt does not match this dispatch".to_string(),
                ));
            }
        };
        Ok(Some(DurableToolAdmission { operation }))
    }

    pub(crate) fn durable_budget_binding(
        &self,
        admission: &DurableToolAdmission,
        capability: &CapabilityToken,
    ) -> Result<(BudgetAdmissionBinding, BudgetEventAuthority), KernelError> {
        let runtime = self.durable_runtime()?;
        let mut revocation_ids = Vec::with_capacity(capability.delegation_chain.len() + 1);
        revocation_ids.push(capability.id.clone());
        revocation_ids.extend(
            capability
                .delegation_chain
                .iter()
                .map(|link| link.capability_id.clone()),
        );
        let revocation_set =
            CanonicalRevocationSet::canonicalize(revocation_ids).map_err(|error| {
                KernelError::DurableAdmission(format!(
                    "capability revocation set is invalid: {error}"
                ))
            })?;
        Ok((
            BudgetAdmissionBinding {
                operation_id: admission.operation_id().to_string(),
                revocation_set,
                authorization_artifact_digests: Vec::new(),
                last_observed_revocation: None,
                supplemental_verifier_id: None,
                supplemental_verifier_config_digest: None,
                supplemental_authorization_artifact_digest: None,
                supplemental_authorization_expires_at: None,
            },
            runtime.authority(),
        ))
    }

    pub(crate) fn record_durable_budget_authorized(
        &self,
        admission: &mut DurableToolAdmission,
        budget_mutation: &PreExecutionBudgetMutation,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        let hold = budget_mutation.durable_hold_result().ok_or_else(|| {
            KernelError::DurableAdmission(
                "durable admission did not produce an authoritative budget hold".to_string(),
            )
        })?;
        let expected_authority = self.durable_runtime()?.authority();
        if hold.authorize_metadata.authority.as_ref() != Some(&expected_authority) {
            return Err(KernelError::DurableAdmission(
                "budget hold authority does not match the admission store fence".to_string(),
            ));
        }
        let expected_hold_id = admission.budget_hold_id(hold.grant_index);
        if hold.budget_hold_id != expected_hold_id {
            return Err(KernelError::DurableAdmission(
                "budget hold does not match the admission operation".to_string(),
            ));
        }
        match admission.operation.state() {
            AdmissionOperationState::BrokerAttemptRegistered => {
                admission.operation = self.apply_admission_command(
                    admission.operation.clone(),
                    vec![AdmissionAttachment::BudgetHoldId(
                        AdmissionIdentifier::try_new("budget_hold_id", expected_hold_id)?,
                    )],
                    AdmissionOperationState::BudgetAuthorized,
                    trusted_now_unix_ms,
                )?;
            }
            AdmissionOperationState::BudgetAuthorized
            | AdmissionOperationState::ReadyToDispatch
            | AdmissionOperationState::CapturePending
                if admission
                    .operation
                    .budget_hold_id()
                    .is_some_and(|hold_id| hold_id.as_str() == expected_hold_id) => {}
            state => {
                return Err(KernelError::DurableAdmission(format!(
                    "budget authorization cannot resume from state {state:?}"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn mark_durable_capture_pending(
        &self,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        if admission.operation.state() == AdmissionOperationState::BudgetAuthorized {
            admission.operation = self.apply_admission_command(
                admission.operation.clone(),
                Vec::new(),
                AdmissionOperationState::ReadyToDispatch,
                trusted_now_unix_ms,
            )?;
        }
        if admission.operation.state() == AdmissionOperationState::ReadyToDispatch {
            admission.operation = self.apply_admission_command(
                admission.operation.clone(),
                Vec::new(),
                AdmissionOperationState::CapturePending,
                trusted_now_unix_ms,
            )?;
        }
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(KernelError::DurableAdmission(format!(
                "capture cannot start from state {:?}",
                admission.operation.state()
            )));
        }
        Ok(())
    }

    pub(crate) fn commit_durable_dispatch(
        &self,
        admission: &mut DurableToolAdmission,
        trusted_now_unix_ms: u64,
    ) -> Result<(), KernelError> {
        if admission.operation.state() != AdmissionOperationState::CapturePending {
            return Err(KernelError::DurableAdmission(format!(
                "dispatch cannot commit from state {:?}",
                admission.operation.state()
            )));
        }
        admission.operation = self.apply_admission_command(
            admission.operation.clone(),
            Vec::new(),
            AdmissionOperationState::DispatchCommitted,
            trusted_now_unix_ms,
        )?;
        Ok(())
    }

    pub(crate) fn record_durable_tool_return(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
        output: &ToolServerOutput,
        reported_cost: Option<ToolInvocationCost>,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeRecordV1, KernelError> {
        let runtime = self.durable_runtime()?;
        if admission.operation.state() != AdmissionOperationState::DispatchCommitted {
            return Err(KernelError::DurableAdmission(format!(
                "tool return cannot be recorded from state {:?}",
                admission.operation.state()
            )));
        }
        let provider_attempt =
            admission
                .operation
                .provider_attempt()
                .cloned()
                .ok_or_else(|| {
                    KernelError::DurableAdmission(
                        "durable tool return has no registered provider attempt".to_owned(),
                    )
                })?;
        let invocation_output = match output {
            ToolServerOutput::Value(value) => InvocationOutputV1::Value {
                value: value.clone(),
            },
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                InvocationOutputV1::CompleteStream {
                    chunks: stream
                        .chunks
                        .iter()
                        .map(|chunk| chunk.data.clone())
                        .collect(),
                }
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
                InvocationOutputV1::IncompleteStream {
                    chunks: stream
                        .chunks
                        .iter()
                        .map(|chunk| chunk.data.clone())
                        .collect(),
                    reason: reason.clone(),
                }
            }
        };
        let transport_terminal_evidence_digest = admission_digest(
            "transport_terminal_evidence_digest",
            &LocalToolReturnEvidence {
                schema: "chio.local-tool-return-evidence.v1",
                operation_id: admission.operation_id(),
                provider_attempt: &provider_attempt,
                output: &invocation_output,
                reported_cost: &reported_cost,
            },
        )?;
        let monetary_cost =
            reported_cost
                .as_ref()
                .map(|cost| chio_core::capability::scope::MonetaryAmount {
                    units: cost.units,
                    currency: cost.currency.clone(),
                });
        let commit = admission
            .operation
            .dispatch_commit()
            .cloned()
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable tool return lost its dispatch commit".to_owned(),
                )
            })?;
        let raw = RawInvocationOutcomeV1::from_committed_dispatch(
            &admission.operation,
            &commit,
            AdmissionIdentifier::try_new("tool_server", request.server_id.clone())?,
            AdmissionIdentifier::try_new("tool_name", request.tool_name.clone())?,
            provider_attempt,
            transport_terminal_evidence_digest,
            invocation_output,
            monetary_cost,
        )
        .map_err(tool_outcome_error)?;
        let blob = raw.canonical_blob().map_err(tool_outcome_error)?;
        let record = ToolOutcomeRecordV1::record_tool_returned(
            &admission.operation,
            &raw,
            &blob,
            runtime.fence.clone(),
            trusted_now_unix_ms,
        )
        .map_err(tool_outcome_error)?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_owned())
            })?;
        let lease = runtime
            .store
            .claim_recovery(
                admission.operation.binding().operation_id(),
                admission.operation.version(),
                &runtime.claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                &runtime.fence,
            )
            .map_err(durable_store_error)?;
        let (stored, finalizing) = runtime
            .outcome_store
            .record_tool_returned(
                &admission.operation,
                &lease,
                &blob,
                &record,
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(durable_outcome_store_error)?
            .into_parts();
        admission.operation = finalizing;
        Ok(stored)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_durable_tool_return(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
        returned_outcome: &ToolOutcomeRecordV1,
        output: ToolServerOutput,
        elapsed: Duration,
        matched_grant_index: usize,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime = self.durable_runtime()?;
        if admission.operation.state() != AdmissionOperationState::Finalizing {
            return Err(KernelError::DurableAdmission(format!(
                "terminal projection cannot start from state {:?}",
                admission.operation.state()
            )));
        }
        if !self.post_invocation_pipeline.is_empty() {
            return Err(KernelError::DurableAdmission(
                "post-invocation pipeline changed after durable admission".to_owned(),
            ));
        }

        let limited = self.apply_stream_limits(output, elapsed)?;
        let output = match limited {
            ToolServerOutput::Value(value) => ToolCallOutput::Value(value),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                ToolCallOutput::Stream(stream)
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => {
                return Err(KernelError::DurableAdmission(format!(
                    "incomplete durable output retained for recovery: {reason}"
                )));
            }
        };
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;
        let resolved_output_digest = AdmissionDigest::try_new(
            "resolved_output_digest",
            receipt_content.content_hash.clone(),
        )?;
        let trusted_now_unix_ms = current_unix_timestamp_ms()
            .max(returned_outcome.recorded_at_unix_ms())
            .max(1);
        let lease = self.claim_admission_recovery(&admission.operation, trusted_now_unix_ms)?;
        let elapsed_millis = u64::try_from(elapsed.as_millis())
            .unwrap_or(I_JSON_MAX_SAFE_INTEGER)
            .min(I_JSON_MAX_SAFE_INTEGER);
        let normalized_context = PostReturnNormalizedRequestContextV1::from_verified_normalization(
            serde_json::to_value(KernelPostReturnContext {
                schema: "chio.kernel-post-return-context.v1",
                request_binding_hash: admission
                    .operation
                    .binding()
                    .request_binding_hash()
                    .as_str(),
                matched_grant_index,
                elapsed_millis,
                max_stream_total_bytes: self.config.max_stream_total_bytes,
                max_stream_chunks: self.config.memory_budget.max_stream_chunks,
                max_stream_duration_secs: self.config.max_stream_duration_secs,
            })
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
        )
        .map_err(tool_outcome_error)?;
        let implementation_digest = AdmissionDigest::try_new(
            "implementation_digest",
            sha256_hex(b"chio.kernel-output-finalization.v1"),
        )?;
        let prepared = PostReturnEvaluationRecordV1::prepare(
            &admission.operation,
            returned_outcome,
            vec![FrozenEvaluationStepV1 {
                phase: EvaluationPhaseV1::OutputGuard,
                position: 0,
                component_id: AdmissionIdentifier::try_new(
                    "component_id",
                    "kernel-output-finalization",
                )?,
                component_version: AdmissionIdentifier::try_new("component_version", "v1")?,
                implementation_digest,
                mode: EvaluationModeV1::Pure,
            }],
            trusted_now_unix_ms,
            normalized_context,
        )
        .map_err(tool_outcome_error)?;
        let prepared = runtime
            .outcome_store
            .begin_post_return_evaluation(&lease, &prepared, &runtime.fence, trusted_now_unix_ms)
            .map_err(durable_outcome_store_error)?;
        let post_guard_decision_digest = admission_digest(
            "post_guard_decision_digest",
            &KernelOutputGuardDecision {
                schema: "chio.kernel-output-guard-decision.v1",
                resolved_output_digest: resolved_output_digest.as_str(),
                complete: true,
            },
        )?;
        let evaluated = prepared
            .record_next_pure_result(post_guard_decision_digest.clone())
            .map_err(tool_outcome_error)?;
        let evaluated = runtime
            .outcome_store
            .stage_post_return_evaluation(
                admission.operation.binding().operation_id(),
                prepared.version(),
                &lease,
                &evaluated,
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(durable_outcome_store_error)?;
        let pricing_verdict_digest = admission_digest(
            "pricing_verdict_digest",
            &KernelPricingVerdict {
                schema: "chio.kernel-pricing-verdict.v1",
                disposition: "not_applicable",
            },
        )?;
        let (terminal_evaluation, resolved_output) = evaluated
            .resolve_with_signing_preimage(
                receipt_content.canonical_content.clone(),
                post_guard_decision_digest,
                pricing_verdict_digest,
                SettlementDispositionV1::NotApplicable,
            )
            .map_err(tool_outcome_error)?;
        let terminal_outcome = returned_outcome
            .transition(
                returned_outcome.version(),
                ToolOutcomeTransitionV1::Resolve(
                    terminal_evaluation
                        .terminal_evidence()
                        .map_err(tool_outcome_error)?,
                ),
            )
            .map_err(tool_outcome_error)?;
        let (terminal_evaluation, terminal_outcome) = runtime
            .outcome_store
            .finalize_post_return(
                admission.operation.binding().operation_id(),
                evaluated.version(),
                &lease,
                &terminal_evaluation,
                returned_outcome.version(),
                &terminal_outcome,
                Some(&resolved_output),
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(durable_outcome_store_error)?;
        let context = AdmissionProjectionContext {
            operation_id: admission.operation.binding().operation_id().clone(),
            request_id: admission.operation.binding().request_id().clone(),
            expected_operation_version: admission.operation.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: lease.coordinator_lease_epoch(),
            store_fence: runtime.fence.clone(),
        };
        let tool_outcome = ToolOutcomeTerminalEvidenceV1::from_records(
            &admission.operation,
            &context,
            &terminal_outcome,
            &terminal_evaluation,
        )
        .map_err(tool_outcome_error)?;
        let projected_operation_version =
            admission
                .operation
                .version()
                .checked_add(1)
                .ok_or_else(|| {
                    KernelError::DurableAdmission("operation version overflowed".to_owned())
                })?;
        let admission_metadata = AdmissionReceiptMetadataV1 {
            schema: AdmissionReceiptSchema::V1,
            operation_id: context.operation_id.clone(),
            request_id: context.request_id.clone(),
            request_namespace_digest: admission
                .operation
                .binding()
                .request_namespace_digest()
                .clone(),
            request_binding_hash: admission.operation.binding().request_binding_hash().clone(),
            projected_operation_version,
            projected_state: AdmissionOperationState::Completed,
            projected_dispatch_state: AdmissionDispatchState::Terminal,
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: context.coordinator_lease_id.clone(),
            coordinator_lease_epoch: context.coordinator_lease_epoch,
            store_fence: context.store_fence.clone(),
            retained_dispatch_commit: admission.operation.dispatch_commit().cloned(),
            compensation_status: AdmissionCompensationStatus::NotCompensated,
            tool_outcome_id: Some(terminal_outcome.outcome_id().clone()),
            tool_outcome_version: Some(terminal_outcome.version()),
        };
        let memory_action_kind = crate::memory_provenance::classify_memory_action(
            &request.tool_name,
            &request.arguments,
        );
        let memory_read_metadata = match memory_action_kind.as_ref() {
            Some(crate::memory_provenance::MemoryActionKind::Read { store, key }) => {
                self.resolve_memory_read_provenance_metadata(store, key)
            }
            _ => None,
        };
        let timestamp = trusted_now_unix_ms / 1_000;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            timestamp,
            extra_metadata.as_ref(),
        )?;
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        merge_metadata_objects(receipt_content.metadata, request_metadata),
                        extra_metadata,
                    ),
                    receipt_attribution_metadata(&request.capability, Some(matched_grant_index)),
                ),
                memory_read_metadata,
            ),
            Some(serde_json::json!({
                ADMISSION_RECEIPT_METADATA_KEY: admission_metadata
            })),
        );
        let action =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {error}"))
            })?;
        let receipt = self.build_and_sign_receipt(ReceiptParams {
            request_id: Some(&request.request_id),
            capability_id: &request.capability.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Allow,
            action,
            content_hash: receipt_content.content_hash,
            canonical_content: receipt_content.canonical_content,
            metadata,
            timestamp,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })?;
        let receipt = VerifiedAdmissionReceipt::from_kernel_verified(
            receipt,
            &self.config.keypair.public_key(),
            &admission.operation,
            &context,
            &tool_outcome,
        )
        .map_err(|error| {
            KernelError::DurableAdmission(format!("terminal receipt qualification failed: {error}"))
        })?;
        let observer_work = if admission
            .operation
            .binding()
            .participant_requirements()
            .observation_attempt_zero
        {
            Some(ObservationAttemptZero::from_verified(
                &admission.operation,
                &context,
                &receipt,
                terminal_outcome.outcome_id().clone(),
                terminal_outcome.version(),
            )?)
        } else {
            None
        };
        let projected_receipt = receipt.receipt().clone();
        let projection =
            AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
                context,
                receipt,
                tool_outcome: Some(tool_outcome),
                payment_evidence: None,
                authorization: None,
                eligibility: None,
                observer_work,
                obligation: None,
            }));
        let terminal = runtime
            .store
            .commit_admission_projection(&projection)
            .map_err(|error| {
                KernelError::DurableAdmission(format!("atomic terminal projection failed: {error}"))
            })?;
        if terminal.state != AdmissionOperationState::Completed {
            return Err(KernelError::DurableAdmission(
                "terminal projection did not complete the operation".to_owned(),
            ));
        }
        admission.operation = runtime
            .store
            .load_by_operation_id(admission.operation.binding().operation_id())
            .map_err(durable_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "completed admission operation disappeared".to_owned(),
                )
            })?;
        self.append_chio_receipt_to_local_log(projected_receipt.clone());
        self.apply_federation_cosign_for_admitted_request(request, &projected_receipt)?;
        if let Some(crate::memory_provenance::MemoryActionKind::Write { store, key }) =
            memory_action_kind.as_ref()
        {
            self.append_memory_provenance_for_write(
                store,
                key,
                &request.capability.id,
                &projected_receipt.id,
                projected_receipt.timestamp,
            )?;
        }
        let execution_nonce =
            self.mint_execution_nonce_for_allow(request, &request.capability, &projected_receipt)?;
        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: Some(output),
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt: projected_receipt,
            execution_nonce,
        })
    }

    fn claim_admission_recovery(
        &self,
        operation: &AdmissionOperationV1,
        trusted_now_unix_ms: u64,
    ) -> Result<crate::admission_operation::AdmissionRecoveryLease, KernelError> {
        let runtime = self.durable_runtime()?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_owned())
            })?;
        runtime
            .store
            .claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &runtime.claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                &runtime.fence,
            )
            .map_err(durable_store_error)
    }

    fn apply_admission_command(
        &self,
        operation: AdmissionOperationV1,
        attachments: Vec<AdmissionAttachment>,
        next_state: AdmissionOperationState,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionOperationV1, KernelError> {
        let runtime = self.durable_runtime()?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(RECOVERY_LEASE_DURATION_MS)
            .ok_or_else(|| {
                KernelError::DurableAdmission("recovery lease expiration overflowed".to_string())
            })?;
        let lease = runtime
            .store
            .claim_recovery(
                operation.binding().operation_id(),
                operation.version(),
                &runtime.claimant_id,
                trusted_now_unix_ms,
                expires_at_unix_ms,
                &runtime.fence,
            )
            .map_err(durable_store_error)?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease,
            attachments,
            Some(next_state),
            None,
            None,
        )?;
        runtime
            .store
            .compare_and_swap(&command, trusted_now_unix_ms)
            .map(|result| result.into_operation())
            .map_err(durable_store_error)
    }

    fn durable_runtime(&self) -> Result<&DurableAdmissionRuntime, KernelError> {
        self.durable_admission_runtime.as_ref().ok_or_else(|| {
            KernelError::DurableAdmission(
                "qualified admission operation store is unavailable".to_string(),
            )
        })
    }
}

fn admission_digest(
    field: &'static str,
    value: &impl Serialize,
) -> Result<AdmissionDigest, KernelError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| KernelError::DurableAdmission(format!("{field}: {error}")))?;
    AdmissionDigest::try_new(field, sha256_hex(&canonical)).map_err(KernelError::from)
}

fn durable_store_error(
    error: crate::admission_operation::AdmissionOperationStoreError,
) -> KernelError {
    KernelError::DurableAdmission(error.to_string())
}

fn durable_outcome_store_error(error: ToolOutcomeStoreError) -> KernelError {
    KernelError::DurableAdmission(error.to_string())
}

fn tool_outcome_error(error: crate::tool_outcome::ToolOutcomeError) -> KernelError {
    KernelError::DurableAdmission(error.to_string())
}
