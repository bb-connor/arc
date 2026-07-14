use serde::Serialize;

use super::*;

pub(crate) struct DurableToolReturn {
    raw: RawInvocationOutcomeV1,
    outcome: ToolOutcomeRecordV1,
}

pub(crate) struct DurableToolReturnInput<'a> {
    pub(crate) request: &'a ToolCallRequest,
    pub(crate) output: &'a ToolServerOutput,
    pub(crate) reported_cost: Option<ToolInvocationCost>,
    pub(crate) matched_grant_index: usize,
    pub(crate) elapsed: Duration,
    pub(crate) extra_receipt_metadata: Option<serde_json::Value>,
    pub(crate) pre_invocation_guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
    pub(crate) trusted_now_unix_ms: u64,
}

#[derive(Serialize)]
struct LocalToolReturnEvidence<'a> {
    schema: &'static str,
    operation_id: &'a str,
    provider_attempt: &'a ProviderAttemptBindingV1,
    matched_grant_index: u64,
    elapsed_millis: u64,
    stream_limits: InvocationStreamLimitsV1,
    output: &'a InvocationOutputV1,
    reported_cost: &'a Option<ToolInvocationCost>,
    receipt_metadata_snapshot: &'a Option<serde_json::Value>,
    pre_invocation_guard_evidence: &'a [chio_core::receipt::metadata::GuardEvidence],
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

impl ChioKernel {
    pub(crate) fn record_durable_tool_return(
        &self,
        admission: &mut DurableToolAdmission,
        input: DurableToolReturnInput<'_>,
    ) -> Result<DurableToolReturn, KernelError> {
        let DurableToolReturnInput {
            request,
            output,
            reported_cost,
            matched_grant_index,
            elapsed,
            extra_receipt_metadata,
            pre_invocation_guard_evidence,
            trusted_now_unix_ms,
        } = input;
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
        let elapsed_millis = if fixed_runtime_unix_secs_for_current_thread().is_some() {
            0
        } else {
            u64::try_from(elapsed.as_millis())
                .unwrap_or(I_JSON_MAX_SAFE_INTEGER)
                .min(I_JSON_MAX_SAFE_INTEGER)
        };
        let matched_grant_index_usize = matched_grant_index;
        let matched_grant_index = u64::try_from(matched_grant_index_usize)
            .ok()
            .filter(|index| *index <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                KernelError::DurableAdmission("matched grant index is not I-JSON safe".to_owned())
            })?;
        let stream_limits = self.durable_stream_limits()?;
        let receipt_timestamp = trusted_now_unix_ms / 1_000;
        let request_metadata = request_receipt_metadata(
            request,
            self.attestation_trust_policy.as_ref(),
            receipt_timestamp,
            extra_receipt_metadata.as_ref(),
        )?;
        let memory_read_metadata = match crate::memory_provenance::classify_memory_action(
            &request.tool_name,
            &request.arguments,
        ) {
            Some(crate::memory_provenance::MemoryActionKind::Read { store, key }) => {
                self.resolve_memory_read_provenance_metadata(&store, &key)
            }
            _ => None,
        };
        let receipt_metadata_snapshot = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(request_metadata, extra_receipt_metadata),
                    receipt_attribution_metadata(
                        &request.capability,
                        Some(matched_grant_index_usize),
                    ),
                ),
                memory_read_metadata,
            ),
            Some(serde_json::json!({
                "receipt_context": {
                    "request_id": request.request_id.as_str()
                }
            })),
        );
        let transport_terminal_evidence_digest = admission_digest(
            "transport_terminal_evidence_digest",
            &LocalToolReturnEvidence {
                schema: "chio.local-tool-return-evidence.v1",
                operation_id: admission.operation_id(),
                provider_attempt: &provider_attempt,
                matched_grant_index,
                elapsed_millis,
                stream_limits,
                output: &invocation_output,
                reported_cost: &reported_cost,
                receipt_metadata_snapshot: &receipt_metadata_snapshot,
                pre_invocation_guard_evidence,
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
            matched_grant_index,
            elapsed_millis,
            stream_limits,
            invocation_output,
            monetary_cost,
            receipt_metadata_snapshot,
            pre_invocation_guard_evidence.to_vec(),
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
        Ok(DurableToolReturn {
            raw,
            outcome: stored,
        })
    }

    pub(crate) fn recover_durable_tool_admission(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
    ) -> Result<Option<ToolCallResponse>, KernelError> {
        match admission.state() {
            AdmissionOperationState::Finalizing => {
                let tool_return = self.load_durable_tool_return(admission)?;
                self.finalize_durable_tool_return(admission, request, &tool_return)
                    .map(Some)
            }
            AdmissionOperationState::Completed => self
                .completed_durable_tool_response(admission, request)
                .map(Some),
            _ => Ok(None),
        }
    }

    fn load_durable_tool_return(
        &self,
        admission: &DurableToolAdmission,
    ) -> Result<DurableToolReturn, KernelError> {
        let runtime = self.durable_runtime()?;
        let operation_id = admission.operation.binding().operation_id();
        let raw = runtime
            .outcome_store
            .load_raw_invocation_by_operation(operation_id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("raw tool return disappeared".to_owned())
            })?;
        let outcome = runtime
            .outcome_store
            .lookup_by_operation(operation_id)
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("recorded tool outcome disappeared".to_owned())
            })?;
        let blob = raw.canonical_blob().map_err(tool_outcome_error)?;
        outcome
            .validate_canonical_blob(&admission.operation, &blob)
            .map_err(tool_outcome_error)?;
        Ok(DurableToolReturn { raw, outcome })
    }

    fn materialize_durable_output(
        &self,
        raw: &RawInvocationOutcomeV1,
    ) -> Result<ToolCallOutput, KernelError> {
        let output = invocation_output_to_server_output(raw.output());
        match self.apply_stream_limit_snapshot(
            output,
            Duration::from_millis(raw.elapsed_millis()),
            raw.stream_limits(),
        )? {
            ToolServerOutput::Value(value) => Ok(ToolCallOutput::Value(value)),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                Ok(ToolCallOutput::Stream(stream))
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => {
                Err(KernelError::DurableAdmission(format!(
                    "incomplete durable output retained for recovery: {reason}"
                )))
            }
        }
    }

    fn durable_evaluation_contract(
        &self,
        admission: &DurableToolAdmission,
        raw: &RawInvocationOutcomeV1,
    ) -> Result<
        (
            usize,
            Vec<FrozenEvaluationStepV1>,
            PostReturnNormalizedRequestContextV1,
        ),
        KernelError,
    > {
        let matched_grant_index = raw.matched_grant_index().map_err(tool_outcome_error)?;
        if !admission.permits_grant(matched_grant_index) {
            return Err(KernelError::DurableAdmission(
                "recorded tool return does not match the captured grant".to_owned(),
            ));
        }
        let stream_limits = raw.stream_limits();
        let normalized_context = PostReturnNormalizedRequestContextV1::from_verified_normalization(
            serde_json::to_value(KernelPostReturnContext {
                schema: "chio.kernel-post-return-context.v1",
                request_binding_hash: admission
                    .operation
                    .binding()
                    .request_binding_hash()
                    .as_str(),
                matched_grant_index,
                elapsed_millis: raw.elapsed_millis(),
                max_stream_total_bytes: stream_limits.max_total_bytes,
                max_stream_chunks: stream_limits.max_chunks,
                max_stream_duration_secs: stream_limits.max_duration_secs,
            })
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?,
        )
        .map_err(tool_outcome_error)?;
        let implementation_digest = AdmissionDigest::try_new(
            "implementation_digest",
            sha256_hex(b"chio.kernel-output-finalization.v1"),
        )?;
        let frozen_steps = vec![FrozenEvaluationStepV1 {
            phase: EvaluationPhaseV1::OutputGuard,
            position: 0,
            component_id: AdmissionIdentifier::try_new(
                "component_id",
                "kernel-output-finalization",
            )?,
            component_version: AdmissionIdentifier::try_new("component_version", "v1")?,
            implementation_digest,
            mode: EvaluationModeV1::Pure,
        }];
        Ok((matched_grant_index, frozen_steps, normalized_context))
    }

    fn completed_durable_tool_response(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
    ) -> Result<ToolCallResponse, KernelError> {
        let runtime = self.durable_runtime()?;
        let tool_return = self.load_durable_tool_return(admission)?;
        let output = self.materialize_durable_output(&tool_return.raw)?;
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;
        let expected_non_admission_metadata = merge_metadata_objects(
            receipt_content.metadata.clone(),
            tool_return.raw.receipt_metadata_snapshot().cloned(),
        );
        let evaluation = runtime
            .outcome_store
            .lookup_post_return_evaluation(admission.operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("terminal evaluation disappeared".to_owned())
            })?;
        let (_, frozen_steps, normalized_context) =
            self.durable_evaluation_contract(admission, &tool_return.raw)?;
        evaluation
            .validate_against(&admission.operation, &tool_return.outcome)
            .and_then(|_| evaluation.validate_replay_contract(&frozen_steps, &normalized_context))
            .map_err(tool_outcome_error)?;
        if !matches!(
            evaluation.state(),
            PostReturnEvaluationStateV1::Resolved { .. }
        ) {
            return Err(KernelError::DurableAdmission(
                "completed admission retains a nonterminal evaluation".to_owned(),
            ));
        }
        let resolved_output = runtime
            .outcome_store
            .load_resolved_output_by_operation(admission.operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("resolved output preimage disappeared".to_owned())
            })?;
        let ResolvedToolOutcomeV1::Resolved {
            resolved_output: expected_output,
            resolved_output_size_bytes,
            ..
        } = tool_return.outcome.disposition()
        else {
            return Err(KernelError::DurableAdmission(
                "completed admission retains an unresolved tool outcome".to_owned(),
            ));
        };
        if resolved_output.blob_ref() != expected_output
            || u64::try_from(resolved_output.bytes().len()).ok()
                != Some(*resolved_output_size_bytes)
            || resolved_output.bytes() != receipt_content.canonical_content.as_slice()
        {
            return Err(KernelError::DurableAdmission(
                "completed output conflicts with its retained preimage".to_owned(),
            ));
        }
        let receipt_id = match admission.operation.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id,
            _ => {
                return Err(KernelError::DurableAdmission(
                    "completed admission has no receipt replay reference".to_owned(),
                ));
            }
        };
        let receipt = runtime
            .store
            .load_chio_receipt(receipt_id.as_str())
            .map_err(|error| KernelError::DurableAdmission(error.to_string()))?
            .ok_or_else(|| {
                KernelError::DurableAdmission("projected receipt disappeared".to_owned())
            })?;
        self.validate_completed_durable_receipt(
            admission,
            request,
            &tool_return,
            &receipt_content.content_hash,
            expected_non_admission_metadata,
            &receipt,
        )?;
        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: Some(output),
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        })
    }

    fn validate_completed_durable_receipt(
        &self,
        admission: &DurableToolAdmission,
        request: &ToolCallRequest,
        tool_return: &DurableToolReturn,
        expected_content_hash: &str,
        expected_non_admission_metadata: Option<serde_json::Value>,
        receipt: &chio_core::receipt::body::ChioReceipt,
    ) -> Result<(), KernelError> {
        let runtime = self.durable_runtime()?;
        let operation = &admission.operation;
        let replay_receipt_id = match operation.terminal_replay() {
            Some(AdmissionTerminalReplay::Receipt { receipt_id, .. }) => receipt_id.as_str(),
            _ => "",
        };
        let action =
            ToolCallAction::from_parameters(request.arguments.clone()).map_err(|error| {
                KernelError::DurableAdmission(format!("replay action is invalid: {error}"))
            })?;
        let binding = operation.binding().to_persisted();
        let expected_tenant = (binding.authenticated_tenant_id.as_str() != LOCAL_SYSTEM_TENANT_ID)
            .then_some(binding.authenticated_tenant_id.as_str());
        let signature_valid = receipt.verify_signature().map_err(|error| {
            KernelError::DurableAdmission(format!("replay receipt verification failed: {error}"))
        })?;
        let metadata = receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|value| value.get(ADMISSION_RECEIPT_METADATA_KEY))
            .cloned()
            .and_then(|value| serde_json::from_value::<AdmissionReceiptMetadataV1>(value).ok())
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "replay receipt admission metadata is invalid".to_owned(),
                )
            })?;
        let expected_outcome_id = Some(tool_return.outcome.outcome_id());
        let signing_nonce = receipt
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| {
                metadata.get(chio_core::receipt::signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY)
            })
            .and_then(serde_json::Value::as_str)
            .filter(|nonce| !nonce.is_empty())
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "projected receipt has no canonical signing nonce".to_owned(),
                )
            })?;
        let expected_metadata = merge_metadata_objects(
            merge_metadata_objects(
                expected_non_admission_metadata,
                Some(serde_json::json!({
                    ADMISSION_RECEIPT_METADATA_KEY: metadata.clone()
                })),
            ),
            Some(serde_json::json!({
                chio_core::receipt::signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY:
                    signing_nonce
            })),
        );
        let dispatch_fence = operation
            .dispatch_commit()
            .map(|commit| &commit.store_fence);
        if receipt.metadata != expected_metadata {
            return Err(KernelError::DurableAdmission(
                "projected receipt metadata conflicts with the retained snapshot".to_owned(),
            ));
        }
        if dispatch_fence.is_none_or(|fence| {
            metadata.store_fence.store_uuid != fence.store_uuid
                || metadata.store_fence.owner_epoch < fence.owner_epoch
        }) || metadata.store_fence.store_uuid != runtime.fence.store_uuid
            || metadata.store_fence.owner_epoch > runtime.fence.owner_epoch
        {
            return Err(KernelError::DurableAdmission(
                "projected receipt store fence conflicts with the admission lineage".to_owned(),
            ));
        }
        if !signature_valid
            || receipt.id != replay_receipt_id
            || receipt.kernel_key != self.config.keypair.public_key()
            || receipt.decision.as_ref() != Some(&Decision::Allow)
            || receipt.capability_id != request.capability.id
            || receipt.tool_server != request.server_id
            || receipt.tool_name != request.tool_name
            || receipt.action.parameters != action.parameters
            || receipt.action.parameter_hash != action.parameter_hash
            || receipt.content_hash != expected_content_hash
            || receipt.policy_hash != operation.binding().policy_hash().as_str()
            || receipt.tenant_id.as_deref() != expected_tenant
            || receipt.evidence != tool_return.raw.pre_invocation_guard_evidence()
            || metadata.schema != AdmissionReceiptSchema::V1
            || metadata.operation_id != *operation.binding().operation_id()
            || metadata.request_id != *operation.binding().request_id()
            || metadata.request_namespace_digest != *operation.binding().request_namespace_digest()
            || metadata.request_binding_hash != *operation.binding().request_binding_hash()
            || metadata.projected_operation_version != operation.version()
            || metadata.projected_state != AdmissionOperationState::Completed
            || metadata.projected_dispatch_state != AdmissionDispatchState::Terminal
            || metadata.trusted_time_unix_ms == 0
            || receipt.timestamp != metadata.trusted_time_unix_ms / 1_000
            || metadata.coordinator_lease_epoch != operation.coordinator_lease_epoch()
            || metadata.retained_dispatch_commit != operation.dispatch_commit().cloned()
            || metadata.compensation_status != AdmissionCompensationStatus::NotCompensated
            || metadata.tool_outcome_id.as_ref() != expected_outcome_id
            || metadata.tool_outcome_version != Some(tool_return.outcome.version())
        {
            return Err(KernelError::DurableAdmission(
                "projected receipt conflicts with the completed admission".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn finalize_durable_tool_return(
        &self,
        admission: &mut DurableToolAdmission,
        request: &ToolCallRequest,
        tool_return: &DurableToolReturn,
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
        let raw_blob = tool_return
            .raw
            .canonical_blob()
            .map_err(tool_outcome_error)?;
        tool_return
            .outcome
            .validate_canonical_blob(&admission.operation, &raw_blob)
            .map_err(tool_outcome_error)?;
        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(
            tool_return.raw.pre_invocation_guard_evidence().to_vec(),
        );
        let (_, frozen_steps, normalized_context) =
            self.durable_evaluation_contract(admission, &tool_return.raw)?;
        let output = self.materialize_durable_output(&tool_return.raw)?;
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;
        let resolved_output_digest = AdmissionDigest::try_new(
            "resolved_output_digest",
            receipt_content.content_hash.clone(),
        )?;
        let stored_outcome = runtime
            .outcome_store
            .lookup_by_operation(admission.operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?
            .ok_or_else(|| {
                KernelError::DurableAdmission("recorded tool outcome disappeared".to_owned())
            })?;
        if !stored_outcome.same_immutable_outcome(&tool_return.outcome) {
            return Err(KernelError::DurableAdmission(
                "recorded tool outcome conflicts with the recovery input".to_owned(),
            ));
        }
        stored_outcome
            .validate_canonical_blob(&admission.operation, &raw_blob)
            .map_err(tool_outcome_error)?;
        let existing_evaluation = runtime
            .outcome_store
            .lookup_post_return_evaluation(admission.operation.binding().operation_id())
            .map_err(durable_outcome_store_error)?;
        let trusted_now_unix_ms = current_unix_timestamp_ms()
            .max(stored_outcome.recorded_at_unix_ms())
            .max(
                existing_evaluation
                    .as_ref()
                    .map_or(0, PostReturnEvaluationRecordV1::trusted_time_unix_ms),
            )
            .max(1);
        let lease = self.claim_admission_recovery(&admission.operation, trusted_now_unix_ms)?;
        let mut evaluation = match existing_evaluation {
            Some(existing) => existing,
            None => {
                if !matches!(
                    stored_outcome.disposition(),
                    ResolvedToolOutcomeV1::Returned
                ) {
                    return Err(KernelError::DurableAdmission(
                        "terminal tool outcome has no retained evaluation".to_owned(),
                    ));
                }
                let prepared = PostReturnEvaluationRecordV1::prepare(
                    &admission.operation,
                    &stored_outcome,
                    frozen_steps.clone(),
                    trusted_now_unix_ms,
                    normalized_context.clone(),
                )
                .map_err(tool_outcome_error)?;
                runtime
                    .outcome_store
                    .begin_post_return_evaluation(
                        &lease,
                        &prepared,
                        &runtime.fence,
                        trusted_now_unix_ms,
                    )
                    .map_err(durable_outcome_store_error)?
            }
        };
        evaluation
            .validate_against(&admission.operation, &stored_outcome)
            .and_then(|_| evaluation.validate_replay_contract(&frozen_steps, &normalized_context))
            .map_err(tool_outcome_error)?;
        let post_guard_decision_digest = admission_digest(
            "post_guard_decision_digest",
            &KernelOutputGuardDecision {
                schema: "chio.kernel-output-guard-decision.v1",
                resolved_output_digest: resolved_output_digest.as_str(),
                complete: true,
            },
        )?;
        let pricing_verdict_digest = admission_digest(
            "pricing_verdict_digest",
            &KernelPricingVerdict {
                schema: "chio.kernel-pricing-verdict.v1",
                disposition: "not_applicable",
            },
        )?;
        let (terminal_evaluation, terminal_outcome) = match evaluation.state() {
            PostReturnEvaluationStateV1::Evaluating => {
                match evaluation.step_result_digest(0) {
                    Some(recorded) if recorded != &post_guard_decision_digest => {
                        return Err(KernelError::DurableAdmission(
                            "retained output-guard result conflicts with replay".to_owned(),
                        ));
                    }
                    Some(_) => {}
                    None => {
                        let next = evaluation
                            .record_next_pure_result(post_guard_decision_digest.clone())
                            .map_err(tool_outcome_error)?;
                        evaluation = runtime
                            .outcome_store
                            .stage_post_return_evaluation(
                                admission.operation.binding().operation_id(),
                                evaluation.version(),
                                &lease,
                                &next,
                                &runtime.fence,
                                trusted_now_unix_ms,
                            )
                            .map_err(durable_outcome_store_error)?;
                    }
                }
                if !matches!(
                    stored_outcome.disposition(),
                    ResolvedToolOutcomeV1::Returned
                ) {
                    return Err(KernelError::DurableAdmission(
                        "resolved tool outcome retains an incomplete evaluation".to_owned(),
                    ));
                }
                let (terminal_evaluation, resolved_output) = evaluation
                    .resolve_with_signing_preimage(
                        receipt_content.canonical_content.clone(),
                        post_guard_decision_digest.clone(),
                        pricing_verdict_digest.clone(),
                        SettlementDispositionV1::NotApplicable,
                    )
                    .map_err(tool_outcome_error)?;
                let terminal_outcome = stored_outcome
                    .transition(
                        stored_outcome.version(),
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
                        evaluation.version(),
                        &lease,
                        &terminal_evaluation,
                        stored_outcome.version(),
                        &terminal_outcome,
                        Some(&resolved_output),
                        &runtime.fence,
                        trusted_now_unix_ms,
                    )
                    .map_err(durable_outcome_store_error)?;
                (terminal_evaluation, terminal_outcome)
            }
            PostReturnEvaluationStateV1::Resolved { .. } => {
                let ResolvedToolOutcomeV1::Resolved {
                    resolved_output: expected_output,
                    resolved_output_size_bytes,
                    post_guard_decision_digest: recorded_guard,
                    pricing_verdict_digest: recorded_pricing,
                    settlement_disposition,
                    ..
                } = stored_outcome.disposition()
                else {
                    return Err(KernelError::DurableAdmission(
                        "resolved evaluation has no resolved tool outcome".to_owned(),
                    ));
                };
                let resolved_output = runtime
                    .outcome_store
                    .load_resolved_output_by_operation(admission.operation.binding().operation_id())
                    .map_err(durable_outcome_store_error)?
                    .ok_or_else(|| {
                        KernelError::DurableAdmission(
                            "resolved output preimage disappeared".to_owned(),
                        )
                    })?;
                if evaluation.step_result_digest(0) != Some(&post_guard_decision_digest)
                    || evaluation.step_result_digest(1).is_some()
                    || resolved_output.blob_ref() != expected_output
                    || u64::try_from(resolved_output.bytes().len()).ok()
                        != Some(*resolved_output_size_bytes)
                    || resolved_output.bytes() != receipt_content.canonical_content.as_slice()
                    || recorded_guard != &post_guard_decision_digest
                    || recorded_pricing != &pricing_verdict_digest
                    || settlement_disposition != &SettlementDispositionV1::NotApplicable
                {
                    return Err(KernelError::DurableAdmission(
                        "resolved finalization artifacts conflict with replay".to_owned(),
                    ));
                }
                (evaluation, stored_outcome)
            }
            PostReturnEvaluationStateV1::Frozen { .. } => {
                return Err(KernelError::DurableAdmission(
                    "post-return evaluation is frozen".to_owned(),
                ));
            }
        };
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
        let timestamp = trusted_now_unix_ms / 1_000;
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                receipt_content.metadata,
                tool_return.raw.receipt_metadata_snapshot().cloned(),
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
}
