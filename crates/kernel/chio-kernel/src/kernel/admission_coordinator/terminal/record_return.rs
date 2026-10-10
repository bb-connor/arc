//! Record an observed return once; historical loading never creates authority.
use super::*;

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
            context,
            elapsed,
            trusted_now_unix_ms,
        } = input;
        context.validate_binding(admission, request)?;
        let matched_grant_index = context.matched_grant_index;
        let pre_invocation_guard_evidence = &context.pre_invocation_guard_evidence;
        self.validate_guarded_output(request, matched_grant_index, output, false)?;
        let runtime = self.durable_runtime()?;
        let _mutation_guard = runtime.lock_mutations()?;
        let trusted_now_unix_ms = runtime.refresh_trusted_time(trusted_now_unix_ms)?;
        if !matches!(
            admission.operation.state(),
            AdmissionOperationState::DispatchCommitted
                | AdmissionOperationState::AwaitingCallerReport
        ) {
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
        let elapsed_millis = u64::try_from(elapsed.as_millis())
            .unwrap_or(I_JSON_MAX_SAFE_INTEGER)
            .min(I_JSON_MAX_SAFE_INTEGER);
        let matched_grant_index_usize = matched_grant_index;
        let matched_grant_index = u64::try_from(matched_grant_index_usize)
            .ok()
            .filter(|index| *index <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                KernelError::DurableAdmission("matched grant index is not I-JSON safe".to_owned())
            })?;
        let stream_limits = context.stream_limits;
        // This is an observation of the completed read, not an admission fact.
        let memory_read_metadata = match crate::memory_provenance::classify_memory_action(
            &request.tool_name,
            &request.arguments,
        ) {
            Some(crate::memory_provenance::MemoryActionKind::Read { store, key }) => {
                self.resolve_memory_read_provenance_metadata(&store, &key)
            }
            _ => None,
        };
        let receipt_metadata_snapshot =
            context.metadata_with_return_observation(memory_read_metadata);
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
        let raw = RawInvocationOutcomeV1::from_committed_dispatch_with_request(
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
            request,
            context.security_invocation_context.clone(),
        )
        .map_err(tool_outcome_error)?;
        let raw = raw
            .with_security_release_requirement(context.security_release_required)
            .map_err(tool_outcome_error)?;
        let raw = raw
            .with_federation_context_json(
                context
                    .federation_context
                    .as_ref()
                    .map(|federation| federation.canonical_json().to_owned()),
            )
            .map_err(tool_outcome_error)?;
        let raw = match context.receipt_signing_identity.as_ref() {
            Some(identity) => raw
                .with_receipt_signing_identity(identity.clone())
                .map_err(tool_outcome_error)?,
            None => raw,
        };
        let raw = raw
            .with_caller_delivery_evidence(context.caller_delivery_evidence.clone())
            .map_err(tool_outcome_error)?;
        let raw = raw
            .with_original_security_dispatch_binding(
                context.original_security_dispatch_binding.clone(),
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
        let claim =
            Self::recovery_claim_request(runtime, &admission.operation, trusted_now_unix_ms)?;
        let admission_store: &dyn QualifiedAdmissionOperationStore = runtime.store.as_ref();
        let (stored, finalizing) = runtime
            .outcome_store
            .claim_and_record_tool_returned(
                admission_store,
                claim,
                &mut qualified_lease(claim, trusted_now_unix_ms),
                &admission.operation,
                &blob,
                &record,
                &runtime.fence,
                trusted_now_unix_ms,
            )
            .map_err(durable_outcome_store_error)?
            .into_parts();
        admission.operation = finalizing;
        Ok(DurableToolReturn {
            origin: DurableReturnOrigin::Observed,
            raw,
            outcome: stored,
        })
    }
}
