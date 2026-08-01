use super::*;

impl ChioKernel {
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn try_evaluate_agent_economy_tool_call(
        &self,
        request: &ToolCallRequest,
        matching: MatchingGrant<'_>,
        pre_invocation_guard_evidence: &[chio_core::receipt::metadata::GuardEvidence],
        extra_metadata: Option<serde_json::Value>,
        security_context: Option<&SecurityInvocationContext>,
        now_unix_secs: u64,
        now_unix_ms: u64,
    ) -> Result<Option<ToolCallResponse>, KernelError> {
        if self.agent_economy_durable_admission_runtime.is_none() {
            return Ok(None);
        }

        self.reconcile_durable_admission_startup()?;
        let mut admission = match self.begin_durable_tool_admission(
            request,
            std::slice::from_ref(&matching),
            now_unix_ms,
        ) {
            Ok(Some(admission)) => admission,
            Ok(None) => return Ok(None),
            Err(error) => {
                let reason = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "agent-economy durable admission denied"
                );
                return self
                    .with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                        self.build_deny_response_with_metadata(
                            request,
                            &reason,
                            now_unix_secs,
                            Some(matching.index),
                            extra_metadata,
                        )
                    })
                    .map(Some);
            }
        };
        if let Some(response) = self.recover_durable_tool_admission(&mut admission, request)? {
            return Ok(Some(response));
        }

        let runtime_admission = self.run_runtime_admission_hook(
            request,
            extra_metadata.as_ref(),
            now_unix_secs,
            now_unix_ms,
            Some(matching.index),
        );
        let mut extra_metadata =
            merge_metadata_objects(extra_metadata, runtime_admission.metadata.clone());
        if !runtime_admission.allowed {
            let reason = runtime_admission
                .reason
                .unwrap_or_else(|| "runtime admission denied".to_owned());
            extra_metadata = self.compensate_agent_economy_pre_dispatch(
                request,
                &admission,
                extra_metadata,
                false,
                now_unix_ms,
                "runtime_admission_denied",
            )?;
            return self
                .with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                    self.build_deny_response_with_metadata(
                        request,
                        &reason,
                        now_unix_secs,
                        Some(matching.index),
                        extra_metadata,
                    )
                })
                .map(Some);
        }

        let mut budget_mutation = match self.authorize_agent_economy_budget(
            request,
            &request.capability,
            matching,
            &mut admission,
            now_unix_ms,
        ) {
            Ok(mutation) => mutation,
            Err(error) => {
                let reason = error.to_string();
                extra_metadata = self.compensate_agent_economy_pre_dispatch(
                    request,
                    &admission,
                    extra_metadata,
                    false,
                    now_unix_ms,
                    "budget_authorization_denied",
                )?;
                return self
                    .with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                        self.build_deny_response_with_metadata(
                            request,
                            &reason,
                            now_unix_secs,
                            Some(matching.index),
                            extra_metadata,
                        )
                    })
                    .map(Some);
            }
        };

        let budget_lease_acquired = match self.admit_capability_budget(&request.capability) {
            Ok(acquired) => acquired,
            Err(reason) => {
                extra_metadata = self.compensate_agent_economy_pre_dispatch(
                    request,
                    &admission,
                    extra_metadata,
                    false,
                    now_unix_ms,
                    "delegated_budget_admission_denied",
                )?;
                return self
                    .with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                        self.build_deny_response_with_metadata(
                            request,
                            &format!("sibling-sum budget admission failed: {reason}"),
                            now_unix_secs,
                            Some(matching.index),
                            extra_metadata,
                        )
                    })
                    .map(Some);
            }
        };

        if let Err(error) =
            self.authorize_agent_economy_payment(request, &admission, now_unix_ms)
        {
            if budget_lease_acquired {
                self.release_admitted_capability_budget(&request.capability)
                    .map_err(KernelError::DelegationInvalid)?;
            }
            // Rail authorization may have succeeded before its journal advance
            // failed. Retain the operation for qualified recovery rather than
            // asserting a pre-dispatch release from ambiguous evidence.
            return Err(error);
        }

        let mut security_pre_dispatch = match self
            .run_security_pre_dispatch_hook(request, security_context)
        {
            Ok(outcome) => outcome,
            Err(denial) => {
                let mut denial_evidence = pre_invocation_guard_evidence.to_vec();
                denial_evidence.push(denial.evidence);
                extra_metadata = self.compensate_agent_economy_pre_dispatch(
                    request,
                    &admission,
                    extra_metadata,
                    budget_lease_acquired,
                    now_unix_ms,
                    "security_pre_dispatch_denied",
                )?;
                return self
                    .with_pre_invocation_guard_evidence(&denial_evidence, || {
                        self.build_deny_response_with_metadata(
                            request,
                            denial.reason,
                            now_unix_secs,
                            Some(matching.index),
                            extra_metadata,
                        )
                    })
                    .map(Some);
            }
        };
        let mut security_dispatch_outcome = security_pre_dispatch.dispatch_outcome.take();
        let security_request_lifecycle = security_pre_dispatch.request_lifecycle.take();

        if let Err(error) = self.mark_durable_capture_pending(&mut admission, now_unix_ms) {
            if let Some(outcome) = security_dispatch_outcome.take() {
                outcome.record_dispatch_failed()?;
            }
            extra_metadata = self.compensate_agent_economy_pre_dispatch(
                request,
                &admission,
                extra_metadata,
                budget_lease_acquired,
                now_unix_ms,
                "capture_prepare_failed",
            )?;
            let reason = error.to_string();
            return self
                .with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                    self.build_deny_response_with_metadata(
                        request,
                        &reason,
                        now_unix_secs,
                        Some(matching.index),
                        extra_metadata,
                    )
                })
                .map(Some);
        }
        if let Err(error) = self.capture_and_commit_durable_dispatch(
            &mut admission,
            &request.capability,
            &mut budget_mutation,
            now_unix_ms,
        ) {
            if let Some(outcome) = security_dispatch_outcome.take() {
                outcome.record_dispatch_failed()?;
            }
            if budget_lease_acquired {
                self.release_admitted_capability_budget(&request.capability)
                    .map_err(KernelError::DelegationInvalid)?;
            }
            let reason = error.to_string();
            return self
                .with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                    self.build_deny_response_with_metadata(
                        request,
                        &reason,
                        now_unix_secs,
                        Some(matching.index),
                        self.mark_runtime_admission_reservations_retained_fail_closed(
                            extra_metadata,
                        ),
                    )
                })
                .map(Some);
        }

        if let Some(outcome) = security_dispatch_outcome.as_mut() {
            outcome.mark_dispatch_started();
        }
        let tool_started_at = Instant::now();
        let dispatch_result = self
            .dispatch_within_budget(request, budget_mutation.is_monetary())
            .await;
        if let Some(outcome) = security_dispatch_outcome.take() {
            match &dispatch_result {
                Ok((ToolServerOutput::Value(_), _))
                | Ok((ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)), _)) => {
                    outcome.record_released()?;
                }
                Ok((ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { .. }), _))
                | Err(_) => outcome.record_outcome_unknown_after_dispatch()?,
            }
        }
        let (tool_output, reported_cost) = match dispatch_result {
            Ok(result) => result,
            Err(error) => {
                if budget_lease_acquired {
                    self.release_admitted_capability_budget(&request.capability)
                        .map_err(KernelError::DelegationInvalid)?;
                }
                return Err(error);
            }
        };
        let recorded_at_unix_ms = current_unix_timestamp_ms().max(now_unix_ms);
        let tool_return = self.record_durable_tool_return(
            &mut admission,
            AgentEconomyDurableToolReturnInput {
                request,
                output: &tool_output,
                reported_cost,
                matched_grant_index: matching.index,
                elapsed: tool_started_at.elapsed(),
                extra_receipt_metadata: extra_metadata,
                pre_invocation_guard_evidence,
                trusted_now_unix_ms: recorded_at_unix_ms,
                security_invocation_context: security_context,
            },
        );
        let response = match tool_return {
            Ok(tool_return) => {
                self.finalize_durable_tool_return(&mut admission, request, &tool_return)
            }
            Err(error) => Err(error),
        };
        let lease_release = if budget_lease_acquired {
            self.release_admitted_capability_budget(&request.capability)
                .map_err(KernelError::DelegationInvalid)
        } else {
            Ok(())
        };
        let response = match (response, lease_release) {
            (Ok(response), Ok(())) => response,
            (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
            (Err(primary), Err(cleanup)) => {
                return Err(KernelError::Internal(format!(
                    "agent-economy terminal error: {primary}; delegated-budget cleanup error: {cleanup}"
                )))
            }
        };
        if let Some(permit) = security_request_lifecycle {
            permit.ensure_final_release()?;
        }
        Ok(Some(response))
    }

    #[allow(clippy::too_many_arguments)]
    fn compensate_agent_economy_pre_dispatch(
        &self,
        request: &ToolCallRequest,
        admission: &AgentEconomyDurableToolAdmission,
        metadata: Option<serde_json::Value>,
        budget_lease_acquired: bool,
        trusted_now_unix_ms: u64,
        reason: &'static str,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        let metadata =
            self.release_runtime_admission_reservations_for_pre_dispatch_denial(metadata);
        self.compensate_durable_admission_before_dispatch(
            admission.operation(),
            serde_json::json!({
                "schema": "chio.agent-economy-pre-dispatch-compensation-policy.v1",
                "requestId": request.request_id,
                "reason": reason,
            }),
            trusted_now_unix_ms,
        )?;
        if budget_lease_acquired {
            self.release_admitted_capability_budget(&request.capability)
                .map_err(KernelError::DelegationInvalid)?;
        }
        Ok(metadata)
    }
}
