use super::evaluation_helpers::{PreDispatchCleanupDeny, SecurityDispatchOutcomeRecovery};
use super::*;
use crate::kernel::admission_coordinator::{
    ThresholdDispatchPermit, ThresholdPaymentMode, ThresholdToolAdmissionContext,
};
use crate::kernel::dispatch::dispatch_admission_error_reason;
use crate::kernel::kernel_drop_guard::reserved_runtime_admission_ids;

impl ChioKernel {
    pub(crate) fn evaluate_tool_call_with_nested_flow_client<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(self.evaluate_tool_call_with_nested_flow_client_async(
            parent_context,
            request,
            client,
            extra_metadata,
        ))
    }

    pub(crate) fn evaluate_tool_call_with_nested_flow_client_and_security_context<
        C: NestedFlowClient,
    >(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
        security_context: &SecurityInvocationContext,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(
            self.evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                parent_context,
                request,
                client,
                extra_metadata,
                security_context,
            ),
        )
    }

    pub(crate) async fn evaluate_tool_call_with_nested_flow_client_async<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_with_nested_flow_client_async_inner(
            parent_context,
            request,
            client,
            extra_metadata,
            None,
        )
        .await
    }

    pub(crate) async fn evaluate_tool_call_with_nested_flow_client_async_and_security_context<
        C: NestedFlowClient,
    >(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
        security_context: &SecurityInvocationContext,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_with_nested_flow_client_async_inner(
            parent_context,
            request,
            client,
            extra_metadata,
            Some(security_context),
        )
        .await
    }

    async fn evaluate_tool_call_with_nested_flow_client_async_inner<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<ToolCallResponse, KernelError> {
        let evaluation_id = uuid::Uuid::now_v7().to_string();
        RECEIPT_EVALUATION_SCOPE_KEY
            .scope(
                evaluation_id,
                self.evaluate_tool_call_with_nested_flow_client_async_scoped(
                    parent_context,
                    request,
                    client,
                    extra_metadata,
                    security_context,
                ),
            )
            .await
    }

    async fn evaluate_tool_call_with_nested_flow_client_async_scoped<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<ToolCallResponse, KernelError> {
        request.validate()?;
        self.validate_security_invocation_context_binding(
            request,
            security_context,
            Some(&parent_context.session_id),
        )?;
        // Install the parent session's tenant_id so every
        // receipt signed while this nested-flow evaluation is in flight
        // carries the correct tenant tag.
        let tenant_id = security_context
            .map(|security| security.as_v1().tenant_id().as_str().to_string())
            .or_else(|| self.resolve_tenant_id_for_session(Some(&parent_context.session_id)));
        let _tenant_request_scope =
            self.scope_receipt_tenant_id_for_request(&request.request_id, tenant_id.clone());
        let _tenant_scope = scope_receipt_tenant_id(tenant_id);

        let now_unix_ms = current_unix_timestamp_ms();
        let now = now_unix_ms / 1000;

        // Emergency kill switch: the nested-flow path also
        // deny-fast before receipt negotiation so sampling/elicitation-bearing
        // tool calls cannot slip past while the kernel is stopped.
        if self.is_emergency_stopped() {
            warn!(
                request_id = %request.request_id,
                "emergency stop active -- denying evaluate_tool_call (nested flow)"
            );
            return self.build_emergency_stop_deny_response_with_metadata(
                request,
                EMERGENCY_STOP_DENY_REASON,
                now,
                None,
                None,
            );
        }

        // RSS soft ceiling: shed new admissions before the OS OOM-kills the
        // mediator. The nested-flow path gates on the same atomic-load fast
        // path as the top-level evaluate, right after the emergency stop, so
        // sampling/elicitation-bearing tool calls cannot allocate and run after
        // the sampler raised the soft-ceiling flag.
        if self.is_rss_shedding() {
            warn!(
                request_id = %request.request_id,
                "rss soft ceiling exceeded -- shedding evaluate_tool_call (nested flow)"
            );
            // Receipt-totality: persist a signed deny receipt naming the shed
            // resource, like the emergency-stop fast path above, so the overload
            // denial has the same audit trail as every other admission decision.
            // The shed still returns Overloaded so the tower load-shed edge
            // surfaces backpressure; a receipt-persist failure is logged but must
            // not mask the shed decision (fail-closed).
            if let Err(receipt_error) = self.record_overload_shed_deny_receipt(
                request,
                crate::OverloadResource::Allocation,
                now,
                extra_metadata.clone(),
            ) {
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&receipt_error.to_string()),
                    "failed to persist overload-shed deny receipt"
                );
            }
            return Err(KernelError::Overloaded {
                resource: crate::OverloadResource::Allocation,
            });
        }

        // The pre-dispatch receipt-version admission gate must run on the
        // nested-flow path too. The admission snapshot is scoped for the
        // receipt builders below so a peer that expires during nested tool
        // execution does not change the already-admitted version or key.
        let receipt_admission = match self
            .kernel_receipt_admission_for_remote(request.federated_origin_kernel_id.as_deref(), now)
        {
            Ok(admission) => admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&msg),
                    "receipt federation admission failed pre-dispatch (nested flow)"
                );
                return self.build_negotiation_failclosed_deny_response_with_metadata(
                    request, &msg, now, None, None,
                );
            }
        };
        let _receipt_federation_request_scope = self
            .scope_receipt_federation_admission_for_request(
                &request.request_id,
                receipt_admission.clone(),
            );
        let _receipt_federation_scope =
            scope_receipt_federation_admission(Some(receipt_admission.clone()));

        self.validate_web3_evidence_prerequisites()?;

        debug!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            server = %request.server_id,
            "evaluating tool call with nested-flow bridge"
        );

        let cap = &request.capability;

        // Signature first; the budget admission is deferred until
        // after all subsequent checks pass, so a denied call no longer
        // consumes the parent's share.
        if let Err(reason) = self.verify_capability_full_pre_admit(
            cap,
            request.federated_origin_kernel_id.as_deref(),
            now,
        ) {
            let msg = format!("capability verification failed: {reason}");
            warn!(request_id = %request.request_id, msg = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = self.check_tool_call_revocation_admission(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = self.validate_delegation_admission(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response(request, &msg, now, None);
        }

        let matching_grants = match resolve_required_matching_grants(
            cap,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        ) {
            Ok(grants) => grants,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                return self.build_deny_response(request, &msg, now, None);
            }
        };

        // DPoP enforcement before budget charge: if any matching grant requires
        // DPoP, verify the proof now so an attacker cannot drain the budget with
        // a valid capability token but missing or invalid DPoP proof.
        let dpop_required = matching_grants
            .iter()
            .any(|matching| matching.grant.dpop_required == Some(true));
        if dpop_required {
            let verification = request.dpop_proof.as_ref().map_or_else(
                || {
                    Err(KernelError::DpopVerificationFailed(
                        "grant requires DPoP proof but none was provided".to_string(),
                    ))
                },
                |proof| {
                    self.verify_dpop_for_permission_preview(
                        proof,
                        cap,
                        &request.server_id,
                        &request.tool_name,
                        &request.arguments,
                    )
                },
            );
            if let Err(e) = verification {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "DPoP verification failed");
                return self.build_deny_response(request, &msg, now, None);
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool target not registered");
            return self.build_deny_response(request, &msg, now, None);
        }

        // Confirm durable persistence is healthy BEFORE the first writer-backed
        // metadata write below. Recording capability lineage runs through the
        // receipt writer, so a serving-closed writer must be denied at these
        // gates first; otherwise the lineage write fails against a dead writer and
        // surfaces its own error (or a 500) instead of the clean fail-closed deny.
        if let Err(error) = self.ensure_federated_receipt_persistence_ready(
            request.federated_origin_kernel_id.as_deref(),
        ) {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "federated receipt persistence unavailable pre-dispatch (nested flow)"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request, &msg, now, None, None,
            );
        }
        if let Err(error) = self.ensure_tcb_locks_healthy() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "tcb lock poisoned pre-dispatch (nested flow)"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request, &msg, now, None, None,
            );
        }
        if let Err(error) = self.ensure_receipt_persistence_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "receipt persistence unavailable pre-dispatch (nested flow)"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request, &msg, now, None, None,
            );
        }
        if let Err(error) = self.ensure_revocation_durability_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "revocation durability unavailable pre-dispatch (nested flow)"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request, &msg, now, None, None,
            );
        }

        // Persistence is confirmed healthy, so the writer-backed lineage write can
        // run without racing a dead writer.
        if let Err(error) =
            self.record_observed_capability_snapshot_for_dispatch(cap, security_context)
        {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            return self.build_deny_response(request, &msg, now, None);
        }

        let matched = matching_grants.first().copied().ok_or_else(|| {
            KernelError::Internal("matching grant set unexpectedly empty".to_string())
        })?;
        let matched_grant_index = matched.index;
        let matched_grant = matched.grant;

        let validated_governed_admission = match self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            Some(parent_context),
            now,
        ) {
            Ok(validated_governed_admission) => validated_governed_admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed transaction denied");
                return self.build_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    std::slice::from_ref(&matched),
                    cap,
                    None,
                );
            }
        };
        let verified_governed_payee_binding = validated_governed_admission
            .as_ref()
            .and_then(|admission| admission.verified_payee_binding.clone());
        let _governed_runtime_attestation_receipt_scope =
            scope_governed_runtime_attestation_receipt_record(
                validated_governed_admission
                    .as_ref()
                    .and_then(|admission| admission.verified_runtime_attestation.clone()),
            );
        // Resolve all call-chain receipt evidence before authoritative
        // admission. A failed durable lookup cannot consume quota.
        let governed_call_chain_receipt_evidence = match self.governed_call_chain_receipt_evidence(
            request,
            cap,
            Some(parent_context),
            validated_governed_admission
                .as_ref()
                .and_then(|admission| admission.call_chain_proof.clone()),
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed call-chain evidence lookup failed (nested flow)");
                return self.build_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    std::slice::from_ref(&matched),
                    cap,
                    None,
                );
            }
        };
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(governed_call_chain_receipt_evidence);

        // The session's enforceable filesystem roots scope the guards below. A
        // parent session that was closed or evicted concurrently (or a poisoned
        // session lock) surfaces here before authoritative admission. The
        // top-level async path is unaffected: it receives
        // session_filesystem_roots as a parameter.
        let session_roots = match self
            .session_enforceable_filesystem_root_paths_owned(&parent_context.session_id)
        {
            Ok(roots) => roots,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "session filesystem roots lookup failed pre-dispatch (nested flow)");
                return self.build_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    std::slice::from_ref(&matched),
                    cap,
                    None,
                );
            }
        };

        let pre_invocation_guard_evidence = match self
            .run_guards_within_budget(
                request,
                &cap.scope,
                Some(session_roots.as_slice()),
                Some(matched_grant_index),
                security_context,
            )
            .await
        {
            Ok(evidence) => evidence,
            Err(e) => {
                let msg = e.error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "guard denied");
                return self.with_pre_invocation_guard_evidence(&e.evidence, || {
                    self.build_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        std::slice::from_ref(&matched),
                        cap,
                        None,
                    )
                });
            }
        };

        let verified_governed_approval = validated_governed_admission
            .as_ref()
            .and_then(|admission| admission.verified_governed_approval.as_ref());
        if verified_governed_approval.is_some() && self.execution_nonce_preflight_required(request)
        {
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_execution_nonce_preflight_allow_response_after_cleanup(
                    request,
                    now,
                    matched_grant_index,
                    cap,
                    &PreExecutionBudgetMutation::None,
                    None,
                    extra_metadata,
                    false,
                )
            });
        }

        let caller_receipt_metadata = extra_metadata.clone();
        let mut _threshold_dispatch_intent_scope = None;
        let (mut runtime_admission_metadata, budget_mutation, mut threshold_dispatch_permit) =
            if let Some(verified_approval) = verified_governed_approval {
                let protocol_admission = self.prepare_threshold_protocol_admission(
                    request,
                    cap,
                    matched_grant_index,
                    now,
                )?;
                let request_fingerprint_hash = self.ordinary_request_fingerprint_hash(
                    request,
                    &self.config.policy_hash,
                    caller_receipt_metadata.as_ref(),
                )?;
                let coordinator_authority_id = format!("kernel:{}", self.public_key().to_hex());
                let prepared =
                    crate::threshold_approval::prepare_governed_tool_admission_operation(
                        crate::threshold_approval::GovernedToolAdmissionOperationInput {
                            coordinator_authority_id: &coordinator_authority_id,
                            request_id: &request.request_id,
                            capability_id: &cap.id,
                            authorization_capability_hash: verified_approval
                                .authorization_capability_hash(),
                            request_fingerprint_hash: &request_fingerprint_hash,
                            governed_intent_hash: verified_approval.governed_intent_hash(),
                            policy_hash: &self.config.policy_hash,
                            verified_approval,
                            broker_attempt_id: protocol_admission.broker_attempt_id(),
                            budget_hold_id: Some(protocol_admission.hold_id()),
                            supplemental_authorization_reference: request
                                .supplemental_authorization
                                .as_ref()
                                .map(chio_core::OpaqueSupplementalAuthorization::reference),
                            supplemental_authorization_digest: protocol_admission
                                .supplemental_digest(),
                            execution_nonce_id: request
                                .execution_nonce
                                .as_ref()
                                .map(crate::execution_nonce::SignedExecutionNonce::nonce_id),
                            coordinator_lease_epoch: 1,
                        },
                    )
                    .map_err(|error| KernelError::GovernedTransactionDenied(error.to_string()))?;
                let runtime_admission = self.run_runtime_admission_hook_for_operation(
                    request,
                    extra_metadata.as_ref(),
                    now,
                    now_unix_ms,
                    Some(matched_grant_index),
                    Some(prepared.operation()),
                );
                let threshold_runtime_metadata = merge_metadata_objects(
                    extra_metadata.clone(),
                    runtime_admission.metadata.clone(),
                );
                if !runtime_admission.allowed {
                    let msg = runtime_admission
                        .reason
                        .unwrap_or_else(|| "runtime admission denied".to_string());
                    let deny_metadata = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            threshold_runtime_metadata,
                        )
                        .0;
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied (nested flow)");
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_runtime_admission_monetary_deny_response_with_metadata(
                                request,
                                &msg,
                                now,
                                std::slice::from_ref(&matched),
                                cap,
                                deny_metadata,
                            )
                        },
                    );
                }
                // Threshold admission may authorize payment while reserving the
                // coordinated operation, so journal the intent before entering
                // that coordinator and keep its request scope alive until the
                // terminal receipt commits.
                let threshold_has_monetary =
                    self.ordinary_payment_charge_terms(matched_grant).is_some()
                        || Self::is_governed_mustprepay_request(request);
                match self.record_dispatch_intent_if_side_effecting(
                    request,
                    threshold_has_monetary,
                    now_unix_ms,
                ) {
                    Ok(Some(handle)) => {
                        _threshold_dispatch_intent_scope =
                            Some(self.scope_dispatch_intent_for_request(
                                &request.request_id,
                                Some(handle),
                            ));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let msg = error.to_string();
                        let deny_metadata = self
                            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                                threshold_runtime_metadata,
                            )
                            .0;
                        warn!(
                            request_id = %request.request_id,
                            reason = %redacted!(&msg),
                            "dispatch intent write failed before threshold admission (nested flow)"
                        );
                        return self.with_pre_invocation_guard_evidence(
                            &pre_invocation_guard_evidence,
                            || {
                                self.build_runtime_admission_monetary_deny_response_with_metadata(
                                    request,
                                    &msg,
                                    now,
                                    std::slice::from_ref(&matched),
                                    cap,
                                    self.merge_budget_receipt_metadata(
                                        deny_metadata,
                                        serde_json::json!({}),
                                    ),
                                )
                            },
                        );
                    }
                }
                let prepared_operation = prepared.operation().clone();
                let reserved = self.reserve_threshold_tool_admission_with_payee_binding(
                    ThresholdToolAdmissionContext {
                        request,
                        cap,
                        grant_index: matched_grant_index,
                        grant: matched_grant,
                        now,
                        payment_mode: ThresholdPaymentMode::Dispatch,
                    },
                    prepared,
                    protocol_admission,
                    None,
                    verified_governed_payee_binding.as_ref(),
                );
                let (permit, mutation) = match reserved {
                    Ok(reserved) => reserved,
                    Err(error) => {
                        let mut deny_metadata = self
                            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                                threshold_runtime_metadata,
                            )
                            .0;
                        if let Some(metadata) = self
                            .exact_compensated_threshold_admission_metadata(&prepared_operation)?
                        {
                            deny_metadata = merge_metadata_objects(deny_metadata, Some(metadata));
                            let msg = error.to_string();
                            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed admission compensated before dispatch (nested flow)");
                            let deny_metadata =
                                self.sanitize_budget_authorization_denial_metadata(deny_metadata);
                            return self.with_pre_invocation_guard_evidence(
                                &pre_invocation_guard_evidence,
                                || {
                                    self.build_deny_response_with_metadata(
                                        request,
                                        "invocation budget authorization denied",
                                        now,
                                        Some(matched_grant_index),
                                        deny_metadata,
                                    )
                                },
                            );
                        }
                        return Err(error);
                    }
                };
                (threshold_runtime_metadata, mutation, Some(permit))
            } else {
                let runtime_admission = self.run_runtime_admission_hook(
                    request,
                    extra_metadata.as_ref(),
                    now,
                    now_unix_ms,
                    Some(matched_grant_index),
                );
                let runtime_admission_metadata = merge_metadata_objects(
                    extra_metadata.clone(),
                    runtime_admission.metadata.clone(),
                );
                if !runtime_admission.allowed {
                    let msg = runtime_admission
                        .reason
                        .unwrap_or_else(|| "runtime admission denied".to_string());
                    let runtime_admission_metadata = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            runtime_admission_metadata,
                        )
                        .0;
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied (nested flow)");
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_runtime_admission_monetary_deny_response_with_metadata(
                                request,
                                &msg,
                                now,
                                std::slice::from_ref(&matched),
                                cap,
                                runtime_admission_metadata,
                            )
                        },
                    );
                }
                let (authorized_grant_index, mutation) = match self.check_and_increment_budget(
                    request,
                    cap,
                    std::slice::from_ref(&matched),
                    false,
                    caller_receipt_metadata.as_ref(),
                ) {
                    Ok(result) => result,
                    Err(error) => {
                        let msg = error.to_string();
                        warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                        let deny_metadata = self
                            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                                runtime_admission_metadata,
                            )
                            .0;
                        let deny_metadata =
                            self.sanitize_budget_authorization_denial_metadata(deny_metadata);
                        return self.with_pre_invocation_guard_evidence(
                            &pre_invocation_guard_evidence,
                            || {
                                self.build_deny_response_with_metadata(
                                    request,
                                    "invocation budget authorization denied",
                                    now,
                                    Some(matched_grant_index),
                                    deny_metadata,
                                )
                            },
                        );
                    }
                };
                if authorized_grant_index != matched_grant_index {
                    return Err(KernelError::Internal(
                        "budget authority admitted a grant other than the validated grant"
                            .to_string(),
                    ));
                }
                (runtime_admission_metadata, mutation, None)
            };
        let authorized_grant_index = matched_grant_index;
        if authorized_grant_index != matched_grant_index {
            return Err(KernelError::Internal(
                "budget authority admitted a grant other than the validated grant".to_string(),
            ));
        }

        // Capture whether THIS evaluation acquired a sibling-sum child-budget
        // holder lease. Every successful `admit_capability_budget` against a
        // parent takes one lease (fresh insert OR idempotent re-admit); a later
        // pre-dispatch cleanup releases exactly this evaluation's lease. The
        // reference-counted release frees the shared edge only when the last
        // holder releases, so an overlapping evaluation that still holds it
        // keeps its share and an oversubscribing sibling stays denied.
        let budget_lease_acquired = if let Some(permit) = threshold_dispatch_permit.as_ref() {
            permit.delegated_budget_lease_acquired()
        } else {
            match self.admit_capability_budget(cap) {
                Ok(lease_acquired) => lease_acquired,
                Err(reason) => {
                    let msg = format!("sibling-sum budget admission failed: {reason}");
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                                request,
                                reason: &msg,
                                timestamp: now,
                                matched_grant_index,
                                cap,
                                budget_mutation: &budget_mutation,
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                payment_authorization: None,
                                runtime_admission_metadata,
                                // Admission failed: this evaluation acquired no
                                // lease, so there is nothing for cleanup to release.
                                budget_lease_acquired: false,
                            })
                        },
                    );
                }
            }
        };

        if self.execution_nonce_preflight_required(request) {
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_execution_nonce_preflight_allow_response_after_cleanup(
                    request,
                    now,
                    matched_grant_index,
                    cap,
                    &budget_mutation,
                    threshold_dispatch_permit
                        .as_ref()
                        .and_then(ThresholdDispatchPermit::payment_authorization),
                    runtime_admission_metadata,
                    budget_lease_acquired,
                )
            });
        }

        // For a side-effecting or monetary call, durably journal a dispatch
        // intent BEFORE the earliest possible effect (the prepaid authorize
        // below, or the nested tool dispatch), exactly as the top-level
        // evaluator does: the crash-window guarantee must hold on every path
        // that can execute a tool. On failure, reverse every pre-execution
        // hold through the same pre-dispatch unwind the admission and
        // authorize arms use, then deny before any effect. Read-only calls
        // return None here and pay nothing.
        let has_monetary = budget_mutation.charge_result().is_some()
            || Self::is_governed_mustprepay_request(request);
        let _ordinary_dispatch_intent_scope = if threshold_dispatch_permit.is_none() {
            let dispatch_intent = match self.record_dispatch_intent_if_side_effecting(
                request,
                has_monetary,
                now_unix_ms,
            ) {
                Ok(handle) => handle,
                Err(error) => {
                    let msg = error.to_string();
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&msg),
                        "dispatch intent write failed; denying before dispatch (nested flow)"
                    );
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                                request,
                                reason: &msg,
                                timestamp: now,
                                matched_grant_index,
                                cap,
                                budget_mutation: &budget_mutation,
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                payment_authorization: None,
                                runtime_admission_metadata: runtime_admission_metadata.clone(),
                                budget_lease_acquired,
                            })
                        },
                    );
                }
            };
            Some(self.scope_dispatch_intent_for_request(&request.request_id, dispatch_intent))
        } else {
            None
        };

        if !self.tool_servers.contains_key(&request.server_id) {
            let reason = KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
            .to_string();
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &reason,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    runtime_admission_metadata: runtime_admission_metadata.clone(),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        }

        let credential_reservation_result = if budget_mutation.ordinary_admission().is_some()
            || threshold_dispatch_permit.is_some()
        {
            self.reserve_caller_authorization_credentials(request, cap, dpop_required, now, false)
        } else {
            self.reserve_dispatch_credentials(request, cap, dpop_required, now)
        };
        let mut credential_reservation = match credential_reservation_result {
            Ok(reservation) => reservation,
            Err(error) => {
                let reason = error.to_string();
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason: &reason,
                            timestamp: current_unix_timestamp(),
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            runtime_admission_metadata: runtime_admission_metadata.clone(),
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        };
        let force_dispatch_revalidation =
            credential_reservation.requires_post_reservation_revalidation();
        let revalidation_now_unix_ms = current_unix_timestamp_ms();
        let readiness_result = {
            let mut readiness_drop_guard = PostAdmissionDropGuard::new(
                self,
                request,
                cap,
                Some(matched_grant_index),
                &budget_mutation,
                None,
                PostAdmissionReceiptContext {
                    extra_metadata: runtime_admission_metadata.clone(),
                    pre_invocation_guard_evidence: pre_invocation_guard_evidence.clone(),
                    verified_payee_binding: verified_governed_payee_binding.clone(),
                },
                budget_lease_acquired,
            );
            let result = self
                .wait_for_runtime_admission_dispatch_readiness(request)
                .await;
            readiness_drop_guard.disarm();
            result
        };
        let final_dispatch_admission = match readiness_result {
            Ok(readiness_waited) => self.revalidate_immediately_before_dispatch(
                request,
                dpop_required,
                matched_grant,
                matched_grant_index,
                Some(parent_context),
                Some(&parent_context.session_id),
                Some(session_roots.as_slice()),
                security_context,
                &receipt_admission,
                runtime_admission_metadata.as_ref(),
                false,
                readiness_waited || force_dispatch_revalidation,
                revalidation_now_unix_ms / 1000,
                revalidation_now_unix_ms,
            ),
            Err(error) => Err(error),
        };
        if let Err(error) = final_dispatch_admission {
            let mut reason = dispatch_admission_error_reason(&error);
            let credential_disposition = match credential_reservation.rollback_before_dispatch() {
                Ok(()) => PaymentCredentialDisposition::NonePresent,
                Err(rollback_error) => {
                    reason = format!("{reason}; {rollback_error}");
                    PaymentCredentialDisposition::RetentionOutcomeUnknown
                }
            };
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                    PreDispatchCleanupDeny {
                        request,
                        reason: &reason,
                        timestamp: revalidation_now_unix_ms / 1000,
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        payment_authorization: None,
                        runtime_admission_metadata: runtime_admission_metadata.clone(),
                        verified_payee_binding: verified_governed_payee_binding.as_ref(),
                        budget_lease_acquired,
                    },
                    credential_disposition,
                )
            });
        }

        let payment_authorization = if let Some(permit) = threshold_dispatch_permit.as_ref() {
            permit.payment_authorization().cloned()
        } else {
            match self.authorize_payment_if_needed(
                request,
                budget_mutation.charge_result(),
                budget_mutation.admission_operation_binding(),
                verified_governed_payee_binding.as_ref(),
            ) {
                Ok(authorization) => authorization,
                Err(error) => {
                    let msg = format!("payment authorization failed: {error}");
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "payment denied");
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                                request,
                                reason: &msg,
                                timestamp: now,
                                matched_grant_index,
                                cap,
                                budget_mutation: &budget_mutation,
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                payment_authorization: None,
                                runtime_admission_metadata: runtime_admission_metadata.clone(),
                                budget_lease_acquired,
                            })
                        },
                    );
                }
            }
        };

        if payment_authorization.is_some() {
            if let Err(error) = credential_reservation.retain_after_external_authorization() {
                let reason = format!(
                    "dispatch credential retention failed after payment authorization: {error}"
                );
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                            PreDispatchCleanupDeny {
                                request,
                                reason: &reason,
                                timestamp: current_unix_timestamp(),
                                matched_grant_index,
                                cap,
                                budget_mutation: &budget_mutation,
                                payment_authorization: payment_authorization.as_ref(),
                                runtime_admission_metadata: runtime_admission_metadata.clone(),
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                budget_lease_acquired,
                            },
                            PaymentCredentialDisposition::RetentionOutcomeUnknown,
                        )
                    },
                );
            }
        }

        // Money path: bind the rail's authorization id to the open intent so
        // a monetary orphan names the exact reference an operator reconciles
        // against. Best-effort and bounded: the open intent already proves a
        // monetary attempt through its rail column, so a failed or timed-out
        // attach is logged and never fails the call.
        if let Some(authorization) = payment_authorization.as_ref() {
            if let Some(handle) = self.dispatch_intent_for_request(Some(&request.request_id)) {
                let budget = self.config.deadlines.receipt_append_budget();
                if let Err(error) = self.with_receipt_store(|store| {
                    Ok(store.attach_dispatch_intent_rail_ref_with_timeout(
                        &handle.request_id,
                        handle.tenant_id.as_deref(),
                        &authorization.authorization_id,
                        budget,
                    )?)
                }) {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&error.to_string()),
                        "dispatch intent rail-ref attach failed (nested flow)"
                    );
                }
            }
        }

        if threshold_dispatch_permit.is_none() {
            let nonce_result = match budget_mutation.ordinary_admission() {
                Some(admission) => self.reserve_presented_execution_nonce_for_operation(
                    request,
                    cap,
                    admission.operation_id(),
                ),
                None => Ok(()),
            };
            if let Err(error) = nonce_result {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "execution nonce denied");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason: &msg,
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            payment_authorization: payment_authorization.as_ref(),
                            runtime_admission_metadata: runtime_admission_metadata.clone(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        }

        // The kernel-local tool-server lookup is hoisted above the drop guard
        // and connector entry. Its failure proves that no connector code ran,
        // so this is the only ToolNotRegistered path eligible for full reversal.
        let Some(server) = self.tool_servers.get(&request.server_id) else {
            let error = KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ));
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
            // ToolNotRegistered precedes any tool side effect, and no drop guard
            // is armed yet, so this arm owns the full unwind. Reverse ALL
            // pre-dispatch state (runtime-admission reservations, sibling-sum
            // capability admission, and the pre-execution budget mutation) so a
            // server that vanished between admission and lookup does not leak the
            // consumed child share / invocation slot onto later valid siblings.
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &msg,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    payment_authorization: payment_authorization.as_ref(),
                    runtime_admission_metadata,
                    budget_lease_acquired,
                })
            });
        };

        if payment_authorization.is_some() {
            let post_payment_now_unix_ms = current_unix_timestamp_ms();
            if let Err(error) = self.revalidate_immediately_before_dispatch(
                request,
                dpop_required,
                matched_grant,
                matched_grant_index,
                Some(parent_context),
                Some(&parent_context.session_id),
                Some(session_roots.as_slice()),
                security_context,
                &receipt_admission,
                runtime_admission_metadata.as_ref(),
                false,
                force_dispatch_revalidation,
                post_payment_now_unix_ms / 1000,
                post_payment_now_unix_ms,
            ) {
                let reason = dispatch_admission_error_reason(&error);
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                            PreDispatchCleanupDeny {
                                request,
                                reason: &reason,
                                timestamp: post_payment_now_unix_ms / 1000,
                                matched_grant_index,
                                cap,
                                budget_mutation: &budget_mutation,
                                payment_authorization: payment_authorization.as_ref(),
                                runtime_admission_metadata: runtime_admission_metadata.clone(),
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                budget_lease_acquired,
                            },
                            PaymentCredentialDisposition::RetainedAfterAuthorization,
                        )
                    },
                );
            }
        }

        if let Err(error) = self.mark_session_request_dispatch_started(
            Some(&parent_context.session_id),
            parent_context.request_id.as_str(),
        ) {
            let reason = error.to_string();
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                    PreDispatchCleanupDeny {
                        request,
                        reason: &reason,
                        timestamp: current_unix_timestamp(),
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        payment_authorization: payment_authorization.as_ref(),
                        runtime_admission_metadata: runtime_admission_metadata.clone(),
                        verified_payee_binding: verified_governed_payee_binding.as_ref(),
                        budget_lease_acquired,
                    },
                    if payment_authorization.is_some() {
                        PaymentCredentialDisposition::RetainedAfterAuthorization
                    } else {
                        PaymentCredentialDisposition::NonePresent
                    },
                )
            });
        }

        if let Err(error) = credential_reservation.retain_if_dropped() {
            let reason = format!("dispatch credential retention failed before dispatch: {error}");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                    PreDispatchCleanupDeny {
                        request,
                        reason: &reason,
                        timestamp: current_unix_timestamp(),
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        payment_authorization: payment_authorization.as_ref(),
                        runtime_admission_metadata: runtime_admission_metadata.clone(),
                        verified_payee_binding: verified_governed_payee_binding.as_ref(),
                        budget_lease_acquired,
                    },
                    PaymentCredentialDisposition::RetentionOutcomeUnknown,
                )
            });
        }
        let mut security_pre_dispatch = match self
            .run_security_pre_dispatch_hook(request, security_context)
        {
            Ok(outcome) => outcome,
            Err(denial) => {
                let mut denial_evidence = pre_invocation_guard_evidence.clone();
                denial_evidence.push(denial.evidence);
                let msg = denial.reason;
                warn!(request_id = %request.request_id, reason = msg, "security pre-dispatch denied");
                return self.with_pre_invocation_guard_evidence(&denial_evidence, || {
                    self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                        request,
                        reason: msg,
                        timestamp: now,
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        verified_payee_binding: verified_governed_payee_binding.as_ref(),
                        payment_authorization: payment_authorization.as_ref(),
                        runtime_admission_metadata,
                        budget_lease_acquired,
                    })
                });
            }
        };
        let mut security_dispatch_outcome = security_pre_dispatch.dispatch_outcome.take();
        let security_request_lifecycle = security_pre_dispatch.request_lifecycle.take();
        if let Some(permit) = threshold_dispatch_permit.as_mut() {
            match self.commit_reserved_threshold_protocol_dispatch(
                permit,
                request,
                cap,
                &budget_mutation,
            ) {
                Ok(metadata) => {
                    runtime_admission_metadata =
                        merge_metadata_objects(runtime_admission_metadata, Some(metadata));
                }
                Err(error) => {
                    let operation_metadata =
                        self.refresh_threshold_dispatch_permit_metadata(permit)?;
                    runtime_admission_metadata = merge_metadata_objects(
                        runtime_admission_metadata,
                        Some(operation_metadata),
                    );
                    if permit.operation().state()
                        == AdmissionOperationState::CompensatedBeforeDispatch
                    {
                        runtime_admission_metadata = self
                            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                                runtime_admission_metadata,
                            )
                            .0;
                    }
                    let msg = error.to_string();
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "threshold protocol admission capture denied");
                    let outcome_result = security_dispatch_outcome
                        .take()
                        .map(SecurityDispatchOutcomeHandle::record_dispatch_failed)
                        .transpose();
                    let response = self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_deny_response_with_metadata(
                                request,
                                &msg,
                                now,
                                Some(matched_grant_index),
                                runtime_admission_metadata.clone(),
                            )
                        },
                    );
                    outcome_result?;
                    return response;
                }
            }
        } else if let Some(admission) = budget_mutation.ordinary_admission() {
            match self.commit_ordinary_protocol_dispatch(cap, admission) {
                Ok(metadata) => {
                    runtime_admission_metadata =
                        merge_metadata_objects(runtime_admission_metadata, Some(metadata));
                }
                Err(error) => {
                    let preserve_captured_admission =
                        matches!(&error, KernelError::BudgetCaptureRecoveryRequired(_));
                    let msg = error.to_string();
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "protocol admission capture denied");
                    let outcome_result = security_dispatch_outcome
                        .take()
                        .map(SecurityDispatchOutcomeHandle::record_dispatch_failed)
                        .transpose();
                    let response = self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            if preserve_captured_admission {
                                self.build_deny_response_with_metadata(
                                    request,
                                    &msg,
                                    now,
                                    Some(matched_grant_index),
                                    runtime_admission_metadata.clone(),
                                )
                            } else {
                                self.build_pre_dispatch_cleanup_deny_response(
                                    PreDispatchCleanupDeny {
                                        request,
                                        reason: &msg,
                                        timestamp: now,
                                        matched_grant_index,
                                        cap,
                                        budget_mutation: &budget_mutation,
                                        verified_payee_binding: verified_governed_payee_binding
                                            .as_ref(),
                                        payment_authorization: payment_authorization.as_ref(),
                                        runtime_admission_metadata: runtime_admission_metadata
                                            .clone(),
                                        budget_lease_acquired,
                                    },
                                )
                            }
                        },
                    );
                    outcome_result?;
                    return response;
                }
            }
        }
        let tool_started_at = Instant::now();
        let mut post_admission_drop_guard = PostAdmissionDropGuard::new(
            self,
            request,
            cap,
            Some(matched_grant_index),
            &budget_mutation,
            payment_authorization.as_ref(),
            PostAdmissionReceiptContext {
                extra_metadata: runtime_admission_metadata.clone(),
                pre_invocation_guard_evidence: pre_invocation_guard_evidence.clone(),
                verified_payee_binding: verified_governed_payee_binding.clone(),
            },
            budget_lease_acquired,
        );
        if let Some(permit) = threshold_dispatch_permit.as_ref() {
            post_admission_drop_guard.bind_threshold_operation(permit.operation().clone());
        }
        post_admission_drop_guard.bind_security_dispatch_outcome(security_dispatch_outcome.take());
        // Mark dispatch started before lending the child-receipt buffer to the
        // bridge: the bridge borrows the guard for the whole dispatch block, so
        // the `&mut self` call must happen first. There is no await between here
        // and the invoke below, so the future cannot be dropped in this window.
        post_admission_drop_guard.mark_dispatch_started();
        let nested_interaction_observed = std::sync::atomic::AtomicBool::new(false);
        let dispatch_call = async {
            let mut bridge = SessionNestedFlowBridge {
                sessions: &self.sessions,
                child_receipts: post_admission_drop_guard.child_receipts_mut(),
                nested_interaction_observed: &nested_interaction_observed,
                parent_context,
                allow_sampling: self.config.allow_sampling,
                allow_sampling_tool_use: self.config.allow_sampling_tool_use,
                allow_elicitation: self.config.allow_elicitation,
                policy_hash: &self.config.policy_hash,
                authority_signing_backend: self.authority_signing_backend.as_ref(),
                client,
            };

            match server
                .invoke_stream(
                    &request.tool_name,
                    request.arguments.clone(),
                    Some(&mut bridge),
                )
                .await
            {
                Ok(Some(stream)) => Ok(ToolServerOutput::Stream(stream)),
                Ok(None) => server
                    .invoke(
                        &request.tool_name,
                        request.arguments.clone(),
                        Some(&mut bridge),
                    )
                    .await
                    .map(ToolServerOutput::Value),
                Err(error) => Err(error),
            }
        };
        // Bound the nested tool-server call by the dispatch budget on the same
        // hot path the top-level dispatch enforces, so a blocking nested
        // `invoke_stream`/`invoke` cannot slip past the deadline. The shared
        // helper isolates a connection that blocks synchronously before its
        // first `.await` from the async worker pool via `block_in_place` (the
        // nested-flow bridge borrows the caller's client and session state, so
        // the future cannot be moved onto `spawn_blocking` like the top-level
        // path). On expiry the buffered child receipts recorded so far are still
        // persisted below, and the abort arm unwinds like a cancellation.
        let tool_output_result = match self
            .config
            .deadlines
            .dispatch_budget_for(&request.server_id)
        {
            Some(budget) => {
                crate::kernel::dispatch::dispatch_nested_call_within_budget(dispatch_call, budget)
                    .await
            }
            None => dispatch_call.await,
        };
        let nested_interaction_observed =
            nested_interaction_observed.load(std::sync::atomic::Ordering::Acquire);
        // Persist the buffered child receipts while the guard is still armed,
        // draining each from the guard only once it durably lands. If the commit
        // writer is saturated and a bounded append times out, the `?` returns
        // with the guard armed and dispatch marked started, so its drop runs the
        // post-dispatch abort cleanup: flush the child receipts that had not yet
        // persisted, reverse the pre-execution monetary hold, retain the runtime
        // reservations fail-closed, and record a signed cancellation receipt.
        // Because the guard keeps the not-yet-persisted receipts, a mid-flush
        // append failure cannot lose an already-signed child receipt; recording
        // through a drained buffer would instead drop it. On success the guard is
        // disarmed with an empty buffer, so the disarmed drop flushes nothing and
        // no receipt is double-recorded.
        post_admission_drop_guard.record_buffered_child_receipts()?;
        let tool_output_result = match tool_output_result {
            Err(error @ KernelError::UrlElicitationsRequired { .. })
                if !nested_interaction_observed =>
            {
                security_dispatch_outcome =
                    post_admission_drop_guard.take_security_dispatch_outcome();
                post_admission_drop_guard.disarm();
                drop(post_admission_drop_guard);
                let security_outcome_error = security_dispatch_outcome
                    .take()
                    .map(SecurityDispatchOutcomeHandle::record_dispatch_failed)
                    .transpose()
                    .err();
                let credential_cleanup = if payment_authorization.is_some() {
                    credential_reservation
                        .commit()
                        .map(|_| PaymentCredentialDisposition::RetainedAfterAuthorization)
                } else {
                    credential_reservation
                        .rollback_before_dispatch()
                        .map(|()| PaymentCredentialDisposition::NonePresent)
                };
                let (credential_disposition, credential_cleanup_error) = match credential_cleanup {
                    Ok(disposition) => (disposition, None),
                    Err(cleanup_error) => {
                        warn!(
                            request_id = %request.request_id,
                            reason = %redacted!(&cleanup_error),
                            audit_fault = "url_elicitation_credential_cleanup_unconfirmed",
                            "nested URL-elicitation credential cleanup could not be confirmed"
                        );
                        (
                            PaymentCredentialDisposition::RetentionOutcomeUnknown,
                            Some(cleanup_error.to_string()),
                        )
                    }
                };
                let cleanup_reason = [
                    credential_cleanup_error.as_ref().map(|cleanup_error| {
                        format!(
                            "dispatch credential cleanup could not be confirmed: {cleanup_error}"
                        )
                    }),
                    security_outcome_error.as_ref().map(|outcome_error| {
                        format!("security dispatch outcome could not be recorded: {outcome_error}")
                    }),
                ]
                .into_iter()
                .flatten()
                .fold(
                    "tool server requested URL elicitation before execution".to_string(),
                    |reason, fault| format!("{reason}; {fault}"),
                );
                let cleanup_denial = PreDispatchCleanupDeny {
                    request,
                    reason: &cleanup_reason,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: payment_authorization.as_ref(),
                    runtime_admission_metadata: runtime_admission_metadata.clone(),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                };
                let cleanup_requires_receipt = payment_authorization.is_some()
                    || !reserved_runtime_admission_ids(runtime_admission_metadata.as_ref())
                        .is_empty()
                    || credential_cleanup_error.is_some()
                    || security_outcome_error.is_some();
                if cleanup_requires_receipt {
                    let cleanup = self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                                cleanup_denial,
                                credential_disposition,
                            )
                        },
                    );
                    if credential_cleanup_error.is_some() {
                        return cleanup;
                    }
                    if let Some(outcome_error) = security_outcome_error {
                        return match cleanup {
                            Ok(_) => Err(outcome_error),
                            Err(cleanup_error) => {
                                Err(KernelError::SecurityDispatchOutcomeRecoveryRequired(
                                    format!(
                                        "{outcome_error}; URL-elicitation cleanup failed: {cleanup_error}"
                                    ),
                                ))
                            }
                        };
                    }
                    if let Err(cleanup_error) = cleanup {
                        warn!(
                            request_id = %request.request_id,
                            reason = %redacted!(&cleanup_error),
                            audit_fault = "url_elicitation_cleanup_unrecorded",
                            "nested URL-elicitation cleanup could not be confirmed"
                        );
                    }
                } else if let Err(cleanup_error) = self
                    .unwind_url_elicitation_before_effect(cleanup_denial, credential_disposition)
                {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&cleanup_error),
                        audit_fault = "url_elicitation_cleanup_unrecorded",
                        "nested URL-elicitation cleanup could not be confirmed"
                    );
                }
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            result => result,
        };
        security_dispatch_outcome = post_admission_drop_guard.take_security_dispatch_outcome();
        if let Err(error) = credential_reservation.commit() {
            post_admission_drop_guard.mark_dispatch_credential_commit_failed();
            return Err(error);
        }
        post_admission_drop_guard.disarm();
        drop(post_admission_drop_guard);
        let security_dispatch_outcome_error = security_dispatch_outcome
            .take()
            .map(|outcome| match &tool_output_result {
                Ok(ToolServerOutput::Value(_))
                | Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(_))) => {
                    outcome.record_released()
                }
                Ok(ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { .. }))
                | Err(_) => outcome.record_outcome_unknown_after_dispatch(),
            })
            .transpose()
            .err();
        if let Some(outcome_error) = security_dispatch_outcome_error {
            return Err(self.recover_security_dispatch_outcome_persistence_failure(
                SecurityDispatchOutcomeRecovery {
                    request,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: payment_authorization.as_ref(),
                    threshold_operation: threshold_dispatch_permit
                        .as_ref()
                        .map(ThresholdDispatchPermit::operation),
                    outcome_error,
                    secondary_faults: Vec::new(),
                },
            ));
        }
        let terminal_operation = if let Some(permit) = threshold_dispatch_permit.as_ref() {
            Some(permit.operation().clone())
        } else if let Some(admission) = budget_mutation.ordinary_admission() {
            Some(self.load_ordinary_admission(admission.operation_id())?)
        } else {
            None
        };
        let _terminal_receipt_scope = if let Some(operation) = terminal_operation.as_ref() {
            let (terminal_state, terminal_dispatch_state, terminal_last_error) =
                match &tool_output_result {
                    Ok(ToolServerOutput::Value(_))
                    | Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(_))) => (
                        AdmissionOperationState::Completed,
                        AdmissionDispatchState::EffectCompleted,
                        None,
                    ),
                    Ok(ToolServerOutput::Stream(ToolServerStreamResult::Incomplete {
                        reason,
                        ..
                    })) => (
                        AdmissionOperationState::OutcomeUnknownAfterDispatch,
                        AdmissionDispatchState::OutcomeUnknown,
                        Some(reason.clone()),
                    ),
                    Err(error) => (
                        AdmissionOperationState::OutcomeUnknownAfterDispatch,
                        AdmissionDispatchState::OutcomeUnknown,
                        Some(error.to_string()),
                    ),
                };
            let (metadata, scope) = self.scope_threshold_terminal_receipt_outbox(
                request,
                operation,
                terminal_state,
                terminal_dispatch_state,
                terminal_last_error,
            )?;
            runtime_admission_metadata =
                merge_metadata_objects(runtime_admission_metadata, Some(metadata));
            Some(scope)
        } else {
            None
        };
        let tool_output = match tool_output_result {
            Ok(output) => output,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                let reason =
                    format!("URL elicitation requested after a nested interaction: {error}");
                let metadata = self.ambiguous_dispatch_receipt_metadata(
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    runtime_admission_metadata.clone(),
                );
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_incomplete_response_with_output_metadata_and_payee_binding(
                            request,
                            None,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            metadata,
                            verified_governed_payee_binding.as_ref(),
                        )
                    },
                );
            }
            Err(KernelError::RequestCancelled { request_id, reason }) => {
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let cleanup_metadata = self.post_dispatch_cleanup_receipt_metadata(
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                )?;
                if request_id == parent_context.request_id {
                    self.with_session_mut(&parent_context.session_id, |session| {
                        session.request_cancellation(&parent_context.request_id)?;
                        Ok(())
                    })?;
                }
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call cancelled"
                );
                let response =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        self.build_cancelled_response_with_metadata(
                            request,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            self.mark_runtime_admission_reservations_retained_fail_closed(
                                cleanup_metadata.clone(),
                            ),
                        )
                    });
                return response;
            }
            Err(KernelError::HotPathDeadlineExceeded { stage, budget_ms }) => {
                let reason = format!("hot-path deadline exceeded at {stage}: budget {budget_ms}ms");
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let cleanup_metadata = self.post_dispatch_cleanup_receipt_metadata(
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call deadline expired"
                );
                // A timed-out dispatch may already have applied its side effect,
                // so the runtime-admission reservation is retained and marked
                // auditable rather than released.
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_cancelled_response_with_metadata(
                            request,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            self.mark_runtime_admission_reservations_retained_fail_closed(
                                cleanup_metadata.clone(),
                            ),
                        )
                    },
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let cleanup_metadata = self.post_dispatch_cleanup_receipt_metadata(
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call incomplete"
                );
                let response =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        self.build_incomplete_response_with_output_and_metadata(
                            request,
                            None,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            self.mark_runtime_admission_reservations_retained_fail_closed(
                                cleanup_metadata.clone(),
                            ),
                        )
                    });
                return response;
            }
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                // A tool side effect may have executed: retain the runtime
                // admission reservations and invocation usage (fail-closed),
                // while releasing payment and monetary exposure.
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let cleanup_metadata = self.post_dispatch_cleanup_receipt_metadata(
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                )?;
                let response =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        let deny_metadata = self
                            .mark_runtime_admission_reservations_retained_fail_closed(
                                cleanup_metadata.clone(),
                            );
                        self.build_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            Some(matched_grant_index),
                            deny_metadata,
                        )
                    });
                return response;
            }
        };
        let response =
            self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.finalize_budgeted_tool_output_with_cost_and_metadata(
                    request,
                    tool_output,
                    tool_started_at.elapsed(),
                    now,
                    matched_grant_index,
                    FinalizeToolOutputCostContext {
                        charge_result: budget_mutation.charge_result().cloned(),
                        admission_operation: budget_mutation.admission_operation_binding().cloned(),
                        reported_cost: None,
                        payment_authorization,
                        verified_payee_binding: verified_governed_payee_binding.as_ref(),
                        cap,
                    },
                    security_context,
                    runtime_admission_metadata,
                )
            });
        match response {
            Ok(response) => {
                if let Some(permit) = security_request_lifecycle {
                    permit.ensure_final_release()?;
                }
                Ok(response)
            }
            Err(error) => Err(error),
        }
    }
}
