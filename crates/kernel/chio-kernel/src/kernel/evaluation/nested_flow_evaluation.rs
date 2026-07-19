use super::evaluation_helpers::{PreDispatchCleanupDeny, SecurityDispatchOutcomeRecovery};
use super::*;
use crate::kernel::admission_coordinator::{
    ThresholdDispatchPermit, ThresholdToolAdmissionContext,
};

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
        let _receipt_federation_scope = scope_receipt_federation_admission(Some(receipt_admission));

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

        if let Err(e) = self.check_revocation(cap) {
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
        if matching_grants
            .iter()
            .any(|m| m.grant.dpop_required == Some(true))
        {
            if let Err(e) = self.verify_dpop_for_request(request, cap) {
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

        if let Err(error) =
            self.record_observed_capability_snapshot_for_dispatch(cap, security_context)
        {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            return self.build_deny_response(request, &msg, now, None);
        }

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

        let pre_invocation_guard_evidence = match self.run_guards(
            request,
            &cap.scope,
            Some(session_roots.as_slice()),
            Some(matched_grant_index),
            security_context,
        ) {
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

        let (mut runtime_admission_metadata, budget_mutation, mut threshold_dispatch_permit) =
            if let Some(verified_approval) = verified_governed_approval {
                let protocol_admission = self.prepare_threshold_protocol_admission(
                    request,
                    cap,
                    matched_grant_index,
                    now,
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
                            arguments: &request.arguments,
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
                        );
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
                let prepared_operation = prepared.operation().clone();
                let reserved = self.reserve_threshold_tool_admission(
                    ThresholdToolAdmissionContext {
                        request,
                        cap,
                        grant_index: matched_grant_index,
                        grant: matched_grant,
                        now,
                    },
                    prepared,
                    protocol_admission,
                );
                let (permit, mutation) = match reserved {
                    Ok(reserved) => reserved,
                    Err(error) => {
                        let mut deny_metadata = self
                            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                                threshold_runtime_metadata,
                            );
                        if let Some(metadata) = self
                            .exact_compensated_threshold_admission_metadata(&prepared_operation)?
                        {
                            deny_metadata = merge_metadata_objects(deny_metadata, Some(metadata));
                            let msg = error.to_string();
                            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed admission compensated before dispatch (nested flow)");
                            return self.with_pre_invocation_guard_evidence(
                                &pre_invocation_guard_evidence,
                                || {
                                    self.build_monetary_deny_response_with_metadata(
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
                ) {
                    Ok(result) => result,
                    Err(error) => {
                        let msg = error.to_string();
                        warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                        let deny_metadata = self
                            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                                runtime_admission_metadata,
                            );
                        return self.with_pre_invocation_guard_evidence(
                            &pre_invocation_guard_evidence,
                            || {
                                self.build_monetary_deny_response_with_metadata(
                                    request,
                                    &msg,
                                    now,
                                    std::slice::from_ref(&matched),
                                    cap,
                                    self.merge_budget_receipt_metadata(
                                        deny_metadata,
                                        self.budget_backend_receipt_metadata()?,
                                    ),
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

        let payment_authorization = if let Some(permit) = threshold_dispatch_permit.as_ref() {
            permit.payment_authorization().cloned()
        } else {
            match self.authorize_payment_if_needed(request, budget_mutation.charge_result()) {
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
                                payment_authorization: None,
                                runtime_admission_metadata,
                                budget_lease_acquired,
                            })
                        },
                    );
                }
            }
        };

        if threshold_dispatch_permit.is_none() {
            let nonce_result = match budget_mutation.ordinary_admission() {
                Some(admission) => self.reserve_presented_execution_nonce_for_operation(
                    request,
                    cap,
                    admission.operation_id(),
                ),
                None => self.require_presented_execution_nonce(request, cap),
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
                            payment_authorization: payment_authorization.as_ref(),
                            runtime_admission_metadata,
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
                    payment_authorization: payment_authorization.as_ref(),
                    runtime_admission_metadata,
                    budget_lease_acquired,
                })
            });
        };
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
                            );
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
        let tool_output_result = {
            let mut bridge = SessionNestedFlowBridge {
                sessions: &self.sessions,
                child_receipts: post_admission_drop_guard.child_receipts_mut(),
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
        security_dispatch_outcome = post_admission_drop_guard.take_security_dispatch_outcome();
        post_admission_drop_guard.disarm();
        // Take the buffered child receipts out of the guard before dropping it.
        // The guard is now disarmed AND holds an empty buffer, so its Drop
        // records nothing and the receipts cannot be double-recorded.
        let child_receipts = post_admission_drop_guard.take_child_receipts();
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
        let child_receipt_error = self.record_child_receipts(child_receipts).err();
        if let Some(outcome_error) = security_dispatch_outcome_error {
            let secondary_faults = child_receipt_error
                .as_ref()
                .map(|error| vec![format!("signed child receipt persistence failed: {error}")])
                .unwrap_or_default();
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
                    secondary_faults,
                },
            ));
        }
        if let Some(error) = child_receipt_error {
            // The parent operation remains DispatchCommitted. Without a
            // signed parent terminal receipt, recovery must reconcile rather
            // than manufacture a terminal projection from the child append
            // failure.
            return Err(error);
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
                // Connector code was entered before this error was returned, so
                // the variant is not proof that no side effect occurred. Retain
                // invocation usage and fail-closed runtime/delegation leases,
                // while releasing only payment and monetary exposure. Preserve
                // the UrlElicitationsRequired return shape for edge handling.
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let metadata = self.post_dispatch_cleanup_receipt_metadata(
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                );
                self.record_url_elicitation_post_dispatch_receipt(
                    request,
                    &error.to_string(),
                    now,
                    matched_grant_index,
                    metadata,
                    &pre_invocation_guard_evidence,
                );
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            Err(KernelError::RequestCancelled { request_id, reason }) => {
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let cleanup_metadata = self.post_dispatch_cleanup_receipt_metadata(
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                );
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
            Err(KernelError::RequestIncomplete(reason)) => {
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let cleanup_metadata = self.post_dispatch_cleanup_receipt_metadata(
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                );
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
                    budget_mutation.charge_result(),
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let cleanup_metadata = self.post_dispatch_cleanup_receipt_metadata(
                    runtime_admission_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                );
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
                        reported_cost: None,
                        payment_authorization,
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
