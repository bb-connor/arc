use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;
use crate::budget_store::BudgetInvocationCaptureDecision;

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

    pub(crate) async fn evaluate_tool_call_with_nested_flow_client_async<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        // Install the parent session's tenant_id so every
        // receipt signed while this nested-flow evaluation is in flight
        // carries the correct tenant tag.
        let tenant_id = self.resolve_tenant_id_for_session(Some(&parent_context.session_id));
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
        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            return self.build_deny_response(request, &msg, now, None);
        }

        let (matched_grant_index, mut budget_mutation) = match self.check_and_increment_budget(
            &request.request_id,
            cap,
            &matching_grants,
            self.execution_nonce_preflight_required(request),
        ) {
            Ok(result) => result,
            Err(e) => {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                return self.build_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    &matching_grants,
                    cap,
                    Some(self.budget_backend_receipt_metadata()?),
                );
            }
        };

        let matched_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .map(|matching| matching.grant)
            .ok_or_else(|| {
                KernelError::Internal(format!(
                    "matched grant index {matched_grant_index} missing from candidate set"
                ))
            })?;

        let validated_governed_admission = match self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            budget_mutation.charge_result(),
            Some(parent_context),
            now,
        ) {
            Ok(validated_governed_admission) => validated_governed_admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed transaction denied");
                let reverse = self.reverse_pre_execution_budget_mutation(cap, &budget_mutation)?;
                if let (Some(charge), Some(reverse)) =
                    (budget_mutation.charge_result(), reverse.as_ref())
                {
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        Some(self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", reverse)),
                        )),
                    );
                }
                return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
            }
        };
        let _governed_runtime_attestation_receipt_scope =
            scope_governed_runtime_attestation_receipt_record(
                validated_governed_admission
                    .as_ref()
                    .and_then(|admission| admission.verified_runtime_attestation.clone()),
            );
        // A receipt-store read error while resolving the parent call-chain
        // receipt fails closed, but check_and_increment_budget above already
        // consumed the pre-execution budget (invocation count / monetary hold).
        // Route the error through the same reversal + deny path the governed and
        // guard denial branches use so a transient store failure never burns
        // quota or holds funds for a call that never dispatches.
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
                let reverse = self.reverse_pre_execution_budget_mutation(cap, &budget_mutation)?;
                if let (Some(charge), Some(reverse)) =
                    (budget_mutation.charge_result(), reverse.as_ref())
                {
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        Some(self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", reverse)),
                        )),
                    );
                }
                return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
            }
        };
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(governed_call_chain_receipt_evidence);

        // The session's enforceable filesystem roots scope the guards below. A
        // parent session that was closed or evicted concurrently (or a poisoned
        // session lock) surfaces here as an error, but check_and_increment_budget
        // above already consumed the pre-execution budget (invocation count /
        // monetary hold). Route the error through the same reversal + deny path
        // the governed, call-chain, and guard denial branches use so a transient
        // session-lookup failure never burns quota or holds funds for a call that
        // never dispatches. The top-level async path is unaffected: it receives
        // session_filesystem_roots as a parameter.
        let session_roots = match self
            .session_enforceable_filesystem_root_paths_owned(&parent_context.session_id)
        {
            Ok(roots) => roots,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "session filesystem roots lookup failed pre-dispatch (nested flow)");
                let reverse = self.reverse_pre_execution_budget_mutation(cap, &budget_mutation)?;
                if let (Some(charge), Some(reverse)) =
                    (budget_mutation.charge_result(), reverse.as_ref())
                {
                    return self.build_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        Some(self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", reverse)),
                        )),
                    );
                }
                return self.build_deny_response(request, &msg, now, Some(matched_grant_index));
            }
        };

        let pre_invocation_guard_evidence = match self
            .run_guards_within_budget(
                request,
                &cap.scope,
                Some(session_roots.as_slice()),
                Some(matched_grant_index),
            )
            .await
        {
            Ok(evidence) => evidence,
            Err(e) => {
                let msg = e.error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "guard denied");
                let reverse = self.reverse_pre_execution_budget_mutation(cap, &budget_mutation)?;
                if let (Some(charge), Some(reverse)) =
                    (budget_mutation.charge_result(), reverse.as_ref())
                {
                    return self.with_pre_invocation_guard_evidence(&e.evidence, || {
                        self.build_pre_execution_monetary_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            charge,
                            reverse.committed_cost_units_after,
                            cap,
                            Some(self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            )),
                        )
                    });
                }
                return self.with_pre_invocation_guard_evidence(&e.evidence, || {
                    self.build_deny_response(request, &msg, now, Some(matched_grant_index))
                });
            }
        };

        let runtime_admission = self.run_runtime_admission_hook(
            request,
            extra_metadata.as_ref(),
            now,
            now_unix_ms,
            Some(matched_grant_index),
        );
        let runtime_admission_metadata =
            merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
        if !runtime_admission.allowed {
            let msg = runtime_admission
                .reason
                .unwrap_or_else(|| "runtime admission denied".to_string());
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied (nested flow)");
            let reverse = self.reverse_pre_execution_budget_mutation(cap, &budget_mutation)?;
            if let (Some(charge), Some(reverse)) =
                (budget_mutation.charge_result(), reverse.as_ref())
            {
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_runtime_admission_pre_execution_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        charge,
                        reverse.committed_cost_units_after,
                        cap,
                        self.merge_budget_receipt_metadata(
                            runtime_admission_metadata.clone(),
                            self.budget_execution_receipt_metadata(
                                charge,
                                Some(("reversed", reverse)),
                            ),
                        ),
                    )
                    },
                );
            }
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_runtime_admission_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    Some(matched_grant_index),
                    runtime_admission_metadata,
                )
            });
        }

        // Capture whether THIS evaluation acquired a sibling-sum child-budget
        // holder lease. Every successful `admit_capability_budget` against a
        // parent takes one lease (fresh insert OR idempotent re-admit); a later
        // pre-dispatch cleanup releases exactly this evaluation's lease. The
        // reference-counted release frees the shared edge only when the last
        // holder releases, so an overlapping evaluation that still holds it
        // keeps its share and an oversubscribing sibling stays denied.
        let budget_lease_acquired = match self.admit_capability_budget(cap) {
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
        };

        if self.execution_nonce_preflight_required(request) {
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_execution_nonce_preflight_allow_response_after_cleanup(
                    request,
                    now,
                    matched_grant_index,
                    cap,
                    &budget_mutation,
                    runtime_admission_metadata,
                    budget_lease_acquired,
                )
            });
        }

        if let Err(error) = self.validate_required_execution_nonce(request, cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "execution nonce denied");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
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
            });
        }

        if budget_mutation.charge_result().is_none() {
            if let Err(error) = self.reserve_presented_execution_nonce(request) {
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
                            payment_authorization: None,
                            runtime_admission_metadata,
                            budget_lease_acquired,
                        })
                    },
                );
            }
        }

        // Resolve the server before arming the drop guard. A missing registry
        // entry has not crossed the connector dispatch boundary, so this branch
        // can unwind pre-dispatch admission state.
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
                    payment_authorization: None,
                    runtime_admission_metadata,
                    budget_lease_acquired,
                })
            });
        };
        if budget_mutation.charge_result().is_some() {
            let capture = self.capture_monetary_invocation(cap, &mut budget_mutation);
            match capture {
                Ok(BudgetInvocationCaptureDecision::Captured(_)) => {}
                Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(_)) => {
                    let reason = "monetary invocation was already dispatched";
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_capture_replay_deny_response(
                                request,
                                reason,
                                now,
                                matched_grant_index,
                                cap,
                                &budget_mutation,
                                runtime_admission_metadata,
                                budget_lease_acquired,
                            )
                        },
                    );
                }
                Err(error) => {
                    let internal_reason = error.to_string();
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&internal_reason),
                        "budget invocation capture could not be confirmed"
                    );
                    let reason = "budget invocation capture could not be confirmed";
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_deny_response_with_metadata(
                                request,
                                reason,
                                now,
                                Some(matched_grant_index),
                                self.ambiguous_invocation_capture_receipt_metadata(
                                    &budget_mutation,
                                    runtime_admission_metadata,
                                ),
                            )
                        },
                    );
                }
            }
        }

        let payment_authorization = match self
            .authorize_payment_if_needed(request, budget_mutation.charge_result())
        {
            Ok(authorization) => authorization,
            Err(error) => {
                let internal_reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&internal_reason), "payment denied");
                let error_code = match &error {
                    PaymentError::Unavailable(_) => "unavailable",
                    PaymentError::RailError(_) => "rail_error",
                    PaymentError::Declined(_) => "declined",
                    PaymentError::InsufficientFunds => "insufficient_funds",
                };
                let reason = format!("payment authorization failed: {error_code}");
                if matches!(
                    &error,
                    PaymentError::Declined(_) | PaymentError::InsufficientFunds
                ) {
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_definite_payment_denial_after_capture(
                                request,
                                &reason,
                                now,
                                cap,
                                &budget_mutation,
                                runtime_admission_metadata,
                                budget_lease_acquired,
                            )
                        },
                    );
                }
                let metadata = merge_metadata_objects(
                    self.retained_admission_receipt_metadata(
                        &budget_mutation,
                        runtime_admission_metadata,
                    ),
                    Some(serde_json::json!({
                        "financial": {
                            "payment_authorization_ambiguous": true,
                            "payment_authorization_error_code": error_code,
                            "payment_attempt_reference": request.request_id
                        }
                    })),
                );
                let nonce_error = self.reserve_presented_execution_nonce(request).err();
                let denial_reason = nonce_error.as_ref().map_or(reason.as_str(), |_| {
                    "execution nonce denied after ambiguous payment authorization"
                });
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_deny_response_with_metadata(
                            request,
                            denial_reason,
                            now,
                            Some(matched_grant_index),
                            metadata,
                        )
                    },
                );
            }
        };

        if budget_mutation.charge_result().is_some() {
            if let Err(error) = self.reserve_presented_execution_nonce(request) {
                let reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "execution nonce denied after payment authorization");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_nonce_denial_after_monetary_cleanup(PreDispatchCleanupDeny {
                            request,
                            reason: &reason,
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
        // Mark dispatch started before lending the child-receipt buffer to the
        // bridge: the bridge borrows the guard for the whole dispatch block, so
        // the `&mut self` call must happen first. There is no await between here
        // and the invoke below, so the future cannot be dropped in this window.
        post_admission_drop_guard.mark_dispatch_started();
        let dispatch_call = async {
            let mut bridge = SessionNestedFlowBridge {
                sessions: &self.sessions,
                child_receipts: post_admission_drop_guard.child_receipts_mut(),
                parent_context,
                allow_sampling: self.config.allow_sampling,
                allow_sampling_tool_use: self.config.allow_sampling_tool_use,
                allow_elicitation: self.config.allow_elicitation,
                policy_hash: &self.config.policy_hash,
                kernel_keypair: &self.config.keypair,
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
        // Persist the buffered child receipts while the guard is still armed,
        // draining each from the guard only once it durably lands. If the commit
        // writer is saturated and a bounded append times out, the `?` returns
        // with the guard armed and dispatch marked started, so its drop runs the
        // post-dispatch abort cleanup: flush the child receipts that had not yet
        // persisted, retain admitted budget/runtime state fail-closed, and record
        // a signed cancellation receipt.
        // Because the guard keeps the not-yet-persisted receipts, a mid-flush
        // append failure cannot lose an already-signed child receipt; recording
        // through a drained buffer would instead drop it. On success the guard is
        // disarmed with an empty buffer, so the disarmed drop flushes nothing and
        // no receipt is double-recorded.
        post_admission_drop_guard.record_buffered_child_receipts()?;
        post_admission_drop_guard.disarm();
        drop(post_admission_drop_guard);
        let tool_output = match tool_output_result {
            Ok(output) => output,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                let metadata = self.ambiguous_dispatch_receipt_metadata(
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    runtime_admission_metadata,
                );
                let receipt_result =
                    self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                        self.build_cancelled_response_with_metadata(
                            request,
                            "tool server requested URL elicitation after dispatch entry",
                            now,
                            Some(matched_grant_index),
                            metadata,
                        )
                    });
                if let Err(receipt_error) = receipt_result {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&receipt_error),
                        audit_fault = "url_elicitation_terminal_receipt_unrecorded",
                        "failed to record ambiguous URL-elicitation receipt"
                    );
                }
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&error),
                    "tool call requires URL elicitation"
                );
                return Err(error);
            }
            Err(KernelError::RequestCancelled { request_id, reason }) => {
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
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_cancelled_response_with_metadata(
                            request,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            self.ambiguous_dispatch_receipt_metadata(
                                &budget_mutation,
                                payment_authorization.as_ref(),
                                runtime_admission_metadata.clone(),
                            ),
                        )
                    },
                );
            }
            Err(KernelError::HotPathDeadlineExceeded { stage, budget_ms }) => {
                let reason = format!("hot-path deadline exceeded at {stage}: budget {budget_ms}ms");
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
                            self.ambiguous_dispatch_receipt_metadata(
                                &budget_mutation,
                                payment_authorization.as_ref(),
                                runtime_admission_metadata.clone(),
                            ),
                        )
                    },
                );
            }
            Err(KernelError::RequestIncomplete(reason)) => {
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call incomplete"
                );
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_incomplete_response_with_output_and_metadata(
                            request,
                            None,
                            &reason,
                            now,
                            Some(matched_grant_index),
                            self.ambiguous_dispatch_receipt_metadata(
                                &budget_mutation,
                                payment_authorization.as_ref(),
                                runtime_admission_metadata.clone(),
                            ),
                        )
                    },
                );
            }
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
                // A tool side effect may have executed: retain runtime admission,
                // invocation consumption, and monetary exposure.
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        let deny_metadata = self.ambiguous_dispatch_receipt_metadata(
                            &budget_mutation,
                            payment_authorization.as_ref(),
                            runtime_admission_metadata.clone(),
                        );
                        self.build_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            Some(matched_grant_index),
                            deny_metadata,
                        )
                    },
                );
            }
        };
        self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
            self.finalize_budgeted_tool_output_with_cost_and_metadata(
                request,
                tool_output,
                tool_started_at.elapsed(),
                now,
                matched_grant_index,
                FinalizeToolOutputCostContext {
                    charge_result: budget_mutation.into_charge_result(),
                    reported_cost: None,
                    payment_authorization,
                    cap,
                },
                runtime_admission_metadata,
            )
        })
    }
}
