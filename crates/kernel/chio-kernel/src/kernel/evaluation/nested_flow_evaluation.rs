use std::ops::ControlFlow;

use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::nested_flow_grant_selection::{NestedFlowGrantSelection, SelectedNestedFlowGrant};
use super::*;
use crate::budget_store::BudgetInvocationCaptureDecision;
use crate::finding_denial::denied_metadata;
use crate::kernel::admission_coordinator::{DispatchTransport, DurableRefusalResponse};
use crate::kernel::dispatch::dispatch_admission_error_reason;
use crate::kernel::validation::ambiguous_payment_authorization_metadata;

impl ChioKernel {
    #[cfg(test)]
    pub(crate) fn evaluate_tool_call_with_nested_flow_client<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_with_nested_flow_client_and_security_context(
            parent_context,
            request,
            client,
            extra_metadata,
            None,
            None,
        )
    }

    pub(crate) fn evaluate_tool_call_with_nested_flow_client_and_security_context<
        C: NestedFlowClient,
    >(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
        security_context: Option<&SecurityInvocationContext>,
        session_guard_attempt: Option<GuardInvocationAttempt>,
    ) -> Result<ToolCallResponse, KernelError> {
        block_on_async_tool_dispatch(
            self.evaluate_tool_call_with_nested_flow_client_async_and_security_context(
                parent_context,
                request,
                client,
                extra_metadata,
                security_context,
                session_guard_attempt,
            ),
        )
    }

    #[cfg(test)]
    pub(crate) async fn evaluate_tool_call_with_nested_flow_client_async<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_with_nested_flow_client_async_and_security_context(
            parent_context,
            request,
            client,
            extra_metadata,
            None,
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
        security_context: Option<&SecurityInvocationContext>,
        session_guard_attempt: Option<GuardInvocationAttempt>,
    ) -> Result<ToolCallResponse, KernelError> {
        // Keep the large evaluation state out of the bridge's stack frames.
        // Deep, bounded custody verification must still fit a normal host stack.
        scope_async_receipt_context(Box::pin(
            self.evaluate_tool_call_with_nested_flow_client_async_scoped(
                parent_context,
                request,
                client,
                extra_metadata,
                security_context,
                session_guard_attempt,
            ),
        ))
        .await
    }

    async fn evaluate_tool_call_with_nested_flow_client_async_scoped<C: NestedFlowClient>(
        &self,
        parent_context: &OperationContext,
        request: &ToolCallRequest,
        client: &mut C,
        extra_metadata: Option<serde_json::Value>,
        security_context: Option<&SecurityInvocationContext>,
        session_guard_attempt: Option<GuardInvocationAttempt>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.validate_security_invocation_context_binding(
            request,
            security_context,
            Some(&parent_context.session_id),
        )?;
        self.validate_session_threshold_intent(request, Some(&parent_context.session_id))?;
        // Install the parent session's tenant_id so every
        // receipt signed while this nested-flow evaluation is in flight
        // carries the correct tenant tag.
        let tenant_id = self.resolve_tenant_id_for_session(Some(&parent_context.session_id));
        let _tenant_request_scope =
            self.scope_receipt_tenant_id_for_request(&request.request_id, tenant_id.clone());
        let _tenant_scope = scope_receipt_tenant_id(tenant_id);
        let _session_anchor_scope = self.scope_receipt_session_anchor_for_request(
            &request.request_id,
            Some(&parent_context.session_id),
        )?;

        let now_unix_ms = self.read_authority_time()?.get();
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

        if let Err(error) = request.validate_authorization_extensions() {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "authorization extension rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                RefusalReceiptMetadata::new(extra_metadata.clone(), IdentityDisposition::Reusable),
            );
        }

        if let Err(error) = self.validate_finding_memory_write_admission(request) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "Finding memory write rejected pre-dispatch (nested flow)");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                RefusalReceiptMetadata::new(extra_metadata.clone(), IdentityDisposition::Reusable),
            );
        }

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
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                RefusalReceiptMetadata::new(extra_metadata.clone(), IdentityDisposition::Reusable),
            );
        }

        if let Err(e) = check_time_bounds(cap, now) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                RefusalReceiptMetadata::new(extra_metadata.clone(), IdentityDisposition::Reusable),
            );
        }

        if let Err(e) = self.check_tool_call_revocation_admission(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                RefusalReceiptMetadata::new(extra_metadata.clone(), IdentityDisposition::Reusable),
            );
        }

        if let Err(e) = self.validate_delegation_admission(cap) {
            return self.deny_admission_error(request, &e, now, extra_metadata.clone());
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                RefusalReceiptMetadata::new(extra_metadata.clone(), IdentityDisposition::Reusable),
            );
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
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    RefusalReceiptMetadata::new(
                        extra_metadata.clone(),
                        IdentityDisposition::Reusable,
                    ),
                );
            }
        };
        let required_delivery_grant_index =
            match super::evaluation_helpers::required_delivery_grant_index(&matching_grants) {
                Ok(index) => index,
                Err(reason) => {
                    warn!(request_id = %request.request_id, reason, "delivery contract denied");
                    return self.build_deny_response_with_metadata(
                        request,
                        reason,
                        now,
                        None,
                        RefusalReceiptMetadata::new(
                            extra_metadata.clone(),
                            IdentityDisposition::Reusable,
                        ),
                    );
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
                || Err(KernelError::Dpop(crate::dpop::DpopError::MissingProof)),
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
                return self.deny_admission_error(request, &e, now, None);
            }
        }

        if let Err(e) = self.ensure_registered_tool_target(request) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool target not registered");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                RefusalReceiptMetadata::new(extra_metadata.clone(), IdentityDisposition::Reusable),
            );
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
        self.ensure_post_effect_evidence_latch_clear()?;
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

        self.reconcile_durable_admission_startup()?;
        let mut durable_admission = match self.begin_durable_tool_admission_for_transport(
            request,
            &matching_grants,
            security_context,
            extra_metadata.as_ref(),
            now_unix_ms,
            DispatchTransport::KernelToolServer,
        ) {
            Ok(admission) => admission,
            Err(error) => {
                let Some(disposition) = error.receipt_disposition else {
                    return Err(*error.error);
                };
                let reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "durable admission denied (nested flow)");
                return self.build_deny_response_with_metadata(
                    request,
                    &reason,
                    now,
                    None,
                    RefusalReceiptMetadata::new(
                        error.error.denied_metadata(&extra_metadata),
                        disposition,
                    ),
                );
            }
        };

        if let Some(admission) = durable_admission.as_mut() {
            if let Some(response) = self.recover_durable_tool_admission(admission, request)? {
                return Ok(response);
            }
        }

        // Persistence is confirmed healthy, so the writer-backed lineage write can
        // run without racing a dead writer.
        if let Err(error) = self.record_observed_capability_snapshot(cap) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            if let Some(response) = self.compensate_durable_admission_after_pre_dispatch_cleanup(
                durable_admission
                    .as_ref()
                    .map(DurableToolAdmission::operation),
                None,
                None,
                None,
                DurableRefusalResponse {
                    reason: &msg,
                    cancelled: false,
                    matched_grant_index: None,
                    metadata: extra_metadata.clone(),
                    verified_payee_binding: None,
                },
            )? {
                return Ok(response);
            }
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                RefusalReceiptMetadata::new(
                    extra_metadata.clone(),
                    if durable_admission.is_some() {
                        IdentityDisposition::Terminal
                    } else {
                        IdentityDisposition::Reusable
                    },
                ),
            );
        }

        let session_roots = match self
            .session_enforceable_filesystem_root_paths_owned(&parent_context.session_id)
        {
            Ok(roots) => roots,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "session filesystem roots lookup failed pre-dispatch (nested flow)");
                if let Some(response) = self
                    .compensate_durable_admission_after_pre_dispatch_cleanup(
                        durable_admission
                            .as_ref()
                            .map(DurableToolAdmission::operation),
                        None,
                        None,
                        None,
                        DurableRefusalResponse {
                            reason: &msg,
                            cancelled: false,
                            matched_grant_index: None,
                            metadata: extra_metadata.clone(),
                            verified_payee_binding: None,
                        },
                    )?
                {
                    return Ok(response);
                }
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    RefusalReceiptMetadata::new(
                        extra_metadata.clone(),
                        if durable_admission.is_some() {
                            IdentityDisposition::Terminal
                        } else {
                            IdentityDisposition::Reusable
                        },
                    ),
                );
            }
        };

        let SelectedNestedFlowGrant {
            matched_grant_index,
            mut budget_mutation,
            validated_governed_admission,
            governed_call_chain_receipt_evidence,
            pre_invocation_guard_evidence,
            runtime_admission_metadata,
        } = match self
            .select_nested_flow_grant(NestedFlowGrantSelection {
                parent_context,
                request,
                extra_metadata: &extra_metadata,
                security_context,
                session_guard_attempt,
                now,
                now_unix_ms,
                cap,
                matching_grants: &matching_grants,
                required_delivery_grant_index,
                durable_admission: &mut durable_admission,
                session_roots: &session_roots,
            })
            .await?
        {
            ControlFlow::Continue(selected) => selected,
            ControlFlow::Break(response) => return Ok(response),
        };

        let _governed_runtime_attestation_receipt_scope =
            scope_governed_runtime_attestation_receipt_record(
                validated_governed_admission
                    .as_ref()
                    .and_then(|admission| admission.verified_runtime_attestation.clone()),
            );
        let verified_governed_payee_binding = validated_governed_admission
            .as_ref()
            .and_then(|admission| admission.verified_payee_binding.clone());
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(governed_call_chain_receipt_evidence);

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
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata,
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            // Admission failed: this evaluation acquired no
                            // lease, so there is nothing for cleanup to release.
                            budget_lease_acquired: false,
                        })
                    },
                );
            }
        };

        if self.execution_nonce_preflight_required(request) {
            // Nonce-preflight authorizes without producing output, so an
            // output-digest grant cannot be enforced on it. The root lane
            // rejects this shape before any mint; the nested lane must not
            // be a softer path to the same authorization.
            if matching_grants
                .iter()
                .find(|matching| matching.index == matched_grant_index)
                .is_some_and(|selected| {
                    selected
                        .grant
                        .constraints
                        .iter()
                        .any(|constraint| matches!(constraint, Constraint::OutputDigestSha256(_)))
                })
            {
                let reason =
                    "output-digest delivery cannot be enforced on a no-output authorization path";
                warn!(request_id = %request.request_id, reason, "delivery contract denied");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason,
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata,
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_execution_nonce_preflight_allow_response_after_cleanup(
                    request,
                    now,
                    matched_grant_index,
                    cap,
                    &budget_mutation,
                    durable_admission.as_mut(),
                    runtime_admission_metadata,
                    budget_lease_acquired,
                )
            });
        }

        if let Err(error) = self.validate_required_execution_nonce_for_admission(
            request,
            cap,
            durable_admission.as_ref(),
        ) {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, rejection_code = %error.report().code, reason = %redacted!(&msg), "execution nonce denied");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &msg,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: error
                        .rejection_metadata(runtime_admission_metadata),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        }

        // Nested dispatch enforces the same delivery-contract boundary as a
        // root tool call: an output-digest grant is honored only at the
        // durable output-aware terminal, so reject before any capture when
        // the lane cannot reach it (legacy, non-reversible rail, governed
        // prepay).
        if let Some(selected) = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
        {
            let requires_output_digest = selected
                .grant
                .constraints
                .iter()
                .any(|constraint| matches!(constraint, Constraint::OutputDigestSha256(_)));
            if requires_output_digest {
                let rail_is_reversible = self
                    .payment_adapter
                    .as_ref()
                    .and_then(|adapter| adapter.rail_mode())
                    .is_none_or(|mode| mode == crate::payment::PaymentRailMode::ReversibleHold);
                if durable_admission.is_none()
                    || !rail_is_reversible
                    || Self::is_governed_mustprepay_request(request)
                {
                    let reason = "output-digest delivery requires durable reversible-hold coverage";
                    warn!(request_id = %request.request_id, reason, "delivery contract denied");
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                                request,
                                reason,
                                timestamp: now,
                                matched_grant_index,
                                cap,
                                budget_mutation: &budget_mutation,
                                payment_authorization: None,
                                durable_operation: durable_admission
                                    .as_ref()
                                    .map(DurableToolAdmission::operation),
                                runtime_admission_metadata,
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                budget_lease_acquired,
                            })
                        },
                    );
                }
            }
            // Nested dispatch enforces the same purchase boundary as a
            // root tool call: a purchase-marked grant requires the
            // verified signed purchase context and an open slot-reserved
            // reservation before any mutation.
            if let Err(denial) = self.verify_purchase_admission(selected.grant, request, now) {
                warn!(request_id = %request.request_id, denial = %denial.code(), reason = %redacted!(denial.detail()), "finding purchase denied");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason: denial.detail(),
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata: denied_metadata(
                                &runtime_admission_metadata,
                                &denial,
                            ),
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
            if let Err(denial) = self.verify_recovery_admission(selected.grant, request, now) {
                warn!(request_id = %request.request_id, denial = %denial.code(), reason = %redacted!(denial.detail()), "finding recovery denied");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason: denial.detail(),
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata: denied_metadata(
                                &runtime_admission_metadata,
                                &denial,
                            ),
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        }

        // Nested dispatch has the same financial durability boundary as a root
        // tool call. The selected grant, not the set of candidates, decides
        // whether money is at risk, and no financial hold may cross into the tool
        // server without a durable payment participant to reconcile ambiguity.
        if !self.ephemeral_financial_dispatch_allowed()
            && durable_admission
                .as_ref()
                .is_none_or(|admission| !admission.requires_payment())
            && (budget_mutation.charge_result().is_some()
                || Self::is_governed_mustprepay_request(request))
        {
            let reason = "financial tool dispatch requires durable admission coverage";
            warn!(request_id = %request.request_id, reason, "financial nested dispatch denied");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata,
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
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
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata,
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        };
        let matched_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .map(|matching| matching.grant)
            .ok_or_else(|| {
                KernelError::Internal(
                    "selected grant disappeared before dispatch revalidation".to_string(),
                )
            })?;
        let durable_execution_nonce = durable_admission
            .as_ref()
            .is_some_and(DurableToolAdmission::requires_execution_nonce);
        let mut credential_reservation = match self
            .read_authority_time()
            .map_err(KernelError::from)
            .and_then(|time| {
                self.reserve_admitted_dispatch_credentials(
                    request,
                    dpop_required,
                    time.as_secs(),
                    durable_admission.as_ref(),
                    matched_grant_index,
                )
            }) {
            Ok(reservation) => reservation,
            Err(error) => {
                let reason = error.to_string();
                warn!(request_id = %request.request_id, rejection_code = %error.report().code, reason = %redacted!(&reason), "dispatch credential reservation denied (nested flow)");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason: &reason,
                            timestamp: self
                                .read_authority_time()
                                .map(|time| time.as_secs())
                                .unwrap_or(now),
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: None,
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata: error
                                .rejection_metadata(runtime_admission_metadata.clone()),
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        };
        let force_dispatch_revalidation =
            credential_reservation.requires_post_reservation_revalidation();
        let dispatch_context = Self::tool_dispatch_context(request, durable_admission.as_ref());
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
            )
            .with_durable_operation(
                durable_admission
                    .as_ref()
                    .map(DurableToolAdmission::operation),
            );
            let result = self
                .wait_for_tool_dispatch_readiness(request, Some(server), dispatch_context.as_ref())
                .await;
            readiness_drop_guard.disarm();
            result
        };
        let mut runtime_admission_metadata = runtime_admission_metadata;
        let (readiness_result, prepared_delivery) =
            PreparedToolDelivery::retain(readiness_result, &mut runtime_admission_metadata);
        let server = prepared_delivery
            .as_ref()
            .and_then(|prepared| prepared.connection.as_ref())
            .unwrap_or(server);
        let revalidation_time = self.read_authority_time();
        let revalidation_now_unix_ms = revalidation_time
            .as_ref()
            .map(|time| time.get())
            .unwrap_or(now_unix_ms);
        let final_dispatch_admission = match readiness_result {
            Ok(readiness_waited) => revalidation_time.map_err(KernelError::from).and_then(|_| {
                self.revalidate_immediately_before_dispatch(
                    request,
                    durable_admission.as_ref(),
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
                    durable_execution_nonce,
                    readiness_waited || force_dispatch_revalidation,
                    revalidation_now_unix_ms / 1000,
                    revalidation_now_unix_ms,
                )
            }),
            Err(error) => Err(error),
        };
        let mut verified_finding_admission = final_dispatch_admission
            .as_ref()
            .ok()
            .cloned()
            .unwrap_or_default();
        if let Err(error) = final_dispatch_admission {
            let mut reason = dispatch_admission_error_reason(&error);
            if let Err(rollback_error) = credential_reservation.rollback_before_dispatch() {
                reason = format!("{reason}; {rollback_error}");
            }
            warn!(request_id = %request.request_id, reason = %redacted!(&reason), "immediate dispatch revalidation denied (nested flow)");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &reason,
                    timestamp: revalidation_now_unix_ms / 1000,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: error.denied_metadata(&runtime_admission_metadata),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        }
        if let Some(admission) = durable_admission.as_mut() {
            if let Err(error) = self.mark_durable_capture_pending(admission, now_unix_ms) {
                if !error.durable_commit_outcome_is_unknown() {
                    return Err(error);
                }

                let reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "durable capture boundary could not be confirmed (nested flow)");
                return self.build_deny_response_with_metadata(
                    request,
                    &reason,
                    now,
                    Some(matched_grant_index),
                    RefusalReceiptMetadata::new(
                        self.retained_admission_receipt_metadata(
                            &budget_mutation,
                            runtime_admission_metadata.clone(),
                        ),
                        IdentityDisposition::Retained,
                    ),
                );
            }
        }
        if budget_mutation.durable_hold_result().is_some() && durable_admission.is_none() {
            let capture = self.capture_invocation(cap, &mut budget_mutation);
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
                                verified_governed_payee_binding.as_ref(),
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
                                RefusalReceiptMetadata::new(
                                    self.ambiguous_invocation_capture_receipt_metadata(
                                        &budget_mutation,
                                        runtime_admission_metadata,
                                    ),
                                    IdentityDisposition::Retained,
                                ),
                            )
                        },
                    );
                }
            }
        }

        let payment_authorization = match self.authorize_payment_if_needed(
            request,
            budget_mutation.charge_result(),
            durable_admission.as_ref(),
            now_unix_ms,
            verified_governed_payee_binding.as_ref(),
        ) {
            Ok(authorization) => {
                if authorization.is_some() {
                    if let Err(error) = credential_reservation.retain_after_external_authorization()
                    {
                        let reason = format!(
                            "dispatch credential retention failed after payment authorization: {error}"
                        );
                        warn!(request_id = %request.request_id, reason = %redacted!(&reason), "payment credential retention denied (nested flow)");
                        return self.with_pre_invocation_guard_evidence(
                            &pre_invocation_guard_evidence,
                            || {
                                self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                                    PreDispatchCleanupDeny {
                                        request,
                                        reason: &reason,
                                        timestamp: self
                                            .read_authority_time()
                                            .map(|time| time.as_secs())
                                            .unwrap_or(now),
                                        matched_grant_index,
                                        cap,
                                        budget_mutation: &budget_mutation,
                                        payment_authorization: authorization.as_ref(),
                                        durable_operation: durable_admission
                                            .as_ref()
                                            .map(DurableToolAdmission::operation),
                                        runtime_admission_metadata: runtime_admission_metadata
                                            .clone(),
                                        verified_payee_binding: verified_governed_payee_binding
                                            .as_ref(),
                                        budget_lease_acquired,
                                    },
                                    PaymentCredentialDisposition::RetentionOutcomeUnknown,
                                )
                            },
                        );
                    }
                }
                authorization
            }
            Err(error) => {
                let internal_reason = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&internal_reason), "payment denied");
                let error_code = error.code();
                let reason = format!("payment authorization failed: {error_code}");
                if matches!(
                    &error,
                    PaymentError::Declined(_) | PaymentError::InsufficientFunds
                ) {
                    let mut denial_reason = reason.clone();
                    let credential_disposition = if let Err(rollback_error) =
                        credential_reservation.rollback_before_dispatch()
                    {
                        denial_reason = format!("{denial_reason}; {rollback_error}");
                        PaymentCredentialDisposition::RetentionOutcomeUnknown
                    } else {
                        PaymentCredentialDisposition::NonePresent
                    };
                    let cleanup_metadata = self.merge_dispatch_credential_disposition_metadata(
                        runtime_admission_metadata,
                        credential_disposition,
                    );
                    if budget_mutation
                        .charge_result()
                        .and_then(|charge| charge.invocation_capture.as_ref())
                        .is_some()
                    {
                        return self.with_pre_invocation_guard_evidence(
                            &pre_invocation_guard_evidence,
                            || {
                                self.build_definite_payment_denial_after_capture(
                                    request,
                                    &denial_reason,
                                    now,
                                    cap,
                                    &budget_mutation,
                                    durable_admission
                                        .as_ref()
                                        .map(DurableToolAdmission::operation),
                                    cleanup_metadata,
                                    budget_lease_acquired,
                                    verified_governed_payee_binding.as_ref(),
                                )
                            },
                        );
                    }
                    return self.with_pre_invocation_guard_evidence(
                        &pre_invocation_guard_evidence,
                        || {
                            self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                                PreDispatchCleanupDeny {
                                    request,
                                    reason: &denial_reason,
                                    timestamp: now,
                                    matched_grant_index,
                                    cap,
                                    budget_mutation: &budget_mutation,
                                    payment_authorization: None,
                                    durable_operation: durable_admission
                                        .as_ref()
                                        .map(DurableToolAdmission::operation),
                                    runtime_admission_metadata: cleanup_metadata,
                                    verified_payee_binding: verified_governed_payee_binding
                                        .as_ref(),
                                    budget_lease_acquired,
                                },
                                PaymentCredentialDisposition::NonePresent,
                            )
                        },
                    );
                }
                let metadata = merge_metadata_objects(
                    self.retained_admission_receipt_metadata(
                        &budget_mutation,
                        runtime_admission_metadata,
                    ),
                    Some(ambiguous_payment_authorization_metadata(
                        &error,
                        Self::payment_operation_reference(
                            request,
                            durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                        ),
                    )),
                );
                let (denial_reason, credential_disposition) =
                    match credential_reservation.commit() {
                        Ok(disposition) => (reason, disposition),
                        Err(retention_error) => (
                            format!(
                                "payment authorization outcome is ambiguous and credential retention failed: {retention_error}"
                            ),
                            PaymentCredentialDisposition::RetentionOutcomeUnknown,
                        ),
                    };
                let metadata = self.merge_dispatch_credential_disposition_metadata(
                    metadata,
                    credential_disposition,
                );
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_deny_response_with_metadata_and_payee_binding(
                            request,
                            &denial_reason,
                            now,
                            Some(matched_grant_index),
                            RefusalReceiptMetadata::new(metadata, IdentityDisposition::Retained),
                            verified_governed_payee_binding.as_ref(),
                        )
                    },
                );
            }
        };

        if payment_authorization.is_some() {
            let post_payment_time = self.read_authority_time();
            let post_payment_now_unix_ms = post_payment_time
                .as_ref()
                .map(|time| time.get())
                .unwrap_or(revalidation_now_unix_ms);
            let post_payment_admission =
                post_payment_time.map_err(KernelError::from).and_then(|_| {
                    self.revalidate_immediately_before_dispatch(
                        request,
                        durable_admission.as_ref(),
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
                        durable_execution_nonce,
                        // External payment authorization may change mutable authority
                        // even when no single-use dispatch credential was presented.
                        true,
                        post_payment_now_unix_ms / 1000,
                        post_payment_now_unix_ms,
                    )
                });
            if let Ok(admission) = &post_payment_admission {
                verified_finding_admission.clone_from(admission);
            }
            if let Err(error) = post_payment_admission {
                let reason = dispatch_admission_error_reason(&error);
                warn!(request_id = %request.request_id, reason = %redacted!(&reason), "post-payment dispatch revalidation denied (nested flow)");
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
                                durable_operation: durable_admission
                                    .as_ref()
                                    .map(DurableToolAdmission::operation),
                                runtime_admission_metadata: error
                                    .denied_metadata(&runtime_admission_metadata),
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                budget_lease_acquired,
                            },
                            PaymentCredentialDisposition::RetainedAfterAuthorization,
                        )
                    },
                );
            }
        }

        if let Err(refusal) = self.start_session_request_dispatch(
            Some(&parent_context.session_id),
            parent_context.request_id.as_str(),
        ) {
            let reason = refusal.error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&reason), "parent session cancellation won the nested pre-dispatch boundary");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                let cleanup = PreDispatchCleanupDeny {
                    request,
                    reason: refusal.cancellation.as_deref().unwrap_or(&reason),
                    timestamp: self
                        .read_authority_time()
                        .map(|time| time.as_secs())
                        .unwrap_or(now),
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: payment_authorization.as_ref(),
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: runtime_admission_metadata.clone(),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                };
                self.build_session_dispatch_refusal_response(
                    cleanup,
                    refusal.cancellation.is_some(),
                )
            });
        }

        // Claim the pool participant while the durable admission is still in a
        // compensatable pre-dispatch state. Exact replay makes a crash after
        // this point resumable without capturing the invocation twice.
        let pool_claim = self
            .read_authority_time()
            .map_err(KernelError::from)
            .and_then(|time| {
                self.claim_finding_pool_immediately_before_dispatch(
                    matched_grant,
                    request,
                    time.get(),
                    durable_admission
                        .as_ref()
                        .map(|admission| admission.operation().binding().operation_id().as_str()),
                )
            });
        if let Ok(purchase) = &pool_claim {
            verified_finding_admission.purchase.clone_from(purchase);
        }
        if let Err(error) = pool_claim {
            let reason = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&reason), "finding pool nested dispatch claim denied");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                    PreDispatchCleanupDeny {
                        request,
                        reason: &reason,
                        timestamp: self
                            .read_authority_time()
                            .map(|time| time.as_secs())
                            .unwrap_or(now),
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        payment_authorization: payment_authorization.as_ref(),
                        durable_operation: durable_admission
                            .as_ref()
                            .map(DurableToolAdmission::operation),
                        runtime_admission_metadata: error
                            .denied_metadata(&runtime_admission_metadata),
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

        #[cfg(feature = "admission-test-support")]
        let mut credential_reservation = match self.evaluate_native_capture_checkpoint(
            credential_reservation,
            durable_admission.as_mut(),
            &mut budget_mutation,
            NativeCaptureCheckpointContext {
                request,
                security_context,
                timestamp: now,
                matched_grant_index,
                payment_authorization: payment_authorization.as_ref(),
                metadata: runtime_admission_metadata.as_ref(),
                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                budget_lease_acquired,
                evidence: &pre_invocation_guard_evidence,
            },
        ) {
            NativeCaptureCheckpointOutcome::Continue(credentials) => credentials,
            NativeCaptureCheckpointOutcome::Break(response) => return response,
        };
        let mut security_pre_dispatch = match self.run_security_pre_dispatch_hook(
            request,
            security_context,
            durable_admission.as_ref(),
        ) {
            Ok(outcome) => outcome,
            Err(denial) => {
                let mut denial_evidence = pre_invocation_guard_evidence.clone();
                denial_evidence.push(denial.evidence);
                let reason = denial.reason;
                warn!(request_id = %request.request_id, reason, "security pre-dispatch denied (nested flow)");
                return self.build_pre_commit_credential_rejection_response(
                    PreDispatchCleanupDeny {
                        request,
                        reason,
                        timestamp: now,
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        payment_authorization: payment_authorization.as_ref(),
                        durable_operation: durable_admission
                            .as_ref()
                            .map(DurableToolAdmission::operation),
                        runtime_admission_metadata: runtime_admission_metadata.clone(),
                        verified_payee_binding: verified_governed_payee_binding.as_ref(),
                        budget_lease_acquired,
                    },
                    credential_reservation,
                    &denial_evidence,
                );
            }
        };
        // Security has accepted, but dispatch has not started. Retain on
        // uncertain commit/cancellation, never before a definite security denial.
        if let Err(error) = credential_reservation.retain_if_dropped() {
            let reason = format!("dispatch credential retention failed before dispatch: {error}");
            let response =
                self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                    self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                        PreDispatchCleanupDeny {
                            request,
                            reason: &reason,
                            timestamp: self
                                .read_authority_time()
                                .map(|time| time.as_secs())
                                .unwrap_or(now),
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: payment_authorization.as_ref(),
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata: runtime_admission_metadata.clone(),
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        },
                        PaymentCredentialDisposition::RetentionOutcomeUnknown,
                    )
                });
            if let Some(outcome) = security_pre_dispatch.dispatch_outcome.take() {
                outcome.record_dispatch_failed()?;
            }
            return response;
        }
        let mut security_dispatch_outcome = security_pre_dispatch.dispatch_outcome.take();
        let mut security_request_lifecycle = security_pre_dispatch.request_lifecycle.take();

        let durable_return_context = if let Some(admission) = durable_admission.as_mut() {
            let commit = self.freeze_and_commit_evaluation_dispatch(
                admission,
                &mut budget_mutation,
                &mut credential_reservation,
                DurableToolReturnContextInput {
                    request,
                    matched_grant_index,
                    extra_receipt_metadata: runtime_admission_metadata.clone(),
                    pre_invocation_guard_evidence: &pre_invocation_guard_evidence,
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    verified_purchase: verified_finding_admission.purchase.as_ref(),
                    verified_recovery: verified_finding_admission.recovery.as_ref(),
                    trusted_now_unix_ms: now_unix_ms,
                    security_invocation_context: security_context,
                    security_release_required: security_request_lifecycle.is_some(),
                },
            );
            let (context, native_owner) = match commit {
                Ok(committed) => committed,
                Err(error) => {
                    let reason = error.to_string();
                    warn!(request_id = %request.request_id, reason = %redacted!(&reason), "durable dispatch preparation failed (nested flow)");
                    return self.build_durable_dispatch_failure_response(
                        error,
                        PreDispatchCleanupDeny {
                            request,
                            reason: &reason,
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation: &budget_mutation,
                            payment_authorization: payment_authorization.as_ref(),
                            durable_operation: Some(admission.operation()),
                            runtime_admission_metadata,
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        },
                        credential_reservation,
                        &pre_invocation_guard_evidence,
                        security_dispatch_outcome.take(),
                    );
                }
            };
            security_request_lifecycle = native_owner.or(security_request_lifecycle);
            Some(context)
        } else {
            None
        };

        let has_monetary_charge = budget_mutation.charge_result().is_some();
        let prepared_post_effect = match self.prepare_post_effect(
            crate::kernel::effect_obligation::PostEffectPreparation {
                request,
                matched_grant_index,
                budget: &budget_mutation,
                payment: payment_authorization.as_ref(),
                metadata: &runtime_admission_metadata,
                evidence: &pre_invocation_guard_evidence,
                payee: verified_governed_payee_binding.as_ref(),
                admission: durable_admission.as_ref(),
                evaluation_started_at: now_unix_ms,
            },
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Some(admission) = durable_admission.as_ref() {
                    return Err(KernelError::DurableOutcomePending {
                        operation_id: admission.operation_id().to_owned(),
                    });
                }
                let reason = error.to_string();
                return self.build_pre_commit_credential_rejection_response(
                    PreDispatchCleanupDeny {
                        request,
                        reason: &reason,
                        timestamp: now,
                        matched_grant_index,
                        cap,
                        budget_mutation: &budget_mutation,
                        payment_authorization: payment_authorization.as_ref(),
                        durable_operation: None,
                        runtime_admission_metadata,
                        verified_payee_binding: verified_governed_payee_binding.as_ref(),
                        budget_lease_acquired,
                    },
                    credential_reservation,
                    &pre_invocation_guard_evidence,
                );
            }
        };
        let mut obligation = crate::kernel::effect_obligation::PostEffectObligation::enter(
            self,
            crate::kernel::effect_obligation::PostEffectInputs {
                request,
                matched_grant_index,
                budget: budget_mutation,
                payment: payment_authorization,
                metadata: runtime_admission_metadata,
                evidence: pre_invocation_guard_evidence,
                payee: verified_governed_payee_binding,
                admission: durable_admission,
                return_context: durable_return_context,
                credentials: credential_reservation,
                security_outcome: security_dispatch_outcome,
                security_lifecycle: security_request_lifecycle,
                finding: verified_finding_admission,
                security_context,
                parent_context: Some(parent_context),
                prepared: prepared_post_effect,
            },
        );
        let nested_interaction_observed = std::sync::atomic::AtomicBool::new(false);
        let dispatch_is_durable = obligation.admission().is_some();
        let dispatch_call = async {
            let context = crate::ToolInvocationContext::from_request(request)?
                .with_dispatch(dispatch_context.clone());
            let (child_receipts, evidence_slot) = obligation.nested_receipt_sinks()?;
            let mut bridge = SessionNestedFlowBridge {
                clock: self.authority_clock(),
                sessions: &self.sessions,
                child_receipts,
                evidence_slot,
                kernel: self,
                started_children: 0,
                max_child_receipts: self.config.memory_budget.max_post_effect_child_receipts,
                nested_interaction_observed: &nested_interaction_observed,
                parent_context,
                allow_sampling: self.config.allow_sampling,
                allow_sampling_tool_use: self.config.allow_sampling_tool_use,
                allow_elicitation: self.config.allow_elicitation,
                policy_hash: &self.config.policy_hash,
                kernel_keypair: &self.config.keypair,
                client,
            };

            match server
                .invoke_stream_with_context(&context, request.arguments.clone(), Some(&mut bridge))
                .await
            {
                Ok(Some(stream)) => Ok((ToolServerOutput::Stream(stream), None)),
                Ok(None) if has_monetary_charge => server
                    .invoke_with_cost_and_context(
                        &context,
                        request.arguments.clone(),
                        Some(&mut bridge),
                    )
                    .await
                    .map(|(value, cost)| (ToolServerOutput::Value(value), cost)),
                Ok(None) => server
                    .invoke_with_context(&context, request.arguments.clone(), Some(&mut bridge))
                    .await
                    .map(|value| (ToolServerOutput::Value(value), None)),
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
        let dispatch_budget = self
            .config
            .deadlines
            .dispatch_budget_for(&request.server_id);
        let tool_output_result = self
            .timed_dispatch(dispatch_is_durable, async {
                match dispatch_budget {
                    Some(budget) => {
                        crate::kernel::dispatch::dispatch_nested_call_within_budget(
                            dispatch_call,
                            budget,
                        )
                        .await
                    }
                    None => dispatch_call.await,
                }
            })
            .await;
        crate::kernel::effect_obligation::run_post_effect(obligation, tool_output_result).deliver()
    }
}
