use super::evaluation_helpers::{
    ExecutionNonceReservingResponse, PreDispatchCleanupDeny, SecurityDispatchOutcomeRecovery,
};
use super::*;
use crate::kernel::admission_coordinator::{
    ThresholdCallerReservationHandoffContext, ThresholdDispatchPermit, ThresholdPaymentMode,
    ThresholdToolAdmissionContext,
};

impl ChioKernel {
    pub(super) async fn evaluate_tool_call_async_with_session_context(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
        security_context: Option<&SecurityInvocationContext>,
        preflight_disposition: PreflightHoldDisposition,
    ) -> Result<ToolCallResponse, KernelError> {
        self.evaluate_tool_call_async_with_session_context_tracking_replay(
            request,
            session_filesystem_roots,
            extra_metadata,
            session_id,
            security_context,
            preflight_disposition,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn evaluate_tool_call_async_with_session_context_tracking_replay(
        &self,
        request: &ToolCallRequest,
        session_filesystem_roots: Option<&[String]>,
        extra_metadata: Option<serde_json::Value>,
        session_id: Option<&SessionId>,
        security_context: Option<&SecurityInvocationContext>,
        preflight_disposition: PreflightHoldDisposition,
        caller_reservation_replayed: Option<&std::sync::atomic::AtomicBool>,
    ) -> Result<ToolCallResponse, KernelError> {
        request.validate()?;
        self.validate_security_invocation_context_binding(request, security_context, session_id)?;
        // Resolve tenant_id from the session's enterprise identity context
        // (if any) and install it for the remainder of this evaluation so
        // every receipt `build_and_sign_receipt` signs picks up the tag.
        let tenant_id = security_context
            .map(|context| context.as_v1().tenant_id().as_str().to_string())
            .or_else(|| self.resolve_tenant_id_for_session(session_id));
        let _tenant_request_scope =
            self.scope_receipt_tenant_id_for_request(&request.request_id, tenant_id.clone());
        let _tenant_scope = scope_receipt_tenant_id(tenant_id);

        let now_unix_ms = current_unix_timestamp_ms();
        let now = now_unix_ms / 1000;

        // Emergency kill switch: every evaluate path checks the flag
        // before receipt negotiation, capability validation, guard evaluation,
        // or budget mutation so a stopped kernel cannot be coerced into doing
        // any work or peer lookup.
        if self.is_emergency_stopped() {
            warn!(
                request_id = %request.request_id,
                "emergency stop active -- denying evaluate_tool_call"
            );
            return self.build_emergency_stop_deny_response_with_metadata(
                request,
                EMERGENCY_STOP_DENY_REASON,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        // RSS soft ceiling: shed new admissions before the OS OOM-kills the
        // mediator. Checked on the same atomic-load fast path as the emergency
        // stop, right after it.
        if self.is_rss_shedding() {
            warn!(
                request_id = %request.request_id,
                "rss soft ceiling exceeded -- shedding evaluate_tool_call"
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

        // Receipt-version negotiation is a TRUST-BOUNDARY admission check
        // that must run BEFORE any dispatch path. The admission snapshot is
        // scoped for every receipt builder below so persistence and federation cosign
        // use the peer/version/key material admitted before side effects.
        // PROTOCOL.md section 6 normative MUST.
        let receipt_admission = match self
            .kernel_receipt_admission_for_remote(request.federated_origin_kernel_id.as_deref(), now)
        {
            Ok(admission) => admission,
            Err(error) => {
                let msg = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&msg),
                    "receipt federation admission failed pre-dispatch"
                );
                return self.build_negotiation_failclosed_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
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
            "evaluating tool call"
        );

        // Confirm durable persistence is healthy before any path that records a
        // receipt. Both the capability-rejection denials below and the
        // capability-lineage write persist through the receipt writer; against a
        // serving-closed writer that append fails and would surface its own error
        // (or a 500) instead of a clean signed fail-closed Deny. Gating here means
        // a degraded writer always produces the dedicated persistence Deny first.
        if let Err(error) = self.ensure_federated_receipt_persistence_ready(
            request.federated_origin_kernel_id.as_deref(),
        ) {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "federated receipt persistence unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }
        if let Err(error) = self.ensure_tcb_locks_healthy() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "tcb lock poisoned pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }
        if let Err(error) = self.ensure_receipt_persistence_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "receipt persistence unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }
        if let Err(error) = self.ensure_revocation_durability_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "revocation durability unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        let cap = &request.capability;

        // Signature is verified first (no budget mutation); the actual
        // `admit_capability_budget` call is deferred until all
        // subsequent checks (time, revocation, delegation-admission,
        // subject, scope, guards) have passed. Otherwise a denied call
        // would still consume the parent's share, starving later valid
        // siblings.
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
                extra_metadata.clone(),
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
                extra_metadata.clone(),
            );
        }

        if let Err(e) = self.check_revocation(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = self.validate_delegation_admission(cap) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(e) = check_subject_binding(cap, &request.agent_id) {
            let msg = e.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
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
                    extra_metadata.clone(),
                );
            }
        };

        let reserving_preflight = matches!(
            preflight_disposition,
            PreflightHoldDisposition::ReserveForCaller
        ) && self.execution_nonce_preflight_required(request);
        if reserving_preflight {
            self.ensure_caller_reservation_handoff_replay_read_ready(request)?;
            match self.probe_caller_reservation_handoff_after_authentication(
                request,
                extra_metadata.as_ref(),
            )? {
                CallerReservationReplayProbe::Absent => {
                    self.ensure_caller_reservation_handoff_publication_ready(request)?;
                }
                CallerReservationReplayProbe::Conflict => {
                    return Err(KernelError::CallerReservationConflict(
                        "request id is already bound to a different or non-replayable caller reservation"
                            .to_string(),
                    ))
                }
                CallerReservationReplayProbe::Replayed(response) => {
                    if let Some(replayed) = caller_reservation_replayed {
                        replayed.store(true, std::sync::atomic::Ordering::Release);
                    }
                    return Ok(response);
                }
            }
        }

        // DPoP enforcement happens only after the exact replay gate. An exact
        // caller-reservation retry carries the already-consumed original proof
        // in its frozen request and must replay without consuming it again. An
        // absent request still verifies and consumes DPoP before any mutation.
        if matching_grants
            .iter()
            .any(|m| m.grant.dpop_required == Some(true))
        {
            if let Err(e) = self.verify_dpop_for_request(request, cap) {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "DPoP verification failed");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        }

        // The reserve-for-caller authorization path never dispatches a tool on
        // this kernel, so it must not require the caller's tool server to be
        // registered; the sidecar can then avoid registering caller-arbitrary
        // server ids (unbounded growth). Every other path, including a
        // ReserveForCaller request that falls through to dispatch because no nonce
        // preflight is required, still requires registration exactly as before.
        if !reserving_preflight {
            if let Err(e) = self.ensure_registered_tool_target(request) {
                let msg = e.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool target not registered");
                return self.build_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    None,
                    extra_metadata.clone(),
                );
            }
        }

        if let Err(error) =
            self.record_observed_capability_snapshot_for_dispatch(cap, security_context)
        {
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "failed to persist capability lineage");
            return self.build_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        if let Err(error) = self.ensure_federated_receipt_persistence_ready(
            request.federated_origin_kernel_id.as_deref(),
        ) {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "federated receipt persistence unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }
        if let Err(error) = self.ensure_receipt_persistence_ready() {
            let msg = error.to_string();
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&msg),
                "receipt persistence unavailable pre-dispatch"
            );
            return self.build_receipt_persistence_failclosed_deny_response_with_metadata(
                request,
                &msg,
                now,
                None,
                extra_metadata.clone(),
            );
        }

        // Select the most-specific matching grant before any authoritative
        // mutation. Falling through from an exhausted specific grant to a
        // broader grant would also change the governance and guard contract
        // after those checks ran, so admission is pinned to this candidate.
        let matched = matching_grants.first().copied().ok_or_else(|| {
            KernelError::Internal("matching grant set unexpectedly empty".to_string())
        })?;
        let matched_grant_index = matched.index;
        let matched_grant = matched.grant;

        let validated_governed_admission = match self.validate_governed_transaction(
            request,
            cap,
            matched_grant,
            None,
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
                    extra_metadata.clone(),
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
            None,
            validated_governed_admission
                .as_ref()
                .and_then(|admission| admission.call_chain_proof.clone()),
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                let msg = error.to_string();
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed call-chain evidence lookup failed");
                return self.build_monetary_deny_response_with_metadata(
                    request,
                    &msg,
                    now,
                    std::slice::from_ref(&matched),
                    cap,
                    extra_metadata.clone(),
                );
            }
        };
        let _governed_call_chain_receipt_evidence_scope =
            scope_governed_call_chain_receipt_evidence(governed_call_chain_receipt_evidence);

        let pre_invocation_guard_evidence = match self
            .run_guards_within_budget(
                request,
                &cap.scope,
                session_filesystem_roots,
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
                        extra_metadata.clone(),
                    )
                });
            }
        };

        let verified_governed_approval = validated_governed_admission
            .as_ref()
            .and_then(|admission| admission.verified_governed_approval.as_ref());
        if validated_governed_admission.is_none() {
            if let Some(response) = self
                .try_evaluate_agent_economy_tool_call(
                    request,
                    matched,
                    &pre_invocation_guard_evidence,
                    extra_metadata.clone(),
                    security_context,
                    now,
                    now_unix_ms,
                )
                .await?
            {
                return Ok(response);
            }
        }
        if verified_governed_approval.is_some()
            && self.execution_nonce_preflight_required(request)
            && matches!(
                preflight_disposition,
                PreflightHoldDisposition::ReverseForRetry
            )
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
        let (mut extra_metadata, budget_mutation, mut threshold_dispatch_permit) = if let Some(
            verified_approval,
        ) =
            verified_governed_approval
        {
            let protocol_admission =
                self.prepare_threshold_protocol_admission(request, cap, matched_grant_index, now)?;
            let request_fingerprint_hash = self.ordinary_request_fingerprint_hash(
                request,
                &self.config.policy_hash,
                caller_receipt_metadata.as_ref(),
            )?;
            let prepared = crate::threshold_approval::prepare_governed_tool_admission_operation(
                crate::threshold_approval::GovernedToolAdmissionOperationInput {
                    coordinator_authority_id: &format!("kernel:{}", self.public_key().to_hex()),
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
                    supplemental_authorization_digest: protocol_admission.supplemental_digest(),
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
            let threshold_runtime_metadata =
                merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
            if !runtime_admission.allowed {
                let msg = runtime_admission
                    .reason
                    .unwrap_or_else(|| "runtime admission denied".to_string());
                let deny_metadata = self
                    .release_runtime_admission_reservations_for_pre_dispatch_denial(
                        threshold_runtime_metadata,
                    );
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied");
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
            // Threshold admission may authorize payment while it reserves the
            // coordinated operation, so its durable dispatch intent must exist
            // before entering that coordinator. Keep the request-scoped handle
            // alive across every terminal response below so the first committed
            // receipt consumes it.
            let threshold_has_monetary =
                self.ordinary_payment_charge_terms(matched_grant).is_some()
                    || Self::is_governed_mustprepay_request(request);
            match self.record_dispatch_intent_if_side_effecting(
                request,
                threshold_has_monetary,
                now_unix_ms,
            ) {
                Ok(Some(handle)) => {
                    _threshold_dispatch_intent_scope = Some(
                        self.scope_dispatch_intent_for_request(&request.request_id, Some(handle)),
                    );
                }
                Ok(None) => {}
                Err(error) => {
                    let msg = error.to_string();
                    let deny_metadata = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            threshold_runtime_metadata,
                        );
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&msg),
                        "dispatch intent write failed; denying before threshold admission"
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
            let threshold_runtime_metadata = if reserving_preflight {
                self.release_runtime_admission_reservations_for_pre_dispatch_denial(
                    threshold_runtime_metadata,
                )
            } else {
                threshold_runtime_metadata
            };
            let prepared_operation = prepared.operation().clone();
            let reserved = self.reserve_threshold_tool_admission(
                ThresholdToolAdmissionContext {
                    request,
                    cap,
                    grant_index: matched_grant_index,
                    grant: matched_grant,
                    now,
                    payment_mode: if reserving_preflight {
                        ThresholdPaymentMode::CallerReservation
                    } else {
                        ThresholdPaymentMode::Dispatch
                    },
                },
                prepared,
                protocol_admission,
                reserving_preflight.then_some(ThresholdCallerReservationHandoffContext {
                    runtime_response_metadata: threshold_runtime_metadata.as_ref(),
                    caller_receipt_metadata: caller_receipt_metadata.as_ref(),
                }),
            );
            let (permit, mutation) = match reserved {
                Ok(reserved) => reserved,
                Err(error) => {
                    let mut deny_metadata = if reserving_preflight {
                        threshold_runtime_metadata
                    } else {
                        self.release_runtime_admission_reservations_for_pre_dispatch_denial(
                            threshold_runtime_metadata,
                        )
                    };
                    if let Some(metadata) =
                        self.exact_compensated_threshold_admission_metadata(&prepared_operation)?
                    {
                        deny_metadata = merge_metadata_objects(deny_metadata, Some(metadata));
                        let msg = error.to_string();
                        warn!(request_id = %request.request_id, reason = %redacted!(&msg), "governed admission compensated before dispatch");
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
            let extra_metadata =
                merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
            if !runtime_admission.allowed {
                let msg = runtime_admission
                    .reason
                    .unwrap_or_else(|| "runtime admission denied".to_string());
                let extra_metadata = self
                    .release_runtime_admission_reservations_for_pre_dispatch_denial(extra_metadata);
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied");
                return self.with_pre_invocation_guard_evidence(
                    &pre_invocation_guard_evidence,
                    || {
                        self.build_runtime_admission_monetary_deny_response_with_metadata(
                            request,
                            &msg,
                            now,
                            std::slice::from_ref(&matched),
                            cap,
                            extra_metadata,
                        )
                    },
                );
            }
            let (authorized_grant_index, mutation) = match self.check_and_increment_budget(
                request,
                cap,
                std::slice::from_ref(&matched),
                reserving_preflight,
                caller_receipt_metadata.as_ref(),
            ) {
                Ok(result) => result,
                Err(error) => {
                    let msg = error.to_string();
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "capability rejected");
                    let deny_metadata = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            extra_metadata,
                        );
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
                    "budget authority admitted a grant other than the validated grant".to_string(),
                ));
            }
            (extra_metadata, mutation, None)
        };
        let authorized_grant_index = matched_grant_index;
        if authorized_grant_index != matched_grant_index {
            return Err(KernelError::Internal(
                "budget authority admitted a grant other than the validated grant".to_string(),
            ));
        }
        if threshold_dispatch_permit
            .as_ref()
            .is_some_and(ThresholdDispatchPermit::preexisting_operation)
            || budget_mutation
                .ordinary_admission()
                .is_some_and(OrdinaryAdmissionMutation::preexisting_operation)
        {
            if let Some(replayed) = caller_reservation_replayed {
                replayed.store(true, std::sync::atomic::Ordering::Release);
            }
        }

        if let Some(verified_approval) = validated_governed_admission
            .as_ref()
            .and_then(|admission| admission.verified_governed_approval.as_ref())
        {
            debug!(
                request_id = %request.request_id,
                approval_set_hash = %verified_approval.approval_set_hash(),
                "governed approval set verified"
            );
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
                                runtime_admission_metadata: extra_metadata,
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
                match preflight_disposition {
                    PreflightHoldDisposition::ReverseForRetry => self
                        .build_execution_nonce_preflight_allow_response_after_cleanup(
                            request,
                            now,
                            matched_grant_index,
                            cap,
                            &budget_mutation,
                            threshold_dispatch_permit
                                .as_ref()
                                .and_then(ThresholdDispatchPermit::payment_authorization),
                            extra_metadata,
                            budget_lease_acquired,
                        ),
                    PreflightHoldDisposition::ReserveForCaller => {
                        let threshold_handoff_prepared = threshold_dispatch_permit.is_some();
                        let extra_metadata = if threshold_handoff_prepared {
                            extra_metadata
                        } else {
                            self.release_runtime_admission_reservations_for_pre_dispatch_denial(
                                extra_metadata,
                            )
                        };
                        if !threshold_handoff_prepared {
                            if let PreExecutionBudgetMutation::Admission(admission) =
                                &budget_mutation
                            {
                                let response_metadata = self.caller_reservation_response_metadata(
                                    &budget_mutation,
                                    extra_metadata.clone(),
                                )?;
                                if let Err(error) = self
                                    .prepare_operation_owned_caller_reservation_handoff(
                                        request,
                                        now,
                                        matched_grant_index,
                                        admission,
                                        response_metadata,
                                        caller_receipt_metadata.as_ref(),
                                    )
                                {
                                    let msg = error.to_string();
                                    warn!(
                                        request_id = %request.request_id,
                                        reason = %redacted!(&msg),
                                        "caller reservation handoff intent persistence failed"
                                    );
                                    return self.build_pre_dispatch_cleanup_deny_response(
                                        PreDispatchCleanupDeny {
                                            request,
                                            reason: &msg,
                                            timestamp: now,
                                            matched_grant_index,
                                            cap,
                                            budget_mutation: &budget_mutation,
                                            payment_authorization: None,
                                            runtime_admission_metadata: extra_metadata,
                                            budget_lease_acquired,
                                        },
                                    );
                                }
                            }
                        }
                        // MustPrepay authorization and capture are external
                        // financial effects. Operation-owned invocation capture is
                        // also an irreversible admission effect. Journal and scope
                        // the dispatch intent before either can run. The reserve or
                        // denial receipt consumes the row. Threshold admission
                        // installed its request-scoped intent before entering the
                        // coordinator, so only the ordinary path writes one here.
                        let _reserve_dispatch_intent_scope = if threshold_dispatch_permit
                            .is_none()
                            && (Self::is_governed_mustprepay_request(request)
                                || budget_mutation.ordinary_admission().is_some())
                        {
                            let dispatch_intent = match self
                                .record_dispatch_intent_if_side_effecting(request, true, now_unix_ms)
                            {
                                Ok(handle) => handle,
                                Err(error) => {
                                    let msg = error.to_string();
                                    warn!(
                                        request_id = %request.request_id,
                                        reason = %redacted!(&msg),
                                        "dispatch intent write failed; denying before reserve prepayment"
                                    );
                                    return self.build_pre_dispatch_cleanup_deny_response(
                                        PreDispatchCleanupDeny {
                                            request,
                                            reason: &msg,
                                            timestamp: now,
                                            matched_grant_index,
                                            cap,
                                            budget_mutation: &budget_mutation,
                                            payment_authorization: None,
                                            runtime_admission_metadata: extra_metadata,
                                            budget_lease_acquired,
                                        },
                                    );
                                }
                            };
                            Some(self.scope_dispatch_intent_for_request(
                                &request.request_id,
                                dispatch_intent,
                            ))
                        } else {
                            None
                        };
                        // A governed MustPrepay intent must have prepaid before a
                        // reserved nonce is minted: this kernel never dispatches the
                        // tool on the reserve path, so there is no later point to
                        // settle the payment. Deny fail-closed (reversing the hold and
                        // releasing the admitted share) when the prepayment cannot be
                        // authorized or settled, so no nonce is handed out unpaid.
                        let settled_prepayment =
                            match self.ensure_reserved_mustprepay_prepaid(
                                request,
                                budget_mutation.charge_result(),
                                budget_mutation.admission_operation_binding(),
                                threshold_dispatch_permit
                                    .as_ref()
                                    .and_then(ThresholdDispatchPermit::payment_authorization),
                            ) {
                                Ok(settled_prepayment) => settled_prepayment,
                                Err(error) => {
                                    let msg = error.to_string();
                                    warn!(
                                        request_id = %request.request_id,
                                        reason = %redacted!(&msg),
                                        "reserve-for-caller prepayment gate denied"
                                    );
                                    return self.build_pre_dispatch_cleanup_deny_response(
                                        PreDispatchCleanupDeny {
                                            request,
                                            reason: &msg,
                                            timestamp: now,
                                            matched_grant_index,
                                            cap,
                                            budget_mutation: &budget_mutation,
                                            payment_authorization: None,
                                            runtime_admission_metadata: extra_metadata,
                                            budget_lease_acquired,
                                        },
                                    );
                                }
                            };
                        // A settled MustPrepay prepayment is captured before the
                        // reservation is issued. Carry its rail reference onto the
                        // reserved hold so the downstream reconcile receipt can name
                        // the transaction that funded the spend. A failure proven to
                        // precede invocation capture compensates the hold and refunds
                        // this prepayment. Once the operation is capture-pending or
                        // caller-reserved, neither effect may be reversed from an
                        // ambiguous acknowledgement.
                        let reserved_payment_reference = settled_prepayment
                            .as_ref()
                            .and_then(|prepayment| prepayment.payment_reference.clone());
                        match self.build_execution_nonce_authorization_reserving_response(
                            ExecutionNonceReservingResponse {
                                request,
                                timestamp: now,
                                matched_grant_index,
                                budget_mutation: &budget_mutation,
                                runtime_admission_metadata: extra_metadata,
                                caller_receipt_metadata: caller_receipt_metadata.as_ref(),
                                reserved_payment_reference,
                                budget_lease_acquired,
                                threshold_supplemental_prepared: threshold_dispatch_permit
                                    .is_some(),
                            },
                        ) {
                            Ok(response) => Ok(response),
                            Err(error) => {
                                let may_refund_prepayment = budget_mutation
                                    .ordinary_admission()
                                    .is_none_or(|admission| {
                                        self.load_ordinary_admission(admission.operation_id())
                                            .is_ok_and(|operation| {
                                                operation.state()
                                                    == AdmissionOperationState::CompensatedBeforeDispatch
                                            })
                                    });
                                if may_refund_prepayment {
                                    if let Some(prepayment) = settled_prepayment.as_ref() {
                                        self.refund_reserved_mustprepay_prepayment(
                                            request,
                                            &budget_mutation,
                                            prepayment,
                                        );
                                    }
                                }
                                Err(error)
                            }
                        }
                    }
                }
            });
        }

        // For a side-effecting or monetary call, durably journal a dispatch
        // intent BEFORE the earliest possible effect (the prepaid authorize
        // below, or tool dispatch), so a crash in the effect-to-receipt window
        // leaves a durable trace to reconcile at the next boot. On failure,
        // reverse every pre-execution hold through the same pre-dispatch
        // unwind the admission and authorize arms use, then deny before any
        // effect. Read-only calls return None here and pay nothing.
        let has_monetary = budget_mutation.charge_result().is_some()
            || Self::is_governed_mustprepay_request(request);
        // Threshold admission installed its intent before entering the
        // coordinator because that coordinator can authorize payment. Ordinary
        // admission reaches its first external effect here, after preflight.
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
                        "dispatch intent write failed; denying before dispatch"
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
                                payment_authorization: None,
                                runtime_admission_metadata: extra_metadata.clone(),
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

        let payment_authorization = if let Some(permit) = threshold_dispatch_permit.as_ref() {
            permit.payment_authorization().cloned()
        } else {
            match self.authorize_payment_if_needed(
                request,
                budget_mutation.charge_result(),
                budget_mutation.admission_operation_binding(),
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
                                payment_authorization: None,
                                runtime_admission_metadata: extra_metadata.clone(),
                                budget_lease_acquired,
                            })
                        },
                    );
                }
            }
        };

        // Bind the rail authorization to the open intent so a crash orphan
        // identifies the exact external transaction an operator must reconcile.
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
                        "dispatch intent rail-ref attach failed"
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
                            runtime_admission_metadata: extra_metadata.clone(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        }

        // Resolve the kernel-local target before dispatch is marked started.
        // This is the only ToolNotRegistered condition that proves no connector
        // code ran and therefore still qualifies for full pre-dispatch reversal.
        if !self.tool_servers.contains_key(&request.server_id) {
            let error = KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ));
            let msg = error.to_string();
            warn!(request_id = %request.request_id, reason = %redacted!(&msg), "tool server error");
            return self.with_pre_invocation_guard_evidence(&pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &msg,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation: &budget_mutation,
                    payment_authorization: payment_authorization.as_ref(),
                    runtime_admission_metadata: extra_metadata.clone(),
                    budget_lease_acquired,
                })
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
                        payment_authorization: payment_authorization.as_ref(),
                        runtime_admission_metadata: extra_metadata,
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
                    extra_metadata = merge_metadata_objects(extra_metadata, Some(metadata));
                }
                Err(error) => {
                    let operation_metadata =
                        self.refresh_threshold_dispatch_permit_metadata(permit)?;
                    extra_metadata =
                        merge_metadata_objects(extra_metadata, Some(operation_metadata));
                    if permit.operation().state()
                        == AdmissionOperationState::CompensatedBeforeDispatch
                    {
                        extra_metadata = self
                            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                                extra_metadata,
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
                                extra_metadata.clone(),
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
                    extra_metadata = merge_metadata_objects(extra_metadata, Some(metadata));
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
                                    extra_metadata.clone(),
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
                                        runtime_admission_metadata: extra_metadata.clone(),
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
                extra_metadata: extra_metadata.clone(),
                pre_invocation_guard_evidence: pre_invocation_guard_evidence.clone(),
            },
            budget_lease_acquired,
        );
        if let Some(permit) = threshold_dispatch_permit.as_ref() {
            post_admission_drop_guard.bind_threshold_operation(permit.operation().clone());
        }
        post_admission_drop_guard.bind_security_dispatch_outcome(security_dispatch_outcome.take());
        post_admission_drop_guard.mark_dispatch_started();
        let dispatch_result = self.dispatch_within_budget(request, has_monetary).await;
        security_dispatch_outcome = post_admission_drop_guard.take_security_dispatch_outcome();
        post_admission_drop_guard.disarm();
        drop(post_admission_drop_guard);
        let security_dispatch_outcome_error = security_dispatch_outcome
            .take()
            .map(|outcome| match &dispatch_result {
                Ok((ToolServerOutput::Value(_), _))
                | Ok((ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)), _)) => {
                    outcome.record_released()
                }
                Ok((ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { .. }), _))
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
                match &dispatch_result {
                    Ok((ToolServerOutput::Value(_), _))
                    | Ok((ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)), _)) => (
                        AdmissionOperationState::Completed,
                        AdmissionDispatchState::EffectCompleted,
                        None,
                    ),
                    Ok((
                        ToolServerOutput::Stream(ToolServerStreamResult::Incomplete {
                            reason, ..
                        }),
                        _,
                    )) => (
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
            extra_metadata = merge_metadata_objects(extra_metadata, Some(metadata));
            Some(scope)
        } else {
            None
        };
        let (tool_output, reported_cost) = match dispatch_result {
            Ok(result) => result,
            Err(error @ KernelError::UrlElicitationsRequired { .. }) => {
                // Connector code was entered before this error was returned, so
                // the variant is not proof that no side effect occurred. Retain
                // invocation usage and fail-closed runtime/delegation leases,
                // while releasing only payment and monetary exposure. Preserve
                // the UrlElicitationsRequired return shape for edge handling.
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let metadata = self.post_dispatch_cleanup_receipt_metadata(
                    extra_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                )?;
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
            Err(KernelError::RequestCancelled { reason, .. }) => {
                let cleanup = self.release_post_dispatch_monetary_invocation(
                    request,
                    cap,
                    &budget_mutation,
                    payment_authorization.as_ref(),
                    threshold_dispatch_permit.is_some(),
                );
                let cleanup_metadata = self.post_dispatch_cleanup_receipt_metadata(
                    extra_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                )?;
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
                    extra_metadata.clone(),
                    budget_mutation.charge_result(),
                    &cleanup,
                )?;
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "tool call deadline expired"
                );
                // A timed-out dispatch may already have applied its side effect,
                // so the runtime-admission reservation is NOT released; it is
                // retained and marked auditable, exactly as the cancellation arm
                // does. Releasing here would be fail-open: a single-use
                // destructive lease could be replayed after the destructive
                // action already executed.
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
                    extra_metadata.clone(),
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
            Err(e) => {
                let msg = e.to_string();
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
                    extra_metadata.clone(),
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
                        reported_cost,
                        payment_authorization,
                        cap,
                    },
                    security_context,
                    extra_metadata,
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
