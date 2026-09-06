//! Strict-nonce preflight of the async evaluation core.

use super::evaluation_helpers::{ExecutionNonceReservingResponse, PreDispatchCleanupDeny};
use super::*;
use crate::kernel::dispatch::dispatch_admission_error_reason;

/// Evaluation state at the strict-nonce preflight: every admission check has
/// passed, the pre-execution hold is reserved, and no execution nonce was
/// presented on the request.
pub(super) struct StrictNoncePreflight<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) session_filesystem_roots: Option<&'a [String]>,
    pub(super) session_id: Option<&'a SessionId>,
    pub(super) security_context: Option<&'a SecurityInvocationContext>,
    pub(super) preflight_disposition: PreflightHoldDisposition,
    pub(super) receipt_admission: &'a ReceiptFederationAdmission,
    pub(super) now: u64,
    pub(super) cap: &'a CapabilityToken,
    pub(super) matching_grants: &'a [MatchingGrant<'a>],
    pub(super) dpop_required: bool,
    pub(super) matched_grant_index: usize,
    pub(super) matched_grant: &'a ToolGrant,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) durable_admission: &'a mut Option<DurableToolAdmission>,
    pub(super) extra_metadata: Option<serde_json::Value>,
    pub(super) pre_invocation_guard_evidence: &'a [GuardEvidence],
    pub(super) verified_governed_payee_binding: &'a Option<VerifiedGovernedPayeeBinding>,
    pub(super) budget_lease_acquired: bool,
}

impl ChioKernel {
    /// Settle the reserved hold per the preflight disposition without
    /// dispatching the tool: reverse it for a retry, or keep it open and hand
    /// the caller a non-authoritative authorization carrying the minted nonce.
    pub(super) async fn run_async_strict_nonce_preflight(
        &self,
        preflight: StrictNoncePreflight<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let StrictNoncePreflight {
            request,
            session_filesystem_roots,
            session_id,
            security_context,
            preflight_disposition,
            receipt_admission,
            now,
            cap,
            matching_grants,
            dpop_required,
            matched_grant_index,
            matched_grant,
            budget_mutation,
            durable_admission,
            extra_metadata,
            pre_invocation_guard_evidence,
            verified_governed_payee_binding,
            budget_lease_acquired,
        } = preflight;
        // Nonce-preflight authorizes without producing output: reserve-
        // for-caller settles a prepayment and reverse-for-retry mints a
        // nonce, neither reaching an output-aware terminal. An
        // output-digest grant cannot be enforced here, so reject before
        // any mint or capture.
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
            return self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason,
                    timestamp: now,
                    matched_grant_index,
                    cap,
                    budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: extra_metadata.clone(),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        }
        if preflight_disposition == PreflightHoldDisposition::ReverseForRetry {
            return self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                self.build_execution_nonce_preflight_allow_response_after_cleanup(
                    request,
                    now,
                    matched_grant_index,
                    cap,
                    budget_mutation,
                    durable_admission.as_mut(),
                    extra_metadata,
                    budget_lease_acquired,
                )
            });
        }

        let governed_mustprepay = Self::is_governed_mustprepay_request(request);
        let mut credential_reservation = match self.reserve_caller_authorization_credentials(
            request,
            cap,
            dpop_required,
            now,
            governed_mustprepay,
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                let reason = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "reserve-for-caller credential reservation denied"
                );
                return self.with_pre_invocation_guard_evidence(
                    pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                            request,
                            reason: &reason,
                            timestamp: now,
                            matched_grant_index,
                            cap,
                            budget_mutation,
                            payment_authorization: None,
                            durable_operation: durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata: extra_metadata.clone(),
                            verified_payee_binding: verified_governed_payee_binding.as_ref(),
                            budget_lease_acquired,
                        })
                    },
                );
            }
        };

        let revalidation_now_unix_ms = current_unix_timestamp_ms();
        let readiness_result = {
            let mut readiness_drop_guard = PostAdmissionDropGuard::new(
                self,
                request,
                cap,
                Some(matched_grant_index),
                budget_mutation,
                None,
                PostAdmissionReceiptContext {
                    extra_metadata: extra_metadata.clone(),
                    pre_invocation_guard_evidence: pre_invocation_guard_evidence.to_vec(),
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
                .wait_for_runtime_admission_dispatch_readiness(request)
                .await;
            readiness_drop_guard.disarm();
            result
        };
        let reserve_authorization_admission = match readiness_result {
            Ok(readiness_waited) => self
                .revalidate_immediately_before_dispatch(
                    request,
                    dpop_required,
                    matched_grant,
                    matched_grant_index,
                    None,
                    session_id,
                    session_filesystem_roots,
                    security_context,
                    receipt_admission,
                    extra_metadata.as_ref(),
                    true,
                    false,
                    readiness_waited
                        || credential_reservation.requires_post_reservation_revalidation(),
                    revalidation_now_unix_ms / 1000,
                    revalidation_now_unix_ms,
                )
                .map(|_| ()),
            Err(error) => Err(error),
        };
        if let Err(error) = reserve_authorization_admission {
            let mut reason = dispatch_admission_error_reason(&error);
            let credential_disposition =
                if let Err(rollback_error) = credential_reservation.rollback_before_dispatch() {
                    reason = format!("{reason}; {rollback_error}");
                    PaymentCredentialDisposition::RetentionOutcomeUnknown
                } else {
                    PaymentCredentialDisposition::NonePresent
                };
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&reason),
                "reserve-for-caller revalidation denied"
            );
            return self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                let denial = PreDispatchCleanupDeny {
                    request,
                    reason: &reason,
                    timestamp: revalidation_now_unix_ms / 1000,
                    matched_grant_index,
                    cap,
                    budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: error.denied_metadata(&extra_metadata),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                };
                if credential_disposition == PaymentCredentialDisposition::RetentionOutcomeUnknown {
                    self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                        denial,
                        credential_disposition,
                    )
                } else {
                    self.build_pre_dispatch_cleanup_deny_response(denial)
                }
            });
        }

        if governed_mustprepay && !credential_reservation.has_payment_authorization_credential() {
            let mut reason =
                "strict reserve-for-caller payment authorization omitted its governed replay marker"
                    .to_string();
            if let Err(rollback_error) = credential_reservation.rollback_before_dispatch() {
                reason = format!("{reason}; {rollback_error}");
            }
            return self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                self.build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                    request,
                    reason: &reason,
                    timestamp: revalidation_now_unix_ms / 1000,
                    matched_grant_index,
                    cap,
                    budget_mutation,
                    payment_authorization: None,
                    durable_operation: durable_admission
                        .as_ref()
                        .map(DurableToolAdmission::operation),
                    runtime_admission_metadata: extra_metadata.clone(),
                    verified_payee_binding: verified_governed_payee_binding.as_ref(),
                    budget_lease_acquired,
                })
            });
        }

        let settled_prepayment = match self.ensure_reserved_mustprepay_prepaid(
            request,
            budget_mutation.charge_result(),
            durable_admission.as_ref(),
            revalidation_now_unix_ms,
            verified_governed_payee_binding.as_ref(),
        ) {
            Ok(prepayment) => prepayment,
            Err(error) => {
                let mut reason = error.to_string();
                let credential_disposition = if governed_mustprepay {
                    match credential_reservation.commit() {
                        Ok(disposition) => disposition,
                        Err(retention_error) => {
                            reason = format!("{reason}; {retention_error}");
                            PaymentCredentialDisposition::RetentionOutcomeUnknown
                        }
                    }
                } else {
                    match credential_reservation.rollback_before_dispatch() {
                        Ok(()) => PaymentCredentialDisposition::NonePresent,
                        Err(rollback_error) => {
                            reason = format!("{reason}; {rollback_error}");
                            PaymentCredentialDisposition::RetentionOutcomeUnknown
                        }
                    }
                };
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "reserve-for-caller prepayment gate denied"
                );
                return self.with_pre_invocation_guard_evidence(
                    pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                            PreDispatchCleanupDeny {
                                request,
                                reason: &reason,
                                timestamp: revalidation_now_unix_ms / 1000,
                                matched_grant_index,
                                cap,
                                budget_mutation,
                                payment_authorization: None,
                                durable_operation: durable_admission
                                    .as_ref()
                                    .map(DurableToolAdmission::operation),
                                runtime_admission_metadata: extra_metadata.clone(),
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                budget_lease_acquired,
                            },
                            credential_disposition,
                        )
                    },
                );
            }
        };

        let credential_disposition = match credential_reservation
            .retain_after_external_authorization()
        {
            Ok(disposition) => disposition,
            Err(error) => {
                let reason = format!(
                    "reserve-for-caller credential retention failed before authorization: {error}"
                );
                return self.with_pre_invocation_guard_evidence(
                    pre_invocation_guard_evidence,
                    || {
                        self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                            PreDispatchCleanupDeny {
                                request,
                                reason: &reason,
                                timestamp: current_unix_timestamp(),
                                matched_grant_index,
                                cap,
                                budget_mutation,
                                payment_authorization: settled_prepayment
                                    .as_ref()
                                    .map(|prepayment| &prepayment.authorization),
                                durable_operation: durable_admission
                                    .as_ref()
                                    .map(DurableToolAdmission::operation),
                                runtime_admission_metadata: extra_metadata.clone(),
                                verified_payee_binding: verified_governed_payee_binding.as_ref(),
                                budget_lease_acquired,
                            },
                            PaymentCredentialDisposition::RetentionOutcomeUnknown,
                        )
                    },
                );
            }
        };

        let reserved_payment_reference = settled_prepayment
            .as_ref()
            .and_then(|prepayment| prepayment.payment_reference.clone());
        let response =
            self.with_pre_invocation_guard_evidence(pre_invocation_guard_evidence, || {
                self.build_execution_nonce_authorization_reserving_response(
                    ExecutionNonceReservingResponse {
                        request,
                        timestamp: now,
                        matched_grant_index,
                        budget_mutation,
                        runtime_admission_metadata: extra_metadata,
                        reserved_payment_reference,
                        budget_lease_acquired,
                    },
                )
            });
        if response.is_err() {
            if let Some(prepayment) = settled_prepayment.as_ref() {
                self.refund_reserved_mustprepay_prepayment(request, &prepayment.authorization);
            }
        }
        let response = response?;
        let committed_disposition = credential_reservation.commit()?;
        debug_assert_eq!(committed_disposition, credential_disposition);
        Ok(response)
    }
}
