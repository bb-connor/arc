//! Strict-nonce preflight of the async evaluation core.

use super::evaluation_helpers::ExecutionNonceReservingResponse;
use super::pre_dispatch_custody::{AdmissionDenial, BudgetedAdmission};
use super::*;
use crate::kernel::dispatch::dispatch_admission_error_reason;
use crate::kernel::responses::PreflightNonceSource;

/// Evaluation state at the strict-nonce preflight: every admission check has
/// passed, the custody holds the reserved pre-execution hold, and no
/// execution nonce was presented on the request.
pub(super) struct StrictNoncePreflight<'a, 'c> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) session_filesystem_roots: Option<&'a [String]>,
    pub(super) session_id: Option<&'a SessionId>,
    pub(super) security_context: Option<&'a SecurityInvocationContext>,
    pub(super) preflight_disposition: PreflightHoldDisposition,
    pub(super) receipt_admission: &'a ReceiptFederationAdmission,
    pub(super) now: u64,
    pub(super) matching_grants: &'a [MatchingGrant<'a>],
    pub(super) dpop_required: bool,
    pub(super) matched_grant: &'a ToolGrant,
    pub(super) custody: BudgetedAdmission<'c>,
}

impl ChioKernel {
    /// Settle the reserved hold per the preflight disposition without
    /// dispatching the tool: reverse it for a retry, or keep it open and hand
    /// the caller a non-authoritative authorization carrying the minted nonce.
    pub(super) async fn run_async_strict_nonce_preflight(
        &self,
        preflight: StrictNoncePreflight<'_, '_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let StrictNoncePreflight {
            request,
            session_filesystem_roots,
            session_id,
            security_context,
            preflight_disposition,
            receipt_admission,
            now,
            matching_grants,
            dpop_required,
            matched_grant,
            mut custody,
        } = preflight;
        let matched_grant_index = custody.matched_grant_index();
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
            return custody.deny(AdmissionDenial::new(reason));
        }
        if preflight_disposition == PreflightHoldDisposition::ReverseForRetry {
            return custody.allow_preflight_retry();
        }

        let governed_mustprepay = Self::is_governed_mustprepay_request(request);
        let credential_reservation = self.reserve_admitted_caller_credentials(
            request,
            dpop_required,
            now,
            custody.durable(),
            matched_grant_index,
        );
        let reservation_requires_revalidation = match credential_reservation {
            Ok(reservation) => {
                let requires_revalidation = reservation.requires_post_reservation_revalidation();
                custody.hold_credentials(reservation);
                requires_revalidation
            }
            Err(error) => {
                let reason = error.to_string();
                warn!(
                    request_id = %request.request_id,
                    reason = %redacted!(&reason),
                    "reserve-for-caller credential reservation denied"
                );
                return custody.deny(AdmissionDenial::new(&reason));
            }
        };

        let revalidation_now_unix_ms = self.read_authority_time()?.get();
        let readiness_result = self
            .wait_for_runtime_admission_dispatch_readiness(request)
            .await;
        let reserve_authorization_admission = match readiness_result {
            Ok(readiness_waited) => self
                .revalidate_immediately_before_dispatch(
                    request,
                    custody.durable(),
                    dpop_required,
                    matched_grant,
                    matched_grant_index,
                    None,
                    session_id,
                    session_filesystem_roots,
                    security_context,
                    receipt_admission,
                    custody.metadata().as_ref(),
                    true,
                    false,
                    readiness_waited || reservation_requires_revalidation,
                    revalidation_now_unix_ms / 1000,
                    revalidation_now_unix_ms,
                )
                .map(|_| ()),
            Err(error) => Err(error),
        };
        if let Err(error) = reserve_authorization_admission {
            let mut reason = dispatch_admission_error_reason(&error);
            let credential_disposition = if let Err(rollback_error) = custody.rollback_credentials()
            {
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
            let metadata = error.denied_metadata(custody.metadata());
            return custody.deny(
                AdmissionDenial::new(&reason)
                    .at(revalidation_now_unix_ms / 1000)
                    .with_metadata(metadata)
                    .with_credentials(credential_disposition),
            );
        }

        if governed_mustprepay
            && !custody
                .credentials()
                .is_ok_and(|credentials| credentials.has_payment_authorization_credential())
        {
            let mut reason =
                "strict reserve-for-caller payment authorization omitted its governed replay marker"
                    .to_string();
            if let Err(rollback_error) = custody.rollback_credentials() {
                reason = format!("{reason}; {rollback_error}");
            }
            return custody.deny(AdmissionDenial::new(&reason).at(revalidation_now_unix_ms / 1000));
        }

        let prepayment = self.ensure_reserved_mustprepay_prepaid(
            request,
            custody.budget().charge_result(),
            custody.durable(),
            revalidation_now_unix_ms,
            custody.payee(),
        );
        let settled_prepayment = match prepayment {
            Ok(prepayment) => prepayment,
            Err(error) => {
                let mut reason = error.to_string();
                let credential_disposition = if governed_mustprepay {
                    match custody
                        .credentials()
                        .and_then(|credentials| credentials.commit())
                    {
                        Ok(disposition) => disposition,
                        Err(retention_error) => {
                            reason = format!("{reason}; {retention_error}");
                            PaymentCredentialDisposition::RetentionOutcomeUnknown
                        }
                    }
                } else {
                    match custody.rollback_credentials() {
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
                return custody.deny(
                    AdmissionDenial::new(&reason)
                        .at(revalidation_now_unix_ms / 1000)
                        .with_credentials(credential_disposition),
                );
            }
        };

        let credential_disposition = match custody
            .credentials()
            .and_then(|credentials| credentials.retain_after_external_authorization())
        {
            Ok(disposition) => disposition,
            Err(error) => {
                let reason = format!(
                    "reserve-for-caller credential retention failed before authorization: {error}"
                );
                if let Some(prepayment) = settled_prepayment.as_ref() {
                    custody.hold_payment(prepayment.authorization.clone());
                }
                return custody.deny(
                    AdmissionDenial::new(&reason)
                        .sampled()
                        .with_credentials(PaymentCredentialDisposition::RetentionOutcomeUnknown),
                );
            }
        };

        let reserved_payment_reference = settled_prepayment
            .as_ref()
            .and_then(|prepayment| prepayment.payment_reference.clone());
        // The reserved hold stays open for the caller that executes the tool.
        custody.settle_with_credentials(|held| {
            let response = self.with_pre_invocation_guard_evidence(held.evidence, || {
                self.build_execution_nonce_authorization_reserving_response(
                    ExecutionNonceReservingResponse {
                        durable_admission: None,
                        request,
                        timestamp: now,
                        matched_grant_index: held.grant_index,
                        budget_mutation: held.budget,
                        runtime_admission_metadata: held.metadata,
                        runtime_reservation: held.runtime,
                        reserved_payment_reference,
                        budget_lease_acquired: held.lease_acquired,
                        nonce: PreflightNonceSource::Mint,
                    },
                )
            });
            if response.is_err() {
                if let Some(prepayment) = settled_prepayment.as_ref() {
                    self.refund_reserved_mustprepay_prepayment(request, &prepayment.authorization);
                }
            }
            let response = response?;
            let committed_disposition = held.credentials.commit()?;
            debug_assert_eq!(committed_disposition, credential_disposition);
            Ok(response)
        })
    }
}
