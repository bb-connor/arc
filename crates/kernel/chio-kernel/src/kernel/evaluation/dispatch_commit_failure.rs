//! Keep definite pre-commit rejection distinct from an unconfirmed store commit.

use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;
use crate::kernel::credential_reservation::DispatchCredentialReservation;

impl ChioKernel {
    /// A rejected security or local-freeze decision never authorizes a tool
    /// effect. Resolve this attempt's reversible credentials before signing the
    /// denial, preserving prior payment or irreversible nonce retention.
    pub(super) fn build_pre_commit_credential_rejection_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        credentials: DispatchCredentialReservation<'_>,
        evidence: &[chio_core::receipt::metadata::GuardEvidence],
    ) -> Result<ToolCallResponse, KernelError> {
        let mut reason = denial.reason.to_owned();
        let disposition = if denial.payment_authorization.is_some() {
            credentials.retention_disposition()
        } else {
            match credentials.rollback_before_dispatch_with_disposition() {
                Ok(disposition) => disposition,
                Err(error) => {
                    reason = format!("{reason}; {error}");
                    PaymentCredentialDisposition::RetentionOutcomeUnknown
                }
            }
        };
        self.with_pre_invocation_guard_evidence(evidence, || {
            self.build_pre_dispatch_cleanup_deny_response_with_credentials(
                PreDispatchCleanupDeny {
                    reason: &reason,
                    ..denial
                },
                disposition,
            )
        })
    }

    pub(super) fn build_durable_dispatch_failure_response(
        &self,
        failure: DurableDispatchCommitError,
        denial: PreDispatchCleanupDeny<'_>,
        credentials: DispatchCredentialReservation<'_>,
        evidence: &[chio_core::receipt::metadata::GuardEvidence],
        security_outcome: Option<SecurityDispatchOutcomeHandle>,
    ) -> Result<ToolCallResponse, KernelError> {
        let response = self.with_pre_invocation_guard_evidence(evidence, || {
            match failure {
                DurableDispatchCommitError::RejectedBeforeCommit(_) => self
                    .build_pre_commit_credential_rejection_response(denial, credentials, evidence),
                DurableDispatchCommitError::CommitUnconfirmed(_) => {
                    // Do not infer nonexecution from an error returned after
                    // entering the store. Original holds and credentials remain
                    // owned for authoritative recovery, never optimistic refund.
                    self.build_deny_response_with_metadata_and_payee_binding(
                        denial.request,
                        denial.reason,
                        denial.timestamp,
                        Some(denial.matched_grant_index),
                        self.ambiguous_dispatch_receipt_metadata(
                            denial.budget_mutation,
                            denial.payment_authorization,
                            denial.runtime_admission_metadata,
                        ),
                        denial.verified_payee_binding,
                    )
                }
            }
        });
        if let Some(outcome) = security_outcome {
            outcome.record_dispatch_failed()?;
        }
        response
    }
}
