//! Pre-dispatch custody of one evaluation's admitted resources.
//!
//! The custody owns what an evaluation acquires before dispatch: the durable
//! admission operation, the selected grant's budget mutation and runtime
//! reservation, the sibling-share lease, the dispatch credentials and the
//! payment authorization. Every pre-dispatch exit consumes it. Dropped
//! unconsumed (an early `?`, a panic, or a future dropped at an await) it
//! unwinds those resources exactly as the post-admission drop guard does
//! before dispatch. Dispatch takes the resources back out through
//! [`BudgetedAdmission::into_dispatch`].

use std::ops::ControlFlow;

use super::evaluation_helpers::{PreDispatchCleanupDeny, PreDispatchCleanupOutcome};
use super::*;
use crate::admission_operation::AdmissionOperationV1;
use crate::budget_store::BudgetInvocationCaptureDecision;
use crate::kernel::credential_reservation::DispatchCredentialReservation;

/// The resources one evaluation holds before dispatch, and the receipt
/// context a drop reports a cleanup fault with.
struct AdmissionCustody<'a> {
    kernel: &'a ChioKernel,
    request: &'a ToolCallRequest,
    /// The evaluation's admission sample, in seconds.
    admitted_at: u64,
    armed: bool,
    grant_index: Option<usize>,
    budget: PreExecutionBudgetMutation,
    runtime: RuntimeReservation,
    lease_acquired: bool,
    payment: Option<PaymentAuthorization>,
    metadata: Option<serde_json::Value>,
    /// `None` until a grant is selected with its guard evidence. A denial
    /// signed without evidence leaves the ambient evidence scope untouched.
    evidence: Option<Vec<GuardEvidence>>,
    payee: Option<VerifiedGovernedPayeeBinding>,
    credentials: Option<DispatchCredentialReservation<'a>>,
    /// Declared last so its live owner outlives both the Drop body's
    /// compensation and the credential release that follows it.
    durable: Option<DurableToolAdmission>,
}

impl Drop for AdmissionCustody<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let custody = &*self;
        let compensation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(test)]
            if PANIC_DURING_COMPENSATION.with(std::cell::Cell::get) {
                panic!("injected pre-dispatch custody compensation panic");
            }
            drop(custody.pre_dispatch_guard());
        }));
        if compensation.is_err() {
            warn!(
                request_id = %self.request.request_id,
                audit_fault = "admission_custody_drop_panicked",
                "pre-dispatch custody compensation panicked; recovery owns the admitted resources"
            );
        }
    }
}

#[cfg(test)]
thread_local! {
    pub(crate) static PANIC_DURING_COMPENSATION: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

impl<'a> AdmissionCustody<'a> {
    fn operation(&self) -> Option<&AdmissionOperationV1> {
        self.durable.as_ref().map(DurableToolAdmission::operation)
    }

    /// An armed, not-yet-dispatched post-admission guard over this custody's
    /// own resources. Dropping it is the pre-dispatch unwind.
    fn pre_dispatch_guard(&self) -> PostAdmissionDropGuard<'_> {
        PostAdmissionDropGuard::new(
            self.kernel,
            self.request,
            &self.request.capability,
            self.grant_index,
            &self.budget,
            self.payment.as_ref(),
            PostAdmissionReceiptContext {
                extra_metadata: self.metadata.clone(),
                runtime_reservation: self.runtime.clone(),
                pre_invocation_guard_evidence: self.evidence.clone().unwrap_or_default(),
                verified_payee_binding: self.payee.clone(),
            },
            self.lease_acquired,
        )
        .with_durable_operation(self.operation())
    }

    fn with_evidence<T>(
        &self,
        build: impl FnOnce() -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        match &self.evidence {
            Some(evidence) => self
                .kernel
                .with_pre_invocation_guard_evidence(evidence, build),
            None => build(),
        }
    }

    fn timestamp(&self, time: DenialTime) -> u64 {
        match time {
            DenialTime::Admitted => self.admitted_at,
            DenialTime::At(timestamp) => timestamp,
            DenialTime::Sampled => self
                .kernel
                .read_authority_time()
                .map(|time| time.as_secs())
                .unwrap_or(self.admitted_at),
        }
    }

    fn cleanup_denial<'s>(
        &'s self,
        reason: &'s str,
        timestamp: u64,
        grant_index: usize,
        metadata: Option<serde_json::Value>,
    ) -> PreDispatchCleanupDeny<'s> {
        PreDispatchCleanupDeny {
            request: self.request,
            reason,
            timestamp,
            matched_grant_index: grant_index,
            cap: &self.request.capability,
            budget_mutation: &self.budget,
            payment_authorization: self.payment.as_ref(),
            durable_operation: self.operation(),
            runtime_admission_metadata: metadata,
            runtime_reservation: &self.runtime,
            verified_payee_binding: self.payee.as_ref(),
            budget_lease_acquired: self.lease_acquired,
        }
    }
}

/// What an exit before grant selection does with the durable operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperationSettlement {
    /// Compensate the operation as never dispatched.
    Compensate,
    /// Leave the operation to recovery: parked for approval, or holding a
    /// runtime reservation whose release was not confirmed.
    Retain,
}

impl OperationSettlement {
    pub(crate) fn compensate_if(compensate: bool) -> Self {
        if compensate {
            Self::Compensate
        } else {
            Self::Retain
        }
    }
}

#[derive(Clone, Copy)]
enum DenialTime {
    Admitted,
    At(u64),
    /// Trusted time when the denial is signed, else the admission sample.
    Sampled,
}

/// A pre-dispatch denial signed through the shared cleanup.
pub(crate) struct AdmissionDenial<'r> {
    reason: &'r str,
    time: DenialTime,
    /// `None` signs with the custody's own receipt metadata.
    metadata: Option<Option<serde_json::Value>>,
    credentials: PaymentCredentialDisposition,
    outcome: PreDispatchCleanupOutcome,
}

impl<'r> AdmissionDenial<'r> {
    pub(crate) fn new(reason: &'r str) -> Self {
        Self {
            reason,
            time: DenialTime::Admitted,
            metadata: None,
            credentials: PaymentCredentialDisposition::NonePresent,
            outcome: PreDispatchCleanupOutcome::Denied,
        }
    }

    pub(crate) fn at(mut self, timestamp: u64) -> Self {
        self.time = DenialTime::At(timestamp);
        self
    }

    /// Sign with trusted time read at the denial, falling back to the
    /// admission sample, so a clock fault cannot skip the cleanup.
    pub(crate) fn sampled(mut self) -> Self {
        self.time = DenialTime::Sampled;
        self
    }

    pub(crate) fn with_metadata(mut self, metadata: Option<serde_json::Value>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub(crate) fn with_credentials(mut self, disposition: PaymentCredentialDisposition) -> Self {
        self.credentials = disposition;
        self
    }

    /// Report the host's cancellation instead of a denial.
    pub(crate) fn cancelled_if(mut self, cancelled: bool) -> Self {
        if cancelled {
            self.outcome = PreDispatchCleanupOutcome::Cancelled;
        }
        self
    }
}

/// Custody from durable admission until a grant is selected. It holds the
/// durable operation, which a drop compensates.
pub(crate) struct PreparedAdmission<'a>(AdmissionCustody<'a>);

/// The grant a selection admitted, with its budget mutation and runtime
/// reservation, moved into custody.
pub(crate) struct SelectedGrant {
    pub(crate) grant_index: usize,
    pub(crate) budget: PreExecutionBudgetMutation,
    pub(crate) runtime: RuntimeReservation,
    pub(crate) metadata: Option<serde_json::Value>,
    pub(crate) evidence: Option<Vec<GuardEvidence>>,
    pub(crate) payee: Option<VerifiedGovernedPayeeBinding>,
}

impl<'a> PreparedAdmission<'a> {
    pub(crate) fn open(
        kernel: &'a ChioKernel,
        request: &'a ToolCallRequest,
        admitted_at: u64,
        metadata: Option<serde_json::Value>,
        durable: Option<DurableToolAdmission>,
    ) -> Self {
        Self(AdmissionCustody {
            kernel,
            request,
            admitted_at,
            armed: true,
            grant_index: None,
            budget: PreExecutionBudgetMutation::None,
            runtime: RuntimeReservation::NONE,
            lease_acquired: false,
            payment: None,
            metadata,
            evidence: None,
            payee: None,
            credentials: None,
            durable,
        })
    }

    pub(crate) fn durable(&self) -> Option<&DurableToolAdmission> {
        self.0.durable.as_ref()
    }

    pub(crate) fn durable_mut(&mut self) -> Option<&mut DurableToolAdmission> {
        self.0.durable.as_mut()
    }

    pub(crate) fn operation(&self) -> Option<&AdmissionOperationV1> {
        self.0.operation()
    }

    /// Name the candidate grant whose guards run next, so a drop reports a
    /// cleanup fault against it.
    pub(crate) fn attempt(
        &mut self,
        grant_index: usize,
        payee: Option<VerifiedGovernedPayeeBinding>,
    ) {
        self.0.grant_index = Some(grant_index);
        self.0.payee = payee;
    }

    /// End the evaluation before a grant is selected. The operation is
    /// compensated first when `settlement` says so; the response is built
    /// while the operation's live owner is still held.
    pub(crate) fn settle_then<T>(
        mut self,
        settlement: OperationSettlement,
        respond: impl FnOnce() -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        self.0.armed = false;
        if settlement == OperationSettlement::Compensate {
            self.0
                .kernel
                .compensate_durable_admission_after_pre_dispatch_cleanup(
                    self.0.operation(),
                    None,
                    None,
                )?;
        }
        respond()
    }

    pub(crate) fn select(self, selected: SelectedGrant) -> BudgetedAdmission<'a> {
        let PreparedAdmission(mut custody) = self;
        custody.grant_index = Some(selected.grant_index);
        custody.budget = selected.budget;
        custody.runtime = selected.runtime;
        custody.metadata = selected.metadata;
        custody.evidence = selected.evidence;
        custody.payee = selected.payee;
        BudgetedAdmission {
            custody,
            grant_index: selected.grant_index,
        }
    }
}

/// Custody of a selected grant's admitted resources until dispatch.
pub(crate) struct BudgetedAdmission<'a> {
    custody: AdmissionCustody<'a>,
    grant_index: usize,
}

/// The admitted resources handed to dispatch. Nothing here compensates on
/// drop: dispatch owns their disposition.
pub(crate) struct AdmittedDispatch<'a> {
    pub(crate) durable: Option<DurableToolAdmission>,
    pub(crate) budget: PreExecutionBudgetMutation,
    pub(crate) runtime: RuntimeReservation,
    pub(crate) lease_acquired: bool,
    pub(crate) payment: Option<PaymentAuthorization>,
    pub(crate) metadata: Option<serde_json::Value>,
    pub(crate) evidence: Vec<GuardEvidence>,
    pub(crate) payee: Option<VerifiedGovernedPayeeBinding>,
    pub(crate) credentials: DispatchCredentialReservation<'a>,
}

/// A disarmed custody's resources, lent to an exit that owns its own
/// cleanup contract.
pub(crate) struct HeldAdmission<'s, 'a> {
    pub(crate) grant_index: usize,
    pub(crate) budget: &'s mut PreExecutionBudgetMutation,
    pub(crate) runtime: &'s RuntimeReservation,
    pub(crate) lease_acquired: bool,
    pub(crate) metadata: Option<serde_json::Value>,
    pub(crate) evidence: &'s [GuardEvidence],
    pub(crate) credentials: &'s mut DispatchCredentialReservation<'a>,
    pub(crate) durable: Option<&'s mut DurableToolAdmission>,
}

impl<'a> BudgetedAdmission<'a> {
    pub(crate) fn matched_grant_index(&self) -> usize {
        self.grant_index
    }

    pub(crate) fn durable(&self) -> Option<&DurableToolAdmission> {
        self.custody.durable.as_ref()
    }

    pub(crate) fn durable_mut(&mut self) -> Option<&mut DurableToolAdmission> {
        self.custody.durable.as_mut()
    }

    pub(crate) fn operation(&self) -> Option<&AdmissionOperationV1> {
        self.custody.operation()
    }

    pub(crate) fn budget(&self) -> &PreExecutionBudgetMutation {
        &self.custody.budget
    }

    pub(crate) fn metadata(&self) -> &Option<serde_json::Value> {
        &self.custody.metadata
    }

    pub(crate) fn metadata_mut(&mut self) -> &mut Option<serde_json::Value> {
        &mut self.custody.metadata
    }

    pub(crate) fn payee(&self) -> Option<&VerifiedGovernedPayeeBinding> {
        self.custody.payee.as_ref()
    }

    pub(crate) fn payment(&self) -> Option<&PaymentAuthorization> {
        self.custody.payment.as_ref()
    }

    pub(crate) fn hold_lease(&mut self, acquired: bool) {
        self.custody.lease_acquired = acquired;
    }

    pub(crate) fn hold_credentials(&mut self, credentials: DispatchCredentialReservation<'a>) {
        self.custody.credentials = Some(credentials);
    }

    pub(crate) fn hold_payment(&mut self, payment: PaymentAuthorization) {
        self.custody.payment = Some(payment);
    }

    /// The reserved dispatch credentials. Their absence after reservation
    /// is an invariant fault the caller fails closed on.
    pub(crate) fn credentials(
        &mut self,
    ) -> Result<&mut DispatchCredentialReservation<'a>, KernelError> {
        self.custody.credentials.as_mut().ok_or_else(|| {
            KernelError::admission_invariant("pre-dispatch custody lost its dispatch credentials")
        })
    }

    /// Roll back the reserved dispatch credentials before a denial.
    pub(crate) fn rollback_credentials(&mut self) -> Result<(), KernelError> {
        self.custody.credentials.take().map_or(
            Ok(()),
            DispatchCredentialReservation::rollback_before_dispatch,
        )
    }

    /// Release every admitted resource through the shared pre-dispatch
    /// cleanup and sign the denial.
    pub(crate) fn deny(self, denial: AdmissionDenial<'_>) -> Result<ToolCallResponse, KernelError> {
        let BudgetedAdmission {
            mut custody,
            grant_index,
        } = self;
        custody.armed = false;
        let metadata = match denial.metadata {
            Some(metadata) => metadata,
            None => custody.metadata.take(),
        };
        let custody = &custody;
        custody.with_evidence(|| {
            let timestamp = custody.timestamp(denial.time);
            custody.kernel.build_pre_dispatch_cleanup_response(
                custody.cleanup_denial(denial.reason, timestamp, grant_index, metadata),
                denial.credentials,
                denial.outcome,
            )
        })
    }

    /// The host refused to start the session request's dispatch. Credentials
    /// stay retained once a payment authorization was acknowledged.
    pub(crate) fn deny_session_refusal(
        self,
        reason: &str,
        cancelled: bool,
    ) -> Result<ToolCallResponse, KernelError> {
        let disposition = if self.custody.payment.is_some() {
            PaymentCredentialDisposition::RetainedAfterAuthorization
        } else {
            PaymentCredentialDisposition::NonePresent
        };
        self.deny(
            AdmissionDenial::new(reason)
                .sampled()
                .with_credentials(disposition)
                .cancelled_if(cancelled),
        )
    }

    /// The durable capture boundary could not be confirmed, so the store may
    /// already treat the operation as capturing: every hold is retained for
    /// recovery and named in the denial.
    pub(crate) fn deny_capture_pending(
        self,
        reason: &str,
    ) -> Result<ToolCallResponse, KernelError> {
        let BudgetedAdmission {
            mut custody,
            grant_index,
        } = self;
        custody.armed = false;
        let kernel = custody.kernel;
        let metadata =
            kernel.retained_admission_receipt_metadata(&custody.budget, custody.metadata.take());
        kernel.build_deny_response_with_metadata(
            custody.request,
            reason,
            custody.admitted_at,
            Some(grant_index),
            metadata,
        )
    }

    /// Capture the invocation of a budget hold no durable operation owns.
    /// An invocation another dispatch already captured, or a capture that
    /// could not be confirmed, ends the evaluation with its retained hold.
    pub(crate) fn capture_non_durable_invocation(
        mut self,
    ) -> ControlFlow<Result<ToolCallResponse, KernelError>, Self> {
        if self.custody.durable.is_some() || self.custody.budget.durable_hold_result().is_none() {
            return ControlFlow::Continue(self);
        }
        let custody = &mut self.custody;
        let capture = custody
            .kernel
            .capture_invocation(&custody.request.capability, &mut custody.budget);
        match capture {
            Ok(BudgetInvocationCaptureDecision::Captured(_)) => ControlFlow::Continue(self),
            Ok(BudgetInvocationCaptureDecision::AlreadyCaptured(_)) => ControlFlow::Break(
                self.deny_captured_replay("monetary invocation was already dispatched"),
            ),
            Err(error) => {
                let internal_reason = error.to_string();
                warn!(
                    request_id = %self.custody.request.request_id,
                    reason = %redacted!(&internal_reason),
                    "budget invocation capture could not be confirmed"
                );
                ControlFlow::Break(
                    self.deny_unconfirmed_capture(
                        "budget invocation capture could not be confirmed",
                    ),
                )
            }
        }
    }

    /// Another dispatch captured this invocation: release only this
    /// evaluation's runtime reservation and lease, never the captured hold.
    fn deny_captured_replay(self, reason: &str) -> Result<ToolCallResponse, KernelError> {
        let BudgetedAdmission {
            mut custody,
            grant_index,
        } = self;
        custody.armed = false;
        let metadata = custody.metadata.take();
        let custody = &custody;
        custody.with_evidence(|| {
            let kernel = custody.kernel;
            let (runtime_metadata, _) = kernel
                .release_runtime_admission_reservations_for_pre_dispatch_denial(
                    None,
                    &custody.runtime,
                    metadata,
                );
            let runtime_metadata = kernel
                .release_budget_lease_with_evidence(
                    &custody.request.capability,
                    custody.lease_acquired,
                    runtime_metadata,
                )
                .metadata;
            let metadata = match custody.budget.charge_result() {
                Some(charge) => kernel.merge_budget_receipt_metadata(
                    runtime_metadata,
                    kernel.budget_execution_receipt_metadata(charge, None, None),
                ),
                None => runtime_metadata,
            };
            kernel.build_deny_response_with_metadata_and_payee_binding(
                custody.request,
                reason,
                custody.admitted_at,
                Some(grant_index),
                metadata,
                custody.payee.as_ref(),
            )
        })
    }

    fn deny_unconfirmed_capture(self, reason: &str) -> Result<ToolCallResponse, KernelError> {
        let BudgetedAdmission {
            mut custody,
            grant_index,
        } = self;
        custody.armed = false;
        let metadata = custody.metadata.take();
        let custody = &custody;
        custody.with_evidence(|| {
            custody.kernel.build_deny_response_with_metadata(
                custody.request,
                reason,
                custody.admitted_at,
                Some(grant_index),
                custody
                    .kernel
                    .ambiguous_invocation_capture_receipt_metadata(&custody.budget, metadata),
            )
        })
    }

    /// The payment rail definitively declined the authorization: roll the
    /// credentials back and unwind every hold, cancelling a captured one.
    pub(crate) fn deny_declined_payment(
        mut self,
        reason: String,
    ) -> Result<ToolCallResponse, KernelError> {
        let mut denial_reason = reason;
        let credential_disposition = if let Err(rollback_error) = self.rollback_credentials() {
            denial_reason = format!("{denial_reason}; {rollback_error}");
            PaymentCredentialDisposition::RetentionOutcomeUnknown
        } else {
            PaymentCredentialDisposition::NonePresent
        };
        let metadata = self
            .custody
            .kernel
            .merge_dispatch_credential_disposition_metadata(
                self.custody.metadata.take(),
                credential_disposition,
            );
        if self
            .custody
            .budget
            .charge_result()
            .and_then(|charge| charge.invocation_capture.as_ref())
            .is_some()
        {
            return self.deny_captured_payment(&denial_reason, metadata);
        }
        self.deny(AdmissionDenial::new(&denial_reason).with_metadata(metadata))
    }

    /// A definite payment denial after the invocation was captured: cancel
    /// the captured hold before dispatch and compensate the operation only
    /// once the runtime reservation and lease were confirmed released.
    fn deny_captured_payment(
        self,
        reason: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let BudgetedAdmission {
            mut custody,
            grant_index: _,
        } = self;
        custody.armed = false;
        let custody = &custody;
        custody.with_evidence(|| {
            let kernel = custody.kernel;
            let cap = &custody.request.capability;
            let (runtime_metadata, runtime_release_confirmed) = kernel
                .release_runtime_admission_reservations_for_pre_dispatch_denial(
                    custody.operation(),
                    &custody.runtime,
                    metadata,
                );
            let lease_release = kernel.release_budget_lease_with_evidence(
                cap,
                custody.lease_acquired,
                runtime_metadata,
            );
            let runtime_metadata = lease_release.metadata;
            let charge = custody.budget.charge_result().ok_or_else(|| {
                KernelError::Internal(
                    "captured payment denial is missing its monetary budget hold".to_string(),
                )
            })?;
            let cancellation = match kernel
                .cancel_captured_monetary_before_dispatch(&cap.id, charge)
            {
                Ok(cancellation) => cancellation,
                Err(error) => {
                    let internal_reason = error.to_string();
                    warn!(
                        request_id = %custody.request.request_id,
                        reason = %redacted!(&internal_reason),
                        "captured budget cancellation could not be confirmed"
                    );
                    return kernel.build_deny_response_with_metadata_and_payee_binding(
                        custody.request,
                        "captured budget cancellation could not be confirmed",
                        custody.admitted_at,
                        Some(charge.grant_index),
                        kernel.ambiguous_cancellation_receipt_metadata(charge, runtime_metadata),
                        custody.payee.as_ref(),
                    );
                }
            };
            if runtime_release_confirmed && lease_release.confirmed {
                kernel.compensate_durable_admission_after_pre_dispatch_cleanup(
                    custody.operation(),
                    Some(&cancellation),
                    None,
                )?;
            }
            kernel.build_pre_execution_monetary_deny_response_with_metadata_and_payee_binding(
                custody.request,
                reason,
                custody.admitted_at,
                charge,
                cancellation.committed_cost_units_after,
                cap,
                kernel.merge_budget_receipt_metadata(
                    runtime_metadata,
                    kernel.budget_execution_receipt_metadata(
                        charge,
                        Some(("cancelled_before_dispatch", &cancellation)),
                        None,
                    ),
                ),
                custody.payee.as_ref(),
            )
        })
    }

    /// The payment rail's answer is ambiguous: retain every hold and the
    /// credentials, and sign the ambiguity for recovery.
    pub(crate) fn deny_ambiguous_payment(
        self,
        reason: String,
        error_code: &str,
    ) -> Result<ToolCallResponse, KernelError> {
        let BudgetedAdmission {
            mut custody,
            grant_index,
        } = self;
        custody.armed = false;
        let kernel = custody.kernel;
        let retained =
            kernel.retained_admission_receipt_metadata(&custody.budget, custody.metadata.take());
        let payment_attempt_reference =
            ChioKernel::payment_operation_reference(custody.request, custody.operation());
        let metadata = merge_metadata_objects(
            retained,
            Some(serde_json::json!({
                "financial": {
                    "payment_authorization_ambiguous": true,
                    "payment_authorization_error_code": error_code,
                    "payment_attempt_reference": payment_attempt_reference
                }
            })),
        );
        let retention = custody.credentials.as_mut().map_or(
            Ok(PaymentCredentialDisposition::NonePresent),
            |credentials| credentials.commit(),
        );
        let (denial_reason, credential_disposition) = match retention {
            Ok(disposition) => (reason, disposition),
            Err(retention_error) => (
                format!(
                    "payment authorization outcome is ambiguous and credential retention failed: {retention_error}"
                ),
                PaymentCredentialDisposition::RetentionOutcomeUnknown,
            ),
        };
        let metadata =
            kernel.merge_dispatch_credential_disposition_metadata(metadata, credential_disposition);
        let custody = &custody;
        custody.with_evidence(|| {
            kernel.build_deny_response_with_metadata_and_payee_binding(
                custody.request,
                &denial_reason,
                custody.admitted_at,
                Some(grant_index),
                metadata,
                custody.payee.as_ref(),
            )
        })
    }

    /// The security pre-dispatch hook denied the call. The credentials are
    /// resolved by value before the denial is signed with the hook's evidence.
    pub(crate) fn deny_security(
        mut self,
        reason: &str,
        evidence: GuardEvidence,
    ) -> Result<ToolCallResponse, KernelError> {
        let credentials = self.take_credentials()?;
        let BudgetedAdmission {
            mut custody,
            grant_index,
        } = self;
        custody.armed = false;
        let mut denial_evidence = custody.evidence.clone().unwrap_or_default();
        denial_evidence.push(evidence);
        let metadata = custody.metadata.take();
        custody
            .kernel
            .build_pre_commit_credential_rejection_response(
                custody.cleanup_denial(reason, custody.admitted_at, grant_index, metadata),
                credentials,
                &denial_evidence,
            )
    }

    /// Without a nonce, the strict preflight unwinds every pre-execution
    /// mutation and answers with the nonce to retry with.
    pub(crate) fn allow_preflight_retry(self) -> Result<ToolCallResponse, KernelError> {
        let BudgetedAdmission {
            mut custody,
            grant_index,
        } = self;
        custody.armed = false;
        let AdmissionCustody {
            kernel,
            request,
            admitted_at,
            budget,
            runtime,
            lease_acquired,
            metadata,
            evidence,
            durable,
            ..
        } = &mut custody;
        let (kernel, request) = (*kernel, *request);
        let metadata = metadata.take();
        let respond = || {
            kernel.build_execution_nonce_preflight_allow_response_after_cleanup(
                request,
                *admitted_at,
                grant_index,
                &request.capability,
                budget,
                durable.as_mut(),
                metadata,
                runtime,
                *lease_acquired,
            )
        };
        match evidence {
            Some(evidence) => kernel.with_pre_invocation_guard_evidence(evidence, respond),
            None => respond(),
        }
    }

    /// Settle through an exit that hands the admitted resources on instead
    /// of unwinding them, such as a caller reservation that keeps its hold.
    /// The credentials must be held; without them the custody fails closed
    /// and compensates.
    pub(crate) fn settle_with_credentials<T>(
        self,
        exit: impl FnOnce(HeldAdmission<'_, 'a>) -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        let BudgetedAdmission {
            mut custody,
            grant_index,
        } = self;
        let AdmissionCustody {
            armed,
            budget,
            runtime,
            lease_acquired,
            metadata,
            evidence,
            credentials,
            durable,
            ..
        } = &mut custody;
        let Some(credentials) = credentials.as_mut() else {
            return Err(KernelError::admission_invariant(
                "pre-dispatch custody lost its dispatch credentials",
            ));
        };
        *armed = false;
        exit(HeldAdmission {
            grant_index,
            budget,
            runtime,
            lease_acquired: *lease_acquired,
            metadata: metadata.take(),
            evidence: evidence.as_deref().unwrap_or_default(),
            credentials,
            durable: durable.as_mut(),
        })
    }

    /// Run the native capture checkpoint over the held resources. When the
    /// checkpoint ends the evaluation it has already settled them.
    #[cfg(feature = "admission-test-support")]
    pub(crate) fn native_capture_checkpoint(
        mut self,
        security_context: Option<&SecurityInvocationContext>,
    ) -> ControlFlow<Result<ToolCallResponse, KernelError>, Self> {
        let credentials = match self.take_credentials() {
            Ok(credentials) => credentials,
            Err(error) => return ControlFlow::Break(Err(error)),
        };
        let custody = &mut self.custody;
        let outcome = custody.kernel.evaluate_native_capture_checkpoint(
            credentials,
            custody.durable.as_mut(),
            &mut custody.budget,
            NativeCaptureCheckpointContext {
                request: custody.request,
                security_context,
                timestamp: custody.admitted_at,
                matched_grant_index: self.grant_index,
                payment_authorization: custody.payment.as_ref(),
                metadata: custody.metadata.as_ref(),
                runtime_reservation: &custody.runtime,
                verified_payee_binding: custody.payee.as_ref(),
                budget_lease_acquired: custody.lease_acquired,
                evidence: custody.evidence.as_deref().unwrap_or_default(),
            },
        );
        match outcome {
            ControlFlow::Continue(credentials) => {
                self.custody.credentials = Some(credentials);
                ControlFlow::Continue(self)
            }
            ControlFlow::Break(response) => {
                self.custody.armed = false;
                ControlFlow::Break(response)
            }
        }
    }

    /// Hand the admitted resources to dispatch. Without held credentials the
    /// custody fails closed and compensates.
    pub(crate) fn into_dispatch(mut self) -> Result<AdmittedDispatch<'a>, KernelError> {
        let credentials = self.take_credentials()?;
        let custody = &mut self.custody;
        custody.armed = false;
        Ok(AdmittedDispatch {
            durable: custody.durable.take(),
            budget: std::mem::replace(&mut custody.budget, PreExecutionBudgetMutation::None),
            runtime: std::mem::take(&mut custody.runtime),
            lease_acquired: custody.lease_acquired,
            payment: custody.payment.take(),
            metadata: custody.metadata.take(),
            evidence: custody.evidence.take().unwrap_or_default(),
            payee: custody.payee.take(),
            credentials,
        })
    }

    fn take_credentials(&mut self) -> Result<DispatchCredentialReservation<'a>, KernelError> {
        self.custody.credentials.take().ok_or_else(|| {
            KernelError::admission_invariant("pre-dispatch custody lost its dispatch credentials")
        })
    }
}
