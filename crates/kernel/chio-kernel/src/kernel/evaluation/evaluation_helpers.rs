use super::*;

pub(super) struct PreDispatchCleanupDeny<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) reason: &'a str,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `admit_capability_budget` return). Only then may cleanup release
    /// one: the reference-counted release frees the shared edge only when the
    /// last holder releases, so an overlapping evaluation that still holds it
    /// keeps its share and an oversubscribing sibling stays denied.
    pub(super) budget_lease_acquired: bool,
}

pub(super) struct SecurityDispatchOutcomeRecovery<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) threshold_operation: Option<&'a AdmissionOperation>,
    pub(super) outcome_error: KernelError,
    pub(super) secondary_faults: Vec<String>,
}

impl ChioKernel {
    pub(super) fn recover_security_dispatch_outcome_persistence_failure(
        &self,
        recovery: SecurityDispatchOutcomeRecovery<'_>,
    ) -> KernelError {
        let SecurityDispatchOutcomeRecovery {
            request,
            cap,
            budget_mutation,
            payment_authorization,
            threshold_operation,
            outcome_error,
            mut secondary_faults,
        } = recovery;
        let primary_reason = match &outcome_error {
            KernelError::SecurityDispatchOutcomeRecoveryRequired(reason) => reason.clone(),
            error => format!("security dispatch outcome recorder failed: {error}"),
        };

        // Do not terminalize an operation when the security outcome recorder
        // failed before a signed receipt could be staged. Leaving the durable
        // dispatch commitment unresolved is the fail-closed recovery state.

        if let Err(failure) = self.release_post_dispatch_monetary_invocation(
            request,
            cap,
            budget_mutation.charge_result(),
            payment_authorization,
            threshold_operation.is_some(),
        ) {
            secondary_faults.push(format!(
                "post-dispatch monetary cleanup failed: {}",
                failure.reason()
            ));
        }

        let reason = if secondary_faults.is_empty() {
            primary_reason
        } else {
            format!(
                "{primary_reason}; secondary recovery faults: {}",
                secondary_faults.join(" | ")
            )
        };
        warn!(
            request_id = %request.request_id,
            reason = %redacted!(&reason),
            audit_fault = "security_dispatch_outcome_recovery_required",
            "security dispatch outcome persistence failed after connector entry"
        );
        KernelError::SecurityDispatchOutcomeRecoveryRequired(reason)
    }

    pub(super) fn with_pre_invocation_guard_evidence<T>(
        &self,
        evidence: &[chio_core::receipt::metadata::GuardEvidence],
        build: impl FnOnce() -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        let _guard_evidence_scope = scope_pre_invocation_guard_evidence(evidence.to_vec());
        build()
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn record_url_elicitation_post_dispatch_receipt(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: usize,
        metadata: Option<serde_json::Value>,
        pre_invocation_guard_evidence: &[chio_core::receipt::metadata::GuardEvidence],
    ) {
        let metadata = self.mark_runtime_admission_reservations_retained_fail_closed(metadata);
        let _guard_evidence_scope =
            scope_pre_invocation_guard_evidence(pre_invocation_guard_evidence.to_vec());
        if let Err(error) = self.build_incomplete_response_with_output_and_metadata(
            request,
            None,
            reason,
            timestamp,
            Some(matched_grant_index),
            metadata,
        ) {
            warn!(
                request_id = %request.request_id,
                reason = %redacted!(&error),
                audit_fault = "url_elicitation_terminal_receipt_unrecorded",
                "failed to record URL-elicitation post-dispatch receipt"
            );
        }
    }

    pub(super) fn build_pre_dispatch_cleanup_deny_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let threshold_operation =
            self.threshold_operation_for_budget_mutation(denial.budget_mutation)?;
        let reverse = if let Some(operation) = threshold_operation.as_ref() {
            // The admission reversal first wins the durable compensation CAS.
            // No participant may be released while dispatch can still win.
            let reverse =
                self.reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation)?;
            if let Some(payment_authorization) = denial.payment_authorization {
                self.release_threshold_payment_authorization(
                    denial.request,
                    denial.budget_mutation,
                    payment_authorization,
                )?;
            }
            if denial.budget_lease_acquired {
                self.release_threshold_delegated_budget(denial.cap, operation)?;
            }
            reverse
        } else {
            let reverse = match denial.payment_authorization {
                Some(payment_authorization) => self.unwind_aborted_monetary_invocation(
                    denial.request,
                    denial.cap,
                    denial.budget_mutation,
                    Some(payment_authorization),
                )?,
                None => {
                    self.reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation)?
                }
            };
            if denial.budget_lease_acquired {
                self.release_pre_dispatch_delegated_budget(denial.cap, denial.budget_mutation)?;
            }
            reverse
        };
        let mut runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                denial.runtime_admission_metadata,
            );
        if let Some(operation) = threshold_operation.as_ref() {
            let terminal_metadata = self
                .exact_compensated_threshold_admission_metadata(operation)?
                .ok_or_else(|| {
                    KernelError::Internal(format!(
                        "threshold admission operation {} did not expose its compensated receipt projection",
                        operation.operation_id()
                    ))
                })?;
            runtime_admission_metadata =
                merge_metadata_objects(runtime_admission_metadata, Some(terminal_metadata));
        }

        if let (Some(charge), Some(reverse)) =
            (denial.budget_mutation.charge_result(), reverse.as_ref())
        {
            return self.build_pre_execution_monetary_deny_response_with_metadata(
                denial.request,
                denial.reason,
                denial.timestamp,
                charge,
                reverse.committed_cost_units_after,
                denial.cap,
                self.merge_budget_receipt_metadata(
                    runtime_admission_metadata,
                    self.budget_execution_receipt_metadata(charge, Some(("reversed", reverse))),
                ),
            );
        }

        self.build_deny_response_with_metadata(
            denial.request,
            denial.reason,
            denial.timestamp,
            Some(denial.matched_grant_index),
            runtime_admission_metadata,
        )
    }

    // The preflight-allow cleanup legitimately threads the full pre-dispatch
    // state (request, grant, capability, budget mutation, admission metadata,
    // and the budget-lease gate) needed to reverse it; grouping them into
    // a params struct would only rename the same inputs.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn build_execution_nonce_preflight_allow_response_after_cleanup(
        &self,
        request: &ToolCallRequest,
        timestamp: u64,
        matched_grant_index: usize,
        cap: &CapabilityToken,
        budget_mutation: &PreExecutionBudgetMutation,
        payment_authorization: Option<&PaymentAuthorization>,
        runtime_admission_metadata: Option<serde_json::Value>,
        budget_lease_acquired: bool,
    ) -> Result<ToolCallResponse, KernelError> {
        let threshold_operation = self.threshold_operation_for_budget_mutation(budget_mutation)?;
        // Admission reversal wins the durable compensation CAS before any
        // operation-owned runtime, payment, or delegated-budget participant
        // is released.
        let reverse = self.reverse_pre_execution_budget_mutation(cap, budget_mutation)?;
        if threshold_operation.is_some() {
            if let Some(payment_authorization) = payment_authorization {
                self.release_threshold_payment_authorization(
                    request,
                    budget_mutation,
                    payment_authorization,
                )?;
            }
        }
        if budget_lease_acquired {
            self.release_pre_dispatch_delegated_budget(cap, budget_mutation)?;
        }
        let runtime_admission_metadata = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        let budget_metadata = match (budget_mutation.charge_result(), reverse.as_ref()) {
            (Some(charge), Some(reverse)) => {
                Some(self.budget_execution_receipt_metadata(charge, Some(("reversed", reverse))))
            }
            _ => None,
        };
        let preflight_metadata = Some(serde_json::json!({
            "execution_nonce": {
                "stage": "preflight",
                "tool_dispatched": false
            }
        }));
        let metadata = merge_metadata_objects(
            merge_metadata_objects(runtime_admission_metadata, budget_metadata),
            preflight_metadata,
        );

        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            timestamp,
            Some(matched_grant_index),
            metadata,
        )
    }
}
