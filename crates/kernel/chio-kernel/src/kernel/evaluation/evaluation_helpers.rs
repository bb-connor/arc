use super::*;
use crate::kernel::dispatch::PreDispatchMonetaryUnwindFailure;
use crate::kernel::responses::{OperationOwnedCallerReservationResponse, ReservedHoldStamp};

/// Incomplete-decision reason for a strict-nonce preflight whose hold was
/// reversed. The caller retries the same endpoint presenting the minted nonce,
/// at which point the hold is re-taken and the tool dispatched.
const EXECUTION_NONCE_PREFLIGHT_RETRY_REASON: &str =
    "execution nonce preflight requires retry with presented nonce";

/// Incomplete-decision reason for a pre-execution authorization whose hold was
/// reserved (kept open) for a caller that executes the tool downstream. The
/// caller does not retry this endpoint: it presents the minted nonce to the
/// real tool server, which consumes it and reconciles the reserved hold.
const EXECUTION_NONCE_AUTHORIZATION_RESERVED_REASON: &str =
    "pre-execution authorization reserved; present the minted execution nonce to the tool server";

pub(super) struct PreDispatchCleanupDeny<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) reason: &'a str,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) cap: &'a CapabilityToken,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) payment_authorization: Option<&'a PaymentAuthorization>,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    pub(super) verified_payee_binding: Option<&'a VerifiedGovernedPayeeBinding>,
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

pub(super) struct ExecutionNonceReservingResponse<'a> {
    pub(super) request: &'a ToolCallRequest,
    pub(super) timestamp: u64,
    pub(super) matched_grant_index: usize,
    pub(super) budget_mutation: &'a PreExecutionBudgetMutation,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
    pub(super) caller_receipt_metadata: Option<&'a serde_json::Value>,
    pub(super) reserved_payment_reference: Option<String>,
    pub(super) threshold_supplemental_prepared: bool,
    /// Whether THIS evaluation acquired a sibling-sum child-budget holder lease
    /// (the `admit_capability_budget` return). The non-monetary share release
    /// runs only when true so the reference-counted release never frees an
    /// overlapping sibling's still-held share.
    pub(super) budget_lease_acquired: bool,
}

struct CleanupReleaseOutcome {
    metadata: Option<serde_json::Value>,
    confirmed: bool,
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
            budget_mutation,
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

    pub(super) fn merge_dispatch_credential_disposition_metadata(
        &self,
        metadata: Option<serde_json::Value>,
        disposition: PaymentCredentialDisposition,
    ) -> Option<serde_json::Value> {
        if disposition == PaymentCredentialDisposition::NonePresent {
            return metadata;
        }
        merge_metadata_objects(
            metadata,
            Some(serde_json::json!({
                "chio_runtime": {
                    "payment_credential_disposition": disposition,
                    "dispatch_credential_disposition": disposition,
                    "dispatch_credential_retention_outcome_unknown":
                        disposition == PaymentCredentialDisposition::RetentionOutcomeUnknown
                }
            })),
        )
    }

    fn release_budget_lease_with_evidence(
        &self,
        cap: &CapabilityToken,
        lease_acquired: bool,
        metadata: Option<serde_json::Value>,
    ) -> CleanupReleaseOutcome {
        if !lease_acquired {
            return CleanupReleaseOutcome {
                metadata,
                confirmed: true,
            };
        }
        match self.release_admitted_capability_budget(cap) {
            Ok(()) => CleanupReleaseOutcome {
                metadata,
                confirmed: true,
            },
            Err(error) => {
                warn!(
                    capability_id = %cap.id,
                    reason = %redacted!(&error),
                    "admitted capability budget lease release could not be confirmed"
                );
                CleanupReleaseOutcome {
                    metadata: merge_metadata_objects(
                        metadata,
                        Some(serde_json::json!({
                            "budget_authority": {
                                "lease_release_unconfirmed": true,
                                "lease_retained": true,
                                "lease_capability_id": cap.id
                            }
                        })),
                    ),
                    confirmed: false,
                }
            }
        }
    }

    /// Unwind all pre-dispatch state and record the signed deny receipt for
    /// an evaluation whose tool provably did not run. Every caller owns
    /// either a pre-dispatch denial or a dispatch error that precedes any
    /// tool side effect, so on an error exit here (a failed cleanup step or
    /// a failed deny-receipt append) the evaluation returns without a
    /// terminal receipt and the journaled dispatch intent must not survive:
    /// an open row for a call that never executed would dead-letter at the
    /// next boot as a false orphan. The clear is bounded, open-state
    /// guarded, and a no-op both for denials reached before the intent write
    /// (no handle registered) and for a deny receipt that already consumed
    /// the intent (the consume unregisters the handle).
    pub(super) fn build_pre_dispatch_cleanup_deny_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let request = denial.request;
        let result = self.build_pre_dispatch_cleanup_deny_response_with_credentials(
            denial,
            PaymentCredentialDisposition::NonePresent,
        );
        if result.is_err() {
            self.clear_dispatch_intent_for_non_dispatch_exit(request);
        }
        result
    }

    /// Unwind a typed URL-elicitation result without creating a terminal
    /// receipt. The tool boundary guarantees that this result precedes any
    /// tool effect, so a clean unwind leaves the request retryable.
    pub(super) fn unwind_url_elicitation_before_effect(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        credential_disposition: PaymentCredentialDisposition,
    ) -> Result<(), KernelError> {
        if let Some(operation) =
            self.threshold_operation_for_budget_mutation(denial.budget_mutation)?
        {
            self.reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation)?;
            if let Some(payment_authorization) = denial.payment_authorization {
                self.release_threshold_payment_authorization(
                    denial.request,
                    denial.budget_mutation,
                    payment_authorization,
                )?;
            }
            if denial.budget_lease_acquired {
                self.release_threshold_delegated_budget(denial.cap, &operation)?;
            }
            let metadata = self.merge_dispatch_credential_disposition_metadata(
                denial.runtime_admission_metadata,
                credential_disposition,
            );
            let (_, runtime_release_confirmed) =
                self.release_runtime_admission_reservations_for_pre_dispatch_denial(metadata);
            return if runtime_release_confirmed {
                Ok(())
            } else {
                Err(KernelError::Internal(
                    "URL-elicitation runtime admission cleanup could not be confirmed".to_string(),
                ))
            };
        }
        let runtime_metadata = self.merge_dispatch_credential_disposition_metadata(
            denial.runtime_admission_metadata,
            credential_disposition,
        );
        let (runtime_metadata, runtime_release_confirmed) =
            self.release_runtime_admission_reservations_for_pre_dispatch_denial(runtime_metadata);
        let lease_release = self.release_budget_lease_with_evidence(
            denial.cap,
            denial.budget_lease_acquired,
            runtime_metadata,
        );
        let _reverse = match denial.payment_authorization {
            Some(payment_authorization) => self
                .unwind_pre_dispatch_monetary_invocation_with_evidence(
                    denial.request,
                    denial.cap,
                    denial.budget_mutation,
                    Some(payment_authorization),
                    credential_disposition,
                )
                .map(|(reverse, _)| reverse)
                .map_err(|failure| *failure.error)?,
            None => {
                self.reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation)?
            }
        };
        if !runtime_release_confirmed || !lease_release.confirmed {
            return Err(KernelError::Internal(
                "URL-elicitation admission cleanup could not be confirmed".to_string(),
            ));
        }
        Ok(())
    }

    pub(super) fn build_pre_dispatch_cleanup_deny_response_with_credentials(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        credential_disposition: PaymentCredentialDisposition,
    ) -> Result<ToolCallResponse, KernelError> {
        if self
            .threshold_operation_for_budget_mutation(denial.budget_mutation)?
            .is_some()
        {
            return self
                .pre_dispatch_threshold_cleanup_deny_response(denial, credential_disposition);
        }
        let runtime_admission_metadata = self.merge_dispatch_credential_disposition_metadata(
            denial.runtime_admission_metadata,
            credential_disposition,
        );
        let (runtime_admission_metadata, _runtime_release_confirmed) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        let lease_release = self.release_budget_lease_with_evidence(
            denial.cap,
            denial.budget_lease_acquired,
            runtime_admission_metadata,
        );
        let runtime_admission_metadata = lease_release.metadata;
        let reverse_result = match denial.payment_authorization {
            Some(payment_authorization) => self
                .unwind_pre_dispatch_monetary_invocation_with_evidence(
                    denial.request,
                    denial.cap,
                    denial.budget_mutation,
                    Some(payment_authorization),
                    credential_disposition,
                ),
            None => self
                .reverse_pre_execution_budget_mutation(denial.cap, denial.budget_mutation)
                .map(|reverse| (reverse, None))
                .map_err(PreDispatchMonetaryUnwindFailure::from),
        };
        let (reverse, unwind_evidence) = match reverse_result {
            Ok(result) => result,
            Err(failure) => {
                warn!(
                    request_id = %denial.request.request_id,
                    reason = %redacted!(&failure.error),
                    "pre-dispatch cleanup could not be confirmed"
                );
                let metadata = match denial.budget_mutation.charge_result() {
                    Some(charge) => self.merge_budget_receipt_metadata(
                        runtime_admission_metadata,
                        self.budget_execution_receipt_metadata(charge, None, None)?,
                    ),
                    None => runtime_admission_metadata,
                };
                let metadata = merge_metadata_objects(
                    metadata,
                    Some(serde_json::json!({
                        "budget_authority": {
                            "pre_dispatch_cleanup_unconfirmed": true,
                            "admission_release_unconfirmed": true,
                            "admission_may_be_retained": true,
                            "cleanup_mutation_kind": match denial.budget_mutation {
                                PreExecutionBudgetMutation::Charge(_) => "charge",
                                PreExecutionBudgetMutation::Admission(_) => "admission",
                                PreExecutionBudgetMutation::Invocation { .. } => "invocation",
                                PreExecutionBudgetMutation::None => "none",
                            },
                            "cleanup_capability_id": denial.cap.id,
                            "cleanup_grant_index": denial.matched_grant_index,
                            "cleanup_hold_id": denial.budget_mutation.charge_result()
                                .map(|charge| charge.budget_hold_id.as_str()),
                            "cleanup_attempt_event_id": denial.budget_mutation.charge_result()
                                .map(BudgetChargeResult::reverse_event_id),
                            "cleanup_attempt_event_id_available": denial.budget_mutation
                                .charge_result().is_some()
                        }
                    })),
                );
                let metadata = match failure.evidence {
                    Some(evidence) => merge_metadata_objects(
                        metadata,
                        Some(serde_json::json!({
                            "chio_runtime": {
                                "pre_dispatch_payment_unwind": evidence
                            }
                        })),
                    ),
                    None => match denial.payment_authorization {
                        Some(authorization) => merge_metadata_objects(
                            metadata,
                            Some(serde_json::json!({
                                "financial": {
                                    "payment_reference": authorization.authorization_id,
                                    "payment_authorization_may_be_retained": true,
                                    "payment_unwind_unconfirmed": true,
                                    "payment_unwind_attempt_reference": denial.request.request_id
                                }
                            })),
                        ),
                        None => metadata,
                    },
                };
                return self.build_deny_response_with_metadata_and_payee_binding(
                    denial.request,
                    &format!(
                        "{}; pre-dispatch cleanup could not be confirmed: {}",
                        denial.reason, failure.error
                    ),
                    denial.timestamp,
                    Some(denial.matched_grant_index),
                    metadata,
                    denial.verified_payee_binding,
                );
            }
        };
        let runtime_admission_metadata = match unwind_evidence {
            Some(evidence) => merge_metadata_objects(
                runtime_admission_metadata,
                Some(serde_json::json!({
                    "chio_runtime": {
                        "pre_dispatch_payment_unwind": evidence
                    }
                })),
            ),
            None => runtime_admission_metadata,
        };
        if let (Some(charge), Some(reverse)) =
            (denial.budget_mutation.charge_result(), reverse.as_ref())
        {
            return self
                .build_pre_execution_monetary_deny_response_with_metadata_and_payee_binding(
                    denial.request,
                    denial.reason,
                    denial.timestamp,
                    charge,
                    reverse.committed_cost_units_after,
                    denial.cap,
                    self.merge_budget_receipt_metadata(
                        runtime_admission_metadata,
                        self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", reverse)),
                            None,
                        )?,
                    ),
                    denial.verified_payee_binding,
                );
        }

        self.build_deny_response_with_metadata_and_payee_binding(
            denial.request,
            denial.reason,
            denial.timestamp,
            Some(denial.matched_grant_index),
            runtime_admission_metadata,
            denial.verified_payee_binding,
        )
    }

    fn pre_dispatch_threshold_cleanup_deny_response(
        &self,
        denial: PreDispatchCleanupDeny<'_>,
        credential_disposition: PaymentCredentialDisposition,
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
        let runtime_admission_metadata = self.merge_dispatch_credential_disposition_metadata(
            denial.runtime_admission_metadata,
            credential_disposition,
        );
        let (mut runtime_admission_metadata, runtime_release_confirmed) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        if !runtime_release_confirmed {
            return Err(KernelError::Internal(
                "threshold runtime admission cleanup could not be confirmed".to_string(),
            ));
        }
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
            return self
                .build_pre_execution_monetary_deny_response_with_metadata_and_payee_binding(
                    denial.request,
                    denial.reason,
                    denial.timestamp,
                    charge,
                    reverse.committed_cost_units_after,
                    denial.cap,
                    self.merge_budget_receipt_metadata(
                        runtime_admission_metadata,
                        self.budget_execution_receipt_metadata(
                            charge,
                            Some(("reversed", reverse)),
                            None,
                        )?,
                    ),
                    denial.verified_payee_binding,
                );
        }

        self.build_deny_response_with_metadata_and_payee_binding(
            denial.request,
            denial.reason,
            denial.timestamp,
            Some(denial.matched_grant_index),
            runtime_admission_metadata,
            denial.verified_payee_binding,
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
        let (runtime_admission_metadata, runtime_release_confirmed) = self
            .release_runtime_admission_reservations_for_pre_dispatch_denial(
                runtime_admission_metadata,
            );
        if !runtime_release_confirmed {
            return Err(KernelError::Internal(
                "execution nonce preflight runtime cleanup could not be confirmed".to_string(),
            ));
        }
        let budget_metadata = match (budget_mutation.charge_result(), reverse.as_ref()) {
            (Some(charge), Some(reverse)) => Some(self.budget_execution_receipt_metadata(
                charge,
                Some(("reversed", reverse)),
                None,
            )?),
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
            EXECUTION_NONCE_PREFLIGHT_RETRY_REASON,
            None,
        )
    }

    /// Build the pre-execution authorization response for a caller that executes
    /// the tool itself (the sidecar mediated `/v1/evaluate` route).
    ///
    /// Unlike [`Self::build_execution_nonce_preflight_allow_response_after_cleanup`],
    /// a monetary reservation KEEPS the pre-execution budget hold reserved
    /// (open): it does not call `reverse_pre_execution_budget_mutation`. Only the
    /// in-memory per-dispatch runtime-admission slot is released, because the tool
    /// never dispatches on this kernel. The delegated child's sibling-sum share
    /// stays admitted in `budget_registry` and is recorded against the reserved
    /// hold (see `build_execution_nonce_preflight_allow_response_with_metadata`),
    /// so an outstanding reservation still counts against the parent; it is
    /// released only when the hold closes (reconciled by nonce or reaped). The
    /// durable hold stays open so it also enforces `max_total_cost` against
    /// concurrent authorizations; it is reconciled at the execution site when
    /// the caller presents the minted nonce, or reclaimed by the crash reaper
    /// if the caller never executes (fail-closed, never over-subscribed).
    ///
    /// An invocation-limited non-monetary grant authorizes an atomic
    /// zero-exposure hold. Only a fully unlimited grant authorizes no hold and
    /// releases its sibling-sum share immediately.
    ///
    /// The receipt records the reserved hold's authorize block with no terminal
    /// disposition, so it is truthfully non-authoritative: the hold is reserved,
    /// not reconciled, and `is_authoritative_spend_receipt` rejects it.
    pub(super) fn build_execution_nonce_authorization_reserving_response(
        &self,
        reserving: ExecutionNonceReservingResponse<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        let ExecutionNonceReservingResponse {
            request,
            timestamp,
            matched_grant_index,
            budget_mutation,
            runtime_admission_metadata,
            caller_receipt_metadata,
            reserved_payment_reference,
            threshold_supplemental_prepared,
            budget_lease_acquired,
        } = reserving;

        // Only an unlimited grant (no reserved hold at all) authorizes nothing
        // durable to record the delegated child's admitted sibling-sum share
        // against, so its share is released now, matching the reverse-for-retry
        // preflight; otherwise it would stay admitted for the parent's whole
        // lifetime, permanently shrinking its sibling-sum headroom. A monetary OR
        // an invocation-only grant creates a durable reserved hold below, so its
        // share is RETAINED and recorded against that hold, then released when the
        // hold closes (reconcile-by-nonce or the TTL reaper, both keyed off the
        // hold id). The reference-counted release runs only when THIS evaluation
        // acquired a lease, so it never frees an overlapping sibling's still-held
        // share.
        if matches!(budget_mutation, PreExecutionBudgetMutation::None) && budget_lease_acquired {
            self.release_admitted_capability_budget(&request.capability)
                .map_err(KernelError::DelegationInvalid)?;
        }

        // Record the reserved hold's authorize block with NO terminal event:
        // the hold is open, neither reversed nor reconciled. This is what keeps
        // the receipt non-authoritative and keeps the budget reserved.
        let metadata =
            self.caller_reservation_response_metadata(budget_mutation, runtime_admission_metadata)?;

        if let PreExecutionBudgetMutation::Admission(admission) = budget_mutation {
            return self.build_operation_owned_caller_reservation_response(
                OperationOwnedCallerReservationResponse {
                    request,
                    admission,
                    caller_receipt_metadata,
                    reserved_payment_reference,
                    threshold_supplemental_prepared,
                    budget_lease_acquired,
                },
            );
        }

        // The reserved hold is kept open and bound into the signed nonce so
        // reconcile-by-nonce (and reverse-by-nonce) can name the exact hold to
        // settle at the execution site. The response builder stamps the hold's TTL
        // deadline from the minted nonce's exact expiry, keeping the reaper
        // deadline and the nonce validity window consistent. A monetary grant
        // keeps its already-authorized charge; an invocation-only caller
        // reservation stamps the zero-exposure hold that was authorized atomically
        // with its invocation debit.
        let reserved_hold = match budget_mutation {
            PreExecutionBudgetMutation::Charge(charge) => Some(ReservedHoldStamp::Monetary {
                charge,
                payment_reference: reserved_payment_reference,
            }),
            PreExecutionBudgetMutation::Invocation { .. } => {
                return Err(KernelError::Internal(
                    "caller reservation reached response without an atomic invocation hold"
                        .to_string(),
                ));
            }
            PreExecutionBudgetMutation::Admission(_) => {
                return Err(KernelError::Internal(
                    "operation-owned reservation bypassed the composite reservation builder"
                        .to_string(),
                ));
            }
            PreExecutionBudgetMutation::None => None,
        };

        self.build_execution_nonce_preflight_allow_response_with_metadata(
            request,
            timestamp,
            Some(matched_grant_index),
            metadata,
            EXECUTION_NONCE_AUTHORIZATION_RESERVED_REASON,
            reserved_hold,
        )
    }

    pub(crate) fn caller_reservation_response_metadata(
        &self,
        budget_mutation: &PreExecutionBudgetMutation,
        runtime_admission_metadata: Option<serde_json::Value>,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        let budget_metadata = if let Some(charge) = budget_mutation.charge_result() {
            Some(self.budget_execution_receipt_metadata(charge, None, None)?)
        } else {
            None
        };
        let authorization_metadata = Some(serde_json::json!({
            "execution_nonce": {
                "stage": "authorization",
                "tool_dispatched": false,
                "hold_disposition": "reserved"
            }
        }));
        Ok(merge_metadata_objects(
            merge_metadata_objects(runtime_admission_metadata, budget_metadata),
            authorization_metadata,
        ))
    }

    pub(crate) fn prepare_operation_owned_caller_reservation_handoff(
        &self,
        request: &ToolCallRequest,
        timestamp: u64,
        matched_grant_index: usize,
        admission: &OrdinaryAdmissionMutation,
        response_metadata: Option<serde_json::Value>,
        caller_receipt_metadata: Option<&serde_json::Value>,
    ) -> Result<(), KernelError> {
        self.prepare_caller_reservation_handoff_intent(PrepareCallerReservationHandoff {
            request,
            timestamp,
            matched_grant_index,
            admission,
            response_metadata,
            caller_receipt_metadata,
            incomplete_reason: EXECUTION_NONCE_AUTHORIZATION_RESERVED_REASON,
        })
    }
}
