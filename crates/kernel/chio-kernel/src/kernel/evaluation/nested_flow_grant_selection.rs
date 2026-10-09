//! Grant selection for the nested-flow evaluation path.

use std::ops::ControlFlow;

use super::pre_dispatch_custody::{
    AdmissionDenial, BudgetedAdmission, OperationSettlement, PreparedAdmission, SelectedGrant,
};
use super::*;

/// Inputs to nested-flow grant selection: the matching grants in specificity
/// order and the admission state every candidate is validated against.
pub(super) struct NestedFlowGrantSelection<'a> {
    pub(super) parent_context: &'a OperationContext,
    pub(super) request: &'a ToolCallRequest,
    pub(super) extra_metadata: &'a Option<serde_json::Value>,
    pub(super) security_context: Option<&'a SecurityInvocationContext>,
    pub(super) now: u64,
    pub(super) now_unix_ms: u64,
    pub(super) cap: &'a CapabilityToken,
    pub(super) matching_grants: &'a [MatchingGrant<'a>],
    pub(super) required_delivery_grant_index: Option<usize>,
    pub(super) session_roots: &'a [String],
}

/// The governed evidence of the grant that passed governed validation,
/// guards, runtime admission, and the budget charge. Its admitted resources
/// are in the returned custody.
pub(super) struct SelectedNestedFlowGrant {
    pub(super) validated_governed_admission: Option<ValidatedGovernedAdmission>,
    pub(super) governed_call_chain_receipt_evidence: Option<GovernedCallChainReceiptEvidence>,
}

pub(super) type NestedFlowGrantSelectionOutcome<'c> =
    ControlFlow<ToolCallResponse, (BudgetedAdmission<'c>, SelectedNestedFlowGrant)>;

impl ChioKernel {
    pub(super) async fn select_nested_flow_grant<'c>(
        &self,
        mut custody: PreparedAdmission<'c>,
        selection: NestedFlowGrantSelection<'_>,
    ) -> Result<NestedFlowGrantSelectionOutcome<'c>, KernelError> {
        let NestedFlowGrantSelection {
            parent_context,
            request,
            extra_metadata,
            security_context,
            now,
            now_unix_ms,
            cap,
            matching_grants,
            required_delivery_grant_index,
            session_roots,
        } = selection;
        let mut budget_error = None;
        let mut budget_error_metadata = None;
        let mut runtime_release_retained = false;
        let mut governed_error = None;
        let mut guard_denial = None;
        let mut selected = None;
        for matching in matching_grants {
            if required_delivery_grant_index.is_some_and(|required| matching.index != required) {
                continue;
            }
            if custody
                .durable()
                .is_some_and(|admission| !admission.permits_matching_grant(matching))
            {
                continue;
            }

            let validated_governed_admission = match self.validate_governed_transaction_pure(
                request,
                cap,
                matching.grant,
                GovernedValidationContext {
                    parent_context: Some(parent_context),
                    now,
                },
            ) {
                Ok(validated) => validated,
                Err(error) => {
                    governed_error.get_or_insert(error);
                    continue;
                }
            };
            let governed_call_chain_receipt_evidence = match self
                .governed_call_chain_receipt_evidence(
                    request,
                    cap,
                    Some(parent_context),
                    validated_governed_admission
                        .as_ref()
                        .and_then(|admission| admission.call_chain_proof.clone()),
                ) {
                Ok(evidence) => evidence,
                Err(error) => {
                    governed_error.get_or_insert(error);
                    continue;
                }
            };
            custody.attempt(
                matching.index,
                validated_governed_admission
                    .as_ref()
                    .and_then(|admission| admission.verified_payee_binding.clone()),
            );
            let guard_result = self
                .run_guards_within_budget(
                    request,
                    &cap.scope,
                    Some(session_roots),
                    Some(matching.index),
                    security_context,
                )
                .await;
            let pre_invocation_guard_evidence = match guard_result {
                Ok(evidence) => evidence,
                Err(error) => {
                    let msg = error.error.to_string();
                    warn!(request_id = %request.request_id, reason = %redacted!(&msg), "guard denied (nested flow)");
                    guard_denial.get_or_insert(error);
                    continue;
                }
            };
            let runtime_admission = self.run_pre_budget_admission(
                request,
                security_context,
                extra_metadata.as_ref(),
                now,
                now_unix_ms,
                matching.index,
                matching_grants
                    .iter()
                    .any(|grant| grant.grant.dpop_required == Some(true)),
                custody.durable_mut(),
            );
            let runtime_reservation = RuntimeReservation::from_decision(&runtime_admission);
            let runtime_admission_metadata =
                merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
            if !runtime_admission.allowed {
                let msg = runtime_admission
                    .reason
                    .unwrap_or_else(|| "runtime admission denied".to_string());
                warn!(request_id = %request.request_id, reason = %redacted!(&msg), "runtime admission denied (nested flow)");
                let (runtime_admission_metadata, runtime_release_confirmed) = self
                    .release_runtime_admission_reservations_for_pre_dispatch_denial(
                        custody.operation(),
                        &runtime_reservation,
                        runtime_admission_metadata,
                    );
                return custody
                    .settle_then(
                        OperationSettlement::compensate_if(runtime_release_confirmed),
                        || {
                            self.with_pre_invocation_guard_evidence(
                                &pre_invocation_guard_evidence,
                                || {
                                    self.build_runtime_admission_deny_response_with_metadata(
                                        request,
                                        &msg,
                                        now,
                                        Some(matching.index),
                                        runtime_admission_metadata,
                                    )
                                },
                            )
                        },
                    )
                    .map(ControlFlow::Break);
            }

            match self.check_and_increment_budget(
                request,
                cap,
                std::slice::from_ref(matching),
                self.execution_nonce_preflight_required(request),
                custody.durable_mut(),
                now_unix_ms,
            ) {
                Ok(BudgetAdmissionOutcome::Authorized {
                    grant_index,
                    mutation,
                }) => {
                    if let Err(error) = self.reserve_validated_governed_approval(
                        request,
                        validated_governed_admission.as_ref(),
                        custody.durable_mut(),
                        now_unix_ms,
                    ) {
                        let msg = error.to_string();
                        return custody
                            .select(SelectedGrant {
                                grant_index,
                                budget: *mutation,
                                runtime: runtime_reservation,
                                metadata: runtime_admission_metadata,
                                evidence: None,
                                payee: None,
                            })
                            .deny(AdmissionDenial::new(&msg))
                            .map(ControlFlow::Break);
                    }
                    selected = Some((
                        grant_index,
                        *mutation,
                        validated_governed_admission,
                        governed_call_chain_receipt_evidence,
                        pre_invocation_guard_evidence,
                        runtime_admission_metadata,
                        runtime_reservation,
                    ));
                    break;
                }
                Ok(BudgetAdmissionOutcome::PendingApproval {
                    grant_index,
                    proposal,
                }) => {
                    let (runtime_admission_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            custody.operation(),
                            &runtime_reservation,
                            runtime_admission_metadata,
                        );
                    if !runtime_release_confirmed {
                        budget_error = Some(KernelError::admission_pending(
                            "runtime admission reservation retained on pending approval",
                        ));
                        budget_error_metadata = runtime_admission_metadata;
                        runtime_release_retained = true;
                        break;
                    }
                    // The parked operation keeps its durable state for approval.
                    return custody
                        .settle_then(OperationSettlement::Retain, || {
                            self.with_pre_invocation_guard_evidence(
                                &pre_invocation_guard_evidence,
                                || {
                                    self.build_pending_approval_response_with_metadata(
                                        request,
                                        &proposal,
                                        now,
                                        grant_index,
                                        runtime_admission_metadata,
                                    )
                                },
                            )
                        })
                        .map(ControlFlow::Break);
                }
                Err(error @ KernelError::BudgetExhausted(_)) => {
                    let (runtime_admission_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            custody.operation(),
                            &runtime_reservation,
                            runtime_admission_metadata,
                        );
                    budget_error = Some(
                        if required_delivery_grant_index == Some(matching.index)
                            && matching_grants.len() > 1
                        {
                            KernelError::admission_refused("a delivery-marked grant cannot be bypassed by sibling grant selection")
                        } else {
                            error
                        },
                    );
                    if !runtime_release_confirmed {
                        budget_error_metadata = runtime_admission_metadata;
                        runtime_release_retained = true;
                        break;
                    }
                }
                Err(error) => {
                    let msg = error.to_string();
                    let (runtime_admission_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            custody.operation(),
                            &runtime_reservation,
                            runtime_admission_metadata,
                        );
                    return custody
                        .settle_then(
                            OperationSettlement::compensate_if(runtime_release_confirmed),
                            || {
                                self.with_pre_invocation_guard_evidence(
                                    &pre_invocation_guard_evidence,
                                    || {
                                        self.build_monetary_deny_response_with_metadata(
                                            request,
                                            &msg,
                                            now,
                                            matching_grants,
                                            cap,
                                            self.merge_budget_receipt_metadata(
                                                runtime_admission_metadata,
                                                self.budget_backend_receipt_metadata()?,
                                            ),
                                        )
                                    },
                                )
                            },
                        )
                        .map(ControlFlow::Break);
                }
            }
        }

        let Some((
            matched_grant_index,
            budget_mutation,
            validated_governed_admission,
            governed_call_chain_receipt_evidence,
            pre_invocation_guard_evidence,
            runtime_admission_metadata,
            runtime_reservation,
        )) = selected
        else {
            // Guards are evaluated per grant, so a denial on one candidate only
            // decides the request once every later candidate has also failed.
            // A recorded budget denial still wins, since it carries the
            // stuck-reservation evidence the loop broke out to preserve.
            if budget_error.is_none() {
                if let Some(denial) = guard_denial {
                    let msg = denial.error.to_string();
                    return custody
                        .settle_then(OperationSettlement::Compensate, || {
                            let receipt_metadata = Some(self.budget_backend_receipt_metadata()?);
                            self.with_pre_invocation_guard_evidence(&denial.evidence, || {
                                self.build_monetary_deny_response_with_metadata(
                                    request,
                                    &msg,
                                    now,
                                    matching_grants,
                                    cap,
                                    receipt_metadata,
                                )
                            })
                        })
                        .map(ControlFlow::Break);
                }
            }
            let error = budget_error.or(governed_error).unwrap_or_else(|| {
                KernelError::admission_record(
                    "retained budget hold does not identify a matching grant",
                )
            });
            let msg = error.to_string();
            // An unconfirmed runtime release keeps the operation on its
            // recovery path, as at every other pre-dispatch denial.
            let settlement = OperationSettlement::compensate_if(
                !runtime_release_retained
                    && custody.durable().is_some_and(|admission| {
                        admission.state()
                    == crate::admission_operation::AdmissionOperationState::BrokerAttemptRegistered
                    }),
            );
            return custody
                .settle_then(settlement, || {
                    self.build_monetary_deny_response_with_metadata(
                        request,
                        &msg,
                        now,
                        matching_grants,
                        cap,
                        self.merge_budget_receipt_metadata(
                            error.rejection_metadata(merge_metadata_objects(
                                extra_metadata.clone(),
                                budget_error_metadata,
                            )),
                            self.budget_backend_receipt_metadata()?,
                        ),
                    )
                })
                .map(ControlFlow::Break);
        };

        let payee = validated_governed_admission
            .as_ref()
            .and_then(|admission| admission.verified_payee_binding.clone());
        let custody = custody.select(SelectedGrant {
            grant_index: matched_grant_index,
            budget: budget_mutation,
            runtime: runtime_reservation,
            metadata: runtime_admission_metadata,
            evidence: Some(pre_invocation_guard_evidence),
            payee,
        });
        Ok(ControlFlow::Continue((
            custody,
            SelectedNestedFlowGrant {
                validated_governed_admission,
                governed_call_chain_receipt_evidence,
            },
        )))
    }
}
