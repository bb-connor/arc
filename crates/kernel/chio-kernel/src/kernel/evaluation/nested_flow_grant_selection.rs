//! Grant selection for the nested-flow evaluation path.

use std::ops::ControlFlow;

use super::evaluation_helpers::PreDispatchCleanupDeny;
use super::*;
use crate::kernel::admission_coordinator::DurableRefusalResponse;

/// Inputs to nested-flow grant selection: the matching grants in specificity
/// order and the admission state every candidate is validated against.
pub(super) struct NestedFlowGrantSelection<'a> {
    pub(super) parent_context: &'a OperationContext,
    pub(super) request: &'a ToolCallRequest,
    pub(super) extra_metadata: &'a Option<serde_json::Value>,
    pub(super) security_context: Option<&'a SecurityInvocationContext>,
    pub(super) session_guard_attempt: Option<GuardInvocationAttempt>,
    pub(super) now: u64,
    pub(super) now_unix_ms: u64,
    pub(super) cap: &'a CapabilityToken,
    pub(super) matching_grants: &'a [MatchingGrant<'a>],
    pub(super) required_delivery_grant_index: Option<usize>,
    pub(super) durable_admission: &'a mut Option<DurableToolAdmission>,
    pub(super) session_roots: &'a [String],
}

/// The grant that passed governed validation, guards, runtime admission, and
/// the budget charge, with the admission state the dispatch path carries on.
pub(super) struct SelectedNestedFlowGrant {
    pub(super) matched_grant_index: usize,
    pub(super) budget_mutation: PreExecutionBudgetMutation,
    pub(super) validated_governed_admission: Option<ValidatedGovernedAdmission>,
    pub(super) governed_call_chain_receipt_evidence: Option<GovernedCallChainReceiptEvidence>,
    pub(super) pre_invocation_guard_output: crate::kernel::PreInvocationGuardOutput,
    pub(super) runtime_admission_metadata: Option<serde_json::Value>,
}

impl ChioKernel {
    pub(super) async fn select_nested_flow_grant(
        &self,
        selection: NestedFlowGrantSelection<'_>,
    ) -> Result<ControlFlow<ToolCallResponse, SelectedNestedFlowGrant>, KernelError> {
        let NestedFlowGrantSelection {
            parent_context,
            request,
            extra_metadata,
            security_context,
            session_guard_attempt,
            now,
            now_unix_ms,
            cap,
            matching_grants,
            required_delivery_grant_index,
            durable_admission,
            session_roots,
        } = selection;
        let mut budget_error = None;
        let mut budget_error_metadata = None;
        let mut runtime_release_retained = false;
        let mut governed_error = None;
        let mut guard_denial = None;
        let mut selected = None;
        let guard_attempt = GuardInvocationAttempt::for_evaluation(
            durable_admission.as_ref(),
            session_guard_attempt,
        );
        for matching in matching_grants {
            if required_delivery_grant_index.is_some_and(|required| matching.index != required) {
                continue;
            }
            if durable_admission
                .as_ref()
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
            let no_budget_mutation = PreExecutionBudgetMutation::None;
            let mut guard_drop_guard = PostAdmissionDropGuard::new(
                self,
                request,
                cap,
                Some(matching.index),
                &no_budget_mutation,
                None,
                PostAdmissionReceiptContext {
                    extra_metadata: extra_metadata.clone(),
                    pre_invocation_guard_output: crate::kernel::PreInvocationGuardOutput::default(),
                    verified_payee_binding: validated_governed_admission
                        .as_ref()
                        .and_then(|admission| admission.verified_payee_binding.clone()),
                },
                false,
            )
            .with_durable_operation(
                durable_admission
                    .as_ref()
                    .map(DurableToolAdmission::operation),
            );
            let guard_result = self
                .run_guards_within_budget(
                    request,
                    &cap.scope,
                    Some(session_roots),
                    Some(matching.index),
                    security_context,
                    &guard_attempt,
                )
                .await;
            guard_drop_guard.disarm();
            drop(guard_drop_guard);
            let pre_invocation_guard_output = match guard_result {
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
                durable_admission.as_mut(),
            );
            let runtime_admission_metadata =
                merge_metadata_objects(extra_metadata.clone(), runtime_admission.metadata.clone());
            if !runtime_admission.allowed {
                let denial = Denial::new(
                    ClientDenialCode::RuntimeAdmissionDenied,
                    runtime_admission
                        .reason
                        .unwrap_or_else(|| "runtime admission denied".to_string()),
                );
                warn!(request_id = %request.request_id, reason = %redacted!(denial.detail()), "runtime admission denied (nested flow)");
                let (runtime_admission_metadata, runtime_release_confirmed) = self
                    .release_runtime_admission_reservations_for_hook_denial(
                        durable_admission
                            .as_ref()
                            .map(DurableToolAdmission::operation),
                        runtime_admission_metadata,
                        runtime_admission.hook_release_metadata.as_ref(),
                    );
                if !runtime_release_confirmed && durable_admission.is_some() {
                    return Err(KernelError::DurableAdmission(
                        "runtime admission reservation release could not be confirmed".into(),
                    ));
                }
                return self
                    .with_pre_invocation_guard_output(&pre_invocation_guard_output, || {
                        if runtime_release_confirmed && durable_admission.is_some() {
                            if let Some(response) = self
                                .compensate_durable_admission_after_pre_dispatch_cleanup(
                                    durable_admission
                                        .as_ref()
                                        .map(DurableToolAdmission::operation),
                                    None,
                                    None,
                                    None,
                                    DurableRefusalResponse {
                                        denial: &denial,
                                        cancelled: false,
                                        matched_grant_index: Some(matching.index),
                                        metadata: runtime_admission_metadata.clone(),
                                        verified_payee_binding: None,
                                    },
                                )?
                            {
                                return Ok(response);
                            }
                        }
                        self.build_runtime_admission_deny_response_with_metadata(
                            request,
                            &denial,
                            now,
                            Some(matching.index),
                            RefusalReceiptMetadata::new(
                                runtime_admission_metadata,
                                if durable_admission.is_some() || !runtime_release_confirmed {
                                    IdentityDisposition::Terminal
                                } else {
                                    IdentityDisposition::Reusable
                                },
                            ),
                        )
                    })
                    .map(ControlFlow::Break);
            }

            match self.check_and_increment_budget(
                request,
                cap,
                std::slice::from_ref(matching),
                self.execution_nonce_preflight_required(request),
                durable_admission.as_mut(),
                now_unix_ms,
            ) {
                Ok(BudgetAdmissionOutcome::Authorized {
                    grant_index,
                    mutation,
                }) => {
                    if let Err(error) = self.reserve_validated_governed_approval(
                        request,
                        validated_governed_admission.as_ref(),
                        durable_admission.as_mut(),
                        now_unix_ms,
                    ) {
                        let denial = Denial::from_error(&error);
                        return self
                            .build_pre_dispatch_cleanup_deny_response(PreDispatchCleanupDeny {
                                request,
                                denial: &denial,
                                timestamp: now,
                                matched_grant_index: grant_index,
                                cap,
                                budget_mutation: mutation.as_ref(),
                                payment_authorization: None,
                                durable_operation: durable_admission
                                    .as_ref()
                                    .map(DurableToolAdmission::operation),
                                runtime_admission_metadata: error
                                    .rejection_metadata(runtime_admission_metadata),
                                verified_payee_binding: None,
                                budget_lease_acquired: false,
                            })
                            .map(ControlFlow::Break);
                    }
                    selected = Some((
                        grant_index,
                        *mutation,
                        validated_governed_admission,
                        governed_call_chain_receipt_evidence,
                        pre_invocation_guard_output,
                        runtime_admission_metadata,
                    ));
                    break;
                }
                Ok(BudgetAdmissionOutcome::PendingApproval {
                    grant_index,
                    proposal,
                }) => {
                    let (runtime_admission_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata,
                        );
                    if !runtime_release_confirmed {
                        budget_error = Some(KernelError::DurableAdmission(
                            "runtime admission reservation retained on pending approval"
                                .to_string(),
                        ));
                        budget_error_metadata = runtime_admission_metadata;
                        runtime_release_retained = true;
                        break;
                    }
                    return self
                        .with_pre_invocation_guard_output(&pre_invocation_guard_output, || {
                            self.build_pending_approval_response_with_metadata(
                                request,
                                &proposal,
                                now,
                                grant_index,
                                runtime_admission_metadata,
                            )
                        })
                        .map(ControlFlow::Break);
                }
                Err(error @ KernelError::BudgetExhausted(_)) => {
                    let (runtime_admission_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata,
                        );
                    budget_error = Some(
                        if required_delivery_grant_index == Some(matching.index)
                            && matching_grants.len() > 1
                        {
                            KernelError::DurableAdmission(
                                "a delivery-marked grant cannot be bypassed by sibling grant selection"
                                    .to_string(),
                            )
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
                    let denial = Denial::from_error(&error);
                    let (runtime_admission_metadata, runtime_release_confirmed) = self
                        .release_runtime_admission_reservations_for_pre_dispatch_denial(
                            durable_admission
                                .as_ref()
                                .map(DurableToolAdmission::operation),
                            runtime_admission_metadata,
                        );
                    if !runtime_release_confirmed && durable_admission.is_some() {
                        return Err(error);
                    }
                    let receipt_metadata = self.merge_budget_receipt_metadata(
                        error.rejection_metadata(runtime_admission_metadata),
                        self.budget_backend_receipt_metadata()?,
                    );
                    return self
                        .with_pre_invocation_guard_output(&pre_invocation_guard_output, || {
                            if runtime_release_confirmed && durable_admission.is_some() {
                                let (matched_grant_index, financial_metadata) =
                                    self.monetary_deny_metadata(matching_grants, cap)?;
                                if let Some(response) = self
                                    .compensate_durable_admission_after_pre_dispatch_cleanup(
                                        durable_admission
                                            .as_ref()
                                            .map(DurableToolAdmission::operation),
                                        None,
                                        None,
                                        None,
                                        DurableRefusalResponse {
                                            denial: &denial,
                                            cancelled: false,
                                            matched_grant_index,
                                            metadata: merge_metadata_objects(
                                                financial_metadata,
                                                receipt_metadata.clone(),
                                            ),
                                            verified_payee_binding: None,
                                        },
                                    )?
                                {
                                    return Ok(response);
                                }
                            }
                            self.build_monetary_deny_response_with_metadata(
                                request,
                                &denial,
                                now,
                                matching_grants,
                                cap,
                                RefusalReceiptMetadata::new(
                                    receipt_metadata,
                                    if durable_admission.is_some() || !runtime_release_confirmed {
                                        IdentityDisposition::Terminal
                                    } else {
                                        IdentityDisposition::Reusable
                                    },
                                ),
                            )
                        })
                        .map(ControlFlow::Break);
                }
            }
        }

        let Some((
            matched_grant_index,
            budget_mutation,
            validated_governed_admission,
            governed_call_chain_receipt_evidence,
            pre_invocation_guard_output,
            runtime_admission_metadata,
        )) = selected
        else {
            // Guards are evaluated per grant, so a denial on one candidate only
            // decides the request once every later candidate has also failed.
            // A recorded budget denial still wins, since it carries the
            // stuck-reservation evidence the loop broke out to preserve.
            if budget_error.is_none() {
                if let Some(guard) = guard_denial {
                    let denial = Denial::from_error(&guard.error);
                    let receipt_metadata = Some(self.budget_backend_receipt_metadata()?);
                    return self
                        .with_pre_invocation_guard_output(&guard.output, || {
                            if durable_admission.is_some() {
                                let (matched_grant_index, financial_metadata) =
                                    self.monetary_deny_metadata(matching_grants, cap)?;
                                if let Some(response) = self
                                    .compensate_durable_admission_after_pre_dispatch_cleanup(
                                        durable_admission
                                            .as_ref()
                                            .map(DurableToolAdmission::operation),
                                        None,
                                        None,
                                        None,
                                        DurableRefusalResponse {
                                            denial: &denial,
                                            cancelled: false,
                                            matched_grant_index,
                                            metadata: merge_metadata_objects(
                                                financial_metadata,
                                                receipt_metadata.clone(),
                                            ),
                                            verified_payee_binding: None,
                                        },
                                    )?
                                {
                                    return Ok(response);
                                }
                            }
                            self.build_monetary_deny_response_with_metadata(
                                request,
                                &denial,
                                now,
                                matching_grants,
                                cap,
                                RefusalReceiptMetadata::new(
                                    receipt_metadata,
                                    if durable_admission.is_some() {
                                        IdentityDisposition::Terminal
                                    } else {
                                        IdentityDisposition::Reusable
                                    },
                                ),
                            )
                        })
                        .map(ControlFlow::Break);
                }
            }
            let error = budget_error.or(governed_error).unwrap_or_else(|| {
                KernelError::DurableAdmission(
                    "retained budget hold does not identify a matching grant".to_string(),
                )
            });
            let denial = Denial::from_error(&error);
            if durable_admission.as_ref().is_some_and(|admission| {
                runtime_release_retained
                    || !matches!(
                        admission.state(),
                        crate::admission_operation::AdmissionOperationState::Prepared
                            | crate::admission_operation::AdmissionOperationState::BrokerAttemptRegistered
                    )
            }) {
                return Err(error);
            }
            let receipt_metadata = self.merge_budget_receipt_metadata(
                error.rejection_metadata(merge_metadata_objects(
                    extra_metadata.clone(),
                    budget_error_metadata,
                )),
                self.budget_backend_receipt_metadata()?,
            );
            if durable_admission.is_some() {
                let (matched_grant_index, financial_metadata) =
                    self.monetary_deny_metadata(matching_grants, cap)?;
                if let Some(response) = self
                    .compensate_durable_admission_after_pre_dispatch_cleanup(
                        durable_admission
                            .as_ref()
                            .map(DurableToolAdmission::operation),
                        None,
                        None,
                        None,
                        DurableRefusalResponse {
                            denial: &denial,
                            cancelled: false,
                            matched_grant_index,
                            metadata: merge_metadata_objects(
                                financial_metadata,
                                receipt_metadata.clone(),
                            ),
                            verified_payee_binding: None,
                        },
                    )?
                {
                    return Ok(ControlFlow::Break(response));
                }
            }
            return self
                .build_monetary_deny_response_with_metadata(
                    request,
                    &denial,
                    now,
                    matching_grants,
                    cap,
                    RefusalReceiptMetadata::new(
                        receipt_metadata,
                        if durable_admission.is_some() || runtime_release_retained {
                            IdentityDisposition::Terminal
                        } else {
                            IdentityDisposition::Reusable
                        },
                    ),
                )
                .map(ControlFlow::Break);
        };

        Ok(ControlFlow::Continue(SelectedNestedFlowGrant {
            matched_grant_index,
            budget_mutation,
            validated_governed_admission,
            governed_call_chain_receipt_evidence,
            pre_invocation_guard_output,
            runtime_admission_metadata,
        }))
    }
}
