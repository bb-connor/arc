//! Payment and budget outcomes retained while preparing terminal tool output.

use super::payment_outcome::{
    release_unsettled_payment_metadata, retained_payment_capture_metadata,
};
use super::*;
use crate::kernel::responses::AllowResponseNonce;

impl ChioKernel {
    pub(crate) fn tool_server_measures_realized_cost(&self, server_id: &str) -> bool {
        self.tool_servers
            .get(server_id)
            .is_none_or(|server| server.measures_realized_cost())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Keep the existing explicit boundary parameters together; changing the owning API is separate from enforcing unsafe and panic rules."
    )]
    fn prepare_unmeasured_cost_provisional_allow(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        charge: &BudgetChargeResult,
        extra_metadata: Option<serde_json::Value>,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
        mut fault_progress: Option<
            &mut crate::kernel::effect_obligation::recovery::PreparedFaultReceipt,
        >,
    ) -> Result<crate::kernel::responses::PreparedResponse, KernelError> {
        let cap = &request.capability;
        let reverse = if charge.invocation_capture.is_some() {
            self.cancel_captured_monetary_before_dispatch(&cap.id, charge)?
        } else {
            self.reverse_budget_charge(&cap.id, charge)?
        };
        if let Some(progress) = fault_progress.as_deref_mut() {
            progress.observe_economics(Some(&self.budget_execution_receipt_metadata(
                charge,
                Some(("reversed", &reverse)),
                None,
            )));
        }
        let financial = FinancialReceiptMetadata {
            grant_index: crate::receipt_support::checked_receipt_count(
                charge.grant_index,
                "grant index",
            )?,
            cost_charged: 0,
            currency: charge.currency.clone(),
            budget_remaining: financial_budget_remaining(
                charge.budget_total,
                reverse.committed_cost_units_after,
            )?,
            budget_total: charge.budget_total,
            delegation_depth: crate::receipt_support::checked_receipt_count(
                cap.delegation_chain.len(),
                "delegation depth",
            )?,
            root_budget_holder: cap.issuer.to_hex(),
            payment_reference: None,
            settlement_status: SettlementStatus::Pending,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: None,
        };
        if let Some(progress) = fault_progress {
            progress.observe_economics(Some(&serde_json::json!({ "financial": financial })));
        }
        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(value) => ToolCallOutput::Value(value.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream))
            | ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };
        let budget_metadata =
            self.budget_execution_receipt_metadata(charge, Some(("reversed", &reverse)), None);
        let metadata = merge_metadata_objects(
            Some(serde_json::json!({ "financial": financial })),
            self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
        );

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .prepare_allow_response_with_metadata_and_payee_binding(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    metadata,
                    verified_payee_binding,
                    AllowResponseNonce::Suppressed,
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .prepare_incomplete_response_with_output_metadata_and_payee_binding(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    RefusalReceiptMetadata::new(
                        self.mark_runtime_admission_reservations_retained_fail_closed(metadata),
                        IdentityDisposition::Terminal,
                    ),
                    verified_payee_binding,
                ),
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Preparation preserves the existing finalization input contract."
    )]
    pub(in crate::kernel) fn prepare_budgeted_tool_output_with_cost_and_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        cost_context: crate::kernel::responses::PrepareToolOutputCostContext<'_>,
        mut extra_metadata: Option<serde_json::Value>,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
        security_context: Option<&SecurityInvocationContext>,
    ) -> Result<crate::kernel::responses::PreparedResponse, KernelError> {
        let crate::kernel::responses::PrepareToolOutputCostContext {
            charge_result,
            reported_cost,
            payment_authorization,
            cap,
            mut fault_progress,
        } = cost_context;
        let Some(charge) = charge_result else {
            if let Some(authorization) = payment_authorization.as_ref() {
                let mut extra_metadata = extra_metadata;
                let (quoted_units, quoted_currency) = Self::mustprepay_quoted_amount(request)
                    .ok_or_else(|| {
                        KernelError::GovernedTransactionDenied(
                            "payment authorization omitted its MustPrepay quote".to_string(),
                        )
                    })?;
                let settlement = if authorization.state.is_final() {
                    ReceiptSettlement::from_authorization(authorization)
                } else {
                    let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                        KernelError::Internal(
                            "payment authorization present without configured adapter".to_string(),
                        )
                    })?;
                    let result = match adapter.capture(
                        &authorization.authorization_id,
                        quoted_units,
                        &quoted_currency,
                        &request.request_id,
                    ) {
                        Ok(result) => {
                            if let Some(progress) = fault_progress.as_deref_mut() {
                                progress.observe_payment_result(
                                    authorization,
                                    &result,
                                    quoted_units,
                                    false,
                                );
                            }
                            result
                        }
                        Err(error) => {
                            // A capture error does not establish that no payment
                            // happened and cannot authorize voiding a positive hold.
                            let metadata = merge_metadata_objects(
                                extra_metadata,
                                Some(retained_payment_capture_metadata(
                                    request,
                                    authorization,
                                    &error,
                                )),
                            );
                            if let Some(progress) = fault_progress.as_deref_mut() {
                                progress.observe_economics(metadata.as_ref());
                            }
                            return self.prepare_deny_response_with_metadata(
                                request,
                                &Denial::new(
                                    ClientDenialCode::PaymentUnavailable,
                                    format!(
                                        "MustPrepay authorization could not be settled after execution: {}",
                                        error.code()
                                    ),
                                ),
                                timestamp,
                                Some(matched_grant_index),
                                RefusalReceiptMetadata::new(self.mark_runtime_admission_reservations_retained_fail_closed(
                                    metadata,
                                ), IdentityDisposition::Terminal),
                            );
                        }
                    };
                    if result.settlement_status != crate::payment::RailSettlementStatus::Settled {
                        let financial = release_unsettled_payment_metadata(
                            adapter.as_ref(),
                            request,
                            authorization,
                            &result,
                        );
                        let release_metadata = serde_json::json!({ "financial": financial });
                        if let Some(progress) = fault_progress.as_deref_mut() {
                            progress.observe_economics(Some(&release_metadata));
                        }
                        extra_metadata =
                            merge_metadata_objects(extra_metadata, Some(release_metadata));
                    }
                    ReceiptSettlement::from_payment_result(&result)
                };
                if let Some(progress) = fault_progress.as_deref_mut() {
                    progress.observe_economics(extra_metadata.as_ref());
                }
                if settlement.settlement_status != SettlementStatus::Settled {
                    return self.prepare_deny_response_with_metadata(
                        request,
                        &Denial::new(
                            ClientDenialCode::PaymentUnavailable,
                            "MustPrepay authorization could not be settled after execution",
                        ),
                        timestamp,
                        Some(matched_grant_index),
                        RefusalReceiptMetadata::new(extra_metadata, IdentityDisposition::Terminal),
                    );
                }
                let (payment_reference, settlement_status) = settlement.into_receipt_parts();
                let financial = FinancialReceiptMetadata {
                    grant_index: crate::receipt_support::checked_receipt_count(
                        matched_grant_index,
                        "grant index",
                    )?,
                    cost_charged: quoted_units,
                    currency: quoted_currency,
                    budget_remaining: None,
                    budget_total: None,
                    delegation_depth: crate::receipt_support::checked_receipt_count(
                        cap.delegation_chain.len(),
                        "delegation depth",
                    )?,
                    root_budget_holder: cap.issuer.to_hex(),
                    payment_reference,
                    settlement_status,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: None,
                };
                let metadata = merge_metadata_objects(
                    extra_metadata,
                    Some(serde_json::json!({ "financial": financial })),
                );
                if let Some(progress) = fault_progress.as_deref_mut() {
                    progress.observe_economics(metadata.as_ref());
                }
                return self.prepare_tool_output_with_metadata_and_payee_binding(
                    request,
                    output,
                    elapsed,
                    timestamp,
                    matched_grant_index,
                    metadata,
                    verified_payee_binding,
                    security_context,
                );
            }
            return self.prepare_tool_output_with_metadata_and_payee_binding(
                request,
                output,
                elapsed,
                timestamp,
                matched_grant_index,
                extra_metadata,
                verified_payee_binding,
                security_context,
            );
        };

        if payment_authorization.is_none()
            && !self.tool_server_measures_realized_cost(&request.server_id)
        {
            return self.prepare_unmeasured_cost_provisional_allow(
                request,
                output,
                elapsed,
                timestamp,
                charge,
                extra_metadata,
                verified_payee_binding,
                fault_progress,
            );
        }

        let reported_cost_ref = reported_cost;
        let mut oracle_evidence = None;
        let mut cross_currency_note = None;
        let (actual_cost, cross_currency_failed) = if let Some(cost) =
            reported_cost_ref.filter(|cost| cost.currency != charge.currency)
        {
            match self.resolve_cross_currency_cost(cost, &charge.currency, timestamp) {
                Ok((converted_units, evidence)) => {
                    oracle_evidence = Some(evidence);
                    cross_currency_note = Some(serde_json::json!({
                        "oracle_conversion": {
                            "status": "applied",
                            "reported_currency": cost.currency,
                            "grant_currency": charge.currency,
                            "reported_units": cost.units,
                            "converted_units": converted_units
                        }
                    }));
                    (converted_units, false)
                }
                Err(error @ KernelError::Clock(_)) => return Err(error),
                Err(error) => {
                    warn!(
                        request_id = %request.request_id,
                        reported_currency = %cost.currency,
                        charged_currency = %charge.currency,
                        reason = %redacted!(&error),
                        "cross-currency reconciliation failed; closing hold at authorized exposure"
                    );
                    cross_currency_note = Some(serde_json::json!({
                        "oracle_conversion": {
                            "status": "failed",
                            "reported_currency": cost.currency,
                            "grant_currency": charge.currency,
                            "reported_units": cost.units,
                            "provisional_units": charge.cost_charged,
                            "reason": error.to_string()
                        }
                    }));
                    (charge.cost_charged, true)
                }
            }
        } else {
            (
                reported_cost_ref
                    .map(|cost| cost.units)
                    .unwrap_or(charge.cost_charged),
                false,
            )
        };

        let payment_already_settled = payment_authorization
            .as_ref()
            .is_some_and(|authorization| authorization.state.is_final());
        let cost_overrun =
            !cross_currency_failed && actual_cost > charge.cost_charged && charge.cost_charged > 0;

        if cost_overrun {
            warn!(
                request_id = %request.request_id,
                reported = actual_cost,
                charged = charge.cost_charged,
                "tool server reported cost exceeds max_cost_per_invocation; settlement_status=failed"
            );
        }

        let realized_budget_units =
            if cross_currency_failed || payment_already_settled || cost_overrun {
                charge.cost_charged
            } else {
                actual_cost.min(charge.cost_charged)
            };
        let reconcile = self.reconcile_budget_charge(&cap.id, charge, realized_budget_units)?;
        if let Some(progress) = fault_progress.as_deref_mut() {
            progress.observe_economics(Some(&self.budget_execution_receipt_metadata(
                charge,
                Some(("reconciled", &reconcile)),
                None,
            )));
        }
        let running_committed_cost_units = reconcile.committed_cost_units_after;

        let payment_result = if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.state.is_final() || cross_currency_failed || cost_overrun {
                None
            } else {
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::Internal(
                        "payment authorization present without configured adapter".to_string(),
                    )
                })?;
                Some(if actual_cost == 0 {
                    adapter.release(&authorization.authorization_id, &request.request_id)
                } else {
                    adapter.capture(
                        &authorization.authorization_id,
                        actual_cost,
                        &charge.currency,
                        &request.request_id,
                    )
                })
            }
        } else {
            None
        };

        if let (Some(authorization), Some(result)) =
            (payment_authorization, payment_result.as_ref())
        {
            match result {
                Ok(result) => {
                    if let Some(progress) = fault_progress.as_deref_mut() {
                        progress.observe_payment_result(
                            authorization,
                            result,
                            actual_cost,
                            actual_cost == 0,
                        );
                    }
                }
                Err(error) if actual_cost > 0 => {
                    extra_metadata = merge_metadata_objects(
                        extra_metadata,
                        Some(retained_payment_capture_metadata(
                            request,
                            authorization,
                            error,
                        )),
                    );
                    if let Some(progress) = fault_progress.as_deref_mut() {
                        progress.observe_economics(extra_metadata.as_ref());
                    }
                }
                Err(error) => {
                    if let Some(progress) = fault_progress.as_deref_mut() {
                        progress.observe_economics(Some(&serde_json::json!({ "financial": {
                            "authorization_id": authorization.authorization_id,
                            "payment_reference": authorization.authorization_id,
                            "settlement_status": SettlementStatus::Failed,
                            "release_outcome": "outcome_unknown",
                            "payment_release_error_code": error.code(),
                            "payment_authorization_retained": true,
                            "payment_release_confirmed": false
                        }})));
                    }
                }
            }
        }
        let settlement = if cross_currency_failed || cost_overrun {
            ReceiptSettlement {
                payment_reference: payment_authorization
                    .as_ref()
                    .map(|authorization| authorization.authorization_id.clone()),
                settlement_status: SettlementStatus::Failed,
            }
        } else if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.state.is_final() {
                ReceiptSettlement::from_authorization(authorization)
            } else if let Some(payment_result) = payment_result.as_ref() {
                match payment_result {
                    Ok(result) => ReceiptSettlement::from_payment_result(result),
                    Err(error) => {
                        if actual_cost == 0 {
                            warn!(
                                request_id = %request.request_id,
                                reason = %redacted!(&error),
                                "post-execution payment settlement failed"
                            );
                        }
                        ReceiptSettlement {
                            payment_reference: Some(authorization.authorization_id.clone()),
                            settlement_status: SettlementStatus::Failed,
                        }
                    }
                }
            } else {
                warn!(
                    request_id = %request.request_id,
                    authorization_id = %authorization.authorization_id,
                    "unsettled authorization completed without a payment result"
                );
                ReceiptSettlement {
                    payment_reference: Some(authorization.authorization_id.clone()),
                    settlement_status: SettlementStatus::Failed,
                }
            }
        } else {
            ReceiptSettlement::settled()
        };
        let recorded_cost = if payment_already_settled && !cross_currency_failed && !cost_overrun {
            charge.cost_charged
        } else {
            actual_cost
        };

        let budget_remaining =
            financial_budget_remaining(charge.budget_total, running_committed_cost_units)?;
        let delegation_depth = crate::receipt_support::checked_receipt_count(
            cap.delegation_chain.len(),
            "delegation depth",
        )?;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) = settlement.into_receipt_parts();
        let payment_breakdown = payment_authorization.as_ref().map(|authorization| {
            serde_json::json!({
                "payment": {
                    "authorization_id": authorization.authorization_id,
                    "adapter_metadata": authorization.metadata,
                    "preauthorized_units": charge.cost_charged,
                    "recorded_units": recorded_cost
                }
            })
        });

        let financial_meta = FinancialReceiptMetadata {
            grant_index: crate::receipt_support::checked_receipt_count(
                charge.grant_index,
                "grant index",
            )?,
            cost_charged: recorded_cost,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: merge_metadata_objects(
                merge_metadata_objects(
                    reported_cost_ref.and_then(|cost| cost.breakdown.clone()),
                    payment_breakdown,
                ),
                cross_currency_note,
            ),
            oracle_evidence,
            attempted_cost: None,
        };

        if let Some(progress) = fault_progress {
            progress.observe_economics(Some(&serde_json::json!({ "financial": financial_meta })));
        }
        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(value) => ToolCallOutput::Value(value.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                ToolCallOutput::Stream(stream.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        let preminted_execution_nonce = if request.execution_nonce.is_none() {
            if let Some(nonce_config) = self.execution_nonce_config.as_ref() {
                let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(
                    |error| {
                        KernelError::ReceiptSigningFailed(format!(
                            "failed to hash parameters for nonce binding: {error}"
                        ))
                    },
                )?;
                let now = i64::try_from(self.trusted_now_millis()?.as_secs())
                    .map_err(|_| chio_security_types::clock::ClockError::Overflow)?;
                let binding = crate::execution_nonce::NonceBinding {
                    subject_id: cap.subject.to_hex(),
                    request_id: request.request_id.clone(),
                    capability_id: cap.id.clone(),
                    tool_server: request.server_id.clone(),
                    tool_name: request.tool_name.clone(),
                    parameter_hash: action.parameter_hash,
                };
                Some(Box::new(self.sign_execution_nonce(
                    binding,
                    None,
                    None,
                    nonce_config,
                    now,
                )?))
            } else {
                None
            }
        } else {
            None
        };
        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => {
                let budget_metadata = self.budget_execution_receipt_metadata(
                    charge,
                    Some(("reconciled", &reconcile)),
                    preminted_execution_nonce
                        .as_deref()
                        .map(|nonce| nonce.nonce_id())
                        .or_else(|| {
                            request
                                .execution_nonce
                                .as_ref()
                                .map(|nonce| nonce.nonce_id())
                        }),
                );
                let merged_extra_metadata = merge_metadata_objects(
                    financial_json,
                    self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
                );
                self.prepare_allow_response_with_metadata_and_payee_binding(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    merged_extra_metadata,
                    verified_payee_binding,
                    match preminted_execution_nonce {
                        Some(nonce) => AllowResponseNonce::Preminted(nonce),
                        None => AllowResponseNonce::MintForAllow,
                    },
                )
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => {
                let budget_metadata = self.budget_execution_receipt_metadata(
                    charge,
                    Some(("reconciled", &reconcile)),
                    None,
                );
                let merged_extra_metadata = merge_metadata_objects(
                    financial_json,
                    self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
                );
                self.prepare_incomplete_response_with_output_metadata_and_payee_binding(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    // An incomplete stream retains any consumed runtime lease
                    // because tool effects may have committed.
                    RefusalReceiptMetadata::new(
                        self.mark_runtime_admission_reservations_retained_fail_closed(
                            merged_extra_metadata,
                        ),
                        IdentityDisposition::Terminal,
                    ),
                    verified_payee_binding,
                )
            }
        }
    }
}
