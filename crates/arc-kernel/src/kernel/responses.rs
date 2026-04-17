use std::sync::atomic::Ordering;

use super::*;

pub(crate) struct FinalizeToolOutputCostContext<'a> {
    pub(crate) charge_result: Option<BudgetChargeResult>,
    pub(crate) reported_cost: Option<ToolInvocationCost>,
    pub(crate) payment_authorization: Option<PaymentAuthorization>,
    pub(crate) cap: &'a CapabilityToken,
}

impl ArcKernel {
    /// denial reason is monetary budget exhaustion.
    pub(crate) fn build_monetary_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matching_grants: &[MatchingGrant<'_>],
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_monetary_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matching_grants,
            cap,
            None,
        )
    }

    pub(crate) fn build_monetary_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matching_grants: &[MatchingGrant<'_>],
        cap: &CapabilityToken,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        // Look for a monetary grant among the matching candidates to populate metadata.
        let monetary_grant = matching_grants.iter().find(|m| {
            m.grant.max_cost_per_invocation.is_some() || m.grant.max_total_cost.is_some()
        });

        if let Some(mg) = monetary_grant {
            let grant = mg.grant;
            let currency = grant
                .max_cost_per_invocation
                .as_ref()
                .map(|m| m.currency.clone())
                .or_else(|| grant.max_total_cost.as_ref().map(|m| m.currency.clone()))
                .unwrap_or_else(|| "USD".to_string());
            let budget_total = grant
                .max_total_cost
                .as_ref()
                .map(|m| m.units)
                .unwrap_or(u64::MAX);
            let attempted_cost = grant
                .max_cost_per_invocation
                .as_ref()
                .map(|m| m.units)
                .unwrap_or(0);
            let delegation_depth = cap.delegation_chain.len() as u32;
            let root_budget_holder = cap.issuer.to_hex();
            let (payment_reference, settlement_status) =
                ReceiptSettlement::not_applicable().into_receipt_parts();

            let financial_meta = FinancialReceiptMetadata {
                grant_index: mg.index as u32,
                cost_charged: 0,
                currency,
                budget_remaining: 0,
                budget_total,
                delegation_depth,
                root_budget_holder,
                payment_reference,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: Some(attempted_cost),
            };

            let metadata = merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        receipt_attribution_metadata(cap, Some(mg.index)),
                        Some(serde_json::json!({ "financial": financial_meta })),
                    ),
                    extra_metadata.clone(),
                ),
                governed_request_metadata(
                    request,
                    self.attestation_trust_policy.as_ref(),
                    timestamp,
                )?,
            );
            let receipt_content = receipt_content_for_output(None, None)?;

            let action =
                ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
                    KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
                })?;

            let receipt = self.build_and_sign_receipt(ReceiptParams {
                capability_id: &cap.id,
                tool_name: &request.tool_name,
                server_id: &request.server_id,
                decision: Decision::Deny {
                    reason: reason.to_string(),
                    guard: "kernel".to_string(),
                },
                action,
                content_hash: receipt_content.content_hash,
                metadata,
                timestamp,
                trust_level: arc_core::TrustLevel::default(),
                tenant_id: None,
            })?;

            self.record_arc_receipt(&receipt)?;

            return Ok(ToolCallResponse {
                request_id: request.request_id.clone(),
                verdict: Verdict::Deny,
                output: None,
                reason: Some(reason.to_string()),
                terminal_state: OperationTerminalState::Completed,
                receipt,
                execution_nonce: None,
            });
        }

        // No monetary grant -- standard deny.
        self.build_deny_response_with_metadata(request, reason, timestamp, None, extra_metadata)
    }

    pub(crate) fn build_pre_execution_monetary_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_pre_execution_monetary_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            charge,
            committed_cost_after_release,
            cap,
            None,
        )
    }

    pub(crate) fn build_pre_execution_monetary_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        charge: &BudgetChargeResult,
        committed_cost_after_release: u64,
        cap: &CapabilityToken,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let delegation_depth = cap.delegation_chain.len() as u32;
        let root_budget_holder = cap.issuer.to_hex();
        let (payment_reference, settlement_status) =
            ReceiptSettlement::not_applicable().into_receipt_parts();
        let budget_remaining = charge
            .budget_total
            .saturating_sub(committed_cost_after_release);

        let financial_meta = FinancialReceiptMetadata {
            grant_index: charge.grant_index as u32,
            cost_charged: 0,
            currency: charge.currency.clone(),
            budget_remaining,
            budget_total: charge.budget_total,
            delegation_depth,
            root_budget_holder,
            payment_reference,
            settlement_status,
            cost_breakdown: None,
            oracle_evidence: None,
            attempted_cost: Some(charge.cost_charged),
        };

        let receipt_content = receipt_content_for_output(None, None)?;
        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        receipt_attribution_metadata(cap, Some(charge.grant_index)),
                        Some(serde_json::json!({ "financial": financial_meta })),
                    ),
                    extra_metadata,
                ),
                governed_request_metadata(
                    request,
                    self.attestation_trust_policy.as_ref(),
                    timestamp,
                )?,
            ),
            timestamp,
            trust_level: arc_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_arc_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        })
    }

    pub(crate) fn finalize_tool_output(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
    ) -> Result<ToolCallResponse, KernelError> {
        self.finalize_tool_output_with_metadata(
            request,
            output,
            elapsed,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn finalize_tool_output_with_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        match self.apply_stream_limits(output, elapsed)? {
            ToolServerOutput::Value(value) => self.build_allow_response_with_metadata(
                request,
                ToolCallOutput::Value(value),
                timestamp,
                Some(matched_grant_index),
                extra_metadata.clone(),
            ),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => self
                .build_allow_response_with_metadata(
                    request,
                    ToolCallOutput::Stream(stream),
                    timestamp,
                    Some(matched_grant_index),
                    extra_metadata.clone(),
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(ToolCallOutput::Stream(stream)),
                    &reason,
                    timestamp,
                    Some(matched_grant_index),
                    extra_metadata,
                ),
        }
    }

    /// Finalize a tool output with optional monetary metadata injected into the receipt.
    pub(crate) fn finalize_tool_output_with_cost(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        cost_context: FinalizeToolOutputCostContext<'_>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.finalize_tool_output_with_cost_and_metadata(
            request,
            output,
            elapsed,
            timestamp,
            matched_grant_index,
            cost_context,
            None,
        )
    }

    pub(crate) fn finalize_tool_output_with_cost_and_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        cost_context: FinalizeToolOutputCostContext<'_>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let FinalizeToolOutputCostContext {
            charge_result,
            reported_cost,
            payment_authorization,
            cap,
        } = cost_context;
        let Some(charge) = charge_result else {
            // Non-monetary grant: use normal path.
            return self.finalize_tool_output_with_metadata(
                request,
                output,
                elapsed,
                timestamp,
                matched_grant_index,
                extra_metadata,
            );
        };

        let reported_cost_ref = reported_cost.as_ref();
        let mut oracle_evidence = None;
        let mut cross_currency_note = None;
        let (actual_cost, cross_currency_failed) =
            if let Some(cost) = reported_cost_ref.filter(|cost| cost.currency != charge.currency) {
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
                    Err(error) => {
                        warn!(
                            request_id = %request.request_id,
                            reported_currency = %cost.currency,
                            charged_currency = %charge.currency,
                            reason = %error,
                            "cross-currency reconciliation failed; keeping provisional charge"
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
        let keep_provisional_charge = cross_currency_failed
            || matches!(payment_authorization.as_ref(), Some(authorization) if authorization.settled);
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

        let running_committed_cost_units = if keep_provisional_charge || cost_overrun {
            charge.new_committed_cost_units
        } else {
            self.reduce_budget_charge_to_actual(&cap.id, &charge, actual_cost)?
        };

        let payment_result = if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled || cross_currency_failed || cost_overrun {
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

        let settlement = if cross_currency_failed || cost_overrun {
            ReceiptSettlement {
                payment_reference: payment_authorization
                    .as_ref()
                    .map(|authorization| authorization.authorization_id.clone()),
                settlement_status: SettlementStatus::Failed,
            }
        } else if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled {
                ReceiptSettlement::from_authorization(authorization)
            } else if let Some(payment_result) = payment_result.as_ref() {
                match payment_result {
                    Ok(result) => ReceiptSettlement::from_payment_result(result),
                    Err(error) => {
                        warn!(
                            request_id = %request.request_id,
                            reason = %error,
                            "post-execution payment settlement failed"
                        );
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
        let recorded_cost = if keep_provisional_charge && !cross_currency_failed && !cost_overrun {
            charge.cost_charged
        } else {
            actual_cost
        };

        // Use the running total charged so far (not just this invocation) so that
        // budget_remaining reflects cumulative spend across all prior invocations.
        let budget_remaining = charge
            .budget_total
            .saturating_sub(running_committed_cost_units);
        let delegation_depth = cap.delegation_chain.len() as u32;
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
            grant_index: charge.grant_index as u32,
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

        let limited_output = self.apply_stream_limits(output, elapsed)?;
        let tool_call_output = match &limited_output {
            ToolServerOutput::Value(v) => ToolCallOutput::Value(v.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(s)) => {
                ToolCallOutput::Stream(s.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));
        let merged_extra_metadata = merge_metadata_objects(financial_json, extra_metadata.clone());

        match limited_output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => self
                .build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    merged_extra_metadata.clone(),
                ),
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    merged_extra_metadata,
                ),
        }
    }

    pub(crate) fn apply_stream_limits(
        &self,
        output: ToolServerOutput,
        elapsed: Duration,
    ) -> Result<ToolServerOutput, KernelError> {
        let ToolServerOutput::Stream(stream_result) = output else {
            return Ok(output);
        };

        let duration_limit = Duration::from_secs(self.config.max_stream_duration_secs);
        let duration_exceeded =
            self.config.max_stream_duration_secs > 0 && elapsed > duration_limit;

        let (stream, base_reason) = match stream_result {
            ToolServerStreamResult::Complete(stream) => (stream, None),
            ToolServerStreamResult::Incomplete { stream, reason } => (stream, Some(reason)),
        };

        let (stream, total_bytes, truncated) =
            truncate_stream_to_byte_limit(&stream, self.config.max_stream_total_bytes)?;

        let limit_reason = if truncated {
            Some(format!(
                "ARC_SERVER_STREAM_LIMIT: stream exceeded max total bytes of {}",
                self.config.max_stream_total_bytes
            ))
        } else if duration_exceeded {
            Some(format!(
                "ARC_SERVER_STREAM_LIMIT: stream exceeded max duration of {}s",
                self.config.max_stream_duration_secs
            ))
        } else {
            None
        };

        if let Some(reason) = limit_reason {
            warn!(
                request_bytes = total_bytes,
                elapsed_ms = elapsed.as_millis(),
                "stream output exceeded configured limits"
            );
            return Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ));
        }

        if let Some(reason) = base_reason {
            Ok(ToolServerOutput::Stream(
                ToolServerStreamResult::Incomplete { stream, reason },
            ))
        } else {
            Ok(ToolServerOutput::Stream(ToolServerStreamResult::Complete(
                stream,
            )))
        }
    }

    /// Build a denial response with a signed receipt.
    pub(crate) fn build_deny_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_deny_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn build_deny_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Deny {
                reason: reason.to_string(),
                guard: "kernel".to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        receipt_content.metadata,
                        governed_request_metadata(
                            request,
                            self.attestation_trust_policy.as_ref(),
                            timestamp,
                        )?,
                    ),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
            trust_level: arc_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_arc_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce: None,
        })
    }

    /// Build a cancellation response with a signed cancelled receipt.
    pub(crate) fn build_cancelled_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_cancelled_response_with_metadata(
            request,
            reason,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn build_cancelled_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(None, None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Cancelled {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        receipt_content.metadata,
                        governed_request_metadata(
                            request,
                            self.attestation_trust_policy.as_ref(),
                            timestamp,
                        )?,
                    ),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
            trust_level: arc_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_arc_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output: None,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Cancelled {
                reason: reason.to_string(),
            },
            receipt,
            execution_nonce: None,
        })
    }

    /// Build an incomplete response with a signed incomplete receipt.
    pub(crate) fn build_incomplete_response(
        &self,
        request: &ToolCallRequest,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_incomplete_response_with_output(
            request,
            None,
            reason,
            timestamp,
            matched_grant_index,
        )
    }

    /// Build an incomplete response with optional partial output and a signed incomplete receipt.
    pub(crate) fn build_incomplete_response_with_output(
        &self,
        request: &ToolCallRequest,
        output: Option<ToolCallOutput>,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_incomplete_response_with_output_and_metadata(
            request,
            output,
            reason,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn build_incomplete_response_with_output_and_metadata(
        &self,
        request: &ToolCallRequest,
        output: Option<ToolCallOutput>,
        reason: &str,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let receipt_content = receipt_content_for_output(output.as_ref(), None)?;

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Incomplete {
                reason: reason.to_string(),
            },
            action,
            content_hash: receipt_content.content_hash,
            metadata: merge_metadata_objects(
                merge_metadata_objects(
                    merge_metadata_objects(
                        receipt_content.metadata,
                        governed_request_metadata(
                            request,
                            self.attestation_trust_policy.as_ref(),
                            timestamp,
                        )?,
                    ),
                    extra_metadata,
                ),
                receipt_attribution_metadata(cap, matched_grant_index),
            ),
            timestamp,
            trust_level: arc_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_arc_receipt(&receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Deny,
            output,
            reason: Some(reason.to_string()),
            terminal_state: OperationTerminalState::Incomplete {
                reason: reason.to_string(),
            },
            receipt,
            execution_nonce: None,
        })
    }

    pub(crate) fn build_allow_response(
        &self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
    ) -> Result<ToolCallResponse, KernelError> {
        self.build_allow_response_with_metadata(
            request,
            output,
            timestamp,
            matched_grant_index,
            None,
        )
    }

    pub(crate) fn build_allow_response_with_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolCallOutput,
        timestamp: u64,
        matched_grant_index: Option<usize>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let cap = &request.capability;
        let expected_chunks = match &output {
            ToolCallOutput::Stream(stream) => Some(stream.chunk_count()),
            ToolCallOutput::Value(_) => None,
        };
        let receipt_content = receipt_content_for_output(Some(&output), expected_chunks)?;

        // Merge extra_metadata (e.g. "financial") into receipt_content.metadata.
        let metadata = merge_metadata_objects(
            merge_metadata_objects(
                merge_metadata_objects(
                    receipt_content.metadata,
                    governed_request_metadata(
                        request,
                        self.attestation_trust_policy.as_ref(),
                        timestamp,
                    )?,
                ),
                extra_metadata,
            ),
            receipt_attribution_metadata(cap, matched_grant_index),
        );

        let action = ToolCallAction::from_parameters(request.arguments.clone()).map_err(|e| {
            KernelError::ReceiptSigningFailed(format!("failed to hash parameters: {e}"))
        })?;

        let receipt = self.build_and_sign_receipt(ReceiptParams {
            capability_id: &cap.id,
            tool_name: &request.tool_name,
            server_id: &request.server_id,
            decision: Decision::Allow,
            action,
            content_hash: receipt_content.content_hash,
            metadata,
            timestamp,
            trust_level: arc_core::TrustLevel::default(),
            tenant_id: None,
        })?;

        self.record_arc_receipt(&receipt)?;

        info!(
            request_id = %request.request_id,
            tool = %request.tool_name,
            receipt_id = %receipt.id,
            "tool call allowed"
        );

        // Phase 1.1: mint a short-lived, single-use execution nonce bound
        // to this allow verdict so tool servers can verify the kernel
        // authorized this exact invocation. Opt-in; when no config is
        // installed the field remains `None` for backward compatibility.
        let execution_nonce = self.mint_execution_nonce_for_allow(request, cap, &receipt)?;

        Ok(ToolCallResponse {
            request_id: request.request_id.clone(),
            verdict: Verdict::Allow,
            output: Some(output),
            reason: None,
            terminal_state: OperationTerminalState::Completed,
            receipt,
            execution_nonce,
        })
    }

    /// Build and sign a receipt from a `ReceiptParams` descriptor.
    pub(crate) fn build_and_sign_receipt(
        &self,
        params: ReceiptParams<'_>,
    ) -> Result<ArcReceipt, KernelError> {
        // Phase 1.5 multi-tenant receipt isolation: resolve tenant_id for
        // this receipt. Precedence:
        //   1. An explicit override on `ReceiptParams` (currently unused).
        //   2. The active scoped tenant context set by the evaluate path
        //      from `session.auth_context().enterprise_identity.tenant_id`.
        //
        // Tenant_id is never taken from a caller-provided field on the
        // request: allowing caller choice would defeat the isolation the
        // store-level WHERE clause enforces.
        let tenant_id = params
            .tenant_id
            .clone()
            .or_else(current_scoped_receipt_tenant_id);

        let body = ArcReceiptBody {
            id: next_receipt_id("rcpt"),
            timestamp: params.timestamp,
            capability_id: params.capability_id.to_string(),
            tool_server: params.server_id.to_string(),
            tool_name: params.tool_name.to_string(),
            action: params.action,
            decision: params.decision,
            content_hash: params.content_hash,
            policy_hash: self.config.policy_hash.clone(),
            evidence: vec![],
            metadata: params.metadata,
            trust_level: params.trust_level,
            tenant_id,
            kernel_key: self.config.keypair.public_key(),
        };

        ArcReceipt::sign(body, &self.config.keypair)
            .map_err(|e| KernelError::ReceiptSigningFailed(e.to_string()))
    }

    pub(crate) fn record_arc_receipt(&self, receipt: &ArcReceipt) -> Result<(), KernelError> {
        if let Some(seq) = self
            .with_receipt_store(|store| Ok(store.append_arc_receipt_returning_seq(receipt)?))?
            .flatten()
        {
            let last_checkpoint_seq = self.last_checkpoint_seq.load(Ordering::SeqCst);
            if seq > 0
                && self.checkpoint_batch_size > 0
                && (seq - last_checkpoint_seq) >= self.checkpoint_batch_size
            {
                self.maybe_trigger_checkpoint(seq)?;
            }
        }
        self.receipt_log
            .lock()
            .map_err(|_| KernelError::Internal("receipt log lock poisoned".to_string()))?
            .append(receipt.clone());
        Ok(())
    }

    /// Trigger a Merkle checkpoint for all receipts in [last_checkpoint_seq+1, batch_end_seq].
    pub(crate) fn maybe_trigger_checkpoint(&self, batch_end_seq: u64) -> Result<(), KernelError> {
        let batch_start_seq = self.last_checkpoint_seq.load(Ordering::SeqCst) + 1;

        let Some(receipt_bytes_with_seqs) = self.with_receipt_store(|store| {
            Ok(store.receipts_canonical_bytes_range(batch_start_seq, batch_end_seq)?)
        })?
        else {
            return Ok(());
        };

        if receipt_bytes_with_seqs.is_empty() {
            return Ok(());
        }

        let receipt_bytes: Vec<Vec<u8>> = receipt_bytes_with_seqs
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect();

        let checkpoint_seq = self.checkpoint_seq_counter.fetch_add(1, Ordering::SeqCst) + 1;

        let previous_checkpoint = if checkpoint_seq > 1 {
            self.with_receipt_store(|store| Ok(store.load_checkpoint_by_seq(checkpoint_seq - 1)?))?
                .flatten()
        } else {
            None
        };

        let checkpoint = checkpoint::build_checkpoint_with_previous(
            checkpoint_seq,
            batch_start_seq,
            batch_end_seq,
            &receipt_bytes,
            &self.config.keypair,
            previous_checkpoint.as_ref(),
        )
        .map_err(|e| KernelError::Internal(format!("checkpoint build failed: {e}")))?;

        let _ = self.with_receipt_store(|store| Ok(store.store_checkpoint(&checkpoint)?))?;
        self.last_checkpoint_seq
            .store(batch_end_seq, Ordering::SeqCst);
        Ok(())
    }
}
