impl ChioKernel {
    pub(super) fn reconcile_budget_charge(
        &self,
        capability_id: &str,
        charge: &BudgetChargeResult,
        realized_cost_units: u64,
    ) -> Result<BudgetReconcileHoldDecision, KernelError> {
        let authority = charge.authorize_metadata.authority.clone();
        self.with_budget_store(|store| {
            let reconciled = store.reconcile_budget_hold(BudgetReconcileHoldRequest {
                capability_id: capability_id.to_string(),
                grant_index: charge.grant_index,
                exposed_cost_units: charge.cost_charged,
                realized_spend_units: realized_cost_units.min(charge.cost_charged),
                hold_id: Some(charge.budget_hold_id.clone()),
                event_id: Some(charge.reconcile_event_id()),
                authority,
                admission_operation: charge.admission_operation.clone(),
            })?;
            self.validate_budget_terminal_decision_for_store(
                store,
                &reconciled,
                BudgetTerminalDecisionExpectation {
                    authorization_metadata: &charge.authorize_metadata,
                    expected_event_id: &charge.reconcile_event_id(),
                    expected_authority: charge.authorize_metadata.authority.as_ref(),
                    expected_capability_id: Some(capability_id),
                    expected_grant_index: charge.grant_index,
                    expected_hold_id: &charge.budget_hold_id,
                    expected_admission_operation: charge.admission_operation.as_ref(),
                    expected_mutation_kind: crate::budget_store::BudgetMutationKind::ReconcileSpend,
                    expected_exposure_units: charge.cost_charged,
                    expected_realized_spend_units: realized_cost_units.min(charge.cost_charged),
                    expected_invocation_state: if charge.admission_operation.is_some() {
                        BudgetInvocationReservationState::Captured
                    } else {
                        BudgetInvocationReservationState::Absent
                    },
                    expected_monetary_state: BudgetMonetaryHoldState::Reconciled,
                    stage: "budget reconcile",
                },
            )?;
            Ok(reconciled)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn finalize_budgeted_tool_output_with_cost_and_metadata(
        &self,
        request: &ToolCallRequest,
        output: ToolServerOutput,
        elapsed: Duration,
        timestamp: u64,
        matched_grant_index: usize,
        cost_context: FinalizeToolOutputCostContext<'_>,
        security_context: Option<&SecurityInvocationContext>,
        extra_metadata: Option<serde_json::Value>,
    ) -> Result<ToolCallResponse, KernelError> {
        let FinalizeToolOutputCostContext {
            charge_result,
            admission_operation,
            reported_cost,
            payment_authorization,
            verified_payee_binding,
            cap,
        } = cost_context;
        let Some(charge) = charge_result else {
            // When a payment was authorized but the grant carries no monetary ceiling,
            // the realized spend is the prepaid quote. Settle the authorization so the
            // invocation is recorded as a completed prepayment; fail closed if it
            // cannot be settled rather than admit the tool against a perpetual hold.
            let Some(auth) = payment_authorization.as_ref() else {
                return self.finalize_tool_output_with_metadata_and_security_context(
                    FinalizeToolOutputRequest {
                        request,
                        output,
                        elapsed,
                        timestamp,
                        matched_grant_index,
                        security_context,
                        verified_payee_binding,
                        extra_metadata,
                    },
                );
            };
            let Some(settlement) = self.settle_prepaid_authorization_without_charge(
                request,
                auth,
                None,
                admission_operation.as_ref(),
            )?
            else {
                return self.build_deny_response_with_metadata(
                    request,
                    "MustPrepay authorization could not be settled after execution",
                    timestamp,
                    Some(matched_grant_index),
                    self.mark_runtime_admission_reservations_retained_fail_closed(extra_metadata),
                );
            };
            let (payment_reference, settlement_status) = settlement.into_receipt_parts();
            // A grant with no monetary ceiling carries no budget charge, so the
            // realized spend is the prepaid quote. Populate the full financial
            // envelope from the quote (amount, currency, settlement, lineage) so
            // the receipt deserializes as `FinancialReceiptMetadata` and reflects
            // the completed prepaid spend, not a partial fragment that receipt
            // queries and dashboards cannot read.
            let (quoted_units, quoted_currency) =
                Self::mustprepay_quoted_amount(request).unwrap_or_else(|| (0, "USD".to_string()));
            let financial_meta = FinancialReceiptMetadata {
                grant_index: matched_grant_index as u32,
                cost_charged: quoted_units,
                currency: quoted_currency,
                budget_remaining: 0,
                budget_total: quoted_units,
                delegation_depth: cap.delegation_chain.len() as u32,
                root_budget_holder: cap.issuer.to_hex(),
                payment_reference,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: None,
            };
            let payment_meta = serde_json::json!({ "financial": financial_meta });
            // The kernel-built `financial` block is authoritative and must win over
            // any `financial` keys carried in caller/route `extra_metadata`, so the
            // settled-prepayment status that `require_earned_mediated_trust_level`
            // reads at the sign site reflects the real settlement and can never be
            // forged by a caller-supplied override. Pass it as the winning (second)
            // argument, matching the reconciled-hold path (see
            // `merge_budget_receipt_metadata`).
            let mut extra_metadata = extra_metadata;
            strip_reserved_economic_receipt_metadata(&mut extra_metadata);
            let metadata = merge_metadata_objects(extra_metadata, Some(payment_meta));
            return self.finalize_tool_output_with_metadata_and_security_context(
                FinalizeToolOutputRequest {
                    request,
                    output,
                    elapsed,
                    timestamp,
                    matched_grant_index,
                    security_context,
                    verified_payee_binding,
                    extra_metadata: metadata,
                },
            );
        };

        // A tool server that does not measure realized cost (a pre-execution
        // authorization gate that dispatches a pass-through while the real tool
        // runs elsewhere) never yields a settled, reconciled authoritative
        // spend: nothing executed here, so there is no realized cost to
        // reconcile. Release the pre-execution monetary exposure and emit a provisional
        // receipt. Guarded on the absence of a payment authorization because
        // such gates carry no prepayment; a prepaid invocation always runs
        // through the measured settlement path below.
        if payment_authorization.is_none()
            && !self.tool_server_measures_realized_cost(&request.server_id)
        {
            return self.finalize_unmeasured_cost_provisional_allow(
                request,
                output,
                elapsed,
                timestamp,
                charge,
                security_context,
                extra_metadata,
            );
        }

        let reported_cost_ref = reported_cost.as_ref();
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
            .is_some_and(|authorization| authorization.settled);
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
        let reconcile = self.reconcile_budget_charge(&cap.id, &charge, realized_budget_units)?;
        let running_committed_cost_units = reconcile.committed_cost_units_after;

        let payment_result = if let Some(authorization) = payment_authorization.as_ref() {
            if authorization.settled || cross_currency_failed || cost_overrun {
                None
            } else {
                let adapter = self.payment_adapter.as_ref().ok_or_else(|| {
                    KernelError::Internal(
                        "payment authorization present without configured adapter".to_string(),
                    )
                })?;
                // Commit the terminal settle action BEFORE any money can
                // move, so a crash inside the rail call replays the exact
                // recorded operation instead of guessing.
                let settle = if actual_cost == 0 {
                    crate::payment::PaymentSettleIntent {
                        action: crate::payment::PaymentSettleAction::Release,
                        amount_units: None,
                    }
                } else {
                    crate::payment::PaymentSettleIntent {
                        action: crate::payment::PaymentSettleAction::Capture,
                        amount_units: Some(actual_cost),
                    }
                };
                self.advance_payment_journal_if_active(
                    &request.request_id,
                    crate::payment::PaymentJournalState::Authorized,
                    crate::payment::PaymentJournalState::Settling,
                    None,
                    None,
                    Some(settle),
                )?;
                let settle_once = || match (actual_cost, admission_operation.as_ref()) {
                    (0, Some(binding)) => adapter.release_for_operation(
                        binding.operation_id(),
                        binding.request_binding_hash(),
                        &authorization.authorization_id,
                        &request.request_id,
                    ),
                    (0, None) => {
                        adapter.release(&authorization.authorization_id, &request.request_id)
                    }
                    (_, Some(binding)) => {
                        adapter.capture_for_operation(OperationPaymentCaptureRequest {
                            operation_id: binding.operation_id(),
                            request_binding_hash: binding.request_binding_hash(),
                            authorization_id: &authorization.authorization_id,
                            amount_units: actual_cost,
                            currency: &charge.currency,
                            reference: &request.request_id,
                        })
                    }
                    (_, None) => adapter.capture(
                        &authorization.authorization_id,
                        actual_cost,
                        &charge.currency,
                        &request.request_id,
                    ),
                };
                let result = settle_once();
                let result = if admission_operation.is_some() {
                    result.or_else(|_| settle_once())
                } else {
                    result
                };
                if let Ok(payment) = result.as_ref() {
                    self.advance_payment_journal_if_active(
                        &request.request_id,
                        crate::payment::PaymentJournalState::Settling,
                        crate::payment::PaymentJournalState::Settled,
                        None,
                        Some(&payment.transaction_id),
                        None,
                    )?;
                }
                Some(result)
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
                            reason = %redacted!(&error),
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
        let recorded_cost = if payment_already_settled && !cross_currency_failed && !cost_overrun {
            charge.cost_charged
        } else {
            actual_cost
        };

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
        let budget_metadata = self.budget_execution_receipt_metadata(
            &charge,
            Some(("reconciled", &reconcile)),
            None,
        )?;
        let financial_json = Some(serde_json::json!({ "financial": financial_meta }));
        let mut extra_metadata = extra_metadata;
        strip_reserved_economic_receipt_metadata(&mut extra_metadata);
        let merged_extra_metadata = merge_metadata_objects(
            self.merge_budget_receipt_metadata(extra_metadata, budget_metadata),
            financial_json,
        );

        let post_invocation = if security_context.is_some() {
            self.apply_post_invocation_pipeline(
                request,
                limited_output,
                Some(charge.grant_index),
                security_context,
                merged_extra_metadata,
            )?
        } else {
            PostInvocationHandling {
                output: limited_output,
                extra_metadata: merged_extra_metadata,
                blocked_reason: None,
                evidence: Vec::new(),
            }
        };
        let _post_invocation_evidence_scope =
            scope_post_invocation_guard_evidence(post_invocation.evidence);
        if let Some(reason) = post_invocation.blocked_reason.as_deref() {
            return self.build_deny_response_with_metadata(
                request,
                reason,
                timestamp,
                Some(charge.grant_index),
                self.mark_runtime_admission_reservations_retained_fail_closed(
                    post_invocation.extra_metadata,
                ),
            );
        }

        let tool_call_output = match &post_invocation.output {
            ToolServerOutput::Value(value) => ToolCallOutput::Value(value.clone()),
            ToolServerOutput::Stream(ToolServerStreamResult::Complete(stream)) => {
                ToolCallOutput::Stream(stream.clone())
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, .. }) => {
                ToolCallOutput::Stream(stream.clone())
            }
        };

        match post_invocation.output {
            ToolServerOutput::Value(_)
            | ToolServerOutput::Stream(ToolServerStreamResult::Complete(_)) => {
                let preminted_execution_nonce = if request.execution_nonce.is_none() {
                    if let Some(nonce_config) = self.execution_nonce_config.as_ref() {
                        let action = ToolCallAction::from_parameters(request.arguments.clone())
                            .map_err(|error| {
                                KernelError::ReceiptSigningFailed(format!(
                                    "failed to hash parameters for nonce binding: {error}"
                                ))
                            })?;
                        let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
                        let binding = self.nonce_binding_for(request, cap, &action.parameter_hash);
                        let signed = crate::execution_nonce::mint_execution_nonce_with_backend(
                            self.authority_signing_backend.as_ref(),
                            binding,
                            nonce_config,
                            now,
                        )?;
                        Some(Box::new(signed))
                    } else {
                        None
                    }
                } else {
                    None
                };
                let execution_nonce_id = preminted_execution_nonce
                    .as_deref()
                    .map(|nonce| nonce.nonce_id())
                    .or_else(|| {
                        request
                            .execution_nonce
                            .as_ref()
                            .map(|nonce| nonce.nonce_id())
                    });
                let budget_metadata = self.budget_execution_receipt_metadata(
                    &charge,
                    Some(("reconciled", &reconcile)),
                    execution_nonce_id,
                )?;
                let merged = self
                    .merge_budget_receipt_metadata(post_invocation.extra_metadata, budget_metadata);
                self.build_allow_response_with_metadata(
                    request,
                    tool_call_output,
                    timestamp,
                    Some(charge.grant_index),
                    merged,
                    match preminted_execution_nonce {
                        Some(nonce) => AllowResponseNonce::Preminted(nonce),
                        None => AllowResponseNonce::MintForAllow,
                    },
                )
            }
            ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { reason, .. }) => self
                .build_incomplete_response_with_output_and_metadata(
                    request,
                    Some(tool_call_output),
                    &reason,
                    timestamp,
                    Some(charge.grant_index),
                    self.mark_runtime_admission_reservations_retained_fail_closed(
                        post_invocation.extra_metadata,
                    ),
                ),
        }
    }

    fn block_on_price_oracle<T>(
        &self,
        future: impl Future<Output = Result<T, PriceOracleError>>,
    ) -> Result<T, KernelError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                    handle
                        .block_on(future)
                        .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))
                }),
                tokio::runtime::RuntimeFlavor::CurrentThread => {
                    Err(KernelError::CrossCurrencyOracle(
                        "current-thread tokio runtime cannot synchronously resolve price oracles"
                            .to_string(),
                    ))
                }
                flavor => Err(KernelError::CrossCurrencyOracle(format!(
                    "unsupported tokio runtime flavor for synchronous oracle resolution: {flavor:?}"
                ))),
            },
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    KernelError::CrossCurrencyOracle(format!(
                        "failed to build synchronous oracle runtime: {error}"
                    ))
                })?
                .block_on(future)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string())),
        }
    }

    pub(crate) fn resolve_cross_currency_cost(
        &self,
        reported_cost: &ToolInvocationCost,
        grant_currency: &str,
        timestamp: u64,
    ) -> Result<(u64, chio_core::web3::anchors::OracleConversionEvidence), KernelError> {
        let oracle =
            self.price_oracle
                .as_ref()
                .ok_or_else(|| KernelError::NoCrossCurrencyOracle {
                    base: reported_cost.currency.clone(),
                    quote: grant_currency.to_string(),
                })?;
        let rate =
            self.block_on_price_oracle(oracle.get_rate(&reported_cost.currency, grant_currency))?;
        let converted_units =
            convert_supported_units(reported_cost.units, &rate, rate.conversion_margin_bps)
                .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        let evidence = rate
            .to_conversion_evidence(
                reported_cost.units,
                reported_cost.currency.clone(),
                grant_currency.to_string(),
                converted_units,
                timestamp,
            )
            .map_err(|error| KernelError::CrossCurrencyOracle(error.to_string()))?;
        Ok((converted_units, evidence))
    }

    pub(crate) fn ensure_registered_tool_target(
        &self,
        request: &ToolCallRequest,
    ) -> Result<(), KernelError> {
        self.tool_servers.get(&request.server_id).ok_or_else(|| {
            KernelError::ToolNotRegistered(format!(
                "server \"{}\" / tool \"{}\"",
                request.server_id, request.tool_name
            ))
        })?;
        Ok(())
    }

    pub(crate) fn authorize_payment_if_needed(
        &self,
        request: &ToolCallRequest,
        charge_result: Option<&BudgetChargeResult>,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        verified_payee_binding: Option<&VerifiedGovernedPayeeBinding>,
    ) -> Result<Option<PaymentAuthorization>, PaymentError> {
        // Derive the authorization amount. A MustPrepay intent prepays its quoted
        // cost, so the quote funds the prepayment whenever it is present, even when
        // a provisional monetary budget hold accompanies it: that hold covers
        // metered budget accounting, not the price the payer must prepay. Only a
        // non-MustPrepay metered charge authorizes the charged amount, and a request
        // with neither needs no payment.
        let (amount_units, currency) = if let Some(amount) = Self::mustprepay_quoted_amount(request)
        {
            amount
        } else if let Some(charge) = charge_result {
            (charge.cost_charged, charge.currency.clone())
        } else {
            return Ok(None);
        };

        let Some(adapter) = self.payment_adapter.as_ref() else {
            // The governed gate denies MustPrepay without an adapter earlier, but
            // the payment boundary is fail-closed as defense-in-depth: a MustPrepay
            // intent (which may also carry a provisional charge) must never reach
            // here without an adapter and be admitted unpaid.
            if Self::is_governed_mustprepay_request(request) {
                return Err(PaymentError::RailError(
                    "MustPrepay intent reached payment authorization without a configured adapter"
                        .to_string(),
                ));
            }
            return Ok(None);
        };

        let governed = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.as_tool_invocation().map(|body| (intent, body)))
            .map(|(governed_intent, intent)| {
                governed_intent
                    .binding_hash()
                    .map(|intent_hash| GovernedPaymentContext {
                        intent_id: intent.id.clone(),
                        intent_hash,
                        purpose: intent.purpose.clone(),
                        server_id: intent.server_id.clone(),
                        tool_name: intent.tool_name.clone(),
                        approval_token_id: request
                            .approval_token
                            .as_ref()
                            .map(|token| token.id.clone())
                            .or_else(|| {
                                request
                                    .threshold_approval_proposal
                                    .as_ref()
                                    .map(|proposal| proposal.body().proposal_id().to_owned())
                            }),
                    })
                    .map_err(|error| {
                        PaymentError::RailError(format!(
                            "failed to hash governed intent for payment authorization: {error}"
                        ))
                    })
            })
            .transpose()?;
        let commerce = if amount_units == 0 {
            None
        } else if let Some(commerce) = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.as_tool_invocation())
            .and_then(|intent| intent.commerce.as_ref())
        {
            let binding = verified_payee_binding.ok_or_else(|| {
                PaymentError::RailError(
                    "governed commerce payment omitted verified payee binding".to_owned(),
                )
            })?;
            let approval_artifact_digest = request
                .approval_artifact_digest()
                .map_err(|error| PaymentError::RailError(error.to_string()))?
                .ok_or_else(|| {
                    PaymentError::RailError(
                        "governed commerce payment omitted verified approval".to_owned(),
                    )
                })?;
            let intent_hash = governed
                .as_ref()
                .map(|context| context.intent_hash.as_str());
            if binding.beneficiary_id() != commerce.seller
                || commerce.settlement_destination_ref.as_deref()
                    != Some(binding.settlement_destination_ref())
                || intent_hash != Some(binding.economic_intent_digest())
                || binding.pre_action_authority_digest() != approval_artifact_digest
            {
                return Err(PaymentError::RailError(
                    "governed commerce payment does not match verified payee binding".to_owned(),
                ));
            }
            Some(CommercePaymentContext {
                seller: binding.beneficiary_id().to_owned(),
                settlement_destination_ref: binding.settlement_destination_ref().to_owned(),
                payee_binding_digest: binding.payee_binding_digest().to_owned(),
                pre_action_authority_digest: binding.pre_action_authority_digest().to_owned(),
                shared_payment_token_id: commerce.shared_payment_token_id.clone(),
                max_amount: request
                    .governed_intent
                    .as_ref()
                    .and_then(|intent| intent.as_tool_invocation())
                    .and_then(|intent| intent.max_amount.clone()),
            })
        } else {
            if verified_payee_binding.is_some() {
                return Err(PaymentError::RailError(
                    "verified payee binding has no governed commerce context".to_owned(),
                ));
            }
            None
        };
        let payee = verified_payee_binding.map_or_else(
            || request.server_id.clone(),
            |binding| binding.beneficiary_id().to_owned(),
        );

        let payment_request = PaymentAuthorizeRequest {
            operation_id: admission_operation.map(|binding| binding.operation_id().to_string()),
            request_binding_hash: admission_operation
                .map(|binding| binding.request_binding_hash().to_string()),
            amount_units,
            currency,
            payer: request.agent_id.clone(),
            payee,
            reference: request.request_id.clone(),
            governed,
            commerce,
        };
        let authorization = match admission_operation {
            Some(binding) => {
                if payment_request.operation_id.as_deref() != Some(binding.operation_id())
                    || payment_request.request_binding_hash.as_deref()
                        != Some(binding.request_binding_hash())
                {
                    return Err(PaymentError::RailError(
                        "operation-owned payment request binding diverged before authorization"
                            .to_string(),
                    ));
                }
                let lookup = || {
                    adapter.lookup_authorization_for_operation(
                        binding.operation_id(),
                        binding.request_binding_hash(),
                    )
                };
                match lookup()? {
                    Some(authorization) => authorization,
                    None => match adapter.authorize_for_operation(
                        binding.operation_id(),
                        binding.request_binding_hash(),
                        &payment_request,
                    ) {
                        Ok(authorization) => authorization,
                        Err(authorize_error) => match lookup() {
                            Ok(Some(authorization)) => authorization,
                            Ok(None) => return Err(authorize_error),
                            Err(lookup_error) => {
                                return Err(PaymentError::Unavailable(format!(
                                    "operation-owned payment authorization outcome is unknown after failure ({authorize_error}); recovery lookup failed: {lookup_error}"
                                )));
                            }
                        },
                    },
                }
            }
            None => adapter.authorize(&payment_request)?,
        };
        // Every operation-owned ordinary admission that authorizes payment writes
        // its HoldPlaced row atomically with budget admission, including a
        // no-ceiling MustPrepay whose budget exposure is zero. Legacy monetary
        // charges also write a row. Advance either shape before returning the rail
        // authorization so a crash cannot leave moved money behind HoldPlaced.
        if charge_result.is_some() || admission_operation.is_some() {
            // Persist the rail authorization id BEFORE returning, so a crash
            // after authorize leaves a recoverable Authorized row. If the
            // advance cannot commit, undo the rail hold we just placed and fail
            // closed; the HoldPlaced row still records the attempt for boot
            // reconciliation.
            if let Err(error) = self.persist_payment_authorization_idempotently(
                request,
                admission_operation,
                &authorization,
            ) {
                if let Err(cleanup_error) = self
                    .cleanup_payment_after_authorization_journal_failure(
                        request,
                        admission_operation,
                        &authorization,
                        amount_units,
                        &payment_request.currency,
                        adapter.as_ref(),
                    )
                {
                    warn!(
                        request_id = %request.request_id,
                        reason = %redacted!(&cleanup_error),
                        "rail cleanup after failed journal advance remains recoverable"
                    );
                }
                return Err(PaymentError::Unavailable(format!(
                    "payment journal advance to authorized failed: {error}"
                )));
            }
        }
        Ok(Some(authorization))
    }

    fn persist_payment_authorization_idempotently(
        &self,
        request: &ToolCallRequest,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        authorization: &PaymentAuthorization,
    ) -> Result<(), PaymentError> {
        let transaction_id = authorization
            .settled
            .then(|| Self::payment_authorization_transaction_reference(authorization))
            .flatten();
        if self.payment_journal_active() {
            let current = self.payment_journal_for_authorization_recovery(request)?;
            match current.as_ref() {
                Some(record)
                    if self.payment_journal_authorization_matches(
                        record,
                        admission_operation,
                        authorization,
                        transaction_id,
                    ) =>
                {
                    return Ok(());
                }
                Some(record)
                    if record.state == crate::payment::PaymentJournalState::HoldPlaced
                        && record.admission_operation.as_ref() == admission_operation
                        && record.authorization_id.is_none()
                        && record.transaction_id.is_none()
                        && record.settle_action.is_none()
                        && record.settle_amount_units.is_none() => {}
                Some(_) => {
                    return Err(PaymentError::Unavailable(
                        "payment journal predecessor does not match the exact authorization operation"
                            .to_string(),
                    ));
                }
                None => {
                    return Err(PaymentError::Unavailable(
                        "payment journal authorization predecessor is unavailable".to_string(),
                    ));
                }
            }
        }
        match self.advance_payment_journal_if_active(
            &request.request_id,
            crate::payment::PaymentJournalState::HoldPlaced,
            crate::payment::PaymentJournalState::Authorized,
            Some(&authorization.authorization_id),
            transaction_id,
            None,
        ) {
            Ok(()) if !self.payment_journal_active() => Ok(()),
            Ok(()) => {
                if self.payment_journal_contains_authorization(
                    request,
                    admission_operation,
                    authorization,
                    transaction_id,
                )? {
                    Ok(())
                } else {
                    Err(PaymentError::Unavailable(
                        "payment journal authorization readback did not match the exact operation"
                            .to_string(),
                    ))
                }
            }
            Err(advance_error) => {
                if self.payment_journal_contains_authorization(
                    request,
                    admission_operation,
                    authorization,
                    transaction_id,
                )? {
                    Ok(())
                } else {
                    Err(PaymentError::Unavailable(format!(
                        "payment journal authorization persistence failed: {advance_error}"
                    )))
                }
            }
        }
    }

    fn payment_journal_for_authorization_recovery(
        &self,
        request: &ToolCallRequest,
    ) -> Result<Option<crate::payment::PaymentJournalRecord>, PaymentError> {
        self.with_budget_store(|store| {
            store
                .get_payment_journal(&request.request_id)
                .map_err(KernelError::from)
        })
        .map_err(|error| {
            PaymentError::Unavailable(format!(
                "payment journal authorization readback failed: {error}"
            ))
        })
    }

    fn payment_journal_authorization_matches(
        &self,
        record: &crate::payment::PaymentJournalRecord,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        authorization: &PaymentAuthorization,
        transaction_id: Option<&str>,
    ) -> bool {
        record.state == crate::payment::PaymentJournalState::Authorized
            && record.admission_operation.as_ref() == admission_operation
            && record.authorization_id.as_deref() == Some(authorization.authorization_id.as_str())
            && transaction_id
                .is_none_or(|expected| record.transaction_id.as_deref() == Some(expected))
    }

    fn payment_journal_contains_authorization(
        &self,
        request: &ToolCallRequest,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        authorization: &PaymentAuthorization,
        transaction_id: Option<&str>,
    ) -> Result<bool, PaymentError> {
        let current = self.payment_journal_for_authorization_recovery(request)?;
        Ok(current.as_ref().is_some_and(|record| {
            self.payment_journal_authorization_matches(
                record,
                admission_operation,
                authorization,
                transaction_id,
            )
        }))
    }

    fn cleanup_payment_after_authorization_journal_failure(
        &self,
        request: &ToolCallRequest,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        authorization: &PaymentAuthorization,
        amount_units: u64,
        currency: &str,
        adapter: &dyn PaymentAdapter,
    ) -> Result<(), PaymentError> {
        let refund_transaction_id = authorization
            .settled
            .then(|| {
                self.resolve_settled_authorization_transaction_reference(
                    request,
                    admission_operation,
                    authorization,
                    adapter,
                )
            })
            .transpose()?;
        let settle = crate::payment::PaymentSettleIntent {
            action: if refund_transaction_id.is_some() {
                crate::payment::PaymentSettleAction::Refund
            } else {
                crate::payment::PaymentSettleAction::Release
            },
            amount_units: refund_transaction_id.as_ref().map(|_| amount_units),
        };
        let cleanup_intent_matches = |record: &crate::payment::PaymentJournalRecord| {
            record.state == crate::payment::PaymentJournalState::Settling
                && record.admission_operation.as_ref() == admission_operation
                && record.authorization_id.as_deref()
                    == Some(authorization.authorization_id.as_str())
                && record.transaction_id.as_deref() == refund_transaction_id.as_deref()
                && record.settle_action == Some(settle.action)
                && record.settle_amount_units == settle.amount_units
        };
        let current = self.payment_journal_for_authorization_recovery(request)?;
        let cleanup_already_committed = current.as_ref().is_some_and(cleanup_intent_matches);
        if !cleanup_already_committed {
            if !current.as_ref().is_some_and(|record| {
                record.state == crate::payment::PaymentJournalState::HoldPlaced
                    && record.admission_operation.as_ref() == admission_operation
                    && record.authorization_id.is_none()
                    && record.transaction_id.is_none()
                    && record.settle_action.is_none()
                    && record.settle_amount_units.is_none()
            }) {
                return Err(PaymentError::Unavailable(
                    "payment cleanup predecessor does not match the exact authorization operation"
                        .to_string(),
                ));
            }
            let commit = self.advance_payment_journal_if_active(
                &request.request_id,
                crate::payment::PaymentJournalState::HoldPlaced,
                crate::payment::PaymentJournalState::Settling,
                Some(&authorization.authorization_id),
                refund_transaction_id.as_deref(),
                Some(settle),
            );
            if let Err(commit_error) = commit {
                let committed = self
                    .payment_journal_for_authorization_recovery(request)
                    .map_err(|read_error| {
                        PaymentError::Unavailable(format!(
                            "payment cleanup intent commit failed ({commit_error}); readback failed: {read_error}"
                        ))
                    })?;
                if !committed.as_ref().is_some_and(cleanup_intent_matches) {
                    return Err(PaymentError::Unavailable(format!(
                        "payment cleanup intent could not be committed: {commit_error}"
                    )));
                }
            } else if !self
                .payment_journal_for_authorization_recovery(request)?
                .as_ref()
                .is_some_and(cleanup_intent_matches)
            {
                return Err(PaymentError::Unavailable(
                    "payment cleanup intent readback did not match the exact authorization operation"
                        .to_string(),
                ));
            }
        }

        let cleanup_once = || match refund_transaction_id.as_deref() {
            Some(transaction_id) => match admission_operation {
                Some(binding) => adapter.refund_for_operation(OperationPaymentRefundRequest {
                    operation_id: binding.operation_id(),
                    request_binding_hash: binding.request_binding_hash(),
                    transaction_id,
                    amount_units,
                    currency,
                    reference: &request.request_id,
                }),
                None => adapter.refund(transaction_id, amount_units, currency, &request.request_id),
            },
            None => match admission_operation {
                Some(binding) => adapter.release_for_operation(
                    binding.operation_id(),
                    binding.request_binding_hash(),
                    &authorization.authorization_id,
                    &request.request_id,
                ),
                None => adapter.release(&authorization.authorization_id, &request.request_id),
            },
        };
        let cleanup = cleanup_once();
        let cleanup = if admission_operation.is_some() {
            cleanup.or_else(|_| cleanup_once())
        } else {
            cleanup
        }?;
        self.advance_payment_journal_if_active(
            &request.request_id,
            crate::payment::PaymentJournalState::Settling,
            crate::payment::PaymentJournalState::Settled,
            None,
            Some(&cleanup.transaction_id),
            None,
        )
        .map_err(|error| {
            PaymentError::Unavailable(format!(
                "payment cleanup succeeded but its journal completion failed: {error}"
            ))
        })
    }

    fn resolve_settled_authorization_transaction_reference(
        &self,
        request: &ToolCallRequest,
        admission_operation: Option<&BudgetAdmissionOperationBinding>,
        authorization: &PaymentAuthorization,
        adapter: &dyn PaymentAdapter,
    ) -> Result<String, PaymentError> {
        if let Some(transaction_id) =
            Self::payment_authorization_transaction_reference(authorization)
        {
            return Ok(transaction_id.to_string());
        }
        let state = match admission_operation {
            Some(binding) => adapter.settlement_state_for_operation(
                binding.operation_id(),
                binding.request_binding_hash(),
                &request.request_id,
                Some(&authorization.authorization_id),
            ),
            None => {
                adapter.settlement_state(&request.request_id, Some(&authorization.authorization_id))
            }
        }?;
        match state {
            crate::payment::RailSettlementState::Settled {
                authorization_id,
                result,
            } if authorization_id == authorization.authorization_id
                && !result.transaction_id.is_empty() =>
            {
                Ok(result.transaction_id)
            }
            _ => Err(PaymentError::RailError(
                "settled authorization has no matching transaction reference".to_string(),
            )),
        }
    }

    pub(crate) fn payment_authorization_transaction_reference(
        authorization: &PaymentAuthorization,
    ) -> Option<&str> {
        ["transaction_id", "transactionId"]
            .into_iter()
            .find_map(|key| {
                authorization
                    .metadata
                    .get(key)
                    .and_then(serde_json::Value::as_str)
            })
            .filter(|value| !value.is_empty())
    }
}
